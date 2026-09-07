//! Cross-module integration tests for the Aura analysis engine.
//!
//! These compile as part of the `aura-cli` crate (which `#[path]`-includes the
//! exact same modules the GUI uses) so they exercise the real analysis code on
//! every `cargo test`. They cover the modules that previously had *zero*
//! tests: the CFG/xref engine (`cfg`), the decompiler (`decomp`), the LZX
//! decompressor (`lzx`), the PowerPC decoder (`ppc_disasm`), every non-PS1
//! platform parser (`ps3`/`ps4ps5`/`wiiu`/`xbox360`), and the core ELF engine
//! (`engine`). The PS1 modules already ship their own inline tests.

use crate::cfg::{
    self, decode_at, decode_flow, build_function_cfg, build_xref_index,
    EdgeKind, Flow, XrefKind,
};
use crate::decomp::{self, IrStmt};
use crate::ppc_disasm::{self, PpcEndian};
use crate::lzx;

use std::collections::BTreeMap;

// ---------------------------------------------------------------------------
// Small MIPS word encoders — keep the tests readable.
// ---------------------------------------------------------------------------

/// Encode an R-type MIPS word: op | (rs<<21) | (rt<<16) | (rd<<11) | (shamt<<6) | funct.
fn r_type(op: u32, rs: u32, rt: u32, rd: u32, shamt: u32, funct: u32) -> u32 {
    (op << 26) | (rs << 21) | (rt << 16) | (rd << 11) | (shamt << 6) | funct
}

/// Encode an I-type MIPS word: op | (rs<<21) | (rt<<16) | imm.
fn i_type(op: u32, rs: u32, rt: u32, imm: u32) -> u32 {
    (op << 26) | (rs << 21) | (rt << 16) | (imm & 0xFFFF)
}

/// Encode a J-type MIPS word: op | (target & 0x3FFFFFF).
fn j_type(op: u32, target: u32) -> u32 {
    (op << 26) | (target & 0x03FFFFFF)
}

/// `jr $ra` (op=0, rs=31, funct=8).
const JR_RA: u32 = 0x03E00008; // r_type(0, 31, 0, 0, 0, 8)
/// `nop` (sll $zero,$zero,0).
const NOP: u32 = 0x00000000;

/// Pack a slice of big-endian words into bytes.
fn words_be(words: &[u32]) -> Vec<u8> {
    let mut v = Vec::with_capacity(words.len() * 4);
    for w in words {
        v.extend_from_slice(&w.to_be_bytes());
    }
    v
}

/// Pack a slice of little-endian words into bytes.
fn words_le(words: &[u32]) -> Vec<u8> {
    let mut v = Vec::with_capacity(words.len() * 4);
    for w in words {
        v.extend_from_slice(&w.to_le_bytes());
    }
    v
}

// ===========================================================================
// cfg.rs — control-flow decode, basic-block construction, xref index
// ===========================================================================

mod cfg_tests {
    use super::*;

    #[test]
    fn decode_flow_seq_for_nop() {
        // nop = sll $zero,$zero,0 → op=0 funct=0 → Seq (not a control transfer)
        assert!(matches!(decode_flow(NOP, 0x1000), Flow::Seq));
    }

    #[test]
    fn decode_flow_jr_ra() {
        let f = decode_flow(JR_RA, 0x1000);
        assert!(matches!(f, Flow::Jr { rs: 31 }));
    }

    #[test]
    fn decode_flow_jalr() {
        // jalr $ra, $t9 → op=0 funct=9 rs=31
        let w = r_type(0, 31, 0, 31, 0, 9);
        assert!(matches!(decode_flow(w, 0x1000), Flow::Jalr { rs: 31 }));
    }

    #[test]
    fn decode_flow_jump_and_call_targets() {
        // j 0x1004 → op=2, target_field = 0x1004>>2 = 0x401. jump_target uses
        // (PC+4 & 0xF0000000) | (target_field<<2). At addr 0x0, PC+4=4,
        // target_field<<2 = 0x401<<2 = 0x1004.
        let w = j_type(2, 0x1004 >> 2);
        assert!(matches!(decode_flow(w, 0x0), Flow::Jump { target: 0x1004 }));
        // jal uses the same encoding, op=3
        let w2 = j_type(3, 0x1004 >> 2);
        assert!(matches!(decode_flow(w2, 0x0), Flow::Call { target: 0x1004 }));
    }

    #[test]
    fn decode_flow_conditional_branches() {
        // beq (op4), bne(op5), blez(op6), bgtz(op7), beql(op0x14), bnel(op0x15)
        for op in [0x04u32, 0x05, 0x06, 0x07, 0x14, 0x15] {
            let w = i_type(op, 4, 5, 2);
            assert!(
                matches!(decode_flow(w, 0x1000), Flow::CondBranch { .. }),
                "op {:#x} should be a conditional branch",
                op
            );
        }
    }

    #[test]
    fn decode_flow_regimm_branches() {
        // bltz (rt=0), bgez (rt=1) etc. under op=1 (REGIMM)
        for rt in [0x00u32, 0x01, 0x02, 0x03, 0x10, 0x11] {
            let w = i_type(1, 6, rt, 1);
            assert!(
                matches!(decode_flow(w, 0x1000), Flow::CondBranch { .. }),
                "REGIMM rt {:#x} should branch",
                rt
            );
        }
    }

    #[test]
    fn decode_flow_branch_target_is_pc_plus_4_plus_imm_x4() {
        // beq at 0x1004, imm=2 → target = 0x1004 + 4 + (2<<2) = 0x1010
        let w = i_type(4, 4, 5, 2);
        match decode_flow(w, 0x1004) {
            Flow::CondBranch { target } => assert_eq!(target, 0x1010),
            other => panic!("expected CondBranch, got {:?}", other),
        }
    }

    #[test]
    fn decode_at_le_and_be_match() {
        let data = words_le(&[0x12345678]);
        let ins = decode_at(&data, 0, 0x1000, true).unwrap();
        assert_eq!(ins.word, 0x12345678);
        assert_eq!(ins.addr, 0x1000);

        let data = words_be(&[0x12345678]);
        let ins = decode_at(&data, 0, 0x1000, false).unwrap();
        assert_eq!(ins.word, 0x12345678);
    }

    #[test]
    fn decode_at_returns_none_out_of_range() {
        assert!(decode_at(&[0, 0, 0], 0, 0, true).is_none());
    }

    #[test]
    fn build_function_cfg_branch_and_return() {
        // Function layout (LE), base 0x1000, end 0x101C:
        //   0x1000: nop
        //   0x1004: beq $a0,$a1, 0x1014   (imm=3: 0x1004+4+3*4 = 0x1014)
        //   0x1008: nop                  (delay slot)
        //   0x100C: jr $ra
        //   0x1010: nop                  (delay slot)
        //   0x1014: jr $ra
        //   0x1018: nop                  (delay slot)
        let beq = i_type(4, 4, 5, 3); // beq $a0,$a1,+3
        let data = words_le(&[NOP, beq, NOP, JR_RA, NOP, JR_RA, NOP]);
        let cfg = build_function_cfg(&data, 0x1000, 0x1000, 0x101C, true);

        // Three blocks: 0x1000 (entry), 0x100C, 0x1014.
        assert_eq!(cfg.blocks.len(), 3, "should have 3 basic blocks");
        assert!(cfg.blocks.contains_key(&0x1000));
        assert!(cfg.blocks.contains_key(&0x100C));
        assert!(cfg.blocks.contains_key(&0x1014));

        // Entry block contains the branch + its delay slot (3 instrs).
        let entry = &cfg.blocks[&0x1000];
        assert_eq!(entry.instrs.len(), 3);
        assert_eq!(entry.end, 0x100C);

        // Function returns (jr $ra reachable).
        assert!(cfg.returns, "function should be flagged as returning");

        // Edges: BranchTaken 0x1000->0x1014, BranchNotTaken 0x1000->0x100C.
        let has_edge = |to: u32, kind: EdgeKind| {
            cfg.edges.iter().any(|e| e.from == 0x1000 && e.to == to && e.kind == kind)
        };
        assert!(has_edge(0x1014, EdgeKind::BranchTaken));
        assert!(has_edge(0x100C, EdgeKind::BranchNotTaken));
    }

    #[test]
    fn build_function_cfg_unconditional_jump_within_function() {
        // j back to a target inside the function → Jump edge.
        //   0x1000: j 0x1008  (target_field = 0x1008>>2 = 0x402)
        //   0x1004: nop (delay slot)
        //   0x1008: jr $ra
        //   0x100C: nop (delay slot)
        let j = j_type(2, 0x1008 >> 2);
        let data = words_le(&[j, NOP, JR_RA, NOP]);
        let cfg = build_function_cfg(&data, 0x1000, 0x1000, 0x1010, true);
        assert_eq!(cfg.blocks.len(), 2);
        assert!(cfg.returns);
        assert!(cfg.edges.iter().any(|e| e.kind == EdgeKind::Jump && e.to == 0x1008));
    }

    #[test]
    fn xref_index_records_and_lookups_up() {
        let mut idx = build_xref_index(&[]);
        assert!(idx.is_empty());

        idx.add(0x2000, 0x3000, XrefKind::Call);
        idx.add(0x2004, 0x3000, XrefKind::Branch);
        let refs = idx.refs_to(0x3000);
        assert_eq!(refs.len(), 2);
        // No refs to an unreferenced address.
        assert!(idx.refs_to(0x9999).is_empty());
        // len() counts *distinct* referenced addresses (here: just 0x3000).
        assert_eq!(idx.len(), 1);
    }

    #[test]
    fn xref_index_built_from_cfgs() {
        // One CFG with a JAL (call) edge → the xref index should record it.
        // jal 0x2000 at addr 0x1000 (target_field = 0x2000>>2 = 0x800)
        let jal = j_type(3, 0x2000 >> 2);
        let data = words_le(&[jal, NOP, JR_RA, NOP]);
        let cfg = build_function_cfg(&data, 0x1000, 0x1000, 0x1010, true);
        let idx = build_xref_index(&[cfg]);
        // The call target 0x2000 should have at least one xref from 0x1000.
        let refs = idx.refs_to(0x2000);
        assert!(!refs.is_empty(), "expected xrefs to the JAL call target");
        assert!(refs.iter().any(|r| r.kind == XrefKind::Call));
    }
}

// ===========================================================================
// decomp.rs — instruction lifter + function decompiler
// ===========================================================================

mod decomp_tests {
    use super::*;

    #[test]
    fn lift_nop() {
        let known = BTreeMap::new();
        let stmts = decomp::lift_instruction(NOP, 0x1000, &known);
        assert_eq!(stmts.len(), 1);
        assert!(matches!(stmts[0], IrStmt::Nop));
    }

    #[test]
    fn lift_addu_is_binop_add() {
        // addu $v0,$a0,$a1 = op0 rs4 rt5 rd2 funct0x21
        let w = r_type(0, 4, 5, 2, 0, 0x21);
        let known = BTreeMap::new();
        let stmts = decomp::lift_instruction(w, 0x1000, &known);
        assert_eq!(stmts.len(), 1);
        match &stmts[0] {
            IrStmt::BinOp { dst, op, a, b } => {
                assert_eq!(dst, "$v0");
                assert_eq!(op, "+");
                assert_eq!(a, "$a0");
                assert_eq!(b, "$a1");
            }
            other => panic!("expected BinOp, got {:?}", other),
        }
    }

    #[test]
    fn lift_sub_is_binop_sub() {
        // sub $v0,$a0,$a1 = funct0x22
        let w = r_type(0, 4, 5, 2, 0, 0x22);
        let stmts = decomp::lift_instruction(w, 0x1000, &BTreeMap::new());
        assert!(matches!(stmts[0], IrStmt::BinOp { ref op, .. } if op == "-"));
    }

    #[test]
    fn lift_and_or_xor() {
        for (funct, sym) in [(0x24u32, "&"), (0x25, "|"), (0x26, "^")] {
            let w = r_type(0, 4, 5, 2, 0, funct);
            let stmts = decomp::lift_instruction(w, 0x1000, &BTreeMap::new());
            assert!(
                matches!(&stmts[0], IrStmt::BinOp { op, .. } if op == sym),
                "funct {:#x} should lift to op {}",
                funct, sym
            );
        }
    }

    #[test]
    fn lift_jal_uses_known_name() {
        // jal 0x2000 → known_funcs maps it to "my_func"
        let w = j_type(3, 0x2000 >> 2);
        let mut known = BTreeMap::new();
        known.insert(0x2000, "my_func".to_string());
        let stmts = decomp::lift_instruction(w, 0x1000, &known);
        match &stmts[0] {
            IrStmt::Call { target } => assert_eq!(target, "my_func"),
            other => panic!("expected Call, got {:?}", other),
        }
    }

    #[test]
    fn lift_jal_unknown_renders_address() {
        let w = j_type(3, 0x2000 >> 2);
        let stmts = decomp::lift_instruction(w, 0x1000, &BTreeMap::new());
        match &stmts[0] {
            IrStmt::Call { target } => assert!(target.contains("2000"), "got {}", target),
            other => panic!("expected Call, got {:?}", other),
        }
    }

    #[test]
    fn lift_beq_is_cond_goto() {
        // beq $a0,$a1,+3 → CondGoto { cond: "$a0 == $a1", label: loc_... }
        let w = i_type(4, 4, 5, 3);
        let stmts = decomp::lift_instruction(w, 0x1004, &BTreeMap::new());
        match &stmts[0] {
            IrStmt::CondGoto { cond, label } => {
                assert!(cond.contains("$a0"), "cond={}", cond);
                assert!(cond.contains("$a1"));
                // target = 0x1004 + 4 + 3*4 = 0x1014
                assert!(label.contains("1014"), "label={}", label);
            }
            other => panic!("expected CondGoto, got {:?}", other),
        }
    }

    #[test]
    fn lift_load_word() {
        // lw $t0, 8($a0) = op0x23 rs4 rt8 imm8
        let w = i_type(0x23, 4, 8, 8);
        let stmts = decomp::lift_instruction(w, 0x1000, &BTreeMap::new());
        match &stmts[0] {
            IrStmt::Load { dst, base, offset, size } => {
                assert_eq!(dst, "$t0");
                assert_eq!(base, "$a0");
                assert_eq!(*offset, 8);
                assert_eq!(*size, 4);
            }
            other => panic!("expected Load, got {:?}", other),
        }
    }

    #[test]
    fn lift_store_word() {
        // sw $t0, 16($sp) = op0x2b rs29 rt8 imm16
        let w = i_type(0x2B, 29, 8, 16);
        let stmts = decomp::lift_instruction(w, 0x1000, &BTreeMap::new());
        assert!(matches!(&stmts[0], IrStmt::Store { size: 4, offset: 16, .. }));
    }

    #[test]
    fn lift_addiu_imm_is_signed() {
        // addiu $sp,$sp,-8 → op9 rs29 rt29 imm=0xFFF8 (-8)
        let w = i_type(9, 29, 29, 0xFFF8);
        let stmts = decomp::lift_instruction(w, 0x1000, &BTreeMap::new());
        match &stmts[0] {
            IrStmt::BinOp { dst, op, a, b } => {
                assert_eq!(dst, "$sp");
                assert_eq!(op, "+");
                assert_eq!(a, "$sp");
                assert_eq!(b, "-8", "addiu imm should be sign-extended to -8, got {}", b);
            }
            other => panic!("expected BinOp, got {:?}", other),
        }
    }

    #[test]
    fn lift_unknown_word_is_raw() {
        // An op field with no handler (e.g. op=0x3F, funct=0x3F) → Raw.
        let w = 0xFFFFFFFF;
        let stmts = decomp::lift_instruction(w, 0x1000, &BTreeMap::new());
        assert!(matches!(stmts[0], IrStmt::Raw { .. }));
    }

    #[test]
    fn decompile_function_renders_jr_ra_as_return() {
        // jr $ra in the CFG must be emitted as "return;" (not "goto $ra;").
        //   0x1000: jr $ra ; 0x1004: nop (delay slot)
        let data = words_le(&[JR_RA, NOP]);
        let cfg = build_function_cfg(&data, 0x1000, 0x1000, 0x1008, true);
        let d = decomp::decompile_function(&cfg, &data, 0x1000, true, &BTreeMap::new());
        assert!(d.pseudocode.contains("return;"), "pseudocode was:\n{}", d.pseudocode);
        assert!(!d.pseudocode.contains("goto $ra;"), "should not emit goto $ra");
    }

    #[test]
    fn decompile_function_names_unknown_entry_as_sub() {
        let data = words_le(&[JR_RA, NOP]);
        let cfg = build_function_cfg(&data, 0x1000, 0x1000, 0x1008, true);
        let d = decomp::decompile_function(&cfg, &data, 0x1000, true, &BTreeMap::new());
        assert!(d.pseudocode.contains("void sub_"), "pseudocode:\n{}", d.pseudocode);
        // The header comment renders the entry as 0x{08X} = "0x00001000".
        assert!(d.pseudocode.contains("0x00001000"), "pseudocode:\n{}", d.pseudocode);
    }

    #[test]
    fn decompile_function_uses_known_name() {
        let data = words_le(&[JR_RA, NOP]);
        let cfg = build_function_cfg(&data, 0x1000, 0x1000, 0x1008, true);
        let mut known = BTreeMap::new();
        known.insert(0x1000, "do_thing".to_string());
        let d = decomp::decompile_function(&cfg, &data, 0x1000, true, &known);
        assert!(d.pseudocode.contains("void do_thing()"), "pseudocode:\n{}", d.pseudocode);
    }

    #[test]
    fn decompile_function_emits_label_for_branch_target() {
        // A branch creates a block target that must get a loc_ label.
        //   0x1000: beq $a0,$a1,0x1008 (imm=1: 0x1000+4+1*4=0x1008)
        //   0x1004: nop (delay slot)
        //   0x1008: jr $ra ; 0x100C: nop
        let beq = i_type(4, 4, 5, 1);
        let data = words_le(&[beq, NOP, JR_RA, NOP]);
        let cfg = build_function_cfg(&data, 0x1000, 0x1000, 0x1010, true);
        let d = decomp::decompile_function(&cfg, &data, 0x1000, true, &BTreeMap::new());
        assert!(d.pseudocode.contains("loc_00001008"), "pseudocode:\n{}", d.pseudocode);
        assert!(d.pseudocode.contains("if ("), "should contain a conditional");
    }
}

// ===========================================================================
// lzx.rs — argument validation (full round-trip needs a real XEX fixture)
// ===========================================================================

mod lzx_tests {
    use super::*;

    #[test]
    fn rejects_zero_window_size() {
        let r = lzx::lzx_decompress(&[0u8; 16], 0, 16);
        assert_eq!(r.unwrap_err(), lzx::LzxError::Args);
    }

    #[test]
    fn rejects_non_power_of_two_window() {
        // 0x30000 is not a power of two.
        let r = lzx::lzx_decompress(&[0u8; 16], 0x30000, 16);
        assert_eq!(r.unwrap_err(), lzx::LzxError::Args);
    }

    #[test]
    fn rejects_out_of_range_window_bits() {
        // 2^14 = 0x4000 → window_bits 14, outside the 15..=21 range.
        let r = lzx::lzx_decompress(&[0u8; 16], 0x4000, 16);
        assert_eq!(r.unwrap_err(), lzx::LzxError::Args);
        // 2^22 = 0x400000 → window_bits 22, also out of range.
        let r = lzx::lzx_decompress(&[0u8; 16], 0x400000, 16);
        assert_eq!(r.unwrap_err(), lzx::LzxError::Args);
    }

    #[test]
    fn accepts_in_range_window_size_but_fails_on_garbage() {
        // 2^17 = 0x20000 (window_bits 17) is valid; random bytes are not a
        // valid LZX stream so we expect a Decrunched or Read error (never Args).
        let r = lzx::lzx_decompress(&[0x55u8; 64], 0x20000, 64);
        let err = r.unwrap_err();
        assert!(
            err == lzx::LzxError::Decrunched || err == lzx::LzxError::Read,
            "expected Decrunched/Read, got {:?}",
            err
        );
    }
}

// ===========================================================================
// ppc_disasm.rs — endianness-aware PowerPC decoding
// ===========================================================================

mod ppc_disasm_tests {
    use super::*;

    #[test]
    fn decodes_nop_as_ori() {
        // PowerPC "nop" is `ori 0,0,0` = 0x60000000.
        let bytes_be = 0x60000000u32.to_be_bytes();
        let ins = ppc_disasm::disassemble_ppc_at(&bytes_be, 0, 0x1000, 1, PpcEndian::Big);
        assert_eq!(ins.len(), 1);
        assert_eq!(ins[0].size, 4);
        assert_eq!(ins[0].address, 0x1000);
    }

    #[test]
    fn decodes_blr() {
        // `blr` = 0x4E800020.
        let bytes_be = 0x4E800020u32.to_be_bytes();
        let ins = ppc_disasm::disassemble_ppc_at(&bytes_be, 0, 0x2000, 1, PpcEndian::Big);
        assert_eq!(ins.len(), 1);
        assert!(ins[0].mnemonic.contains("blr") || ins[0].mnemonic.contains("b"));
    }

    #[test]
    fn big_and_little_endian_decode_same_word_differently() {
        // The same 4 bytes decode to different instructions under each
        // endianness (byte order matters). Use 0x7C6320A6 (mfspr) as the BE
        // word; under LE the bytes are reversed.
        let word = 0x7C6320A6u32;
        let be = ppc_disasm::disassemble_ppc_at(&word.to_be_bytes(), 0, 0, 1, PpcEndian::Big);
        let le = ppc_disasm::disassemble_ppc_at(&word.to_be_bytes(), 0, 0, 1, PpcEndian::Little);
        assert_eq!(be.len(), 1);
        assert_eq!(le.len(), 1);
        // The two must not produce identical mnemonics+operands (endianness flip).
        let be_str = format!("{} {}", be[0].mnemonic, be[0].operands);
        let le_str = format!("{} {}", le[0].mnemonic, le[0].operands);
        assert_ne!(be_str, le_str, "endianness should change the decode");
    }

    #[test]
    fn caps_at_max_instructions() {
        let data = [0x60u8, 0x00, 0x00, 0x00].repeat(10); // 10 nops worth
        let ins = ppc_disasm::disassemble_ppc_at(&data, 0, 0, 3, PpcEndian::Big);
        assert_eq!(ins.len(), 3);
    }

    #[test]
    fn stops_on_truncated_word() {
        let data = [0x60u8, 0x00, 0x00]; // only 3 bytes
        let ins = ppc_disasm::disassemble_ppc_at(&data, 0, 0, 10, PpcEndian::Big);
        assert!(ins.is_empty());
    }

    #[test]
    fn legacy_api_matches_little_endian() {
        // The legacy `disassemble_ppc_instruction` was written for GameCube ELFs
        // which this tool historically read little-endian, so it reads words as
        // LE. It must therefore match the explicit `PpcEndian::Little` path on
        // the same bytes (NOT the big-endian path).
        let word = 0x60000000u32; // nop when decoded as BE
        let data = word.to_be_bytes();
        let legacy = ppc_disasm::disassemble_ppc_instruction(&data, 0, 1);
        let le = ppc_disasm::disassemble_ppc_at(&data, 0, 0, 1, PpcEndian::Little);
        assert_eq!(legacy.len(), 1);
        assert_eq!(le.len(), 1);
        assert_eq!(legacy[0].mnemonic, le[0].mnemonic);
        assert_eq!(legacy[0].operands, le[0].operands);
    }
}

// ===========================================================================
// ps4ps5.rs — x86-64 disassembly + format detection
// ===========================================================================

mod ps4ps5_tests {
    use super::*;

    #[test]
    fn disassemble_x64_decodes_function_prologue() {
        // push rbp; mov rbp,rsp; pop rbp; ret
        let code = [0x55, 0x48, 0x89, 0xE5, 0x5D, 0xC3];
        let ins = crate::ps4ps5::disassemble_x64(&code, 0x400000, 10);
        assert!(!ins.is_empty());
        // First instruction is `push rbp`.
        assert!(ins[0].text.contains("push"), "got: {}", ins[0].text);
        // Last is `ret`.
        assert!(ins.last().unwrap().text.contains("ret"), "got: {}", ins.last().unwrap().text);
        // Addresses are sequential and sized correctly.
        assert_eq!(ins[0].address, 0x400000);
        assert_eq!(ins[0].size, 1);
    }

    #[test]
    fn disassemble_x64_caps_at_max() {
        let code = [0x90u8; 64]; // nops
        let ins = crate::ps4ps5::disassemble_x64(&code, 0, 5);
        assert!(ins.len() <= 5);
    }

    #[test]
    fn is_ps4ps5_elf_detects_le_elf64_x8664() {
        // Minimal ELF64 LE x86-64: magic + class 2 + data 1 (LE) + machine 62.
        // e_machine lives at ELF header offset 18 (after the 16-byte e_ident
        // and 2-byte e_type).
        let mut hdr = [0u8; 20];
        hdr[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
        hdr[4] = 2; // 64-bit
        hdr[5] = 1; // little-endian
        hdr[18..20].copy_from_slice(&62u16.to_le_bytes()); // EM_X86_64
        assert!(crate::ps4ps5::is_ps4ps5_elf(&hdr));
    }

    #[test]
    fn is_ps4ps5_elf_rejects_be_and_wrong_machine() {
        let mut hdr = [0u8; 20];
        hdr[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
        hdr[4] = 2;
        hdr[5] = 2; // big-endian → not a PS4/PS5 LE ELF
        hdr[18..20].copy_from_slice(&62u16.to_le_bytes());
        assert!(!crate::ps4ps5::is_ps4ps5_elf(&hdr));

        // Correct endianness but wrong machine.
        hdr[5] = 1;
        hdr[18..20].copy_from_slice(&8u16.to_le_bytes()); // EM_MIPS
        assert!(!crate::ps4ps5::is_ps4ps5_elf(&hdr));
    }

    #[test]
    fn parse_ps4ps5_rejects_garbage() {
        let r = crate::ps4ps5::parse_ps4ps5(&[0u8; 32], "junk.bin");
        assert!(r.is_err());
    }

    #[test]
    fn parse_ps4ps5_parses_plain_elf64() {
        let elf = minimal_elf64_x8664();
        let info = crate::ps4ps5::parse_ps4ps5(&elf, "homebrew.elf").expect("parse");
        assert_eq!(info.machine, 62);
        assert!(info.file_type.contains("ELF"));
        assert!(!info.encrypted);
    }

    /// Build a minimal valid ELF64 little-endian x86-64 image with one `.text`
    /// section containing `ret` (0xC3), used by several tests.
    fn minimal_elf64_x8664() -> Vec<u8> {
        // Layout:
        //   0x00  ELF header (64 bytes)
        //   0x40  section header table: [0]=NULL, [1]=.shstrtab, [2]=.text
        //   0xD8  .shstrtab bytes: "\0.shstrtab\0.text\0"
        //   0xE8  .text bytes: 0xC3 (ret)
        let text_off: u64 = 0xE8;
        let text_addr: u64 = 0x401000;
        let shstrtab: &[u8] = b"\0.shstrtab\0.text\0";
        let shstr_off: u64 = 0xD8;
        let shstr_name_idx: u32 = 1; // offset of ".shstrtab" in the strtab
        let text_name_idx: u32 = 11; // offset of ".text" in the strtab
        let _ = text_addr;

        let mut buf = vec![0u8; 0xE8 + 1];

        // --- ELF header ---
        buf[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
        buf[4] = 2; // ELFCLASS64
        buf[5] = 1; // ELFDATA2LSB (little-endian)
        buf[6] = 1; // EV_CURRENT
        buf[16..18].copy_from_slice(&2u16.to_le_bytes()); // e_type = ET_EXEC
        buf[18..20].copy_from_slice(&62u16.to_le_bytes()); // e_machine = EM_X86_64
        buf[20..24].copy_from_slice(&1u32.to_le_bytes()); // e_version = EV_CURRENT
        buf[24..32].copy_from_slice(&text_addr.to_le_bytes()); // e_entry
        // e_shoff = 0x40 (section headers right after ELF header)
        buf[40..48].copy_from_slice(&0x40u64.to_le_bytes());
        buf[52..54].copy_from_slice(&64u16.to_le_bytes()); // e_ehsize
        buf[58..60].copy_from_slice(&64u16.to_le_bytes()); // e_shentsize
        buf[60..62].copy_from_slice(&3u16.to_le_bytes()); // e_shnum
        buf[62..64].copy_from_slice(&1u16.to_le_bytes()); // e_shstrndx = section 1

        // --- Section header table at 0x40 (3 entries × 64 bytes) ---
        let sh_off = 0x40usize;
        // Section 0: NULL (already zeroed)
        // Section 1: .shstrtab
        let s1 = sh_off + 64;
        buf[s1..s1 + 4].copy_from_slice(&shstr_name_idx.to_le_bytes()); // sh_name
        buf[s1 + 4..s1 + 8].copy_from_slice(&3u32.to_le_bytes()); // SHT_STRTAB
        buf[s1 + 24..s1 + 32].copy_from_slice(&shstr_off.to_le_bytes()); // sh_offset
        buf[s1 + 32..s1 + 40].copy_from_slice(&(shstrtab.len() as u64).to_le_bytes()); // sh_size
        // Section 2: .text
        let s2 = sh_off + 128;
        buf[s2..s2 + 4].copy_from_slice(&text_name_idx.to_le_bytes()); // sh_name
        buf[s2 + 4..s2 + 8].copy_from_slice(&1u32.to_le_bytes()); // SHT_PROGBITS
        buf[s2 + 8..s2 + 16].copy_from_slice(&0x6u64.to_le_bytes()); // SHF_ALLOC|SHF_EXECINSTR
        buf[s2 + 16..s2 + 24].copy_from_slice(&text_addr.to_le_bytes()); // sh_addr
        buf[s2 + 24..s2 + 32].copy_from_slice(&text_off.to_le_bytes()); // sh_offset
        buf[s2 + 32..s2 + 40].copy_from_slice(&1u64.to_le_bytes()); // sh_size (1 byte: ret)

        // --- .shstrtab at 0xD8 ---
        buf[shstr_off as usize..shstr_off as usize + shstrtab.len()].copy_from_slice(shstrtab);
        // --- .text at 0xE8 ---
        buf[text_off as usize] = 0xC3; // ret

        buf
    }
}

// ===========================================================================
// ps3.rs — big-endian ELF / SELF detection
// ===========================================================================

mod ps3_tests {
    use super::*;

    #[test]
    fn parse_ps3_rejects_garbage() {
        let r = crate::ps3::parse_ps3(&[0u8; 32], "junk.bin");
        assert!(r.is_err());
    }

    #[test]
    fn parse_ps3_parses_be_elf32() {
        let elf = minimal_be_elf32();
        let info = crate::ps3::parse_ps3(&elf, "ps3.elf").expect("parse");
        assert!(info.file_type.contains("BE"), "file_type={}", info.file_type);
        assert_eq!(info.machine, 0x15); // EM_PPC (20) — PS3 uses PowerPC
    }

    /// Minimal big-endian ELF32 (class=1, data=2(BE)) with EM_PPC (20).
    fn minimal_be_elf32() -> Vec<u8> {
        let mut buf = vec![0u8; 64]; // just a header, no sections
        buf[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
        buf[4] = 1; // ELFCLASS32
        buf[5] = 2; // ELFDATA2MSB (big-endian)
        buf[6] = 1; // EV_CURRENT
        buf[18..20].copy_from_slice(&0x15u16.to_be_bytes()); // e_machine = EM_PPC
        buf[24..28].copy_from_slice(&0x10000u32.to_be_bytes()); // e_entry
        buf
    }
}

// ===========================================================================
// wiiu.rs — RPX/RPL detection
// ===========================================================================

mod wiiu_tests {
    use super::*;

    #[test]
    fn parse_rpx_rpl_rejects_garbage() {
        let r = crate::wiiu::parse_rpx_rpl(&[0u8; 32], "junk.bin");
        assert!(r.is_err());
    }
}

// ===========================================================================
// xbox360.rs — XEX container detection + version decoding
// ===========================================================================

mod xbox360_tests {
    use super::*;

    #[test]
    fn is_xex_detects_magic() {
        // XEX magic: "XEX0" / "XEX1" / "XEX2"
        assert!(crate::xbox360::is_xex(b"XEX2xxxx"));
        assert!(crate::xbox360::is_xex(b"XEX0"));
        assert!(!crate::xbox360::is_xex(b"XXXX"));
        assert!(!crate::xbox360::is_xex(b""));
    }

    #[test]
    fn decode_version_formats_known_values() {
        // Version is a u32; just ensure it returns a non-empty string.
        let s = crate::xbox360::decode_version(0x00020001);
        assert!(!s.is_empty());
    }

    #[test]
    fn decode_title_id_is_stable() {
        // Round-trip stability: same input → same output string.
        let a = crate::xbox360::decode_title_id(0x41560800);
        let b = crate::xbox360::decode_title_id(0x41560800);
        assert_eq!(a, b);
        assert!(!a.is_empty());
    }

    #[test]
    fn parse_xex_rejects_garbage() {
        let r = crate::xbox360::parse_xex(&[0u8; 64], "junk.xex");
        assert!(r.is_err());
    }
}

// ===========================================================================
// engine.rs — ELF parsing + format identification helpers
// ===========================================================================

mod engine_tests {
    use super::*;

    #[test]
    fn parse_elf_data_rejects_too_small() {
        let r = crate::engine::parse_elf_data(&[0u8; 10], "tiny.bin");
        assert!(r.is_err());
    }

    #[test]
    fn parse_elf_data_rejects_bad_magic() {
        let mut buf = vec![0u8; 128];
        buf[0..4].copy_from_slice(b"NOPE");
        let r = crate::engine::parse_elf_data(&buf, "fake.elf");
        assert!(r.is_err());
    }

    #[test]
    fn identify_data_recognizes_elf_classes() {
        // ELF32 LE
        let mut h = [0u8; 8];
        h[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
        h[4] = 1; h[5] = 1;
        assert_eq!(crate::engine::identify_data(&h), "elf32-le");
        // ELF32 BE
        h[5] = 2;
        assert_eq!(crate::engine::identify_data(&h), "elf32-be");
        // ELF64 LE
        h[4] = 2; h[5] = 1;
        assert_eq!(crate::engine::identify_data(&h), "elf64-le");
        // ELF64 BE
        h[5] = 2;
        assert_eq!(crate::engine::identify_data(&h), "elf64-be");
    }

    #[test]
    fn read_u32_le_and_be_round_trip() {
        let bytes = [0x12u8, 0x34, 0x56, 0x78];
        assert_eq!(crate::engine::read_u32(&bytes, 0, true), 0x78563412);
        assert_eq!(crate::engine::read_u32(&bytes, 0, false), 0x12345678);
    }

    #[test]
    fn read_u16_le_and_be_round_trip() {
        let bytes = [0xABu8, 0xCD];
        assert_eq!(crate::engine::read_u16(&bytes, 0, true), 0xCDAB);
        assert_eq!(crate::engine::read_u16(&bytes, 0, false), 0xABCD);
    }

    #[test]
    fn supported_formats_returns_json_object() {
        let v = crate::engine::supported_formats().expect("formats");
        assert!(v.is_object(), "expected a JSON object, got: {}", v);
    }

    #[test]
    fn toml_basic_string_escapes_quotes_and_backslashes() {
        // toml_basic_string returns a TOML basic string, which is wrapped in
        // double quotes, with internal quotes/backslashes escaped.
        assert_eq!(crate::engine::toml_basic_string("a\"b"), "\"a\\\"b\"");
        assert_eq!(crate::engine::toml_basic_string("a\\b"), "\"a\\\\b\"");
    }
}


