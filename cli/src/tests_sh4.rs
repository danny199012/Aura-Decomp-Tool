//! SH-4 disassembler tests — every expectation below was derived from
//! MAME's `sh_dasm.cpp` SH-4 tables and cross-checked against its SH-2/SH-4
//! executors and QEMU's `target/sh4/translate.c` (branch/literal math,
//! bank registers, FPU corners). No real game data is needed: every case
//! is a 16-bit word, disassembled at the Dreamcast user-space base.

use crate::sh4_disasm::{disassemble_sh4_at, disassemble_sh4_instruction, Sh4Instruction};

const BASE: u32 = 0x8C00_8000;

fn d(word: u16) -> Sh4Instruction {
    disassemble_sh4_instruction(word, BASE)
}

#[test]
fn system_instructions_decode_exactly() {
    for (word, expected) in [
        (0x0009u16, "nop"),
        (0x0008, "clrt"),
        (0x0018, "sett"),
        (0x0028, "clrmac"),
        (0x0038, "ldtlb"),
        (0x0048, "clrs"),
        (0x0058, "sets"),
        (0x0019, "div0u"),
        (0x001B, "sleep"),
    ] {
        let i = d(word);
        assert_eq!(i.mnemonic, expected, "word {word:#06x}");
        assert_eq!(i.operands, "", "word {word:#06x}");
        assert!(!i.is_branch && !i.is_call && !i.is_return, "word {word:#06x}");
        assert_eq!(i.size, 2);
    }
}

#[test]
fn returns_and_control_flags() {
    let rts = d(0x000B);
    assert_eq!(rts.mnemonic, "rts");
    assert!(rts.is_branch && rts.is_return && rts.has_delay_slot);
    assert!(!rts.is_call);

    let rte = d(0x002B);
    assert_eq!(rte.mnemonic, "rte");
    assert!(rte.is_return && rte.has_delay_slot);

    let jsr = d(0x4B0B); // jsr @r11
    assert_eq!(jsr.mnemonic, "jsr");
    assert_eq!(jsr.operands, "@r11");
    assert!(jsr.is_branch && jsr.is_call && jsr.has_delay_slot);
    assert!(jsr.branch_target.is_none(), "register branches have no static target");

    let jmp = d(0x402B); // jmp @r0
    assert_eq!(jmp.mnemonic, "jmp");
    assert!(jmp.is_branch && jmp.has_delay_slot);
    assert!(!jmp.is_call, "jmp is a computed branch, not a call");

    let braf = d(0x0223); // braf r2
    assert_eq!(braf.mnemonic, "braf");
    assert!(braf.is_branch && braf.has_delay_slot && !braf.is_call);

    let bsrf = d(0x0303); // bsrf r3
    assert_eq!(bsrf.mnemonic, "bsrf");
    assert!(bsrf.is_branch && bsrf.is_call && bsrf.has_delay_slot);
}

#[test]
fn move_family_renders_sh4_syntax() {
    // mov.l Rm,@(disp,Rn)
    assert_eq!(d(0x1234).operands, "r3, @(0x10, r2)");
    // mov.l Rm,@-Rn (function prologue push)
    let push = d(0x2FE6);
    assert_eq!(push.mnemonic, "mov.l");
    assert_eq!(push.operands, "r14, @-r15");
    // mov.l @Rm+,Rn (epilogue pop)
    assert_eq!(d(0x6EF6).operands, "@r15+, r14");
    // neg Rm,Rn / mov Rm,Rn
    assert_eq!(d(0x63AB).mnemonic, "neg");
    assert_eq!(d(0x63AB).operands, "r10, r3");
    assert_eq!(d(0x6323).mnemonic, "mov");
    assert_eq!(d(0x6323).operands, "r2, r3");
    // R0-indexed moves
    assert_eq!(d(0x0454).operands, "r5, @(r0, r4)"); // mov.b Rm,@(R0,Rn)
    assert_eq!(d(0x0C4C).operands, "@(r0, r4), r12"); // mov.b @(R0,Rm),Rn
    // displacement loads/stores with size scaling
    assert_eq!(d(0x5324).operands, "@(0x10, r2), r3"); // mov.l @(disp,Rm),Rn
    assert_eq!(d(0x8126).operands, "r0, @(0xc, r2)"); // mov.w R0,@(disp,Rn)
    assert_eq!(d(0x85A8).operands, "@(0x10, r10), r0");
    // GBR forms use 8-bit displacements
    assert_eq!(d(0xC008).operands, "r0, @(0x8, gbr)");
    assert_eq!(d(0xC640).operands, "@(0x100, gbr), r0");
    // ext / multiply
    assert_eq!(d(0x612C).mnemonic, "extu.b");
    assert_eq!(d(0x24EE).mnemonic, "mulu.w"); // mulu.w Rm,Rn
    assert_eq!(d(0x24EE).operands, "r14, r4");
    assert_eq!(d(0x0277).operands, "r7, r2"); // mul.l
}

#[test]
fn immediate_operands_are_signed_or_hex_by_semantics() {
    assert_eq!(d(0x7110).operands, "#16, r1"); // add #imm
    assert_eq!(d(0xE3FF).operands, "#-1, r3"); // mov #imm
    assert_eq!(d(0x88FC).operands, "#-4, r0"); // cmp/eq #imm
    assert_eq!(d(0xC90F).operands, "#0x0f, r0"); // and #imm (mask, byte-padded)
    assert_eq!(d(0xCC80).operands, "#0x80, @(r0, gbr)"); // tst.b
    assert_eq!(d(0xC320).operands, "#0x20"); // trapa
    assert_eq!(d(0xC320).mnemonic, "trapa");
}

#[test]
fn branch_targets_use_instruction_plus_four() {
    // bra +0x10 from 0x8C008000 -> 0x8C008014
    let bra = d(0xA008);
    assert_eq!(bra.mnemonic, "bra");
    assert_eq!(bra.operands, "0x8c008014");
    assert_eq!(bra.branch_target, Some(BASE + 0x14));
    assert!(bra.has_delay_slot);

    // bra $ (disp = -2): the classic "bra $; nop" idle loop.
    let self_loop = d(0xAFFE);
    assert_eq!(self_loop.branch_target, Some(BASE));
    assert_eq!(self_loop.operands, "0x8c008000");

    // bsr (call) with the same math
    let bsr = d(0xB100);
    assert_eq!(bsr.mnemonic, "bsr");
    assert_eq!(bsr.branch_target, Some(BASE + 0x204));
    assert!(bsr.is_call && bsr.has_delay_slot);

    // bt / bf have no delay slot; bf -1 branches to the next instruction.
    let bt = d(0x8904);
    assert_eq!(bt.mnemonic, "bt");
    assert_eq!(bt.branch_target, Some(BASE + 0xC));
    assert!(!bt.has_delay_slot && !bt.is_call);

    let bf = d(0x8BFF);
    assert_eq!(bf.mnemonic, "bf");
    assert_eq!(bf.branch_target, Some(BASE + 2));

    let bts = d(0x8D04);
    assert_eq!(bts.mnemonic, "bt.s");
    assert!(bts.has_delay_slot);

    let bfs = d(0x8FFF);
    assert_eq!(bfs.mnemonic, "bf.s");
    assert_eq!(bfs.branch_target, Some(BASE + 2));
    assert!(bfs.has_delay_slot);
}

#[test]
fn pc_relative_literals_include_the_alignment_fixup() {
    // mov.w @(0x20,pc),r3: literal = instr + 4 + disp*2 (no extra alignment).
    let w = d(0x9310);
    assert_eq!(w.mnemonic, "mov.w");
    assert_eq!(w.operands, "@(0x20, pc), r3");
    assert_eq!(w.literal_address, Some(BASE + 4 + 0x20));

    // mov.l @(0x4,pc),r0: literal = ((instr + 4) & !3) + disp*4.
    let l = d(0xD001);
    assert_eq!(l.mnemonic, "mov.l");
    assert_eq!(l.operands, "@(0x4, pc), r0");
    assert_eq!(l.literal_address, Some(BASE + 8));

    // The fixup matters on a non-4-aligned address: from ...802 the base
    // ((...806) & !3) rounds DOWN to ...804.
    let misaligned = disassemble_sh4_instruction(0xD000, BASE + 2);
    assert_eq!(misaligned.literal_address, Some(BASE + 4));

    // mova uses the same aligned base.
    let mova = d(0xC701);
    assert_eq!(mova.mnemonic, "mova");
    assert_eq!(mova.literal_address, Some(BASE + 8));
    let mova_misaligned = disassemble_sh4_instruction(0xC701, BASE + 2);
    assert_eq!(mova_misaligned.literal_address, Some(BASE + 8));
}

#[test]
fn system_register_loads_stores_and_bank_slots() {
    assert_eq!(d(0x0102).operands, "sr, r1"); // stc SR,Rn
    assert_eq!(d(0x002A).operands, "pr, r0"); // sts PR,Rn
    assert_eq!(d(0x402A).mnemonic, "lds"); // lds Rn,PR (register in bits 11:8)
    assert_eq!(d(0x401E).operands, "r0, gbr"); // ldc Rm,GBR
    assert_eq!(d(0x4F22).operands, "pr, @-r15"); // sts.l PR,@-Rn
    assert_eq!(d(0x4F26).operands, "@r15+, pr"); // lds.l @Rn+,PR
    assert_eq!(d(0x4243).operands, "spc, @-r2"); // stc.l SPC,@-Rn

    // Bank registers, verified against MAME's STCRBANK / LDCRBANK executors:
    // stc Rm_BANK,Rn (source = bank slot Rm & 7) and
    // ldc Rn,Rm_BANK (source = Rn, bank slot = Rm & 7).
    assert_eq!(d(0x0292).operands, "r1_bank, r2");
    assert_eq!(d(0x419E).operands, "r1, r1_bank");
    assert_eq!(d(0x45B3).operands, "r3_bank, @-r5");
    assert_eq!(d(0x45B7).operands, "@r5+, r3_bank");
}

#[test]
fn sh4_specific_operands() {
    assert_eq!(d(0x432C).operands, "r2, r3"); // shad Rm,Rn
    assert_eq!(d(0x4508).mnemonic, "shll2");
    assert_eq!(d(0x4110).mnemonic, "dt");
    assert_eq!(d(0x4224).mnemonic, "rotcl");
    assert_eq!(d(0x0229).mnemonic, "movt"); // movt r2
    assert_eq!(d(0x0183).mnemonic, "pref");
    assert_eq!(d(0x02C3).mnemonic, "movca.l");
    assert_eq!(d(0x411B).mnemonic, "tas.b");
    assert_eq!(d(0x000F).operands, "@r0+, @r0+"); // mac.l
    assert_eq!(d(0x4FFF).operands, "@r15+, @r15+"); // mac.w
    assert_eq!(d(0x34DD).operands, "r13, r4"); // dmuls.l
}

#[test]
fn fpu_group_decodes_the_sh4_extensions() {
    assert_eq!(d(0xF320).operands, "fr2, fr3"); // fadd
    assert_eq!(d(0xF54B).operands, "fr4, @-r5"); // fmov.s Fm,@-Rn
    assert_eq!(d(0xF30D).operands, "fpul, fr3"); // fsts
    assert_eq!(d(0xF08D).mnemonic, "fldi0");
    assert_eq!(d(0xF37D).mnemonic, "fsrra");
    assert_eq!(d(0xF4AD).operands, "fpul, dr4"); // fcnvsd
    assert_eq!(d(0xF4BD).operands, "dr4, fpul"); // fcnvds
    // FIPR/FTRV vector indices come from bits 11:10 / 9:8 (QEMU-verified).
    assert_eq!(d(0xF4ED).operands, "fv0, fv4"); // fipr FVm,FVn
    assert_eq!(d(0xF9FD).operands, "xmtrx, fv8"); // ftrv
    assert_eq!(d(0xF21E).operands, "fr0, fr1, fr2"); // fmac FR0,Fm,Fn
    // FSCHG (0xF3FD) and FRCHG (0xFBFD) per QEMU.
    assert_eq!(d(0xF3FD).mnemonic, "fschg");
    assert_eq!(d(0xFBFD).mnemonic, "frchg");
}

#[test]
fn reserved_words_render_as_word_directives() {
    for word in [0x0000u16, 0x0052, 0xF0CD] {
        let i = d(word);
        assert_eq!(i.mnemonic, ".word", "word {word:#06x}");
        assert_eq!(i.operands, format!("0x{word:04x}"), "word {word:#06x}");
        assert!(!i.is_branch);
    }
}

#[test]
fn listing_decodes_little_endian_with_offsets_and_addresses() {
    // mov.l r14,@-r15 ; sts.l pr,@-r15 ; rts — a classic SH-4 prologue tail.
    let data = [0xE6u8, 0x2F, 0x22, 0x4F, 0x0B, 0x00, 0xAA /* stray byte */];
    let insns = disassemble_sh4_at(&data, 0, BASE, 10);
    assert_eq!(insns.len(), 3, "the stray byte must not become an instruction");
    assert_eq!(insns[0].mnemonic, "mov.l");
    assert_eq!(insns[0].operands, "r14, @-r15");
    assert_eq!(insns[0].address, BASE);
    assert_eq!(insns[0].file_offset, 0);
    assert_eq!(insns[1].mnemonic, "sts.l");
    assert_eq!(insns[1].address, BASE + 2);
    assert_eq!(insns[1].file_offset, 2);
    let rts = &insns[2];
    assert_eq!(rts.mnemonic, "rts");
    assert_eq!(rts.address, BASE + 4);
    assert!(rts.is_return && rts.has_delay_slot);

    // Starting mid-buffer keeps file_offset/address in sync.
    let shifted = disassemble_sh4_at(&data, 2, BASE, 10);
    assert_eq!(shifted.len(), 2);
    assert_eq!(shifted[0].mnemonic, "sts.l");
    assert_eq!(shifted[0].file_offset, 2);
    assert_eq!(shifted[0].address, BASE);
}

#[test]
fn epilogue_sequence_flags_the_delay_slot() {
    // mov.l @r15+,r14 ; lds.l @r15+,pr ; rts ; nop
    let data = [0xF6u8, 0x6E, 0x26, 0x4F, 0x0B, 0x00, 0x09, 0x00];
    let insns = disassemble_sh4_at(&data, 0, BASE, 10);
    assert_eq!(insns.len(), 4);
    assert_eq!(insns[2].mnemonic, "rts");
    assert!(insns[2].has_delay_slot);
    assert_eq!(insns[3].mnemonic, "nop");
    assert!(!insns[3].has_delay_slot);
}

#[test]
fn instructions_serialize_for_the_cli_json_output() {
    let value = serde_json::to_value(&d(0x4B0B)).unwrap();
    assert_eq!(value["mnemonic"], "jsr");
    assert_eq!(value["operands"], "@r11");
    assert_eq!(value["address"], BASE);
    assert_eq!(value["size"], 2);
    assert_eq!(value["is_call"], true);
}
