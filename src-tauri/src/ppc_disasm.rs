//! Shared PowerPC disassembler used by the GameCube/Wii (Gekko/Broadway)
//! and Xbox 360 (Xenon) backends.
//!
//! The decoder was originally written for GameCube ELF images (which this
//! tool historically read little-endian); [`disassemble_ppc_at`] exposes the
//! endianness explicitly so big-endian Xbox 360 code sections decode
//! correctly, while [`disassemble_ppc_instruction`] keeps the original
//! behaviour for existing callers.

use serde::{Deserialize, Serialize};

/// PowerPC register names
const REG_NAMES: [&str; 32] = [
    "r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7",
    "r8", "r9", "r10","r11","r12","r13","r14","r15",
    "r16","r17","r18","r19","r20","r21","r22","r23",
    "r24","r25","r26","r27","r28","r29","r30","r31",
];

/// Disassembled instruction result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PpcInstruction {
    pub address: u64,
    pub bytes: Vec<u8>,
    pub mnemonic: String,
    pub operands: String,
    pub size: usize,
}

// ===================== PowerPC Disassembler =====================

/// Read a 32-bit value from the ELF at given offset (little-endian)
#[inline]
fn read_u32(data: &[u8], offset: usize) -> u32 {
    if offset + 4 > data.len() {
        return 0;
    }
    u32::from_le_bytes([data[offset], data[offset+1], data[offset+2], data[offset+3]])
}

/// Format a register name from bits [4:0] of the instruction
fn format_reg<T: Into<u32>>(bits: T) -> &'static str {
    REG_NAMES[(bits.into() & 0x1F) as usize]
}

/// Disassemble PowerPC instructions from ELF data starting at given address
pub fn disassemble_ppc_instruction(data: &[u8], address: u64, max_instructions: usize) -> Vec<PpcInstruction> {
    let mut instructions = Vec::new();
    let start_offset = address as usize;

    while start_offset + (instructions.len() * 4) < data.len() && instructions.len() < max_instructions {
        let offset = start_offset + (instructions.len() * 4);
        if offset + 4 > data.len() {
            break;
        }

        let instr = read_u32(data, offset);
        let addr = address + (instructions.len() as u64 * 4);

        // Decode the instruction
        let (mnemonic, operands) = decode_ppc_instruction(instr, data, offset, addr);

        let bytes: Vec<u8> = data[offset..offset + 4].to_vec();
        instructions.push(PpcInstruction {
            address: addr,
            bytes,
            mnemonic: mnemonic.to_string(),
            operands: operands.to_string(),
            size: 4,
        });
    }

    instructions
}

/// Decode a PowerPC instruction word and return (mnemonic, operands).
///
/// Two-level dispatch on primary opcode then extended (XO/XL/X/A-form)
/// opcode, with opcode values cross-checked against GNU binutils'
/// `opcodes/ppc-opc.c`. Covers the common userland PowerPC ISA used by
/// GameCube/Wii (Gekko/Broadway) and Xbox 360 (Xenon) binaries, including
/// the usual assembler aliases (li, lis, mr, nop, blr, bctr, mflr, ...).
fn decode_ppc_instruction(instr: u32, _data: &[u8], _offset: usize, pc: u64) -> (String, String) {
    let op = instr >> 26;
    let rt = ((instr >> 21) & 0x1F) as u8; // RT / RS / D / FRT field
    let ra = ((instr >> 16) & 0x1F) as u8; // RA field
    let rb = ((instr >> 11) & 0x1F) as u8; // RB field
    let rc = (instr >> 6) & 0x1F; // RC field (float A-form)
    let xo10 = (instr >> 1) & 0x3FF; // X/XL/XO extended opcode
    let xo5 = (instr >> 1) & 0x1F; // A-form extended opcode
    let rcrec = instr & 1 != 0; // Rc bit

    let simm = (instr & 0xFFFF) as u16 as i16 as i32;
    let uimm = (instr & 0xFFFF) as u32;

    // Sign-extended branch displacements.
    let mut li = instr & 0x03FF_FFFC;
    if li & 0x0200_0000 != 0 {
        li |= 0xFC00_0000;
    }
    let li = li as i32;
    let mut bd = instr & 0x0000_FFFC;
    if bd & 0x0000_8000 != 0 {
        bd |= 0xFFFF_0000;
    }
    let bd = bd as i32;
    let aa = instr & 0x2 != 0;
    let lk = instr & 0x1 != 0;
    let branch_target = |disp: i32| -> u64 {
        if aa {
            disp as i64 as u64
        } else {
            (pc as i64 + disp as i64) as u64
        }
    };

    // Effective-address helper for D-form load/store: "disp(rA)".
    let d_form = |disp: i32| -> String {
        if ra == 0 {
            format!("{}(0)", disp)
        } else if disp >= 0 {
            format!("0x{:X}({})", disp, format_reg(ra))
        } else {
            format!("-0x{:X}({})", -(disp as i64), format_reg(ra))
        }
    };

    let dot = if rcrec { "." } else { "" };

    match op {
        // ---- Immediate arithmetic ----
        7 => (format!("mulli"), format!("{}, {}, {}", format_reg(rt), format_reg(ra), simm)),
        8 => (format!("subfic"), format!("{}, {}, {}", format_reg(rt), format_reg(ra), simm)),
        10 => {
            let crf = (instr >> 23) & 0x7;
            if crf == 0 {
                (format!("cmplwi"), format!("{}, 0x{:X}", format_reg(ra), uimm))
            } else {
                (format!("cmpli"), format!("cr{}, {}, 0x{:X}", crf, format_reg(ra), uimm))
            }
        }
        11 => {
            let crf = (instr >> 23) & 0x7;
            if crf == 0 {
                (format!("cmpwi"), format!("{}, {}", format_reg(ra), simm))
            } else {
                (format!("cmpi"), format!("cr{}, {}, {}", crf, format_reg(ra), simm))
            }
        }
        14 => {
            if ra == 0 {
                (format!("li"), format!("{}, {}", format_reg(rt), simm))
            } else {
                (format!("addi"), format!("{}, {}, {}", format_reg(rt), format_reg(ra), simm))
            }
        }
        15 => {
            if ra == 0 {
                (format!("lis"), format!("{}, 0x{:X}", format_reg(rt), uimm))
            } else {
                (format!("addis"), format!("{}, {}, {}", format_reg(rt), format_reg(ra), simm))
            }
        }
        24 => {
            if instr == 0x6000_0000 {
                (format!("nop"), String::new())
            } else {
                (format!("ori"), format!("{}, {}, 0x{:X}", format_reg(ra), format_reg(rt), uimm))
            }
        }
        25 => (format!("oris"), format!("{}, {}, 0x{:X}", format_reg(ra), format_reg(rt), uimm)),
        26 => (format!("xori"), format!("{}, {}, 0x{:X}", format_reg(ra), format_reg(rt), uimm)),
        27 => (format!("xoris"), format!("{}, {}, 0x{:X}", format_reg(ra), format_reg(rt), uimm)),
        28 => (format!("andi."), format!("{}, {}, 0x{:X}", format_reg(ra), format_reg(rt), uimm)),
        29 => (format!("andis."), format!("{}, {}, 0x{:X}", format_reg(ra), format_reg(rt), uimm)),

        // ---- Branches ----
        16 => {
            let bo = ((instr >> 21) & 0x1F) as u8;
            let bi = ((instr >> 16) & 0x1F) as u8;
            let target = branch_target(bd);
            let suf = if lk { "l" } else { "" };
            // Simplified mnemonics for common conditions on cr0.
            let cond_alias = match (bo, bi) {
                (12, 0) => Some("blt"),
                (4, 1) => Some("ble"),
                (12, 2) => Some("beq"),
                (4, 0) => Some("bge"),
                (12, 1) => Some("bgt"),
                (4, 2) => Some("bne"),
                (12, 3) => Some("bso"),
                (4, 3) => Some("bns"),
                _ => None,
            };
            if bo == 20 {
                (format!("b{}", suf), format!("0x{:X}", target))
            } else if bo == 16 {
                (format!("bdnz{}", suf), format!("0x{:X}", target))
            } else if bo == 18 {
                (format!("bdz{}", suf), format!("0x{:X}", target))
            } else if let Some(alias) = cond_alias {
                (format!("{}{}", alias, suf), format!("0x{:X}", target))
            } else {
                (format!("bc{}", suf), format!("{}, {}, 0x{:X}", bo, bi, target))
            }
        }
        17 => (format!("sc"), String::new()),
        18 => {
            let target = branch_target(li);
            if lk {
                (format!("bl"), format!("0x{:X}", target))
            } else {
                (format!("b"), format!("0x{:X}", target))
            }
        }

        // ---- XL group (op 19): CR ops, bclr/bcctr, rfi, isync ----
        19 => match xo10 {
            0 => {
                let crfd = (instr >> 23) & 0x7;
                let crfs = (instr >> 18) & 0x7;
                (format!("mcrf"), format!("cr{}, cr{}", crfd, crfs))
            }
            16 => {
                let bo = ((instr >> 21) & 0x1F) as u8;
                let bi = ((instr >> 16) & 0x1F) as u8;
                if bo == 20 && bi == 0 && !lk {
                    (format!("blr"), String::new())
                } else if bo == 20 && bi == 0 && lk {
                    (format!("blrl"), String::new())
                } else {
                    let alias = match (bo, bi) {
                        (12, 0) => "blt", (4, 1) => "ble", (12, 2) => "beq", (4, 0) => "bge",
                        (12, 1) => "bgt", (4, 2) => "bne", (12, 3) => "bso", (4, 3) => "bns",
                        _ => "",
                    };
                    if !alias.is_empty() {
                        (format!("{}lr{}", alias, if lk { "l" } else { "" }), String::new())
                    } else {
                        (format!("bclr{}", if lk { "l" } else { "" }), format!("{}, {}", bo, bi))
                    }
                }
            }
            18 => (format!("rfid"), String::new()),
            33 => (format!("crnor"), format!("{}, {}, {}", rt, ra, rb)),
            50 => (format!("rfi"), String::new()),
            129 => (format!("crandc"), format!("{}, {}, {}", rt, ra, rb)),
            150 => (format!("isync"), String::new()),
            193 => (format!("crxor"), format!("{}, {}, {}", rt, ra, rb)),
            225 => (format!("crnand"), format!("{}, {}, {}", rt, ra, rb)),
            257 => (format!("crand"), format!("{}, {}, {}", rt, ra, rb)),
            289 => (format!("creqv"), format!("{}, {}, {}", rt, ra, rb)),
            417 => (format!("crorc"), format!("{}, {}, {}", rt, ra, rb)),
            449 => (format!("cror"), format!("{}, {}, {}", rt, ra, rb)),
            528 => {
                let bo = ((instr >> 21) & 0x1F) as u8;
                if bo == 20 {
                    (format!("bctr{}", if lk { "l" } else { "" }), String::new())
                } else {
                    (format!("bcctr{}", if lk { "l" } else { "" }), String::new())
                }
            }
            _ => (format!(".word"), format!("0x{:08X}", instr)),
        },

        // ---- X/XO group (op 31) ----
        31 => {
            let oe = (instr >> 10) & 1 != 0;
            let osuf = if oe { "o" } else { "" };
            match xo10 {
                0 => {
                    let crf = (instr >> 23) & 0x7;
                    (format!("cmp"), format!("cr{}, {}, {}", crf, format_reg(ra), format_reg(rb)))
                }
                4 => (format!("tw"), format!("{}, {}, {}", rt, format_reg(ra), format_reg(rb))),
                8 => (format!("subfc{}{}", osuf, dot), format!("{}, {}, {}", format_reg(rt), format_reg(ra), format_reg(rb))),
                10 => (format!("addc{}{}", osuf, dot), format!("{}, {}, {}", format_reg(rt), format_reg(ra), format_reg(rb))),
                19 => (format!("mfcr"), format!("{}", format_reg(rt))),
                23 => (format!("lwzx"), format!("{}, {}, {}", format_reg(rt), format_reg(ra), format_reg(rb))),
                24 => (format!("slw{}", dot), format!("{}, {}, {}", format_reg(ra), format_reg(rt), format_reg(rb))),
                26 => (format!("cntlzw{}", dot), format!("{}, {}", format_reg(ra), format_reg(rt))),
                28 => (format!("and{}", dot), format!("{}, {}, {}", format_reg(ra), format_reg(rt), format_reg(rb))),
                32 => {
                    let crf = (instr >> 23) & 0x7;
                    (format!("cmpl"), format!("cr{}, {}, {}", crf, format_reg(ra), format_reg(rb)))
                }
                40 => (format!("subf{}{}", osuf, dot), format!("{}, {}, {}", format_reg(rt), format_reg(ra), format_reg(rb))),
                60 => (format!("andc{}", dot), format!("{}, {}, {}", format_reg(ra), format_reg(rt), format_reg(rb))),
                87 => (format!("lbzx"), format!("{}, {}, {}", format_reg(rt), format_reg(ra), format_reg(rb))),
                104 => (format!("neg{}{}", osuf, dot), format!("{}, {}", format_reg(rt), format_reg(ra))),
                124 => {
                    // nor rA, rS, rB; 'not' alias when rS == rB
                    if rt == rb {
                        (format!("not{}", dot), format!("{}, {}", format_reg(ra), format_reg(rt)))
                    } else {
                        (format!("nor{}", dot), format!("{}, {}, {}", format_reg(ra), format_reg(rt), format_reg(rb)))
                    }
                }
                136 => (format!("subfe{}{}", osuf, dot), format!("{}, {}, {}", format_reg(rt), format_reg(ra), format_reg(rb))),
                138 => (format!("adde{}{}", osuf, dot), format!("{}, {}, {}", format_reg(rt), format_reg(ra), format_reg(rb))),
                144 => {
                    let crm = (instr >> 12) & 0xFF;
                    (format!("mtcrf"), format!("0x{:02X}, {}", crm, format_reg(rt)))
                }
                151 => (format!("stwx"), format!("{}, {}, {}", format_reg(rt), format_reg(ra), format_reg(rb))),
                200 => (format!("subfze{}{}", osuf, dot), format!("{}, {}", format_reg(rt), format_reg(ra))),
                202 => (format!("addze{}{}", osuf, dot), format!("{}, {}", format_reg(rt), format_reg(ra))),
                215 => (format!("stbx"), format!("{}, {}, {}", format_reg(rt), format_reg(ra), format_reg(rb))),
                232 => (format!("subfme{}{}", osuf, dot), format!("{}, {}", format_reg(rt), format_reg(ra))),
                234 => (format!("addme{}{}", osuf, dot), format!("{}, {}", format_reg(rt), format_reg(ra))),
                235 => (format!("mullw{}{}", osuf, dot), format!("{}, {}, {}", format_reg(rt), format_reg(ra), format_reg(rb))),
                266 => (format!("add{}{}", osuf, dot), format!("{}, {}, {}", format_reg(rt), format_reg(ra), format_reg(rb))),
                279 => (format!("lhzx"), format!("{}, {}, {}", format_reg(rt), format_reg(ra), format_reg(rb))),
                284 => (format!("eqv{}", dot), format!("{}, {}, {}", format_reg(ra), format_reg(rt), format_reg(rb))),
                316 => (format!("xor{}", dot), format!("{}, {}, {}", format_reg(ra), format_reg(rt), format_reg(rb))),
                339 => {
                    let spr = ((((instr >> 11) & 0x1F) as u16) << 5) | ((instr >> 16) & 0x1F) as u16;
                    match spr {
                        1 => (format!("mfxer"), format!("{}", format_reg(rt))),
                        8 => (format!("mflr"), format!("{}", format_reg(rt))),
                        9 => (format!("mfctr"), format!("{}", format_reg(rt))),
                        _ => (format!("mfspr"), format!("{}, {}", format_reg(rt), spr_name(spr))),
                    }
                }
                343 => (format!("lhax"), format!("{}, {}, {}", format_reg(rt), format_reg(ra), format_reg(rb))),
                407 => (format!("sthx"), format!("{}, {}, {}", format_reg(rt), format_reg(ra), format_reg(rb))),
                412 => (format!("orc{}", dot), format!("{}, {}, {}", format_reg(ra), format_reg(rt), format_reg(rb))),
                444 => {
                    // or rA, rS, rB; 'mr' alias when rS == rB
                    if rt == rb {
                        (format!("mr{}", dot), format!("{}, {}", format_reg(ra), format_reg(rt)))
                    } else {
                        (format!("or{}", dot), format!("{}, {}, {}", format_reg(ra), format_reg(rt), format_reg(rb)))
                    }
                }
                459 => (format!("divwu{}{}", osuf, dot), format!("{}, {}, {}", format_reg(rt), format_reg(ra), format_reg(rb))),
                467 => {
                    let spr = ((((instr >> 11) & 0x1F) as u16) << 5) | ((instr >> 16) & 0x1F) as u16;
                    match spr {
                        1 => (format!("mtxer"), format!("{}", format_reg(rt))),
                        8 => (format!("mtlr"), format!("{}", format_reg(rt))),
                        9 => (format!("mtctr"), format!("{}", format_reg(rt))),
                        _ => (format!("mtspr"), format!("{}, {}", spr_name(spr), format_reg(rt))),
                    }
                }
                476 => (format!("nand{}", dot), format!("{}, {}, {}", format_reg(ra), format_reg(rt), format_reg(rb))),
                491 => (format!("divw{}{}", osuf, dot), format!("{}, {}, {}", format_reg(rt), format_reg(ra), format_reg(rb))),
                536 => (format!("srw{}", dot), format!("{}, {}, {}", format_reg(ra), format_reg(rt), format_reg(rb))),
                792 => (format!("sraw{}", dot), format!("{}, {}, {}", format_reg(ra), format_reg(rt), format_reg(rb))),
                824 => (format!("srawi{}", dot), format!("{}, {}, {}", format_reg(ra), format_reg(rt), rb)),
                922 => (format!("extsh{}", dot), format!("{}, {}", format_reg(ra), format_reg(rt))),
                954 => (format!("extsb{}", dot), format!("{}, {}", format_reg(ra), format_reg(rt))),
                _ => (format!(".word"), format!("0x{:08X}", instr)),
            }
        }

        // ---- mullhw group (op 4) ----
        4 => match xo10 {
            424 => (format!("mullhw{}", dot), format!("{}, {}, {}", format_reg(rt), format_reg(ra), format_reg(rb))),
            392 => (format!("mullhwu{}", dot), format!("{}, {}, {}", format_reg(rt), format_reg(ra), format_reg(rb))),
            _ => (format!(".word"), format!("0x{:08X}", instr)),
        },

        // ---- D-form loads/stores ----
        32 => (format!("lwz"), format!("{}, {}", format_reg(rt), d_form(simm))),
        33 => (format!("lwzu"), format!("{}, {}", format_reg(rt), d_form(simm))),
        34 => (format!("lbz"), format!("{}, {}", format_reg(rt), d_form(simm))),
        35 => (format!("lbzu"), format!("{}, {}", format_reg(rt), d_form(simm))),
        36 => (format!("stw"), format!("{}, {}", format_reg(rt), d_form(simm))),
        37 => (format!("stwu"), format!("{}, {}", format_reg(rt), d_form(simm))),
        38 => (format!("stb"), format!("{}, {}", format_reg(rt), d_form(simm))),
        39 => (format!("stbu"), format!("{}, {}", format_reg(rt), d_form(simm))),
        40 => (format!("lhz"), format!("{}, {}", format_reg(rt), d_form(simm))),
        41 => (format!("lhzu"), format!("{}, {}", format_reg(rt), d_form(simm))),
        42 => (format!("lha"), format!("{}, {}", format_reg(rt), d_form(simm))),
        43 => (format!("lhau"), format!("{}, {}", format_reg(rt), d_form(simm))),
        44 => (format!("sth"), format!("{}, {}", format_reg(rt), d_form(simm))),
        45 => (format!("sthu"), format!("{}, {}", format_reg(rt), d_form(simm))),
        46 => (format!("lmw"), format!("{}, {}", format_reg(rt), d_form(simm))),
        47 => (format!("stmw"), format!("{}, {}", format_reg(rt), d_form(simm))),
        48 => (format!("lfs"), format!("f{}, {}", rt, d_form(simm))),
        49 => (format!("lfsu"), format!("f{}, {}", rt, d_form(simm))),
        50 => (format!("lfd"), format!("f{}, {}", rt, d_form(simm))),
        51 => (format!("lfdu"), format!("f{}, {}", rt, d_form(simm))),
        52 => (format!("stfs"), format!("f{}, {}", rt, d_form(simm))),
        53 => (format!("stfsu"), format!("f{}, {}", rt, d_form(simm))),
        54 => (format!("stfd"), format!("f{}, {}", rt, d_form(simm))),
        55 => (format!("stfdu"), format!("f{}, {}", rt, d_form(simm))),

        // ---- DS-form 64-bit loads/stores (Xenon is PPC64) ----
        58 | 62 => {
            let mut ds = (instr >> 2) & 0x3FFF;
            if ds & 0x2000 != 0 {
                ds |= 0xFFFF_C000;
            }
            let disp = ((ds as u16 as i16) as i32) << 2;
            let name = match (op, instr & 0x3) {
                (58, 0) => "ld",
                (58, 1) => "ldu",
                (58, 2) => "lwa",
                (62, 0) => "std",
                (62, 1) => "stdu",
                _ => ".word",
            };
            if name == ".word" {
                (format!(".word"), format!("0x{:08X}", instr))
            } else {
                (format!("{}", name), format!("{}, {}", format_reg(rt), d_form(disp)))
            }
        }

        // ---- Single-precision float A-form (op 59) ----
        59 => match xo5 {
            18 => (format!("fdivs{}", dot), format!("f{}, f{}, f{}", rt, ra, rb)),
            20 => (format!("fsubs{}", dot), format!("f{}, f{}, f{}", rt, ra, rb)),
            21 => (format!("fadds{}", dot), format!("f{}, f{}, f{}", rt, ra, rb)),
            24 => (format!("fres{}", dot), format!("f{}, f{}", rt, rb)),
            25 => (format!("fmuls{}", dot), format!("f{}, f{}, f{}", rt, ra, rc as u8)),
            28 => (format!("fmsubs{}", dot), format!("f{}, f{}, f{}, f{}", rt, ra, rc as u8, rb)),
            29 => (format!("fmadds{}", dot), format!("f{}, f{}, f{}, f{}", rt, ra, rc as u8, rb)),
            30 => (format!("fnmsubs{}", dot), format!("f{}, f{}, f{}, f{}", rt, ra, rc as u8, rb)),
            31 => (format!("fnmadds{}", dot), format!("f{}, f{}, f{}, f{}", rt, ra, rc as u8, rb)),
            _ => (format!(".word"), format!("0x{:08X}", instr)),
        },

        // ---- Double-precision float + float X-form (op 63) ----
        63 => match xo5 {
            18 => (format!("fdiv{}", dot), format!("f{}, f{}, f{}", rt, ra, rb)),
            20 => (format!("fsub{}", dot), format!("f{}, f{}, f{}", rt, ra, rb)),
            21 => (format!("fadd{}", dot), format!("f{}, f{}, f{}", rt, ra, rb)),
            25 => (format!("fmul{}", dot), format!("f{}, f{}, f{}", rt, ra, rc as u8)),
            28 => (format!("fmsub{}", dot), format!("f{}, f{}, f{}, f{}", rt, ra, rc as u8, rb)),
            29 => (format!("fmadd{}", dot), format!("f{}, f{}, f{}, f{}", rt, ra, rc as u8, rb)),
            30 => (format!("fnmsub{}", dot), format!("f{}, f{}, f{}, f{}", rt, ra, rc as u8, rb)),
            31 => (format!("fnmadd{}", dot), format!("f{}, f{}, f{}, f{}", rt, ra, rc as u8, rb)),
            _ => match xo10 {
                0 => {
                    let crf = (instr >> 23) & 0x7;
                    (format!("fcmpu"), format!("cr{}, f{}, f{}", crf, ra, rb))
                }
                12 => (format!("frsp{}", dot), format!("f{}, f{}", rt, rb)),
                14 => (format!("fctiw{}", dot), format!("f{}, f{}", rt, rb)),
                15 => (format!("fctiwz{}", dot), format!("f{}, f{}", rt, rb)),
                32 => {
                    let crf = (instr >> 23) & 0x7;
                    (format!("fcmpo"), format!("cr{}, f{}, f{}", crf, ra, rb))
                }
                40 => (format!("fneg{}", dot), format!("f{}, f{}", rt, rb)),
                72 => (format!("fmr{}", dot), format!("f{}, f{}", rt, rb)),
                264 => (format!("fabs{}", dot), format!("f{}, f{}", rt, rb)),
                _ => (format!(".word"), format!("0x{:08X}", instr)),
            },
        },

        _ => (format!(".word"), format!("0x{:08X}", instr)),
    }
}

/// Name a special-purpose register number for mfspr/mtspr display.
fn spr_name(spr: u16) -> String {
    match spr {
        1 => "xer".to_string(),
        8 => "lr".to_string(),
        9 => "ctr".to_string(),
        18 => "dsisr".to_string(),
        19 => "dar".to_string(),
        22 => "dec".to_string(),
        26 => "srr0".to_string(),
        27 => "srr1".to_string(),
        272..=275 => format!("sprg{}", spr - 272),
        287 => "pvr".to_string(),
        _ => format!("spr{}", spr),
    }
}


// ===================== Endianness-aware public API =====================

/// PowerPC instruction stream endianness.
///
/// GameCube/Wii and Xbox 360 code is big-endian; the historical GameCube ELF
/// path in this tool read words little-endian, so both are supported.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PpcEndian {
    Little,
    Big,
}

#[inline]
fn read_u32_be(data: &[u8], offset: usize) -> u32 {
    if offset + 4 > data.len() {
        return 0;
    }
    u32::from_be_bytes([data[offset], data[offset + 1], data[offset + 2], data[offset + 3]])
}

/// Disassemble PowerPC instructions with explicit file offset, display
/// address, and endianness.
///
/// * `data` - buffer containing the instruction bytes
/// * `file_offset` - byte offset inside `data` where decoding starts
/// * `display_address` - virtual address shown for the first instruction
/// * `max_instructions` - decode cap
/// * `endian` - how 32-bit instruction words are read from `data`
pub fn disassemble_ppc_at(
    data: &[u8],
    file_offset: usize,
    display_address: u64,
    max_instructions: usize,
    endian: PpcEndian,
) -> Vec<PpcInstruction> {
    let mut instructions = Vec::new();

    while file_offset + (instructions.len() * 4) < data.len() && instructions.len() < max_instructions {
        let offset = file_offset + (instructions.len() * 4);
        if offset + 4 > data.len() {
            break;
        }

        let instr = match endian {
            PpcEndian::Little => read_u32(data, offset),
            PpcEndian::Big => read_u32_be(data, offset),
        };
        let addr = display_address + (instructions.len() as u64 * 4);

        let (mnemonic, operands) = decode_ppc_instruction(instr, data, offset, addr);

        let bytes: Vec<u8> = data[offset..offset + 4].to_vec();
        instructions.push(PpcInstruction {
            address: addr,
            bytes,
            mnemonic: mnemonic.to_string(),
            operands: operands.to_string(),
            size: 4,
        });
    }

    instructions
}
