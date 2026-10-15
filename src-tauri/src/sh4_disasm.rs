//! SH-4 (Hitachi SH7091) disassembler — Dreamcast / Naomi machine code.
//!
//! Decodes the fixed 16-bit SH-4 instruction set: the CPU at the heart of
//! the Sega Dreamcast and Naomi arcade boards, and the ISA that SH-4
//! recompilation projects (dcrecomp-style static recompiles) work on. This
//! is the analysis tier — disassembly for xrefs / function discovery — not
//! a recompiler.
//!
//! Every table entry and the address arithmetic were transcribed from
//! MAME's `src/devices/cpu/sh/sh_dasm.cpp` (BSD-3-Clause) using its SH-4
//! specific (`sh34`) groups, then cross-checked against:
//!
//! - MAME's SH-2/SH-4 executors (`sh.cpp` / `sh4.cpp`) for semantics:
//!   branch targets and PC-relative literal addresses are computed from
//!   (instruction address + 4) — confirmed by BSR/JSR writing
//!   `PR = instr + 4`; `LDC Rn,Rm_BANK` moves `Rn` (bits 11:8) into bank
//!   slot `Rm & 7` (bits 7:4) and `STC Rm_BANK,Rn` is the reverse;
//! - QEMU's `target/sh4/translate.c` for the FPU corner cases:
//!   FSCHG = 0xF3FD, FRCHG = 0xFBFD, FTRV requires bits 9:8 == 01
//!   (0xF1FD/0xF5FD/0xF9FD/0xFDFD), and FIPR/FMAC/FCNVSD/FSRRA/FLDI*
//!   as tabled below. (FSCA is an SH-4A addition that does not exist on
//!   the Dreamcast SH7091; it is rendered MAME-style for completeness.)
//!
//! Rendering is lowercase (`mov.l r14, @-r15`), matching the MIPS
//! disassembler's style. Reserved/unknown words render as `.word 0x…`
//! instead of guessing.

use serde::{Deserialize, Serialize};

/// One decoded SH-4 instruction (fixed 16-bit encoding).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Sh4Instruction {
    /// Display (virtual) address — 0x8C008000-based for Dreamcast user code.
    pub address: u32,
    /// Offset of this instruction inside the decoded buffer.
    pub file_offset: usize,
    /// The raw 16-bit encoding (little-endian on Dreamcast).
    pub raw: u16,
    pub mnemonic: String,
    pub operands: String,
    /// SH-4 instructions are always 2 bytes.
    pub size: usize,
    /// Any control transfer (branch, call or return).
    pub is_branch: bool,
    /// Subroutine call (jsr / bsr / bsrf).
    pub is_call: bool,
    /// Return from subroutine / exception (rts / rte).
    pub is_return: bool,
    /// The next instruction is a delay slot, executed before the transfer.
    pub has_delay_slot: bool,
    /// Static branch target when computable (immediate displacement forms).
    pub branch_target: Option<u32>,
    /// Effective address of a PC-relative data/address load
    /// (mov.w / mov.l @(disp,PC) and mova).
    pub literal_address: Option<u32>,
}

#[derive(Debug, Clone)]
struct Dec {
    mnemonic: String,
    operands: String,
    is_branch: bool,
    is_call: bool,
    is_return: bool,
    has_delay_slot: bool,
    branch_target: Option<u32>,
    literal_address: Option<u32>,
}

impl Dec {
    fn plain(mnemonic: &str, operands: String) -> Dec {
        Dec {
            mnemonic: mnemonic.to_string(),
            operands,
            is_branch: false,
            is_call: false,
            is_return: false,
            has_delay_slot: false,
            branch_target: None,
            literal_address: None,
        }
    }

    fn unknown(word: u16) -> Dec {
        Dec::plain(".word", format!("0x{word:04x}"))
    }

    /// Immediate-displacement branch with a computable target.
    fn branch_to(mnemonic: &str, target: u32, delay: bool) -> Dec {
        Dec {
            is_branch: true,
            has_delay_slot: delay,
            branch_target: Some(target),
            ..Dec::plain(mnemonic, format!("0x{target:08x}"))
        }
    }

    /// Register/computed branch (jsr, jmp, braf, bsrf).
    fn jump_reg(mnemonic: &str, operands: String, delay: bool, call: bool) -> Dec {
        Dec {
            is_branch: true,
            has_delay_slot: delay,
            is_call: call,
            ..Dec::plain(mnemonic, operands)
        }
    }

    /// rts / rte.
    fn ret(mnemonic: &str) -> Dec {
        Dec {
            is_branch: true,
            is_return: true,
            has_delay_slot: true,
            ..Dec::plain(mnemonic, String::new())
        }
    }

    /// PC-relative data/address load with a computable literal address.
    fn literal(mnemonic: &str, operands: String, literal: u32) -> Dec {
        Dec {
            literal_address: Some(literal),
            ..Dec::plain(mnemonic, operands)
        }
    }

    /// Mark a branch as a subroutine call (bsr).
    fn call(mut self) -> Dec {
        self.is_call = true;
        self
    }
}

fn r(i: u32) -> String {
    format!("r{i}")
}

fn sext(value: u32, bits: u32) -> i32 {
    let shift = 32 - bits;
    ((value << shift) as i32) >> shift
}

/// SH-4 computes every PC-relative address from (instruction address + 4).
fn pc_rel_base(address: u32) -> u32 {
    address.wrapping_add(4)
}

fn branch_target(address: u32, disp: i32) -> u32 {
    (pc_rel_base(address) as i64 + disp as i64 * 2) as u32
}

/// mov.l / mova literal addresses are 4-byte aligned off the PC-relative base.
fn aligned_literal(address: u32, disp: u32) -> u32 {
    (pc_rel_base(address) & !3).wrapping_add(disp)
}

fn decode(word: u16, address: u32, file_offset: usize) -> Sh4Instruction {
    let n = ((word >> 8) & 0xF) as u32; // Rn field (bits 11:8)
    let m = ((word >> 4) & 0xF) as u32; // Rm field (bits 7:4)
    let d4 = (word & 0xF) as u32;
    let d8 = (word & 0xFF) as u32;
    let disp12 = sext((word & 0xFFF) as u32, 12);
    let s8 = sext(d8, 8);

    let dec = match word >> 12 {
        // ---------------------------------------------------------------- 0
        0x0 => match word & 0xF {
            0x2 => {
                if word & 0x80 != 0 {
                    Dec::plain("stc", format!("r{}_bank, {}", m & 7, r(n)))
                } else {
                    match word & 0x70 {
                        0x00 => Dec::plain("stc", format!("sr, {}", r(n))),
                        0x10 => Dec::plain("stc", format!("gbr, {}", r(n))),
                        0x20 => Dec::plain("stc", format!("vbr, {}", r(n))),
                        0x30 => Dec::plain("stc", format!("ssr, {}", r(n))),
                        0x40 => Dec::plain("stc", format!("spc, {}", r(n))),
                        _ => Dec::unknown(word),
                    }
                }
            }
            0x3 => match word & 0xF0 {
                0x00 => Dec::jump_reg("bsrf", r(n), true, true),
                0x20 => Dec::jump_reg("braf", r(n), true, false),
                0x80 => Dec::plain("pref", format!("@{}", r(n))),
                0x90 => Dec::plain("ocbi", format!("@{}", r(n))),
                0xA0 => Dec::plain("ocbp", format!("@{}", r(n))),
                0xB0 => Dec::plain("ocbwb", format!("@{}", r(n))),
                0xC0 => Dec::plain("movca.l", format!("r0, @{}", r(n))),
                _ => Dec::unknown(word),
            },
            0x4 => Dec::plain("mov.b", format!("{}, @(r0, {})", r(m), r(n))),
            0x5 => Dec::plain("mov.w", format!("{}, @(r0, {})", r(m), r(n))),
            0x6 => Dec::plain("mov.l", format!("{}, @(r0, {})", r(m), r(n))),
            0x7 => Dec::plain("mul.l", format!("{}, {}", r(m), r(n))),
            0x8 => match word & 0x70 {
                0x00 => Dec::plain("clrt", String::new()),
                0x10 => Dec::plain("sett", String::new()),
                0x20 => Dec::plain("clrmac", String::new()),
                0x30 => Dec::plain("ldtlb", String::new()),
                0x40 => Dec::plain("clrs", String::new()),
                0x50 => Dec::plain("sets", String::new()),
                _ => Dec::unknown(word),
            },
            0x9 => match word & 0x30 {
                0x00 => Dec::plain("nop", String::new()),
                0x10 => Dec::plain("div0u", String::new()),
                0x20 => Dec::plain("movt", r(n)),
                _ => Dec::unknown(word),
            },
            0xA => match word & 0x70 {
                0x00 => Dec::plain("sts", format!("mach, {}", r(n))),
                0x10 => Dec::plain("sts", format!("macl, {}", r(n))),
                0x20 => Dec::plain("sts", format!("pr, {}", r(n))),
                0x30 => Dec::plain("stc", format!("sgr, {}", r(n))),
                0x50 => Dec::plain("sts", format!("fpul, {}", r(n))),
                0x60 => Dec::plain("sts", format!("fpscr, {}", r(n))),
                0x70 => Dec::plain("stc", format!("dbr, {}", r(n))),
                _ => Dec::unknown(word),
            },
            0xB => match word & 0x30 {
                0x00 => Dec::ret("rts"),
                0x10 => Dec::plain("sleep", String::new()),
                0x20 => Dec::ret("rte"),
                _ => Dec::unknown(word),
            },
            0xC => Dec::plain("mov.b", format!("@(r0, {}), {}", r(m), r(n))),
            0xD => Dec::plain("mov.w", format!("@(r0, {}), {}", r(m), r(n))),
            0xE => Dec::plain("mov.l", format!("@(r0, {}), {}", r(m), r(n))),
            0xF => Dec::plain("mac.l", format!("@{}+, @{}+", r(n), r(m))),
            _ => Dec::unknown(word),
        },
        // ---------------------------------------------------------------- 1
        0x1 => Dec::plain("mov.l", format!("{}, @(0x{:x}, {})", r(m), d4 * 4, r(n))),
        // ---------------------------------------------------------------- 2
        0x2 => match word & 0xF {
            0x0 => Dec::plain("mov.b", format!("{}, @{}", r(m), r(n))),
            0x1 => Dec::plain("mov.w", format!("{}, @{}", r(m), r(n))),
            0x2 => Dec::plain("mov.l", format!("{}, @{}", r(m), r(n))),
            0x4 => Dec::plain("mov.b", format!("{}, @-{}", r(m), r(n))),
            0x5 => Dec::plain("mov.w", format!("{}, @-{}", r(m), r(n))),
            0x6 => Dec::plain("mov.l", format!("{}, @-{}", r(m), r(n))),
            0x7 => Dec::plain("div0s", format!("{}, {}", r(m), r(n))),
            0x8 => Dec::plain("tst", format!("{}, {}", r(m), r(n))),
            0x9 => Dec::plain("and", format!("{}, {}", r(m), r(n))),
            0xA => Dec::plain("xor", format!("{}, {}", r(m), r(n))),
            0xB => Dec::plain("or", format!("{}, {}", r(m), r(n))),
            0xC => Dec::plain("cmp/str", format!("{}, {}", r(m), r(n))),
            0xD => Dec::plain("xtrct", format!("{}, {}", r(m), r(n))),
            0xE => Dec::plain("mulu.w", format!("{}, {}", r(m), r(n))),
            0xF => Dec::plain("muls.w", format!("{}, {}", r(m), r(n))),
            _ => Dec::unknown(word),
        },
        // ---------------------------------------------------------------- 3
        0x3 => match word & 0xF {
            0x0 => Dec::plain("cmp/eq", format!("{}, {}", r(m), r(n))),
            0x2 => Dec::plain("cmp/hs", format!("{}, {}", r(m), r(n))),
            0x3 => Dec::plain("cmp/ge", format!("{}, {}", r(m), r(n))),
            0x4 => Dec::plain("div1", format!("{}, {}", r(m), r(n))),
            0x5 => Dec::plain("dmulu.l", format!("{}, {}", r(m), r(n))),
            0x6 => Dec::plain("cmp/hi", format!("{}, {}", r(m), r(n))),
            0x7 => Dec::plain("cmp/gt", format!("{}, {}", r(m), r(n))),
            0x8 => Dec::plain("sub", format!("{}, {}", r(m), r(n))),
            0xA => Dec::plain("subc", format!("{}, {}", r(m), r(n))),
            0xB => Dec::plain("subv", format!("{}, {}", r(m), r(n))),
            0xC => Dec::plain("add", format!("{}, {}", r(m), r(n))),
            0xD => Dec::plain("dmuls.l", format!("{}, {}", r(m), r(n))),
            0xE => Dec::plain("addc", format!("{}, {}", r(m), r(n))),
            0xF => Dec::plain("addv", format!("{}, {}", r(m), r(n))),
            _ => Dec::unknown(word),
        },
        // ---------------------------------------------------------------- 4
        0x4 => match word & 0xF {
            0x0 => match word & 0x30 {
                0x00 => Dec::plain("shll", r(n)),
                0x10 => Dec::plain("dt", r(n)),
                0x20 => Dec::plain("shal", r(n)),
                _ => Dec::unknown(word),
            },
            0x1 => match word & 0x30 {
                0x00 => Dec::plain("shlr", r(n)),
                0x10 => Dec::plain("cmp/pz", r(n)),
                0x20 => Dec::plain("shar", r(n)),
                _ => Dec::unknown(word),
            },
            0x2 => match word & 0xF0 {
                0x00 => Dec::plain("sts.l", format!("mach, @-{}", r(n))),
                0x10 => Dec::plain("sts.l", format!("macl, @-{}", r(n))),
                0x20 => Dec::plain("sts.l", format!("pr, @-{}", r(n))),
                0x30 => Dec::plain("stc.l", format!("sgr, @-{}", r(n))),
                0x50 => Dec::plain("sts.l", format!("fpul, @-{}", r(n))),
                0x60 => Dec::plain("stc.l", format!("fpscr, @-{}", r(n))),
                0xF0 => Dec::plain("stc.l", format!("dbr, @-{}", r(n))),
                _ => Dec::unknown(word),
            },
            0x3 => {
                if word & 0x80 != 0 {
                    Dec::plain("stc.l", format!("r{}_bank, @-{}", m & 7, r(n)))
                } else {
                    match word & 0x70 {
                        0x00 => Dec::plain("stc.l", format!("sr, @-{}", r(n))),
                        0x10 => Dec::plain("stc.l", format!("gbr, @-{}", r(n))),
                        0x20 => Dec::plain("stc.l", format!("vbr, @-{}", r(n))),
                        0x30 => Dec::plain("stc.l", format!("ssr, @-{}", r(n))),
                        0x40 => Dec::plain("stc.l", format!("spc, @-{}", r(n))),
                        _ => Dec::unknown(word),
                    }
                }
            }
            0x4 => match word & 0x30 {
                0x00 => Dec::plain("rotl", r(n)),
                0x20 => Dec::plain("rotcl", r(n)),
                _ => Dec::unknown(word),
            },
            0x5 => match word & 0x30 {
                0x00 => Dec::plain("rotr", r(n)),
                0x10 => Dec::plain("cmp/pl", r(n)),
                0x20 => Dec::plain("rotcr", r(n)),
                _ => Dec::unknown(word),
            },
            0x6 => match word & 0xF0 {
                0x00 => Dec::plain("lds.l", format!("@{}+, mach", r(n))),
                0x10 => Dec::plain("lds.l", format!("@{}+, macl", r(n))),
                0x20 => Dec::plain("lds.l", format!("@{}+, pr", r(n))),
                0x50 => Dec::plain("lds.l", format!("@{}+, fpul", r(n))),
                0x60 => Dec::plain("lds.l", format!("@{}+, fpscr", r(n))),
                0xF0 => Dec::plain("ldc.l", format!("@{}+, dbr", r(n))),
                _ => Dec::unknown(word),
            },
            0x7 => {
                if word & 0x80 != 0 {
                    Dec::plain("ldc.l", format!("@{}+, r{}_bank", r(n), m & 7))
                } else {
                    match word & 0x70 {
                        0x00 => Dec::plain("ldc.l", format!("@{}+, sr", r(n))),
                        0x10 => Dec::plain("ldc.l", format!("@{}+, gbr", r(n))),
                        0x20 => Dec::plain("ldc.l", format!("@{}+, vbr", r(n))),
                        0x30 => Dec::plain("ldc.l", format!("@{}+, ssr", r(n))),
                        0x40 => Dec::plain("ldc.l", format!("@{}+, spc", r(n))),
                        _ => Dec::unknown(word),
                    }
                }
            }
            0x8 => match word & 0x30 {
                0x00 => Dec::plain("shll2", r(n)),
                0x10 => Dec::plain("shll8", r(n)),
                0x20 => Dec::plain("shll16", r(n)),
                _ => Dec::unknown(word),
            },
            0x9 => match word & 0x30 {
                0x00 => Dec::plain("shlr2", r(n)),
                0x10 => Dec::plain("shlr8", r(n)),
                0x20 => Dec::plain("shlr16", r(n)),
                _ => Dec::unknown(word),
            },
            0xA => match word & 0xF0 {
                0x00 => Dec::plain("lds", format!("{}, mach", r(n))),
                0x10 => Dec::plain("lds", format!("{}, macl", r(n))),
                0x20 => Dec::plain("lds", format!("{}, pr", r(n))),
                0x50 => Dec::plain("lds", format!("{}, fpul", r(n))),
                0x60 => Dec::plain("lds", format!("{}, fpscr", r(n))),
                0xF0 => Dec::plain("ldc", format!("{}, dbr", r(n))),
                _ => Dec::unknown(word),
            },
            0xB => match word & 0x30 {
                0x00 => Dec::jump_reg("jsr", format!("@{}", r(n)), true, true),
                0x10 => Dec::plain("tas.b", format!("@{}", r(n))),
                0x20 => Dec::jump_reg("jmp", format!("@{}", r(n)), true, false),
                _ => Dec::unknown(word),
            },
            0xC => Dec::plain("shad", format!("{}, {}", r(m), r(n))),
            0xD => Dec::plain("shld", format!("{}, {}", r(m), r(n))),
            0xE => {
                if word & 0x80 != 0 {
                    // Verified against MAME's LDCRBANK executor: the source is
                    // Rn (bits 11:8) and the bank slot index is Rm & 7.
                    Dec::plain("ldc", format!("{}, r{}_bank", r(n), m & 7))
                } else {
                    match word & 0x70 {
                        0x00 => Dec::plain("ldc", format!("{}, sr", r(n))),
                        0x10 => Dec::plain("ldc", format!("{}, gbr", r(n))),
                        0x20 => Dec::plain("ldc", format!("{}, vbr", r(n))),
                        0x30 => Dec::plain("ldc", format!("{}, ssr", r(n))),
                        0x40 => Dec::plain("ldc", format!("{}, spc", r(n))),
                        _ => Dec::unknown(word),
                    }
                }
            }
            0xF => Dec::plain("mac.w", format!("@{}+, @{}+", r(n), r(m))),
            _ => Dec::unknown(word),
        },
        // ---------------------------------------------------------------- 5
        0x5 => Dec::plain("mov.l", format!("@(0x{:x}, {}), {}", d4 * 4, r(m), r(n))),
        // ---------------------------------------------------------------- 6
        0x6 => match word & 0xF {
            0x0 => Dec::plain("mov.b", format!("@{}, {}", r(m), r(n))),
            0x1 => Dec::plain("mov.w", format!("@{}, {}", r(m), r(n))),
            0x2 => Dec::plain("mov.l", format!("@{}, {}", r(m), r(n))),
            0x3 => Dec::plain("mov", format!("{}, {}", r(m), r(n))),
            0x4 => Dec::plain("mov.b", format!("@{}+, {}", r(m), r(n))),
            0x5 => Dec::plain("mov.w", format!("@{}+, {}", r(m), r(n))),
            0x6 => Dec::plain("mov.l", format!("@{}+, {}", r(m), r(n))),
            0x7 => Dec::plain("not", format!("{}, {}", r(m), r(n))),
            0x8 => Dec::plain("swap.b", format!("{}, {}", r(m), r(n))),
            0x9 => Dec::plain("swap.w", format!("{}, {}", r(m), r(n))),
            0xA => Dec::plain("negc", format!("{}, {}", r(m), r(n))),
            0xB => Dec::plain("neg", format!("{}, {}", r(m), r(n))),
            0xC => Dec::plain("extu.b", format!("{}, {}", r(m), r(n))),
            0xD => Dec::plain("extu.w", format!("{}, {}", r(m), r(n))),
            0xE => Dec::plain("exts.b", format!("{}, {}", r(m), r(n))),
            0xF => Dec::plain("exts.w", format!("{}, {}", r(m), r(n))),
            _ => Dec::unknown(word),
        },
        // ---------------------------------------------------------------- 7
        0x7 => Dec::plain("add", format!("#{}, {}", s8, r(n))),
        // ---------------------------------------------------------------- 8
        0x8 => match n {
            0x0 => Dec::plain("mov.b", format!("r0, @(0x{:x}, {})", d4, r(m))),
            0x1 => Dec::plain("mov.w", format!("r0, @(0x{:x}, {})", d4 * 2, r(m))),
            0x4 => Dec::plain("mov.b", format!("@(0x{:x}, {}), r0", d4, r(m))),
            0x5 => Dec::plain("mov.w", format!("@(0x{:x}, {}), r0", d4 * 2, r(m))),
            0x8 => Dec::plain("cmp/eq", format!("#{}, r0", s8)),
            0x9 => Dec::branch_to("bt", branch_target(address, s8), false),
            0xB => Dec::branch_to("bf", branch_target(address, s8), false),
            0xD => Dec::branch_to("bt.s", branch_target(address, s8), true),
            0xF => Dec::branch_to("bf.s", branch_target(address, s8), true),
            _ => Dec::unknown(word),
        },
        // ---------------------------------------------------------------- 9
        0x9 => Dec::literal(
            "mov.w",
            format!("@(0x{:x}, pc), {}", d8 * 2, r(n)),
            pc_rel_base(address) + d8 * 2,
        ),
        // --------------------------------------------------------------- A
        0xA => Dec::branch_to("bra", branch_target(address, disp12), true),
        // --------------------------------------------------------------- B
        // --------------------------------------------------------------- B
        0xB => Dec::branch_to("bsr", branch_target(address, disp12), true).call(),
        // --------------------------------------------------------------- C
        0xC => match n {
            0x0 => Dec::plain("mov.b", format!("r0, @(0x{:x}, gbr)", d8)),
            0x1 => Dec::plain("mov.w", format!("r0, @(0x{:x}, gbr)", d8 * 2)),
            0x2 => Dec::plain("mov.l", format!("r0, @(0x{:x}, gbr)", d8 * 4)),
            0x3 => Dec::plain("trapa", format!("#0x{:02x}", d8)),
            0x4 => Dec::plain("mov.b", format!("@(0x{:x}, gbr), r0", d8)),
            0x5 => Dec::plain("mov.w", format!("@(0x{:x}, gbr), r0", d8 * 2)),
            0x6 => Dec::plain("mov.l", format!("@(0x{:x}, gbr), r0", d8 * 4)),
            0x7 => Dec::literal(
                "mova",
                format!("@(0x{:x}, pc), r0", d8 * 4),
                aligned_literal(address, d8 * 4),
            ),
            0x8 => Dec::plain("tst", format!("#0x{:02x}, r0", d8)),
            0x9 => Dec::plain("and", format!("#0x{:02x}, r0", d8)),
            0xA => Dec::plain("xor", format!("#0x{:02x}, r0", d8)),
            0xB => Dec::plain("or", format!("#0x{:02x}, r0", d8)),
            0xC => Dec::plain("tst.b", format!("#0x{:02x}, @(r0, gbr)", d8)),
            0xD => Dec::plain("and.b", format!("#0x{:02x}, @(r0, gbr)", d8)),
            0xE => Dec::plain("xor.b", format!("#0x{:02x}, @(r0, gbr)", d8)),
            0xF => Dec::plain("or.b", format!("#0x{:02x}, @(r0, gbr)", d8)),
            _ => Dec::unknown(word),
        },
        // --------------------------------------------------------------- D
        0xD => Dec::literal(
            "mov.l",
            format!("@(0x{:x}, pc), {}", d8 * 4, r(n)),
            aligned_literal(address, d8 * 4),
        ),
        // --------------------------------------------------------------- E
        0xE => Dec::plain("mov", format!("#{}, {}", s8, r(n))),
        // --------------------------------------------------------------- F
        0xF => match word & 0xF {
            0x0 => Dec::plain("fadd", format!("fr{}, fr{}", m, n)),
            0x1 => Dec::plain("fsub", format!("fr{}, fr{}", m, n)),
            0x2 => Dec::plain("fmul", format!("fr{}, fr{}", m, n)),
            0x3 => Dec::plain("fdiv", format!("fr{}, fr{}", m, n)),
            0x4 => Dec::plain("fcmp/eq", format!("fr{}, fr{}", m, n)),
            0x5 => Dec::plain("fcmp/gt", format!("fr{}, fr{}", m, n)),
            0x6 => Dec::plain("fmov.s", format!("@(r0, {}), fr{}", r(m), n)),
            0x7 => Dec::plain("fmov.s", format!("fr{}, @(r0, {})", m, r(n))),
            0x8 => Dec::plain("fmov.s", format!("@{}, fr{}", r(m), n)),
            0x9 => Dec::plain("fmov.s", format!("@{}+, fr{}", r(m), n)),
            0xA => Dec::plain("fmov.s", format!("fr{}, @{}", m, r(n))),
            0xB => Dec::plain("fmov.s", format!("fr{}, @-{}", m, r(n))),
            0xC => Dec::plain("fmov.s", format!("fr{}, fr{}", m, n)),
            0xD => match word & 0xF0 {
                0x00 => Dec::plain("fsts", format!("fpul, fr{}", n)),
                0x10 => Dec::plain("flds", format!("fr{}, fpul", n)),
                0x20 => Dec::plain("float", format!("fpul, fr{}", n)),
                0x30 => Dec::plain("ftrc", format!("fr{}, fpul", n)),
                0x40 => Dec::plain("fneg", format!("fr{}", n)),
                0x50 => Dec::plain("fabs", format!("fr{}", n)),
                0x60 => Dec::plain("fsqrt", format!("fr{}", n)),
                0x70 => Dec::plain("fsrra", format!("fr{}", n)),
                0x80 => Dec::plain("fldi0", format!("fr{}", n)),
                0x90 => Dec::plain("fldi1", format!("fr{}", n)),
                0xA0 => Dec::plain("fcnvsd", format!("fpul, dr{}", n)),
                0xB0 => Dec::plain("fcnvds", format!("dr{}, fpul", n)),
                0xE0 => Dec::plain(
                    "fipr",
                    format!("fv{}, fv{}", (n & 3) << 2, n & 12),
                ),
                0xF0 => {
                    if word & 0x100 != 0 {
                        if word & 0x200 != 0 {
                            match word & 0xC00 {
                                0x000 => Dec::plain("fschg", String::new()),
                                0x800 => Dec::plain("frchg", String::new()),
                                _ => Dec::unknown(word),
                            }
                        } else {
                            Dec::plain("ftrv", format!("xmtrx, fv{}", n & 12))
                        }
                    } else {
                        // FSCA is SH-4A-only; rendered MAME-style.
                        Dec::plain("fsca", format!("fpul, dr{}", n & 14))
                    }
                }
                _ => Dec::unknown(word),
            },
            0xE => Dec::plain("fmac", format!("fr0, fr{}, fr{}", m, n)),
            _ => Dec::unknown(word),
        },
        _ => Dec::unknown(word),
    };

    Sh4Instruction {
        address,
        file_offset,
        raw: word,
        size: 2,
        mnemonic: dec.mnemonic,
        operands: dec.operands,
        is_branch: dec.is_branch,
        is_call: dec.is_call,
        is_return: dec.is_return,
        has_delay_slot: dec.has_delay_slot,
        branch_target: dec.branch_target,
        literal_address: dec.literal_address,
    }
}

/// Decode a single SH-4 instruction word.
pub fn disassemble_sh4_instruction(word: u16, address: u32) -> Sh4Instruction {
    decode(word, address, 0)
}

/// Disassemble a run of SH-4 instructions from a raw little-endian image
/// (a `1ST_READ.BIN` payload, a track dump, or extracted code). Dreamcast
/// SH-4 code is always little-endian. Stops at `max_instr` or when fewer
/// than 2 bytes remain.
pub fn disassemble_sh4_at(
    data: &[u8],
    file_offset: usize,
    display_address: u32,
    max_instr: usize,
) -> Vec<Sh4Instruction> {
    let mut out = Vec::new();
    let mut offset = file_offset.min(data.len());
    let mut address = display_address;
    while out.len() < max_instr && offset + 2 <= data.len() {
        let word = u16::from_le_bytes([data[offset], data[offset + 1]]);
        out.push(decode(word, address, offset));
        offset += 2;
        address = address.wrapping_add(2);
    }
    out
}
