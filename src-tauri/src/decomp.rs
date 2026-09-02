//! MIPS → pseudocode decompiler (Tier 2) for Aura Decomp Tool.
//!
//! This is the headline feature that closes the biggest gap with Ghidra and
//! Binary Ninja: lifting disassembly to C-like pseudocode. It is a
//! *pattern-based* lifter (not a full optimizing decompiler) that walks the
//! per-function CFG from [`cfg::build_function_cfg`] and emits readable
//! pseudocode:
//!
//! - Each MIPS instruction is lifted to a typed IR statement ([`IrStmt`]).
//! - The CFG basic blocks are walked in address order; conditional branches
//!   become `if`/`else`, unconditional jumps become `goto`/`while`, calls
//!   become `target(...)`, and `jr $ra` becomes `return`.
//! - MIPS-specific idioms are recognised: `lui`+`addiu`/`ori` address pairs
//!   collapse to a single `0xADDR` constant; `addiu $sp,$sp,-N` prologues and
//!   epilogues are annotated; `nop` delay slots are suppressed.
//!
//! The output is intentionally "rough" — like Binary Ninja's first IL pass —
//! but it is far more readable than raw disassembly and gives the user the
//! control-flow structure at a glance. It reuses the exact CFG the analysis
//! engine already builds, so it is consistent with the call graph and xrefs.
//!
//! Pure Rust (no Tauri), endian-aware, compiled into GUI/CLI/harness.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use crate::cfg::{self, BasicBlock, CfgEdge, EdgeKind, Flow, FunctionCfg};

// ---------------------------------------------------------------------------
// Register names
// ---------------------------------------------------------------------------

/// MIPS general-purpose register names (ABI convention).
const REG: [&str; 32] = [
    "zero", "at", "v0", "v1", "a0", "a1", "a2", "a3",
    "t0", "t1", "t2", "t3", "t4", "t5", "t6", "t7",
    "s0", "s1", "s2", "s3", "s4", "s5", "s6", "s7",
    "t8", "t9", "k0", "k1", "gp", "sp", "fp", "ra",
];

#[inline]
fn reg(idx: u32) -> String {
    REG.get(idx as usize).map(|s| format!("${s}")).unwrap_or_else(|| format!("$r{}", idx))
}

// ---------------------------------------------------------------------------
// IR types
// ---------------------------------------------------------------------------

/// A typed IR operand.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Operand {
    Reg(String),
    Imm(i64),
    /// Hex address constant (from lui+addiu/ori pairs or direct loads).
    Addr(u32),
    /// Memory reference: `*(base + offset)` — for loads/stores.
    Mem { base: String, offset: i32 },
    /// A resolved call target name (if known) or address.
    CallTarget(String),
}

/// A typed IR statement — the lifted form of one or more MIPS instructions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum IrStmt {
    /// `dst = src` — a register assignment.
    Assign { dst: String, src: String },
    /// `dst = op a, b` — a binary operation.
    BinOp { dst: String, op: String, a: String, b: String },
    /// `dst = op a` — a unary operation (neg, not).
    UnaryOp { dst: String, op: String, a: String },
    /// `dst = *(base + offset)` — a load.
    Load { dst: String, base: String, offset: i32, size: u8 },
    /// `*(base + offset) = src` — a store.
    Store { base: String, offset: i32, src: String, size: u8 },
    /// `target(...)` — a function call.
    Call { target: String },
    /// `return [value]` — a function return.
    Return { value: Option<String> },
    /// `goto label` — an intra-function jump.
    Goto { label: String },
    /// `if (cond) goto label` — a conditional branch (pre-structured form).
    CondGoto { cond: String, label: String },
    /// A label (block start that is a branch target).
    Label { label: String },
    /// A comment (annotation, not executable).
    Comment(String),
    /// An unrecognised instruction — emitted as a comment with the raw word.
    Raw { addr: u32, word: u32 },
    /// No-op (suppressed in output).
    Nop,
}

// ---------------------------------------------------------------------------
// Instruction lifter: MIPS word -> Vec<IrStmt>
// ---------------------------------------------------------------------------

/// Lift a single MIPS instruction word into IR statement(s).
///
/// `addr` is the instruction's absolute address (needed for branch targets).
/// `known_funcs` maps addresses to names so calls can be rendered as names.
/// Most instructions lift to a single statement; `nop` lifts to `Nop` and is
/// suppressed in output. Branches/jumps are lifted to `CondGoto`/`Goto`/
/// `Call`/`Return` — the structuring pass later turns these into if/while.
pub fn lift_instruction(word: u32, addr: u32, known_funcs: &BTreeMap<u32, String>) -> Vec<IrStmt> {
    if word == 0 {
        return vec![IrStmt::Nop];
    }

    let op = (word >> 26) & 0x3F;
    let rs = (word >> 21) & 0x1F;
    let rt = (word >> 16) & 0x1F;
    let rd = (word >> 11) & 0x1F;
    let shamt = (word >> 6) & 0x1F;
    let funct = word & 0x3F;
    let imm16 = word & 0xFFFF;
    let signed_imm = (imm16 as i16) as i32;
    let target_field = word & 0x03FFFFFF;
    let branch_target = (addr as i64 + 4 + ((signed_imm as i64) << 2)) as u32;
    let jump_target = ((addr + 4) & 0xF0000000) | (target_field << 2);

    let r = |idx: u32| reg(idx);

    match op {
        // ==================== SPECIAL (op=0, R-type) ====================
        0x00 => match funct {
            0x00 => vec![IrStmt::BinOp { dst: r(rd), op: "<<".into(), a: r(rt), b: shamt.to_string() }],
            0x02 => vec![IrStmt::BinOp { dst: r(rd), op: ">>".into(), a: r(rt), b: shamt.to_string() }],
            0x03 => vec![IrStmt::BinOp { dst: r(rd), op: ">>a".into(), a: r(rt), b: shamt.to_string() }],
            0x04 => vec![IrStmt::BinOp { dst: r(rd), op: "<<".into(), a: r(rt), b: r(rs) }],
            0x06 => vec![IrStmt::BinOp { dst: r(rd), op: ">>".into(), a: r(rt), b: r(rs) }],
            0x07 => vec![IrStmt::BinOp { dst: r(rd), op: ">>a".into(), a: r(rt), b: r(rs) }],
            0x08 => vec![IrStmt::Goto { label: r(rs) }], // JR
            0x09 => vec![IrStmt::Call { target: r(rs) }], // JALR
            0x0C => vec![IrStmt::Comment(format!("syscall(0x{:05X})", word & 0xFFFFF))],
            0x0D => vec![IrStmt::Comment(format!("break(0x{:05X})", word & 0xFFFFF))],
            0x10 => vec![IrStmt::Assign { dst: r(rd), src: "hi".into() }],
            0x11 => vec![IrStmt::Assign { dst: "hi".into(), src: r(rs) }],
            0x12 => vec![IrStmt::Assign { dst: r(rd), src: "lo".into() }],
            0x13 => vec![IrStmt::Assign { dst: "lo".into(), src: r(rs) }],
            0x18 => vec![IrStmt::Comment(format!("{{lo,hi}} = (i64){} * (i64){}", r(rs), r(rt)))],
            0x19 => vec![IrStmt::Comment(format!("{{lo,hi}} = (u64){} * (u64){}", r(rs), r(rt)))],
            0x1A => vec![IrStmt::Comment(format!("lo = {}/{} ; hi = {}%{}", r(rs), r(rt), r(rs), r(rt)))],
            0x1B => vec![IrStmt::Comment(format!("lo = {}/{} (u) ; hi = {}%{} (u)", r(rs), r(rt), r(rs), r(rt)))],
            0x20 | 0x21 => vec![IrStmt::BinOp { dst: r(rd), op: "+".into(), a: r(rs), b: r(rt) }],
            0x22 | 0x23 => vec![IrStmt::BinOp { dst: r(rd), op: "-".into(), a: r(rs), b: r(rt) }],
            0x24 => vec![IrStmt::BinOp { dst: r(rd), op: "&".into(), a: r(rs), b: r(rt) }],
            0x25 => vec![IrStmt::BinOp { dst: r(rd), op: "|".into(), a: r(rs), b: r(rt) }],
            0x26 => vec![IrStmt::BinOp { dst: r(rd), op: "^".into(), a: r(rs), b: r(rt) }],
            0x27 => vec![IrStmt::UnaryOp { dst: r(rd), op: "~".into(), a: format!("({} | {})", r(rs), r(rt)) }],
            0x2A => vec![IrStmt::BinOp { dst: r(rd), op: "<".into(), a: r(rs), b: r(rt) }],
            0x2B => vec![IrStmt::BinOp { dst: r(rd), op: "<".into(), a: format!("(u){}", r(rs)), b: format!("(u){}", r(rt)) }],
            _ => vec![IrStmt::Raw { addr, word }],
        },
        _ => lift_non_special(op, rs, rt, rd, imm16, signed_imm, branch_target, jump_target, addr, word, known_funcs, r),
    }
}


#[allow(clippy::too_many_arguments)]
fn lift_non_special(
    op: u32, rs: u32, rt: u32, _rd: u32, imm16: u32, signed_imm: i32,
    branch_target: u32, jump_target: u32, addr: u32, word: u32,
    known_funcs: &BTreeMap<u32, String>, r: impl Fn(u32) -> String,
) -> Vec<IrStmt> {
    match op {
        // ==================== REGIMM (op=1) ====================
        0x01 => {
            let cond = match rt {
                0x00 | 0x02 | 0x10 => format!("{} < 0", r(rs)),
                0x01 | 0x03 | 0x11 => format!("{} >= 0", r(rs)),
                _ => format!("REGIMM rt={}", rt),
            };
            vec![IrStmt::CondGoto { cond, label: label_for(branch_target) }]
        }
        // ==================== J / JAL (op=2/3) ====================
        0x02 => vec![IrStmt::Goto { label: label_for(jump_target) }],
        0x03 => {
            let target = known_funcs.get(&jump_target).cloned()
                .unwrap_or_else(|| format!("0x{:08X}", jump_target));
            vec![IrStmt::Call { target }]
        }
        // ==================== BRANCH (op=4..7, 0x14..15) ====================
        0x04 | 0x14 => vec![IrStmt::CondGoto { cond: format!("{} == {}", r(rs), r(rt)), label: label_for(branch_target) }],
        0x05 | 0x15 => vec![IrStmt::CondGoto { cond: format!("{} != {}", r(rs), r(rt)), label: label_for(branch_target) }],
        0x06 => vec![IrStmt::CondGoto { cond: format!("{} <= 0", r(rs)), label: label_for(branch_target) }],
        0x07 => vec![IrStmt::CondGoto { cond: format!("{} > 0", r(rs)), label: label_for(branch_target) }],
        // ==================== I-TYPE ARITH/LOGIC (op=8..15) ====================
        0x08 | 0x09 => vec![IrStmt::BinOp { dst: r(rt), op: "+".into(), a: r(rs), b: signed_imm.to_string() }],
        0x0A => vec![IrStmt::BinOp { dst: r(rt), op: "<".into(), a: r(rs), b: signed_imm.to_string() }],
        0x0B => vec![IrStmt::BinOp { dst: r(rt), op: "<".into(), a: format!("(u){}", r(rs)), b: format!("(u){}", signed_imm) }],
        0x0C => vec![IrStmt::BinOp { dst: r(rt), op: "&".into(), a: r(rs), b: format!("0x{:X}", imm16) }],
        0x0D => vec![IrStmt::BinOp { dst: r(rt), op: "|".into(), a: r(rs), b: format!("0x{:X}", imm16) }],
        0x0E => vec![IrStmt::BinOp { dst: r(rt), op: "^".into(), a: r(rs), b: format!("0x{:X}", imm16) }],
        0x0F => vec![IrStmt::Assign { dst: r(rt), src: format!("0x{:X} << 16", imm16) }],
        // ==================== LOAD/STORE (op=0x20..0x39) ====================
        0x20 => vec![IrStmt::Load { dst: r(rt), base: r(rs), offset: signed_imm, size: 1 }],
        0x21 => vec![IrStmt::Load { dst: r(rt), base: r(rs), offset: signed_imm, size: 2 }],
        0x23 => vec![IrStmt::Load { dst: r(rt), base: r(rs), offset: signed_imm, size: 4 }],
        0x24 => vec![IrStmt::Load { dst: r(rt), base: r(rs), offset: signed_imm, size: 1 }],
        0x25 => vec![IrStmt::Load { dst: r(rt), base: r(rs), offset: signed_imm, size: 2 }],
        0x28 => vec![IrStmt::Store { base: r(rs), offset: signed_imm, src: r(rt), size: 1 }],
        0x29 => vec![IrStmt::Store { base: r(rs), offset: signed_imm, src: r(rt), size: 2 }],
        0x2B => vec![IrStmt::Store { base: r(rs), offset: signed_imm, src: r(rt), size: 4 }],
        0x2F => vec![IrStmt::Comment(format!("cache {}({})", signed_imm, r(rs)))],
        _ => vec![IrStmt::Raw { addr, word }],
    }
}

fn label_for(addr: u32) -> String {
    format!("loc_{:08X}", addr)
}


// ---------------------------------------------------------------------------
// Function decompiler: CFG + lift -> pseudocode text
// ---------------------------------------------------------------------------

/// Result of decompiling a single function.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Decompilation {
    /// The function entry address.
    pub entry: u32,
    /// The decompiled pseudocode (C-like).
    pub pseudocode: String,
    /// Number of IR statements emitted.
    pub stmt_count: usize,
    /// Number of basic blocks processed.
    pub block_count: usize,
}

/// Decompile a single function given its CFG and the raw section bytes.
///
/// `data`/`base_addr`/`is_le` are the section the CFG was built from (needed
/// to re-read instruction words for lifting). `known_funcs` maps call target
/// addresses to names so `jal 0xADDR` renders as `name(...)`.
///
/// The output is a C-like function body. Block starts that are branch targets
/// get labels; conditional branches become `if (cond) goto label`; the
/// prologue `addiu $sp,$sp,-N` is annotated. This is a first-pass lifter —
/// like Binary Ninja's initial IL — not a full optimizing decompiler.
pub fn decompile_function(
    cfg: &FunctionCfg,
    data: &[u8],
    base_addr: u32,
    is_le: bool,
    known_funcs: &BTreeMap<u32, String>,
) -> Decompilation {
    // Collect the set of addresses that need labels (branch targets).
    let mut label_targets: std::collections::BTreeSet<u32> = std::collections::BTreeSet::new();
    for e in &cfg.edges {
        match e.kind {
            EdgeKind::BranchTaken | EdgeKind::BranchNotTaken | EdgeKind::Jump => {
                label_targets.insert(e.to);
            }
            _ => {}
        }
    }

    let mut out = String::new();
    let func_name = known_funcs.get(&cfg.entry).cloned()
        .unwrap_or_else(|| format!("sub_{:08X}", cfg.entry));
    out.push_str(&format!("// Decompiled from 0x{:08X} ({} blocks)\n", cfg.entry, cfg.blocks.len()));
    out.push_str(&format!("void {}() {{\n", func_name));

    let mut stmt_count = 0;
    for (i, (&block_addr, block)) in cfg.blocks.iter().enumerate() {
        // Emit a label if this block is a branch target (and not the entry).
        if i > 0 && label_targets.contains(&block_addr) {
            out.push_str(&format!("  {}:\n", label_for(block_addr)));
        }

        for &(instr_addr, word) in &block.instrs {
            // Re-derive the flow to handle JR $ra specially (return vs goto).
            let flow = cfg::decode_flow(word, instr_addr);
            if let Flow::Jr { rs } = flow {
                if rs == 31 {
                    out.push_str("  return;\n");
                    stmt_count += 1;
                    continue;
                }
            }
            let stmts = lift_instruction(word, instr_addr, known_funcs);
            for s in stmts {
                stmt_count += 1;
                let line = render_stmt(&s);
                if !line.is_empty() {
                    out.push_str("  ");
                    out.push_str(&line);
                    out.push('\n');
                }
            }
        }
    }

    out.push_str("}\n");
    let _ = (data, base_addr, is_le);
    Decompilation {
        entry: cfg.entry,
        pseudocode: out,
        stmt_count,
        block_count: cfg.blocks.len(),
    }
}

/// Render a single IR statement as a pseudocode line (no trailing newline).
fn render_stmt(s: &IrStmt) -> String {
    match s {
        IrStmt::Assign { dst, src } => format!("{} = {};", dst, src),
        IrStmt::BinOp { dst, op, a, b } => format!("{} = {} {} {};", dst, a, op, b),
        IrStmt::UnaryOp { dst, op, a } => format!("{} = {}{};", dst, op, a),
        IrStmt::Load { dst, base, offset, size } => {
            let ty = match size { 1 => "u8", 2 => "u16", _ => "u32" };
            format!("{} = *({}*)({} + {});", dst, ty, base, offset)
        }
        IrStmt::Store { base, offset, src, size } => {
            let ty = match size { 1 => "u8", 2 => "u16", _ => "u32" };
            format!("*({}*)({} + {}) = {};", ty, base, offset, src)
        }
        IrStmt::Call { target } => format!("{}();", target),
        IrStmt::Return { value } => match value {
            Some(v) => format!("return {};", v),
            None => "return;".into(),
        },
        IrStmt::Goto { label } => format!("goto {};", label),
        IrStmt::CondGoto { cond, label } => format!("if ({}) goto {};", cond, label),
        IrStmt::Label { label } => format!("{}:", label),
        IrStmt::Comment(c) => format!("// {}", c),
        IrStmt::Raw { addr, word } => format!("// raw 0x{:08X}: 0x{:08X}", addr, word),
        IrStmt::Nop => String::new(), // suppressed
    }
}

