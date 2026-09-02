//! Control-flow graph (CFG) + cross-reference (xref) analysis for Aura Decomp Tool.
//!
//! This is the "Tier 1" foundation that makes Aura behave like Ghidra / Binary
//! Ninja instead of a flat linear-sweep disassembler:
//!
//! - [`build_function_cfg`] does *recursive-descent* basic-block construction
//!   over a code section: starting from a function entry, it decodes
//!   instructions, splits blocks at branches/jumps/returns, and follows
//!   targets — respecting the MIPS branch-delay slot (the instruction after
//!   a branch always executes before the transfer). This is the same approach
//!   Ghidra's disassembly engine uses.
//! - [`build_xref_index`] walks every function CFG and produces a global
//!   cross-reference map: for each address, who references it and how
//!   (call, jump, branch, data). This is the navigation primitive Ghidra/BN
//!   users rely on ("X" to list xrefs).
//! - Indirect-call resolution for the common PS2 import-thunk pattern
//!   (`lw $t9, [import]; jalr $t9`) is handled by [`resolve_indirect_calls`].
//!
//! The module is pure Rust (no Tauri) and endian-aware so it works for both
//! PS1 (big-endian) and PS2 (little- or big-endian) MIPS binaries. It is
//! compiled into the GUI (`mod cfg;` in main.rs), the CLI, and the test
//! harness via `#[path]`.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

// ---------------------------------------------------------------------------
// Structured MIPS instruction decode (control-flow view)
// ---------------------------------------------------------------------------

/// A decoded MIPS instruction with enough structure for CFG construction.
/// We do NOT re-implement full disassembly here — the existing decoders own
/// the human-readable rendering. This only extracts control-flow semantics:
/// is it a branch/jump/call/return, and where does it go.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MipsInstr {
    /// Absolute address of this instruction.
    pub addr: u32,
    /// Raw 32-bit word.
    pub word: u32,
    /// Control-flow classification.
    pub flow: Flow,
}

/// Control-flow classification of a single MIPS instruction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Flow {
    /// Not a control-flow instruction (ordinary arithmetic/load/store/etc.).
    Seq,
    /// Conditional branch (BEQ/BNE/BLEZ/BGTZ/BLTZ/BGEZ and likely variants).
    /// `target` is the branch destination; the delay-slot instruction at
    /// `addr+4` always runs, then either the target or `addr+8` (fallthrough).
    CondBranch { target: u32 },
    /// Unconditional jump (J). Delay slot runs, then transfer to `target`.
    Jump { target: u32 },
    /// Direct call (JAL). Delay slot runs, then transfer to `target`.
    Call { target: u32 },
    /// Indirect jump (JR) — target unknown at static-analysis time.
    /// `jr $ra` (rs==31) is a function return; other `jr` are indirect jumps.
    Jr { rs: u32 },
    /// Indirect call (JALR) — target unknown at static-analysis time.
    Jalr { rs: u32 },
    /// Unknown / undecodable word. Treated as sequential (no flow change).
    Unknown,
}

/// Decode a single MIPS word into a control-flow instruction.
///
/// `addr` is the absolute address of the instruction; it is needed to resolve
/// PC-relative branch targets and the high-4-bits of J/JAL targets.
pub fn decode_flow(word: u32, addr: u32) -> Flow {
    let op = (word >> 26) & 0x3F;
    let rs = (word >> 21) & 0x1F;
    let rt = (word >> 16) & 0x1F;
    let imm16 = word & 0xFFFF;
    let signed_imm = (imm16 as i16) as i32;
    let target_field = word & 0x03FFFFFF;
    let funct = word & 0x3F;

    // Branch target = PC + 4 + sign_ext(imm) << 2  (delay slot is PC+4)
    let branch_target = (addr as i64 + 4 + ((signed_imm as i64) << 2)) as u32;
    // Jump target = (PC+4 & 0xF0000000) | (target_field << 2)
    let jump_target = ((addr + 4) & 0xF0000000) | (target_field << 2);

    match op {
        0x00 => {
            // SPECIAL — check for JR (funct 8) and JALR (funct 9)
            match funct {
                0x08 => Flow::Jr { rs },
                0x09 => Flow::Jalr { rs },
                _ => Flow::Seq,
            }
        }
        0x01 => {
            // REGIMM — BLTZ/BGEZ/BLTZAL/BGEZAL (all conditional, rt selects)
            match rt {
                0x00 | 0x01 | 0x02 | 0x03 | 0x10 | 0x11 => Flow::CondBranch { target: branch_target },
                _ => Flow::Seq,
            }
        }
        0x02 => Flow::Jump { target: jump_target },
        0x03 => Flow::Call { target: jump_target },
        0x04 | 0x05 | 0x06 | 0x07 | 0x14 | 0x15 => {
            // BEQ/BNE/BLEZ/BGTZ/BEQL/BNEL — conditional branch
            Flow::CondBranch { target: branch_target }
        }
        _ => Flow::Seq,
    }
}

/// Decode a full instruction word at a file offset within a code section.
/// `data` is the section bytes; `offset` is byte offset; `base_addr` is the
/// section's load address. Returns None if the offset is out of range.
pub fn decode_at(data: &[u8], offset: usize, base_addr: u32, is_le: bool) -> Option<MipsInstr> {
    if offset + 4 > data.len() {
        return None;
    }
    let word = if is_le {
        u32::from_le_bytes([data[offset], data[offset + 1], data[offset + 2], data[offset + 3]])
    } else {
        u32::from_be_bytes([data[offset], data[offset + 1], data[offset + 2], data[offset + 3]])
    };
    let addr = base_addr.wrapping_add(offset as u32);
    Some(MipsInstr { addr, word, flow: decode_flow(word, addr) })
}

// ---------------------------------------------------------------------------
// Basic blocks + per-function CFG
// ---------------------------------------------------------------------------

/// A basic block: a maximal straight-line sequence of instructions with no
/// internal control-flow transfers. Control enters only at `start` and leaves
/// only at the end (via the edges in [`CfgEdge`]).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BasicBlock {
    /// Start address (inclusive) of the first instruction in the block.
    pub start: u32,
    /// End address (exclusive): the byte address just past the last instruction.
    /// For a block ending with a branch at `b` (delay slot at `b+4`), end = `b+8`.
    pub end: u32,
    /// The instructions in this block, as (addr, word) pairs. Kept compact
    /// (no mnemonic strings) so large binaries don't blow up memory.
    pub instrs: Vec<(u32, u32)>,
}

/// Kind of edge between basic blocks.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum EdgeKind {
    /// Natural fall-through from the previous block (no branch taken).
    Fallthrough,
    /// Conditional branch taken.
    BranchTaken,
    /// Conditional branch not taken (fallthrough after the delay slot).
    BranchNotTaken,
    /// Unconditional jump (J).
    Jump,
    /// Direct call (JAL) — the callee is a separate function; this edge is
    /// informational and usually NOT followed for intra-function CFG.
    Call,
}

/// An edge in the CFG: from one block to another.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CfgEdge {
    pub from: u32,
    pub to: u32,
    pub kind: EdgeKind,
}

/// A per-function control-flow graph.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionCfg {
    /// Function entry address.
    pub entry: u32,
    /// Basic blocks, keyed by start address.
    pub blocks: BTreeMap<u32, BasicBlock>,
    /// Edges between blocks.
    pub edges: Vec<CfgEdge>,
    /// Whether the function appears to return (contains a `jr $ra` reachable
    /// from entry). Functions that tail-call (end in `j`) may not.
    pub returns: bool,
}

#[inline]
fn in_range(addr: u32, lo: u32, hi: u32) -> bool {
    addr >= lo && addr < hi
}


/// Build the CFG for a single function by recursive-descent disassembly.
///
/// `data` is the section bytes, `base_addr` its load address, `func_start` the
/// function entry, `func_end` the exclusive upper bound (next function start
/// or section end). The walker decodes from `func_start`, splits blocks at
/// control-flow instructions, and follows direct branch/jump targets that
/// land within [func_start, func_end). Indirect targets (JR/JALR) are not
/// followed (they're recorded as edges to the resolved target only when we
/// can resolve them — see [`resolve_indirect_calls`]).
///
/// `is_le` selects instruction endianness (PS1 = false, PS2 LE = true).
pub fn build_function_cfg(
    data: &[u8],
    base_addr: u32,
    func_start: u32,
    func_end: u32,
    is_le: bool,
) -> FunctionCfg {
    let mut blocks: BTreeMap<u32, BasicBlock> = BTreeMap::new();
    let mut edges: Vec<CfgEdge> = Vec::new();
    let mut returns = false;

    // Worklist of block-start addresses to decode, within the function.
    let mut work: Vec<u32> = vec![func_start];
    let mut visited_starts: BTreeSet<u32> = BTreeSet::new();

    while let Some(start) = work.pop() {
        if start < base_addr || start >= func_end {
            continue;
        }
        if !visited_starts.insert(start) {
            continue; // already decoded this block start
        }

        let mut instrs: Vec<(u32, u32)> = Vec::new();
        let mut off = (start - base_addr) as usize;
        let mut block_end = start;

        loop {
            let Some(insn) = decode_at(data, off, base_addr, is_le) else { break };
            // Stop if we've walked into an already-decoded block (another branch
            // target). That address is a new block start, not part of this one.
            if insn.addr != start && blocks.contains_key(&insn.addr) {
                edges.push(CfgEdge { from: block_end, to: insn.addr, kind: EdgeKind::Fallthrough });
                break;
            }
            instrs.push((insn.addr, insn.word));
            block_end = insn.addr.wrapping_add(4);
            off += 4;

            match insn.flow {
                Flow::Seq | Flow::Unknown => continue,
                Flow::CondBranch { target } => {
                    // The delay slot (next instruction) is part of THIS block.
                    if let Some(ds) = decode_at(data, off, base_addr, is_le) {
                        instrs.push((ds.addr, ds.word));
                        block_end = ds.addr.wrapping_add(4);
                        off += 4;
                    }
                    if in_range(target, func_start, func_end) {
                        edges.push(CfgEdge { from: start, to: target, kind: EdgeKind::BranchTaken });
                        work.push(target);
                    }
                    edges.push(CfgEdge { from: start, to: block_end, kind: EdgeKind::BranchNotTaken });
                    work.push(block_end);
                    break;
                }
                Flow::Jump { target } => {
                    if let Some(ds) = decode_at(data, off, base_addr, is_le) {
                        instrs.push((ds.addr, ds.word));
                        block_end = ds.addr.wrapping_add(4);
                        off += 4;
                    }
                    if in_range(target, func_start, func_end) {
                        edges.push(CfgEdge { from: start, to: target, kind: EdgeKind::Jump });
                        work.push(target);
                    }
                    break;
                }
                Flow::Call { target } => {
                    if let Some(ds) = decode_at(data, off, base_addr, is_le) {
                        instrs.push((ds.addr, ds.word));
                        block_end = ds.addr.wrapping_add(4);
                        off += 4;
                    }
                    edges.push(CfgEdge { from: start, to: target, kind: EdgeKind::Call });
                    edges.push(CfgEdge { from: start, to: block_end, kind: EdgeKind::Fallthrough });
                    work.push(block_end);
                    break;
                }
                Flow::Jr { rs } => {
                    if rs == 31 { returns = true; }
                    if let Some(ds) = decode_at(data, off, base_addr, is_le) {
                        instrs.push((ds.addr, ds.word));
                        block_end = ds.addr.wrapping_add(4);
                        off += 4;
                    }
                    break;
                }
                Flow::Jalr { rs } => {
                    let _ = rs;
                    if let Some(ds) = decode_at(data, off, base_addr, is_le) {
                        instrs.push((ds.addr, ds.word));
                        block_end = ds.addr.wrapping_add(4);
                        off += 4;
                    }
                    edges.push(CfgEdge { from: start, to: block_end, kind: EdgeKind::Fallthrough });
                    work.push(block_end);
                    break;
                }
            }
        }

        blocks.insert(start, BasicBlock { start, end: block_end, instrs });
    }

    FunctionCfg { entry: func_start, blocks, edges, returns }
}


// ---------------------------------------------------------------------------
// Cross-reference index
// ---------------------------------------------------------------------------

/// How an address is referenced.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum XrefKind {
    /// Direct call (JAL).
    Call,
    /// Unconditional jump (J) used as a tail call or goto.
    Jump,
    /// Conditional branch (BEQ/BNE/...).
    Branch,
    /// Data reference (load/store address, lui/addiu address pair).
    Data,
}

/// A single cross-reference: `from` references `to` with kind `kind`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Xref {
    /// Address of the referencing instruction.
    pub from: u32,
    /// Address being referenced.
    pub to: u32,
    pub kind: XrefKind,
}

/// A global cross-reference index: for each address, the list of references
/// to it. This is the "X" (xrefs) navigation primitive from Ghidra/BN.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct XrefIndex {
    /// target address -> list of references pointing at it.
    pub by_target: BTreeMap<u32, Vec<Xref>>,
}

impl XrefIndex {
    pub fn add(&mut self, from: u32, to: u32, kind: XrefKind) {
        self.by_target.entry(to).or_default().push(Xref { from, to, kind });
    }

    /// Look up all references to `addr`. Returns an empty slice if none.
    pub fn refs_to(&self, addr: u32) -> &[Xref] {
        match self.by_target.get(&addr) {
            Some(v) => v.as_slice(),
            None => &[],
        }
    }

    /// Number of distinct referenced addresses.
    pub fn len(&self) -> usize {
        self.by_target.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_target.is_empty()
    }
}

/// Build a global xref index from a set of per-function CFGs.
///
/// Walks every edge of every CFG and records it as an xref. Call edges become
/// `XrefKind::Call`, jumps become `Jump`, branches become `Branch`.
pub fn build_xref_index(cfgs: &[FunctionCfg]) -> XrefIndex {
    let mut idx = XrefIndex::default();
    for cfg in cfgs {
        for e in &cfg.edges {
            let kind = match e.kind {
                EdgeKind::Call => XrefKind::Call,
                EdgeKind::Jump => XrefKind::Jump,
                EdgeKind::BranchTaken | EdgeKind::BranchNotTaken => XrefKind::Branch,
                EdgeKind::Fallthrough => continue, // not a user-visible xref
            };
            idx.add(e.from, e.to, kind);
        }
    }
    idx
}


// ---------------------------------------------------------------------------
// Indirect-call resolution + whole-binary CFG
// ---------------------------------------------------------------------------

/// A resolved indirect call: the `jalr $t9` at `callsite` was determined to
/// target `target` (e.g. an imported function address resolved from a
/// relocation or a `lw $t9, [import]` pattern).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IndirectCall {
    pub callsite: u32,
    pub target: u32,
    /// Optional resolved name (from relocations / imports).
    pub name: Option<String>,
}

/// Resolve indirect calls of the form `lw $t9, off($gp); jalr $t9` (the
/// canonical PS2 import-thunk pattern) using a map of GOT-slot addresses to
/// imported symbol names. Returns the resolved calls; unresolved `jalr $t9`
/// are skipped (we can't know the target without runtime GP tracking).
///
/// `import_slots` maps a GOT/import-slot address -> symbol name. For PS2 these
/// come from R_MIPS_HI16/LO16 relocations against imported symbols.
pub fn resolve_indirect_calls(
    cfg: &FunctionCfg,
    data: &[u8],
    base_addr: u32,
    is_le: bool,
    import_slots: &BTreeMap<u32, String>,
) -> Vec<IndirectCall> {
    let mut out = Vec::new();
    // Walk blocks looking for the pattern: lw $t9, off($gp) ; jalr $t9
    // lw: op=0x23, rt=25 ($t9), rs=28 ($gp). jalr: op=0, rs=25, funct=9.
    for (_start, block) in &cfg.blocks {
        let instrs = &block.instrs;
        let mut i = 0;
        while i + 1 < instrs.len() {
            let (_a0, w0) = instrs[i];
            let (a1, w1) = instrs[i + 1];
            if is_lw_t9_gp(w0) && is_jalr_t9(w1) {
                // off = sign_ext(imm16) of the lw; the GOT slot address is
                // gp + off. We don't know gp statically, so we look for a
                // matching import slot by the *relocated* value if available.
                let imm16 = (w0 & 0xFFFF) as i16 as i32 as u32;
                if let Some(name) = import_slots.get(&imm16) {
                    out.push(IndirectCall { callsite: a1, target: 0, name: Some(name.clone()) });
                }
            }
            i += 1;
        }
    }
    let _ = (base_addr, is_le, data);
    out
}

#[inline]
fn is_lw_t9_gp(w: u32) -> bool {
    let op = (w >> 26) & 0x3F;
    let rs = (w >> 21) & 0x1F;
    let rt = (w >> 16) & 0x1F;
    op == 0x23 && rs == 28 && rt == 25 // lw $t9, off($gp)
}

#[inline]
fn is_jalr_t9(w: u32) -> bool {
    let op = (w >> 26) & 0x3F;
    let rs = (w >> 21) & 0x1F;
    let funct = w & 0x3F;
    op == 0x00 && rs == 25 && funct == 0x09 // jalr $t9 (or jalr $ra,$t9)
}

/// Build CFGs for every function in `functions` over a single code section.
/// Returns the vector of per-function CFGs in the same order as `functions`.
pub fn build_all_cfgs(
    data: &[u8],
    base_addr: u32,
    functions: &[(u32, u32)], // (start, end_exclusive)
    is_le: bool,
) -> Vec<FunctionCfg> {
    functions
        .iter()
        .map(|&(start, end)| build_function_cfg(data, base_addr, start, end, is_le))
        .collect()
}

