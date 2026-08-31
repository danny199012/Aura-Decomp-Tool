//! PS1 binary analysis heuristics.
//!
//! Pure functions that take parsed ELF section data and return annotated,
//! structured results. This module exposes a single Tauri command,
//! [`analyze_ps1_binary`], which mirrors the architecture of
//! `sce_symbol_scanner.rs`: it takes a file path, parses the ELF via the
//! shared `parse_elf_file` helper in `main.rs`, and runs four heuristics:
//!
//! 1. **String extraction** from `.rodata` — null-terminated ASCII strings ≥4 chars.
//! 2. **Constant pool identification** (LUI+ORI pairs) that load a full 32-bit value.
//! 3. **Interrupt handler detection** based on PS1 entry conventions.
//! 4. **State machine pattern matching** — jump-table dispatch patterns.

use serde::Serialize;

// ---------------------------------------------------------------------------
// Result types (all Serialize so they can be returned from the Tauri command)
// ---------------------------------------------------------------------------

/// A single extracted ASCII string found in a `.rodata`-style section.
#[derive(Serialize, Debug)]
pub struct ExtractedString {
    /// Offset of the first byte within the section data.
    pub offset: usize,
    /// The decoded (lossy) string value.
    pub value: String,
    /// Length in bytes (excluding the terminating NUL).
    pub length: usize,
}

/// A LUI+ORI pair that together load a full 32-bit constant into one register.
#[derive(Serialize, Debug)]
pub struct ConstantPoolEntry {
    /// Register index ($0-$31) receiving the loaded value.
    pub register: u8,
    /// The full 32-bit value loaded by the pair.
    pub value: u32,
    /// Offset (in bytes from section start) of the LUI instruction.
    pub lui_offset: usize,
    /// Offset (in bytes from section start) of the ORI instruction.
    pub ori_offset: usize,
}

/// A function that matches PS1 interrupt-handler conventions.
#[derive(Serialize, Debug)]
pub struct InterruptHandler {
    /// Start offset within the code section (bytes from section start).
    pub offset: usize,
    /// Estimated size in bytes of the prologue/epilogue region inspected.
    pub size: usize,
    /// Human-readable reasons this function was flagged as an interrupt handler.
    pub reasons: Vec<String>,
}

/// A detected jump-table dispatch (state machine) pattern.
#[derive(Serialize, Debug)]
pub struct StateMachinePattern {
    /// Offset of the indexed load instruction that reads the table entry.
    pub load_offset: usize,
    /// Register holding the computed index.
    pub index_register: u8,
    /// Base register used for the table (if a base+offset load).
    pub base_register: Option<u8>,
    /// Offset of the branch/jump that dispatches to the table entry.
    pub jump_offset: usize,
    /// Estimated number of entries in the table (best-effort).
    pub estimated_entries: u32,
}

/// Aggregated result returned by [`analyze_ps1_binary`].
#[derive(Serialize, Debug)]
pub struct Ps1AnalysisResult {
    /// Strings extracted from read-only data sections.
    pub strings: Vec<ExtractedString>,
    /// LUI+ORI constant-pool pairs found in code sections.
    pub constants: Vec<ConstantPoolEntry>,
    /// Functions matching PS1 interrupt-handler conventions.
    pub interrupt_handlers: Vec<InterruptHandler>,
    /// Jump-table dispatch (state machine) patterns.
    pub state_machines: Vec<StateMachinePattern>,
}

// ---------------------------------------------------------------------------
// ELF section access helpers
// ---------------------------------------------------------------------------

/// Minimal view of an ELF section header, mirroring the fields in `main.rs`.
pub struct SectionView<'a> {
    pub name: &'a str,
    pub data: &'a [u8],
}

impl<'a> SectionView<'a> {
    fn new(name: &'a str, data: &'a [u8]) -> Self {
        SectionView { name, data }
    }
}

// ---------------------------------------------------------------------------
// 1. String extraction from .rodata
// ---------------------------------------------------------------------------

/// Scan a byte slice for null-terminated ASCII strings of at least `min_len`
/// characters and return their offsets and values.
pub fn extract_strings(data: &[u8], min_len: usize) -> Vec<ExtractedString> {
    let mut out = Vec::new();
    if data.is_empty() {
        return out;
    }

    // Walk the buffer, collecting runs of printable ASCII terminated by NUL.
    let mut i = 0usize;
    while i < data.len() {
        // Start a candidate string at any printable byte.
        if is_printable_ascii(data[i]) {
            let start = i;
            // Advance until we hit a NUL or end of buffer.
            while i < data.len() && data[i] != 0 {
                i += 1;
            }
            let len = i - start;
            if len >= min_len {
                let value = decode_ascii_run(&data[start..i]);
                out.push(ExtractedString {
                    offset: start,
                    value,
                    length: len,
                });
            }
        } else {
            // Skip non-printable bytes (including NUL terminators).
            i += 1;
        }
    }

    out
}

fn is_printable_ascii(b: u8) -> bool {
    b >= 0x20 && b <= 0x7e
}

/// Decode a run of bytes as lossy UTF-8 (ASCII-compatible).
fn decode_ascii_run(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

// ---------------------------------------------------------------------------
// 2. Constant pool identification (LUI + ORI pairs)
// ---------------------------------------------------------------------------

/// MIPS opcode field values used by the LUI/ORI pair detector.
const OP_LUI: u32 = 0x0c; // bits[31:26] == 001100 -> LUI
const OP_OR: u32 = 0x24;  // bits[31:26] == 100100 -> ORI (OR with immediate)

/// Scan a code section for `lui $rx, imm` immediately followed by
/// `ori $rx, $rx, imm2`, which together load the full 32-bit constant
/// `(imm << 16) | imm2` into register `$rx`. Returns each pair found.
pub fn identify_constant_pools(data: &[u8]) -> Vec<ConstantPoolEntry> {
    let mut out = Vec::new();
    if data.len() < 8 {
        return out;
    }

    // MIPS instructions are 4 bytes, little-endian on PS1.
    for i in (0..data.len()).step_by(4) {
        if i + 8 > data.len() {
            break;
        }
        let lui = u32::from_le_bytes([data[i], data[i + 1], data[i + 2], data[i + 3]]);
        let ori = u32::from_le_bytes([data[i + 4], data[i + 5], data[i + 6], data[i + 7]]);

        if is_lui(lui) && is_ori(ori) {
            let rt_lui = reg_rt(lui);
            let rs_ori = reg_rs(ori);
            let rt_ori = reg_rt(ori);

            // The ORI must target the same register that LUI loaded, and use
            // that same register as its source.
            if rt_lui != 0 && rt_lui == rt_ori && rt_lui == rs_ori {
                let imm1 = (lui >> 16) & 0xffff;
                let imm2 = ori & 0xffff;
                let value = (imm1 << 16) | imm2;
                out.push(ConstantPoolEntry {
                    register: rt_lui,
                    value,
                    lui_offset: i,
                    ori_offset: i + 4,
                });
            }
        }
    }

    out
}

fn is_lui(instr: u32) -> bool {
    (instr >> 26) == OP_LUI
}

fn is_ori(instr: u32) -> bool {
    (instr >> 26) == OP_OR
}

/// rt field, bits[20:16].
fn reg_rt(instr: u32) -> u8 {
    ((instr >> 16) & 0x1f) as u8
}

/// rs field, bits[25:21].
fn reg_rs(instr: u32) -> u8 {
    ((instr >> 21) & 0x1f) as u8
}

// ---------------------------------------------------------------------------
// 3. Interrupt handler detection
// ---------------------------------------------------------------------------

const OP_JALR: u32 = 0x0f; // bits[31:26] == 000011 -> JAL/JALR (base)
const OP_SW: u32 = 0x2a;   // store word
const OP_LW: u32 = 0x8e;   // load word

/// Detect functions that follow PS1 interrupt-handler conventions.
///
/// Heuristics applied to each candidate function prologue (first ~16 bytes):
/// - Saves `$ra` and/or `$fp`/frame pointer on the stack (`sw $ra, off($sp)`).
/// - Sets up a frame with `addiu $sp, $sp, -N`.
/// - Optionally jumps through a register (`jalr`) — common in IRQ dispatch.
pub fn detect_interrupt_handlers(data: &[u8]) -> Vec<InterruptHandler> {
    let mut out = Vec::new();
    if data.len() < 16 {
        return out;
    }

    // Inspect prologues at every instruction boundary (best-effort, since we
    // don't have a full function map here). We look for the classic PS1 IRQ
    // entry pattern: save $ra, adjust stack, then dispatch.
    let mut i = 0usize;
    while i + 4 <= data.len() {
        let instr = u32::from_le_bytes([data[i], data[i + 1], data[i + 2], data[i + 3]]);

        // A prologue that stores $ra (register 31) to the stack is a strong
        // signal of an interrupt entry point.
        if is_store_word(instr) && reg_rt(instr) == 31 {
            let mut reasons = Vec::new();
            reasons.push("saves $ra on the stack".to_string());

            // Look at the next instruction for a frame setup (addiu $sp).
            if i + 8 <= data.len() {
                let next = u32::from_le_bytes([data[i + 4], data[i + 5], data[i + 6], data[i + 7]]);
                if is_addiu_sp(next) {
                    reasons.push("adjusts stack frame (addiu $sp)".to_string());
                }
            }

            // Look a couple of instructions ahead for a jalr dispatch.
            let mut j = i;
            while j + 4 <= data.len() && j < i + 20 {
                let cand = u32::from_le_bytes([data[j], data[j + 1], data[j + 2], data[j + 3]]);
                if is_jalr(cand) {
                    reasons.push("dispatches via jalr (IRQ dispatch)".to_string());
                    break;
                }
                j += 4;
            }

            // Only flag when we have at least the $ra save plus one more signal.
            if reasons.len() >= 2 {
                out.push(InterruptHandler {
                    offset: i,
                    size: 16,
                    reasons,
                });
            }
        }

        i += 4;
    }

    out
}

fn is_store_word(instr: u32) -> bool {
    (instr >> 26) == OP_SW
}

fn is_load_word(instr: u32) -> bool {
    (instr >> 26) == OP_LW
}

/// `addiu $sp, $sp, imm` — frame setup. rs=$sp(29), rt=$sp(29).
fn is_addiu_sp(instr: u32) -> bool {
    let op = (instr >> 26) & 0x3f;
    // ADDIU opcode is 0x09 (001001); the special-form check differs, so we
    // match on the ALU immediate format with both registers being $sp.
    if op != 0x09 {
        return false;
    }
    reg_rt(instr) == 29 && reg_rs(instr) == 29
}

fn is_jalr(instr: u32) -> bool {
    (instr >> 26) == OP_JALR
}

// ---------------------------------------------------------------------------
// 4. State machine pattern matching (jump-table dispatch)
// ---------------------------------------------------------------------------

/// Detect jump-table dispatch patterns common in PS1 game code: an indexed
/// load (`lw $r, off($base + index<<shift)`) followed by a branch/jump to the
/// loaded table entry.
pub fn detect_state_machines(data: &[u8]) -> Vec<StateMachinePattern> {
    let mut out = Vec::new();
    if data.len() < 12 {
        return out;
    }

    for i in (0..data.len()).step_by(4) {
        if i + 12 > data.len() {
            break;
        }
        let load = u32::from_le_bytes([data[i], data[i + 1], data[i + 2], data[i + 3]]);

        // Indexed load: lw $rt, off($rs) where the offset encodes a scaled index.
        if is_load_word(load) {
            let rt = reg_rt(load);
            let base = reg_rs(load);
            let offset = (load >> 16) as i32;

            // A non-zero scaled offset suggests table indexing.
            if offset != 0 && rt != 0 {
                // Look for a jump/branch within the next few instructions that
                // uses the loaded register or a related dispatch register.
                let mut j = i + 4;
                while j + 4 <= data.len() && j < i + 16 {
                    let cand = u32::from_le_bytes([data[j], data[j + 1], data[j + 2], data[j + 3]]);
                    if is_jalr(cand) || is_jump(cand) {
                        out.push(StateMachinePattern {
                            load_offset: i,
                            index_register: rt,
                            base_register: Some(base),
                            jump_offset: j,
                            estimated_entries: estimate_table_entries(offset),
                        });
                        break;
                    }
                    j += 4;
                }
            }
        }
    }

    out
}

fn is_jump(instr: u32) -> bool {
    (instr >> 26) == 0x02 // J instruction
}

/// Best-effort estimate of table size from the scaled offset. A typical
/// `lw $r, N($base)` where N is a multiple of 4 implies N/4 entries before
/// this one; we expose that as a rough entry count.
fn estimate_table_entries(offset: i32) -> u32 {
    (offset / 4).unsigned_abs()
}

// ---------------------------------------------------------------------------
// Tauri command
// ---------------------------------------------------------------------------

use crate::{ElfFileInfo, ElfSection};

/// Analyze a PS1 ELF binary and return structured heuristic results.
#[tauri::command]
pub fn analyze_ps1_binary(path: String) -> Result<Ps1AnalysisResult, String> {
    let info = crate::parse_elf_file(path)?;

    // Partition sections by role.
    let mut rodata_sections: Vec<&ElfSection> = Vec::new();
    let mut code_sections: Vec<&ElfSection> = Vec::new();

    for s in &info.sections {
        if is_rodata_like(s) {
            rodata_sections.push(s);
        } else if is_code_like(s) {
            code_sections.push(s);
        }
    }

    // 1. Strings from .rodata (and any read-only data section).
    let mut strings: Vec<ExtractedString> = Vec::new();
    for s in &rodata_sections {
        strings.extend(extract_strings(&s.data, 4));
    }

    // 2. Constant pools + 3. interrupt handlers + 4. state machines from code.
    let mut constants: Vec<ConstantPoolEntry> = Vec::new();
    let mut interrupt_handlers: Vec<InterruptHandler> = Vec::new();
    let mut state_machines: Vec<StateMachinePattern> = Vec::new();

    for s in &code_sections {
        constants.extend(identify_constant_pools(&s.data));
        interrupt_handlers.extend(detect_interrupt_handlers(&s.data));
        state_machines.extend(detect_state_machines(&s.data));
    }

    Ok(Ps1AnalysisResult {
        strings,
        constants,
        interrupt_handlers,
        state_machines,
    })
}

/// A section is "rodata-like" if its name contains `rodata` or it is a known
/// read-only data segment.
fn is_rodata_like(s: &ElfSection) -> bool {
    s.name.contains("rodata") || s.name == ".data.rel.ro"
}

/// A section is "code-like" if it holds executable instructions.
fn is_code_like(s: &ElfSection) -> bool {
    s.name.starts_with(".text") || s.name == ".init" || s.name == ".fini"
}

// Keep the `SectionView` helper referenced (used by future extensions).
#[allow(dead_code)]
fn _section_view_keepalive<'a>(name: &'a str, data: &'a [u8]) -> SectionView<'a> {
    SectionView::new(name, data)
}