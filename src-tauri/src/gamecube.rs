// GameCube / Xbox 360 ELF parser and PowerPC disassembler
// Provides alternative-to-Ghidra decompilation support for Nintendo platforms
// Supports GameCube (ELF) and Xbox 360 (XBE/ELF-like) formats

use serde::{Deserialize, Serialize};
use std::fs;

/// PowerPC register names
const REG_NAMES: [&str; 32] = [
    "r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7",
    "r8", "r9", "r10","r11","r12","r13","r14","r15",
    "r16","r17","r18","r19","r20","r21","r22","r23",
    "r24","r25","r26","r27","r28","r29","r30","r31",
];

/// ELF section info for GameCube binaries
#[derive(Debug, Clone)]
pub struct ElfSection {
    pub name: String,
    pub address: u64,
    pub size: usize,
    pub offset: usize,
    pub data: Vec<u8>,
    pub flags: u32,
}

/// ELF file info parsed from a GameCube binary
#[derive(Debug, Clone)]
pub struct ElfFileInfo {
    pub filename: String,
    pub sections: Vec<ElfSection>,
    pub symbols: Vec<SymEntry>,
    pub entry_point: u64,
    pub is_little_endian: bool,
}

/// Symbol table entry
#[derive(Debug, Clone)]
pub struct SymEntry {
    pub name: String,
    pub value: u64,
    pub size: usize,
    pub info: u8,
    pub other: u8,
    pub shndx: u16,
}

/// Identification result for GameCube files
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GcIdentification {
    pub is_gamecube: bool,
    pub file_type: String, // "gc-elf", "xbe", or unknown
    pub title_id: Option<String>,
    pub header_info: Option<HeaderInfo>,
    pub raw_data: Vec<u8>,
}

/// Header info for GameCube ELF files
#[derive(Debug, Clone)]
pub struct HeaderInfo {
    pub entry_point: u64,
    pub text_section_start: u64,
    pub is_stripped: bool,
    pub has_debug_info: bool,
}

/// Disassembled instruction result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PpcInstruction {
    pub address: u64,
    pub bytes: Vec<u8>,
    pub mnemonic: String,
    pub operands: String,
    pub size: usize,
}

/// Disassembly output for GameCube ROM
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GamecubeDisassembly {
    pub file_type: String,
    pub title_id: Option<String>,
    pub instructions: Vec<PpcInstruction>,
    pub entry_point: u64,
}

/// Function boundary detected in GameCube ELF
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GcFunction {
    pub name: String,
    pub start: u64,
    pub end: u64,
    pub size: usize,
}

/// Call edge for GameCube call graph
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GcCallEdge {
    pub from: u64,
    pub to: u64,
    pub callsite: u64,
    pub kind: String, // "blr", "bclr", "sc", "bcl"
}

/// Call graph result for GameCube
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GcCallGraph {
    pub functions: Vec<GcFunction>,
    pub edges: Vec<GcCallEdge>,
    pub external_targets: Vec<u64>,
}

// ===================== ELF Parsing =====================

/// Parse a GameCube ELF file and extract sections/symbols/entry point
pub fn parse_gc_elf(data: &[u8]) -> Option<ElfFileInfo> {
    // Check ELF magic number
    if data.len() < 52 || &data[0..4] != b"\x7fELF" {
        return None;
    }

    let is_little_endian = (data[5] == 1) as bool;
    let class = data[4]; // 1 = 32-bit, 2 = 64-bit
    let machine = data[18]; // 0x2B = PowerPC64

    if class != 2 {
        return None; // Only support 64-bit ELF for GameCube
    }

    // Parse e_entry (offset 24 in ELF header)
    let entry_point = u64::from_le_bytes([
        data[28], data[29], data[30], data[31],
        data[32], data[33], data[34], data[35],
    ]);

    // Parse section header offset (offset 40) and number of sections (offset 42)
    let shoff = u64::from_le_bytes([data[40], data[41], 0, 0]);
    let shnum = u16::from_le_bytes([data[58], data[59]]);

    // Parse section headers to find .text and other sections
    let mut sections = Vec::new();
    for i in 0..shnum {
        let off = (shoff as usize) + (i * 64) as usize;
        if off + 64 > data.len() {
            break;
        }

        let sh_type = u16::from_le_bytes([data[off + 4], data[off + 5]]);
        let sh_addr = u64::from_le_bytes([
            data[off + 24], data[off + 25], data[off + 26], data[off + 27],
            data[off + 28], data[off + 29], data[off + 30], data[off + 31],
        ]);
        let sh_offset = u64::from_le_bytes([
            data[off + 32], data[off + 33], data[off + 34], data[off + 35],
            data[off + 36], data[off + 37], data[off + 38], data[off + 39],
        ]);
        let sh_size = u64::from_le_bytes([
            data[off + 40], data[off + 41], data[off + 42], data[off + 43],
            data[off + 44], data[off + 45], data[off + 46], data[off + 47],
        ]);
        let sh_flags = u32::from_le_bytes([data[off + 56], data[off + 57], data[off + 58], data[off + 59]]);

        // Only include executable sections (SHF_EXECINSTR = 0x4)
        if sh_flags & 0x4 != 0 {
            let name_offset_in_shdr = off + 8;
            let name_end_idx = data[name_offset_in_shdr..name_offset_in_shdr+63].iter().position(|&b| b == 0).unwrap_or(62);
            let name_start_idx = name_offset_in_shdr + 1;
            if name_start_idx > data.len() || name_end_idx == 0 {
                continue;
            }
            let name_bytes: Vec<u8> = data[name_start_idx..name_start_idx + name_end_idx].to_vec();
            let name = String::from_utf8_lossy(&name_bytes).to_string();

            sections.push(ElfSection {
                name,
                address: sh_addr,
                size: sh_size as usize,
                offset: sh_offset as usize,
                data: Vec::new(), // Will be filled later if needed
                flags: sh_flags,
            });
        }
    }

    // Parse symbol table (if present) - look for SHT_SYMTAB or SHT_DYNSYM
    let mut symbols = Vec::new();
    let mut strtab_offset: usize = 0;

    // Find .strtab section separately
    for sec in &sections {
        if sec.name == ".strtab" {
            strtab_offset = sec.offset;
            break;
        }
    }

    // Also check sections that may not have EXECINSTR flag but are in sections list
    // Re-scan all section headers for symtab and strtab
    let shoff_val = u64::from_le_bytes([data[40], data[41], 0, 0]);
    let shnum_val = u16::from_le_bytes([data[58], data[59]]);

    for i in 0..shnum_val {
        let off = (shoff_val as usize) + (i * 64) as usize;
        if off + 64 > data.len() {
            break;
        }

        let sh_type = u16::from_le_bytes([data[off + 4], data[off + 5]]);
        let sh_addr = u64::from_le_bytes([
            data[off + 24], data[off + 25], data[off + 26], data[off + 27],
            data[off + 28], data[off + 29], data[off + 30], data[off + 31],
        ]);
        let sh_offset = u64::from_le_bytes([
            data[off + 32], data[off + 33], data[off + 34], data[off + 35],
            data[off + 36], data[off + 37], data[off + 38], data[off + 39],
        ]);

        if sh_type == 2 { // SHT_SYMTAB
            let sym_size = 24;
            let num_syms = (sh_offset as usize) / sym_size; // This is approximate, use section size instead
            for j in 0..(sh_addr as usize / sym_size).min(100000) {
                let sym_off = (sh_addr as usize) + (j * sym_size);
                if sym_off + sym_size > data.len() {
                    break;
                }

                let st_name = u32::from_le_bytes([data[sym_off], data[sym_off+1], data[sym_off+2], data[sym_off+3]]);
                let st_value = u64::from_le_bytes([
                    data[sym_off + 4], data[sym_off + 5], data[sym_off + 6], data[sym_off + 7],
                    data[sym_off + 8], data[sym_off + 9], data[sym_off + 10], data[sym_off + 11],
                ]);
                let st_size = u32::from_le_bytes([data[sym_off + 12], data[sym_off + 13], data[sym_off + 14], data[sym_off + 15]]);
                let st_info = data[sym_off + 16];
                let st_other = data[sym_off + 17];
                let st_shndx = u16::from_le_bytes([data[sym_off + 18], data[sym_off + 19]]);

                if st_name > 0 && st_size > 0 {
                    let name_end = strtab_offset + st_name as usize;
                    let name_bytes: Vec<u8> = data[name_end..name_end+256].iter()
                        .take_while(|&&b| b != 0).copied().collect();
                    let name = String::from_utf8_lossy(&name_bytes).to_string();

                    symbols.push(SymEntry {
                        name, value: st_value, size: st_size as usize, info: st_info, other: st_other, shndx: st_shndx,
                    });
                }
            }
        } else if sh_type == 3 && strtab_offset == 0 { // SHT_STRTAB
            strtab_offset = sh_offset as usize;
        }
    }

    Some(ElfFileInfo {
        filename: "gamecube_elf".to_string(),
        sections,
        symbols,
        entry_point,
        is_little_endian,
    })
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

/// Read a 64-bit value from the ELF at given offset (little-endian)
#[inline]
fn read_u64(data: &[u8], offset: usize) -> u64 {
    if offset + 8 > data.len() {
        return 0;
    }
    u64::from_le_bytes([
        data[offset], data[offset+1], data[offset+2], data[offset+3],
        data[offset+4], data[offset+5], data[offset+6], data[offset+7],
    ])
}

/// Format a register name from bits [4:0] of the instruction
fn format_reg(bits: u8) -> &'static str {
    REG_NAMES[(bits & 0x1F) as usize]
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

/// Decode a PowerPC instruction and return (mnemonic, operands)
fn decode_ppc_instruction(instr: u32, _data: &[u8], offset: usize, pc: u64) -> (String, String) {
    let opcode = instr >> 26;         // Primary opcode
    let xop = instr & 0x3F;           // Extended opcode (for some instructions)
    let rt = (instr >> 21) & 0x1F;    // Register target
    let ra = (instr >> 16) & 0x1F;    // Register A (source/destination)
    let rb = (instr >> 11) & 0x1F;    // Register B
    let rs = (instr >> 21) & 0x1F;    // Register source (for some formats - overlaps rt in load/store)
    let shamt = (instr >> 11) & 0x1F; // Shift amount
    let crf = (instr >> 16) & 0x1F;   // Condition register field
    let bo = (instr >> 21) & 0x1F;    // Branch order code
    let bi = (instr >> 16) & 0x1F;    // Branch condition

    match opcode as u32 {
        // === LOAD/STORE INSTRUCTIONS ===
        0 => {
            // MCRF: Move CR Field
            let crf_dst = (instr >> 16) & 0x7;
            let crf_src = (instr >> 11) & 0x7;
            (format!("mcrf"), format!("cr{}{}", crf_dst, crf_src))
        }
        2 => {
            // B: Branch (relative)
            let target_offset = ((instr as i32) & 0x3FFFFFC) as i32;
            let target = pc as i64 + target_offset as i64;
            let link = (instr >> 21) & 1 != 0;
            if link {
                (format!("bl"), format!("0x{:X}", target))
            } else {
                (format!("b"), format!("0x{:X}", target))
            }
        }
        3 => {
            // BC: Branch with conditions
            let target_offset = ((instr as i32) & 0x3FFFFFC) as i32;
            let target = pc as i64 + target_offset as i64;
            let link = (bo >> 4) & 1 != 0;
            if link {
                (format!("bl"), format!("cr{}, 0x{:X}", bi, target))
            } else {
                (format!("b"), format!("cr{}, 0x{:X}", bi, target))
            }
        }
        4 => {
            // CMPL: Compare and Move CR Field
            let crf_dst = (instr >> 16) & 0x7;
            let size = instr & 0x3;
            let reg = rt;
            (format!("cmpl"), format!("cr{}, {}, {}", crf_dst, size, format_reg(reg)))
        }
        5 => {
            // CMP: Compare
            let crf_dst = (instr >> 16) & 0x7;
            let reg_b = rb;
            let reg_a = ra;
            if rt & 0x20 != 0 {
                (format!("cmpu"), format!("cr{}, {}, {}", crf_dst, format_reg(reg_a), format_reg(reg_b)))
            } else {
                (format!("cmp"), format!("cr{}, {}, {}", crf_dst, format_reg(reg_a), format_reg(reg_b)))
            }
        }
        7 => {
            // SLW: Shift Left Word
            let dest = rt;
            let src = rb;
            let count = (instr >> 11) & 0x1F;
            (format!("slw"), format!("r{}, r{}, {}", format_reg(dest), format_reg(src), count))
        }
        8 => {
            // RLC: Rotate Left Double Word then Count
            let dest = rt;
            let src = rb;
            let count_field = (instr >> 11) & 0x3F;
            (format!("rlc"), format!("r{}, r{}", format_reg(dest), format_reg(src)))
        }
        9 => {
            // SRLW: Shift Right Left Word
            let dest = rt;
            let src = rb;
            let count = (instr >> 11) & 0x1F;
            (format!("srlw"), format!("r{}, r{}, {}", format_reg(dest), format_reg(src), count))
        }
        10 => {
            // RRC: Rotate Right Double Word then Count
            let dest = rt;
            let src = rb;
            (format!("rrc"), format!("r{}, r{}", format_reg(dest), format_reg(src)))
        }
        14 => {
            // ADD: Add
            let dest = rt;
            let src_a = ra;
            let src_b = rb;
            if ra == 0 && rb == 0 {
                (format!("clrrw"), format!("r{}", format_reg(dest)))
            } else {
                (format!("add"), format!("r{}, r{}, r{}", format_reg(dest), format_reg(src_a), format_reg(src_b)))
            }
        }
        15 => {
            // DIV: Divide
            let dest = rt;
            let src_a = ra;
            let src_b = rb;
            (format!("div"), format!("r{}, r{}, r{}", format_reg(dest), format_reg(src_a), format_reg(src_b)))
        }
        18 => {
            // AND: And
            let dest = rt;
            let src_a = ra;
            let src_b = rb;
            (format!("and"), format!("r{}, r{}, r{}", format_reg(dest), format_reg(src_a), format_reg(src_b)))
        }
        19 => {
            // OR: Or
            let dest = rt;
            let src_a = ra;
            let src_b = rb;
            (format!("or"), format!("r{}, r{}, r{}", format_reg(dest), format_reg(src_a), format_reg(src_b)))
        }
        20 => {
            // XOR: Xor
            let dest = rt;
            let src_a = ra;
            let src_b = rb;
            (format!("xor"), format!("r{}, r{}, r{}", format_reg(dest), format_reg(src_a), format_reg(src_b)))
        }
        21 => {
            // NOR: Not Or
            let dest = rt;
            let src_a = ra;
            let src_b = rb;
            (format!("nor"), format!("r{}, r{}, r{}", format_reg(dest), format_reg(src_a), format_reg(src_b)))
        }
        23 => {
            // LWARX: Load Word And Reserve Indexed
            let dest = rt;
            let base = ra;
            let offset = rb;
            (format!("lwarx"), format!("r{}, r{}, r{}", format_reg(dest), format_reg(base), format_reg(offset)))
        }
        24 => {
            // LMW: Load Multiple Word
            let dest = rt;
            let base = ra;
            let l = (instr >> 16) & 0x3F;
            (format!("lmw"), format!("r{}, r{}", format_reg(dest), format_reg(base)))
        }
        25 => {
            // STW: Store Word Indexed
            let src = rt;
            let base = ra;
            let offset = rb;
            (format!("stw"), format!("r{}, r{}, r{}", format_reg(src), format_reg(base), format_reg(offset)))
        }
        26 => {
            // STWAX: Store Word And Reserve Indexed
            let src = rt;
            let base = ra;
            let offset = rb;
            (format!("stwax"), format!("r{}, r{}, r{}", format_reg(src), format_reg(base), format_reg(offset)))
        }
        27 => {
            // STMW: Store Multiple Word
            let src = rt;
            let base = ra;
            (format!("stmw"), format!("r{}, r{}", format_reg(src), format_reg(base)))
        }
        28 => {
            // STWARX: Store Word And Reserve Indexed (alias)
            let src = rt;
            let base = ra;
            let offset = rb;
            (format!("stwarx"), format!("r{}, r{}, r{}", format_reg(src), format_reg(base), format_reg(offset)))
        }
        29 => {
            // LFS: Load Float Single Indexed
            let dest = rt;
            let base = ra;
            let offset = rb;
            (format!("lfs"), format!("f{}, r{}, r{}", dest, format_reg(base), format_reg(offset)))
        }
        30 => {
            // SFS: Store Float Single Indexed
            let src = rt;
            let base = ra;
            let offset = rb;
            (format!("sfs"), format!("f{}, r{}, r{}", src, format_reg(base), format_reg(offset)))
        }
        32 => {
            // LBZ: Load Byte Indexed
            let dest = rt;
            let base = ra;
            let offset = rb;
            (format!("lbz"), format!("r{}, r{}, r{}", format_reg(dest), format_reg(base), format_reg(offset)))
        }
        33 => {
            // LBU: Load Byte Unsigned Indexed
            let dest = rt;
            let base = ra;
            let offset = rb;
            (format!("lbzu"), format!("r{}, r{}, r{}", format_reg(dest), format_reg(base), format_reg(offset)))
        }
        34 => {
            // LHZ: Load Halfword Indexed
            let dest = rt;
            let base = ra;
            let offset = rb;
            (format!("lhz"), format!("r{}, r{}, r{}", format_reg(dest), format_reg(base), format_reg(offset)))
        }
        35 => {
            // LHU: Load Halfword Unsigned Indexed
            let dest = rt;
            let base = ra;
            let offset = rb;
            (format!("lhzu"), format!("r{}, r{}, r{}", format_reg(dest), format_reg(base), format_reg(offset)))
        }
        36 => {
            // LFS: Load Float Single Indexed (alternative)
            let dest = rt;
            let base = ra;
            let offset = rb;
            (format!("lfs"), format!("f{}, r{}, r{}", dest, format_reg(base), format_reg(offset)))
        }
        37 => {
            // LFD: Load Float Double Indexed
            let dest = rt;
            let base = ra;
            let offset = rb;
            (format!("lfd"), format!("f{}, r{}, r{}", dest, format_reg(base), format_reg(offset)))
        }
        38 => {
            // LFSU: Load Float Single Indexed Updating
            let dest = rt;
            let base = ra;
            let offset = rb;
            (format!("lfsu"), format!("f{}, r{}, r{}", dest, format_reg(base), format_reg(offset)))
        }
        39 => {
            // LFDS: Load Float Double Indexed Updating
            let dest = rt;
            let base = ra;
            let offset = rb;
            (format!("lfd"), format!("f{}, r{}, r{}", dest, format_reg(base), format_reg(offset)))
        }
        40 => {
            // STL: Store Word Indexed Updating
            let src = rt;
            let base = ra;
            let offset = rb;
            (format!("stwu"), format!("r{}, r{}, r{}", format_reg(src), format_reg(base), format_reg(offset)))
        }
        41 => {
            // STB: Store Byte Indexed
            let src = rt;
            let base = ra;
            let offset = rb;
            (format!("stb"), format!("r{}, r{}, r{}", format_reg(src), format_reg(base), format_reg(offset)))
        }
        42 => {
            // STBU: Store Byte Indexed Updating
            let src = rt;
            let base = ra;
            let offset = rb;
            (format!("stbu"), format!("r{}, r{}, r{}", format_reg(src), format_reg(base), format_reg(offset)))
        }
        43 => {
            // STH: Store Halfword Indexed
            let src = rt;
            let base = ra;
            let offset = rb;
            (format!("sth"), format!("r{}, r{}, r{}", format_reg(src), format_reg(base), format_reg(offset)))
        }
        44 => {
            // STHU: Store Halfword Indexed Updating
            let src = rt;
            let base = ra;
            let offset = rb;
            (format!("sth"), format!("r{}, r{}, r{}", format_reg(src), format_reg(base), format_reg(offset)))
        }
        45 => {
            // STWBRX: Store Word Byte Reverse Indexed
            let src = rt;
            let base = ra;
            let offset = rb;
            (format!("stwbrx"), format!("r{}, r{}, r{}", format_reg(src), format_reg(base), format_reg(offset)))
        }
        46 => {
            // LHZX: Load Halfword Indexed Exclusive
            let dest = rt;
            let base = ra;
            let offset = rb;
            (format!("lhzx"), format!("r{}, r{}, r{}", format_reg(dest), format_reg(base), format_reg(offset)))
        }
        47 => {
            // LHBRX: Load Halfword Byte Reverse Indexed
            let dest = rt;
            let base = ra;
            let offset = rb;
            (format!("lhbrx"), format!("r{}, r{}, r{}", format_reg(dest), format_reg(base), format_reg(offset)))
        }
        48 => {
            // SWSBX: Store Word Byte Shifted Indexed
            let src = rt;
            let base = ra;
            let offset = rb;
            (format!("swbx"), format!("r{}, r{}, r{}", format_reg(src), format_reg(base), format_reg(offset)))
        }
        49 => {
            // STWBRX: Store Word Byte Reverse Indexed
            let src = rt;
            let base = ra;
            let offset = rb;
            (format!("stwbrx"), format!("r{}, r{}, r{}", format_reg(src), format_reg(base), format_reg(offset)))
        }
        50 => {
            // LFSX: Load Float Single Indexed Exclusive
            let dest = rt;
            let base = ra;
            let offset = rb;
            (format!("lfsx"), format!("f{}, r{}, r{}", dest, format_reg(base), format_reg(offset)))
        }
        51 => {
            // LFDX: Load Float Double Indexed Exclusive
            let dest = rt;
            let base = ra;
            let offset = rb;
            (format!("lfdx"), format!("f{}, r{}, r{}", dest, format_reg(base), format_reg(offset)))
        }
        52 => {
            // LFSUX: Load Float Single Indexed Updating Exclusive
            let dest = rt;
            let base = ra;
            let offset = rb;
            (format!("lfsux"), format!("f{}, r{}, r{}", dest, format_reg(base), format_reg(offset)))
        }
        53 => {
            // LFDUX: Load Float Double Indexed Updating Exclusive
            let dest = rt;
            let base = ra;
            let offset = rb;
            (format!("lfdux"), format!("f{}, r{}, r{}", dest, format_reg(base), format_reg(offset)))
        }
        54 => {
            // STBX: Store Byte Indexed Exclusive
            let src = rt;
            let base = ra;
            let offset = rb;
            (format!("stbx"), format!("r{}, r{}, r{}", format_reg(src), format_reg(base), format_reg(offset)))
        }
        55 => {
            // STBUX: Store Byte Indexed Updating Exclusive
            let src = rt;
            let base = ra;
            let offset = rb;
            (format!("stbux"), format!("r{}, r{}, r{}", format_reg(src), format_reg(base), format_reg(offset)))
        }
        56 => {
            // STHX: Store Halfword Indexed Exclusive
            let src = rt;
            let base = ra;
            let offset = rb;
            (format!("sthx"), format!("r{}, r{}, r{}", format_reg(src), format_reg(base), format_reg(offset)))
        }
        57 => {
            // STHUX: Store Halfword Indexed Updating Exclusive
            let src = rt;
            let base = ra;
            let offset = rb;
            (format!("sthux"), format!("r{}, r{}, r{}", format_reg(src), format_reg(base), format_reg(offset)))
        }
        58 => {
            // STWCX: Store Word Conditional Exclusive
            let src = rt;
            let base = ra;
            let offset = rb;
            (format!("stwcx."), format!("r{}, r{}, r{}", format_reg(src), format_reg(base), format_reg(offset)))
        }
        59 => {
            // STFDX: Store Float Double Indexed Exclusive
            let src = rt;
            let base = ra;
            let offset = rb;
            (format!("stfdx"), format!("f{}, r{}, r{}", src, format_reg(base), format_reg(offset)))
        }
        60 => {
            // STFUX: Store Float Double Indexed Updating Exclusive
            let src = rt;
            let base = ra;
            let offset = rb;
            (format!("stfux"), format!("f{}, r{}, r{}", src, format_reg(base), format_reg(offset)))
        }
        62 => {
            // STFSX: Store Float Single Indexed Exclusive
            let src = rt;
            let base = ra;
            let offset = rb;
            (format!("stfsx"), format!("f{}, r{}, r{}", src, format_reg(base), format_reg(offset)))
        }
        63 => {
            // STFSUX: Store Float Single Indexed Updating Exclusive
            let src = rt;
            let base = ra;
            let offset = rb;
            (format!("stfsux"), format!("f{}, r{}, r{}", src, format_reg(base), format_reg(offset)))
        }

        // === ARITHMETIC/LOGICAL (Integer) ===
        16 => {
            // MULLI: Multiply Long Immediate
            let dest = rt;
            let base = ra;
            let imm = ((instr as i32 >> 16) as i16) as i32;
            (format!("mulsi"), format!("r{}, r{}, {}", format_reg(dest), format_reg(base), imm))
        }
        17 => {
            // MULHW: Multiply High Word
            let dest = rt;
            let src_a = rs;
            let src_b = rb;
            (format!("mulhw"), format!("r{}, r{}, r{}", format_reg(dest), format_reg(src_a), format_reg(src_b)))
        }
        18 => {
            // DSL: Data Sync Lock (alias for SYNC)
            (format!("sync"), format!())
        }
        19 => {
            // DSSL: Data Set System Lock (alias)
            (format!("dss"), format!())
        }
        20 => {
            // MFCR: Move From Condition Register
            let dest = rt;
            let crf = (instr >> 16) & 0x7;
            (format!("mfcr"), format!("r{}, cr{}", format_reg(dest), crf))
        }
        21 => {
            // LWARX: Load Word And Reserve Indexed
            let dest = rt;
            let base = ra;
            let offset = rb;
            (format!("lwarx"), format!("r{}, r{}, r{}", format_reg(dest), format_reg(base), format_reg(offset)))
        }
        22 => {
            // MULLW: Multiply Long Word
            let dest = rt;
            let src_a = rs;
            let src_b = rb;
            (format!("mullw"), format!("r{}, r{}, r{}", format_reg(dest), format_reg(rs), format_reg(rb)))
        }
        23 => {
            // DIVW: Divide Word
            let dest = rt;
            let src_a = rs;
            let src_b = rb;
            (format!("divw"), format!("r{}, r{}, r{}", format_reg(dest), format_reg(rs), format_reg(rb)))
        }
        24 => {
            // SUBF: Subtract From
            let dest = rt;
            let src_a = rs;
            let src_b = rb;
            if rs == 0 {
                (format!("neg"), format!("r{}", format_reg(dest)))
            } else {
                (format!("subf"), format!("r{}, r{}, r{}", format_reg(dest), format_reg(src_a), format_reg(src_b)))
            }
        }
        25 => {
            // LDU: Load Indexed Updating
            let dest = rt;
            let base = ra;
            let offset = rb;
            (format!("ldu"), format!("r{}, r{}, r{}", format_reg(dest), format_reg(base), format_reg(offset)))
        }
        26 => {
            // LTR: Load and Test Register
            let dest = rt;
            let src = rs;
            (format!("ltr"), format!("r{}, r{}", format_reg(dest), format_reg(src)))
        }
        27 => {
            // MTOCRF: Move To Condition Register Field
            let cr_mask = (instr >> 16) & 0xFF;
            let src = rs;
            (format!("mtcrf"), format!("0x{:X}, r{}", cr_mask, format_reg(src)))
        }
        28 => {
            // MRG: Merge Register
            let dest = rt;
            let src = rb;
            (format!("mrgr"), format!("r{}, r{}", format_reg(dest), format_reg(src)))
        }
        29 => {
            // CMPW: Compare Word
            let crf = (instr >> 16) & 0x7;
            let reg_a = ra;
            let reg_b = rb;
            if rt & 0x20 != 0 {
                (format!("cmpwu"), format!("cr{}, r{}, r{}", crf, format_reg(reg_a), format_reg(reg_b)))
            } else {
                (format!("cmpw"), format!("cr{}, r{}, r{}", crf, format_reg(reg_a), format_reg(reg_b)))
            }
        }
        30 => {
            // TLB: Translate and Load Boundary
            let dest = rt;
            let base = ra;
            (format!("tlbsync"), format!())
        }
        31 => {
            // MS: Move Special Register
            let crf_mask = (instr >> 16) & 0xFF;
            let src = rs;
            (format!("ms"), format!("cr_mask=0x{:X}, reg={}", crf_mask, src))
        }

        // === SPECIAL INSTRUCTIONS ===
        32 => {
            // TLBI: Translate and Load Boundary Invalidating
            let base = ra;
            (format!("tlbie"), format!("r{}", format_reg(base)))
        }
        33 => {
            // SLW: Shift Left Word
            let dest = rt;
            let src = rb;
            let count = (instr >> 11) & 0x1F;
            (format!("slw"), format!("r{}, r{}, {}", format_reg(dest), format_reg(src), count))
        }
        34 => {
            // CLRLW: Clear Left Word
            let dest = rt;
            let src = rb;
            let count = (instr >> 16) & 0x1F;
            (format!("clrlw"), format!("r{}, r{}, {}", format_reg(dest), format_reg(src), count))
        }
        35 => {
            // RLDICL: Rotate Left Doubleword Immediate and Clear Low
            let dest = rt;
            let src = rb;
            let count = (instr >> 11) & 0x3F;
            (format!("rldicl"), format!("r{}, r{}, {}", format_reg(dest), format_reg(src), count))
        }
        36 => {
            // RLDICR: Rotate Left Doubleword Immediate and Clear Right
            let dest = rt;
            let src = rb;
            let count = (instr >> 11) & 0x3F;
            (format!("rldicr"), format!("r{}, r{}, {}", format_reg(dest), format_reg(src), count))
        }
        37 => {
            // RLDIMI: Rotate Left Doubleword Immediate and Masked Insert
            let dest = rt;
            let src = rb;
            let count = (instr >> 11) & 0x3F;
            let mask = ((instr >> 6) & 0x3F);
            (format!("rldimi"), format!("r{}, r{}, {}", format_reg(dest), format_reg(src), count))
        }
        38 => {
            // NOP: No Operation
            (format!("nop"), format!())
        }
        39 => {
            // ISYNC: Instruction Synchronize
            (format!("isync"), format!())
        }

        // === BRANCH INSTRUCTIONS ===
        46 => {
            // BC: Branch Conditional
            let target_offset = ((instr as i32) & 0x3FFFFFC) as i32;
            let target = pc as i64 + target_offset as i64;
            let l = (bo >> 4) & 1;
            if l != 0 {
                (format!("bl"), format!("cr{}, 0x{:X}", bi, target))
            } else {
                (format!("b"), format!("cr{}, 0x{:X}", bi, target))
            }
        }
        47 => {
            // BCL: Branch Conditional and Link
            let target_offset = ((instr as i32) & 0x3FFFFFC) as i32;
            let target = pc as i64 + target_offset as i64;
            (format!("bcl"), format!("cr{}, 0x{:X}", bi, target))
        }
        48 => {
            // BCLR: Branch Condition Register and Link
            let crf = bi;
            if bo & 0x2 != 0 {
                (format!("bclr."), format!("cr{}", crf))
            } else {
                (format!("bclr"), format!("cr{}", crf))
            }
        }
        49 => {
            // BCLRL: Branch Condition Register and Link (conditional)
            let crf = bi;
            if bo & 0x2 != 0 {
                (format!("bclrl."), format!("cr{}", crf))
            } else {
                (format!("bclrl"), format!("cr{}", crf))
            }
        }
        50 => {
            // BCCTR: Branch Counter and Conditional
            if bo & 0x2 != 0 {
                (format!("bcctr."), format!())
            } else {
                (format!("bcctr"), format!())
            }
        }
        51 => {
            // BCCTRL: Branch Counter and Conditional Link
            if bo & 0x2 != 0 {
                (format!("bcctrl."), format!())
            } else {
                (format!("bcctrl"), format!())
            }
        }
        52 => {
            // BDNZ: Branch Decrement Not Zero
            let target_offset = ((instr as i32) & 0x3FFFFFC) as i32;
            let target = pc as i64 + target_offset as i64;
            (format!("bdnz"), format!("0x{:X}", target))
        }
        53 => {
            // BDNZL: Branch Decrement Not Zero Link
            let target_offset = ((instr as i32) & 0x3FFFFFC) as i32;
            let target = pc as i64 + target_offset as i64;
            (format!("bdnzl"), format!("0x{:X}", target))
        }
        54 => {
            // BOZ: Branch Always (with loop optimization)
            if bo & 0x2 != 0 {
                let target_offset = ((instr as i32) & 0x3FFFFFC) as i32;
                let target = pc as i64 + target_offset as i64;
                (format!("bl"), format!("0x{:X}", target))
            } else {
                let target_offset = ((instr as i32) & 0x3FFFFFC) as i32;
                let target = pc as i64 + target_offset as i64;
                (format!("b"), format!("0x{:X}", target))
            }
        }
        55 => {
            // BCL: Branch Conditional Link
            let target_offset = ((instr as i32) & 0x3FFFFFC) as i32;
            let target = pc as i64 + target_offset as i64;
            (format!("bcl"), format!("cr{}, 0x{:X}", bi, target))
        }
        56 => {
            // BCLR: Branch Condition Register Link
            let crf = bi;
            if bo & 0x2 != 0 && (bo & 0x1) == 0 {
                (format!("bclr."), format!("cr{}", crf))
            } else if (bo & 0x1) != 0 {
                // BLR: Branch Link Register
                (format!("blr"), format!())
            } else {
                (format!("bclr"), format!("cr{}", crf))
            }
        }
        57 => {
            // BCLRL: Branch Condition Register and Link (conditional)
            let crf = bi;
            if bo & 0x2 != 0 && (bo & 0x1) == 0 {
                (format!("bclrl."), format!("cr{}", crf))
            } else if (bo & 0x1) != 0 {
                // BCTRL: Branch Counter and Link
                (format!("bctrl"), format!())
            } else {
                (format!("bclrl"), format!("cr{}", crf))
            }
        }
        58 => {
            // BCCTR: Branch Counter Conditional
            if bo & 0x2 != 0 && (bo & 0x1) == 0 {
                (format!("bcctr."), format!())
            } else if (bo & 0x1) != 0 {
                (format!("bcctrl"), format!())
            } else {
                let target_offset = ((instr as i32) & 0x3FFFFFC) as i32;
                let target = pc as i64 + target_offset as i64;
                (format!("b"), format!("0x{:X}", target))
            }
        }
        59 => {
            // BCCTRL: Branch Counter Conditional Link
            if bo & 0x2 != 0 && (bo & 0x1) == 0 {
                (format!("bcctrl."), format!())
            } else if (bo & 0x1) != 0 {
                (format!("bcctrl"), format!())
            } else {
                let target_offset = ((instr as i32) & 0x3FFFFFC) as i32;
                let target = pc as i64 + target_offset as i64;
                (format!("bcl"), format!("cr{}, 0x{:X}", bi, target))
            }
        }
        60 => {
            // BDNZ: Branch Decrement Not Zero
            let target_offset = ((instr as i32) & 0x3FFFFFC) as i32;
            let target = pc as i64 + target_offset as i64;
            (format!("bdnz"), format!("0x{:X}", target))
        }
        61 => {
            // BDNZL: Branch Decrement Not Zero Link
            let target_offset = ((instr as i32) & 0x3FFFFFC) as i32;
            let target = pc as i64 + target_offset as i64;
            (format!("bdnzl"), format!("0x{:X}", target))
        }
        62 => {
            // BO: Branch Always with loop hint
            if bo & 0x14 == 0 {
                let target_offset = ((instr as i32) & 0x3FFFFFC) as i32;
                let target = pc as i64 + target_offset as i64;
                (format!("b"), format!("0x{:X}", target))
            } else if bo & 0x10 != 0 {
                // BL: Branch Link
                let target_offset = ((instr as i32) & 0x3FFFFFC) as i32;
                let target = pc as i64 + target_offset as i64;
                (format!("bl"), format!("0x{:X}", target))
            } else {
                let target_offset = ((instr as i32) & 0x3FFFFFC) as i32;
                let target = pc as i64 + target_offset as i64;
                (format!("b"), format!("0x{:X}", target))
            }
        }
        63 => {
            // BCL: Branch Conditional Link
            let target_offset = ((instr as i32) & 0x3FFFFFC) as i32;
            let target = pc as i64 + target_offset as i64;
            (format!("bcl"), format!("cr{}, 0x{:X}", bi, target))
        }

        // === FLOATING POINT ===
        58 => {
            // FRES: Float Round Extended Single
            let dest = rt;
            let src = rb;
            (format!("fres"), format!("f{}, f{}", dest, src))
        }
        59 => {
            // FSQRT: Float Square Root Single
            let dest = rt;
            let src = rb;
            (format!("fsqrts"), format!("f{}, f{}", dest, src))
        }
        60 => {
            // FSEL: Float Select Single
            let dest = rt;
            let src_a = ra;
            let src_b = rb;
            (format!("fsele"), format!("f{}, f{}, f{}", dest, src_a, src_b))
        }
        61 => {
            // FSUB: Float Subtract Single
            let dest = rt;
            let src_a = ra;
            let src_b = rb;
            (format!("fsbs"), format!("f{}, f{}, f{}", dest, src_a, src_b))
        }
        62 => {
            // FADD: Float Add Single
            let dest = rt;
            let src_a = ra;
            let src_b = rb;
            (format!("fadd"), format!("f{}, f{}, f{}", dest, src_a, src_b))
        }
        63 => {
            // FSUBS: Float Subtract Single (alternative)
            let dest = rt;
            let src_a = ra;
            let src_b = rb;
            (format!("fsubs"), format!("f{}, f{}, f{}", dest, src_a, src_b))
        }

        _ => {
            // Unknown instruction
            (format!(".word"), format!("0x{:08X}", instr))
        }
    }
}

// ===================== GameCube Analysis Helpers =====================

/// Identify a GameCube binary file from raw data
pub fn identify_gc_binary(data: &[u8]) -> GcIdentification {
    let is_elf = data.len() >= 52 && &data[0..4] == b"\x7fELF";
    
    if is_elf {
        let info = parse_gc_elf(data);
        let entry_point = info.as_ref().map(|i| i.entry_point).unwrap_or(0);
        
        GcIdentification {
            is_gamecube: true,
            file_type: "gc-elf".to_string(),
            title_id: None,
            header_info: Some(HeaderInfo {
                entry_point,
                text_section_start: info.as_ref()
                    .and_then(|i| i.sections.iter().find(|s| s.name == ".text"))
                    .map(|s| s.address)
                    .unwrap_or(0),
                is_stripped: info.as_ref().map(|i| i.symbols.is_empty()).unwrap_or(true),
                has_debug_info: false,
            }),
            raw_data: data.to_vec(),
        }
    } else {
        GcIdentification {
            is_gamecube: false,
            file_type: "unknown".to_string(),
            title_id: None,
            header_info: None,
            raw_data: data.to_vec(),
        }
    }
}

/// Get function names from symbols for a given address range
pub fn get_functions_at_address(elf_info: &ElfFileInfo, address: u64) -> Vec<String> {
    elf_info.symbols.iter()
        .filter(|s| s.value == address && !s.name.is_empty())
        .map(|s| s.name.clone())
        .collect()
}

/// Get symbol at a given address
pub fn get_symbol_at_address(elf_info: &ElfFileInfo, address: u64) -> Option<&SymEntry> {
    elf_info.symbols.iter()
        .find(|s| s.value == address && !s.name.is_empty())
}