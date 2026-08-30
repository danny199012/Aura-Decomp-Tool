// GameCube / Xbox 360 ELF parser and PowerPC disassembler
// Provides alternative-to-Ghidra decompilation support for Nintendo platforms
// Supports GameCube (ELF) binaries

use serde::{Deserialize, Serialize};
use std::fs;

// The PowerPC disassembler lives in the shared `ppc_disasm` module;
// re-exported here so existing callers keep working.
pub use crate::ppc_disasm::{disassemble_ppc_instruction, PpcInstruction};

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
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeaderInfo {
    pub entry_point: u64,
    pub text_section_start: u64,
    pub is_stripped: bool,
    pub has_debug_info: bool,
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
    let shoff = if data.len() >= 48 {
        u64::from_le_bytes(data[40..48].try_into().unwrap())
    } else {
        0
    };
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
    let shoff_val = if data.len() >= 48 {
        u64::from_le_bytes(data[40..48].try_into().unwrap())
    } else {
        0
    };
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