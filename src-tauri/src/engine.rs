//! Shared analysis engine for Aura Decomp Tool.
//!
//! Pure, Tauri-free core: ELF32 parsing, magic identification, function
//! detection, call-graph construction, MIPS + GameBoy disassemblers, SDK
//! scan and config/export helpers. Compiled into BOTH the GUI binary
//! (`mod engine;` in main.rs) and the standalone `aura-cli` (via `#[path]`),
//! so there is a single source of truth for the analysis engine.

use serde::{Deserialize, Serialize};
use std::sync::OnceLock;
use std::path::Path;

use crate::sce_symbol_scanner::{CodeSection, SceSymbolDatabase, SceSymbolMatch};
use std::fs;
use crate::{decomp_export, ps1_symbols, ps3, ps4ps5, sdk_symbols, wiiu, xbox, xbox360};

/// GameBoy ROM header info (first 0x150 bytes are standardized)
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct GbHeader {
    pub title: String,
    pub manufacturer_code: String,
    pub cgb_flag: u8,
    /// "gb" or "cgb"
    pub mode: String,
    pub sgb_flag: u8,
    pub licensee_code: Option<(u8, u8)>,
    pub version: u8,
    pub rom_size: usize,
    pub ram_size: usize,
    pub destination: u8,
    pub header_checksum: u8,
    pub global_checksum: u16,
}

/// A single Z80 instruction for the disassembly output
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Z80Instruction {
    pub address: u32,
    pub bytes: Vec<u8>,
    pub mnemonic: String,
    pub operand: String,
    pub size: u8,
}

/// Result of a GameBoy ROM identification
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct GbIdentification {
    pub is_gameboy: bool,
    pub header: Option<GbHeader>,
    pub rom_data: Vec<u8>,
}


/// Open + parse an ELF32 file by path. Kept here (not in the GUI layer) so both
/// the engine's export routing and the CLI can parse files without a Tauri
/// command being involved.
/// Open + parse an ELF32 file by path. Named `_engine` so the GUI's own
/// `parse_elf_file` Tauri command (which wraps this) can keep its name.
pub fn parse_elf_file_engine(path: String) -> Result<ElfFileInfo, String> {
    let data = std::fs::read(&path).map_err(|e| format!("Failed to read file: {e}"))?;
    let filename = path
        .split('/')
        .last()
        .or(path.split('\\').last())
        .unwrap_or("unknown")
        .to_string();
    parse_elf_data(&data, &filename)
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ElfSection {
    pub name: String,
    pub address: u32,
    pub size: u32,
    pub offset: u32,
    pub data: Vec<u8>,
    #[serde(default)]
    pub flags: u32,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ElfSymbol {
    pub name: String,
    pub address: u32,
    pub size: u32,
    pub section: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ElfFileInfo {
    pub filename: String,
    pub sections: Vec<ElfSection>,
    pub symbols: Vec<ElfSymbol>,
    pub entry_point: u32,
    pub file_size: u64,
    pub is_little_endian: bool,
    pub is_32bit: bool,
    /// Dynamic relocations (SHT_REL / SHT_RELA). Retail PS2 games are usually
    /// statically linked and have none; dev/homebrew builds use these to name
    /// imported symbols at specific call-site offsets.
    #[serde(default)]
    pub relocations: Vec<Relocation>,
}

/// A single ELF relocation entry (mirrors what ps2recomp's Relocation carries).
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Relocation {
    /// ABSOLUTE virtual address where the fixup applies (target section's
    /// sh_addr + r_offset). Section-relative r_offset (ET_REL/homebrew) is
    /// normalized here so it matches the absolute callsite addresses the call
    /// graph emits; for ET_EXEC binaries this is already absolute.
    pub offset: u32,
    /// Resolved symbol name (empty if the symbol is unnamed/section-local).
    pub symbol_name: String,
    /// MIPS relocation type (R_MIPS_*). R_MIPS_26 (= 4) patches JAL/J targets.
    pub r_type: u32,
    /// Symbol index in the referenced symbol table.
    pub symbol: u32,
}

/// MIPS ELF relocation type numbers (ELF MIPS ABI). Only R_MIPS_26 (the JAL/J
/// call relocation) is used to resolve call-graph targets to import names; the
/// 16-bit immediate types patch lui/addiu pairs, not calls.
const R_MIPS_26: u32 = 4;

/// Helper functions to read u32 from byte slice with endianness support
pub fn read_u32(data: &[u8], offset: usize, is_little_endian: bool) -> u32 {
    if offset + 4 > data.len() {
        return 0;
    }
    if is_little_endian {
        u32::from_le_bytes([data[offset], data[offset+1], data[offset+2], data[offset+3]])
    } else {
        u32::from_be_bytes([data[offset], data[offset+1], data[offset+2], data[offset+3]])
    }
}

/// Helper functions to read u16 from byte slice with endianness support
pub fn read_u16(data: &[u8], offset: usize, is_little_endian: bool) -> u16 {
    if offset + 2 > data.len() {
        return 0;
    }
    if is_little_endian {
        u16::from_le_bytes([data[offset], data[offset+1]])
    } else {
        u16::from_be_bytes([data[offset], data[offset+1]])
    }
}

/// Core ELF32 parser operating on in-memory bytes. Shared by `parse_elf_file`
/// (path-based Tauri command) and the PS1 disc-image path, which extracts the
/// embedded executable first and parses that.
pub fn parse_elf_data(data: &[u8], filename: &str) -> Result<ElfFileInfo, String> {
    if data.len() < 64 {
        return Err("File too small to be a valid ELF".to_string());
    }

    // Check ELF magic number: 0x7f 'E' 'L' 'F'
    if data[0..4] != [0x7f, b'E', b'L', b'F'] {
        return Err("Not a valid ELF file (bad magic number)".to_string());
    }

    let is_32bit = data[4] == 1; // EI_CLASS: ELFCLASS32 = 1
    let is_little_endian = data[5] == 1; // EI_DATA: 1 = LSB, 2 = MSB

    if !is_32bit {
        return Err("Only 32-bit ELF files are supported".to_string());
    }

    // Parse ELF header for 32-bit. EVERY field must respect the file's endianness;
    // the previous code hard-coded big-endian for the counts/sizes, which silently
    // corrupted section parsing on little-endian (PS2) ELFs.
    let e_type = read_u16(&data, 16, is_little_endian);
    let e_machine = read_u16(&data, 18, is_little_endian);
    let _e_version = read_u32(&data, 20, is_little_endian);
    let e_entry = read_u32(&data, 24, is_little_endian);
    let _e_phoff = read_u32(&data, 28, is_little_endian);
    let e_shoff = read_u32(&data, 32, is_little_endian);
    let _e_phentsize = read_u16(&data, 42, is_little_endian);
    let _e_phnum = read_u16(&data, 44, is_little_endian);
    let e_shentsize = read_u16(&data, 46, is_little_endian);
    let e_shnum = read_u16(&data, 48, is_little_endian);
    let e_shstrndx = read_u16(&data, 50, is_little_endian);


    let mut sections: Vec<ElfSection> = Vec::new();
    let mut symbols: Vec<ElfSymbol> = Vec::new();

    if e_shoff > 0 && e_shnum > 0 && (e_shoff as usize) < data.len() {
        // Parse section headers to get section name string table
        let shstrtab_offset = (e_shoff as usize) + (e_shstrndx as usize) * (e_shentsize as usize);

        if shstrtab_offset + 24 <= data.len() {
            let str_tab_offset: u32 = read_u32(&data, shstrtab_offset + 16, is_little_endian);
            let str_tab_size: u32 = read_u32(&data, shstrtab_offset + 20, is_little_endian);


            if str_tab_offset < data.len() as u32 && str_tab_size > 0 {
                let str_tab_end = std::cmp::min(str_tab_offset + str_tab_size, data.len() as u32) as usize;
                let str_table = &data[str_tab_offset as usize..str_tab_end];

                // Find the null string to validate the string table
                if let Some(null_pos) = str_table.iter().position(|&b| b == 0) {
                    let str_table_str = std::str::from_utf8(&str_table[..null_pos]).unwrap_or("");

                    // Parse each section header
                    for i in 0..e_shnum {
                        let sh_offset = (e_shoff as usize) + (i as usize) * (e_shentsize as usize);
                        if sh_offset + (e_shentsize as usize) > data.len() {
                            break;
                        }

                        let sh_name_idx: u32 = read_u32(&data, sh_offset, is_little_endian);
                        let sh_type: u32 = read_u32(&data, sh_offset + 4, is_little_endian);
                        let sh_flags: u32 = read_u32(&data, sh_offset + 8, is_little_endian);
                        let sh_addr: u32 = read_u32(&data, sh_offset + 12, is_little_endian);
                        let sh_offset_val: u32 = read_u32(&data, sh_offset + 16, is_little_endian);
                        let sh_size: u32 = read_u32(&data, sh_offset + 20, is_little_endian);
                        let sh_link: u32 = read_u32(&data, sh_offset + 24, is_little_endian);

                        // Get section name from string table
                        let section_name = if sh_name_idx < str_table.len() as u32 {
                            let name_start = str_table.iter().skip(sh_name_idx as usize).position(|&b| b == 0);
                            if let Some(name_len) = name_start {
                                std::str::from_utf8(&str_table[sh_name_idx as usize..sh_name_idx as usize + name_len]).unwrap_or("").to_string()
                            } else {
                                format!("<name {}>", sh_name_idx)
                            }
                        } else {
                            String::new()
                        };


                        // SHT_PROGBITS (1) - actual data sections like .text, .data
                        if sh_type == 1 && sh_size > 0 {
                            let data_start = sh_offset_val as usize;
                            let data_end = std::cmp::min(data_start + sh_size as usize, data.len());

                            sections.push(ElfSection {
                                name: format!(".{}", if section_name.starts_with('.') { &section_name[1..] } else { &section_name }),
                                address: sh_addr,
                                size: sh_size,
                                offset: sh_offset_val,
                                data: data[data_start..data_end].to_vec(),
                                flags: sh_flags,
                            });
                        }

                        // SHT_SYMTAB (2) and SHT_DYNSYM (11)
                        if sh_type == 2 || sh_type == 11 {
                            if sh_size > 0 && sh_offset_val < data.len() as u32 {
                                // ELF32 symbol entry is 16 bytes
                                let sym_entry_size = 16u32;
                                let num_symbols = sh_size / sym_entry_size;

                                // The linked section table (sh_link) contains the string table for symbol names
                                if sh_link < e_shnum as u32 {
                                    let sym_stab_offset = (e_shoff as usize) + (sh_link as usize) * (e_shentsize as usize);
                                    if sym_stab_offset + 24 <= data.len() {
                                        let sym_str_offset: u32 = read_u32(&data, sym_stab_offset + 16, is_little_endian);
                                        let sym_str_size: u32 = read_u32(&data, sym_stab_offset + 20, is_little_endian);

                                        if sym_str_offset < data.len() as u32 && sym_str_size > 0 {
                                            let sym_str_end = std::cmp::min(sym_str_offset + sym_str_size, data.len() as u32) as usize;
                                            let sym_str_table = &data[sym_str_offset as usize..sym_str_end];

                                            for j in 0..num_symbols {
                                                let sym_off = (sh_offset_val as usize) + (j as usize * sym_entry_size as usize);
                                                if sym_off + sym_entry_size as usize > data.len() {
                                                    break;
                                                }

                                                let st_name_idx: u32 = read_u32(&data, sym_off, is_little_endian);
                                                let st_info: u8 = data[sym_off + 4];
                                                let _st_other: u8 = data[sym_off + 5];
                                                let st_shndx: u16 = read_u16(&data, sym_off + 6, is_little_endian);
                                                let st_value: u32 = read_u32(&data, sym_off + 8, is_little_endian);
                                                let st_size_val: u32 = read_u32(&data, sym_off + 12, is_little_endian);

                                                // STT_FUNC = 0x2
                                                let _st_type = st_info & 0xf;

                                                if st_name_idx > 0 && st_name_idx < sym_str_table.len() as u32 {
                                                    let name_start = (st_name_idx as usize)..sym_str_table.len();
                                                    if let Some(name_len) = sym_str_table[name_start.start..].iter().position(|&b| b == 0) {
                                                        let name_bytes = &sym_str_table[name_start.start..name_start.start + name_len];
                                                        let name = std::str::from_utf8(name_bytes).unwrap_or("").to_string();

                                                        let section_str = if st_shndx != 0xFFFF {
                                                            format!("#{}", st_shndx)
                                                        } else {
                                                            "NOSEL".to_string()
                                                        };

                                                        symbols.push(ElfSymbol {
                                                            name: if name.is_empty() { format!("0x{:08X}", st_value) } else { name },
                                                            address: st_value,
                                                            size: st_size_val,
                                                            section: section_str,
                                                        });
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    // Sort sections by address
    sections.sort_by_key(|s| s.address);

    // Sort and deduplicate symbols by address
    symbols.sort_by_key(|s| s.address);

    // ---- Relocation pass -------------------------------------------------
    // Walk section headers for SHT_REL / SHT_RELA and resolve each entry's
    // symbol name. Retail PS2 games usually have none (statically linked);
    // dev/homebrew builds use them to name imports.
    let relocations = parse_relocations(data, e_shoff, e_shnum, e_shentsize, is_little_endian);

    Ok(ElfFileInfo {
        filename: filename.to_string(),
        sections,
        symbols,
        entry_point: e_entry,
        file_size: data.len() as u64,
        is_little_endian,
        is_32bit,
        relocations,
    })
}

/// Parse ELF32 relocations from SHT_REL (9) and SHT_RELA (4) sections.
/// Pure function (no I/O) so it can be unit-tested in isolation.
/// Resolves each relocation's symbol name via the linked symbol + string tables.
fn parse_relocations(
    data: &[u8],
    e_shoff: u32,
    e_shnum: u16,
    e_shentsize: u16,
    is_little_endian: bool,
) -> Vec<Relocation> {
    let mut relocations: Vec<Relocation> = Vec::new();
    if e_shoff == 0 || e_shnum == 0 || (e_shoff as usize) >= data.len() {
        return relocations;
    }

    // ELF32_Shdr (40 bytes): name(4) type(4) flags(4) addr(4) offset(4)
    //                       size(4) link(4) info(4) addralign(4) entsize(4)
    // Fields we need: type, addr, offset, size, link, info, entsize.
    // (type, addr, offset, size, link, info, entsize)
    let shdrs: Vec<(u32, u32, u32, u32, u32, u32, u32)> = (0..e_shnum)
        .map(|i| {
            let so = e_shoff as usize + i as usize * e_shentsize as usize;
            (
                read_u32(data, so + 4, is_little_endian),  // sh_type
                read_u32(data, so + 12, is_little_endian), // sh_addr
                read_u32(data, so + 16, is_little_endian), // sh_offset
                read_u32(data, so + 20, is_little_endian), // sh_size
                read_u32(data, so + 24, is_little_endian), // sh_link
                read_u32(data, so + 28, is_little_endian), // sh_info
                read_u32(data, so + 36, is_little_endian), // sh_entsize
            )
        })
        .collect();

    const SHT_REL: u32 = 9;
    const SHT_RELA: u32 = 4;
    for shdr in &shdrs {
        let (sh_type, _sh_addr, sh_offset, sh_size, sh_link, sh_info, sh_entsize) = *shdr;
        if (sh_type != SHT_REL && sh_type != SHT_RELA) || sh_size == 0 {
            continue;
        }
        // sh_link -> symbol table section; resolve its string table (symtab's link).
        let symtab_idx = sh_link as usize;
        if symtab_idx >= shdrs.len() {
            continue;
        }
        let (sym_type, _sym_addr, sym_off, _sym_size, sym_strtab_link, _sym_info, sym_entsize) =
            shdrs[symtab_idx];
        // Sanity: the linked section really is a symbol table.
        const SHT_SYMTAB: u32 = 2;
        const SHT_DYNSYM: u32 = 11;
        if sym_type != SHT_SYMTAB && sym_type != SHT_DYNSYM {
            continue;
        }
        if sym_entsize == 0 || sym_strtab_link as usize >= shdrs.len() {
            continue;
        }
        let str_off = shdrs[sym_strtab_link as usize].2 as usize;
        let str_size = shdrs[sym_strtab_link as usize].3 as usize;
        if str_off + str_size > data.len() {
            continue;
        }
        let str_table = &data[str_off..str_off + str_size];

        // sh_info -> the section these relocations APPLY TO. For ET_REL objects
        // (most PS2 homebrew/dev ELFs) r_offset is section-relative, so we add
        // the target section's sh_addr to normalize it to an absolute address —
        // matching the absolute callsite addresses the call graph produces. For
        // already-linked ET_EXEC binaries r_offset is already absolute and the
        // target section's sh_addr is typically 0, leaving it unchanged.
        let target_sh_addr = if (sh_info as usize) < shdrs.len() {
            shdrs[sh_info as usize].1 // sh_addr of the target section
        } else {
            0
        };

        let entry_size = if sh_entsize > 0 {
            sh_entsize
        } else if sh_type == SHT_REL {
            8
        } else {
            12
        };
        let num_entries = (sh_size as usize) / (entry_size as usize);
        for j in 0..num_entries {
            let base = (sh_offset as usize) + j * (entry_size as usize);
            if base + entry_size as usize > data.len() {
                break;
            }
            // ELF32_Rel: r_offset(4) + r_info(4). RELA adds r_addend(4).
            let r_offset = read_u32(data, base, is_little_endian);
            let r_info = read_u32(data, base + 4, is_little_endian);
            // ELF32: r_sym = r_info >> 8, r_type = r_info & 0xFF
            let r_sym = r_info >> 8;
            let r_type = r_info & 0xFF;

            let symbol_name = {
                let sym_entry = (sym_off as usize) + (r_sym as usize) * (sym_entsize as usize);
                if r_sym > 0 && sym_entry + (sym_entsize as usize) <= data.len() {
                    let st_name = read_u32(data, sym_entry, is_little_endian) as usize;
                    if st_name < str_table.len() {
                        let end = str_table[st_name..]
                            .iter()
                            .position(|&b| b == 0)
                            .unwrap_or(str_table.len() - st_name);
                        std::str::from_utf8(&str_table[st_name..st_name + end])
                            .unwrap_or("")
                            .to_string()
                    } else {
                        String::new()
                    }
                } else {
                    String::new()
                }
            };

            relocations.push(Relocation {
                offset: r_offset.wrapping_add(target_sh_addr),
                symbol_name,
                r_type,
                symbol: r_sym,
            });
        }
    }
    relocations
}


pub fn identify_data(h: &[u8]) -> String {
    if h.len() >= 5 && &h[0..4] == [0x7f, b'E', b'L', b'F'] {
        if h[4] == 1 {
            return if h[5] == 1 { "elf32-le".into() } else { "elf32-be".into() };
        }
        if h[4] == 2 {
            return if h[5] == 1 { "elf64-le".into() } else { "elf64-be".into() };
        }
        return "elf-unknown".into();
    }
    // PS-X executable: "PS-X EXE" at offset 0
    if h.len() >= 8 && &h[0..8] == b"PS-X EXE" {
        return "psx-exe".into();
    }
    // Original Xbox executable: "XBEH"
    if h.len() >= 4 && &h[0..4] == b"XBEH" {
        return "xbe".into();
    }
    // Xbox 360 executable: "XEX0" / "XEX1" / "XEX2"
    if h.len() >= 4 && &h[0..3] == b"XEX" && (b'0'..=b'2').contains(&h[3]) {
        return "xex".into();
    }
    // PS3/PS4/PS5 SELF: "SCE\0" — check both byte orders since the 4-byte magic
    // 0x53434500 may appear as "SCE\0" (BE) or "\0ECS" (LE) depending on the tool
    // that produced the file.
    if h.len() >= 4 {
        if (&h[0..3] == b"SCE" && h[3] == 0) || (h[0] == 0 && &h[1..4] == b"ECS") {
            return "self".into();
        }
    }
    // CHD (MAME compressed hunks — PS1/PS2/etc. disc images): "MComprHD"
    if h.len() >= 8 && &h[0..8] == b"MComprHD" {
        return "chd".into();
    }
    // GameBoy ROM: fixed Nintendo logo bitmap at 0x104..0x133.
    if h.len() >= 0x150 {
        const NINTENDO_LOGO: [u8; 48] = [
            0xCE, 0xED, 0x66, 0x66, 0xCC, 0x0D, 0x00, 0x0B, 0x03, 0x73, 0x00, 0x83,
            0x00, 0x0C, 0x00, 0x0D, 0x00, 0x08, 0x11, 0x1F, 0x88, 0x89, 0x00, 0x0E,
            0xDC, 0xCC, 0x6E, 0xE6, 0xDD, 0xDD, 0xD9, 0x99, 0xBB, 0xBB, 0x67, 0x63,
            0x6E, 0x0E, 0xEC, 0xCC, 0xDD, 0xDC, 0x99, 0x9F, 0xBB, 0xB9, 0x33, 0x3E,
        ];
        if h[0x104..0x134] == NINTENDO_LOGO {
            return "gb-rom".into();
        }
    }
    // PS4 eboot.bin / SELF: first 4 bytes are 4F 15 3D 1D (0x1D3D154F LE). This
    // magic covers both the OpenOrbis homebrew "fake SELF" container (parseable)
    // and the retail/encrypted SELF (needs Sony's keys). Distinguish by probing
    // the fSELF header (keytype 0x101 + embedded ELF).
    if h.len() >= 4 && ps4ps5::is_ps4_eboot_magic(h) {
        return if ps4ps5::is_fself(h) { "ps4-self".into() } else { "ps4-encrypted".into() };
    }
    // Raw CD-ROM image (.bin/.img with 2352-byte sectors): starts with the
    // CD-ROM sync pattern (00 FF FF FF FF FF FF FF FF FF FF 00).
    if h.len() >= 12 && h[0] == 0x00 && h[1..12].iter().all(|&b| b == 0xFF) && h[12] == 0x00 {
        return "ps1-disc".into();
    }
    // PlayStation disc image (.iso with 2048-byte sectors): ISO9660 PVD
    // "CD001" at sector 16 (byte 0x8001).
    if h.len() > 0x8005 && &h[0x8001..0x8006] == b"CD001" {
        return "ps1-disc".into();
    }
    // iNES ROM: "NES\x1a" at offset 0.
    if h.len() >= 4 && &h[0..4] == b"NES\x1a" {
        return "nes-rom".into();
    }
    // GameBoy Advance ROM: the Nintendo logo bitmap at 0x04..0x9F (different
    // offset than GB's 0x104) + the fixed byte 0x96 at 0xB5 (complement check).
    if h.len() > 0xB5 && h[0xB5] == 0x96 {
        const GBA_LOGO: [u8; 176] = [
            0x24,0xFF,0xAE,0x51,0x69,0x9A,0xA2,0x21,0x3D,0x84,0x82,0x0C,0x7F,0x31,0xA4,0xF2,
            0x32,0x0F,0x12,0x2B,0x19,0xE7,0x4B,0x11,0x61,0xD4,0x87,0x76,0x6C,0xBF,0x01,0x86,
            0x1B,0x25,0xAF,0x16,0x2F,0x3F,0xC3,0x41,0x56,0x5F,0x8C,0x51,0x71,0x60,0x33,0xCB,
            0xBF,0xAC,0x06,0x1B,0x3B,0x33,0x9E,0x33,0xF1,0x56,0x4E,0x75,0x81,0x28,0xE0,0x71,
            0xFD,0x8D,0x41,0x0F,0x71,0x30,0xB5,0x4E,0x54,0xBF,0x65,0x99,0xFB,0x4F,0x4E,0x4D,
            0x13,0xDC,0x3B,0x72,0x4D,0x3A,0x33,0xAE,0x30,0x75,0x6D,0x17,0x78,0x2F,0x86,0x47,
            0x4B,0x61,0x4C,0x33,0x36,0x21,0x26,0x89,0xCD,0xAD,0x53,0x8B,0xF2,0x38,0x59,0xCE,
            0x67,0x01,0x97,0x73,0x57,0x74,0x6F,0xF3,0x16,0x05,0x48,0x59,0xB6,0xFB,0xCD,0x7B,
            0x36,0x9D,0x9A,0x48,0xF8,0x3F,0x4A,0x60,0x3C,0x57,0x57,0x4F,0x76,0x12,0xA3,0x6F,
            0x4F,0xA3,0xB5,0x4C,0x0F,0x3E,0x57,0x3A,0x9C,0x21,0xFC,0xFB,0x50,0x08,0x6F,0xC8,
            0x80,0x3A,0xE6,0xE6,0x49,0x20,0x17,0x52,0xD0,0xD1,0x44,0x90,0xFC,0x4C,0x4B,0x61,
        ];
        // Check first 16 bytes of the logo as a quick, reliable match.
        if &h[4..20] == &GBA_LOGO[0..16] {
            return "gba-rom".into();
        }
    }
    // Nintendo 64 ROM: three byte-orderings exist.
    // .z64 (big-endian):    80 37 12 40
    // .v64 (byteswapped):   37 80 40 12
    // .n64 (little-endian): 40 12 37 80
    if h.len() >= 4 {
        let b = &h[0..4];
        if b == [0x80, 0x37, 0x12, 0x40]
            || b == [0x37, 0x80, 0x40, 0x12]
            || b == [0x40, 0x12, 0x37, 0x80]
        {
            return "n64-rom".into();
        }
    }
    // Nintendo DS ROM: the header at 0x00 has the game title (ASCII) + game
    // code at 0x0C. The header CRC at 0x15E validates. A reliable check: the
    // ROM size at 0x80-0x83 (u32 LE) should be a power of 2 and <= 512MB.
    // We also check that the title (0x00-0x0C) is printable ASCII.
    if h.len() >= 0x84 {
        let title_ascii = h[0..0x0C].iter().all(|&b| b == 0 || b.is_ascii_alphanumeric() || b == b'_');
        let rom_size = u32::from_le_bytes([h[0x80], h[0x81], h[0x82], h[0x83]]);
        let is_pow2 = rom_size > 0 && (rom_size & (rom_size - 1)) == 0;
        if title_ascii && is_pow2 && rom_size <= 0x20000000 {
            return "nds-rom".into();
        }
    }
    // SNES/SFC ROM: no reliable magic at offset 0 (the header is at 0x7FC0 or
    // 0xFFC0 depending on whether there's a 512-byte SMC copier header).
    // Check for the internal ROM info at 0xFFC0 (or 0x7FC0 for small ROMs):
    // offset 0 has the game title (ASCII), and offset 0xFFD5 has the ROM type.
    // For a quick check: if bytes at 0xFFC0-0xFFD0 are mostly printable ASCII
    // (the game title) and 0xFFD5 (memory mode) is a known value (0x20, 0x30,
    // 0x31, 0x32, 0x33, 0x35, 0x3A), it's likely a SNES ROM.
    if h.len() > 0xFFD6 {
        let title_ok = h[0xFFC0..0xFFD0].iter().all(|&b| b == 0 || b == 0x20 || b.is_ascii_alphanumeric());
        let rom_type = h[0xFFD5];
        let known_types = [0x20, 0x30, 0x31, 0x32, 0x33, 0x35, 0x3A, 0x40, 0x42, 0x43, 0x45, 0x4A];
        if title_ok && known_types.contains(&rom_type) {
            return "snes-rom".into();
        }
    }
    // Also check with SMC copier header (512 bytes offset).
    if h.len() > 0x101D6 {
        let title_ok = h[0x101C0..0x101D0].iter().all(|&b| b == 0 || b == 0x20 || b.is_ascii_alphanumeric());
        let rom_type = h[0x101D5];
        let known_types = [0x20, 0x30, 0x31, 0x32, 0x33, 0x35, 0x3A, 0x40, 0x42, 0x43, 0x45, 0x4A];
        if title_ok && known_types.contains(&rom_type) {
            return "snes-rom".into();
        }
    }
    "raw".into()
}


pub fn disassemble_mips_section(data: Vec<u8>, section_name: String, start_addr: u32, is_little_endian: bool) -> Result<String, String> {
    if data.is_empty() {
        return Err("No data to disassemble".to_string());
    }

    let mut output = String::new();
    output.push_str(&format!("Disassembly: {} ({} bytes)\n\n", section_name, data.len()));

    const REG: [&str; 32] = [
        "$zero", "$at", "$v0", "$v1", "$a0", "$a1", "$a2", "$a3",
        "$t0", "$t1", "$t2", "$t3", "$t4", "$t5", "$t6", "$t7",
        "$s0", "$s1", "$s2", "$s3", "$s4", "$s5", "$s6", "$s7",
        "$t8", "$t9", "$k0", "$k1", "$gp", "$sp", "$fp", "$ra",
    ];

    // Branch/jump mnemonics that have a delay slot.
    const DELAY_SLOT_MNEMONICS: &[&str] = &[
        "J", "JAL", "JR", "JALR", "BEQ", "BNE", "BLEZ", "BGTZ",
        "BLTZ", "BGEZ", "BLTZAL", "BGEZAL", "BEQL", "BNEL",
    ];

    let mut offset = 0usize;
    let max_instructions = 1000; // safety cap

    while offset + 4 <= data.len() && offset / 4 < max_instructions {
        let addr = start_addr + (offset as u32);

        let bytes = [data[offset], data[offset + 1], data[offset + 2], data[offset + 3]];
        let instr = if is_little_endian {
            u32::from_le_bytes(bytes)
        } else {
            u32::from_be_bytes(bytes)
        };

        let op = (instr >> 26) & 0x3F;
        let rs = ((instr >> 21) & 0x1F) as usize;
        let rt = ((instr >> 16) & 0x1F) as usize;
        let rd = ((instr >> 11) & 0x1F) as usize;
        let shamt = (instr >> 6) & 0x1F;
        let funct = instr & 0x3F;
        let target_field = instr & 0x03FFFFFF;
        let imm16 = instr & 0xFFFF;
        let signed_imm = (imm16 as i16) as i32;
        let branch_target = (addr as i64 + 4 + ((signed_imm as i64) << 2)) as u32;

        let (mnemonic, operand): (String, String) = if op == 0 {
            // SPECIAL: decode by funct
            if instr == 0 {
                ("NOP".to_string(), String::new())
            } else {
                match funct {
                    0x00 => ("SLL".into(), format!("{}, {}, {}", REG[rd], REG[rt], shamt)),
                    0x02 => ("SRL".into(), format!("{}, {}, {}", REG[rd], REG[rt], shamt)),
                    0x03 => ("SRA".into(), format!("{}, {}, {}", REG[rd], REG[rt], shamt)),
                    0x04 => ("SLLV".into(), format!("{}, {}, {}", REG[rd], REG[rt], REG[rs])),
                    0x06 => ("SRLV".into(), format!("{}, {}, {}", REG[rd], REG[rt], REG[rs])),
                    0x07 => ("SRAV".into(), format!("{}, {}, {}", REG[rd], REG[rt], REG[rs])),
                    0x08 => ("JR".into(), REG[rs].to_string()),
                    0x09 => ("JALR".into(), format!("{}, {}", REG[rd], REG[rs])),
                    0x0C => ("SYSCALL".into(), format!("0x{:X}", instr & 0xFFFFF)),
                    0x0D => ("BREAK".into(), format!("0x{:X}", instr & 0xFFFFF)),
                    0x10 => ("MFHI".into(), REG[rd].to_string()),
                    0x11 => ("MTHI".into(), REG[rs].to_string()),
                    0x12 => ("MFLO".into(), REG[rd].to_string()),
                    0x13 => ("MTLO".into(), REG[rs].to_string()),
                    0x18 => ("MULT".into(), format!("{}, {}", REG[rs], REG[rt])),
                    0x19 => ("MULTU".into(), format!("{}, {}", REG[rs], REG[rt])),
                    0x1A => ("DIV".into(), format!("{}, {}", REG[rs], REG[rt])),
                    0x1B => ("DIVU".into(), format!("{}, {}", REG[rs], REG[rt])),
                    0x20 => ("ADD".into(), format!("{}, {}, {}", REG[rd], REG[rs], REG[rt])),
                    0x21 => ("ADDU".into(), format!("{}, {}, {}", REG[rd], REG[rs], REG[rt])),
                    0x22 => ("SUB".into(), format!("{}, {}, {}", REG[rd], REG[rs], REG[rt])),
                    0x23 => ("SUBU".into(), format!("{}, {}, {}", REG[rd], REG[rs], REG[rt])),
                    0x24 => ("AND".into(), format!("{}, {}, {}", REG[rd], REG[rs], REG[rt])),
                    0x25 => ("OR".into(), format!("{}, {}, {}", REG[rd], REG[rs], REG[rt])),
                    0x26 => ("XOR".into(), format!("{}, {}, {}", REG[rd], REG[rs], REG[rt])),
                    0x27 => ("NOR".into(), format!("{}, {}, {}", REG[rd], REG[rs], REG[rt])),
                    0x2A => ("SLT".into(), format!("{}, {}, {}", REG[rd], REG[rs], REG[rt])),
                    0x2B => ("SLTU".into(), format!("{}, {}, {}", REG[rd], REG[rs], REG[rt])),
                    _ => (format!("SPECIAL 0x{:02X}", funct), format!("{},{},{}", REG[rs], REG[rt], REG[rd])),
                }
            }
        } else {
            match op {
                0x01 => match rt {
                    0x00 => ("BLTZ".into(), format!("{}, 0x{:08X}", REG[rs], branch_target)),
                    0x01 => ("BGEZ".into(), format!("{}, 0x{:08X}", REG[rs], branch_target)),
                    0x02 => ("BLTZL".into(), format!("{}, 0x{:08X}", REG[rs], branch_target)),
                    0x03 => ("BGEZL".into(), format!("{}, 0x{:08X}", REG[rs], branch_target)),
                    0x10 => ("BLTZAL".into(), format!("{}, 0x{:08X}", REG[rs], branch_target)),
                    0x11 => ("BGEZAL".into(), format!("{}, 0x{:08X}", REG[rs], branch_target)),
                    _ => ("REGIMM".into(), format!("rt={}, {}", rt, REG[rs])),
                },
                0x02 => {
                    let jaddr = ((addr + 4) & 0xF0000000) | (target_field << 2);
                    ("J".into(), format!("0x{:08X}", jaddr))
                }
                0x03 => {
                    let jaddr = ((addr + 4) & 0xF0000000) | (target_field << 2);
                    ("JAL".into(), format!("0x{:08X}", jaddr))
                }
                0x04 => ("BEQ".into(), format!("{}, {}, 0x{:08X}", REG[rs], REG[rt], branch_target)),
                0x05 => ("BNE".into(), format!("{}, {}, 0x{:08X}", REG[rs], REG[rt], branch_target)),
                0x06 => ("BLEZ".into(), format!("{}, 0x{:08X}", REG[rs], branch_target)),
                0x07 => ("BGTZ".into(), format!("{}, 0x{:08X}", REG[rs], branch_target)),
                0x08 => ("ADDI".into(), format!("{}, {}, {}", REG[rt], REG[rs], signed_imm)),
                0x09 => ("ADDIU".into(), format!("{}, {}, {}", REG[rt], REG[rs], signed_imm)),
                0x0A => ("SLTI".into(), format!("{}, {}, {}", REG[rt], REG[rs], signed_imm)),
                0x0B => ("SLTIU".into(), format!("{}, {}, {}", REG[rt], REG[rs], signed_imm)),
                0x0C => ("ANDI".into(), format!("{}, {}, 0x{:X}", REG[rt], REG[rs], imm16)),
                0x0D => ("ORI".into(), format!("{}, {}, 0x{:X}", REG[rt], REG[rs], imm16)),
                0x0E => ("XORI".into(), format!("{}, {}, 0x{:X}", REG[rt], REG[rs], imm16)),
                0x0F => ("LUI".into(), format!("{}, 0x{:X}", REG[rt], imm16)),
                0x10 => match rs {
                    0x00 => ("MFC0".into(), format!("{}, ${}", REG[rd], rt)),
                    0x04 => ("MTC0".into(), format!("{}, ${}", REG[rd], rt)),
                    _ => ("COP0".into(), format!("rs={}, rt={}, rd={}", rs, rt, rd)),
                },
                0x14 => ("BEQL".into(), format!("{}, {}, 0x{:08X}", REG[rs], REG[rt], branch_target)),
                0x15 => ("BNEL".into(), format!("{}, {}, 0x{:08X}", REG[rs], REG[rt], branch_target)),
                0x20 => ("LB".into(), format!("{}, {}({})", REG[rt], signed_imm, REG[rs])),
                0x21 => ("LH".into(), format!("{}, {}({})", REG[rt], signed_imm, REG[rs])),
                0x22 => ("LWL".into(), format!("{}, {}({})", REG[rt], signed_imm, REG[rs])),
                0x23 => ("LW".into(), format!("{}, {}({})", REG[rt], signed_imm, REG[rs])),
                0x24 => ("LBU".into(), format!("{}, {}({})", REG[rt], signed_imm, REG[rs])),
                0x25 => ("LHU".into(), format!("{}, {}({})", REG[rt], signed_imm, REG[rs])),
                0x26 => ("LWR".into(), format!("{}, {}({})", REG[rt], signed_imm, REG[rs])),
                0x28 => ("SB".into(), format!("{}, {}({})", REG[rt], signed_imm, REG[rs])),
                0x29 => ("SH".into(), format!("{}, {}({})", REG[rt], signed_imm, REG[rs])),
                0x2A => ("SWL".into(), format!("{}, {}({})", REG[rt], signed_imm, REG[rs])),
                0x2B => ("SW".into(), format!("{}, {}({})", REG[rt], signed_imm, REG[rs])),
                0x2E => ("SWR".into(), format!("{}, {}({})", REG[rt], signed_imm, REG[rs])),
                0x2F => ("CACHE".into(), format!("{}, {}({})", rt, signed_imm, REG[rs])),
                0x30 => ("LL".into(), format!("{}, {}({})", REG[rt], signed_imm, REG[rs])),
                0x31 => ("LWC1".into(), format!("$f{}, {}({})", rt, signed_imm, REG[rs])),
                0x38 => ("SC".into(), format!("{}, {}({})", REG[rt], signed_imm, REG[rs])),
                0x39 => ("SWC1".into(), format!("$f{}, {}({})", rt, signed_imm, REG[rs])),
                0x11 | 0x12 | 0x13 => (format!("COP{}", op - 0x10), format!("rs={}, rt={}, rd={}", rs, rt, rd)),
                _ => (".word".into(), format!("0x{:08X} ; unknown opcode 0x{:02X}", instr, op)),
            }
        };

        // Delay-slot comment: a branch/jump makes the *next* instruction a delay slot.
        // We tag the branch line itself so readers can find them.
        let delay_note = if DELAY_SLOT_MNEMONICS.contains(&mnemonic.as_str()) {
            " ; delay slot follows"
        } else {
            ""
        };

        output.push_str(&format!("{:08X}  {:08X}  {} {}{}\n", addr, instr, mnemonic, operand, delay_note));

        offset += 4;
    }

    Ok(output)
}


/// A discovered function: a named range of code.
#[derive(Serialize, Debug, Clone)]
pub struct FunctionEntry {
    pub name: String,
    pub start: u32,
    pub end: u32,
    pub size: u32,
}

// ===================== Call graph =====================
//
// A directed graph of which function calls which, built from direct JAL/J
// instructions. Indirect calls (`jalr`, `jr $t9`/`jr $v0`) are NOT covered
// here — they need register/liveness tracking and are deferred. This still
// captures the overwhelming majority of calls in a typical EE binary.
//
// The graph is computed standalone (independent of the function-boundary scan)
// so it works for both stripped (JAL-scan) and non-stripped (symbol-table)
// binaries: the symbol path in `detect_functions_inner` returns early, so a
// scan coupled to `detect_functions_in_sections` would be skipped on
// non-stripped ELFs. Keeping it separate serves both paths equally.

/// Kind of direct call edge. Indirect calls are not yet represented.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum CallKind {
    /// `jal target` — a subroutine call that returns to the delay slot+4.
    Jal,
    /// `j target` used as a tail call (i.e. the target is OUTSIDE the
    /// containing function). Intra-function `j` (gotos/loops) are dropped.
    Jump,
}

/// A resolved call edge between two detected functions.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct CallEdge {
    /// Caller function's START address (the `from` is mapped from the raw
    /// callsite by attribution against the detected function ranges).
    pub from: u32,
    /// Callee target address (the JAL/J target field).
    pub to: u32,
    /// Address of the JAL/J instruction itself.
    pub callsite: u32,
    pub kind: CallKind,
}

/// The full call graph for a binary: attributed edges + the set of targets
/// that no detected function starts at (external imports / undetected code).
#[derive(Serialize, Debug, Clone)]
pub struct CallGraph {
    pub edges: Vec<CallEdge>,
    /// JAL/J targets that don't coincide with any detected function start.
    /// Deduped + sorted ascending. Informational — feeds later stub
    /// classification and the "missed functions" hint.
    pub external_targets: Vec<u32>,
    /// (target_address, imported_symbol_name) pairs resolved from R_MIPS_26
    /// relocations at JAL callsites. Lets the UI show e.g. "printf" instead of
    /// "ext_XXXXXXXX" for imported SDK functions. Empty on stripped retail
    /// binaries (no relocations). Sorted by address, deduped by address.
    pub target_names: Vec<(u32, String)>,
}

/// Pre-attribution raw edge: a direct call instruction and its target, before
/// we know which function the callsite belongs to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RawCallEdge {
    pub callsite: u32,
    pub target: u32,
    pub kind: CallKind,
}

/// Heuristically detect function boundaries in an executable section.
///
/// Stripped PS2 retail games (e.g. Midnight Club 3) ship with no symbol table,
/// so we mirror the approach PS2Recomp's "JAL Scanner" uses: scan executable
/// sections for JAL/J/JR instructions to infer function start addresses.
///
/// - A `JAL target` or `J target` whose target lands inside an executable
///   section is treated as a function start.
/// - The entry point is always a function start.
/// - Function ends are computed as (next start - 1) within the same section.
///
/// "Executable section" = has the SHF_EXECINSTR flag (0x4), which only .text
/// carries on PS2 ELFs. This prevents the scanner from emitting bogus function
/// entries for data sections that happen to contain JAL-like bit patterns.
pub fn detect_functions_in_sections(
    sections: &[ElfSection],
    entry_point: u32,
    is_little_endian: bool,
) -> Vec<FunctionEntry> {
    const SHF_EXECINSTR: u32 = 0x4;
    let is_exec = |s: &ElfSection| (s.flags & SHF_EXECINSTR) != 0;

    // Collect candidate starts: entry point + JAL/J targets.
    let mut starts: std::collections::BTreeSet<u32> = std::collections::BTreeSet::new();
    if entry_point != 0 {
        starts.insert(entry_point);
    }

    for sec in sections.iter().filter(|s| is_exec(s)) {
        let data = &sec.data;
        let mut off = 0usize;
        while off + 4 <= data.len() {
            let instr = read_u32(data, off, is_little_endian);
            let op = (instr >> 26) & 0x3F;
            if op == 0x03 {
                // JAL target = (pc_of_delay_slot & 0xF0000000) | (target_field << 2)
                let field = instr & 0x03FFFFFF;
                let pc = sec.address + off as u32 + 4;
                let target = (pc & 0xF0000000) | (field << 2);
                if target >= sec.address && target < sec.address + data.len() as u32 {
                    starts.insert(target);
                }
            } else if op == 0x02 {
                // J (direct jump) - also a likely function entry
                let field = instr & 0x03FFFFFF;
                let pc = sec.address + off as u32 + 4;
                let target = (pc & 0xF0000000) | (field << 2);
                if target >= sec.address && target < sec.address + data.len() as u32 {
                    starts.insert(target);
                }
            }
            off += 4;
        }
    }

    // Build function ranges. Each start begins a function; it ends where the
    // next start (in the same section) begins, aligned down to the instruction.
    let mut funcs: Vec<FunctionEntry> = Vec::new();
    for sec in sections.iter().filter(|s| is_exec(s)) {
        let sec_start = sec.address;
        let sec_end = sec.address + sec.data.len() as u32;

        // Starts that fall within this section, sorted ascending.
        let mut sec_starts: Vec<u32> = starts
            .range(sec_start..sec_end)
            .copied()
            .collect();
        // Ensure the section has at least one start (its own base) so we don't
        // miss code at the top with no caller.
        if sec_starts.is_empty() {
            sec_starts.push(sec_start);
        }

        for (i, &start) in sec_starts.iter().enumerate() {
            let next = if i + 1 < sec_starts.len() {
                sec_starts[i + 1]
            } else {
                sec_end
            };
            let end = next;
            if end > start {
                let size = end - start;
                funcs.push(FunctionEntry {
                    name: format!("sub_{:08X}", start),
                    start,
                    end,
                    size,
                });
            }
        }
    }
    funcs
}

/// Scan executable sections once and record every direct call instruction
/// (JAL op 0x03, J op 0x02) as a pre-attribution `RawCallEdge`.
///
/// The target is computed identically to the JAL-scan in
/// `detect_functions_in_sections`: `(pc_of_delay_slot & 0xF0000000) |
/// (field << 2)`. Edges are only kept when the target lands inside an
/// executable section (a call into data/.rodata is almost certainly a
/// misdecoded instruction, not a real call).
///
/// Returns raw edges with NO `from` yet — attribution to the containing
/// function happens in `build_call_graph`, after function boundaries are known.
pub fn collect_call_edges(sections: &[ElfSection], is_little_endian: bool) -> Vec<RawCallEdge> {
    const SHF_EXECINSTR: u32 = 0x4;
    // Build the union of executable-section address ranges so a target landing
    // in ANY executable section is accepted (not just the caller's section).
    let exec_ranges: Vec<(u32, u32)> = sections
        .iter()
        .filter(|s| (s.flags & SHF_EXECINSTR) != 0)
        .map(|s| (s.address, s.address + s.data.len() as u32))
        .collect();
    let in_exec = |addr: u32| exec_ranges.iter().any(|(lo, hi)| addr >= *lo && addr < *hi);

    let mut edges: Vec<RawCallEdge> = Vec::new();
    for sec in sections.iter().filter(|s| (s.flags & SHF_EXECINSTR) != 0) {
        let data = &sec.data;
        let mut off = 0usize;
        while off + 4 <= data.len() {
            let instr = read_u32(data, off, is_little_endian);
            let op = (instr >> 26) & 0x3F;
            if op == 0x03 || op == 0x02 {
                let field = instr & 0x03FFFFFF;
                let pc_of_delay_slot = sec.address + off as u32 + 4;
                let target = (pc_of_delay_slot & 0xF0000000) | (field << 2);
                if in_exec(target) {
                    edges.push(RawCallEdge {
                        callsite: sec.address + off as u32,
                        target,
                        kind: if op == 0x03 { CallKind::Jal } else { CallKind::Jump },
                    });
                }
            }
            off += 4;
        }
    }
    edges
}

/// Attribute each raw edge to its containing function and apply call-graph
/// filters. Pure; testable in isolation.
///
/// Steps:
/// 1. Sort a copy of `funcs` by `start` and binary-search each callsite into
///    the function whose `[start, end)` contains it → that's the `from`.
///    Edges whose callsite is in no detected function are dropped (the
///    instruction is in a gap we never classified as code).
/// 2. Drop J edges whose target is inside the *same* attributed function
///    (`from == that func`): those are intra-function gotos/loops, not calls.
///    JAL is never dropped this way — a JAL to one's own start is legitimate
///    self-recursion.
/// 3. Targets that match no function `start` go into `external_targets`
///    (deduped, sorted). Such edges stay in `edges` — they're real calls to
///    undetected code and worth surfacing.
pub fn build_call_graph(mut raw: Vec<RawCallEdge>, funcs: &[FunctionEntry]) -> CallGraph {
    // Attribute callsite -> function via sorted starts + range containment.
    let mut by_start: Vec<&FunctionEntry> = funcs.iter().collect();
    by_start.sort_by_key(|f| f.start);

    let edges: Vec<CallEdge> = raw
        .drain(..)
        .filter_map(|r| {
            // Largest start <= callsite.
            let pos = by_start
                .partition_point(|f| f.start <= r.callsite)
                .saturating_sub(1);
            let func = by_start.get(pos)?;
            if r.callsite < func.start || r.callsite >= func.end {
                return None; // callsite in an unclassified gap
            }
            // Drop intra-function tail jumps (but keep self-recursion via JAL).
            if matches!(r.kind, CallKind::Jump) && r.target >= func.start && r.target < func.end {
                return None;
            }
            Some(CallEdge {
                from: func.start,
                to: r.target,
                callsite: r.callsite,
                kind: r.kind,
            })
        })
        .collect();

    // External targets: edge `to`s that aren't any function's start.
    let is_start = |a: u32| by_start.iter().any(|f| f.start == a);
    let mut external: Vec<u32> = edges
        .iter()
        .filter(|e| !is_start(e.to))
        .map(|e| e.to)
        .collect();
    external.sort_unstable();
    external.dedup();

    CallGraph { edges, external_targets: external, target_names: Vec::new() }
}

/// True when this instruction makes the *following* instruction a branch
/// delay slot. Mirrors `DELAY_SLOT_MNEMONICS` (main.rs:596): J/JAL/JR/JALR,
/// every conditional branch (op 0x04–0x07), REGIMM (op 0x01: BLTZ/BGEZ and
/// the -AL variants), and BEQL/BNEL. A plain `jr $ra` (SPECIAL funct 0x08)
/// and `jalr` (0x09) are included, since the delay slot is what carries the
/// instruction that actually returns control.
fn has_delay_slot(instr: u32) -> bool {
    let op = (instr >> 26) & 0x3F;
    // SPECIAL: JR (0x08), JALR (0x09). A raw nop is `0x00000000` (op 0, funct
    // 0 = SLL) and must NOT be flagged here, so check funct explicitly.
    if op == 0x00 {
        let funct = instr & 0x3F;
        return funct == 0x08 || funct == 0x09;
    }
    // 0x01 REGIMM, 0x02 J, 0x03 JAL, 0x04 BEQ, 0x05 BNE, 0x06 BLEZ, 0x07 BGTZ,
    // 0x14 BEQL, 0x15 BNEL.
    matches!(op, 0x01 | 0x02 | 0x03 | 0x04 | 0x05 | 0x06 | 0x07 | 0x14 | 0x15)
}

/// Refine a function's exclusive `End` by trimming trailing `nop` padding.
///
/// PS2Recomp treats `End` as exclusive (`for addr = start; addr < end; addr += 4`
/// in elf_analyzer.cpp, and `endExclusive = maxAddr + 1` in ExportPS2Functions.java),
/// so for a function that returns via `jr $ra` the correct End is `jr_addr + 8`
/// — the `jr` plus its mandatory delay slot.
///
/// The naive JAL-scan End (`next_function_start`) overshoots: it swallows any
/// trailing `nop` alignment padding between functions and any tail-called/orphaned
/// code that no `jal` lands on. This trims it back.
///
/// Algorithm: walk backwards from the current End, dropping trailing `nop`
/// (0x00000000) words — **but never** an instruction that is a branch delay
/// slot, and never below `start + 4` (every function keeps at least one
/// instruction). One backward pass is sufficient because a trailing nop that is
/// the delay slot of the final control-flow instruction is protected by
/// `has_delay_slot(prev)`: the trim halts there, which is exactly End =
/// `last_cf_addr + 8`. Early/mid-function returns are mid-span and untouched.
///
/// Only ever *shortens* End; never grows it. Returns `end_current` unchanged if
/// the function isn't in the given section or the trim would empty it.
fn refine_end(
    data: &[u8],
    base: u32,
    start: u32,
    end_current: u32,
    is_little_endian: bool,
) -> u32 {
    let start_off = (start.wrapping_sub(base)) as usize;
    // Section containment: the whole current span must live in this section.
    if start_off + 4 > data.len() || end_current < base {
        return end_current;
    }
    let end_off = (end_current.wrapping_sub(base)) as usize;
    if end_off > data.len() {
        return end_current;
    }

    let mut end = end_current;
    loop {
        // Need at least two instructions in the span (the one we'd trim + the
        // one that precedes it, whose delay-slot membership we must check).
        if end < start + 8 {
            break;
        }
        let last_off = (end.wrapping_sub(base)) as usize - 4;
        if read_u32(data, last_off, is_little_endian) != 0 {
            break; // not a nop — stop trimming
        }
        let prev_off = last_off.saturating_sub(4);
        if read_u32(data, prev_off, is_little_endian) != 0
            && has_delay_slot(read_u32(data, prev_off, is_little_endian))
        {
            break; // this nop is a delay slot — protected, stop
        }
        end -= 4;
    }
    end
}

/// Apply `refine_end` to every detected function against its containing
/// executable section. Functions whose start isn't in a known section (or whose
/// trim would leave no body) are left with their JAL-scan End unchanged.
fn refine_function_boundaries(
    sections: &[ElfSection],
    funcs: &mut [FunctionEntry],
    is_little_endian: bool,
) {
    const SHF_EXECINSTR: u32 = 0x4;
    for f in funcs.iter_mut() {
        // Find the executable section that contains this function's start.
        let Some(sec) = sections
            .iter()
            .find(|s| (s.flags & SHF_EXECINSTR) != 0 && f.start >= s.address && f.start < s.address + s.data.len() as u32)
        else {
            continue;
        };
        let new_end = refine_end(&sec.data, sec.address, f.start, f.end, is_little_endian);
        if new_end <= f.start {
            continue; // safety net: never let End collapse onto Start
        }
        f.end = new_end;
        f.size = new_end - f.start;
    }
}


pub fn enrich_call_graph_with_relocs(mut graph: CallGraph, relocations: &[Relocation]) -> CallGraph {
    // Lookup: absolute callsite offset -> imported symbol name, for JAL relocs.
    let mut name_at_offset: std::collections::HashMap<u32, &str> = std::collections::HashMap::new();
    for r in relocations {
        if r.r_type == R_MIPS_26 && !r.symbol_name.is_empty() {
            name_at_offset.entry(r.offset).or_insert(r.symbol_name.as_str());
        }
    }
    if name_at_offset.is_empty() {
        return graph; // nothing to resolve (stripped retail binaries land here)
    }

    // target address -> name. Multiple callsites can target the same import;
    // first edge wins (the target address is identical, so the name is too).
    let mut name_by_target: std::collections::BTreeMap<u32, String> = std::collections::BTreeMap::new();
    for e in &graph.edges {
        if !matches!(e.kind, CallKind::Jal) {
            continue;
        }
        if let Some(name) = name_at_offset.get(&e.callsite) {
            name_by_target.entry(e.to).or_insert_with(|| name.to_string());
        }
    }
    graph.target_names = name_by_target.into_iter().collect();
    graph
}


pub fn detect_functions_inner(info: &ElfFileInfo) -> Result<Vec<FunctionEntry>, String> {
    // Prefer real symbol-table functions when the binary isn't stripped.
    let real: Vec<FunctionEntry> = info
        .symbols
        .iter()
        .filter(|s| s.size > 0)
        .map(|s| FunctionEntry {
            name: s.name.clone(),
            start: s.address,
            end: s.address + s.size,
            size: s.size,
        })
        .collect();
    if !real.is_empty() {
        return Ok(real);
    }

    // JAL-scan heuristic to find candidate function boundaries.
    let mut funcs =
        detect_functions_in_sections(&info.sections, info.entry_point, info.is_little_endian);

    // PS1 SDK symbol matcher (libsd/libcd/libspuc/kernel): renames sub_XXXXXXXX
    // entries where the embedded PS1 database has an unambiguous hash match.
    apply_ps1_sdk_names(&info.sections, &mut funcs);

    // Trim trailing nop padding / overshoot so each End is the function's real
    // exclusive boundary (e.g. `jr $ra + 8`). Done before SDK renaming so that
    // matches, when present, still win with their authoritative DB size.
    refine_function_boundaries(&info.sections, &mut funcs, info.is_little_endian);

    // Renames: try to turn sub_XXXXXXXX into real SDK names via the embedded
    // SCE symbol database (the same one ps2recomp's analyzer ships). This is
    // the pass that closes the gap between Aura's heuristic names and
    // ps2recomp's named output on stripped retail games.
    apply_sce_sdk_names(&info.sections, &mut funcs);

    Ok(funcs)
}

/// Lazily-loaded embedded SCE SDK symbol database. Parsing the ~12 MB of JSON
/// takes a few hundred ms, so it's done once per process on first use.
pub fn sce_db() -> &'static Result<SceSymbolDatabase, String> {
    static DB: OnceLock<Result<SceSymbolDatabase, String>> = OnceLock::new();
    DB.get_or_init(SceSymbolDatabase::load_embedded)
}

/// Build the code-section views the scanner needs from Aura's ELF sections.
/// Only executable sections (SHF_EXECINSTR) are passed in.
fn sce_code_sections<'a>(sections: &'a [ElfSection]) -> Vec<CodeSection<'a>> {
    const SHF_EXECINSTR: u32 = 0x4;
    sections
        .iter()
        .filter(|s| (s.flags & SHF_EXECINSTR) != 0)
        .map(|s| CodeSection {
            address: s.address,
            data: &s.data,
        })
        .collect()
}

/// Rename `sub_XXXXXXXX` entries to their real PS1 SDK names (libsd/libcd/
/// libspuc/kernel) where the embedded PS1 symbol database has a reference to a
/// name that lands exactly on a detected function start inside a code section.
/// Best-effort — on fully stripped retail binaries this is typically a no-op;
/// the PS1 matcher scans for ASCII symbol names, so it fires when the binary
/// actually carries those strings (notably dev/partial-strip builds).
pub fn apply_ps1_sdk_names(sections: &[ElfSection], funcs: &mut [FunctionEntry]) {
    let matches = ps1_symbols::scan_ps1_symbol_matches(sections);
    if matches.is_empty() {
        return;
    }
    // Index name resolves by absolute address (section base + match offset).
    let by_addr: std::collections::HashMap<u32, &str> = matches
        .iter()
        .filter_map(|m| {
            let sec = sections.get(m.section_index)?;
            (!sec.name.starts_with(".text")).then_some(())?;
            Some((sec.address + m.offset, m.symbol.as_str()))
        })
        .collect();
    for f in funcs.iter_mut() {
        if let Some(name) = by_addr.get(&f.start) {
            f.name = name.to_string();
        }
    }
}

/// Rename `sub_XXXXXXXX` entries to their real SDK names where the SCE symbol
/// database has an unambiguous hash match. Runs the matcher over executable
/// sections and patches any `FunctionEntry` whose start coincides with a match.
/// Leaves unmatched entries as `sub_XXXXXXXX`.
pub fn apply_sce_sdk_names(sections: &[ElfSection], funcs: &mut [FunctionEntry]) {
    let matches = scan_sce_sdk_matches(sections);
    if matches.is_empty() {
        return;
    }
    // Index matches by start address for O(1) lookup.
    let by_start: std::collections::HashMap<u32, &SceSymbolMatch> =
        matches.iter().map(|m| (m.address, m)).collect();
    for f in funcs.iter_mut() {
        if let Some(m) = by_start.get(&f.start) {
            f.name = m.name.clone();
            // The DB size may extend past the JAL-scan boundary (the matcher
            // grows past trailing NOP padding); trust it and widen the range.
            f.end = f.start + m.size;
            f.size = m.size;
        }
    }
}

/// Run the SCE SDK matcher over the given ELF's executable sections and return
/// the raw matches (before any renaming). Exposed as a command so the UI can
/// show a "found N SDK functions" breakdown on demand.
pub fn scan_sce_sdk_matches(sections: &[ElfSection]) -> Vec<SceSymbolMatch> {
    match sce_db() {
        Ok(db) => db.scan(&sce_code_sections(sections)),
        Err(_) => Vec::new(),
    }
}


pub fn identify_gb_data(data: &[u8]) -> Result<GbIdentification, String> {
    if data.len() < 0x150 {
        return Ok(GbIdentification { is_gameboy: false, header: None, rom_data: Vec::new() });
    }

    // Reliable GameBoy identification = the fixed Nintendo logo bitmap at
    // 0x104..0x133 (48 bytes). Every real GB/GBC ROM carries this exact pattern;
    // the previous 0x148/0x149 check was wrong (those are the ROM/RAM size
    // bytes, which vary per game and are almost never 0x00/0xFF).
    const NINTENDO_LOGO: [u8; 48] = [
        0xCE, 0xED, 0x66, 0x66, 0xCC, 0x0D, 0x00, 0x0B, 0x03, 0x73, 0x00, 0x83,
        0x00, 0x0C, 0x00, 0x0D, 0x00, 0x08, 0x11, 0x1F, 0x88, 0x89, 0x00, 0x0E,
        0xDC, 0xCC, 0x6E, 0xE6, 0xDD, 0xDD, 0xD9, 0x99, 0xBB, 0xBB, 0x67, 0x63,
        0x6E, 0x0E, 0xEC, 0xCC, 0xDD, 0xDC, 0x99, 0x9F, 0xBB, 0xB9, 0x33, 0x3E,
    ];
    if data[0x104..0x134] != NINTENDO_LOGO {
        return Ok(GbIdentification { is_gameboy: false, header: None, rom_data: Vec::new() });
    }

    // Parse the ROM header (all fields per GB spec).
    let title_bytes = &data[0x134..=0x143]; // 12 bytes, ASCII, may be padded with NULs/spaces
    let title = String::from_utf8_lossy(title_bytes)
        .trim_matches(|c: char| c == '\0' || c == ' ')
        .to_string();

    let manufacturer_id = &data[0x13F..=0x142]; // 4 bytes, ASCII
    let manufacturer_code = String::from_utf8_lossy(manufacturer_id)
        .trim_matches(|c: char| c == '\0')
        .to_string();

    let cgb_flag = data[0x143]; // $03 = CGB, $80 = non-CGB (old), $00 = DMG
    let mode = if cgb_flag != 0 { "cgb".into() } else { "gb".into() };

    let sgb_flag = data[0x146]; // $03 = SGB, $00 = non-SGB
    let licensee_code_hi = data[0x144];
    let licensee_code_lo = data[0x145];
    let licensee_present = licensee_code_hi != 0xFF; // old-style: $33 = Nintendo
    let licensee_code = if licensee_present {
        Some((licensee_code_hi, licensee_code_lo))
    } else {
        None
    };

    // ROM size table (Nintendo spec):
    // 0x00=256KB(no ext RAM), 0x01=512KB, 0x02=1MB, 0x03=2MB
    let rom_size_table: [usize; 4] = [256 * 1024, 512 * 1024, 1024 * 1024, 2 * 1024 * 1024];
    let rom_idx = (data[0x148] & 0x0C) >> 2; // bits 5-4 of ROM size byte
    let rom_size = if rom_idx < 4 { rom_size_table[rom_idx as usize] } else { data.len() };

    // RAM size table:
    // 0x00=none, 0x01=2KB, 0x02=8KB, 0x03=32KB, 0x04=64KB, 0x05=16KB (SGB)
    let ram_size_table: [usize; 6] = [0, 2 * 1024, 8 * 1024, 32 * 1024, 64 * 1024, 16 * 1024];
    let ram_idx = (data[0x149] & 0xE0) >> 5; // bits 7-5 of ext RAM size byte
    let ram_size = if ram_idx < 6 { ram_size_table[ram_idx as usize] } else { 0 };

    let destination = data[0x14A]; // $00=JP, $01=INTL
    let header_checksum = data[0x14D]; // simple checksum of bytes 0x0134-0x014C
    let global_checksum = u16::from_be_bytes([data[0x14E], data[0x14F]]);

    Ok(GbIdentification {
        is_gameboy: true,
        header: Some(GbHeader {
            title,
            manufacturer_code,
            cgb_flag,
            mode,
            sgb_flag,
            licensee_code,
            version: data[0x14C], // revision number
            rom_size,
            ram_size,
            destination,
            header_checksum,
            global_checksum,
        }),
        rom_data: data.to_vec(),
    })
}

/// Append one disassembled GameBoy instruction line to the output buffer.
#[allow(clippy::too_many_arguments)]
pub fn emit(output: &mut String, addr: u32, bytes: &[u8], mnemonic: &str, operands: &str) {
    let hex = bytes.iter().map(|b| format!("{:02X}", b)).collect::<Vec<_>>().join(" ");
    output.push_str(&format!("{:08X}  {:8}  {:<8} {}\n", addr, hex, mnemonic, operands));
}

/// Read a little-endian u16 from the ROM at `offset`.
pub fn read_le_u16(data: &[u8], offset: usize) -> u16 {
    let lo = data.get(offset).copied().unwrap_or(0);
    let hi = data.get(offset + 1).copied().unwrap_or(0);
    u16::from_le_bytes([lo, hi])
}

/// Disassemble the GameBoy Z80 ROM starting at `base_addr` (usually 0x0000).
/// Returns a formatted disassembly string.
pub fn disassemble_gb_data(rom_data: Vec<u8>, base_addr: u32, max_instructions: Option<usize>) -> Result<String, String> {
    if rom_data.is_empty() || base_addr as usize >= rom_data.len() {
        return Err("No ROM data to disassemble".to_string());
    }

    let max_instr = max_instructions.unwrap_or(4096);
    let mut output = String::new();
    output.push_str(&format!("GameBoy Z80 Disassembly (ROM, {} bytes)\n\n", rom_data.len()));

    // GameBoy Z80 subset register names

    let mut offset = base_addr as usize;
    let mut pc = 0u32; // program counter relative to ROM start

    while offset < rom_data.len() && pc.saturating_sub(base_addr) / 4 < max_instr as u32 {
        let addr = base_addr + pc.wrapping_sub(base_addr);
        let opcode = rom_data[offset] as u16;
        let mut size: u8 = 1;

        // Decode the instruction
        match opcode {
            // NOP
            0x00 => emit(&mut output, addr, &[0], "nop", ""),

            // LD BC, nn
            0x01 => {
                let val = read_le_u16(&rom_data, offset);
                emit(&mut output, addr, &[opcode as u8, (val&0xFF) as u8, ((val>>8)&0xFF) as u8], "ld", &format!("bc, 0x{:04X}", val));
                size = 3;
            }

            // LD (BC), A
            0x02 => emit(&mut output, addr, &[opcode as u8], "ld", "(bc), a"),

            // INC BC
            0x03 => emit(&mut output, addr, &[opcode as u8], "inc", "bc"),

            // INC C
            0x04 => emit(&mut output, addr, &[opcode as u8], "inc", "c"),

            // INC B
            0x05 => emit(&mut output, addr, &[opcode as u8], "inc", "b"),

            // LD C, n
            0x06 => {
                let val = rom_data[offset+1];
                emit(&mut output, addr, &[opcode as u8, val], "ld", &format!("c, 0x{:02X}", val));
                size = 2;
            }

            // RLCA
            0x07 => emit(&mut output, addr, &[opcode as u8], "rlca", ""),

            // LD (nn), SP
            0x08 => {
                let addr_val = read_le_u16(&rom_data, offset);
                emit(&mut output, addr, &[opcode as u8, (addr_val&0xFF) as u8, ((addr_val>>8)&0xFF) as u8], "ld", &format!("(0x{:04X}), sp", addr_val));
                size = 3;
            }

            // RET
            0xC9 => emit(&mut output, addr, &[opcode as u8], "ret", ""),

            // ADD HL, BC
            0x09 => emit(&mut output, addr, &[opcode as u8], "add hl, bc", ""),

            // DEC BC
            0x0B => emit(&mut output, addr, &[opcode as u8], "dec bc", ""),

            // INC A
            0x0C => emit(&mut output, addr, &[opcode as u8], "inc a", ""),

            // DEC A
            0x0D => emit(&mut output, addr, &[opcode as u8], "dec a", ""),

            // LD A, n
            0x0E => {
                let val = rom_data[offset+1];
                emit(&mut output, addr, &[opcode as u8, val], "ld", &format!("a, 0x{:02X}", val));
                size = 2;
            }

            // JR n
            0x18 => {
                let rel = rom_data[offset+1] as i8;
                emit(&mut output, addr, &[opcode as u8, rel as u8], "jr", &format!("+{}", rel as i16));
                size = 2;
            }

            // JP nn
            0xC3 => {
                let jp_addr = read_le_u16(&rom_data, offset);
                emit(&mut output, addr, &[opcode as u8, (jp_addr&0xFF) as u8, ((jp_addr>>8)&0xFF) as u8], "jp", &format!("0x{:04X}", jp_addr));
                size = 3;
            }

            // JP HL
            0xE9 => emit(&mut output, addr, &[opcode as u8], "jp hl", ""),

            // DI
            0xF3 => emit(&mut output, addr, &[opcode as u8], "di", ""),

            // EI
            0xFB => emit(&mut output, addr, &[opcode as u8], "ei", ""),

            // CPL
            0x2F => emit(&mut output, addr, &[opcode as u8], "cpl", ""),

            // SCF
            0x3F => emit(&mut output, addr, &[opcode as u8], "scf", ""),

            // CCF
            0x3E => emit(&mut output, addr, &[opcode as u8], "ccf", ""),

            // HALT
            0x76 => emit(&mut output, addr, &[opcode as u8], "halt", ""),

            // ADD A, n
            0xC6 => {
                let val = rom_data[offset+1];
                emit(&mut output, addr, &[opcode as u8, val], "add", &format!("a, 0x{:02X}", val));
                size = 2;
            }

            // SUB n
            0xD6 => {
                let val = rom_data[offset+1];
                emit(&mut output, addr, &[opcode as u8, val], "sub", &format!("0x{:02X}", val));
                size = 2;
            }

            // AND n
            0xE6 => {
                let val = rom_data[offset+1];
                emit(&mut output, addr, &[opcode as u8, val], "and", &format!("0x{:02X}", val));
                size = 2;
            }

            // XOR n
            0xEE => {
                let val = rom_data[offset+1];
                emit(&mut output, addr, &[opcode as u8, val], "xor", &format!("0x{:02X}", val));
                size = 2;
            }

            // CP n
            0xFE => {
                let val = rom_data[offset+1];
                emit(&mut output, addr, &[opcode as u8, val], "cp", &format!("0x{:02X}", val));
                size = 2;
            }

            // Default: unknown instruction
            _ => {
                emit(&mut output, addr, &[opcode as u8], &format!("db 0x{:02X}", opcode), "");
            }
        }

        offset += size as usize;
        pc += size as u32;
    }

    Ok(output)
}


/// Escape a path for TOML double-quoted string (backslashes -> forward slashes
/// keeps it portable and avoids TOML escape headaches on Windows).
pub fn toml_path(p: &str) -> String {
    let normalized = p.replace('\\', "/");
    let mut s = String::with_capacity(normalized.len() + 2);
    s.push('"');
    for ch in normalized.chars() {
        if ch == '"' {
            s.push('\\');
        }
        s.push(ch);
    }
    s.push('"');
    s
}

/// Escape an arbitrary string for a TOML basic string (double-quoted). Unlike
/// `toml_path` this preserves backslashes (only escaping `\` and `"`), so a
/// symbol name is emitted verbatim. Per TOML basic-string rules, control
/// characters below 0x20 are also escaped (unusual in symbol names, but keeps
/// the output strictly valid).
pub fn toml_basic_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04X}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// Build the config.toml body for a ps2recomp config bundle (pure, testable).
/// Mirrors the schema ExportPS2Functions.java emits so `ps2recomp config.toml`
/// consumes it directly.
pub fn build_config_toml(
    path: &str,
    output_dir: &str,
    csv_path: &str,
    info: &ElfFileInfo,
    funcs: &[FunctionEntry],
    from_symbols: usize,
    heuristic: usize,
    sce_sdk_named: usize,
    untracked_stubs: &[String],
) -> String {
    let mut t = String::new();
    t.push_str("# Auto-generated by Aura Decomp Tool\n");
    t.push_str("# Consumed by ps2recomp: `ps2recomp config.toml`\n");
    t.push_str("#\n");
    t.push_str("# Notes:\n");
    t.push_str("# - ghidra_output points at the function CSV (Name,Start,End,Size).\n");
    t.push_str("# - stubs/skip are intentionally empty; classify and populate stubs\n");
    t.push_str("#   manually once you know which functions need a host-provided body.\n");
    t.push_str(&format!(
        "# - {sce_sdk_named} function(s) were named via the embedded SCE SDK symbol DB.\n"
    ));
    t.push_str("# - untracked_stubs lists the SDK-matched functions ps2recomp identified\n");
    t.push_str("#   as library/SDK code. It is informational only and ignored by the recompiler.\n\n");

    t.push_str("[general]\n");
    t.push_str(&format!("input = {}\n", toml_path(path)));
    t.push_str(&format!("output = {}\n", toml_path(output_dir)));
    t.push_str(&format!("ghidra_output = {}\n", toml_path(csv_path)));
    t.push_str("single_file_output = false\n");
    t.push_str("patch_syscalls = false\n");
    t.push_str("patch_cop0 = true\n");
    t.push_str("patch_cache = true\n");
    t.push_str("stubs = []\n");
    // untracked_stubs: informational, ignored by ps2recomp. Emit one per line so
    // the list is readable and diffs cleanly. Empty -> single-line [].
    if untracked_stubs.is_empty() {
        t.push_str("untracked_stubs = []\n");
    } else {
        t.push_str("untracked_stubs = [\n");
        for name in untracked_stubs {
            t.push_str(&format!("    {},\n", toml_basic_string(name)));
        }
        t.push_str("]\n");
    }
    t.push_str("skip = []\n\n");

    t.push_str("[ghidra_export]\n");
    t.push_str(&format!("input_filename = {}\n", toml_path(&info.filename)));
    t.push_str(&format!("entry_point = \"0x{:08X}\"\n", info.entry_point));
    t.push_str(&format!("is_little_endian = {}\n", info.is_little_endian));
    t.push_str(&format!("sections = {}\n", info.sections.len()));
    t.push_str(&format!("symbols = {}\n", info.symbols.len()));
    t.push_str(&format!("relocations = {}\n", info.relocations.len()));
    t.push_str(&format!("function_count = {}\n", funcs.len()));
    t.push_str(&format!("from_symbols = {}\n", from_symbols));
    t.push_str(&format!("from_jal_heuristic = {}\n", heuristic));
    t.push_str(&format!("sce_sdk_named = {}\n", sce_sdk_named));
    t
}


pub fn export_decomp_project(
    path: String,
    platform: String,
    output_dir: String,
) -> Result<decomp_export::DecompExportResult, String> {
    let data = fs::read(&path).map_err(|e| format!("Failed to read file: {e}"))?;
    let filename = Path::new(&path)
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| path.clone());

    let (sections, functions, entry, little_endian): (
        Vec<decomp_export::DecompSection>,
        Vec<decomp_export::DecompFunction>,
        u64,
        bool,
    ) = match platform.as_str() {
        "PS1" | "PS2" => {
            let info = parse_elf_file_engine(path.clone())?;
            let funcs = detect_functions_inner(&info)?;

            let sections: Vec<decomp_export::DecompSection> = info
                .sections
                .iter()
                .filter(|s| !s.data.is_empty())
                .map(|s| decomp_export::DecompSection {
                    name: s.name.clone(),
                    address: s.address as u64,
                    size: s.size as usize,
                    is_code: s.name.starts_with(".text") || s.name.starts_with(".init"),
                    file_offset: s.offset as u64,
                })
                .collect();
            let functions: Vec<decomp_export::DecompFunction> = funcs
                .iter()
                .map(|f| decomp_export::DecompFunction {
                    address: f.start as u64,
                    name: f.name.clone(),
                    size: f.size as usize,
                    is_named: !f.name.starts_with("sub_"),
                    source: if !f.name.starts_with("sub_") {
                        decomp_export::FunctionSource::SdkMatch
                    } else {
                        decomp_export::FunctionSource::Heuristic
                    },
                })
                .collect();
            (sections, functions, info.entry_point as u64, info.is_little_endian)
        }
        "PS3" => {
            let info = ps3::parse_ps3(&data, &filename)?;
            if info.encrypted {
                return Err("PS3 SELF is encrypted — export requires a decrypted/homebrew binary".into());
            }
            let sections = info.sections.iter().map(|s| decomp_export::DecompSection {
                name: s.name.clone(), address: s.sh_addr, size: s.sh_size as usize,
                is_code: s.is_code, file_offset: s.sh_offset,
            }).collect();
            (sections, vec![], info.entry_point, false)
        }
        "PS4" | "PS5" => {
            let info = ps4ps5::parse_ps4ps5(&data, &filename)?;
            if info.encrypted {
                return Err("PS4/PS5 SELF is encrypted — export requires an unencrypted/homebrew binary".into());
            }
            let sections = info.sections.iter().map(|s| decomp_export::DecompSection {
                name: s.name.clone(), address: s.sh_addr, size: s.sh_size as usize,
                is_code: s.is_code, file_offset: s.sh_offset,
            }).collect();
            (sections, vec![], info.entry_point, true)
        }
        "Wii U" => {
            let info = wiiu::parse_rpx_rpl(&data, &filename)?;
            let sections = info.sections.iter().map(|s| decomp_export::DecompSection {
                name: s.name.clone(), address: s.sh_addr, size: s.sh_size as usize,
                is_code: s.is_code, file_offset: s.sh_offset,
            }).collect();
            let mut by_addr: std::collections::HashMap<u64, String> = std::collections::HashMap::new();
            for f in info.fimports.iter().chain(info.fexports.iter()).chain(info.symbols.iter()) {
                by_addr.entry(f.address).or_insert_with(|| f.name.clone());
            }
            let mut functions: Vec<decomp_export::DecompFunction> = by_addr
                .into_iter()
                .map(|(address, name)| decomp_export::DecompFunction {
                    address, name, size: 0, is_named: true,
                    source: decomp_export::FunctionSource::SymbolTable,
                })
                .collect();
            functions.sort_by_key(|f| f.address);
            (sections, functions, info.entry_point, false)
        }
        "Xbox" => {
            let info = xbox::parse_xbe(&data, &filename)?;
            let sections = info.sections.iter().map(|s| decomp_export::DecompSection {
                name: s.name.clone(), address: s.virtual_address as u64,
                size: s.virtual_size as usize, is_code: s.executable,
                file_offset: s.raw_offset as u64,
            }).collect();
            (sections, vec![], info.entry_point as u64, true)
        }
        "Xbox 360" => {
            let info = xbox360::parse_xex(&data, &filename)?;
            let base = info.image_base.unwrap_or(info.load_address) as u64;
            let sections = info.pe_sections.iter().map(|s| decomp_export::DecompSection {
                name: s.name.clone(), address: base + s.virtual_address as u64,
                size: s.virtual_size as usize, is_code: s.executable,
                file_offset: s.raw_offset as u64,
            }).collect();
            let functions: Vec<decomp_export::DecompFunction> = info.pe_exports
                .iter().filter(|e| !e.name.is_empty())
                .map(|e| decomp_export::DecompFunction {
                    address: base + e.rva as u64, name: e.name.clone(), size: 0,
                    is_named: true, source: decomp_export::FunctionSource::SymbolTable,
                })
                .collect();
            (sections, functions, info.entry_point.unwrap_or(0) as u64, true)
        }
        other => {
            return Err(format!(
                "Export for platform '{other}' is not implemented yet. Use the Disassembly view for it, \
                 or export with a supported platform (PS1/PS2/PS3/PS4/PS5/Wii U/Xbox/Xbox 360)."
            ));
        }
    };

    Ok(decomp_export::generate_decomp_project(
        &filename,
        &platform,
        &sections,
        &functions,
        entry,
        &output_dir,
        little_endian,
    ))
}


pub fn scan_sdk_symbols_data(data: &[u8], platform: String) -> Result<sdk_symbols::SdkScanResult, String> {
    let plat = match platform.as_str() {
        "PS1" => sdk_symbols::Platform::Ps1,
        "PS2" => sdk_symbols::Platform::Ps2,
        "PS3" => sdk_symbols::Platform::Ps3,
        "PS4" => sdk_symbols::Platform::Ps4,
        "PS5" => sdk_symbols::Platform::Ps5,
        "Xbox" => sdk_symbols::Platform::Xbox,
        "Xbox 360" => sdk_symbols::Platform::Xbox360,
        "Wii U" => sdk_symbols::Platform::WiiU,
        "GameCube" => sdk_symbols::Platform::GameCube,
        "Wii" => sdk_symbols::Platform::Wii,
        "Sega Genesis" => sdk_symbols::Platform::SegaGenesis,
        _ => return Err(format!("Unknown platform: {}", platform)),
    };

    // Collect names from .fimports (Wii U), ELF symbols, or other import tables.
    // For now, extract all ASCII strings that look like function names.
    let mut names: Vec<(String, u64)> = Vec::new();
    let mut i = 0;
    while i + 2 < data.len() {
        if data[i].is_ascii_alphabetic() || data[i] == b'_' {
            let end = data[i..]
                .iter()
                .position(|&b| b == 0 || !b.is_ascii_graphic())
                .map(|n| i + n)
                .unwrap_or(i + 64);
            if end - i >= 3 && end - i <= 256 {
                let name = String::from_utf8_lossy(&data[i..end]).to_string();
                if name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.') {
                    names.push((name, i as u64));
                }
            }
            i = end + 1;
        } else {
            i += 1;
        }
    }

    Ok(sdk_symbols::match_by_names(&names, plat))
}


pub fn supported_formats() -> Result<serde_json::Value, String> {
    Ok(serde_json::json!({
        "formats": [
            {
                "name": "ELF (Executable and Linkable Format)",
                "extensions": [".elf", ".sym"],
                "platforms": ["PS1", "PS2", "PS3"]
            },
            {
                "name": "PlayStation 1 Binary",
                "extensions": [".bin", ".cue", ".img"],
                "platforms": ["PS1"]
            },
            {
                "name": "PlayStation 2 ELF/PRX",
                "extensions": [".elf", ".prx", ".irx"],
                "platforms": ["PS2"]
            },
            {
                "name": "PlayStation 3 SELF/ELF",
                "extensions": [".self", ".elf", ".sprx"],
                "platforms": ["PS3"]
            },
            {
                "name": "PlayStation 4/5 SELF/ELF/eboot.bin",
                "extensions": [".self", ".elf", ".bin", ".eboot.bin"],
                "platforms": ["PS4", "PS5"]
            },
            {
                "name": "Wii U RPX/RPL",
                "extensions": [".rpx", ".rpl"],
                "platforms": ["Wii U"]
            },
            {
                "name": "Original Xbox Executable (XBE)",
                "extensions": [".xbe"],
                "platforms": ["Xbox"]
            },
            {
                "name": "Xbox 360 Executable (XEX)",
                "extensions": [".xex"],
                "platforms": ["Xbox 360"]
            }
        ]
    }))
}


