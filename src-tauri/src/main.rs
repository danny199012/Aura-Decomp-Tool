#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod ps1_analysis;
mod ps1_call_graph_enhanced;
mod ps1_disasm;
mod ps1_exe;
mod ps1_memory_map;
mod ps1_recomp_export;
mod ps1_symbols;
mod sce_symbol_scanner;
// Multi-platform backends: shared PowerPC decoder plus Xbox/360/GameCube/Genesis.
mod gamecube;
mod lzx;
mod ppc_disasm;
mod ps3;
mod ps4ps5;
mod sega_genesis;
mod wiiu;
mod xbox;
mod xbox360;

use sce_symbol_scanner::{CodeSection, SceSymbolDatabase, SceSymbolMatch};
use serde::{Deserialize, Serialize};

/// GameBoy ROM header info (first 0x150 bytes are standardized)
#[derive(Serialize, Deserialize, Debug, Clone)]
struct GbHeader {
    title: String,
    manufacturer_code: String,
    cgb_flag: u8,
    /// "gb" or "cgb"
    mode: String,
    sgb_flag: u8,
    licensee_code: Option<(u8, u8)>,
    version: u8,
    rom_size: usize,
    ram_size: usize,
    destination: u8,
    header_checksum: u8,
    global_checksum: u16,
}

/// A single Z80 instruction for the disassembly output
#[derive(Serialize, Deserialize, Debug, Clone)]
struct Z80Instruction {
    address: u32,
    bytes: Vec<u8>,
    mnemonic: String,
    operand: String,
    size: u8,
}

/// Result of a GameBoy ROM identification
#[derive(Serialize, Deserialize, Debug, Clone)]
struct GbIdentification {
    is_gameboy: bool,
    header: Option<GbHeader>,
    rom_data: Vec<u8>,
}
use std::fs;
use std::path::Path;
use std::sync::OnceLock;
use tauri_plugin_dialog::DialogExt;

#[derive(Serialize, Deserialize, Clone, Debug)]
struct LogEntry {
    level: String,
    message: String,
    timestamp: String,
}

#[derive(Serialize, Debug)]
struct FileOpenResponse {
    success: bool,
    filename: Option<String>,
    size: Option<u64>,
    message: String,
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
struct ElfSymbol {
    name: String,
    address: u32,
    size: u32,
    section: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ElfFileInfo {
    pub filename: String,
    pub sections: Vec<ElfSection>,
    symbols: Vec<ElfSymbol>,
    entry_point: u32,
    file_size: u64,
    is_little_endian: bool,
    is_32bit: bool,
    /// Dynamic relocations (SHT_REL / SHT_RELA). Retail PS2 games are usually
    /// statically linked and have none; dev/homebrew builds use these to name
    /// imported symbols at specific call-site offsets.
    #[serde(default)]
    relocations: Vec<Relocation>,
}

/// A single ELF relocation entry (mirrors what ps2recomp's Relocation carries).
#[derive(Serialize, Deserialize, Debug, Clone)]
struct Relocation {
    /// ABSOLUTE virtual address where the fixup applies (target section's
    /// sh_addr + r_offset). Section-relative r_offset (ET_REL/homebrew) is
    /// normalized here so it matches the absolute callsite addresses the call
    /// graph emits; for ET_EXEC binaries this is already absolute.
    offset: u32,
    /// Resolved symbol name (empty if the symbol is unnamed/section-local).
    symbol_name: String,
    /// MIPS relocation type (R_MIPS_*). R_MIPS_26 (= 4) patches JAL/J targets.
    r_type: u32,
    /// Symbol index in the referenced symbol table.
    symbol: u32,
}

/// MIPS ELF relocation type numbers (ELF MIPS ABI). Only R_MIPS_26 (the JAL/J
/// call relocation) is used to resolve call-graph targets to import names; the
/// 16-bit immediate types patch lui/addiu pairs, not calls.
const R_MIPS_26: u32 = 4;

#[derive(Serialize, Deserialize, Debug)]
struct DecompileRequest {
    function_name: String,
    address: String,
}

#[derive(Serialize, Debug)]
struct DecompileResponse {
    success: bool,
    output: Option<String>,
    message: String,
}

fn get_timestamp() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();

    let total_secs = duration.as_secs();
    let hours = (total_secs / 3600) % 24;
    let minutes = (total_secs / 60) % 60;
    let seconds = total_secs % 60;
    format!("{:02}:{:02}:{:02}", hours, minutes, seconds)
}

#[tauri::command]
fn log_message(level: String, message: String) -> Result<(), String> {
    let timestamp = get_timestamp();
    let entry = LogEntry {
        level: level.clone(),
        message: message.clone(),
        timestamp,
    };

    match entry.level.as_str() {
        "ERROR" => eprintln!("[{}] {}", entry.timestamp, entry.message),
        "WARN" => println!("[{}] {}", entry.timestamp, entry.message),
        _ => println!("[{}] [{}] {}", entry.level, entry.timestamp, entry.message),
    }

    Ok(())
}

#[tauri::command]
fn open_file_dialog(app: tauri::AppHandle) -> Result<String, String> {
    let (tx, rx) = std::sync::mpsc::channel();
    app.dialog().file()
        .add_filter("ELF & Symbols", &["elf", "sym", "prx", "irx", "sprx"])
        .add_filter("PlayStation Images", &["bin", "dat", "img", "iso"])
        .add_filter("All Files", &["*"])
        .pick_file(move |path| {
            if let Some(filepath) = path {
                tx.send(filepath.to_string()).ok();
                return;
            }
            tx.send(String::new()).ok();
        });
    match rx.recv_timeout(std::time::Duration::from_secs(30)) {
        Ok(path) => {
            if path.is_empty() {
                Err("No file selected".to_string())
            } else {
                Ok(path)
            }
        },
        Err(_) => Err("Dialog timed out".to_string()),
    }
}

#[tauri::command]
fn open_multiple_files_dialog(app: tauri::AppHandle) -> Result<Vec<String>, String> {
    let (tx, rx) = std::sync::mpsc::channel();
    app.dialog().file()
        .add_filter("ELF & Symbols", &["elf", "sym", "prx", "irx", "sprx"])
        .add_filter("PlayStation Images", &["bin", "dat", "img", "iso"])
        .add_filter("All Files", &["*"])
        .pick_files(move |paths_opt| {
            if let Some(paths) = paths_opt {
                let collected: Vec<String> = paths.into_iter().map(|p| p.to_string()).collect();
                tx.send(collected).ok();
            } else {
                tx.send(Vec::new()).ok();
            }
        });
    match rx.recv_timeout(std::time::Duration::from_secs(30)) {
        Ok(paths) => Ok(paths),
        Err(_) => Ok(Vec::new()),
    }
}

#[tauri::command]
fn open_file(path: String) -> Result<FileOpenResponse, String> {
    let p = Path::new(&path);
    if !p.exists() {
        return Ok(FileOpenResponse {
            success: false,
            filename: None,
            size: None,
            message: format!("File not found: {}", path),
        });
    }

    let metadata = fs::metadata(p).map_err(|e| e.to_string())?;
    let filename = p.file_name().unwrap_or_default().to_str().unwrap_or("unknown").to_string();

    // PS-X wrapper pre-step: if the file is a PS1 executable image, surface its
    // header metadata (and embedded-ELF offset) in the open message so the UI
    // can route to the right loader. Pure detection — no other behaviour changes.
    let psx_note = match ps1_exe::detect_psx_header(&path) {
        Ok(Some(info)) => format!(" [PS-X v{} ELF@0x{:X}]", info.version, info.elf_offset),
        _ => String::new(),
    };

    Ok(FileOpenResponse {
        success: true,
        filename: Some(filename),
        size: Some(metadata.len()),
        message: format!("Opened {} ({} bytes){}", path, metadata.len(), psx_note),
    })
}

/// Read up to `max_bytes` of a raw binary file and return it as a list of bytes.
/// Used when a file is not a valid ELF (e.g. a raw PS-X .bin executable) so the
/// user can still disassemble it at a chosen base address.
#[tauri::command]
fn read_raw_binary(path: String, max_bytes: Option<usize>) -> Result<Vec<u8>, String> {
    let p = Path::new(&path);
    if !p.exists() {
        return Err(format!("File not found: {}", path));
    }
    let metadata = fs::metadata(p).map_err(|e| e.to_string())?;
    let cap = max_bytes.unwrap_or(4 * 1024 * 1024).min(metadata.len() as usize);
    let mut file = fs::File::open(p).map_err(|e| e.to_string())?;
    let mut buf = vec![0u8; cap];
    use std::io::Read;
    let n = file.read(&mut buf).map_err(|e| e.to_string())?;
    buf.truncate(n);
    Ok(buf)
}

/// Identify a file by its magic bytes. Returns a short descriptor like
/// "elf32-le", "elf32-be", "psx-exe", "raw". Helps the UI pick a loader.
#[tauri::command]
fn identify_file(path: String) -> Result<String, String> {
    let p = Path::new(&path);
    if !p.exists() {
        return Err(format!("File not found: {}", path));
    }
    let mut file = fs::File::open(p).map_err(|e| e.to_string())?;
    let mut head = [0u8; 8];
    use std::io::Read;
    let n = file.read(&mut head).unwrap_or(0);
    let h = &head[..n];

    if h.len() >= 5 && &h[0..4] == [0x7f, b'E', b'L', b'F'] {
        if h[4] == 1 {
            return Ok(if h[5] == 1 { "elf32-le".into() } else { "elf32-be".into() });
        }
        if h[4] == 2 {
            return Ok(if h[5] == 1 { "elf64-le".into() } else { "elf64-be".into() });
        }
        return Ok("elf-unknown".into());
    }
    // PS-X executable: "PS-X EXE" at offset 0
    if h.len() >= 8 && &h[0..8] == b"PS-X EXE" {
        return Ok("psx-exe".into());
    }
    // Original Xbox executable: "XBEH"
    if h.len() >= 4 && &h[0..4] == b"XBEH" {
        return Ok("xbe".into());
    }
    // Xbox 360 executable: "XEX0" / "XEX1" / "XEX2"
    if h.len() >= 4 && &h[0..3] == b"XEX" && (b'0'..=b'2').contains(&h[3]) {
        return Ok("xex".into());
    }
    // PS3/PS4/PS5 SELF: "SCE\0"
    if h.len() >= 4 && &h[0..3] == b"SCE" && h[3] == 0 {
        return Ok("self".into());
    }
    // Wii U RPX/RPL: BE ELF64 with e_machine==21 — detected by reading more bytes
    Ok("raw".into())
}

/// Helper functions to read u32 from byte slice with endianness support
fn read_u32(data: &[u8], offset: usize, is_little_endian: bool) -> u32 {
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
fn read_u16(data: &[u8], offset: usize, is_little_endian: bool) -> u16 {
    if offset + 2 > data.len() {
        return 0;
    }
    if is_little_endian {
        u16::from_le_bytes([data[offset], data[offset+1]])
    } else {
        u16::from_be_bytes([data[offset], data[offset+1]])
    }
}

/// Parse a MIPS ELF file and extract sections, symbols, and disassembly
#[tauri::command]
pub fn parse_elf_file(path: String) -> Result<ElfFileInfo, String> {
    let data = fs::read(&path).map_err(|e| format!("Failed to read file: {}", e))?;

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

    println!("ELF Header: type={}, machine={}, entry=0x{:08X}, shoff={}, shnum={}, shstrndx={}",
        e_type, e_machine, e_entry, e_shoff, e_shnum, e_shstrndx);

    let mut sections: Vec<ElfSection> = Vec::new();
    let mut symbols: Vec<ElfSymbol> = Vec::new();

    if e_shoff > 0 && e_shnum > 0 && (e_shoff as usize) < data.len() {
        // Parse section headers to get section name string table
        let shstrtab_offset = (e_shoff as usize) + (e_shstrndx as usize) * (e_shentsize as usize);

        if shstrtab_offset + 24 <= data.len() {
            let str_tab_offset: u32 = read_u32(&data, shstrtab_offset + 16, is_little_endian);
            let str_tab_size: u32 = read_u32(&data, shstrtab_offset + 20, is_little_endian);

            println!("Section name string table: offset={}, size={}", str_tab_offset, str_tab_size);

            if str_tab_offset < data.len() as u32 && str_tab_size > 0 {
                let str_tab_end = std::cmp::min(str_tab_offset + str_tab_size, data.len() as u32) as usize;
                let str_table = &data[str_tab_offset as usize..str_tab_end];

                // Find the null string to validate the string table
                if let Some(null_pos) = str_table.iter().position(|&b| b == 0) {
                    let str_table_str = std::str::from_utf8(&str_table[..null_pos]).unwrap_or("");
                    println!("Section name string table: {}", str_table_str);

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

                        println!("Section {}: type={} flags=0x{:X} addr=0x{:08X} size={} offset={}",
                            section_name, sh_type, sh_flags, sh_addr, sh_size, sh_offset_val);

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
    let relocations = parse_relocations(&data, e_shoff, e_shnum, e_shentsize, is_little_endian);

    let filename = path.split('/').last().or(path.split('\\').last()).unwrap_or("unknown").to_string();

    Ok(ElfFileInfo {
        filename,
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

/// MIPS R3000 (PS1/PS2 IOP) disassembler. Produces a textual listing.
/// NOTE: This is the backend variant; the UI uses the in-browser decoder in App.tsx
/// for immediate feedback, but this is kept correct and consistent.
#[tauri::command]
fn disassemble_section(data: Vec<u8>, section_name: String, start_addr: u32, is_little_endian: bool) -> Result<String, String> {
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
struct FunctionEntry {
    name: String,
    start: u32,
    end: u32,
    size: u32,
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
enum CallKind {
    /// `jal target` — a subroutine call that returns to the delay slot+4.
    Jal,
    /// `j target` used as a tail call (i.e. the target is OUTSIDE the
    /// containing function). Intra-function `j` (gotos/loops) are dropped.
    Jump,
}

/// A resolved call edge between two detected functions.
#[derive(Serialize, Deserialize, Clone, Debug)]
struct CallEdge {
    /// Caller function's START address (the `from` is mapped from the raw
    /// callsite by attribution against the detected function ranges).
    from: u32,
    /// Callee target address (the JAL/J target field).
    to: u32,
    /// Address of the JAL/J instruction itself.
    callsite: u32,
    kind: CallKind,
}

/// The full call graph for a binary: attributed edges + the set of targets
/// that no detected function starts at (external imports / undetected code).
#[derive(Serialize, Debug, Clone)]
struct CallGraph {
    edges: Vec<CallEdge>,
    /// JAL/J targets that don't coincide with any detected function start.
    /// Deduped + sorted ascending. Informational — feeds later stub
    /// classification and the "missed functions" hint.
    external_targets: Vec<u32>,
    /// (target_address, imported_symbol_name) pairs resolved from R_MIPS_26
    /// relocations at JAL callsites. Lets the UI show e.g. "printf" instead of
    /// "ext_XXXXXXXX" for imported SDK functions. Empty on stripped retail
    /// binaries (no relocations). Sorted by address, deduped by address.
    target_names: Vec<(u32, String)>,
}

/// Pre-attribution raw edge: a direct call instruction and its target, before
/// we know which function the callsite belongs to.
#[derive(Clone, Debug, PartialEq, Eq)]
struct RawCallEdge {
    callsite: u32,
    target: u32,
    kind: CallKind,
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
fn detect_functions_in_sections(
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
fn collect_call_edges(sections: &[ElfSection], is_little_endian: bool) -> Vec<RawCallEdge> {
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
fn build_call_graph(mut raw: Vec<RawCallEdge>, funcs: &[FunctionEntry]) -> CallGraph {
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

/// Detect functions in a PS2 ELF and return them for display in the UI.
/// Uses real symbols when present; otherwise falls back to JAL-scan heuristics.
#[tauri::command]
fn detect_functions(path: String) -> Result<Vec<FunctionEntry>, String> {
    Ok(detect_functions_inner(&parse_elf_file(path)?)?)
}

/// Build the direct call graph (JAL + tail-call J) for a PS2 ELF and return
/// Resolve the external targets of JAL calls to imported symbol names using
/// `R_MIPS_26` relocations, and store them in `graph.target_names`.
///
/// The join: a R_MIPS_26 relocation sits at the JAL instruction's address and
/// records the imported name the linker would patch the target field with. So
/// for each JAL edge, if a relocation with `offset == edge.callsite` exists,
/// the imported name applies to `edge.to` (the unrelocated stub target). The UI
/// then shows "printf" instead of "ext_XXXXXXXX".
///
/// `relocations` offsets must already be absolute (as `parse_relocations`
/// normalizes them). Retail binaries have no relocations → this is a no-op.
/// Pure; testable in isolation.
fn enrich_call_graph_with_relocs(mut graph: CallGraph, relocations: &[Relocation]) -> CallGraph {
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

/// it for the UI. Edges are attributed to detected functions; targets that
/// match no function start are reported in `external_targets`. Indirect calls
/// (`jalr`/`jr $t9`) are not yet tracked.
#[tauri::command]
fn get_call_graph(path: String) -> Result<CallGraph, String> {
    let info = parse_elf_file(path)?;
    let funcs = detect_functions_inner(&info)?;
    let raw = collect_call_edges(&info.sections, info.is_little_endian);
    let graph = build_call_graph(raw, &funcs);
    Ok(enrich_call_graph_with_relocs(graph, &info.relocations))
}

/// Pure inner form of `detect_functions` — shared by the command and the
/// config/CSV exporters so they all agree on the function set. When the binary
/// is stripped (no symbol-table functions), it additionally runs the SCE SDK
/// symbol matcher against the detected `sub_XXXXXXXX`s so they get real SDK
/// names (printf/PadInit/...) where the database has an unambiguous hit.
fn detect_functions_inner(info: &ElfFileInfo) -> Result<Vec<FunctionEntry>, String> {
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
fn sce_db() -> &'static Result<SceSymbolDatabase, String> {
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

/// Rename `sub_XXXXXXXX` entries to their real SDK names where the SCE symbol
/// database has an unambiguous hash match. Runs the matcher over executable
/// sections and patches any `FunctionEntry` whose start coincides with a match.
/// Leaves unmatched entries as `sub_XXXXXXXX`.
fn apply_sce_sdk_names(sections: &[ElfSection], funcs: &mut [FunctionEntry]) {
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
fn scan_sce_sdk_matches(sections: &[ElfSection]) -> Vec<SceSymbolMatch> {
    match sce_db() {
        Ok(db) => db.scan(&sce_code_sections(sections)),
        Err(_) => Vec::new(),
    }
}

/// Scan a PS2 ELF for SCE SDK library functions and return the matches.
/// Each match is a `(address, size, name, library)` triple — e.g. printf,
/// PadInit, FlushCache — that Aura can use to rename detected `sub_XXXXXXXX`s.
/// Returns an empty list (with a message) if the embedded DB failed to load.
#[tauri::command]
fn scan_sce_symbols(path: String) -> Result<SceSymbolScanResult, String> {
    let info = parse_elf_file(path)?;
    let matches = scan_sce_sdk_matches(&info.sections);
    Ok(SceSymbolScanResult {
        matches,
        db_symbol_count: sce_db().as_ref().map(|d| d.symbol_count()).unwrap_or(0),
        db_error: sce_db().as_ref().err().cloned(),
    })
}

/// Result of an on-demand SCE SDK scan.
#[derive(Serialize, Debug)]
struct SceSymbolScanResult {
    matches: Vec<SceSymbolMatch>,
    /// Total variants in the loaded DB (for the status line).
    db_symbol_count: usize,
    /// Present only if the embedded DB failed to parse.
    db_error: Option<String>,
}

// ===================== GameBoy ROM support =====================

/// Identify a file as a GameBoy ROM and return header info + raw bytes.
#[tauri::command]
fn identify_gb_rom(path: String) -> Result<GbIdentification, String> {
    let data = fs::read(&path).map_err(|e| format!("Failed to read file: {}", e))?;
    if data.len() < 0x150 {
        return Ok(GbIdentification { is_gameboy: false, header: None, rom_data: Vec::new() });
    }

    // Check GameBoy signature at 0x0148-0x0149: $00 $FF must both be present.
    let sig_byte_0 = data[0x148];
    let sig_byte_1 = data[0x149];
    if sig_byte_0 != 0x00 || sig_byte_1 != 0xFF {
        // Also accept the "new style" signature: $00 at 0x014B and $FF at 0x014E.
        let new_a = data.get(0x14B) == Some(&0x00);
        let new_b = data.get(0x14E) == Some(&0xFF);
        if !new_a || !new_b {
            return Ok(GbIdentification { is_gameboy: false, header: None, rom_data: Vec::new() });
        }
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
        rom_data: data,
    })
}

/// Disassemble the GameBoy Z80 ROM starting at `base_addr` (usually 0x0000).
/// Returns a formatted disassembly string.
#[tauri::command]
fn disassemble_gb_rom(rom_data: Vec<u8>, base_addr: u32, max_instructions: Option<usize>) -> Result<String, String> {
    if rom_data.is_empty() || base_addr as usize >= rom_data.len() {
        return Err("No ROM data to disassemble".to_string());
    }

    let max_instr = max_instructions.unwrap_or(4096);
    let mut output = String::new();
    output.push_str(&format!("GameBoy Z80 Disassembly (ROM, {} bytes)\n\n", rom_data.len()));

    // GameBoy Z80 subset register names
    const REGS_8: [&str; 8] = ["b","c","d","e","h","l","(hl)","a"];
    const REGS_16: [&[&str]; 4] = &[&["b","c"], &["d","e"], &["h","l"], &["sp"]];
    const FLAG_Z: &str = "z";
    const FLAG_N: &str = "n";
    const FLAG_H: &str = "h";
    const FLAG_C: &str = "c";

    let mut offset = base_addr as usize;
    let mut pc = 0u32; // program counter relative to ROM start

    while offset < rom_data.len() && (pc - base_addr) / 4 < max_instructions as u32 {
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
                emit(&mut output, addr, &[opcode as u8, (val&0xFF) as u8, ((val>>8)&0xFF) as u8], "ld", "bc, 0x{:04X}", val);
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

            // DEC C
            0x06 => {
                let val = rom_data[offset+1] as i8;
                emit(&mut output, addr, &[opcode as u8, val as u8], "ld", "c, {}", val);
                size = 2;
            }

            // LD C, n
            0x06 => {
                let val = rom_data[offset+1];
                emit(&mut output, addr, &[opcode as u8, val], "ld", "c, 0x{:02X}", val);
                size = 2;
            }

            // RLCA
            0x07 => emit(&mut output, addr, &[opcode as u8], "rlca", ""),

            // LD (nn), SP
            0x08 => {
                let addr_val = read_le_u16(&rom_data, offset);
                emit(&mut output, addr, &[opcode as u8, (addr_val&0xFF) as u8, ((addr_val>>8)&0xFF) as u8], "ld", "(0x{:04X}), sp", addr_val);
                size = 3;
            }

            // RET
            0xC9 => emit(&mut output, addr, &[opcode as u8], "ret", ""),

            // ADD HL, BC
            0x09 => emit(&mut output, addr, &[opcode as u8], "add hl, bc"),

            // DEC BC
            0x0B => emit(&mut output, addr, &[opcode as u8], "dec bc"),

            // INC A
            0x0C => emit(&mut output, addr, &[opcode as u8], "inc a"),

            // DEC A
            0x0D => emit(&mut output, addr, &[opcode as u8], "dec a"),

            // LD A, n
            0x0E => {
                let val = rom_data[offset+1];
                emit(&mut output, addr, &[opcode as u8, val], "ld", "a, 0x{:02X}", val);
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
            0xE9 => emit(&mut output, addr, &[opcode as u8], "jp hl"),

            // DI
            0xF3 => emit(&mut output, addr, &[opcode as u8], "di"),

            // EI
            0xFB => emit(&mut output, addr, &[opcode as u8], "ei"),

            // CPL
            0x2F => emit(&mut output, addr, &[opcode as u8], "cpl"),

            // SCF
            0x3F => emit(&mut output, addr, &[opcode as u8], "scf"),

            // CCF
            0x3E => emit(&mut output, addr, &[opcode as u8], "ccf"),

            // HALT
            0x76 => emit(&mut output, addr, &[opcode as u8], "halt"),

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

/// consumes (Name,Start,End,Size). Addresses are uppercase hex with 0x prefix;
/// Size is decimal in bytes. This is byte-compatible with ExportPS2Functions.java.
///
///   Name,Start,End,Size
///   sub_00100000,0x00100000,0x001001A0,416
#[tauri::command]
fn export_functions_csv(path: String, output_csv: String) -> Result<usize, String> {
    let funcs = detect_functions(path.clone())?;

    let mut csv = String::new();
    csv.push_str("Name,Start,End,Size\n");
    for f in &funcs {
        csv.push_str(&format!(
            "{},0x{:08X},0x{:08X},{}\n",
            f.name, f.start, f.end, f.size
        ));
    }

    fs::write(&output_csv, csv).map_err(|e| format!("Failed to write CSV: {}", e))?;
    Ok(funcs.len())
}

/// Show a native save-file dialog, then write the PS2Recomp CSV there.
/// Returns Some(count) on success, or None if the user cancelled.
#[tauri::command]
fn export_functions_csv_dialog(app: tauri::AppHandle, path: String) -> Result<Option<usize>, String> {
    let (tx, rx) = std::sync::mpsc::channel();
    app.dialog().file()
        .add_filter("CSV (PS2Recomp / Ghidra)", &["csv"])
        .set_file_name("functions.csv")
        .save_file(move |file_path| {
            tx.send(file_path.map(|p| p.to_string())).ok();
        });

    let chosen = match rx.recv_timeout(std::time::Duration::from_secs(120)) {
        Ok(v) => v,
        Err(_) => return Err("Save dialog timed out".to_string()),
    };

    let Some(out_path) = chosen else { return Ok(None) };
    let count = export_functions_csv(path, out_path)?;
    Ok(Some(count))
}

/// Escape a path for TOML double-quoted string (backslashes -> forward slashes
/// keeps it portable and avoids TOML escape headaches on Windows).
fn toml_path(p: &str) -> String {
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
fn toml_basic_string(s: &str) -> String {
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
fn build_config_toml(
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

/// Generate a complete, ps2recomp-valid config.toml for the given ELF.
/// Writes both the CSV (Name,Start,End,Size) and the TOML, returning the
/// function count. The output_dir becomes the recompiler's `output` path and
/// the CSV path is wired into `ghidra_output`.
///
/// This mirrors the schema ExportPS2Functions.java emits, so `ps2recomp
/// <config.toml>` can consume it directly:
///   [general]
///   input = "..."
///   output = "..."
///   ghidra_output = ".../functions.csv"
///   stubs = [...]
///   skip = []
#[tauri::command]
fn generate_config_toml(
    path: String,
    output_dir: String,
) -> Result<ConfigResult, String> {
    let info = parse_elf_file(path.clone())?;
    let funcs = detect_functions_inner(&info)?;

    // Write the CSV beside the TOML.
    let csv_path = format!("{}/functions.csv", output_dir.trim_end_matches('/'));
    let mut csv = String::from("Name,Start,End,Size\n");
    for f in &funcs {
        csv.push_str(&format!(
            "{},0x{:08X},0x{:08X},{}\n",
            f.name, f.start, f.end, f.size
        ));
    }
    fs::write(&csv_path, csv).map_err(|e| format!("Failed to write CSV: {}", e))?;

    // Count how many functions come from real symbols vs JAL heuristics.
    let from_symbols = info.symbols.iter().filter(|s| s.size > 0).count();
    let heuristic = funcs.len().saturating_sub(from_symbols);
    // How many heuristic functions were renamed to SDK names by the matcher.
    let sce_sdk_named = funcs
        .iter()
        .filter(|f| !f.name.starts_with("sub_"))
        .count();

    // The list of SDK-matched function names, sorted + deduped, for the
    // informational `untracked_stubs` array (ps2recomp ignores this field).
    let mut untracked_stubs: Vec<String> = funcs
        .iter()
        .filter_map(|f| {
            if f.name.starts_with("sub_") {
                None
            } else {
                Some(f.name.clone())
            }
        })
        .collect();
    untracked_stubs.sort();
    untracked_stubs.dedup();

    // Build the TOML string (pure helper, unit-tested).
    let config_toml_path = format!("{}/config.toml", output_dir.trim_end_matches('/'));
    let t = build_config_toml(
        &path,
        &output_dir,
        &csv_path,
        &info,
        &funcs,
        from_symbols,
        heuristic,
        sce_sdk_named,
        &untracked_stubs,
    );

    fs::write(&config_toml_path, t).map_err(|e| format!("Failed to write TOML: {}", e))?;

    Ok(ConfigResult {
        toml_path: config_toml_path,
        csv_path,
        function_count: funcs.len(),
        from_symbols,
        from_jal_heuristic: heuristic,
        sce_sdk_named,
        relocation_count: info.relocations.len(),
    })
}

/// Result of generating a ps2recomp config bundle.
#[derive(Serialize, Debug)]
struct ConfigResult {
    toml_path: String,
    csv_path: String,
    function_count: usize,
    from_symbols: usize,
    from_jal_heuristic: usize,
    /// Heuristic functions the SCE SDK matcher successfully renamed.
    sce_sdk_named: usize,
    relocation_count: usize,
}

/// Show a native folder-picker and return the chosen directory, or None if
/// the user cancelled. Used by the "Export PS2Recomp config" flow.
#[tauri::command]
fn pick_output_folder(app: tauri::AppHandle) -> Result<Option<String>, String> {
    let (tx, rx) = std::sync::mpsc::channel();
    app.dialog().file().pick_folder(move |folder| {
        tx.send(folder.map(|p| p.to_string())).ok();
    });
    match rx.recv_timeout(std::time::Duration::from_secs(120)) {
        Ok(v) => Ok(v),
        Err(_) => Err("Folder picker timed out".to_string()),
    }
}

#[tauri::command]
fn decompile_function(request: DecompileRequest) -> Result<DecompileResponse, String> {
    let output = format!(
        "; Function: {}\n; Address: 0x{}\n\n{}:\n    ; Decompiling...",
        request.function_name,
        request.address,
        request.address
    );

    Ok(DecompileResponse {
        success: true,
        output: Some(output),
        message: format!("Decompiled function '{}'", request.function_name),
    })
}

/// Parse an original Xbox XBE executable (header, certificate, sections,
/// library versions, xboxkrnl imports, XOR-decoded entry point).
#[tauri::command]
fn parse_xbe_file(path: String) -> Result<xbox::XbeFileInfo, String> {
    let data = fs::read(&path).map_err(|e| format!("Failed to read file: {}", e))?;
    let filename = Path::new(&path)
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| path.clone());
    xbox::parse_xbe(&data, &filename)
}

/// Disassemble a named section of an original Xbox XBE (32-bit x86, Intel syntax).
#[tauri::command]
fn disassemble_xbe(
    path: String,
    section_name: String,
    max_instructions: Option<usize>,
) -> Result<Vec<xbox::X86Instruction>, String> {
    let data = fs::read(&path).map_err(|e| format!("Failed to read file: {}", e))?;
    xbox::disassemble_xbe_section(&data, &section_name, max_instructions.unwrap_or(5000))
}

/// Parse an Xbox 360 XEX executable (optional headers, security info,
/// import libraries, embedded PE sections and exports when unencrypted).
#[tauri::command]
fn parse_xex_file(path: String) -> Result<xbox360::XexFileInfo, String> {
    let data = fs::read(&path).map_err(|e| format!("Failed to read file: {}", e))?;
    let filename = Path::new(&path)
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| path.clone());
    xbox360::parse_xex(&data, &filename)
}

/// Disassemble a PE section of an Xbox 360 XEX as big-endian PowerPC (Xenon).
#[tauri::command]
fn disassemble_xex(
    path: String,
    section_name: String,
    max_instructions: Option<usize>,
) -> Result<Vec<ppc_disasm::PpcInstruction>, String> {
    let data = fs::read(&path).map_err(|e| format!("Failed to read file: {}", e))?;
    xbox360::disassemble_xex_section(&data, &section_name, max_instructions.unwrap_or(5000))
}

/// Parse a Wii U RPX/RPL (Cafe ELF64 big-endian PPC64).
#[tauri::command]
fn parse_wiiu_file(path: String) -> Result<wiiu::WiiUFileInfo, String> {
    let data = fs::read(&path).map_err(|e| format!("Failed to read file: {}", e))?;
    let filename = Path::new(&path).file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_else(|| path.clone());
    wiiu::parse_rpx_rpl(&data, &filename)
}

/// Disassemble a section of a Wii U RPX/RPL as big-endian PowerPC64.
#[tauri::command]
fn disassemble_wiiu_section(
    path: String,
    section_name: String,
    max_instructions: Option<usize>,
) -> Result<Vec<ppc_disasm::PpcInstruction>, String> {
    let data = fs::read(&path).map_err(|e| format!("Failed to read file: {}", e))?;
    wiiu::disassemble_rpx_section(&data, &section_name, max_instructions.unwrap_or(5000))
}

/// Parse a PS3 executable (SELF or plain BE ELF).
#[tauri::command]
fn parse_ps3_file(path: String) -> Result<ps3::Ps3FileInfo, String> {
    let data = fs::read(&path).map_err(|e| format!("Failed to read file: {}", e))?;
    let filename = Path::new(&path).file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_else(|| path.clone());
    ps3::parse_ps3(&data, &filename)
}

/// Disassemble a section of a PS3 executable as big-endian PowerPC.
#[tauri::command]
fn disassemble_ps3_section(
    path: String,
    section_name: String,
    max_instructions: Option<usize>,
) -> Result<Vec<ppc_disasm::PpcInstruction>, String> {
    let data = fs::read(&path).map_err(|e| format!("Failed to read file: {}", e))?;
    ps3::disassemble_ps3_section(&data, &section_name, max_instructions.unwrap_or(5000))
}

/// Parse a PS4/PS5 executable (SELF or plain LE ELF64 x86-64).
#[tauri::command]
fn parse_ps4ps5_file(path: String) -> Result<ps4ps5::Ps4Ps5FileInfo, String> {
    let data = fs::read(&path).map_err(|e| format!("Failed to read file: {}", e))?;
    let filename = Path::new(&path).file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_else(|| path.clone());
    ps4ps5::parse_ps4ps5(&data, &filename)
}

/// Disassemble a section of a PS4/PS5 executable as 64-bit x86.
#[tauri::command]
fn disassemble_ps4ps5_section(
    path: String,
    section_name: String,
    max_instructions: Option<usize>,
) -> Result<Vec<ps4ps5::X64Instruction>, String> {
    let data = fs::read(&path).map_err(|e| format!("Failed to read file: {}", e))?;
    ps4ps5::disassemble_ps4ps5_section(&data, &section_name, max_instructions.unwrap_or(5000))
}

#[tauri::command]
fn get_supported_formats() -> Result<serde_json::Value, String> {
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
                "name": "PlayStation 4/5 SELF/ELF",
                "extensions": [".self", ".elf", ".bin"],
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

#[tokio::main]
async fn main() {
    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .plugin(tauri_plugin_dialog::init())
        .invoke_handler(tauri::generate_handler![
            log_message,
            open_file_dialog,
            open_multiple_files_dialog,
            open_file,
            read_raw_binary,
            identify_file,
            parse_elf_file,
            disassemble_section,
            detect_functions,
            get_call_graph,
            scan_ps1_symbols,
            analyze_ps1_binary,
            get_enhanced_call_graph,
            generate_ps1_recomp_config,
            scan_sce_symbols,
            export_functions_csv,
            export_functions_csv_dialog,
            generate_config_toml,
            pick_output_folder,
            decompile_function,
            get_supported_formats,
            identify_gb_rom,
            disassemble_gb_rom,
            parse_xbe_file,
            disassemble_xbe,
            parse_xex_file,
            disassemble_xex,
            parse_wiiu_file,
            disassemble_wiiu_section,
            parse_ps3_file,
            disassemble_ps3_section,
            parse_ps4ps5_file,
            disassemble_ps4ps5_section,
        ])
        .run(tauri::generate_context!())
        .expect("error while running Aura Decomp Tool");
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Push a little-endian u32 into a byte buffer.
    fn push_u32(buf: &mut Vec<u8>, v: u32) {
        buf.extend_from_slice(&v.to_le_bytes());
    }

    /// Build a minimal ELF32-LE-MIPS image in memory with:
    ///   - one .text section
    ///   - a .symtab (foo @ 0x100000, bar @ 0x100020) + .strtab
    ///   - a .rel.text with two entries referencing foo and bar
    /// Returns (bytes, shoff, shnum, shentsize).
    fn build_reloc_elf() -> (Vec<u8>, u32, u16, u16) {
        let mut buf: Vec<u8> = Vec::new();

        // ELF header (52 bytes), filled after layout is known.
        buf.resize(52, 0);
        buf[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
        buf[4] = 1; // ELFCLASS32
        buf[5] = 1; // ELFDATA2LSB (little-endian)
        buf[6] = 1; // EV_CURRENT
        push_u32(&mut buf, 0x100000); // e_entry (offset 24)

        // .text: 8 bytes of zeros at offset 52.
        let text_off = buf.len();
        buf.extend_from_slice(&[0u8; 8]);

        // .symtab: 3 entries x 16 bytes (null, foo, bar).
        let sym_off = buf.len();
        let sym_entsize = 16u32;
        buf.extend_from_slice(&[0u8; 16]); // null symbol
        // foo: st_name=1, value=0x100000, type FUNC
        push_u32(&mut buf, 1);              // st_name -> "foo"
        push_u32(&mut buf, 0x100000);       // st_value
        push_u32(&mut buf, 0);              // st_size
        buf.extend_from_slice(&[0x12, 0, 1, 0]); // st_info(STB_GLOBAL|STT_FUNC), other, shndx
        // bar: st_name=5, value=0x100020
        push_u32(&mut buf, 5);              // st_name -> "bar"
        push_u32(&mut buf, 0x100020);       // st_value
        push_u32(&mut buf, 0);              // st_size
        buf.extend_from_slice(&[0x12, 0, 1, 0]);
        let sym_size = buf.len() - sym_off;

        // .strtab: "\0foo\0bar\0"
        let str_off = buf.len();
        buf.extend_from_slice(b"\0foo\0bar\0");
        let str_size = buf.len() - str_off;

        // .rel.text: 2 entries x 8 bytes.
        let rel_off = buf.len();
        push_u32(&mut buf, 0);             // r_offset = 0
        push_u32(&mut buf, (1u32 << 8) | 2); // r_info: sym=1 (foo), type=2 (R_MIPS_32)
        push_u32(&mut buf, 4);             // r_offset = 4
        push_u32(&mut buf, (2u32 << 8) | 2); // r_info: sym=2 (bar), type=2
        let rel_size = buf.len() - rel_off;

        // Section headers (40 bytes each). 6 sections.
        while buf.len() % 4 != 0 {
            buf.push(0);
        }
        let shoff = buf.len() as u32;
        let shentsize = 40u16;
        let shnum = 6u16;
        buf.resize(buf.len() + shnum as usize * shentsize as usize, 0);

        let sh = |buf: &mut Vec<u8>, idx: usize, sh_type: u32, sh_addr: u32, sh_off: u32, sh_size: u32, sh_link: u32, sh_info: u32, sh_entsize: u32| {
            let b = shoff as usize + idx * shentsize as usize;
            buf[b..b + 4].copy_from_slice(&0u32.to_le_bytes()); // sh_name (unused)
            buf[b + 4..b + 8].copy_from_slice(&sh_type.to_le_bytes());
            buf[b + 12..b + 16].copy_from_slice(&sh_addr.to_le_bytes());
            buf[b + 16..b + 20].copy_from_slice(&sh_off.to_le_bytes());
            buf[b + 20..b + 24].copy_from_slice(&sh_size.to_le_bytes());
            buf[b + 24..b + 28].copy_from_slice(&sh_link.to_le_bytes());
            buf[b + 28..b + 32].copy_from_slice(&sh_info.to_le_bytes());
            buf[b + 36..b + 40].copy_from_slice(&sh_entsize.to_le_bytes());
        };
        sh(&mut buf, 0, 0, 0, 0, 0, 0, 0, 0);                 // null
        sh(&mut buf, 1, 1, 0, text_off as u32, 8, 0, 0, 0);   // .text PROGBITS, sh_addr=0
        sh(&mut buf, 2, 2, 0, sym_off as u32, sym_size as u32, 3, 0, sym_entsize); // .symtab -> strtab(3)
        sh(&mut buf, 3, 3, 0, str_off as u32, str_size as u32, 0, 0, 0);           // .strtab
        sh(&mut buf, 4, 3, 0, 0, 0, 0, 0, 0);                 // .shstrtab (dummy)
        sh(&mut buf, 5, 9, 0, rel_off as u32, rel_size as u32, 2, 1, 8);           // .rel.text -> symtab(2), applies to .text(1)

        (buf, shoff, shnum, shentsize)
    }

    #[test]
    fn relocation_parser_resolves_symbol_names() {
        let (buf, shoff, shnum, shentsize) = build_reloc_elf();
        let relocs = parse_relocations(&buf, shoff, shnum, shentsize, true /* little-endian */);
        assert_eq!(relocs.len(), 2, "expected 2 relocations");
        // .text's sh_addr is 0 in this synthetic ELF, so the normalized offset
        // (r_offset + sh_addr) equals the raw r_offset.
        assert_eq!(relocs[0].offset, 0);
        assert_eq!(relocs[0].symbol_name, "foo");
        assert_eq!(relocs[0].r_type, 2);
        assert_eq!(relocs[0].symbol, 1);
        assert_eq!(relocs[1].offset, 4);
        assert_eq!(relocs[1].symbol_name, "bar");
        assert_eq!(relocs[1].symbol, 2);
    }

    /// When the relocation's target section has a non-zero sh_addr (as on real
    /// ET_REL homebrew ELFs whose .text loads at 0x100000), `Relocation.offset`
    /// must be normalized to absolute (r_offset + sh_addr) so it matches the
    /// call graph's absolute callsite addresses.
    #[test]
    fn relocation_offset_normalized_to_absolute() {
        let (mut buf, shoff, shnum, shentsize) = build_reloc_elf();
        // Move .text's sh_addr from 0 to 0x100000 (offset 12 in section header 1).
        let text_sh = shoff as usize + 1 * shentsize as usize + 12;
        buf[text_sh..text_sh + 4].copy_from_slice(&0x100000u32.to_le_bytes());

        let relocs = parse_relocations(&buf, shoff, shnum, shentsize, true);
        assert_eq!(relocs.len(), 2);
        // Raw r_offsets (0, 4) + .text sh_addr (0x100000) = absolute.
        assert_eq!(relocs[0].offset, 0x100000, "offset not normalized by target sh_addr");
        assert_eq!(relocs[1].offset, 0x100004);
    }

    #[test]
    fn relocation_parser_handles_no_rel_sections() {
        // A buffer with section headers but no REL/RELA sections -> empty result.
        let mut buf = vec![0u8; 200];
        buf[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
        let shoff = 60u32;
        buf[32..36].copy_from_slice(&shoff.to_le_bytes());
        let shnum = 2u16;
        let shentsize = 40u16;
        buf[46..48].copy_from_slice(&shentsize.to_le_bytes());
        buf[48..50].copy_from_slice(&shnum.to_le_bytes());
        // Two PROGBITS sections (type 1), no REL.
        let relocs = parse_relocations(&buf, shoff, shnum, shentsize, true);
        assert!(relocs.is_empty(), "no relocations expected");
    }

    #[test]
    fn detect_functions_finds_jal_targets() {
        // Two JAL instructions at 0x100000 and 0x100008, targeting 0x100100 and 0x100200.
        let mut text: Vec<u8> = Vec::new();
        // JAL target: op=0x03 (000011), target_field = (target & 0x0FFFFFFF) >> 2
        let jal = |target: u32| -> u32 { (0x03u32 << 26) | ((target >> 2) & 0x03FFFFFF) };
        push_u32(&mut text, jal(0x100100)); // 0x100000
        push_u32(&mut text, 0);             // 0x100004 (delay slot)
        push_u32(&mut text, jal(0x100200)); // 0x100008
        push_u32(&mut text, 0);             // delay slot
        // Pad so the JAL targets (0x100100, 0x100200) fall inside the section;
        // the scanner only accepts targets within the section's range.
        text.resize(0x100300 - 0x100000, 0);
        let section = ElfSection {
            name: ".text".into(),
            address: 0x100000,
            size: text.len() as u32,
            offset: 0,
            data: text,
            flags: 0x4, // SHF_EXECINSTR
        };
        let funcs = detect_functions_in_sections(&[section], 0x100000, true);
        // Entry (0x100000) + two JAL targets (0x100100, 0x100200).
        let starts: Vec<u32> = funcs.iter().map(|f| f.start).collect();
        assert!(starts.contains(&0x100100), "missing JAL target 0x100100");
        assert!(starts.contains(&0x100200), "missing JAL target 0x100200");
    }

    #[test]
    fn config_toml_has_required_ps2recomp_fields() {
        // The TOML must be parseable by ps2recomp's ConfigManager::loadConfig,
        // which requires: [general] input, output, and tolerates ghidra_output.
        // We validate the key fields are present and well-formed (no need for a
        // full TOML parser here; structure + spot-values suffice).
        let info = ElfFileInfo {
            filename: "test.elf".into(),
            sections: vec![],
            symbols: vec![],
            entry_point: 0x100000,
            file_size: 0,
            is_little_endian: true,
            is_32bit: true,
            relocations: vec![],
        };
        let funcs = vec![FunctionEntry {
            name: "sub_00100000".into(),
            start: 0x100000,
            end: 0x100100,
            size: 0x100,
        }];
        let toml = build_config_toml(
            "G:/games/test.elf",
            "G:/out",
            "G:/out/functions.csv",
            &info,
            &funcs,
            0,
            1,
            0,
            &[], // no SCE matches -> untracked_stubs stays empty
        );
        // Required by ConfigManager::loadConfig
        assert!(toml.contains("[general]"), "missing [general] table");
        assert!(toml.contains("input = \"G:/games/test.elf\""), "bad input path");
        assert!(toml.contains("output = \"G:/out\""), "bad output path");
        assert!(toml.contains("ghidra_output = \"G:/out/functions.csv\""), "bad ghidra_output");
        // Booleans must be valid TOML (lowercase).
        assert!(toml.contains("single_file_output = false"));
        assert!(toml.contains("patch_cop0 = true"));
        // Empty arrays must be valid.
        assert!(toml.contains("stubs = []"));
        assert!(toml.contains("untracked_stubs = []"));
        assert!(toml.contains("skip = []"));
        // Windows backslashes must be normalized (would break TOML escaping).
        assert!(!toml.contains("input = \"G:\\\\"), "backslashes not normalized");
    }

    #[test]
    fn csv_format_matches_ps2recomp() {
        // The CSV writer must emit exactly: Name,Start,End,Size with 0x%08X
        // addresses (uppercase) and decimal size — matching ExportPS2Functions.java.
        let funcs = vec![
            FunctionEntry { name: "foo".into(), start: 0x100000, end: 0x100100, size: 0x100 },
            FunctionEntry { name: "bar".into(), start: 0x100100, end: 0x100120, size: 0x20 },
        ];
        let mut csv = String::from("Name,Start,End,Size\n");
        for f in &funcs {
            csv.push_str(&format!("{},0x{:08X},0x{:08X},{}\n", f.name, f.start, f.end, f.size));
        }
        assert_eq!(csv.lines().next().unwrap(), "Name,Start,End,Size");
        assert_eq!(csv.lines().nth(1).unwrap(), "foo,0x00100000,0x00100100,256");
        assert_eq!(csv.lines().nth(2).unwrap(), "bar,0x00100100,0x00100120,32");
    }

    /// `has_delay_slot` must match exactly the DELAY_SLOT_MNEMONICS table: the
    /// control-flow instructions whose next word is a branch delay slot.
    #[test]
    fn has_delay_slot_matches_reference_set() {
        // Build a single instruction word from its fields.
        let r_type = |funct: u32| funct; // op 0x00
        let i_type = |op: u32, rs: u32, rt: u32, imm: u32| (op << 26) | (rs << 21) | (rt << 16) | (imm & 0xFFFF);

        // --- true: instructions that have a delay slot ---
        // J / JAL
        assert!(has_delay_slot(i_type(0x02, 0, 0, 0)));
        assert!(has_delay_slot(i_type(0x03, 0, 0, 0)));
        // JR $ra (funct 0x08), JALR (funct 0x09)
        assert!(has_delay_slot(r_type(0x08)));
        assert!(has_delay_slot(r_type(0x09)));
        // BEQ / BNE / BLEZ / BGTZ
        assert!(has_delay_slot(i_type(0x04, 0, 0, 0)));
        assert!(has_delay_slot(i_type(0x05, 0, 0, 0)));
        assert!(has_delay_slot(i_type(0x06, 0, 0, 0)));
        assert!(has_delay_slot(i_type(0x07, 0, 0, 0)));
        // REGIMM BLTZ / BGEZ (op 0x01, rt 0x00 / 0x01)
        assert!(has_delay_slot(i_type(0x01, 0, 0x00, 0)));
        assert!(has_delay_slot(i_type(0x01, 0, 0x01, 0)));
        // BEQL / BNEL
        assert!(has_delay_slot(i_type(0x14, 0, 0, 0)));
        assert!(has_delay_slot(i_type(0x15, 0, 0, 0)));

        // --- false: non-delay-slot instructions ---
        // nop (0x00000000): op 0, funct 0 (SLL) — explicitly NOT a delay slot.
        assert!(!has_delay_slot(0x00000000));
        // ADDU (funct 0x21), SLL (funct 0x00 with shift)
        assert!(!has_delay_slot(r_type(0x21)));
        // LUI (op 0x0F), LW (op 0x23), ADDIU (op 0x09), ORI (op 0x0D)
        assert!(!has_delay_slot(i_type(0x0F, 0, 0, 0)));
        assert!(!has_delay_slot(i_type(0x23, 0, 0, 0)));
        assert!(!has_delay_slot(i_type(0x09, 0, 0, 0)));
        assert!(!has_delay_slot(i_type(0x0D, 0, 0, 0)));
    }

    /// `refine_end` trims trailing nop padding while preserving the delay slot
    /// of the final control-flow instruction. End is exclusive.
    #[test]
    fn refine_end_trims_padding_and_keeps_delay_slot() {
        // Helper: build a little-endian code buffer from a list of u32 words.
        let push = |buf: &mut Vec<u8>, v: u32| buf.extend_from_slice(&v.to_le_bytes());
        // jr $ra  = SPECIAL funct 0x08, rs = $ra (31)  -> 0x03E00008.
        const JR_RA: u32 = 0x03E00008;

        // ---- Case 1: jr $ra; nop(delay); nop; nop  (base 0x100000, start 0x100000)
        //    Expected End = jr_addr + 8 = 0x100008 (the 3 padding nops drop off,
        //    the delay-slot nop is protected).
        {
            let mut b = Vec::new();
            push(&mut b, JR_RA);            // 0x100000: jr $ra
            push(&mut b, 0x00000000);        // 0x100004: nop (delay slot)
            push(&mut b, 0x00000000);        // 0x100008: nop (padding)
            push(&mut b, 0x00000000);        // 0x10000C: nop (padding)
            let end = refine_end(&b, 0x100000, 0x100000, 0x100010, true);
            assert_eq!(end, 0x100008, "case 1: jr+8");
        }

        // ---- Case 2: jr $ra; move v0,0 (delay); nop; nop
        //    Expected End = 0x100008 (delay slot is a non-nop, still protected).
        {
            let mut b = Vec::new();
            // OR $v0, $zero, $zero (a stand-in for `move`) — SPECIAL funct 0x25.
            let move_v0_zero: u32 = 0x21; // any non-zero, non-control-flow word
            push(&mut b, JR_RA);            // 0x100000: jr $ra
            push(&mut b, move_v0_zero);     // 0x100004: delay slot (non-nop)
            push(&mut b, 0x00000000);        // 0x100008: padding
            push(&mut b, 0x00000000);        // 0x10000C: padding
            let end = refine_end(&b, 0x100000, 0x100000, 0x100010, true);
            assert_eq!(end, 0x100008, "case 2: jr+8 with non-nop delay slot");
        }

        // ---- Case 3: tail-call function ending in `j X; nop(delay); nop`
        //    Expected End = 0x100008 (j's delay slot is protected).
        {
            let mut b = Vec::new();
            // j 0x200000  = op 0x02, field = 0x200000 >> 2 = 0x80000  -> 0x08080000.
            const J_200000: u32 = 0x08080000;
            push(&mut b, J_200000);         // 0x100000: j 0x200000
            push(&mut b, 0x00000000);        // 0x100004: delay slot
            push(&mut b, 0x00000000);        // 0x100008: padding
            let end = refine_end(&b, 0x100000, 0x100000, 0x10000C, true);
            assert_eq!(end, 0x100008, "case 3: j+8");
        }

        // ---- Case 4: filler code + trailing nops, no control-flow end.
        //    nop padding after real code trims down to the last real word + 4.
        {
            let mut b = Vec::new();
            push(&mut b, 0x00000021);       // 0x100000: ADDU (real)
            push(&mut b, 0x00000020);       // 0x100004: ADD  (real, last)
            push(&mut b, 0x00000000);        // 0x100008: nop (padding)
            push(&mut b, 0x00000000);        // 0x10000C: nop (padding)
            let end = refine_end(&b, 0x100000, 0x100000, 0x100010, true);
            assert_eq!(end, 0x100008, "case 4: trim to last real word + 4");
        }

        // ---- Case 5: safety net — all-nop body never collapses below start+4.
        {
            let mut b = Vec::new();
            push(&mut b, 0x00000000);
            push(&mut b, 0x00000000);
            push(&mut b, 0x00000000);
            let end = refine_end(&b, 0x100000, 0x100000, 0x10000C, true);
            // Can't trim below start + 4 (need ≥2 words to even consider).
            assert!(end >= 0x100004, "case 5: kept at least one instruction");
        }
    }

    /// End-to-end: two JAL-targeted functions with nop padding between them get
    /// the first function's End tightened to `jr $ra + 8` instead of the next
    /// function's start.
    #[test]
    fn refine_function_boundaries_shortens_end() {
        // Layout (base 0x100000):
        //   0x100000: func A body — jr $ra
        //   0x100004:   nop (delay slot)
        //   0x100008:   nop (padding)
        //   0x10000C:   nop (padding)
        //   0x100010: func B start (a JAL target) — jr $ra
        //   0x100014:   nop (delay slot)
        let mut text: Vec<u8> = Vec::new();
        let push = |buf: &mut Vec<u8>, v: u32| buf.extend_from_slice(&v.to_le_bytes());
        const JR_RA: u32 = 0x03E00008; // SPECIAL funct 0x08, rs = $ra
        push(&mut text, JR_RA);        // 0x100000
        push(&mut text, 0x00000000);    // 0x100004 delay
        push(&mut text, 0x00000000);    // 0x100008 padding
        push(&mut text, 0x00000000);    // 0x10000C padding
        push(&mut text, JR_RA);        // 0x100010 (func B)
        push(&mut text, 0x00000000);    // 0x100014 delay

        let section = ElfSection {
            name: ".text".into(),
            address: 0x100000,
            size: text.len() as u32,
            offset: 0,
            data: text,
            flags: 0x4, // SHF_EXECINSTR
        };

        // Simulate JAL-scan output: func A spans [0x100000, 0x100010) (to next
        // start), func B spans [0x100010, end_of_section).
        let mut funcs = vec![
            FunctionEntry { name: "sub_00100000".into(), start: 0x100000, end: 0x100010, size: 0x10 },
            FunctionEntry { name: "sub_00100010".into(), start: 0x100010, end: 0x100018, size: 0x08 },
        ];

        refine_function_boundaries(&[section], &mut funcs, true);

        // Func A: jr at 0x100000 + delay slot -> End 0x100008 (not 0x100010).
        assert_eq!(funcs[0].end, 0x100008, "func A End should be jr+8, not next start");
        assert_eq!(funcs[0].size, 0x8);
        // Func B: jr at 0x100010 + delay slot -> End 0x100018 (unchanged, its
        // body was already exactly jr+delay).
        assert_eq!(funcs[1].end, 0x100018, "func B End unchanged");
    }

    /// `untracked_stubs` is emitted as a TOML array of basic strings when
    /// populated, and stays a single-line `[]` when empty. Confirms escaping
    /// of quotes/backslashes keeps the TOML valid.
    #[test]
    fn untracked_stubs_array_round_trips_through_toml_parser() {
        let info = ElfFileInfo {
            filename: "t.elf".into(),
            sections: vec![],
            symbols: vec![],
            entry_point: 0x100000,
            file_size: 0,
            is_little_endian: true,
            is_32bit: true,
            relocations: vec![],
        };
        // A name with a quote and one with a backslash — both must survive.
        let untracked = vec!["printf".to_string(), "weird\"name".to_string(), "path\\bit".to_string()];
        let toml_str = build_config_toml(
            "G:/t.elf", "G:/out", "G:/out/functions.csv",
            &info, &[], 0, 0, 0, &untracked,
        );
        // Must parse with a real TOML parser.
        let parsed: toml::Value = toml::from_str(&toml_str).expect("TOML must parse");
        let arr = parsed
            .get("general")
            .and_then(|g| g.get("untracked_stubs"))
            .and_then(|v| v.as_array())
            .expect("untracked_stubs must be an array");
        assert_eq!(arr.len(), 3, "all three names preserved");
        let names: Vec<String> = arr.iter().map(|v| v.as_str().unwrap().to_string()).collect();
        assert!(names.contains(&"printf".to_string()));
        assert!(names.contains(&"weird\"name".to_string()), "quote not escaped/preserved");
        assert!(names.contains(&"path\\bit".to_string()), "backslash not escaped/preserved");
        // stubs and skip must still be empty (never auto-populated).
        let general = parsed.get("general").and_then(|v| v.as_table()).unwrap();
        assert!(general.get("stubs").and_then(|v| v.as_array()).map(|a| a.is_empty()).unwrap_or(false));
        assert!(general.get("skip").and_then(|v| v.as_array()).map(|a| a.is_empty()).unwrap_or(false));
    }

    /// `collect_call_edges` records every JAL (op 0x03) and J (op 0x02) with
    /// the correct callsite/target/kind, and only for targets that land in an
    /// executable section.
    #[test]
    fn collect_call_edges_finds_jal_and_j() {
        // Section layout (base 0x100000):
        //   0x100000: jal 0x100200   (op 0x03)
        //   0x100004: nop            (delay slot)
        //   0x100008: j   0x100300   (op 0x02)
        //   0x10000C: nop
        //   ...padding to cover targets...
        let jal = |target: u32| -> u32 { (0x03u32 << 26) | ((target >> 2) & 0x03FFFFFF) };
        let j = |target: u32| -> u32 { (0x02u32 << 26) | ((target >> 2) & 0x03FFFFFF) };
        let mut text: Vec<u8> = Vec::new();
        push_u32(&mut text, jal(0x100200)); // 0x100000
        push_u32(&mut text, 0);             // 0x100004
        push_u32(&mut text, j(0x100300));   // 0x100008
        push_u32(&mut text, 0);             // 0x10000C
        text.resize(0x100400 - 0x100000, 0); // pad so targets are in-range
        let section = ElfSection {
            name: ".text".into(),
            address: 0x100000,
            size: text.len() as u32,
            offset: 0,
            data: text,
            flags: 0x4,
        };

        let edges = collect_call_edges(&[section], true);
        // Two edges: the JAL and the J.
        assert_eq!(edges.len(), 2, "expected 2 raw edges, got {}", edges.len());
        assert_eq!(edges[0], RawCallEdge { callsite: 0x100000, target: 0x100200, kind: CallKind::Jal });
        assert_eq!(edges[1], RawCallEdge { callsite: 0x100008, target: 0x100300, kind: CallKind::Jump });
    }

    /// `build_call_graph` attributes callsites to functions, drops intra-function
    /// tail jumps (but keeps JAL self-recursion), and routes undetected targets
    /// into `external_targets`.
    #[test]
    fn build_call_graph_attributes_and_filters() {
        // Two functions: A = [0x100000, 0x100010), B = [0x100010, 0x100020).
        // Edges (raw):
        //   1) callsite 0x100000 (in A), JAL -> 0x100010 (B's start)     [keep]
        //   2) callsite 0x100004 (in A), J   -> 0x100000 (A's start)     [drop: intra-function jump]
        //   3) callsite 0x100010 (in B), JAL -> 0x100050 (undetected)    [keep + external]
        let funcs = vec![
            FunctionEntry { name: "A".into(), start: 0x100000, end: 0x100010, size: 0x10 },
            FunctionEntry { name: "B".into(), start: 0x100010, end: 0x100020, size: 0x10 },
        ];
        let raw = vec![
            RawCallEdge { callsite: 0x100000, target: 0x100010, kind: CallKind::Jal },
            RawCallEdge { callsite: 0x100004, target: 0x100000, kind: CallKind::Jump },
            RawCallEdge { callsite: 0x100010, target: 0x100050, kind: CallKind::Jal },
        ];
        let g = build_call_graph(raw, &funcs);

        // Edge 2 (intra-function J inside A) is dropped; edges 1 and 3 remain.
        assert_eq!(g.edges.len(), 2, "expected 2 edges after filtering, got {}", g.edges.len());
        // A -> B (the JAL from A).
        assert!(g.edges.iter().any(|e| e.from == 0x100000 && e.to == 0x100010 && e.kind == CallKind::Jal),
            "missing A->B JAL edge");
        // B -> external 0x100050 (kept, since it's a real call to undetected code).
        assert!(g.edges.iter().any(|e| e.from == 0x100010 && e.to == 0x100050),
            "missing B->external JAL edge");
        // The undetected target is reported as external.
        assert_eq!(g.external_targets, vec![0x100050], "external_targets wrong: {:?}", g.external_targets);
    }

    /// A JAL to a function's own start is legitimate self-recursion and must
    /// NOT be dropped (only intra-function `j` is dropped, never `jal`).
    #[test]
    fn call_graph_handles_self_recursion() {
        let funcs = vec![
            FunctionEntry { name: "rec".into(), start: 0x100000, end: 0x100020, size: 0x20 },
        ];
        let raw = vec![
            // Self-call via JAL.
            RawCallEdge { callsite: 0x100008, target: 0x100000, kind: CallKind::Jal },
            // Self-loop via J (this one IS an intra-function jump -> dropped).
            RawCallEdge { callsite: 0x10000C, target: 0x100000, kind: CallKind::Jump },
        ];
        let g = build_call_graph(raw, &funcs);
        // JAL self-edge kept, J self-edge dropped.
        assert_eq!(g.edges.len(), 1, "expected 1 edge (jal kept, j dropped), got {}", g.edges.len());
        assert_eq!(g.edges[0].from, 0x100000);
        assert_eq!(g.edges[0].to, 0x100000);
        assert_eq!(g.edges[0].kind, CallKind::Jal);
        // rec's own start IS a function start, so it's not external.
        assert!(g.external_targets.is_empty());
    }

    /// `enrich_call_graph_with_relocs` resolves JAL targets to imported symbol
    /// names via R_MIPS_26 relocations at the matching callsite address. Non-JAL
    /// relocs and non-JAL edges are ignored; retail binaries (no relocs) no-op.
    #[test]
    fn call_graph_resolves_import_names() {
        // caller A [0x100000,0x100010) JALs two imported stubs.
        let funcs = vec![
            FunctionEntry { name: "A".into(), start: 0x100000, end: 0x100010, size: 0x10 },
        ];
        let raw = vec![
            // Two JALs from A to external (undetected) stubs at 0x200000 / 0x200004.
            RawCallEdge { callsite: 0x100000, target: 0x200000, kind: CallKind::Jal },
            RawCallEdge { callsite: 0x100004, target: 0x200004, kind: CallKind::Jal },
        ];
        let graph = build_call_graph(raw, &funcs);

        // R_MIPS_26 (= 4) relocations at the two callsites name the imports.
        let relocs = vec![
            Relocation { offset: 0x100000, symbol_name: "printf".into(),  r_type: R_MIPS_26, symbol: 1 },
            Relocation { offset: 0x100004, symbol_name: "malloc".into(),  r_type: R_MIPS_26, symbol: 2 },
            // A non-call reloc (R_MIPS_32 = 2) and a different offset must NOT match.
            Relocation { offset: 0x100000, symbol_name: "ignored".into(), r_type: 2,         symbol: 9 },
        ];
        let enriched = enrich_call_graph_with_relocs(graph, &relocs);

        // Both external targets resolved, sorted by address.
        assert_eq!(enriched.target_names.len(), 2, "expected 2 resolved names");
        assert_eq!(enriched.target_names[0], (0x200000, "printf".to_string()));
        assert_eq!(enriched.target_names[1], (0x200004, "malloc".to_string()));
    }

    /// With no relocations (stripped retail binaries), enrichment is a no-op
    /// and `target_names` stays empty.
    #[test]
    fn enrich_call_graph_noop_without_relocations() {
        let funcs = vec![
            FunctionEntry { name: "A".into(), start: 0x100000, end: 0x100010, size: 0x10 },
        ];
        let raw = vec![
            RawCallEdge { callsite: 0x100000, target: 0x200000, kind: CallKind::Jal },
        ];
        let graph = build_call_graph(raw, &funcs);
        let enriched = enrich_call_graph_with_relocs(graph, &[]);
        assert!(enriched.target_names.is_empty(), "no relocs -> no target names");
    }

    /// End-to-end against a real PS2 retail ELF (Midnight Club 3 Remix).
    /// Skips if the file isn't on disk so the test suite stays portable.
    /// Validates: full ELF parse + JAL function detection + the generated TOML
    /// parses with a real TOML parser and has the fields ps2recomp requires.
    #[test]
    fn mc3r_full_pipeline_and_toml_parses() {
        let path = r"G:\Recomps\MC3R\NTGUIDVD.ELF";
        if !std::path::Path::new(path).exists() {
            eprintln!("skipping: MC3R not present at {}", path);
            return;
        }
        // Full parse. parse_elf_file captures only SHT_PROGBITS sections that
        // carry loadable data (NOBITS sections like .bss/.sbss have no file
        // content and are intentionally excluded). MC3R's ELF header has 15
        // section entries; 9 are PROGBITS-with-data.
        let info = parse_elf_file(path.to_string()).expect("parse_elf_file");
        assert!(info.sections.len() >= 9, "expected >=9 PROGBITS sections, got {}", info.sections.len());
        assert!(info.sections.iter().any(|s| s.name == ".text"), "missing .text section");
        assert_eq!(info.entry_point, 0x001056A8, "entry point mismatch");
        assert_eq!(info.is_little_endian, true, "MC3R is little-endian");
        assert!(info.relocations.is_empty(), "MC3R has no dynamic relocations");

        // Function detection (JAL scan — binary is stripped).
        let funcs = detect_functions(path.to_string()).expect("detect_functions");
        assert!(funcs.len() > 2000, "expected >2000 functions, got {}", funcs.len());
        assert!(funcs.len() < 3000, "function count suspiciously high: {}", funcs.len());

        // SCE SDK matcher diagnostic: how many sections are code, how many
        // raw matches come back, and how many functions got renamed.
        const SHF_EXECINSTR: u32 = 0x4;
        let code_secs: Vec<&ElfSection> = info.sections.iter()
            .filter(|s| (s.flags & SHF_EXECINSTR) != 0)
            .collect();
        let raw_matches = scan_sce_sdk_matches(&info.sections);
        let renamed = funcs.iter().filter(|f| !f.name.starts_with("sub_")).count();
        eprintln!(
            "MC3R SCE: {} code sections (flags 0x4), {} raw SDK matches, {} renamed functions",
            code_secs.len(),
            raw_matches.len(),
            renamed,
        );
        // Sample first few raw matches for sanity.
        for m in raw_matches.iter().take(5) {
            eprintln!("  {:08X} {} ({} bytes, {})", m.address, m.name, m.size, m.library);
        }

        // Generate the TOML and prove it parses with a real TOML parser.
        let from_symbols = info.symbols.iter().filter(|s| s.size > 0).count();
        let heuristic = funcs.len().saturating_sub(from_symbols);
        let sce_named = funcs.iter().filter(|f| !f.name.starts_with("sub_")).count();
        // Sorted + deduped SDK-matched names feed the informational
        // untracked_stubs array (ps2recomp ignores it).
        let mut untracked: Vec<String> = funcs
            .iter()
            .filter_map(|f| {
                if f.name.starts_with("sub_") { None } else { Some(f.name.clone()) }
            })
            .collect();
        untracked.sort();
        untracked.dedup();
        let toml_str = build_config_toml(
            path, "G:/out", "G:/out/functions.csv",
            &info, &funcs, from_symbols, heuristic, sce_named, &untracked,
        );
        let parsed: toml::Value = toml::from_str(&toml_str).expect("TOML must parse");
        let general = parsed.get("general").and_then(|v| v.as_table()).expect("[general]");
        // Fields ps2recomp's ConfigManager::loadConfig reads:
        assert!(general.contains_key("input"), "missing input");
        assert!(general.contains_key("output"), "missing output");
        assert!(general.contains_key("ghidra_output"), "missing ghidra_output");
        assert_eq!(general.get("single_file_output").and_then(|v| v.as_bool()), Some(false));
        assert_eq!(general.get("patch_cop0").and_then(|v| v.as_bool()), Some(true));
        // stubs/skip must be arrays.
        assert!(general.get("stubs").map(|v| v.is_array()).unwrap_or(false));
        assert!(general.get("skip").map(|v| v.is_array()).unwrap_or(false));
        // untracked_stubs is an array and carries exactly the deduped SDK names.
        let untracked_arr = general
            .get("untracked_stubs")
            .and_then(|v| v.as_array())
            .expect("untracked_stubs must be a TOML array");
        assert_eq!(untracked_arr.len(), untracked.len(),
            "untracked_stubs length {} != deduped count {}", untracked_arr.len(), untracked.len());
        // The [ghidra_export] table carries the SCE SDK naming breakdown.
        let ghidra = parsed.get("ghidra_export").and_then(|v| v.as_table()).expect("[ghidra_export]");
        assert_eq!(
            ghidra.get("sce_sdk_named").and_then(|v| v.as_integer()),
            Some(sce_named as i64),
            "sce_sdk_named field missing or wrong"
        );
        // MC3R is stripped retail — the SCE matcher must rename a meaningful
        // chunk of the detected functions (it ships a lot of libc/libccc/etc).
        assert!(sce_named > 100, "expected >100 SCE-named functions, got {}", sce_named);
        eprintln!(
            "MC3R: {} functions ({} heuristic, {} SCE SDK-named), TOML OK",
            funcs.len(), heuristic, sce_named
        );

        // ---- Call graph sanity (direct JAL + tail-call J) -----------------
        let raw_edges = collect_call_edges(&info.sections, info.is_little_endian);
        let graph = enrich_call_graph_with_relocs(
            build_call_graph(raw_edges, &funcs),
            &info.relocations,
        );
        // A real retail EE binary must have thousands of direct calls.
        assert!(graph.edges.len() > 1000, "expected >1000 call edges, got {}", graph.edges.len());
        // The entry point is a root: no detected function calls into it.
        let entry_callers = graph.edges.iter().filter(|e| e.to == info.entry_point).count();
        assert_eq!(entry_callers, 0, "entry point 0x{:08X} has {} callers (should be a root)",
            info.entry_point, entry_callers);
        // Unreachable functions (no callers, not the entry) are a strong signal
        // for stubs / interrupt handlers / dead code. MC3R has plenty.
        let called: std::collections::HashSet<u32> = graph.edges.iter().map(|e| e.to).collect();
        let unreachable = funcs.iter().filter(|f| !called.contains(&f.start) && f.start != info.entry_point).count();
        // MC3R has no dynamic relocations, so import-name enrichment is a no-op.
        assert!(graph.target_names.is_empty(),
            "MC3R has no relocations; expected empty target_names, got {}", graph.target_names.len());
        eprintln!(
            "MC3R call graph: {} edges, {} external targets, {} unreachable functions (of {} total)",
            graph.edges.len(), graph.external_targets.len(), unreachable, funcs.len()
        );
        assert!(unreachable > 50, "expected >50 unreachable functions, got {}", unreachable);
    }
}
