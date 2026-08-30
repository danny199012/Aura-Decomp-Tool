//! PlayStation 4 & PlayStation 5 support: little-endian ELF64 x86-64 homebrew
//! executables and SELF wrapper parsing. Disassembly via iced-x86 at 64-bit.
//!
//! Retail PS4/PS5 SELFs are key-gated; they degrade gracefully with an error.

use serde::{Deserialize, Serialize};

/// Quick check for PS4/PS5 SELF magic. PS4/PS5 SELF uses the same "SCE\0"
/// magic as PS3, but the embedded ELF is little-endian x86-64.
pub fn is_self(data: &[u8]) -> bool {
    data.len() >= 4 && &data[0..3] == b"SCE" && data[3] == 0
}

/// Quick check for a little-endian ELF64 with e_machine == EM_X86_64 (62).
pub fn is_ps4ps5_elf(data: &[u8]) -> bool {
    data.len() >= 20 && &data[0..4] == [0x7f, b'E', b'L', b'F']
        && data[4] == 2 && data[5] == 1  // 64-bit, little-endian
        && u16::from_le_bytes([data[18], data[19]]) == 62  // EM_X86_64
}

#[inline] fn ru16le(d:&[u8],o:usize)->u16{ if o+2>d.len(){0}else{u16::from_le_bytes([d[o],d[o+1]])} }
#[inline] fn ru32le(d:&[u8],o:usize)->u32{ if o+4>d.len(){0}else{u32::from_le_bytes([d[o],d[o+1],d[o+2],d[o+3]])} }
#[inline] fn ru64le(d:&[u8],o:usize)->u64{ if o+8>d.len(){0}else{u64::from_le_bytes([d[o],d[o+1],d[o+2],d[o+3],d[o+4],d[o+5],d[o+6],d[o+7]])} }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ps4Ps5Section { pub name: String, pub sh_addr: u64, pub sh_offset: u64, pub sh_size: u64, pub is_code: bool }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ps4Ps5FileInfo {
    pub filename: String,
    pub file_type: String,
    pub entry_point: u64,
    pub machine: u16,
    pub sections: Vec<Ps4Ps5Section>,
    pub has_orbis_note: bool,
    pub encrypted: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct X64Instruction {
    pub address: u64,
    pub bytes: Vec<u8>,
    pub text: String,
    pub size: usize,
}

/// Parse a PS4/PS5 executable (SELF or plain LE ELF64 x86-64).
pub fn parse_ps4ps5(data: &[u8], filename: &str) -> Result<Ps4Ps5FileInfo, String> {
    if is_self(data) {
        return parse_self(data, filename);
    }
    if is_ps4ps5_elf(data) {
        return parse_elf(data, filename);
    }
    Err("Not a PS4/PS5 executable (expected SELF or LE ELF64 x86-64)".into())
}

fn parse_self(data: &[u8], filename: &str) -> Result<Ps4Ps5FileInfo, String> {
    let elf_off = data.windows(4).enumerate().skip(4)
        .find(|(_, w)| *w == [0x7f, b'E', b'L', b'F'])
        .map(|(i, _)| i)
        .ok_or_else(|| "SELF: could not locate embedded ELF (may be encrypted)".to_string())?;
    if !is_ps4ps5_elf(&data[elf_off..]) {
        return Err("SELF: embedded ELF is not LE x86-64 (may be encrypted)".into());
    }
    let mut info = parse_elf(&data[elf_off..], filename)?;
    info.file_type = "SELF (unencrypted)".into();
    Ok(info)
}

fn parse_elf(data: &[u8], filename: &str) -> Result<Ps4Ps5FileInfo, String> {
    if data.len() < 64 { return Err("File too small for ELF64 header".into()); }
    let machine = ru16le(data, 18);
    let entry = ru64le(data, 24);
    let shoff = ru64le(data, 40);
    let shentsize = ru16le(data, 58);
    let shnum = ru16le(data, 60);
    let shstrndx = ru16le(data, 62);

    // Check for ORBIS ELF note (PT_NOTE with note name "ORBIS").
    let has_orbis_note = check_orbis_note(data);

    let mut sections = Vec::new();
    let mut shstrtab_off = 0u64;
    if shoff > 0 && shentsize >= 64 {
        if shstrndx < shnum {
            let so = shoff as usize + (shstrndx as usize) * shentsize as usize;
            if so + 64 <= data.len() { shstrtab_off = ru64le(data, so + 24); }
        }
        for i in 0..shnum.min(1024) {
            let off = shoff as usize + (i as usize) * shentsize as usize;
            if off + 64 > data.len() { break; }
            let name_off = ru32le(data, off) as usize;
            let sh_flags = ru64le(data, off + 8);
            let sh_addr = ru64le(data, off + 16);
            let sh_offset = ru64le(data, off + 24);
            let sh_size = ru64le(data, off + 32);
            let name = if shstrtab_off > 0 && (shstrtab_off as usize + name_off) < data.len() {
                let s = shstrtab_off as usize + name_off;
                let e = data[s..].iter().position(|&b| b==0).map(|n|s+n).unwrap_or(data.len().min(s+64));
                String::from_utf8_lossy(&data[s..e]).to_string()
            } else { format!("sec{}", i) };
            sections.push(Ps4Ps5Section{ name, sh_addr, sh_offset, sh_size, is_code:(sh_flags&0x4)!=0 });
        }
    }

    Ok(Ps4Ps5FileInfo{ filename:filename.into(), file_type:"ELF64-LE x86-64".into(), entry_point:entry, machine, sections, has_orbis_note, encrypted:false })
}

fn check_orbis_note(data: &[u8]) -> bool {
    // Scan for the string "ORBIS" in the file (appears in PT_NOTE entries
    // for PS4 ELF files).
    data.windows(5).any(|w| w == b"ORBIS")
}

/// Disassemble a section of a PS4/PS5 ELF as 64-bit x86 (Intel syntax).
pub fn disassemble_ps4ps5_section(data: &[u8], section_name: &str, max_instructions: usize) -> Result<Vec<X64Instruction>, String> {
    let info = parse_ps4ps5(data, "ps4ps5")?;
    if info.encrypted { return Err("PS4/PS5 SELF is encrypted — disassembly not possible".into()); }
    let section = info.sections.iter().find(|s|s.name==section_name).ok_or_else(||format!("Section '{}' not found",section_name))?.clone();
    let start = section.sh_offset as usize;
    let end = (start+section.sh_size as usize).min(data.len());
    if start>=data.len() { return Err("Section raw data outside file".into()); }
    let code = &data[start..end];
    Ok(disassemble_x64(code, section.sh_addr, max_instructions))
}

/// Disassemble raw bytes as 64-bit x86 instructions (Intel syntax) using iced-x86.
pub fn disassemble_x64(data: &[u8], display_address: u64, max_instructions: usize) -> Vec<X64Instruction> {
    use iced_x86::{Decoder, DecoderOptions, Formatter, IntelFormatter};
    let mut out = Vec::new();
    let mut decoder = Decoder::with_ip(64, data, display_address, DecoderOptions::NONE);
    let mut formatter = IntelFormatter::new();
    let mut text = String::new();
    for instruction in &mut decoder {
        if out.len() >= max_instructions { break; }
        text.clear();
        formatter.format(&instruction, &mut text);
        let s = (instruction.ip() - display_address) as usize;
        let e = s + instruction.len();
        let bytes = if e <= data.len() { data[s..e].to_vec() } else { Vec::new() };
        out.push(X64Instruction{ address: instruction.ip(), bytes, text: text.clone(), size: instruction.len() });
    }
    out
}
