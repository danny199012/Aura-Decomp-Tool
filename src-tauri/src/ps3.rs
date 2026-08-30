//! PlayStation 3 support: plain BE ELF (PPC64 homebrew) and SELF wrapper
//! parsing. Disassembly via the shared big-endian PPC decoder.
//!
//! SPU/SPE disassembly is OUT OF SCOPE (different ISA). Encrypted retail
//! SELFs degrade gracefully with an explanatory error.

use crate::ppc_disasm::{disassemble_ppc_at, PpcEndian, PpcInstruction};
use serde::{Deserialize, Serialize};

/// Quick check for SELF magic ("SCE\0" at offset 0).
pub fn is_self(data: &[u8]) -> bool {
    data.len() >= 4 && &data[0..3] == b"SCE" && data[3] == 0
}

/// Quick check for a big-endian ELF (PS3 homebrew or embedded in SELF).
fn is_be_elf(data: &[u8], min_class: u8) -> bool {
    data.len() >= 20 && &data[0..4] == [0x7f, b'E', b'L', b'F'] && data[4] >= min_class && data[5] == 2
}

#[inline] fn ru16be(d:&[u8],o:usize)->u16{ if o+2>d.len(){0}else{u16::from_be_bytes([d[o],d[o+1]])} }
#[inline] fn ru32be(d:&[u8],o:usize)->u32{ if o+4>d.len(){0}else{u32::from_be_bytes([d[o],d[o+1],d[o+2],d[o+3]])} }
#[inline] fn ru64be(d:&[u8],o:usize)->u64{ if o+8>d.len(){0}else{u64::from_be_bytes([d[o],d[o+1],d[o+2],d[o+3],d[o+4],d[o+5],d[o+6],d[o+7]])} }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ps3Section { pub name: String, pub sh_addr: u64, pub sh_offset: u64, pub sh_size: u64, pub is_code: bool }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ps3FileInfo {
    pub filename: String,
    pub file_type: String,  // "SELF", "ELF32-BE", "ELF64-BE"
    pub entry_point: u64,
    pub machine: u16,
    pub sections: Vec<Ps3Section>,
    pub encrypted: bool,
}

/// Parse a PS3 executable (SELF wrapper or plain BE ELF).
pub fn parse_ps3(data: &[u8], filename: &str) -> Result<Ps3FileInfo, String> {
    if is_self(data) {
        return parse_self(data, filename);
    }
    if is_be_elf(data, 1) {
        return parse_elf(data, filename);
    }
    Err("Not a PS3 executable (expected SELF or big-endian ELF)".into())
}

fn parse_self(data: &[u8], filename: &str) -> Result<Ps3FileInfo, String> {
    // SELF header: magic(4) version(4) sdk_version(4) flags(4) ...
    // The embedded ELF offset varies; for unencrypted SELFs it's typically
    // at a fixed offset (e.g. 0x3E0 or after the metadata). We scan for the
    // ELF magic as a best-effort approach.
    let elf_off = data
        .windows(4)
        .enumerate()
        .skip(4)
        .find(|(_, w)| *w == [0x7f, b'E', b'L', b'F'])
        .map(|(i, _)| i)
        .ok_or_else(|| "SELF: could not locate embedded ELF (may be encrypted)".to_string())?;

    if !is_be_elf(&data[elf_off..], 1) {
        return Err("SELF: embedded ELF is not big-endian (may be encrypted)".into());
    }

    let mut info = parse_elf(&data[elf_off..], filename)?;
    info.file_type = "SELF (unencrypted)".to_string();
    Ok(info)
}

fn parse_elf(data: &[u8], filename: &str) -> Result<Ps3FileInfo, String> {
    let class = data[4]; // 1=32-bit, 2=64-bit
    let machine = ru16be(data, 18);
    let entry = if class == 2 { ru64be(data, 24) } else { ru32be(data, 24) as u64 };
    let (shoff, shentsize, shnum, shstrndx) = if class == 2 {
        (ru64be(data, 40), ru16be(data, 58) as u64, ru16be(data, 60), ru16be(data, 62))
    } else {
        (ru32be(data, 32) as u64, ru16be(data, 46) as u64, ru16be(data, 48), ru16be(data, 50))
    };

    let file_type = if class == 2 { "ELF64-BE" } else { "ELF32-BE" };

    // Section headers
    let mut sections = Vec::new();
    let mut shstrtab_off = 0u64;
    let esize = if class == 2 { 64 } else { 40 };
    if shoff > 0 && shentsize >= esize {
        if shstrndx < shnum {
            let so = shoff as usize + (shstrndx as usize) * shentsize as usize;
            if so + esize as usize <= data.len() {
                shstrtab_off = if class == 2 { ru64be(data, so + 24) } else { ru32be(data, so + 16) as u64 };
            }
        }
        for i in 0..shnum.min(1024) {
            let off = shoff as usize + (i as usize) * shentsize as usize;
            if off + esize as usize > data.len() { break; }
            let name_off = ru32be(data, off) as usize;
            let sh_addr = if class == 2 { ru64be(data, off+16) } else { ru32be(data, off+12) as u64 };
            let sh_offset = if class == 2 { ru64be(data, off+24) } else { ru32be(data, off+16) as u64 };
            let sh_size = if class == 2 { ru64be(data, off+32) } else { ru32be(data, off+20) as u64 };
            let sh_flags = if class == 2 { ru64be(data, off+8) } else { ru32be(data, off+8) as u64 };
            let name = if shstrtab_off > 0 && (shstrtab_off as usize + name_off) < data.len() {
                let s = shstrtab_off as usize + name_off;
                let e = data[s..].iter().position(|&b| b==0).map(|n|s+n).unwrap_or(data.len().min(s+64));
                String::from_utf8_lossy(&data[s..e]).to_string()
            } else { format!("sec{}", i) };
            sections.push(Ps3Section{ name, sh_addr, sh_offset, sh_size, is_code:(sh_flags&0x4)!=0 });
        }
    }

    Ok(Ps3FileInfo{ filename:filename.into(), file_type:file_type.into(), entry_point:entry, machine, sections, encrypted:false })
}

/// Disassemble a named section of a PS3 executable as big-endian PowerPC.
pub fn disassemble_ps3_section(data: &[u8], section_name: &str, max_instructions: usize) -> Result<Vec<PpcInstruction>, String> {
    let info = parse_ps3(data, "ps3")?;
    if info.encrypted { return Err("PS3 SELF is encrypted — disassembly not possible".into()); }
    let section = info.sections.iter().find(|s|s.name==section_name).ok_or_else(||format!("Section '{}' not found",section_name))?.clone();
    let start = section.sh_offset as usize;
    let end = (start+section.sh_size as usize).min(data.len());
    if start>=data.len() { return Err("Section raw data outside file".into()); }
    Ok(disassemble_ppc_at(&data[..end], start, section.sh_addr, max_instructions, PpcEndian::Big))
}
