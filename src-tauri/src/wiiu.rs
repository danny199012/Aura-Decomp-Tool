//! Wii U (RPX/RPL) support: Cafe ELF64 big-endian PowerPC64 parsing,
//! .fimports/.fexports resolution, and big-endian PPC disassembly.
//!
//! RPX files are the main executable; RPL files are shared libraries.
//! Both use ELF64 with big-endian data encoding and e_machine = EM_PPC64 (21).
//! Cafe OS typically maps images at ~0x02000000.

use crate::ppc_disasm::{disassemble_ppc_at, PpcEndian, PpcInstruction};
use serde::{Deserialize, Serialize};

/// Quick check: is this a big-endian ELF64 with e_machine == EM_PPC64?
pub fn is_rpx_rpl(data: &[u8]) -> bool {
    if data.len() < 64 { return false; }
    if &data[0..4] != [0x7f, b'E', b'L', b'F'] { return false; }
    if data[4] != 2 { return false; }  // 64-bit
    if data[5] != 2 { return false; }  // big-endian
    u16::from_be_bytes([data[18], data[19]]) == 21  // EM_PPC64
}

#[inline] fn ru16be(d:&[u8],o:usize)->u16{ if o+2>d.len(){0}else{u16::from_be_bytes([d[o],d[o+1]])} }
#[inline] fn ru32be(d:&[u8],o:usize)->u32{ if o+4>d.len(){0}else{u32::from_be_bytes([d[o],d[o+1],d[o+2],d[o+3]])} }
#[inline] fn ru64be(d:&[u8],o:usize)->u64{ if o+8>d.len(){0}else{u64::from_be_bytes([d[o],d[o+1],d[o+2],d[o+3],d[o+4],d[o+5],d[o+6],d[o+7]])} }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WiiUSection {
    pub name: String,
    pub sh_type: u32,
    pub sh_flags: u64,
    pub sh_addr: u64,
    pub sh_offset: u64,
    pub sh_size: u64,
    pub is_code: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WiiUFunctionName { pub name: String, pub address: u64 }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WiiUFileInfo {
    pub filename: String,
    pub file_type: String,
    pub entry_point: u64,
    pub machine: u16,
    pub sections: Vec<WiiUSection>,
    pub fimports: Vec<WiiUFunctionName>,
    pub fexports: Vec<WiiUFunctionName>,
    pub symbols: Vec<WiiUFunctionName>,
}

pub fn parse_rpx_rpl(data: &[u8], filename: &str) -> Result<WiiUFileInfo, String> {
    if !is_rpx_rpl(data) { return Err("Not a Wii U RPX/RPL (expected BE ELF64 PPC64)".into()); }
    if data.len() < 64 { return Err("File too small for ELF64 header".into()); }
    let e_type = ru16be(data, 16);
    let machine = ru16be(data, 18);
    let entry = ru64be(data, 24);
    let shoff = ru64be(data, 40);
    let shentsize = ru16be(data, 58);
    let shnum = ru16be(data, 60);
    let shstrndx = ru16be(data, 62);
    let file_type = match e_type { 2=>"RPX (executable)".into(), 3=>"RPL (shared library)".into(), _=>format!("ELF type {}",e_type) };

    let mut sections = Vec::new();
    let mut shstrtab_off = 0u64;
    let mut shstrtab_size = 0u64;
    if shoff > 0 && shentsize >= 64 {
        if shstrndx < shnum {
            let so = shoff as usize + (shstrndx as usize)*shentsize as usize;
            if so + 64 <= data.len() {
                shstrtab_off = ru64be(data, so+24);
                shstrtab_size = ru64be(data, so+32);
            }
        }
        for i in 0..shnum.min(1024) {
            let off = shoff as usize + (i as usize)*shentsize as usize;
            if off + 64 > data.len() { break; }
            let name_off = ru32be(data, off) as usize;
            let sh_type = ru32be(data, off+4);
            let sh_flags = ru64be(data, off+8);
            let sh_addr = ru64be(data, off+16);
            let sh_offset = ru64be(data, off+24);
            let sh_size = ru64be(data, off+32);
            let name = if shstrtab_off>0 && (shstrtab_off as usize+name_off)<data.len() {
                let s = shstrtab_off as usize+name_off;
                let e = data[s..].iter().position(|&b|b==0).map(|n|s+n).unwrap_or(data.len().min(s+64));
                String::from_utf8_lossy(&data[s..e]).to_string()
            } else { format!("sec{}",i) };
            sections.push(WiiUSection{ name, sh_type, sh_flags, sh_addr, sh_offset, sh_size, is_code:(sh_flags&0x4)!=0 });
        }
    }

    let mut fimports = Vec::new();
    let mut fexports = Vec::new();
    let mut symbols = Vec::new();
    for sec in &sections {
        match sec.name.as_str() {
            ".fimports" => fimports = extract_cafe_names(data, sec),
            ".fexports" => fexports = extract_cafe_names(data, sec),
            ".symtab" => {
                if let Some(strtab) = sections.iter().find(|s|s.name==".strtab").or_else(||sections.iter().find(|s|s.name==".dynstr")) {
                    let count = (sec.sh_size as usize/24).min(4096);
                    for i in 0..count {
                        let off = sec.sh_offset as usize+i*24;
                        if off+24>data.len() { break; }
                        let nm = ru32be(data,off) as usize;
                        let val = ru64be(data,off+8);
                        let name = read_str_at(data, strtab.sh_offset as usize+nm);
                        if !name.is_empty() { symbols.push(WiiUFunctionName{ name, address:val }); }
                    }
                }
            }
            _ => {}
        }
    }
    Ok(WiiUFileInfo{ filename:filename.into(), file_type, entry_point:entry, machine, sections, fimports, fexports, symbols })
}

fn extract_cafe_names(data: &[u8], sec: &WiiUSection) -> Vec<WiiUFunctionName> {
    let mut out = Vec::new();
    let start = sec.sh_offset as usize;
    let size = sec.sh_size as usize;
    if start+size > data.len() { return out; }
    let s = &data[start..start+size];
    let mut i = 0usize;
    while i+4 < s.len() {
        if s[i].is_ascii_alphabetic() || s[i]==b'_' {
            let end = s[i..].iter().position(|&b|b==0).map(|n|i+n).unwrap_or(i+64);
            let name = String::from_utf8_lossy(&s[i..end]).to_string();
            if name.len()>=2 && name.len()<=256 && name.chars().all(|c|c.is_ascii_graphic()) {
                out.push(WiiUFunctionName{ name, address:sec.sh_addr+i as u64 });
                i = (end+0x14).max((end+3)&!3);
                continue;
            }
        }
        i += 4;
    }
    out
}

fn read_str_at(data: &[u8], off: usize) -> String {
    if off>=data.len() { return String::new(); }
    let e = data[off..].iter().position(|&b|b==0).map(|n|off+n).unwrap_or(data.len());
    String::from_utf8_lossy(&data[off..e]).to_string()
}

pub fn disassemble_rpx_section(data: &[u8], section_name: &str, max_instructions: usize) -> Result<Vec<PpcInstruction>, String> {
    let info = parse_rpx_rpl(data, "rpx")?;
    let section = info.sections.iter().find(|s|s.name==section_name).ok_or_else(||format!("Section '{}' not found",section_name))?.clone();
    let start = section.sh_offset as usize;
    let end = (start+section.sh_size as usize).min(data.len());
    if start>=data.len() { return Err("Section raw data outside file".into()); }
    Ok(disassemble_ppc_at(&data[..end], start, section.sh_addr, max_instructions, PpcEndian::Big))
}
