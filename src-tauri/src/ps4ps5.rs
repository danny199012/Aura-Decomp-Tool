//! PlayStation 4 & PlayStation 5 support: little-endian ELF64 x86-64 homebrew
//! executables, SELF wrapper parsing, and the OpenOrbis/fake-SELF eboot.bin
//! container (magic `4F 15 3D 1D`) used by homebrew. Disassembly via iced-x86
//! at 64-bit.
//!
//! Retail PS4/PS5 SELFs are key-gated; they degrade gracefully with an error.
//! The fSELF layout parsed here mirrors OpenOrbis' create-fself (fork of flatz'
//! make_fself.py): header 0x20, self entries 0x20 each, embedded ELF header +
//! program headers, extended info, NPDRM block, meta blocks/footer, signature,
//! then raw (uncompressed, unencrypted) segment data.

use serde::{Deserialize, Serialize};

/// Quick check for PS4/PS5 SELF magic. PS4/PS5 SELF uses the same "SCE\0"
/// magic as PS3, but the embedded ELF is little-endian x86-64.
pub fn is_self(data: &[u8]) -> bool {
    data.len() >= 4 && &data[0..3] == b"SCE" && data[3] == 0
}

/// PS4/PS5 eboot.bin / SELF header magic: bytes `4F 15 3D 1D` == u32 LE 0x1D3D154F.
pub fn is_ps4_eboot_magic(data: &[u8]) -> bool {
    data.len() >= 4 && data[0] == 0x4F && data[1] == 0x15 && data[2] == 0x3D && data[3] == 0x1D
}

/// True when the header is an OpenOrbis / fake-SELF (homebrew) container:
/// magic + keytype 0x101 + a plausible even entry count + an embedded ELF
/// header right after the self entries. Retail files share the magic but use a
/// different header layout (no keytype 0x101 / no inline ELF), so they fail.
pub fn is_fself(data: &[u8]) -> bool {
    if !is_ps4_eboot_magic(data) || data.len() < 0x20 {
        return false;
    }
    // fSELF: KeyType field at offset 0x08 == 0x101.
    if ru32le(data, 0x08) != 0x101 {
        return false;
    }
    let num = ru16le(data, 0x18) as usize;
    if num == 0 || num > 128 || num % 2 != 0 {
        return false;
    }
    let elf_off = 0x20 + num * 0x20;
    if elf_off + 4 > data.len() {
        return false;
    }
    &data[elf_off..elf_off + 4] == [0x7f, b'E', b'L', b'F']
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

/// Parse a PS4/PS5 executable (SELF, eboot.bin/fSELF, or plain LE ELF64 x86-64).
pub fn parse_ps4ps5(data: &[u8], filename: &str) -> Result<Ps4Ps5FileInfo, String> {
    if is_ps4_eboot_magic(data) {
        return parse_fself(data, filename);
    }
    if is_self(data) {
        return parse_self(data, filename);
    }
    if is_ps4ps5_elf(data) {
        return parse_elf(data, filename);
    }
    Err("Not a PS4/PS5 executable (expected SELF, eboot.bin, or LE ELF64 x86-64)".into())
}

/// Segment types the PS4 loader maps into memory (ELF PT_LOAD plus the Orbis
/// PT_SCE_RELRO / PT_SCE_DYNLIBDATA pseudo-segments).
const PT_LOAD: u32 = 1;
const PT_SCE_RELRO: u32 = 0x6100_0010;
const PT_SCE_DYNLIBDATA: u32 = 0x6100_0000;

/// Parse an OpenOrbis / fake-SELF PS4 eboot.bin container (unencrypted).
///
/// Layout (from create-fself, a port of flatz' make_fself.py):
/// - 0x00  header (0x20 bytes: magic, version/mode/endian/attributes u8s,
///          keytype u32=0x101, header_size u16, meta_size u16, file_size u64,
///          num_entries u16, flags u16)
/// - 0x20  num_entries x 0x20 self entries (properties/offset/file_size/memory_size
///          u64 each); two entries per load segment: meta + data
/// - ELF64 header 0x40 + full program-header table (0x38 each)
/// - extended info 0x40, NPDRM block 0x30, meta blocks 0x50 x N, meta footer
///   0x50, signature 0x100
/// - raw segment data at the offsets recorded in the data entries
///
/// Only the fields needed to locate sections/entry are read; the crypto/meta
/// areas are skipped entirely because fSELF segments are stored raw.
fn parse_fself(data: &[u8], filename: &str) -> Result<Ps4Ps5FileInfo, String> {
    if !is_ps4_eboot_magic(data) {
        return Err("Not a PS4 eboot.bin (missing 4F 15 3D 1D magic)".into());
    }
    if !is_fself(data) {
        return Err(
            "PS4 eboot.bin is a retail/encrypted SELF, which requires Sony's keys to decrypt. \
             Homebrew (OpenOrbis / fake-SELF) eboot.bin files are supported."
                .into(),
        );
    }

    let num = ru16le(data, 0x18) as usize;
    let elf_off = 0x20 + num * 0x20;
    if elf_off + 0x40 > data.len() {
        return Err("PS4 fSELF: truncated (no embedded ELF header)".into());
    }

    let entry = ru64le(data, elf_off + 0x18);
    let machine = ru16le(data, elf_off + 0x12);
    let phentsize = ru16le(data, elf_off + 0x36) as usize;
    let phnum = ru16le(data, elf_off + 0x38) as usize;
    if phentsize < 0x38 || phnum == 0 {
        return Err("PS4 fSELF: invalid program header table".into());
    }
    let ph_off = elf_off + 0x40;
    if ph_off + phnum * phentsize > data.len() {
        return Err("PS4 fSELF: program header table runs past end of file".into());
    }

    // Data entries are the odd-indexed self entries (meta/data pairs per segment).
    let mut data_entries: Vec<(u64, u64)> = Vec::new(); // (file offset, file size)
    for i in (1..num).step_by(2) {
        let o = 0x20 + i * 0x20;
        data_entries.push((ru64le(data, o + 8), ru64le(data, o + 16)));
    }

    let mut sections = Vec::new();
    let mut seg_idx = 0usize;
    for i in 0..phnum {
        let o = ph_off + i * phentsize;
        let p_type = ru32le(data, o);
        if p_type != PT_LOAD && p_type != PT_SCE_RELRO && p_type != PT_SCE_DYNLIBDATA {
            continue;
        }
        let p_flags = ru32le(data, o + 4);
        let p_vaddr = ru64le(data, o + 0x10);
        let p_filesz = ru64le(data, o + 0x20);
        if let Some(&(data_off, data_sz)) = data_entries.get(seg_idx) {
            sections.push(Ps4Ps5Section {
                name: format!("seg{}", seg_idx),
                sh_addr: p_vaddr,
                sh_offset: data_off,
                sh_size: if data_sz > 0 { data_sz } else { p_filesz },
                is_code: (p_flags & 1) != 0,
            });
        }
        seg_idx += 1;
    }

    if sections.is_empty() {
        return Err("PS4 fSELF: no loadable segments found".into());
    }

    Ok(Ps4Ps5FileInfo {
        filename: filename.into(),
        file_type: "SELF (fSELF / homebrew eboot.bin, unencrypted)".into(),
        entry_point: entry,
        machine,
        sections,
        has_orbis_note: false,
        encrypted: false,
    })
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
