//! PS-X EXE: the boot executable format of the original PlayStation.
//!
//! A PS1 disc's `SYSTEM.CNF` names its boot file (`BOOT = cdrom:\SLUS_004.04;1`)
//! and that file is a PS-X EXE: a 2048-byte header followed by the program
//! text, loaded at a fixed address and started at `initial_pc`. There are no
//! sections or symbols, so this header is all the structure there is.
//!
//! Pure parsing over a byte slice: bounds-checked, no allocation beyond the
//! returned strings, never panics on hostile input.

use serde::Serialize;

/// Magic at offset 0.
pub const MAGIC: &[u8; 8] = b"PS-X EXE";
/// Size of the header that precedes the program text.
pub const HEADER_BYTES: usize = 0x800;
/// Smallest prefix [`parse`] needs.
pub const MIN_PARSE_BYTES: usize = 0x4C;

/// The fields of a PS-X EXE header that matter for analysis and display.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PsxExeInfo {
    /// Address execution starts at.
    pub entry_pc: u32,
    /// Initial value of `$gp`.
    pub gp: u32,
    /// Address the program text is loaded at.
    pub load_addr: u32,
    /// Bytes of program text (multiple of 2048 on retail discs).
    pub text_size: u32,
    /// Initial stack pointer (`0` = use the BIOS default).
    pub initial_sp: u32,
    /// The licence marker string, e.g. `Sony Computer Entertainment Inc. for North America area`.
    pub region_marker: String,
}

impl PsxExeInfo {
    /// Region implied by the licence marker, if it has one of the three
    /// standard values.
    pub fn marker_region(&self) -> Option<&'static str> {
        let m = self.region_marker.to_ascii_lowercase();
        if m.contains("north america") {
            Some("NTSC-U/C (North America)")
        } else if m.contains("europe") {
            Some("PAL (Europe)")
        } else if m.contains("japan") {
            Some("NTSC-J (Japan)")
        } else {
            None
        }
    }

    /// True when `entry_pc` lies inside the loaded text. Retail programs
    /// satisfy this; a violation suggests a packed or unusual executable.
    pub fn entry_in_text(&self) -> bool {
        let end = self.load_addr as u64 + self.text_size as u64;
        (self.entry_pc as u64) >= self.load_addr as u64 && (self.entry_pc as u64) < end
    }
}

/// True when `head` starts with the PS-X EXE magic.
pub fn is_psx_exe(head: &[u8]) -> bool {
    head.len() >= MAGIC.len() && &head[..MAGIC.len()] == MAGIC
}

fn le32(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}

/// Parse the header at the start of `head` (at least [`MIN_PARSE_BYTES`], and
/// preferably the whole 2048-byte header so the licence marker is read).
pub fn parse(head: &[u8]) -> Option<PsxExeInfo> {
    if head.len() < MIN_PARSE_BYTES || !is_psx_exe(head) {
        return None;
    }
    // The marker string sits at 0x4C and is NUL-terminated inside the header.
    let marker = if head.len() > 0x4C {
        let end = head.len().min(HEADER_BYTES);
        let raw = &head[0x4C..end];
        let len = raw.iter().position(|&b| b == 0).unwrap_or(raw.len()).min(128);
        String::from_utf8_lossy(&raw[..len]).trim().to_string()
    } else {
        String::new()
    };
    Some(PsxExeInfo {
        entry_pc: le32(head, 0x10),
        gp: le32(head, 0x14),
        load_addr: le32(head, 0x18),
        text_size: le32(head, 0x1C),
        initial_sp: le32(head, 0x30),
        region_marker: marker,
    })
}
