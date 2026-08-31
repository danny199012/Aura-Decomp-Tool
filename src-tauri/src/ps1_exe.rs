//! PS1 EXE format parser.
//!
//! PlayStation 1 executables are wrapped in a "PS-X" header that precedes the
//! actual MIPS ELF image. The wrapper contains metadata (version, load address,
//! entry point) and the raw ELF bytes follow at a fixed offset.
//!
//! This module detects the PS-X magic, extracts the header fields, locates the
//! embedded ELF offset, and provides enough information for `open_file` to route
//! through the correct parser path.

use serde::Serialize;
use std::fs;
use std::path::Path;

/// Parsed PS-X executable header.
#[derive(Serialize, Debug, Clone)]
pub struct PsxExeInfo {
    /// Header version byte (typically 0 for original PS1, 1 for later revisions).
    pub version: u8,
    /// Load address of the ELF in memory (from the PS-X header).
    pub load_address: u32,
    /// Entry point override from the PS-X header (0 means use ELF's e_entry).
    pub entry_point: u32,
    /// File offset where the embedded ELF image begins.
    pub elf_offset: u32,
    /// Size of the embedded ELF in bytes.
    pub elf_size: u32,
}

/// The PS-X magic signature at the start of a PS1 executable file.
const PSX_MAGIC: &[u8; 8] = b"PS-X EXE";

/// Minimum size of a valid PS-X header (magic + version + load_addr + entry).
const MIN_HEADER_SIZE: usize = 0x20; // 32 bytes is the minimum sane header

/// Detect and parse a PS-X executable header at the given file path.
///
/// Returns `Ok(Some(info))` if the file starts with the "PS-X EXE" magic,
/// `Ok(None)` if it doesn't (file is not a PS1 EXE), or `Err(...)` on I/O failure.
pub fn detect_psx_header(path: &str) -> Result<Option<PsxExeInfo>, String> {
    let p = Path::new(path);
    if !p.exists() {
        return Err(format!("File not found: {}", path));
    }

    // Read just the first 256 bytes — enough for the header and to locate ELF.
    let mut file = fs::File::open(p).map_err(|e| e.to_string())?;
    use std::io::Read;
    let mut buf = [0u8; 256];
    let n = file.read(&mut buf).map_err(|e| e.to_string())?;
    if n < MIN_HEADER_SIZE {
        return Ok(None);
    }

    // Check magic: "PS-X EXE" at offset 0.
    if &buf[0..8] != PSX_MAGIC {
        return Ok(None);
    }

    // Parse header fields (big-endian, as PS1 is a big-endian MIPS platform).
    let version = buf[8];
    // Load address at offset 0x0C (4 bytes BE)
    let load_address = u32::from_be_bytes([buf[0x0C], buf[0x0D], buf[0x0E], buf[0x0F]]);
    // Entry point override at offset 0x10 (4 bytes BE). Zero means "use ELF entry".
    let entry_point = u32::from_be_bytes([buf[0x10], buf[0x11], buf[0x12], buf[0x13]]);

    // The embedded ELF starts after the PS-X header. In most PS1 EXE files,
    // the ELF magic (0x7F 'E' 'L' 'F') appears at a small fixed offset from the
    // start of the file. We scan for it within the first 4 KB to be safe.
    let elf_offset = find_elf_offset(&buf[..n])
        .or_else(|| {
            // If not in the first 256 bytes, read more and search further.
            Some(0) // placeholder; we'll re-read below if needed
        })
        .unwrap_or(0);

    // If the quick scan didn't find it (offset still 0 or invalid), do a wider search.
    let elf_offset = if elf_offset == 0 {
        let mut wide_buf = [0u8; 4096];
        use std::io::{Seek, SeekFrom};
        file.seek(SeekFrom::Start(0)).map_err(|e| e.to_string())?;
        let n2 = file.read(&mut wide_buf).map_err(|e| e.to_string())?;
        find_elf_offset(&wide_buf[..n2])
            .ok_or_else(|| "PS-X header found but no embedded ELF magic located".to_string())?
    } else {
        elf_offset
    };

    // Read the ELF header to get its size (e_shoff + section headers, or just
    // use e_ehsize + segment count as a rough bound). For our purposes we need
    // the total file size minus the offset to know how much is ELF.
    let metadata = fs::metadata(p).map_err(|e| e.to_string())?;
    let file_size = metadata.len() as u32;
    let elf_size = if elf_offset < file_size {
        file_size - elf_offset
    } else {
        0
    };

    Ok(Some(PsxExeInfo {
        version,
        load_address,
        entry_point,
        elf_offset,
        elf_size,
    }))
}

/// Scan a byte buffer for the ELF magic (0x7F 'E' 'L' 'F') and return its offset.
fn find_elf_offset(data: &[u8]) -> Option<u32> {
    // The ELF magic is 4 bytes; search up to min(len, 4096) for it.
    let limit = data.len().saturating_sub(3);
    for i in 0..limit {
        if &data[i..i + 4] == [0x7F, b'E', b'L', b'F'] {
            return Some(i as u32);
        }
    }
    None
}

/// Extract the embedded ELF bytes from a PS-X executable file.
///
/// Reads the entire file, locates the ELF offset via `detect_psx_header`, and
/// returns just the ELF portion. This is what gets handed to `parse_elf_file`'s
/// logic (or an in-memory variant) for section/symbol extraction.
pub fn extract_embedded_elf(path: &str) -> Result<Vec<u8>, String> {
    let info = detect_psx_header(path)?
        .ok_or_else(|| "Not a PS-X executable".to_string())?;

    if info.elf_offset == 0 || info.elf_size == 0 {
        return Err("PS-X header present but no embedded ELF found".to_string());
    }

    let data = fs::read(path).map_err(|e| format!("Failed to read file: {}", e))?;
    let start = info.elf_offset as usize;
    if start >= data.len() {
        return Err("ELF offset exceeds file size".to_string());
    }

    Ok(data[start..].to_vec())
}

/// Check if a byte buffer looks like a raw CD-ROM image (2352-byte sectors).
/// Raw sectors start with the CD-ROM sync pattern: 00 FF FF FF FF FF FF FF FF
/// FF FF 00 (12 bytes at the start of every sector).
fn is_raw_cdrom(data: &[u8]) -> bool {
    data.len() >= 2352
        && data[0] == 0x00
        && data[1..12].iter().all(|&b| b == 0xFF)
        && data[12] == 0x00
}

/// Reconstruct a contiguous data stream from a raw 2352-byte-sector CD image
/// by extracting the 2048-byte payload from each sector. PS1 discs use Mode 2
/// (data at offset 24); Mode 1 discs have data at offset 16. We try both.
fn reconstruct_data_from_raw(data: &[u8]) -> Vec<u8> {
    const SECTOR_SIZE: usize = 2352;
    const DATA_SIZE: usize = 2048;

    // Try Mode 2 (offset 24) first — PS1 CD-XA uses Mode 2.
    for &data_off in &[24usize, 16usize] {
        let mut out = Vec::with_capacity(data.len() / SECTOR_SIZE * DATA_SIZE);
        let mut pos = 0;
        while pos + SECTOR_SIZE <= data.len() {
            let end = pos + data_off + DATA_SIZE;
            if end <= data.len() {
                out.extend_from_slice(&data[pos + data_off..end]);
            }
            pos += SECTOR_SIZE;
        }
        // Check if this reconstruction contains a PS-X EXE.
        if find_psx_exe_offset_in_disc(&out).is_some() {
            return out;
        }
    }
    // Fall back to Mode 2 data even if no PS-X EXE found (best effort).
    let mut out = Vec::with_capacity(data.len() / SECTOR_SIZE * DATA_SIZE);
    let mut pos = 0;
    while pos + SECTOR_SIZE <= data.len() {
        let end = pos + 24 + DATA_SIZE;
        if end <= data.len() {
            out.extend_from_slice(&data[pos + 24..end]);
        }
        pos += SECTOR_SIZE;
    }
    out
}

/// Scan a raw disc image for the "PS-X EXE" magic and return its byte offset.
///
/// PS1 games ship on CD-ROMs; the bootable executable (a PS-X EXE) is stored as
/// a file inside the ISO9660 / raw-sector image. We can't mount the filesystem
/// here, so we locate the embedded executable by scanning for its magic. This
/// finds the primary boot executable for the vast majority of PS1 disc images.
pub fn find_psx_exe_offset_in_disc(data: &[u8]) -> Option<usize> {
    let magic = b"PS-X EXE";
    if data.len() < magic.len() {
        return None;
    }
    // A PS-X EXE is 2048-byte sector aligned within the image. Scanning every
    // byte is simplest and correct; cap the search to the first 64 MB to keep
    // worst-case time bounded on huge images.
    let limit = data.len().min(64 * 1024 * 1024);
    data[..limit]
        .windows(magic.len())
        .position(|w| w == magic)
}

/// Extract the embedded ELF executable from a PS1 disc image (.iso/.bin/.img).
///
/// Returns the ELF bytes of the bootable game executable. Works by finding the
/// PS-X EXE inside the disc image and pulling out the ELF that follows it.
///
/// Handles both `.iso` (2048-byte contiguous data sectors) and `.bin` (raw
/// 2352-byte sectors with sync/header/ECC overhead) by reconstructing the data
/// stream from raw sectors before scanning.
pub fn extract_elf_from_disc_image(path: &str) -> Result<Vec<u8>, String> {
    let data = fs::read(path).map_err(|e| format!("Failed to read file: {}", e))?;

    // If this is a raw 2352-byte-sector image (.bin/.img), reconstruct the
    // contiguous data stream (2048 bytes per sector) before scanning — the raw
    // sector headers fragment the ELF across 304-byte gaps otherwise.
    let search_data: std::borrow::Cow<'_, [u8]> = if is_raw_cdrom(&data) {
        std::borrow::Cow::Owned(reconstruct_data_from_raw(&data))
    } else {
        std::borrow::Cow::Borrowed(&data)
    };

    let exe_off = find_psx_exe_offset_in_disc(&search_data)
        .ok_or_else(|| "No PS-X EXE found in disc image".to_string())?;

    // Parse the PS-X header at that offset to locate the embedded ELF.
    let exe = &search_data[exe_off..];
    // Reuse the magic-offset scan logic over the EXE to find the ELF magic.
    let elf_rel = exe
        .windows(4)
        .position(|w| w == [0x7F, b'E', b'L', b'F'])
        .ok_or_else(|| "PS-X EXE present but embedded ELF not located".to_string())?;
    Ok(exe[elf_rel..].to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal PS-X EXE image in memory: "PS-X EXE" header + fake ELF.
    fn build_psx_exe(elf_offset: usize) -> Vec<u8> {
        let mut buf = vec![0u8; elf_offset + 64];
        // Magic
        buf[0..8].copy_from_slice(b"PS-X EXE");
        // Version
        buf[8] = 1;
        // Load address: 0x00100000 (BE)
        buf[0x0C..0x10].copy_from_slice(&0x00100000u32.to_be_bytes());
        // Entry point override: 0 (use ELF's own entry)
        buf[0x10..0x14].copy_from_slice(&0u32.to_be_bytes());

        // Place a fake ELF magic at the expected offset.
        buf[elf_offset..elf_offset + 4].copy_from_slice(&[0x7F, b'E', b'L', b'F']);
        buf[elf_offset + 4] = 1; // EI_CLASS: 32-bit
        buf[elf_offset + 5] = 2; // EI_DATA: big-endian (PS1)

        buf
    }

    #[test]
    fn detects_psx_header_with_embedded_elf() {
        let elf_off = 0x40usize;
        let data = build_psx_exe(elf_off);
        // Write to a temp file for the path-based API.
        let dir = std::env::temp_dir();
        let path = dir.join("test_psx_exe.bin");
        fs::write(&path, &data).unwrap();

        let result = detect_psx_header(path.to_str().unwrap()).unwrap();
        assert!(result.is_some(), "should detect PS-X header");
        let info = result.unwrap();
        assert_eq!(info.version, 1);
        assert_eq!(info.load_address, 0x00100000);
        assert_eq!(info.entry_point, 0);
        assert_eq!(info.elf_offset as usize, elf_off);
        assert!(info.elf_size > 0);

        // Cleanup
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn returns_none_for_non_psx_file() {
        let dir = std::env::temp_dir();
        let path = dir.join("test_not_psx.bin");
        // Write a plain ELF (no PS-X wrapper).
        let mut data = vec![0u8; 64];
        data[0..4].copy_from_slice(&[0x7F, b'E', b'L', b'F']);
        fs::write(&path, &data).unwrap();

        let result = detect_psx_header(path.to_str().unwrap()).unwrap();
        assert!(result.is_none(), "should not match a plain ELF");

        let _ = fs::remove_file(&path);
    }

    #[test]
    fn extract_elf_returns_embedded_portion() {
        let elf_off = 0x40usize;
        let data = build_psx_exe(elf_off);
        let dir = std::env::temp_dir();
        let path = dir.join("test_psx_extract.bin");
        fs::write(&path, &data).unwrap();

        let elf_bytes = extract_embedded_elf(path.to_str().unwrap()).unwrap();
        assert!(elf_bytes.len() >= 64);
        // The extracted bytes should start with ELF magic.
        assert_eq!(&elf_bytes[0..4], &[0x7F, b'E', b'L', b'F']);

        let _ = fs::remove_file(&path);
    }

    #[test]
    fn find_elf_offset_locates_magic() {
        let mut buf = vec![0u8; 128];
        buf[64..68].copy_from_slice(&[0x7F, b'E', b'L', b'F']);
        assert_eq!(find_elf_offset(&buf), Some(64));

        // No magic present.
        let empty = vec![0u8; 32];
        assert_eq!(find_elf_offset(&empty), None);
    }
}