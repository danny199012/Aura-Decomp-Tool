//! Search + string analysis + patching utilities (Tier 4 UX polish) for Aura.
//!
//! Pure-Rust helpers that power the GUI "Search" tab and the CLI `strings` /
//! `search` / `patch-export` commands:
//!
//! - [`collect_strings`] — scan a byte slice for readable ASCII / UTF-16LE
//!   strings and return them with their absolute addresses (Ghidra's "Defined
//!   Strings" window equivalent).
//! - [`find_pattern`] / [`find_string`] / [`find_immediate`] — locate byte
//!   patterns, ASCII strings, and 32-bit immediate values in a binary.
//! - [`string_xrefs_mips`] — find code that references a string's address via
//!   the canonical MIPS `lui`+`addiu`/`ori` address-build idiom, producing a
//!   "references to this string" list (Ghidra's string xrefs).
//! - [`export_bytes`] — write bytes to a file for patched-binary export.

use serde::{Deserialize, Serialize};

/// A discovered string in the binary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FoundString {
    /// Absolute address of the string's first byte.
    pub address: u32,
    /// File offset of the string's first byte.
    pub offset: u32,
    /// The decoded string text.
    pub text: String,
    /// True if this was decoded as UTF-16LE (wide string).
    pub wide: bool,
    /// Length in bytes (as stored).
    pub byte_len: u32,
}

/// Collect printable strings from `data` (base address `base`).
///
/// `min_len` is the minimum string length in *characters* (default 4). The
/// scanner walks the data once and emits contiguous runs of printable ASCII
/// (or, for wide strings, printable codepoints in UTF-16LE). This is a
/// pragmatic approximation of Ghidra's string table discovery.
pub fn collect_strings(data: &[u8], base: u32, min_len: usize) -> Vec<FoundString> {
    let mut out = Vec::new();
    let min_len = if min_len < 1 { 4 } else { min_len };

    // ASCII pass
    let mut i = 0usize;
    while i < data.len() {
        if !is_ascii_print(data[i]) {
            i += 1;
            continue;
        }
        let start = i;
        while i < data.len() && is_ascii_print(data[i]) {
            i += 1;
        }
        let len = i - start;
        if len >= min_len {
            if let Ok(text) = std::str::from_utf8(&data[start..i]) {
                out.push(FoundString {
                    address: base.wrapping_add(start as u32),
                    offset: start as u32,
                    text: text.to_string(),
                    wide: false,
                    byte_len: len as u32,
                });
            }
        }
    }
    // Wide (UTF-16LE) pass
    collect_wide_strings(data, base, min_len, &mut out);

    out.sort_by_key(|s| s.address);
    out
}

#[inline]
fn is_ascii_print(b: u8) -> bool {
    b >= 0x20 && b <= 0x7e
}

// UTF-16LE pass: pairs where the low byte is printable ASCII and the high
// byte is 0 (0x41 0x00 0x42 0x00 ...). Conservative but catches the common
// PlayStation "wide text" tables without false positives.
fn collect_wide_strings(data: &[u8], base: u32, min_len: usize, out: &mut Vec<FoundString>) {
    if data.len() < 2 {
        return;
    }
    let mut j = 0usize;
    while j + 1 < data.len() {
        let lo = data[j];
        let hi = data[j + 1];
        if is_ascii_print(lo) && hi == 0 {
            let start = j;
            while j + 1 < data.len() {
                let l = data[j];
                let h = data[j + 1];
                if is_ascii_print(l) && h == 0 {
                    j += 2;
                } else {
                    break;
                }
            }
            let chars = (j - start) / 2;
            if chars >= min_len {
                let text: String = data[start..j]
                    .chunks_exact(2)
                    .map(|c| c[0] as char)
                    .collect();
                out.push(FoundString {
                    address: base.wrapping_add(start as u32),
                    offset: start as u32,
                    text,
                    wide: true,
                    byte_len: (j - start) as u32,
                });
            }
        } else {
            j += 2;
        }
    }
}

// ---------------------------------------------------------------------------
// Pattern / string / immediate search
// ---------------------------------------------------------------------------

/// A search hit: offset + (optional) absolute address when a base is supplied.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Hit {
    pub offset: u32,
    pub address: Option<u32>,
}

/// Find all occurrences of `needle` (raw bytes) in `data`.
pub fn find_pattern(data: &[u8], needle: &[u8], base: Option<u32>) -> Vec<Hit> {
    let mut out = Vec::new();
    if needle.is_empty() || needle.len() > data.len() {
        return out;
    }
    let mut i = 0usize;
    while i + needle.len() <= data.len() {
        if data[i..i + needle.len()] == *needle {
            out.push(Hit { offset: i as u32, address: base.map(|b| b.wrapping_add(i as u32)) });
        }
        i += 1;
    }
    out
}

/// Find all occurrences of a printable string (case-insensitively if asked).
pub fn find_string(data: &[u8], needle: &str, ignore_case: bool, base: Option<u32>) -> Vec<Hit> {
    if ignore_case {
        let lower = needle.to_lowercase().into_bytes();
        find_pattern_casefold(data, &lower, base)
    } else {
        find_pattern(data, needle.as_bytes(), base)
    }
}

/// Case-insensitive pattern search using lowercased needle.
fn find_pattern_casefold(data: &[u8], needle_lower: &[u8], base: Option<u32>) -> Vec<Hit> {
    let mut out = Vec::new();
    if needle_lower.is_empty() || needle_lower.len() > data.len() {
        return out;
    }
    let max_start = data.len() - needle_lower.len();
    for i in 0..=max_start {
        let window = &data[i..i + needle_lower.len()];
        let ok = window.iter().zip(needle_lower.iter()).all(|(d, n)| d.to_ascii_lowercase() == *n);
        if ok {
            out.push(Hit { offset: i as u32, address: base.map(|b| b.wrapping_add(i as u32)) });
        }
    }
    out
}

/// Find all 32-bit words equal to `value` (respecting endianness).
/// `step` divides both word-aligned (step=4) and byte-aligned scans.
pub fn find_immediate(data: &[u8], value: u32, is_le: bool, base: Option<u32>, step: usize) -> Vec<Hit> {
    let mut out = Vec::new();
    let step = if step == 0 { 4 } else { step };
    let mut i = 0usize;
    while i + 4 <= data.len() {
        let w = if is_le {
            u32::from_le_bytes([data[i], data[i + 1], data[i + 2], data[i + 3]])
        } else {
            u32::from_be_bytes([data[i], data[i + 1], data[i + 2], data[i + 3]])
        };
        if w == value {
            out.push(Hit { offset: i as u32, address: base.map(|b| b.wrapping_add(i as u32)) });
        }
        i += step;
    }
    out
}
// ---------------------------------------------------------------------------
// String xrefs (MIPS lui+addiu/ori address-build idiom)
// ---------------------------------------------------------------------------

/// A reference from code to a string.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StringXref {
    /// Code address of the instruction that references the string.
    pub from: u32,
    /// Address of the referenced string.
    pub to: u32,
    /// The string text (from the string table).
    pub text: String,
}

/// Find code references to string addresses by scanning an executable section
/// for the MIPS address-build idiom:
///
///   lui  $r, (addr >> 16)
///   addiu/ori $r, $r, (addr & 0xFFFF)
///
/// `code` is the executable section bytes, `code_base` its load address,
/// `is_le` its endianness, `strings` the known string list. Only references
/// that land on a known string start are kept (no false positives).
pub fn string_xrefs_mips(
    code: &[u8],
    code_base: u32,
    is_le: bool,
    strings: &[FoundString],
) -> Vec<StringXref> {
    let str_map: std::collections::BTreeMap<u32, &FoundString> =
        strings.iter().map(|s| (s.address, s)).collect();

    let mut out = Vec::new();
    let mut i = 0usize;
    while i + 4 <= code.len() {
        let w = read_word(code, i, is_le);
        let op = (w >> 26) & 0x3F;
        if op == 0x0F {
            // lui rt, imm16 -> rt = imm16 << 16
            let rt = (w >> 16) & 0x1F;
            let hi = (w & 0xFFFF) << 16;
            // Look at the next up-to-8 instructions for addiu/ori rt,rt,lo.
            let mut k = i + 4;
            let window_end = ((i / 4) + 8) * 4;
            while k + 4 <= code.len() && k < window_end {
                let w2 = read_word(code, k, is_le);
                let op2 = (w2 >> 26) & 0x3F;
                let rt2 = (w2 >> 16) & 0x1F;
                if rt2 == rt && (op2 == 0x09 || op2 == 0x0D) {
                    // addiu / ori with the low half
                    let lo = w2 & 0xFFFF;
                    let addr = hi | lo;
                    if let Some(s) = str_map.get(&addr) {
                        out.push(StringXref {
                            from: code_base.wrapping_add(i as u32),
                            to: addr,
                            text: s.text.clone(),
                        });
                        break;
                    }
                    // try sign-extended low half too
                    let lo_signed = (lo as i16) as i32 as u32;
                    let addr_s = hi.wrapping_add(lo_signed);
                    if let Some(s) = str_map.get(&addr_s) {
                        out.push(StringXref {
                            from: code_base.wrapping_add(i as u32),
                            to: addr_s,
                            text: s.text.clone(),
                        });
                        break;
                    }
                }
                k += 4;
            }
        }
        i += 4;
    }
    out
}

#[inline]
fn read_word(data: &[u8], offset: usize, is_le: bool) -> u32 {
    if is_le {
        u32::from_le_bytes([data[offset], data[offset + 1], data[offset + 2], data[offset + 3]])
    } else {
        u32::from_be_bytes([data[offset], data[offset + 1], data[offset + 2], data[offset + 3]])
    }
}

// ---------------------------------------------------------------------------
// Patched export
// ---------------------------------------------------------------------------

/// Write `data` to `out_path` (used to export a patched binary). Returns the
/// number of bytes written.
pub fn export_bytes(data: &[u8], out_path: &str) -> Result<u64, String> {
    std::fs::write(out_path, data).map_err(|e| format!("write {out_path}: {e}"))?;
    Ok(data.len() as u64)
}