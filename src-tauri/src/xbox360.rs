//! Xbox 360 support: XEX executable parsing, embedded PE extraction, and
//! PowerPC (Xenon) disassembly.
//!
//! Format reference: Xenia emulator's `xex2_info.h`. All XEX/PE header fields
//! on this page are big-endian unless noted (the embedded PE headers are
//! little-endian, as on Windows).

use crate::ppc_disasm::{disassemble_ppc_at, PpcEndian, PpcInstruction};
use serde::{Deserialize, Serialize};

// ---- Optional header keys (xex2_header_keys) ----
const XEX_HEADER_RESOURCE_INFO: u32 = 0x0000_02FF;
const XEX_HEADER_FILE_FORMAT_INFO: u32 = 0x0000_03FF;
const XEX_HEADER_DELTA_PATCH_DESCRIPTOR: u32 = 0x0000_05FF;
const XEX_HEADER_BASE_REFERENCE: u32 = 0x0000_0405;
const XEX_HEADER_BOUNDING_PATH: u32 = 0x0000_80FF;
const XEX_HEADER_DEVICE_ID: u32 = 0x0000_8105;
const XEX_HEADER_ORIGINAL_BASE_ADDRESS: u32 = 0x0001_0001;
const XEX_HEADER_ENTRY_POINT: u32 = 0x0001_0100;
const XEX_HEADER_IMAGE_BASE_ADDRESS: u32 = 0x0001_0201;
const XEX_HEADER_IMPORT_LIBRARIES: u32 = 0x0001_03FF;
const XEX_HEADER_CHECKSUM_TIMESTAMP: u32 = 0x0001_8002;
const XEX_HEADER_ENABLED_FOR_CALLCAP: u32 = 0x0001_8102;
const XEX_HEADER_ENABLED_FOR_FASTCAP: u32 = 0x0001_8200;
const XEX_HEADER_ORIGINAL_PE_NAME: u32 = 0x0001_83FF;
const XEX_HEADER_STATIC_LIBRARIES: u32 = 0x0002_00FF;
const XEX_HEADER_TLS_INFO: u32 = 0x0002_0104;
const XEX_HEADER_DEFAULT_STACK_SIZE: u32 = 0x0002_0200;
const XEX_HEADER_DEFAULT_FILESYSTEM_CACHE_SIZE: u32 = 0x0002_0301;
const XEX_HEADER_DEFAULT_HEAP_SIZE: u32 = 0x0002_0401;
const XEX_HEADER_PAGE_HEAP_SIZE_AND_FLAGS: u32 = 0x0002_8002;
const XEX_HEADER_SYSTEM_FLAGS: u32 = 0x0003_0000;
const XEX_HEADER_EXECUTION_INFO: u32 = 0x0004_0006;
const XEX_HEADER_TITLE_WORKSPACE_SIZE: u32 = 0x0004_0201;
const XEX_HEADER_GAME_RATINGS: u32 = 0x0004_0310;
const XEX_HEADER_LAN_KEY: u32 = 0x0004_0404;
const XEX_HEADER_XBOX360_LOGO: u32 = 0x0004_05FF;
const XEX_HEADER_MULTIDISC_MEDIA_IDS: u32 = 0x0004_06FF;
const XEX_HEADER_ALTERNATE_TITLE_IDS: u32 = 0x0004_07FF;
const XEX_HEADER_ADDITIONAL_TITLE_MEMORY: u32 = 0x0004_0801;
const XEX_HEADER_EXPORTS_BY_NAME: u32 = 0x00E1_0402;

/// Quick check for any XEX magic ("XEX0"/"XEX1"/"XEX2").
pub fn is_xex(data: &[u8]) -> bool {
    data.len() >= 4 && &data[0..3] == b"XEX" && (b'0'..=b'2').contains(&data[3])
}

#[inline]
fn ru16be(data: &[u8], off: usize) -> u16 {
    if off + 2 > data.len() {
        return 0;
    }
    u16::from_be_bytes([data[off], data[off + 1]])
}

#[inline]
fn ru32be(data: &[u8], off: usize) -> u32 {
    if off + 4 > data.len() {
        return 0;
    }
    u32::from_be_bytes([data[off], data[off + 1], data[off + 2], data[off + 3]])
}

#[inline]
fn ru16le(data: &[u8], off: usize) -> u16 {
    if off + 2 > data.len() {
        return 0;
    }
    u16::from_le_bytes([data[off], data[off + 1]])
}

#[inline]
fn ru32le(data: &[u8], off: usize) -> u32 {
    if off + 4 > data.len() {
        return 0;
    }
    u32::from_le_bytes([data[off], data[off + 1], data[off + 2], data[off + 3]])
}

/// XEX version field: major.minor.build.qfe packed into one u32.
pub fn decode_version(v: u32) -> String {
    format!(
        "{}.{}.{}.{}",
        (v >> 28) & 0xF,
        (v >> 24) & 0xF,
        (v >> 8) & 0xFFFF,
        v & 0xFF
    )
}

/// Xbox 360 title ids use the same publisher-code scheme as OG Xbox
/// (e.g. 0x4D5307FA -> "MS-250").
pub fn decode_title_id(title_id: u32) -> String {
    let c1 = (title_id >> 24) as u8;
    let c2 = ((title_id >> 16) & 0xFF) as u8;
    let num = title_id & 0xFFFF;
    if c1.is_ascii_alphanumeric() && c2.is_ascii_alphanumeric() {
        format!("{}{}-{}", c1 as char, c2 as char, num)
    } else {
        format!("{:08X}", title_id)
    }
}


fn decode_module_flags(flags: u32) -> Vec<String> {
    const FLAGS: &[(u32, &str)] = &[
        (0x01, "TITLE_PROCESS"),
        (0x02, "EXPORTS_TO_TITLE"),
        (0x04, "SYSTEM_DEBUGGER"),
        (0x08, "DLL_MODULE"),
        (0x10, "MODULE_PATCH"),
        (0x20, "PATCH_FULL"),
        (0x40, "PATCH_DELTA"),
        (0x80, "USER_MODE"),
    ];
    FLAGS
        .iter()
        .filter(|(bit, _)| flags & bit != 0)
        .map(|(_, n)| n.to_string())
        .collect()
}

fn decode_image_flags(flags: u32) -> Vec<String> {
    const FLAGS: &[(u32, &str)] = &[
        (0x0000_0002, "MANUFACTURING_UTILITY"),
        (0x0000_0004, "MANUFACTURING_SUPPORT_TOOLS"),
        (0x0000_0008, "XGD2_MEDIA_ONLY"),
        (0x0000_0100, "CARDEA_KEY"),
        (0x0000_0200, "XEIKA_KEY"),
        (0x0000_0400, "USERMODE_TITLE"),
        (0x0000_0800, "USERMODE_SYSTEM"),
        (0x0400_0000, "KEYVAULT_PRIVILEGES_REQUIRED"),
        (0x0800_0000, "ONLINE_ACTIVATION_REQUIRED"),
        (0x1000_0000, "PAGE_SIZE_4KB"),
        (0x2000_0000, "REGION_FREE"),
        (0x4000_0000, "REVOCATION_CHECK_OPTIONAL"),
        (0x8000_0000, "REVOCATION_CHECK_REQUIRED"),
    ];
    FLAGS
        .iter()
        .filter(|(bit, _)| flags & bit != 0)
        .map(|(_, n)| n.to_string())
        .collect()
}

fn decode_region(region: u32) -> Vec<String> {
    let mut out = Vec::new();
    if region == 0xFFFF_FFFF {
        return vec!["Region free (all)".to_string()];
    }
    if region & 0x0000_00FF != 0 {
        out.push("NTSC-U".to_string());
    }
    if region & 0x0000_0100 != 0 {
        out.push("NTSC-J (Japan)".to_string());
    }
    if region & 0x0000_0200 != 0 {
        out.push("NTSC-J (China)".to_string());
    }
    if region & 0x00FF_0000 != 0 {
        out.push("PAL".to_string());
    }
    if region & 0xFF00_0000 != 0 {
        out.push("Other/Dev".to_string());
    }
    out
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct XexExecutionInfo {
    pub media_id: u32,
    pub version: String,
    pub base_version: String,
    pub title_id: u32,
    pub title_id_str: String,
    pub platform: u8,
    pub executable_table: u8,
    pub disc_number: u8,
    pub disc_count: u8,
    pub savegame_id: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct XexTlsInfo {
    pub slot_count: u32,
    pub raw_data_address: u32,
    pub data_size: u32,
    pub raw_data_size: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct XexStaticLibrary {
    pub name: String,
    pub version_major: u16,
    pub version_minor: u16,
    pub version_build: u16,
    pub approval_type: u8,
    pub version_qfe: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct XexImportLibrary {
    pub name: String,
    pub id: u32,
    pub version: String,
    pub version_min: String,
    pub import_count: u16,
}

/// One section of the PE image embedded in the XEX.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct XexPeSection {
    pub name: String,
    pub virtual_address: u32,
    pub virtual_size: u32,
    /// Offset of the section data within the extracted PE image.
    pub raw_offset: u32,
    pub raw_size: u32,
    pub characteristics: u32,
    pub executable: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct XexExport {
    pub name: String,
    pub ordinal: u32,
    pub rva: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct XexFileInfo {
    pub filename: String,
    pub file_type: String, // "xex0" / "xex1" / "xex2"
    pub module_flags: u32,
    pub module_flag_names: Vec<String>,
    pub data_offset: u32,
    pub security_offset: u32,
    pub load_address: u32,
    pub image_flags: u32,
    pub image_flag_names: Vec<String>,
    pub region: u32,
    pub region_names: Vec<String>,
    pub entry_point: Option<u32>,
    pub image_base: Option<u32>,
    pub original_pe_name: Option<String>,
    pub default_stack_size: Option<u32>,
    pub default_heap_size: Option<u32>,
    pub system_flags: Option<u32>,
    pub execution_info: Option<XexExecutionInfo>,
    pub tls_info: Option<XexTlsInfo>,
    pub static_libraries: Vec<XexStaticLibrary>,
    pub import_libraries: Vec<XexImportLibrary>,
    /// "none" or "normal" (encrypted).
    pub encryption: String,
    /// "none", "basic" (zero-fill), "normal" (LZX) or "delta".
    pub compression: String,
    /// Whether the embedded PE can be extracted without decryption/LZX.
    pub pe_extractable: bool,
    pub pe_sections: Vec<XexPeSection>,
    pub pe_exports: Vec<XexExport>,
}

/// Where an optional header's payload lives.
#[derive(Clone, Copy)]
enum OptData {
    /// The value field IS the data (low byte of key == 0).
    Inline(u32),
    /// The value field is a file offset to `size` bytes (size = (key & 0xFF) * 4).
    Offset { off: usize, size: usize },
    /// The value field is a file offset to a u32 length prefix followed by data.
    LenPrefixed(usize),
}

fn opt_data(data: &[u8], key: u32, value: u32) -> Option<OptData> {
    let size_field = key & 0xFF;
    if size_field == 0xFF {
        let off = value as usize;
        (off + 4 <= data.len()).then_some(OptData::LenPrefixed(off))
    } else if size_field == 0 {
        Some(OptData::Inline(value))
    } else {
        let off = value as usize;
        let size = (size_field as usize) * 4;
        (off + size <= data.len()).then_some(OptData::Offset { off, size })
    }
}

/// Slice behind a length-prefixed optional header value.
fn len_prefixed(data: &[u8], off: usize) -> Option<&[u8]> {
    if off + 4 > data.len() {
        return None;
    }
    let total = ru32be(data, off) as usize;
    if total < 4 || off + total > data.len() {
        return None;
    }
    Some(&data[off + 4..off + total])
}

/// Parse an XEX (Xbox 360 executable) image's headers and metadata.
pub fn parse_xex(data: &[u8], filename: &str) -> Result<XexFileInfo, String> {
    if !is_xex(data) {
        return Err("Missing XEX0/XEX1/XEX2 magic — not an Xbox 360 executable".to_string());
    }
    if data.len() < 0x18 {
        return Err("File too small to be an XEX".to_string());
    }

    let file_type = String::from_utf8_lossy(&data[0..4]).to_lowercase();
    let module_flags = ru32be(data, 0x04);
    let data_offset = ru32be(data, 0x08);
    let security_offset = ru32be(data, 0x10);
    let header_count = ru32be(data, 0x14);

    let mut entry_point = None;
    let mut image_base = None;
    let mut original_base = None;
    let mut original_pe_name = None;
    let mut default_stack_size = None;
    let mut default_heap_size = None;
    let mut system_flags = None;
    let mut execution_info = None;
    let mut tls_info = None;
    let mut static_libraries = Vec::new();
    let mut import_libraries = Vec::new();
    let mut encryption = "unknown".to_string();
    let mut compression = "unknown".to_string();
    let mut basic_blocks: Option<Vec<(u32, u32)>> = None;

    for i in 0..header_count.min(512) {
        let off = 0x18 + (i as usize) * 8;
        if off + 8 > data.len() {
            break;
        }
        let key = ru32be(data, off);
        let value = ru32be(data, off + 4);
        let od = match opt_data(data, key, value) {
            Some(od) => od,
            None => continue,
        };

        match (key, od) {
            (XEX_HEADER_ENTRY_POINT, OptData::Inline(v)) => entry_point = Some(v),
            (XEX_HEADER_IMAGE_BASE_ADDRESS, OptData::Offset { off, .. }) => {
                image_base = Some(ru32be(data, off))
            }
            (XEX_HEADER_ORIGINAL_BASE_ADDRESS, OptData::Offset { off, .. }) => {
                original_base = Some(ru32be(data, off))
            }
            (XEX_HEADER_DEFAULT_STACK_SIZE, OptData::Inline(v)) => default_stack_size = Some(v),
            (XEX_HEADER_SYSTEM_FLAGS, OptData::Inline(v)) => system_flags = Some(v),
            (XEX_HEADER_DEFAULT_HEAP_SIZE, OptData::Offset { off, .. }) => {
                default_heap_size = Some(ru32be(data, off))
            }
            (XEX_HEADER_ORIGINAL_PE_NAME, OptData::LenPrefixed(off)) => {
                if let Some(bytes) = len_prefixed(data, off) {
                    // Field is padded to a 4-byte boundary with NULs.
                    let trimmed: Vec<u8> = bytes
                        .iter()
                        .take_while(|&&b| b != 0)
                        .copied()
                        .collect();
                    original_pe_name = Some(String::from_utf8_lossy(&trimmed).to_string());
                }
            }
            (XEX_HEADER_TLS_INFO, OptData::Offset { off, .. }) => {
                tls_info = Some(XexTlsInfo {
                    slot_count: ru32be(data, off),
                    raw_data_address: ru32be(data, off + 4),
                    data_size: ru32be(data, off + 8),
                    raw_data_size: ru32be(data, off + 12),
                });
            }
            _ => {}
        }
    }

    // Second pass for the structurally complex optional headers.
    for i in 0..header_count.min(512) {
        let off = 0x18 + (i as usize) * 8;
        if off + 8 > data.len() {
            break;
        }

        let key = ru32be(data, off);
        let value = ru32be(data, off + 4);
        let od = match opt_data(data, key, value) {
            Some(od) => od,
            None => continue,
        };

        match (key, od) {
            (XEX_HEADER_EXECUTION_INFO, OptData::Offset { off, .. })
                if off + 0x18 <= data.len() =>
            {
                let title_id = ru32be(data, off + 0x0C);
                execution_info = Some(XexExecutionInfo {
                    media_id: ru32be(data, off),
                    version: decode_version(ru32be(data, off + 4)),
                    base_version: decode_version(ru32be(data, off + 8)),
                    title_id,
                    title_id_str: decode_title_id(title_id),
                    platform: data[off + 0x10],
                    executable_table: data[off + 0x11],
                    disc_number: data[off + 0x12],
                    disc_count: data[off + 0x13],
                    savegame_id: ru32be(data, off + 0x14),
                });
            }
            (XEX_HEADER_STATIC_LIBRARIES, OptData::LenPrefixed(off)) => {
                if let Some(bytes) = len_prefixed(data, off) {
                    for rec in bytes.chunks_exact(16) {
                        let name_bytes: Vec<u8> =
                            rec[0..8].iter().take_while(|&&b| b != 0).copied().collect();
                        static_libraries.push(XexStaticLibrary {
                            name: String::from_utf8_lossy(&name_bytes).to_string(),
                            version_major: u16::from_be_bytes([rec[8], rec[9]]),
                            version_minor: u16::from_be_bytes([rec[10], rec[11]]),
                            version_build: u16::from_be_bytes([rec[12], rec[13]]),
                            approval_type: rec[14],
                            version_qfe: rec[15],
                        });
                    }
                }
            }
            (XEX_HEADER_IMPORT_LIBRARIES, OptData::LenPrefixed(off)) => {
                import_libraries = parse_import_libraries(data, off);
            }
            (XEX_HEADER_FILE_FORMAT_INFO, OptData::LenPrefixed(off)) => {
                if off + 8 <= data.len() {
                    let enc = ru16be(data, off + 4);
                    let comp = ru16be(data, off + 6);
                    encryption = match enc {
                        0 => "none".to_string(),
                        1 => "normal".to_string(),
                        other => format!("unknown({})", other),
                    };
                    compression = match comp {
                        0 => "none".to_string(),
                        1 => "basic".to_string(),
                        2 => "normal (LZX)".to_string(),
                        3 => "delta".to_string(),
                        other => format!("unknown({})", other),
                    };
                    if comp == 1 {
                        basic_blocks = read_basic_blocks(data);
                    }
                }
            }
            _ => {}
        }
    }

    // ---- Security info (load address, image flags, region) ----
    let mut load_address = 0;
    let mut image_flags = 0;
    let mut region = 0;
    let mut image_size = 0u32;
    let sec_off = security_offset as usize;
    if sec_off + 0x184 <= data.len() {
        image_size = ru32be(data, sec_off + 0x04);
        if file_type == "xex2" {
            image_flags = ru32be(data, sec_off + 0x10C);
            load_address = ru32be(data, sec_off + 0x110);
            region = ru32be(data, sec_off + 0x178);
        } else {
            // XEX0/XEX1 layout (xex1_security_info).
            load_address = ru32be(data, sec_off + 0x120);
            region = ru32be(data, sec_off + 0x138);
            image_flags = ru32be(data, sec_off + 0x13C);
        }
    }

    // ---- Embedded PE ----
    let pe_extractable =
        encryption == "none" && (compression == "none" || compression == "basic");
    let mut pe_sections = Vec::new();
    let mut pe_exports = Vec::new();
    let mut final_image_base = image_base.or(original_base);
    if pe_extractable {
        let pe = extract_pe_image(
            data,
            data_offset as usize,
            &compression,
            &basic_blocks,
            image_size,
        );
        if let Ok(pe) = pe {
            if let Some(parsed) = parse_pe(&pe) {
                if final_image_base.is_none() {
                    final_image_base = Some(parsed.image_base);
                }
                if entry_point.is_none() && parsed.entry_point_rva != 0 {
                    entry_point =
                        Some(parsed.image_base.wrapping_add(parsed.entry_point_rva));
                }
                pe_sections = parsed.sections;
                pe_exports = parsed.exports;
            }
        }
    }

    Ok(XexFileInfo {
        filename: filename.to_string(),
        file_type,
        module_flags,
        module_flag_names: decode_module_flags(module_flags),
        data_offset,
        security_offset,
        load_address,
        image_flags,
        image_flag_names: decode_image_flags(image_flags),
        region,
        region_names: decode_region(region),
        entry_point,
        image_base: final_image_base,
        original_pe_name,
        default_stack_size,
        default_heap_size,
        system_flags,
        execution_info,
        tls_info,
        static_libraries,
        import_libraries,
        encryption,
        compression,
        pe_extractable,
        pe_sections,
        pe_exports,
    })
}

/// Parse the XEX import libraries table (e.g. xam.xex, xboxkrnl.exe).
fn parse_import_libraries(data: &[u8], off: usize) -> Vec<XexImportLibrary> {
    let mut out = Vec::new();
    // xex2_opt_import_libraries: { u32 size, u32 string_table_size, u32 count }
    // Note: xenia models this as { size, string_table { size, count, data } }.
    if off + 12 > data.len() {
        return out;
    }
    let total_size = ru32be(data, off) as usize;
    let string_table_size = ru32be(data, off + 4) as usize;
    let count = ru32be(data, off + 8) as usize;
    let strings_off = off + 12;
    if strings_off + string_table_size > data.len() {
        return out;
    }
    let strings = &data[strings_off..strings_off + string_table_size];
    let mut rec_off = strings_off + string_table_size;
    let end = (off + total_size).min(data.len());

    for _ in 0..count.min(64) {
        // xex2_import_library: size(4) digest(0x14) id(4) version(4)
        //                      version_min(4) name_index(2) count(2) table[count](4)
        if rec_off + 0x28 > end {
            break;
        }
        let id = ru32be(data, rec_off + 0x18);
        let version = ru32be(data, rec_off + 0x1C);
        let version_min = ru32be(data, rec_off + 0x20);
        let name_index = ru16be(data, rec_off + 0x24) as usize;
        let import_count = ru16be(data, rec_off + 0x26);

        let name = if name_index < strings.len() {
            let tail = &strings[name_index..];
            let nul = tail.iter().position(|&b| b == 0).unwrap_or(tail.len());
            String::from_utf8_lossy(&tail[..nul]).to_string()
        } else {
            String::new()
        };

        out.push(XexImportLibrary {
            name,
            id,
            version: decode_version(version),
            version_min: decode_version(version_min),
            import_count,
        });

        rec_off += 0x28 + (import_count as usize) * 4;
    }

    out
}


/// Extract the embedded PE image from an XEX (unencrypted images only).
///
/// * `compression` - the decoded compression string from the file format info
/// * `basic_blocks` - zero-fill blocks for "basic" compression
/// * `image_size` - expected output size from the security info (0 = unknown)
fn extract_pe_image(
    data: &[u8],
    data_offset: usize,
    compression: &str,
    basic_blocks: &Option<Vec<(u32, u32)>>,
    image_size: u32,
) -> Result<Vec<u8>, String> {
    if data_offset >= data.len() {
        return Err("XEX data offset is outside the file".to_string());
    }
    match compression {
        "none" => {
            let end = if image_size > 0 {
                (data_offset + image_size as usize).min(data.len())
            } else {
                data.len()
            };
            Ok(data[data_offset..end].to_vec())
        }
        "basic" => {
            let blocks = basic_blocks
                .as_ref()
                .ok_or_else(|| "Missing basic compression block table".to_string())?;
            let mut out = Vec::new();
            let mut src = data_offset;
            for &(d, z) in blocks {
                let d = d as usize;
                if src + d > data.len() {
                    return Err("Basic compression block overruns the file".to_string());
                }
                out.extend_from_slice(&data[src..src + d]);
                out.resize(out.len() + z as usize, 0);
                src += d;
            }
            if image_size > 0 && out.len() > image_size as usize {
                out.truncate(image_size as usize);
            }
            Ok(out)
        }
        other => Err(format!(
            "XEX image uses {} compression — only unencrypted raw/basic images can be disassembled",
            other
        )),
    }
}

/// Parsed bits of the embedded PE that we care about.
struct ParsedPe {
    image_base: u32,
    entry_point_rva: u32,
    sections: Vec<XexPeSection>,
    exports: Vec<XexExport>,
}

/// Parse the embedded PE32 image (headers are little-endian, as on Windows).
fn parse_pe(pe: &[u8]) -> Option<ParsedPe> {
    if pe.len() < 0x40 || &pe[0..2] != b"MZ" {
        return None;
    }
    let pe_off = ru32le(pe, 0x3C) as usize;
    if pe_off + 24 > pe.len() || &pe[pe_off..pe_off + 4] != b"PE\0\0" {
        return None;
    }
    let coff = pe_off + 4;
    let machine = ru16le(pe, coff);
    // 0x01F0/0x01F1 = PowerPC, 0x01F2 = PowerPC BE (Xenon).
    if !(0x01F0..=0x01F2).contains(&machine) {
        return None;
    }
    let num_sections = ru16le(pe, coff + 2) as usize;
    let opt_size = ru16le(pe, coff + 16) as usize;
    let opt = coff + 20;
    if opt + opt_size > pe.len() || opt_size < 96 {
        return None;
    }
    let entry_point_rva = ru32le(pe, opt + 16);
    let image_base = ru32le(pe, opt + 28);
    let export_rva = ru32le(pe, opt + 96);
    let export_size = ru32le(pe, opt + 100);

    let sec_table = opt + opt_size;
    let mut sections = Vec::new();
    for i in 0..num_sections.min(96) {
        let off = sec_table + i * 40;
        if off + 40 > pe.len() {
            break;
        }
        let name_bytes: Vec<u8> = pe[off..off + 8]
            .iter()
            .take_while(|&&b| b != 0)
            .copied()
            .collect();
        let characteristics = ru32le(pe, off + 36);
        sections.push(XexPeSection {
            name: String::from_utf8_lossy(&name_bytes).to_string(),
            virtual_size: ru32le(pe, off + 8),
            virtual_address: ru32le(pe, off + 12),
            raw_size: ru32le(pe, off + 16),
            raw_offset: ru32le(pe, off + 20),
            characteristics,
            executable: characteristics & 0x2000_0000 != 0 || characteristics & 0x20 != 0,
        });
    }

    let rva_to_off = |rva: u32| -> Option<usize> {
        for s in &sections {
            let span = s.virtual_size.max(s.raw_size);
            if rva >= s.virtual_address && rva < s.virtual_address + span {
                let off = (s.raw_offset + (rva - s.virtual_address)) as usize;
                if off < pe.len() {
                    return Some(off);
                }
            }
        }
        None
    };

    // ---- Export directory (little-endian IMAGE_EXPORT_DIRECTORY) ----
    let mut exports = Vec::new();
    if export_rva != 0 && export_size >= 40 {
        if let Some(ed) = rva_to_off(export_rva) {
            if ed + 40 <= pe.len() {
                let base = ru32le(pe, ed + 16);
                let num_names = ru32le(pe, ed + 24).min(100_000);
                let names_rva = ru32le(pe, ed + 32);
                let ords_rva = ru32le(pe, ed + 36);
                if let (Some(names_off), Some(ords_off)) =
                    (rva_to_off(names_rva), rva_to_off(ords_rva))
                {
                    for i in 0..num_names as usize {
                        let no = names_off + i * 4;
                        let oo = ords_off + i * 2;
                        if no + 4 > pe.len() || oo + 2 > pe.len() {
                            break;
                        }
                        let name_rva = ru32le(pe, no);
                        let ord = base + ru16le(pe, oo) as u32;
                        if let Some(noff) = rva_to_off(name_rva) {
                            let tail = &pe[noff..];
                            let nul = tail
                                .iter()
                                .position(|&b| b == 0)
                                .unwrap_or(tail.len())
                                .min(256);
                            exports.push(XexExport {
                                name: String::from_utf8_lossy(&tail[..nul]).to_string(),
                                ordinal: ord,
                                rva: name_rva,
                            });
                        }
                    }
                }
            }
        }
    }

    Some(ParsedPe {
        image_base,
        entry_point_rva,
        sections,
        exports,
    })
}

/// Disassemble a PE section of an XEX as big-endian PowerPC (Xenon).
///
/// Only works for unencrypted images with raw/basic compression; retail
/// LZX-compressed or encrypted XEXes return an explanatory error.
pub fn disassemble_xex_section(
    data: &[u8],
    section_name: &str,
    max_instructions: usize,
) -> Result<Vec<PpcInstruction>, String> {
    let info = parse_xex(data, "xex")?;
    if info.encryption != "none" {
        return Err(format!(
            "XEX is encrypted ({}) — decryption is not supported",
            info.encryption
        ));
    }
    let section = info
        .pe_sections
        .iter()
        .find(|s| s.name == section_name)
        .ok_or_else(|| format!("PE section '{}' not found", section_name))?
        .clone();
    let blocks = read_basic_blocks(data);
    let pe = extract_pe_image(data, info.data_offset as usize, &info.compression, &blocks, 0)?;
    let start = section.raw_offset as usize;
    let end = (start + section.raw_size as usize).min(pe.len());
    if start >= pe.len() {
        return Err("Section raw data is outside the extracted PE image".to_string());
    }
    let display_base = info
        .image_base
        .unwrap_or(0)
        .wrapping_add(section.virtual_address) as u64;
    Ok(disassemble_ppc_at(
        &pe[..end],
        start,
        display_base,
        max_instructions,
        PpcEndian::Big,
    ))
}

/// Scan the optional headers for the file format info and return the basic
/// (zero-fill) compression block table, if present.
fn read_basic_blocks(data: &[u8]) -> Option<Vec<(u32, u32)>> {
    if data.len() < 0x18 || !is_xex(data) {
        return None;
    }
    let header_count = ru32be(data, 0x14);
    for i in 0..header_count.min(512) {
        let off = 0x18 + (i as usize) * 8;
        if off + 8 > data.len() {
            break;
        }
        if ru32be(data, off) != XEX_HEADER_FILE_FORMAT_INFO {
            continue;
        }
        if let Some(OptData::LenPrefixed(foff)) = opt_data(data, ru32be(data, off), ru32be(data, off + 4)) {
            if foff + 8 > data.len() || ru16be(data, foff + 6) != 1 {
                return None; // not basic compression
            }
            let mut blocks = Vec::new();
            let mut boff = foff + 8;
            while boff + 8 <= data.len() && blocks.len() <= 0x10000 {
                let d = ru32be(data, boff);
                let z = ru32be(data, boff + 4);
                if (d == 0 && z == 0) || d > 0x8000_0000 || z > 0x8000_0000 {
                    break;
                }
                blocks.push((d, z));
                boff += 8;
            }
            return Some(blocks);
        }
    }
    None
}

