//! Original Xbox (OG Xbox) support: XBE executable parsing and x86 disassembly.
//!
//! The XBE format is documented on xboxdevwiki.net/Xbe. All header fields are
//! little-endian. Addresses stored in the header are virtual addresses relative
//! to the image base address (typically 0x10000); file offsets for
//! header-resident data are `va - base_address`.
//!
//! Entry point and kernel thunk addresses are XOR-encoded with build-specific
//! keys (a weak obfuscation that also identifies retail/debug builds).

use serde::{Deserialize, Serialize};

// Entry point XOR keys (per the XBE specification).
const ENTRY_POINT_XOR_DEBUG: u32 = 0x9485_9D4B;
const ENTRY_POINT_XOR_RETAIL: u32 = 0xA8FC_57AB;
const ENTRY_POINT_XOR_BETA: u32 = 0xE682_F45B;

// Kernel image thunk address XOR keys.
const KERNEL_THUNK_XOR_DEBUG: u32 = 0x5B6D_40B6;
const KERNEL_THUNK_XOR_RETAIL: u32 = 0xEFB1_F152;

/// Quick check for the XBE magic ("XBEH").
pub fn is_xbe(data: &[u8]) -> bool {
    data.len() >= 4 && &data[0..4] == b"XBEH"
}

/// Which XOR key decoded a plausible address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum XbeBuild {
    Retail,
    Debug,
    Beta,
    /// Neither key produced an address inside the image; raw value reported.
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct XbeLibraryVersion {
    pub name: String,
    pub major: u16,
    pub minor: u16,
    pub build: u16,
    pub qfe: u16,
    pub approved: u8,
    pub debug_build: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct XbeSection {
    pub name: String,
    pub virtual_address: u32,
    pub virtual_size: u32,
    /// Byte offset of the section contents inside the XBE file.
    pub raw_offset: u32,
    pub raw_size: u32,
    pub flags: u32,
    pub writable: bool,
    pub preload: bool,
    pub executable: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct XbeKernelImport {
    pub ordinal: u32,
    pub name: String,
    /// Virtual address of the thunk slot that will hold the import.
    pub thunk_address: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct XbeCertificate {
    pub title_id: u32,
    /// Decoded title id, e.g. "MS-004" (publisher code + game number).
    pub title_id_str: String,
    pub title_name: String,
    pub version: u32,
    pub game_region: u32,
    pub game_region_names: Vec<String>,
    pub allowed_media: u32,
    pub allowed_media_names: Vec<String>,
    pub alternate_title_ids: Vec<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct XbeFileInfo {
    pub filename: String,
    pub file_type: String, // "xbe"
    pub build: XbeBuild,
    pub base_address: u32,
    pub size_of_image: u32,
    pub size_of_headers: u32,
    /// UNIX timestamp of when the image was created.
    pub timestamp: u32,
    pub entry_point: u32,
    pub kernel_thunk_address: u32,
    pub tls_address: u32,
    pub certificate: Option<XbeCertificate>,
    pub sections: Vec<XbeSection>,
    pub library_versions: Vec<XbeLibraryVersion>,
    pub kernel_imports: Vec<XbeKernelImport>,
    pub has_logo_bitmap: bool,
}

/// One disassembled x86 instruction (OG Xbox runs a 32-bit Pentium III).

#[inline]
fn ru16(data: &[u8], off: usize) -> u16 {
    if off + 2 > data.len() {
        return 0;
    }
    u16::from_le_bytes([data[off], data[off + 1]])
}

#[inline]
fn ru32(data: &[u8], off: usize) -> u32 {
    if off + 4 > data.len() {
        return 0;
    }
    u32::from_le_bytes([data[off], data[off + 1], data[off + 2], data[off + 3]])
}

/// Convert a virtual address to a file offset, bounds-checked.
fn va_to_off(va: u32, base: u32, data_len: usize) -> Option<usize> {
    if va < base {
        return None;
    }
    let off = (va - base) as usize;
    if off < data_len {
        Some(off)
    } else {
        None
    }
}

/// Read a NUL-terminated ASCII string stored at a virtual address.
fn read_cstr_at_va(data: &[u8], va: u32, base: u32, max: usize) -> String {
    match va_to_off(va, base, data.len()) {
        Some(off) => {
            let end = data[off..]
                .iter()
                .position(|&b| b == 0)
                .map(|p| off + p)
                .unwrap_or_else(|| data.len().min(off + max));
            let capped = end.min(off + max);
            String::from_utf8_lossy(&data[off..capped]).to_string()
        }
        None => String::new(),
    }
}

/// Try an XOR key and keep the decoded value if it lands inside the image.
fn decode_keyed_addr(encoded: u32, key: u32, base: u32, size_of_image: u32) -> Option<u32> {
    let decoded = encoded ^ key;
    let end = base.saturating_add(size_of_image);
    if decoded >= base && decoded < end {
        Some(decoded)
    } else {
        None
    }
}

fn decode_entry_point(encoded: u32, base: u32, size: u32) -> (u32, XbeBuild) {
    // Retail is by far the most common; try it first, then debug, then beta.
    if let Some(ep) = decode_keyed_addr(encoded, ENTRY_POINT_XOR_RETAIL, base, size) {
        return (ep, XbeBuild::Retail);
    }
    if let Some(ep) = decode_keyed_addr(encoded, ENTRY_POINT_XOR_DEBUG, base, size) {
        return (ep, XbeBuild::Debug);
    }
    if let Some(ep) = decode_keyed_addr(encoded, ENTRY_POINT_XOR_BETA, base, size) {
        return (ep, XbeBuild::Beta);
    }
    (encoded, XbeBuild::Unknown)
}

fn decode_thunk_addr(encoded: u32, base: u32, size: u32) -> (u32, XbeBuild) {
    if let Some(a) = decode_keyed_addr(encoded, KERNEL_THUNK_XOR_RETAIL, base, size) {
        return (a, XbeBuild::Retail);
    }
    if let Some(a) = decode_keyed_addr(encoded, KERNEL_THUNK_XOR_DEBUG, base, size) {
        return (a, XbeBuild::Debug);
    }
    (encoded, XbeBuild::Unknown)
}

fn decode_title_id(title_id: u32) -> String {
    let c1 = (title_id >> 24) as u8;
    let c2 = ((title_id >> 16) & 0xFF) as u8;
    let num = title_id & 0xFFFF;
    if c1.is_ascii_alphanumeric() && c2.is_ascii_alphanumeric() {
        format!("{}{}-{:03}", c1 as char, c2 as char, num)
    } else {
        format!("{:08X}", title_id)
    }
}

fn decode_game_region(region: u32) -> Vec<String> {
    let mut out = Vec::new();
    if region & 0x0000_0001 != 0 {
        out.push("North America (NTSC)".to_string());
    }
    if region & 0x0000_0002 != 0 {
        out.push("Japan (NTSC-J)".to_string());
    }
    if region & 0x0000_0004 != 0 {
        out.push("Europe/Australia (PAL)".to_string());
    }
    if region & 0x8000_0000 != 0 {
        out.push("Debug/Region-free (manufacturing)".to_string());
    }
    if out.is_empty() {
        out.push(format!("Unknown (0x{:08X})", region));
    }
    out
}

fn decode_allowed_media(media: u32) -> Vec<String> {
    const MEDIA: &[(u32, &str)] = &[
        (0x0000_0001, "HARD_DISK"),
        (0x0000_0002, "DVD_X2"),
        (0x0000_0004, "DVD_CD"),
        (0x0000_0008, "CD"),
        (0x0000_0010, "DVD_5_RO"),
        (0x0000_0020, "DVD_9_RO"),
        (0x0000_0040, "DVD_5_RW"),
        (0x0000_0080, "DVD_9_RW"),
        (0x0000_0100, "DONGLE"),
        (0x0000_0200, "MEDIA_BOARD"),
        (0x4000_0000, "NONSECURE_HARD_DISK"),
        (0x8000_0000, "NONSECURE_MODE"),
    ];
    MEDIA
        .iter()
        .filter(|(bit, _)| media & bit != 0)
        .map(|(_, name)| name.to_string())
        .collect()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct X86Instruction {
    pub address: u64,
    pub bytes: Vec<u8>,
    pub text: String,
    pub size: usize,
}


/// Parse an XBE executable image.
pub fn parse_xbe(data: &[u8], filename: &str) -> Result<XbeFileInfo, String> {
    if data.len() < 0x178 {
        return Err("File too small to be an XBE executable".to_string());
    }
    if !is_xbe(data) {
        return Err("Missing XBEH magic — not an original Xbox executable".to_string());
    }

    let base = ru32(data, 0x104);
    let size_of_headers = ru32(data, 0x108);
    let size_of_image = ru32(data, 0x10C);
    let timestamp = ru32(data, 0x114);
    let certificate_va = ru32(data, 0x118);
    let number_of_sections = ru32(data, 0x11C);
    let section_headers_va = ru32(data, 0x120);
    let entry_point_raw = ru32(data, 0x128);
    let tls_va = ru32(data, 0x12C);
    let kernel_thunk_raw = ru32(data, 0x158);
    let number_of_library_versions = ru32(data, 0x160);
    let library_versions_va = ru32(data, 0x164);
    let logo_bitmap_va = ru32(data, 0x170);
    let logo_bitmap_size = ru32(data, 0x174);

    let (entry_point, build) = decode_entry_point(entry_point_raw, base, size_of_image);
    let (kernel_thunk_address, _thunk_build) =
        decode_thunk_addr(kernel_thunk_raw, base, size_of_image);

    // ---- Certificate ----
    let certificate = va_to_off(certificate_va, base, data.len()).map(|off| {
        let title_id = ru32(data, off + 0x08);
        // Title name: 40 UTF-16LE code units at +0x0C.
        let mut title_name = String::new();
        for i in 0..40 {
            let ch = ru16(data, off + 0x0C + i * 2);
            if ch == 0 {
                break;
            }
            title_name.push(char::from_u32(ch as u32).unwrap_or('\u{FFFD}'));
        }
        let alternate_title_ids: Vec<u32> = (0..16)
            .map(|i| ru32(data, off + 0x5C + i * 4))
            .filter(|&id| id != 0)
            .collect();
        let game_region = ru32(data, off + 0xA0);
        let allowed_media = ru32(data, off + 0x9C);
        XbeCertificate {
            title_id,
            title_id_str: decode_title_id(title_id),
            title_name,
            version: ru32(data, off + 0xAC),
            game_region,
            game_region_names: decode_game_region(game_region),
            allowed_media,
            allowed_media_names: decode_allowed_media(allowed_media),
            alternate_title_ids,
        }
    });

    // ---- Sections (56-byte headers) ----
    let mut sections = Vec::new();
    if let Some(sh_off) = va_to_off(section_headers_va, base, data.len()) {
        for i in 0..number_of_sections.min(256) {
            let off = sh_off + (i as usize) * 56;
            if off + 56 > data.len() {
                break;
            }
            let flags = ru32(data, off + 0x00);
            let virtual_address = ru32(data, off + 0x04);
            let virtual_size = ru32(data, off + 0x08);
            let raw_offset = ru32(data, off + 0x0C);
            let raw_size = ru32(data, off + 0x10);
            let name_va = ru32(data, off + 0x14);
            let name = read_cstr_at_va(data, name_va, base, 64);
            sections.push(XbeSection {
                name,
                virtual_address,
                virtual_size,
                raw_offset,
                raw_size,
                flags,
                writable: flags & 0x1 != 0,
                preload: flags & 0x2 != 0,
                executable: flags & 0x4 != 0,
            });
        }
    }

    // ---- Library versions (16 bytes each) ----
    let mut library_versions = Vec::new();
    if let Some(lv_off) = va_to_off(library_versions_va, base, data.len()) {
        for i in 0..number_of_library_versions.min(64) {
            let off = lv_off + (i as usize) * 16;
            if off + 16 > data.len() {
                break;
            }
            let name_bytes: Vec<u8> = data[off..off + 8]
                .iter()
                .take_while(|&&b| b != 0)
                .copied()
                .collect();
            let flags = ru16(data, off + 14);
            library_versions.push(XbeLibraryVersion {
                name: String::from_utf8_lossy(&name_bytes).to_string(),
                major: ru16(data, off + 8),
                minor: ru16(data, off + 10),
                build: ru16(data, off + 12),
                qfe: flags & 0x1FFF,
                approved: ((flags >> 13) & 0x3) as u8,
                debug_build: flags & 0x8000 != 0,
            });
        }
    }

    // ---- Kernel thunk table (imports from xboxkrnl.exe) ----
    let mut kernel_imports = Vec::new();
    if let Some(thunk_off) = va_to_off(kernel_thunk_address, base, data.len()) {
        for i in 0..2048usize {
            let off = thunk_off + i * 4;
            if off + 4 > data.len() {
                break;
            }
            let value = ru32(data, off);
            if value == 0 {
                break; // end of table
            }
            if value & 0x8000_0000 != 0 {
                let ordinal = value & 0x7FFF_FFFF;
                let name = kernel_ordinal_name(ordinal);
                kernel_imports.push(XbeKernelImport {
                    ordinal,
                    name,
                    thunk_address: kernel_thunk_address + (i as u32) * 4,
                });
            }
        }
    }

    Ok(XbeFileInfo {
        filename: filename.to_string(),
        file_type: "xbe".to_string(),
        build,
        base_address: base,
        size_of_image,
        size_of_headers,
        timestamp,
        entry_point,
        kernel_thunk_address,
        tls_address: tls_va,
        certificate,
        sections,
        library_versions,
        kernel_imports,
        has_logo_bitmap: logo_bitmap_va != 0 && logo_bitmap_size != 0,
    })
}

/// Resolve an xboxkrnl.exe ordinal to its export name.
pub fn kernel_ordinal_name(ordinal: u32) -> String {
    KERNEL_ORDINALS
        .binary_search_by_key(&ordinal, |&(n, _)| n)
        .map(|idx| KERNEL_ORDINALS[idx].1.to_string())
        .unwrap_or_else(|_| format!("xboxkrnl_{}", ordinal))
}

/// Disassemble 32-bit x86 code (Intel syntax) from an XBE section.
///
/// * `data` - raw bytes of the code section
/// * `display_address` - virtual address of the first byte
/// * `max_instructions` - decode cap
pub fn disassemble_x86(
    data: &[u8],
    display_address: u64,
    max_instructions: usize,
) -> Vec<X86Instruction> {
    use iced_x86::{Decoder, DecoderOptions, Formatter, IntelFormatter};

    let mut out = Vec::new();
    let mut decoder = Decoder::with_ip(32, data, display_address, DecoderOptions::NONE);
    let mut formatter = IntelFormatter::new();
    let mut text = String::new();

    for instruction in &mut decoder {
        if out.len() >= max_instructions {
            break;
        }
        text.clear();
        formatter.format(&instruction, &mut text);
        let start = (instruction.ip() - display_address) as usize;
        let end = start + instruction.len();
        let bytes = if end <= data.len() {
            data[start..end].to_vec()
        } else {
            Vec::new()
        };
        out.push(X86Instruction {
            address: instruction.ip(),
            bytes,
            text: text.clone(),
            size: instruction.len(),
        });
    }

    out
}

/// Disassemble one named section of an XBE file (used by the Tauri command).
pub fn disassemble_xbe_section(
    data: &[u8],
    section_name: &str,
    max_instructions: usize,
) -> Result<Vec<X86Instruction>, String> {
    let info = parse_xbe(data, "xbe")?;
    let section = info
        .sections
        .iter()
        .find(|s| s.name == section_name)
        .ok_or_else(|| format!("Section '{}' not found", section_name))?;
    let start = section.raw_offset as usize;
    let end = (start + section.raw_size as usize).min(data.len());
    if start >= data.len() {
        return Err("Section raw data is outside the file".to_string());
    }
    Ok(disassemble_x86(
        &data[start..end],
        section.virtual_address as u64,
        max_instructions,
    ))
}

/// xboxkrnl.exe exports by ordinal (full retail table, via xboxdevwiki.net/Kernel).
/// Variable exports (OBJECT_TYPE, keys, etc.) are included; they appear in
/// thunk tables too.
static KERNEL_ORDINALS: &[(u32, &str)] = &[
    (1, "AvGetSavedDataAddress"),
    (2, "AvSendTVEncoderOption"),
    (3, "AvSetDisplayMode"),
    (4, "AvSetSavedDataAddress"),
    (5, "DbgBreakPoint"),
    (6, "DbgBreakPointWithStatus"),
    (7, "DbgLoadImageSymbols"),
    (8, "DbgPrint"),
    (9, "HalReadSMCTrayState"),
    (10, "DbgPrompt"),
    (11, "DbgUnLoadImageSymbols"),
    (12, "ExAcquireReadWriteLockExclusive"),
    (13, "ExAcquireReadWriteLockShared"),
    (14, "ExAllocatePool"),
    (15, "ExAllocatePoolWithTag"),
    (16, "ExEventObjectType"),
    (17, "ExFreePool"),
    (18, "ExInitializeReadWriteLock"),
    (19, "ExInterlockedAddLargeInteger"),
    (20, "ExInterlockedAddLargeStatistic"),
    (21, "ExInterlockedCompareExchange64"),
    (22, "ExMutantObjectType"),
    (23, "ExQueryPoolBlockSize"),
    (24, "ExQueryNonVolatileSetting"),
    (25, "ExReadWriteRefurbInfo"),
    (26, "ExRaiseException"),
    (27, "ExRaiseStatus"),
    (28, "ExReleaseReadWriteLock"),
    (29, "ExSaveNonVolatileSetting"),
    (30, "ExSemaphoreObjectType"),
    (31, "ExTimerObjectType"),
    (32, "ExfInterlockedInsertHeadList"),
    (33, "ExfInterlockedInsertTailList"),
    (34, "ExfInterlockedRemoveHeadList"),
    (35, "FscGetCacheSize"),
    (36, "FscInvalidateIdleBlocks"),
    (37, "FscSetCacheSize"),
    (38, "HalClearSoftwareInterrupt"),
    (39, "HalDisableSystemInterrupt"),
    (40, "HalDiskCachePartitionCount"),
    (41, "HalDiskModelNumber"),
    (42, "HalDiskSerialNumber"),
    (43, "HalEnableSystemInterrupt"),
    (44, "HalGetInterruptVector"),
    (45, "HalReadSMBusValue"),
    (46, "HalReadWritePCISpace"),
    (47, "HalRegisterShutdownNotification"),
    (48, "HalRequestSoftwareInterrupt"),
    (49, "HalReturnToFirmware"),
    (50, "HalWriteSMBusValue"),
    (51, "InterlockedCompareExchange"),
    (52, "InterlockedDecrement"),
    (53, "InterlockedIncrement"),
    (54, "InterlockedExchange"),
    (55, "InterlockedExchangeAdd"),
    (56, "InterlockedFlushSList"),
    (57, "InterlockedPopEntrySList"),
    (58, "InterlockedPushEntrySList"),
    (59, "IoAllocateIrp"),
    (60, "IoBuildAsynchronousFsdRequest"),
    (61, "IoBuildDeviceIoControlRequest"),
    (62, "IoBuildSynchronousFsdRequest"),
    (63, "IoCheckShareAccess"),
    (64, "IoCompletionObjectType"),
    (65, "IoCreateDevice"),
    (66, "IoCreateFile"),
    (67, "IoCreateSymbolicLink"),
    (68, "IoDeleteDevice"),
    (69, "IoDeleteSymbolicLink"),
    (70, "IoDeviceObjectType"),
    (71, "IoFileObjectType"),
    (72, "IoFreeIrp"),
    (73, "IoInitializeIrp"),
    (74, "IoInvalidDeviceRequest"),
    (75, "IoQueryFileInformation"),
    (76, "IoQueryVolumeInformation"),
    (77, "IoQueueThreadIrp"),
    (78, "IoRemoveShareAccess"),
    (79, "IoSetIoCompletion"),
    (80, "IoSetShareAccess"),
    (81, "IoStartNextPacket"),
    (82, "IoStartNextPacketByKey"),
    (83, "IoStartPacket"),
    (84, "IoSynchronousDeviceIoControlRequest"),
    (85, "IoSynchronousFsdRequest"),
    (86, "IofCallDriver"),
    (87, "IofCompleteRequest"),
    (88, "KdDebuggerEnabled"),
    (89, "KdDebuggerNotPresent"),
    (90, "IoDismountVolume"),
    (91, "IoDismountVolumeByName"),
    (92, "KeAlertResumeThread"),
    (93, "KeAlertThread"),
    (94, "KeBoostPriorityThread"),
    (95, "KeBugCheck"),
    (96, "KeBugCheckEx"),
    (97, "KeCancelTimer"),
    (98, "KeConnectInterrupt"),
    (99, "KeDelayExecutionThread"),
    (100, "KeDisconnectInterrupt"),
    (101, "KeEnterCriticalRegion"),
    (102, "MmGlobalData"),
    (103, "KeGetCurrentIrql"),
    (104, "KeGetCurrentThread"),
    (105, "KeInitializeApc"),
    (106, "KeInitializeDeviceQueue"),
    (107, "KeInitializeDpc"),
    (108, "KeInitializeEvent"),
    (109, "KeInitializeInterrupt"),
    (110, "KeInitializeMutant"),
    (111, "KeInitializeQueue"),
    (112, "KeInitializeSemaphore"),
    (113, "KeInitializeTimerEx"),
    (114, "KeInsertByKeyDeviceQueue"),
    (115, "KeInsertDeviceQueue"),
    (116, "KeInsertHeadQueue"),
    (117, "KeInsertQueue"),
    (118, "KeInsertQueueApc"),
    (119, "KeInsertQueueDpc"),
    (120, "KeInterruptTime"),
    (121, "KeIsExecutingDpc"),
    (122, "KeLeaveCriticalRegion"),
    (123, "KePulseEvent"),
    (124, "KeQueryBasePriorityThread"),
    (125, "KeQueryInterruptTime"),
    (126, "KeQueryPerformanceCounter"),
    (127, "KeQueryPerformanceFrequency"),
    (128, "KeQuerySystemTime"),
    (129, "KeRaiseIrqlToDpcLevel"),
    (130, "KeRaiseIrqlToSynchLevel"),
    (131, "KeReleaseMutant"),
    (132, "KeReleaseSemaphore"),
    (133, "KeRemoveByKeyDeviceQueue"),
    (134, "KeRemoveDeviceQueue"),
    (135, "KeRemoveEntryDeviceQueue"),
    (136, "KeRemoveQueue"),
    (137, "KeRemoveQueueDpc"),
    (138, "KeResetEvent"),
    (139, "KeRestoreFloatingPointState"),
    (140, "KeResumeThread"),
    (141, "KeRundownQueue"),
    (142, "KeSaveFloatingPointState"),
    (143, "KeSetBasePriorityThread"),
    (144, "KeSetDisableBoostThread"),
    (145, "KeSetEvent"),
    (146, "KeSetEventBoostPriority"),
    (147, "KeSetPriorityProcess"),
    (148, "KeSetPriorityThread"),
    (149, "KeSetTimer"),
    (150, "KeSetTimerEx"),
    (151, "KeStallExecutionProcessor"),
    (152, "KeSuspendThread"),
    (153, "KeSynchronizeExecution"),
    (154, "KeSystemTime"),
    (155, "KeTestAlertThread"),
    (156, "KeTickCount"),
    (157, "KeTimeIncrement"),
    (158, "KeWaitForMultipleObjects"),
    (159, "KeWaitForSingleObject"),
    (160, "KfRaiseIrql"),
    (161, "KfLowerIrql"),
    (162, "KiBugCheckData"),
    (163, "KiUnlockDispatcherDatabase"),
    (164, "LaunchDataPage"),
    (165, "MmAllocateContiguousMemory"),
    (166, "MmAllocateContiguousMemoryEx"),
    (167, "MmAllocateSystemMemory"),
    (168, "MmClaimGpuInstanceMemory"),
    (169, "MmCreateKernelStack"),
    (170, "MmDeleteKernelStack"),
    (171, "MmFreeContiguousMemory"),
    (172, "MmFreeSystemMemory"),
    (173, "MmGetPhysicalAddress"),
    (174, "MmIsAddressValid"),
    (175, "MmLockUnlockBufferPages"),
    (176, "MmLockUnlockPhysicalPage"),
    (177, "MmMapIoSpace"),
    (178, "MmPersistContiguousMemory"),
    (179, "MmQueryAddressProtect"),
    (180, "MmQueryAllocationSize"),
    (181, "MmQueryStatistics"),
    (182, "MmSetAddressProtect"),
    (183, "MmUnmapIoSpace"),
    (184, "NtAllocateVirtualMemory"),
    (185, "NtCancelTimer"),
    (186, "NtClearEvent"),
    (187, "NtClose"),
    (188, "NtCreateDirectoryObject"),
    (189, "NtCreateEvent"),
    (190, "NtCreateFile"),
    (191, "NtCreateIoCompletion"),
    (192, "NtCreateMutant"),
    (193, "NtCreateSemaphore"),
    (194, "NtCreateTimer"),
    (195, "NtDeleteFile"),
    (196, "NtDeviceIoControlFile"),
    (197, "NtDuplicateObject"),
    (198, "NtFlushBuffersFile"),
    (199, "NtFreeVirtualMemory"),
    (200, "NtFsControlFile"),
    (201, "NtOpenDirectoryObject"),
    (202, "NtOpenFile"),
    (203, "NtOpenSymbolicLinkObject"),
    (204, "NtProtectVirtualMemory"),
    (205, "NtPulseEvent"),
    (206, "NtQueueApcThread"),
    (207, "NtQueryDirectoryFile"),
    (208, "NtQueryDirectoryObject"),
    (209, "NtQueryEvent"),
    (210, "NtQueryFullAttributesFile"),
    (211, "NtQueryInformationFile"),
    (212, "NtQueryIoCompletion"),
    (213, "NtQueryMutant"),
    (214, "NtQuerySemaphore"),
    (215, "NtQuerySymbolicLinkObject"),
    (216, "NtQueryTimer"),
    (217, "NtQueryVirtualMemory"),
    (218, "NtQueryVolumeInformationFile"),
    (219, "NtReadFile"),
    (220, "NtReadFileScatter"),
    (221, "NtReleaseMutant"),
    (222, "NtReleaseSemaphore"),
    (223, "NtRemoveIoCompletion"),
    (224, "NtResumeThread"),
    (225, "NtSetEvent"),
    (226, "NtSetInformationFile"),
    (227, "NtSetIoCompletion"),
    (228, "NtSetSystemTime"),
    (229, "NtSetTimerEx"),
    (230, "NtSignalAndWaitForSingleObjectEx"),
    (231, "NtSuspendThread"),
    (232, "NtUserIoApcDispatcher"),
    (233, "NtWaitForSingleObject"),
    (234, "NtWaitForSingleObjectEx"),
    (235, "NtWaitForMultipleObjectsEx"),
    (236, "NtWriteFile"),
    (237, "NtWriteFileGather"),
    (238, "NtYieldExecution"),
    (239, "ObCreateObject"),
    (240, "ObDirectoryObjectType"),
    (241, "ObInsertObject"),
    (242, "ObMakeTemporaryObject"),
    (243, "ObOpenObjectByName"),
    (244, "ObOpenObjectByPointer"),
    (245, "ObpObjectHandleTable"),
    (246, "ObReferenceObjectByHandle"),
    (247, "ObReferenceObjectByName"),
    (248, "ObReferenceObjectByPointer"),
    (249, "ObSymbolicLinkObjectType"),
    (250, "ObfDereferenceObject"),
    (251, "ObfReferenceObject"),
    (252, "PhyGetLinkState"),
    (253, "PhyInitialize"),
    (254, "PsCreateSystemThread"),
    (255, "PsCreateSystemThreadEx"),
    (256, "PsQueryStatistics"),
    (257, "PsSetCreateThreadNotifyRoutine"),
    (258, "PsTerminateSystemThread"),
    (259, "PsThreadObjectType"),
    (260, "RtlAnsiStringToUnicodeString"),
    (261, "RtlAppendStringToString"),
    (262, "RtlAppendUnicodeStringToString"),
    (263, "RtlAppendUnicodeToString"),
    (264, "RtlAssert"),
    (265, "RtlCaptureContext"),
    (266, "RtlCaptureStackBackTrace"),
    (267, "RtlCharToInteger"),
    (268, "RtlCompareMemory"),
    (269, "RtlCompareMemoryUlong"),
    (270, "RtlCompareString"),
    (271, "RtlCompareUnicodeString"),
    (272, "RtlCopyString"),
    (273, "RtlCopyUnicodeString"),
    (274, "RtlCreateUnicodeString"),
    (275, "RtlDowncaseUnicodeChar"),
    (276, "RtlDowncaseUnicodeString"),
    (277, "RtlEnterCriticalSection"),
    (278, "RtlEnterCriticalSectionAndRegion"),
    (279, "RtlEqualString"),
    (280, "RtlEqualUnicodeString"),
    (281, "RtlExtendedIntegerMultiply"),
    (282, "RtlExtendedLargeIntegerDivide"),
    (283, "RtlExtendedMagicDivide"),
    (284, "RtlFillMemory"),
    (285, "RtlFillMemoryUlong"),
    (286, "RtlFreeAnsiString"),
    (287, "RtlFreeUnicodeString"),
    (288, "RtlGetCallersAddress"),
    (289, "RtlInitAnsiString"),
    (290, "RtlInitUnicodeString"),
    (291, "RtlInitializeCriticalSection"),
    (292, "RtlIntegerToChar"),
    (293, "RtlIntegerToUnicodeString"),
    (294, "RtlLeaveCriticalSection"),
    (295, "RtlLeaveCriticalSectionAndRegion"),
    (296, "RtlLowerChar"),
    (297, "RtlMapGenericMask"),
    (298, "RtlMoveMemory"),
    (299, "RtlMultiByteToUnicodeN"),
    (300, "RtlMultiByteToUnicodeSize"),
    (301, "RtlNtStatusToDosError"),
    (302, "RtlRaiseException"),
    (303, "RtlRaiseStatus"),
    (304, "RtlTimeFieldsToTime"),
    (305, "RtlTimeToTimeFields"),
    (306, "RtlTryEnterCriticalSection"),
    (307, "RtlUlongByteSwap"),
    (308, "RtlUnicodeStringToAnsiString"),
    (309, "RtlUnicodeStringToInteger"),
    (310, "RtlUnicodeToMultiByteN"),
    (311, "RtlUnicodeToMultiByteSize"),
    (312, "RtlUnwind"),
    (313, "RtlUpcaseUnicodeChar"),
    (314, "RtlUpcaseUnicodeString"),
    (315, "RtlUpcaseUnicodeToMultiByteN"),
    (316, "RtlUpperChar"),
    (317, "RtlUpperString"),
    (318, "RtlUshortByteSwap"),
    (319, "RtlWalkFrameChain"),
    (320, "RtlZeroMemory"),
    (321, "XboxEEPROMKey"),
    (322, "XboxHardwareInfo"),
    (323, "XboxHDKey"),
    (324, "XboxKrnlVersion"),
    (325, "XboxSignatureKey"),
    (326, "XeImageFileName"),
    (327, "XeLoadSection"),
    (328, "XeUnloadSection"),
    (329, "READ_PORT_BUFFER_UCHAR"),
    (330, "READ_PORT_BUFFER_USHORT"),
    (331, "READ_PORT_BUFFER_ULONG"),
    (332, "WRITE_PORT_BUFFER_UCHAR"),
    (333, "WRITE_PORT_BUFFER_USHORT"),
    (334, "WRITE_PORT_BUFFER_ULONG"),
    (335, "XcSHAInit"),
    (336, "XcSHAUpdate"),
    (337, "XcSHAFinal"),
    (338, "XcRC4Key"),
    (339, "XcRC4Crypt"),
    (340, "XcHMAC"),
    (341, "XcPKEncPublic"),
    (342, "XcPKDecPrivate"),
    (343, "XcPKGetKeyLen"),
    (344, "XcVerifyPKCS1Signature"),
    (345, "XcModExp"),
    (346, "XcDESKeyParity"),
    (347, "XcKeyTable"),
    (348, "XcBlockCrypt"),
    (349, "XcBlockCryptCBC"),
    (350, "XcCryptService"),
    (351, "XcUpdateCrypto"),
    (352, "RtlRip"),
    (353, "XboxLANKey"),
    (354, "XboxAlternateSignatureKeys"),
    (355, "XePublicKeyData"),
    (356, "HalBootSMCVideoMode"),
    (357, "IdexChannelObject"),
    (358, "HalIsResetOrShutdownPending"),
    (359, "IoMarkIrpMustComplete"),
    (360, "HalInitiateShutdown"),
    (361, "RtlSnprintf"),
    (362, "RtlSprintf"),
    (363, "RtlVsnprintf"),
    (364, "RtlVsprintf"),
    (365, "HalEnableSecureTrayEject"),
    (366, "HalWriteSMCScratchRegister"),
    (370, "XProfpControl"),
    (371, "XProfpGetData"),
    (372, "IrtClientInitFast"),
    (373, "IrtSweep"),
    (374, "MmDbgAllocateMemory"),
    (375, "MmDbgFreeMemory"),
    (376, "MmDbgQueryAvailablePages"),
    (377, "MmDbgReleaseAddress"),
    (378, "MmDbgWriteCheck"),
];


