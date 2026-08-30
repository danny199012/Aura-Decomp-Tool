//! Static PS1 (R3000A) memory map + address classification.
//!
//! The PlayStation 1's R3000A MIPS core sees a fixed physical address space:
//! the CPU, GPU (GNP), SPU (SP-R), MDEC, VIF/VU coprocessors and the I/O
//! controllers each own a window of that space. This module is a pure lookup
//! table plus query helpers — it carries no state and needs no wiring into
//! `main.rs`. It exists so other modules (`ps1_disasm`, `ps1_analysis`, …) can
//! ask "what does this address mean?" without each re-encoding the map.
//!
//! # Address-space layout (R3000A physical view)
//!
//! | Range                    | Size   | Region                          |
//! |--------------------------|--------|---------------------------------|
//! | `0x1F_F0_0000`–`0x1F_FF_FFFF` | 1 MB | Kernel RAM (boot ROM / OSRAM) |
//! | `0x20_00_0000`–`0x37_EF_FFFF` | ~48 MB| User RAM                        |
//! | `0x30_00_0000`–`0x31_FF_FFFF` | 2 MB | GPU (GNP) registers + framebuffer |
//! | `0x1D_00_0000`           | —      | SPU (SP-R) register window       |
//! | `0x1E_00_0000`–`0x1F_EF_FFFF` | 2 MB | MDEC / VIF / VU registers        |
//! | `0x38_00_0000`           | —      | I/O (CD-ROM) controller          |
//!
//! Note: the GPU window overlaps user RAM in the R3000A's physical map; the
//! classification below resolves that by treating the *lower* bound of a
//! register window as authoritative when both could match.

use serde::Serialize;

/// A named region of PS1 physical address space.
#[derive(Serialize, Clone, Copy, Debug, PartialEq, Eq)]
pub enum MemoryRegion {
    /// Kernel RAM (boot ROM / OSRAM) — `0x1F_F0_0000`–`0x1F_FF_FFFF`.
    KernelRam,
    /// User RAM — `0x20_00_0000`–`0x37_EF_FFFF`.
    UserRam,
    /// GPU (GNP) register window + framebuffer — `0x30_00_0000`–`0x31_FF_FFFF`.
    GpuRegisters,
    /// SPU (SP-R) sound processor registers.
    SpuRegisters,
    /// MDEC / VIF / VU coprocessor registers — `0x1E_00_0000`–`0x1F_EF_FFFF`.
    CoprocessorRegisters,
    /// I/O (CD-ROM) controller.
    IoController,
    /// An address that does not fall into any known region.
    Unknown,
}

/// A single entry in the static memory map: a name, an inclusive range and a
/// short human description. The table is ordered so that more specific
/// (register) windows are checked before their containing RAM regions.
#[derive(Serialize, Clone, Copy, Debug)]
pub struct MemoryRegionEntry {
    pub region: MemoryRegion,
    pub name: &'static str,
    /// Inclusive start of the window.
    pub start: u32,
    /// Inclusive end of the window.
    pub end: u32,
    pub description: &'static str,
}

/// The full static PS1 memory map, in classification priority order.
pub const MEMORY_MAP: &[MemoryRegionEntry] = &[
    MemoryRegionEntry {
        region: MemoryRegion::KernelRam,
        name: "Kernel RAM",
        start: 0x1F_F0_0000,
        end:   0x1F_FF_FFFF,
        description: "Boot ROM / OSRAM (kernel code + data)",
    },
    MemoryRegionEntry {
        region: MemoryRegion::GpuRegisters,
        name: "GPU Registers",
        start: 0x30_00_0000,
        end:   0x31_FF_FFFF,
        description: "GNP (GPU) register window + framebuffer",
    },
    MemoryRegionEntry {
        region: MemoryRegion::SpuRegisters,
        name: "SPU Registers",
        start: 0x1D_00_0000,
        end:   0x1D_FF_FFFF,
        description: "SP-R sound processor registers",
    },
    MemoryRegionEntry {
        region: MemoryRegion::CoprocessorRegisters,
        name: "MDEC/VIF/VU Registers",
        start: 0x1E_00_0000,
        end:   0x1F_EF_FFFF,
        description: "MDEC / VIF / VU coprocessor registers",
    },
    MemoryRegionEntry {
        region: MemoryRegion::IoController,
        name: "I/O Controller",
        start: 0x38_00_0000,
        end:   0x38_FF_FFFF,
        description: "CD-ROM I/O controller registers",
    },
    MemoryRegionEntry {
        region: MemoryRegion::UserRam,
        name: "User RAM",
        start: 0x20_00_0000,
        end:   0x37_EF_FFFF,
        description: "Main user addressable RAM (game code + data)",
    },
];

/// Classify a physical PS1 address into its memory region.
///
/// Register windows are checked before the broad User RAM range so that an
/// overlapping GPU/SPU/MDEC address resolves to the specific device rather
/// than "User RAM". Returns [`MemoryRegion::Unknown`] for addresses outside
/// every window.
pub fn classify_address(addr: u32) -> MemoryRegion {
    // Specific register windows first (they overlap User RAM in the physical map).
    if let Some(entry) = MEMORY_MAP.iter().find(|e| e.region != MemoryRegion::UserRam && addr >= e.start && addr <= e.end) {
        return entry.region;
    }
    // Then the broad user/kernel RAM ranges.
    for entry in MEMORY_MAP {
        if (entry.region == MemoryRegion::UserRam || entry.region == MemoryRegion::KernelRam)
            && addr >= entry.start
            && addr <= entry.end
        {
            return entry.region;
        }
    }
    MemoryRegion::Unknown
}

/// Return the full map entry for an address, if any. Useful when a caller needs
/// the human-readable name/description in addition to the region enum.
pub fn lookup_address(addr: u32) -> Option<&'static MemoryRegionEntry> {
    MEMORY_MAP.iter().find(|e| addr >= e.start && addr <= e.end)
}

/// True if `addr` lies inside user RAM (the range where game code/data lives).
pub fn is_user_ram(addr: u32) -> bool {
    classify_address(addr) == MemoryRegion::UserRam
}

/// True if `addr` lies inside kernel RAM.
pub fn is_kernel_ram(addr: u32) -> bool {
    classify_address(addr) == MemoryRegion::KernelRam
}

/// True if `addr` falls in any device register window (GPU/SPU/MDEC/I-O).
pub fn is_device_register(addr: u32) -> bool {
    matches!(
        classify_address(addr),
        MemoryRegion::GpuRegisters
            | MemoryRegion::SpuRegisters
            | MemoryRegion::CoprocessorRegisters
            | MemoryRegion::IoController
    )
}

/// Format a region for display, e.g. `"User RAM (0x20000000-0x37EFFFFF)"`.
pub fn describe_region(addr: u32) -> String {
    match lookup_address(addr) {
        Some(e) => format!("{} ({:#010X}-{:#010X})", e.name, e.start, e.end),
        None => "Unknown".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_kernel_ram() {
        assert_eq!(classify_address(0x1F_F0_0000), MemoryRegion::KernelRam);
        assert_eq!(classify_address(0x1F_FF_FFFF), MemoryRegion::KernelRam);
        assert!(is_kernel_ram(0x1F_F8_0000));
    }

    #[test]
    fn classifies_user_ram() {
        assert_eq!(classify_address(0x20_00_0000), MemoryRegion::UserRam);
        assert_eq!(classify_address(0x37_EF_FFFF), MemoryRegion::UserRam);
        assert!(is_user_ram(0x24_00_0000));
    }

    #[test]
    fn classifies_gpu_registers() {
        assert_eq!(classify_address(0x30_00_0000), MemoryRegion::GpuRegisters);
        assert_eq!(classify_address(0x31_FF_FFFF), MemoryRegion::GpuRegisters);
        assert!(is_device_register(0x30_01_0000));
    }

    #[test]
    fn classifies_spu_registers() {
        assert_eq!(classify_address(0x1D_00_0000), MemoryRegion::SpuRegisters);
        assert!(is_device_register(0x1D_40_0000));
    }

    #[test]
    fn classifies_coprocessor_registers() {
        assert_eq!(classify_address(0x1E_00_0000), MemoryRegion::CoprocessorRegisters);
        assert_eq!(classify_address(0x1F_EF_FFFF), MemoryRegion::CoprocessorRegisters);
    }

    #[test]
    fn classifies_io_controller() {
        assert_eq!(classify_address(0x38_00_0000), MemoryRegion::IoController);
        assert!(is_device_register(0x38_10_0000));
    }

    #[test]
    fn unknown_outside_all_windows() {
        assert_eq!(classify_address(0x00_00_0000), MemoryRegion::Unknown);
        assert_eq!(classify_address(0xFF_FF_FFFF), MemoryRegion::Unknown);
        assert!(!is_user_ram(0x00_00_0000));
        assert!(!is_kernel_ram(0x00_00_0000));
    }

    #[test]
    fn lookup_returns_entry_with_name() {
        let e = lookup_address(0x24_00_0000).expect("user ram should match");
        assert_eq!(e.name, "User RAM");
        assert_eq!(e.region, MemoryRegion::UserRam);
    }

    #[test]
    fn describe_region_formats_range() {
        let s = describe_region(0x24_00_0000);
        assert!(s.starts_with("User RAM"), "got: {}", s);
        assert!(s.contains("0x20000000"), "got: {}", s);
    }

    #[test]
    fn map_is_serializable() {
        // MEMORY_MAP entries are Serialize; ensure the table itself can be
        // turned into JSON (used by a future Tauri command to expose it).
        let _ = serde_json::to_string(MEMORY_MAP).expect("map must serialize");
    }
}