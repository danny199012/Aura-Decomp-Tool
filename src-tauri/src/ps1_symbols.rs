//! PS1-specific symbol database and scanner.
//!
//! Mirrors [`crate::sce_symbol_scanner`] but targets PlayStation 1 libraries:
//! libsd (sound driver), libcd (CD-ROM I/O), libspuc (SPU control), the
//! kernel/system call surface, and common runtime helpers. The architecture is
//! identical — a static database of known symbol names plus a scanner that
//! walks an ELF's sections looking for references to those symbols.

use serde::Serialize;

/// A single known PS1 library/kernel symbol.
#[derive(Debug)]
pub struct Ps1Symbol {
    /// Symbol name as it appears in the binary (e.g. `sdOpen`, `CdRead`).
    pub name: &'static str,
    /// Library / subsystem it belongs to (e.g. "libsd", "kernel").
    pub library: &'static str,
    /// Short human-readable description of what the symbol does.
    pub description: &'static str,
}

/// A match found in an ELF section referencing a known PS1 symbol.
#[derive(Serialize, Debug)]
pub struct Ps1SymbolMatch {
    /// The matched symbol name.
    pub symbol: String,
    /// Library / subsystem the symbol belongs to.
    pub library: String,
    /// Human-readable description of the symbol.
    pub description: String,
    /// Section index where the reference was found.
    pub section_index: usize,
    /// Name of the section (e.g. `.text`, `.rodata`).
    pub section_name: String,
    /// Offset within the section where the match occurred.
    pub offset: u32,
}

/// Result of scanning an ELF for PS1 symbol references.
#[derive(Serialize, Debug)]
pub struct Ps1SymbolScanResult {
    pub matches: Vec<Ps1SymbolMatch>,
    /// Total number of distinct symbols matched.
    pub total_matches: usize,
    /// Breakdown by library (e.g. libsd -> 5).
    pub per_library: std::collections::HashMap<String, usize>,
}

/// The static PS1 symbol database.
///
/// Covers the major PS1 SDK libraries and kernel entry points that commonly
/// appear in decompiled binaries. Extend as needed.
pub fn ps1_symbol_db() -> Vec<Ps1Symbol> {
    vec![
        // ── libsd (Sound Driver) ────────────────────────────────────────
        Ps1Symbol { name: "sdOpen", library: "libsd", description: "Open the sound driver" },
        Ps1Symbol { name: "sdClose", library: "libsd", description: "Close the sound driver" },
        Ps1Symbol { name: "sdSendCmd", library: "libsd", description: "Send a command to the SPU" },
        Ps1Symbol { name: "sdRecvMsg", library: "libsd", description: "Receive a message from the SPU" },
        Ps1Symbol { name: "sdSetMsgHandler", library: "libsd", description: "Register an SPU message handler" },
        Ps1Symbol { name: "sdSendData", library: "libsd", description: "Send data to the SPU (voice/position)" },
        Ps1Symbol { name: "sdRecvData", library: "libsd", description: "Receive data from the SPU" },
        Ps1Symbol { name: "sdSetVoice", library: "libsd", description: "Configure a voice channel" },
        Ps1Symbol { name: "sdSetPos", library: "libsd", description: "Set playback position" },
        Ps1Symbol { name: "sdGetStatus", library: "libsd", description: "Query SPU status" },
        Ps1Symbol { name: "sdInit", library: "libsd", description: "Initialize the sound driver" },

        // ── libcd (CD-ROM I/O) ───────────────────────────────────────────
        Ps1Symbol { name: "CdOpen", library: "libcd", description: "Open a CD file for reading" },
        Ps1Symbol { name: "CdClose", library: "libcd", description: "Close an open CD file" },
        Ps1Symbol { name: "CdRead", library: "libcd", description: "Read data from the CD" },
        Ps1Symbol { name: "CdLseek", library: "libcd", description: "Seek within a CD file" },
        Ps1Symbol { name: "CdControl", library: "libcd", description: "Send control commands to the CD drive" },
        Ps1Symbol { name: "CdInit", library: "libcd", description: "Initialize the CD driver" },
        Ps1Symbol { name: "CdSync", library: "libcd", description: "Synchronize CD operations" },
        Ps1Symbol { name: "CdStop", library: "libcd", description: "Stop CD playback" },
        Ps1Symbol { name: "CdReadPos", library: "libcd", description: "Get current read position" },

        // ── libspuc (SPU Control) ────────────────────────────────────────
        Ps1Symbol { name: "spuInit", library: "libspuc", description: "Initialize SPU control" },
        Ps1Symbol { name: "spuSetVoice", library: "libspuc", description: "Configure SPU voice parameters" },
        Ps1Symbol { name: "spuGetStatus", library: "libspuc", description: "Query SPU status registers" },

        // ── Kernel / System Calls (OSD) ──────────────────────────────────
        Ps1Symbol { name: "osdBoot", library: "kernel", description: "OS boot entry point" },
        Ps1Symbol { name: "osdMain", library: "kernel", description: "OS main loop entry" },
        Ps1Symbol { name: "osdExit", library: "kernel", description: "Terminate the application" },
        Ps1Symbol { name: "osdDelay", library: "kernel", description: "Yield CPU for N ticks" },
        Ps1Symbol { name: "osdGetTime", library: "kernel", description: "Get current system time (ticks)" },
        Ps1Symbol { name: "osdSetTimer", library: "kernel", description: "Set a hardware timer" },
        Ps1Symbol { name: "osdEnableInt", library: "kernel", description: "Enable an interrupt source" },
        Ps1Symbol { name: "osdDisableInt", library: "kernel", description: "Disable an interrupt source" },
        Ps1Symbol { name: "osdSetIntHandler", library: "kernel", description: "Register an interrupt handler" },
        Ps1Symbol { name: "osdPrintf", library: "kernel", description: "Kernel printf (debug)" },
        Ps1Symbol { name: "osdMalloc", library: "kernel", description: "Allocate memory from the kernel heap" },
        Ps1Symbol { name: "osdFree", library: "kernel", description: "Free kernel-allocated memory" },

        // ── Memory / DMA (common in PS1 games) ───────────────────────────
        Ps1Symbol { name: "MemAlloc", library: "memory", description: "Allocate from the game's memory pool" },
        Ps1Symbol { name: "MemFree", library: "memory", description: "Free a memory pool allocation" },
        Ps1Symbol { name: "DmaCopy", library: "dma", description: "DMA copy (GPU/SPU)" },

        // ── Common runtime helpers ───────────────────────────────────────
        Ps1Symbol { name: "_main", library: "runtime", description: "C main entry point" },
        Ps1Symbol { name: "start", library: "runtime", description: "Startup / initialization routine" },
        Ps1Symbol { name: "exit", library: "runtime", description: "Program exit handler" },
    ]
}

/// Scan ELF sections for references to known PS1 symbols.
///
/// This is a lightweight string-based scan: it looks for the symbol names
/// appearing as ASCII strings within section data (typically `.rodata` or
/// `.strtab`). It does NOT perform full symbol-table resolution — that's
/// handled by the ELF parser itself. This complements it by flagging which
/// known PS1 SDK functions are referenced, giving the user a quick "this game
/// uses libsd for audio" style overview.
pub fn scan_ps1_symbol_matches(sections: &[crate::ElfSection]) -> Vec<Ps1SymbolMatch> {
    let db = ps1_symbol_db();
    let mut matches = Vec::new();

    for (sec_idx, sec) in sections.iter().enumerate() {
        // Only scan string-like and data sections where symbol names would appear.
        if !is_scannable_section(sec) {
            continue;
        }

        let data = &sec.data;
        for sym in &db {
            let needle = sym.name.as_bytes();
            if needle.len() < 4 {
                continue; // skip very short names to avoid false positives
            }
            // Sliding window search for the ASCII name within section data.
            if data.len() >= needle.len() {
                for i in 0..(data.len() - needle.len()) {
                    if &data[i..i + needle.len()] == needle {
                        matches.push(Ps1SymbolMatch {
                            symbol: sym.name.to_string(),
                            library: sym.library.to_string(),
                            description: sym.description.to_string(),
                            section_index: sec_idx,
                            section_name: sec.name.clone(),
                            offset: i as u32,
                        });
                        break; // one match per symbol per section is enough
                    }
                }
            }
        }
    }

    matches
}

/// Determine whether a section is worth scanning for symbol name strings.
fn is_scannable_section(sec: &crate::ElfSection) -> bool {
    let name = sec.name.as_str();
    // Scan string tables, rodata, and any section that might contain names.
    matches!(name, ".strtab" | ".rodata" | ".text" | ".data") || name.starts_with(".str")
}

/// Tauri command wrapper that parses an ELF and returns its PS1 SDK
/// symbol-reference matches. Wired into `generate_handler!` in main.rs.
#[tauri::command]
pub fn scan_ps1_symbols(path: String) -> Result<Ps1SymbolScanResult, String> {
    let info = crate::parse_elf_file(path)?;
    Ok(build_ps1_scan_result(&info.sections))
}

/// Build the full scan result from a set of sections.
pub fn build_ps1_scan_result(sections: &[crate::ElfSection]) -> Ps1SymbolScanResult {
    let matches = scan_ps1_symbol_matches(sections);
    let total = matches.len();

    let mut per_library: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    for m in &matches {
        *per_library.entry(m.library.clone()).or_insert(0) += 1;
    }

    Ps1SymbolScanResult { matches, total_matches: total, per_library }
}