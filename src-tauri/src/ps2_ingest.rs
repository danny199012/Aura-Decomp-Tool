//! One-click PS2 ingest: disc image → boot ELF → ps2recomp-ready project.
//!
//! Given a PS2 disc image (`.iso`, `.bin`+`.cue`, raw 2352-byte `.bin`) this
//! module:
//!
//! 1. reads the ISO9660 volume ([`crate::disc`]),
//! 2. parses `SYSTEM.CNF` to find the boot executable (`BOOT2 = cdrom0:\SLUS_203.12;1`),
//! 3. extracts the executables (or the whole disc) into a workspace,
//! 4. analyses the boot ELF with the existing engine (function detection +
//!    embedded SCE SDK symbol matching),
//! 5. writes a `config.toml` + `functions.csv` that `ps2_recomp` consumes, and
//! 6. optionally runs `ps2_recomp` if the user pointed Aura at the binary.
//!
//! What this module deliberately does **not** do: compile the generated C++ or
//! provide the PS2 runtime. Those come from the upstream ps2recomp project
//! (CMake + a C++20 compiler + `ps2xRuntime`); the generated `README.md` and
//! the manifest's `next_steps` say exactly how to finish the build.
//!
//! Pure Rust (no Tauri) so the GUI, the CLI and the test suite share one path.

use crate::disc::{self, DiscEntry, DiscImage, ExtractProgress};
use crate::engine;
use crate::psx_exe::{self, PsxExeInfo};
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::{Read, Seek};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

// ---------------------------------------------------------------------------
// SYSTEM.CNF / serial / region
// ---------------------------------------------------------------------------

/// The keys of `SYSTEM.CNF` Aura cares about.
#[derive(Debug, Clone, Default, Serialize)]
pub struct SystemCnf {
    /// PS1 boot line (`BOOT = cdrom:\SLUS_000.00;1`).
    pub boot: Option<String>,
    /// PS2 boot line (`BOOT2 = cdrom0:\SLUS_203.12;1`).
    pub boot2: Option<String>,
    pub ver: Option<String>,
    pub vmode: Option<String>,
}

/// Parse `SYSTEM.CNF`. Tolerates CRLF/LF, stray NULs, spaces around `=`,
/// lower-case keys and comments; ignores everything it does not recognise.
pub fn parse_system_cnf(text: &str) -> SystemCnf {
    let mut cnf = SystemCnf::default();
    for raw in text.split(['\n', '\r']) {
        let line = raw.trim_matches(|c: char| c.is_whitespace() || c == '\0');
        if line.is_empty() || line.starts_with(';') || line.starts_with('#') {
            continue;
        }
        let Some((k, v)) = line.split_once('=') else { continue };
        let val = v.trim().trim_matches('\0').to_string();
        if val.is_empty() {
            continue;
        }
        match k.trim().to_ascii_uppercase().as_str() {
            "BOOT2" => cnf.boot2 = Some(val),
            "BOOT" => cnf.boot = Some(val),
            "VER" => cnf.ver = Some(val),
            "VMODE" => cnf.vmode = Some(val),
            _ => {}
        }
    }
    cnf
}

/// Turn a `SYSTEM.CNF` boot value into a volume-relative path:
/// `cdrom0:\SLUS_203.12;1` → `SLUS_203.12`, `cdrom0:\DIR\MAIN.ELF;1` → `DIR/MAIN.ELF`.
pub fn boot_disc_path(value: &str) -> String {
    let v = value.trim();
    let v = match v.find(':') {
        Some(i) if v[..i].to_ascii_lowercase().starts_with("cdrom") => &v[i + 1..],
        _ => v,
    };
    let v = v.replace('\\', "/");
    let v = v.trim_start_matches('/');
    match v.rfind(';') {
        Some(i) if v[i + 1..].chars().all(|c| c.is_ascii_digit()) => v[..i].to_string(),
        _ => v.to_string(),
    }
}

/// Derive the product serial from a boot file name: `SLUS_203.12` → `SLUS-20312`.
pub fn serial_from_filename(name: &str) -> Option<String> {
    let base = name.rsplit(['/', '\\']).next()?;
    let b = base.as_bytes();
    if b.len() != 11 {
        return None;
    }
    let ok = b[0..4].iter().all(|c| c.is_ascii_alphabetic())
        && b[4] == b'_'
        && b[5..8].iter().all(|c| c.is_ascii_digit())
        && b[8] == b'.'
        && b[9..11].iter().all(|c| c.is_ascii_digit());
    if !ok {
        return None;
    }
    Some(format!("{}-{}{}", base[0..4].to_ascii_uppercase(), &base[5..8], &base[9..11]))
}

/// Coarse region from a serial prefix.
pub fn region_from_serial(serial: &str) -> &'static str {
    match serial.get(0..4).map(|s| s.to_ascii_uppercase()).as_deref() {
        Some("SLUS") | Some("SCUS") => "NTSC-U/C (North America)",
        Some("SLES") | Some("SCES") | Some("SLED") | Some("SCED") => "PAL (Europe/Australia)",
        Some("SLPS") | Some("SCPS") | Some("SLPM") | Some("SCPM") | Some("SIPS") => "NTSC-J (Japan)",
        Some("SLKA") | Some("SCKA") => "NTSC-K (Korea)",
        Some("SLAJ") | Some("SCAJ") => "NTSC-Asia",
        _ => "Unknown",
    }
}

// ---------------------------------------------------------------------------
// Disc analysis (platform + boot executable)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ElfKind {
    NotElf,
    /// ELF32 little-endian MIPS executable (EE code).
    Mips32Exec,
    /// ELF32 little-endian MIPS IOP module (`.irx`, e_type 0xFF80).
    Mips32Irx,
    /// Some other ELF.
    OtherElf,
}

fn elf_kind(head: &[u8]) -> ElfKind {
    if head.len() < 20 || head[0..4] != [0x7f, b'E', b'L', b'F'] {
        return ElfKind::NotElf;
    }
    let class32_le = head[4] == 1 && head[5] == 1;
    let e_type = u16::from_le_bytes([head[16], head[17]]);
    let machine = u16::from_le_bytes([head[18], head[19]]);
    if class32_le && machine == 8 {
        if e_type == 0xFF80 {
            ElfKind::Mips32Irx
        } else {
            ElfKind::Mips32Exec
        }
    } else {
        ElfKind::OtherElf
    }
}

/// One executable-looking file on the disc.
#[derive(Debug, Clone, Serialize)]
pub struct ExecutableFile {
    pub path: String,
    pub size: u64,
    /// `"ELF"` (EE executable), `"IRX"` (IOP module) or `"ELF (other)"`.
    pub kind: String,
}

struct DiscAnalysis {
    platform: String,
    boot_key: Option<&'static str>,
    boot_value: Option<String>,
    cnf: Option<SystemCnf>,
    /// Index into the entries slice.
    boot_entry: Option<usize>,
    boot_is_ps2_elf: bool,
    /// Parsed header when this is a PS1 disc whose boot file is a PS-X EXE.
    psx_exe: Option<PsxExeInfo>,
    executables: Vec<ExecutableFile>,
    /// Entries (indices) whose first bytes are an ELF header.
    executable_idx: Vec<usize>,
    warnings: Vec<String>,
    /// Files that reach into the part of the image that is missing.
    cut_files: usize,
    /// The boot file itself reaches into the missing part.
    boot_cut: bool,
}

/// Upper bound on how many files are sniffed for an ELF header.
const MAX_SNIFF_FILES: usize = 100_000;

fn analyze<R: Read + Seek>(img: &mut DiscImage<R>, entries: &[DiscEntry]) -> DiscAnalysis {
    let mut a = DiscAnalysis {
        platform: "Unknown".into(),
        boot_key: None,
        boot_value: None,
        cnf: None,
        boot_entry: None,
        boot_is_ps2_elf: false,
        psx_exe: None,
        executables: vec![],
        executable_idx: vec![],
        warnings: vec![],
        cut_files: 0,
        boot_cut: false,
    };

    // SYSTEM.CNF (root only — never a nested one).
    let cnf_entry = entries
        .iter()
        .find(|e| !e.is_dir && e.path.eq_ignore_ascii_case("SYSTEM.CNF"));
    match cnf_entry {
        None => a.warnings.push(
            "No SYSTEM.CNF in the volume root — this does not look like a PlayStation game disc.".into(),
        ),
        Some(e) => match img.read_file(e) {
            Ok(bytes) => {
                let cnf = parse_system_cnf(&String::from_utf8_lossy(&bytes));
                if let Some(v) = cnf.boot2.clone() {
                    a.platform = "PS2".into();
                    a.boot_key = Some("BOOT2");
                    a.boot_value = Some(v);
                } else if let Some(v) = cnf.boot.clone() {
                    a.platform = "PS1".into();
                    a.boot_key = Some("BOOT");
                    a.boot_value = Some(v);
                } else {
                    a.warnings.push("SYSTEM.CNF has neither BOOT2 nor BOOT.".into());
                }
                a.cnf = Some(cnf);
            }
            Err(e) => a.warnings.push(format!("Could not read SYSTEM.CNF: {e}")),
        },
    }

    // Resolve the boot executable.
    if let Some(value) = a.boot_value.clone() {
        let want = boot_disc_path(&value);
        let found = entries
            .iter()
            .position(|e| !e.is_dir && disc::normalize_lookup(&e.path) == disc::normalize_lookup(&want));
        match found {
            Some(i) => {
                a.boot_entry = Some(i);
                if let Ok(head) = img.read_file_head(&entries[i], 64) {
                    a.boot_is_ps2_elf = elf_kind(&head) == ElfKind::Mips32Exec;
                    if a.platform == "PS2" && !a.boot_is_ps2_elf {
                        a.warnings.push(format!(
                            "Boot file {} is not a 32-bit little-endian MIPS ELF (it may be packed or encrypted).",
                            entries[i].path
                        ));
                    }
                }
                if a.platform == "PS1" {
                    let head = img.read_file_head(&entries[i], psx_exe::HEADER_BYTES).unwrap_or_default();
                    a.psx_exe = psx_exe::parse(&head);
                    if a.psx_exe.is_none() {
                        a.warnings.push(format!(
                            "Boot file {} is not a PS-X EXE (no `PS-X EXE` header), so it cannot be recompiled directly.",
                            entries[i].path
                        ));
                    }
                }
            }
            None => a.warnings.push(format!(
                "SYSTEM.CNF boots `{value}`, but no such file exists on the disc."
            )),
        }
    }

    // Sniff every file's first bytes for an ELF header (covers IRX modules and
    // overlay ELFs with arbitrary extensions).
    for (i, e) in entries.iter().enumerate().filter(|(_, e)| !e.is_dir && e.size >= 52).take(MAX_SNIFF_FILES) {
        let Ok(head) = img.read_file_head(e, 20) else { continue };
        let kind = match elf_kind(&head) {
            ElfKind::NotElf => continue,
            ElfKind::Mips32Exec => "ELF",
            ElfKind::Mips32Irx => "IRX",
            ElfKind::OtherElf => "ELF (other)",
        };
        a.executable_idx.push(i);
        a.executables.push(ExecutableFile { path: e.path.clone(), size: e.size, kind: kind.into() });
    }

    // A short image is only a problem when something we need lies in the part
    // that is missing. Say how much is gone and what it touches.
    if img.is_truncated() {
        let cut: Vec<&DiscEntry> = entries.iter().filter(|e| img.entry_is_cut(e)).collect();
        a.cut_files = cut.len();
        a.boot_cut = a.boot_entry.map(|i| img.entry_is_cut(&entries[i])).unwrap_or(false);
        let boot_name = a.boot_entry.map(|i| entries[i].path.clone());
        let files = entries.iter().filter(|e| !e.is_dir).count();
        a.warnings.push(truncation_note(img, &cut, files, boot_name.as_deref(), a.boot_cut));
    }
    a
}

fn human_bytes(b: u64) -> String {
    const UNITS: [&str; 4] = ["bytes", "KiB", "MiB", "GiB"];
    let mut v = b as f64;
    let mut u = 0;
    while v >= 1024.0 && u + 1 < UNITS.len() {
        v /= 1024.0;
        u += 1;
    }
    if u == 0 { format!("{b} bytes") } else { format!("{v:.1} {}", UNITS[u]) }
}

/// What a short image costs, in plain words. Dumps that merely lack trailing
/// blank sectors are common and harmless; one cut through the boot program is
/// not, and the message says which of the two this is.
fn truncation_note<R: Read + Seek>(
    img: &DiscImage<R>,
    cut: &[&DiscEntry],
    files: usize,
    boot_name: Option<&str>,
    boot_cut: bool,
) -> String {
    let missing = img.missing_sectors();
    let mut s = format!(
        "The image holds {} of the {} sectors its volume descriptor claims ({missing} short, {}).",
        img.held_sectors(),
        img.held_sectors() + missing,
        human_bytes(missing * 2048)
    );
    if boot_cut {
        s.push_str(&format!(
            " The boot program{} itself reaches past the end of the image, so a build from it cannot work. \
             Use a complete dump.",
            boot_name.map(|n| format!(" ({n})")).unwrap_or_default()
        ));
    } else if cut.is_empty() {
        s.push_str(
            " No file in the disc's directory reaches into the missing part, so every file the build needs is readable.              (The descriptor can be oversized on some discs; the game reads your original image when it runs.)",
        );
    } else {
        let names: Vec<&str> = cut.iter().take(3).map(|e| e.path.as_str()).collect();
        s.push_str(&format!(
            " {} of {files} file(s) reach into the missing part and cannot be read in full ({}{}). \
             The boot program{} is intact, so the build can go ahead; those files will be missing when the game runs too.",
            cut.len(),
            names.join(", "),
            if cut.len() > names.len() { ", …" } else { "" },
            boot_name.map(|n| format!(" ({n})")).unwrap_or_default()
        ));
    }
    s
}

// ---------------------------------------------------------------------------
// Inspect (read-only)
// ---------------------------------------------------------------------------

/// Everything the wizard shows before anything is written to disk.
#[derive(Debug, Clone, Serialize)]
pub struct DiscInfo {
    pub image_path: String,
    /// The file actually opened (differs from `image_path` for `.cue` sheets).
    pub opened_path: String,
    pub image_size: u64,
    pub layout: String,
    /// `"PS2"`, `"PS1"` or `"Unknown"`.
    pub platform: String,
    pub volume_id: String,
    pub system_id: String,
    /// Best-effort title: the volume label with `_` turned into spaces.
    pub display_name: String,
    pub serial: Option<String>,
    pub region: String,
    pub boot_key: Option<String>,
    /// The boot line exactly as written in SYSTEM.CNF.
    pub boot_value: Option<String>,
    /// Resolved boot file path on the disc.
    pub boot_file: Option<String>,
    pub boot_size: u64,
    pub boot_is_ps2_elf: bool,
    /// True when a PS1 disc's boot file is a PS-X EXE.
    pub boot_is_psx_exe: bool,
    /// Header fields of the PS-X EXE boot file (PS1 only).
    pub psx_exe: Option<PsxExeInfo>,
    pub ver: Option<String>,
    pub vmode: Option<String>,
    pub file_count: usize,
    pub dir_count: usize,
    pub total_bytes: u64,
    pub executable_count: usize,
    /// First few executables (capped) for display.
    pub executables: Vec<ExecutableFile>,
    pub truncated: bool,
    /// Sectors the volume descriptor claims beyond what the image holds.
    pub missing_sectors: u64,
    /// Files that reach into the missing part of a truncated image.
    pub files_past_cut: usize,
    /// The boot file itself reaches into the missing part.
    pub boot_past_cut: bool,
    pub warnings: Vec<String>,
    /// True when the wizard can process this image: a PS2 disc with an ELF
    /// boot file ([`ingest_ps2`]) or a PS1 disc with a PS-X EXE boot file
    /// (`ps1_ingest`). `platform` says which pipeline applies.
    pub can_ingest: bool,
}

fn display_name(volume_id: &str, fallback: &str) -> String {
    let v = volume_id.replace('_', " ").trim().to_string();
    if v.is_empty() { fallback.to_string() } else { v }
}

/// Open an image, list it, and describe it. Writes nothing.
pub fn inspect_image(path: &str) -> Result<DiscInfo, String> {
    let (mut img, opened) = disc::open_disc_file(path)?;
    let entries = img.list_entries()?;
    let a = analyze(&mut img, &entries);
    let vol = img.volume().clone();
    let stem = Path::new(path)
        .file_stem()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_default();
    let boot_file = a.boot_entry.map(|i| entries[i].path.clone());
    let serial = boot_file.as_deref().and_then(serial_from_filename);
    let region = serial
        .as_deref()
        .map(region_from_serial)
        .filter(|r| *r != "Unknown")
        .or_else(|| a.psx_exe.as_ref().and_then(|p| p.marker_region()))
        .unwrap_or("Unknown")
        .to_string();
    let file_count = entries.iter().filter(|e| !e.is_dir).count();
    let can_ingest = a.boot_entry.is_some()
        && ((a.platform == "PS2" && a.boot_is_ps2_elf) || (a.platform == "PS1" && a.psx_exe.is_some()));

    Ok(DiscInfo {
        image_path: path.to_string(),
        opened_path: opened.to_string_lossy().to_string(),
        image_size: img.image_len(),
        layout: img.layout().label().to_string(),
        platform: a.platform.clone(),
        display_name: display_name(&vol.volume_id, &stem),
        volume_id: vol.volume_id,
        system_id: vol.system_id,
        serial,
        region,
        boot_key: a.boot_key.map(|s| s.to_string()),
        boot_value: a.boot_value.clone(),
        boot_size: a.boot_entry.map(|i| entries[i].size).unwrap_or(0),
        boot_file,
        boot_is_ps2_elf: a.boot_is_ps2_elf,
        boot_is_psx_exe: a.psx_exe.is_some(),
        psx_exe: a.psx_exe.clone(),
        ver: a.cnf.as_ref().and_then(|c| c.ver.clone()),
        vmode: a.cnf.as_ref().and_then(|c| c.vmode.clone()),
        file_count,
        dir_count: entries.len() - file_count,
        total_bytes: entries.iter().filter(|e| !e.is_dir).map(|e| e.size).sum(),
        executable_count: a.executables.len(),
        executables: a.executables.iter().take(200).cloned().collect(),
        truncated: img.is_truncated(),
        missing_sectors: img.missing_sectors(),
        files_past_cut: a.cut_files,
        boot_past_cut: a.boot_cut,
        warnings: a.warnings,
        can_ingest,
    })
}

// ---------------------------------------------------------------------------
// Ingest
// ---------------------------------------------------------------------------

/// How much of the disc to copy into the workspace.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ExtractMode {
    /// SYSTEM.CNF, the boot ELF, and every other ELF/IRX on the disc. A few MB.
    Executables,
    /// The whole file tree (several GB for a DVD).
    All,
}

#[derive(Debug, Clone, Deserialize)]
pub struct IngestOptions {
    /// Parent folder; a per-game workspace is created beneath it.
    pub out_root: String,
    pub mode: ExtractMode,
    /// Path to a `ps2_recomp` binary. `None` = do not run the recompiler.
    pub recompiler: Option<String>,
}

/// Progress event emitted during [`ingest_ps2`].
#[derive(Debug, Clone, Serialize, Default)]
pub struct IngestProgress {
    /// `open` | `inspect` | `extract` | `analyze` | `config` | `recompile` | `done`
    pub stage: String,
    pub message: String,
    /// Overall completion in `0.0..=1.0`.
    pub fraction: f64,
    pub files_done: usize,
    pub files_total: usize,
    pub bytes_done: u64,
    pub bytes_total: u64,
}

/// Result of the optional `ps2_recomp` run.
#[derive(Debug, Clone, Serialize)]
pub struct RecompilerRun {
    pub executable: String,
    pub command: String,
    pub success: bool,
    pub exit_code: Option<i32>,
    pub log_path: String,
    /// Last lines of the combined stdout/stderr.
    pub log_tail: Vec<String>,
    pub generated_files: usize,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct IngestResult {
    pub workspace: String,
    pub manifest_path: String,
    pub display_name: String,
    pub serial: Option<String>,
    pub region: String,
    pub platform: String,
    /// Boot executable's path on the disc.
    pub boot_file: String,
    /// Copy of the boot ELF to open in Aura / feed to ps2_recomp.
    pub elf_path: String,
    pub disc_dir: String,
    pub config_toml: String,
    pub functions_csv: String,
    pub recomp_output_dir: String,
    pub entry_point: u32,
    pub function_count: usize,
    pub sdk_named: usize,
    pub extracted_files: usize,
    pub extracted_bytes: u64,
    /// `"all"` or `"executables"`; packaging needs `"all"`.
    pub extract_mode: String,
    /// `ret0@0xADDR` bindings written to `general.stubs` (BIOS-patching SDK
    /// routines); empty when none were detected.
    pub stubbed: Vec<String>,
    pub recompiler: Option<RecompilerRun>,
    pub next_steps: Vec<String>,
    pub warnings: Vec<String>,
}

/// Entries to extract for `mode`: everything, or just `SYSTEM.CNF`, the boot
/// executable and every ELF/IRX on the disc. Directories are not included.
fn plan_from_analysis(a: &DiscAnalysis, entries: &[DiscEntry], mode: ExtractMode) -> Vec<DiscEntry> {
    let mut plan: Vec<DiscEntry> = match mode {
        ExtractMode::All => entries.iter().filter(|e| !e.is_dir).cloned().collect(),
        ExtractMode::Executables => {
            let mut keep: std::collections::BTreeSet<usize> = a.executable_idx.iter().copied().collect();
            if let Some(i) = a.boot_entry {
                keep.insert(i);
            }
            if let Some(i) = entries
                .iter()
                .position(|e| !e.is_dir && e.path.eq_ignore_ascii_case("SYSTEM.CNF"))
            {
                keep.insert(i);
            }
            keep.into_iter().map(|i| entries[i].clone()).collect()
        }
    };
    plan.sort_by(|x, y| x.path.cmp(&y.path));
    plan
}

/// Public entry point for platform-agnostic extraction (`aura-cli disc-extract`,
/// the GUI's "extract only" path).
pub fn plan_extraction<R: Read + Seek>(
    img: &mut DiscImage<R>,
    entries: &[DiscEntry],
    mode: ExtractMode,
) -> Vec<DiscEntry> {
    let a = analyze(img, entries);
    plan_from_analysis(&a, entries, mode)
}

/// SDK routines that patch or scan the EE *kernel* (the BIOS) and so cannot
/// work in a recompiled program, which has no BIOS to patch.
///
/// Evidence: `InitSystemCallTableAddress` walks kernel memory at `0x8008xxxx`
/// looking for its tables. Recompiled and run unmodified, two unrelated games
/// (a homebrew and a retail title) both spin in it forever with no GS
/// activity, never reaching their own code. Binding it to the generic `ret0`
/// handler let the homebrew run on to load its IOP modules. Matching is by
/// the hash-verified SDK database name, so this never touches user code that
/// merely looks similar.
///
/// Extend this list only with a routine that was observed to stall a game and
/// whose stubbing was shown to help.
pub const KERNEL_PATCH_ROUTINES: &[&str] = &["InitSystemCallTableAddress"];

/// `ret0@0xADDR` bindings for every detected routine in
/// [`KERNEL_PATCH_ROUTINES`].
pub fn kernel_stub_bindings(funcs: &[engine::FunctionEntry]) -> Vec<String> {
    let mut v: Vec<String> = funcs
        .iter()
        .filter(|f| KERNEL_PATCH_ROUTINES.contains(&f.name.as_str()))
        .map(|f| format!("ret0@0x{:x}", f.start))
        .collect();
    v.sort();
    v.dedup();
    v
}

/// Minimum gap between two progress callbacks within one stage.
const PROGRESS_INTERVAL: Duration = Duration::from_millis(100);

/// Rate-limits progress callbacks.
///
/// Extraction reports once per file, and a real game has thousands of small
/// files, so an unthrottled consumer is called hundreds of times a second
/// (measured: ~800 events/s, 8,101 events for an 8,005-file disc). The GUI turns
/// each one into a webview event and a re-render, which is pure waste. A stage
/// change or completion always passes; otherwise at most one call per
/// [`PROGRESS_INTERVAL`]. Once the consumer asks to cancel, every later call
/// reports "cancelled" without invoking it again.
pub(crate) struct Throttle<'a> {
    cb: &'a mut dyn FnMut(&IngestProgress) -> bool,
    last_stage: String,
    last_at: Option<Instant>,
    cancelled: bool,
}

impl<'a> Throttle<'a> {
    pub(crate) fn new(cb: &'a mut dyn FnMut(&IngestProgress) -> bool) -> Self {
        Throttle { cb, last_stage: String::new(), last_at: None, cancelled: false }
    }

    /// Returns `false` once the consumer has asked to cancel.
    pub(crate) fn call(&mut self, p: &IngestProgress) -> bool {
        if self.cancelled {
            return false;
        }
        let due = p.stage != self.last_stage
            || p.fraction >= 1.0
            || self.last_at.map_or(true, |t| t.elapsed() >= PROGRESS_INTERVAL);
        if !due {
            return true;
        }
        self.last_stage.clear();
        self.last_stage.push_str(&p.stage);
        self.last_at = Some(Instant::now());
        if (self.cb)(p) {
            true
        } else {
            self.cancelled = true;
            false
        }
    }
}

pub(crate) fn report(t: &mut Throttle, stage: &str, message: &str, fraction: f64) -> Result<(), String> {
    let p = IngestProgress {
        stage: stage.into(),
        message: message.into(),
        fraction: fraction.clamp(0.0, 1.0),
        ..Default::default()
    };
    if t.call(&p) { Ok(()) } else { Err("Cancelled".into()) }
}

/// Run the one-click PS2 pipeline. `progress` returns `false` to cancel.
pub fn ingest_ps2(
    image_path: &str,
    opts: &IngestOptions,
    progress: &mut dyn FnMut(&IngestProgress) -> bool,
) -> Result<IngestResult, String> {
    let mut throttle = Throttle::new(progress);
    let progress = &mut throttle;
    report(progress, "open", "Opening disc image…", 0.0)?;
    let (mut img, _opened) = disc::open_disc_file(image_path)?;

    report(progress, "inspect", "Reading the file system…", 0.02)?;
    let entries = img.list_entries()?;
    let a = analyze(&mut img, &entries);
    let mut warnings = a.warnings.clone();

    if a.platform == "PS1" {
        return Err(
            "This is a PS1 disc (SYSTEM.CNF uses BOOT=), which has its own pipeline: use `aura-cli ps1-ingest` \
             (the wizard picks the right one automatically)."
                .into(),
        );
    }
    if a.platform != "PS2" {
        return Err(
            "No PS2 boot entry (BOOT2) found in SYSTEM.CNF — this does not look like a PS2 game disc.".into(),
        );
    }
    let boot_idx = a.boot_entry.ok_or_else(|| {
        format!(
            "SYSTEM.CNF boots `{}` but that file is not on the disc.",
            a.boot_value.clone().unwrap_or_default()
        )
    })?;
    if !a.boot_is_ps2_elf {
        return Err(format!(
            "The boot file `{}` is not a 32-bit little-endian MIPS ELF, so it cannot be recompiled directly \
             (it may be packed or encrypted).",
            entries[boot_idx].path
        ));
    }
    let boot = entries[boot_idx].clone();

    let serial = serial_from_filename(&boot.path);
    let region = serial.as_deref().map(region_from_serial).unwrap_or("Unknown").to_string();
    let vol = img.volume().clone();
    let stem = Path::new(image_path)
        .file_stem()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| "game".into());
    let name = display_name(&vol.volume_id, &stem);
    let ws_name = disc::sanitize_component(serial.as_deref().unwrap_or(&stem));

    // ----- workspace layout ------------------------------------------------
    // Absolute: the recompiler runs from another directory and reads the
    // config's paths there.
    let ws = absolute_path(Path::new(&opts.out_root)).join(&ws_name);
    let disc_dir = ws.join("disc");
    let recomp_dir = ws.join("recomp");
    let gen_dir = recomp_dir.join("generated");
    for d in [&disc_dir, &recomp_dir, &gen_dir] {
        fs::create_dir_all(d).map_err(|e| format!("Cannot create {}: {e}", d.display()))?;
    }

    // ----- what to extract -------------------------------------------------
    let plan = plan_from_analysis(&a, &entries, opts.mode);

    // ----- extract ----------------------------------------------------------
    report(progress, "extract", "Extracting files…", 0.05)?;
    let summary = {
        let mut cb = |p: &ExtractProgress| {
            let frac = if p.bytes_total > 0 {
                p.bytes_done as f64 / p.bytes_total as f64
            } else if p.files_total > 0 {
                p.files_done as f64 / p.files_total as f64
            } else {
                1.0
            };
            progress.call(&IngestProgress {
                stage: "extract".into(),
                message: if p.current.is_empty() { "Extracting files…".into() } else { format!("Extracting {}", p.current) },
                fraction: 0.05 + 0.75 * frac,
                files_done: p.files_done,
                files_total: p.files_total,
                bytes_done: p.bytes_done,
                bytes_total: p.bytes_total,
            })
        };
        img.extract_entries(&plan, &disc_dir, &mut cb)?
    };

    // ----- boot ELF copy + analysis ---------------------------------------
    report(progress, "analyze", "Analysing the boot ELF…", 0.82)?;
    let elf_bytes = img.read_file(&boot)?;
    let boot_name = boot.name().to_string();
    let elf_file_name = format!("{}.elf", disc::sanitize_component(&boot_name));
    let elf_path = recomp_dir.join(&elf_file_name);
    fs::write(&elf_path, &elf_bytes)
        .map_err(|e| format!("Cannot write {}: {e}", elf_path.display()))?;

    let info = engine::parse_elf_data(&elf_bytes, &elf_file_name)?;
    let funcs = engine::detect_functions_inner(&info)?;
    if funcs.is_empty() {
        warnings.push(
            "No functions were detected in the boot ELF (no executable segments?). \
             The generated config will not recompile to anything useful."
                .into(),
        );
    }
    if let Err(e) = engine::sce_db().as_ref() {
        warnings.push(format!("SCE SDK symbol database failed to load; SDK functions are unnamed: {e}"));
    }

    // ----- ps2_recomp config -----------------------------------------------
    report(progress, "config", "Writing ps2_recomp configuration…", 0.9)?;
    let csv_path = recomp_dir.join("functions.csv");
    let mut csv = String::from("Name,Start,End,Size\n");
    for f in &funcs {
        csv.push_str(&format!("{},0x{:08X},0x{:08X},{}\n", f.name, f.start, f.end, f.size));
    }
    fs::write(&csv_path, csv).map_err(|e| format!("Cannot write {}: {e}", csv_path.display()))?;

    let from_symbols = info.symbols.iter().filter(|s| s.size > 0).count();
    let heuristic = funcs.len().saturating_sub(from_symbols);
    let mut untracked: Vec<String> = funcs
        .iter()
        .filter(|f| !f.name.starts_with("sub_"))
        .map(|f| f.name.clone())
        .collect();
    untracked.sort();
    untracked.dedup();
    let sdk_named = untracked.len();

    let path_str = |p: &Path| p.to_string_lossy().to_string();
    let stubbed = kernel_stub_bindings(&funcs);
    let toml = engine::build_config_toml_with_stubs(
        &path_str(&elf_path),
        &path_str(&gen_dir),
        &path_str(&csv_path),
        &info,
        &funcs,
        from_symbols,
        heuristic,
        sdk_named,
        &untracked,
        &stubbed,
    );
    let config_path = recomp_dir.join("config.toml");
    fs::write(&config_path, toml)
        .map_err(|e| format!("Cannot write {}: {e}", config_path.display()))?;

    let next_steps = next_steps(&config_path, &gen_dir, &disc_dir, opts.recompiler.is_some());
    let readme = build_readme(&name, serial.as_deref(), &region, &elf_path, &config_path, &next_steps);
    let readme_path = recomp_dir.join("README.md");
    fs::write(&readme_path, readme).map_err(|e| format!("Cannot write {}: {e}", readme_path.display()))?;

    // ----- optional recompiler ----------------------------------------------
    let mut recompiler_run: Option<RecompilerRun> = None;
    if let Some(exe) = opts.recompiler.as_deref().filter(|s| !s.trim().is_empty()) {
        report(progress, "recompile", "Running ps2_recomp…", 0.93)?;
        let log = recomp_dir.join("ps2_recomp.log");
        let mut cancelled = false;
        let run = run_recompiler(Path::new(exe), &config_path, &recomp_dir, &gen_dir, &log, &mut || {
            let ok = progress.call(&IngestProgress {
                stage: "recompile".into(),
                message: "Running ps2_recomp…".into(),
                fraction: 0.95,
                ..Default::default()
            });
            if !ok {
                cancelled = true;
            }
            ok
        });
        if cancelled {
            return Err("Cancelled".into());
        }
        if !run.success {
            warnings.push(format!(
                "ps2_recomp did not finish successfully: {}",
                run.error.clone().unwrap_or_else(|| "see log".into())
            ));
        }
        recompiler_run = Some(run);
    }

    // ----- manifest -----------------------------------------------------------
    let manifest_path = ws.join("game.json");
    let manifest = serde_json::json!({
        "aura_ingest_version": 1,
        "created_unix": SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0),
        "source_image": image_path,
        "layout": img.layout().label(),
        "platform": "PS2",
        "display_name": name,
        "volume_id": vol.volume_id,
        "serial": serial,
        "region": region,
        "boot_file": boot.path,
        "boot_elf": path_str(&elf_path),
        "entry_point": format!("0x{:08X}", info.entry_point),
        "extract_mode": match opts.mode { ExtractMode::All => "all", ExtractMode::Executables => "executables" },
        "disc_dir": path_str(&disc_dir),
        "extracted_files": summary.files.len(),
        "extracted_bytes": summary.bytes,
        "recomp": {
            "config_toml": path_str(&config_path),
            "functions_csv": path_str(&csv_path),
            "output_dir": path_str(&gen_dir),
            "function_count": funcs.len(),
            "sdk_named": sdk_named,
            "stubs": stubbed,
        },
        "next_steps": next_steps,
        "warnings": warnings,
    });
    fs::write(&manifest_path, serde_json::to_string_pretty(&manifest).unwrap_or_default())
        .map_err(|e| format!("Cannot write {}: {e}", manifest_path.display()))?;

    report(progress, "done", "Done", 1.0)?;

    Ok(IngestResult {
        workspace: path_str(&ws),
        manifest_path: path_str(&manifest_path),
        display_name: name,
        serial,
        region,
        platform: "PS2".into(),
        boot_file: boot.path,
        elf_path: path_str(&elf_path),
        disc_dir: path_str(&disc_dir),
        config_toml: path_str(&config_path),
        functions_csv: path_str(&csv_path),
        recomp_output_dir: path_str(&gen_dir),
        entry_point: info.entry_point,
        function_count: funcs.len(),
        sdk_named,
        extracted_files: summary.files.len(),
        extracted_bytes: summary.bytes,
        extract_mode: match opts.mode { ExtractMode::All => "all", ExtractMode::Executables => "executables" }.to_string(),
        stubbed,
        recompiler: recompiler_run,
        next_steps,
        warnings,
    })
}

// ---------------------------------------------------------------------------
// Guidance text
// ---------------------------------------------------------------------------

fn next_steps(config: &Path, gen_dir: &Path, disc_dir: &Path, ran_recompiler: bool) -> Vec<String> {
    let mut s = Vec::new();
    s.push(
        "Get the upstream toolchain: `git clone --recurse-submodules https://github.com/ran-j/PS2Recomp.git`, \
         then build it with CMake 3.20+ and a C++20 compiler (MSVC is the compiler upstream tests with)."
            .to_string(),
    );
    if ran_recompiler {
        s.push(format!(
            "ps2_recomp was run for you; its C++ output is in {}. Re-run it with `ps2_recomp \"{}\"` after editing the config.",
            gen_dir.display(),
            config.display()
        ));
    } else {
        s.push(format!(
            "Generate C++: `ps2_recomp \"{}\"` (output goes to {}). Aura can run this for you if you point the wizard at the binary.",
            config.display(),
            gen_dir.display()
        ));
    }
    s.push(
        "Compile the generated C++ together with the `ps2xRuntime` library from the same repository to produce \
         the game executable."
            .to_string(),
    );
    s.push(format!(
        "The extracted game files are in {}. Upstream does not document how ps2xRuntime locates game files at \
         runtime — check its CD/filesystem stubs (e.g. `sceCdRead`) before assuming a path.",
        disc_dir.display()
    ));
    s.push(
        "Expect gaps: upstream describes the runtime as experimental, with partial hardware emulation and slow \
         VU/GS paths, and stub bindings are specific to one exact ELF build."
            .to_string(),
    );
    s
}

fn build_readme(
    name: &str,
    serial: Option<&str>,
    region: &str,
    elf: &Path,
    config: &Path,
    steps: &[String],
) -> String {
    let mut t = String::new();
    t.push_str(&format!("# {name}\n\n"));
    t.push_str("Generated by Aura Decomp Tool's PS2 disc ingest.\n\n");
    t.push_str(&format!("- Serial: {}\n", serial.unwrap_or("unknown")));
    t.push_str(&format!("- Region: {region}\n"));
    t.push_str(&format!("- Boot ELF: `{}`\n", elf.display()));
    t.push_str(&format!("- ps2_recomp config: `{}`\n\n", config.display()));
    t.push_str("## Next steps\n\n");
    for (i, s) in steps.iter().enumerate() {
        t.push_str(&format!("{}. {}\n", i + 1, s));
    }
    t
}

// ---------------------------------------------------------------------------
// Recompiler discovery + execution
// ---------------------------------------------------------------------------

/// Look for any of `names` in a `PATH`-style list, trying `.exe` on Windows.
pub fn search_path(names: &[&str], path_var: &std::ffi::OsStr) -> Option<PathBuf> {
    for dir in std::env::split_paths(path_var) {
        for n in names {
            let plain = dir.join(n);
            if plain.is_file() {
                return Some(plain);
            }
            if cfg!(windows) {
                let exe = dir.join(format!("{n}.exe"));
                if exe.is_file() {
                    return Some(exe);
                }
            }
        }
    }
    None
}

/// Locate `ps2_recomp`: an explicit path, `AURA_PS2RECOMP`, then `PATH`
/// (`ps2_recomp`, then `ps2recomp`).
pub fn find_recompiler(explicit: Option<&str>) -> Option<PathBuf> {
    if let Some(p) = explicit.filter(|s| !s.trim().is_empty()) {
        let pb = PathBuf::from(p);
        return pb.is_file().then_some(pb);
    }
    if let Some(p) = std::env::var_os("AURA_PS2RECOMP") {
        let pb = PathBuf::from(p);
        if pb.is_file() {
            return Some(pb);
        }
    }
    let path = std::env::var_os("PATH")?;
    search_path(&["ps2_recomp", "ps2recomp"], &path)
}

fn count_files(dir: &Path, depth: usize) -> usize {
    if depth > 4 {
        return 0;
    }
    let Ok(rd) = fs::read_dir(dir) else { return 0 };
    rd.filter_map(|e| e.ok())
        .map(|e| {
            let p = e.path();
            if p.is_dir() { count_files(&p, depth + 1) } else { 1 }
        })
        .sum()
}

/// `p` made absolute against the current directory (no symlink resolution and,
/// unlike `canonicalize`, no `\\?\` prefix that CMake and MSBuild dislike).
///
/// Child tools run in another working directory, so every path handed to one
/// has to survive that: a relative `--out ./games` used to reach `ps2_recomp`
/// unchanged and fail with "error opening file".
pub fn absolute_path(p: &Path) -> PathBuf {
    std::path::absolute(p).unwrap_or_else(|_| p.to_path_buf())
}

/// Run `ps2_recomp <config>` in `workdir`, logging combined output to `log`.
/// `keep_going` is polled ~10 times a second; returning `false` kills the child.
pub fn run_recompiler(
    exe: &Path,
    config: &Path,
    workdir: &Path,
    output_dir: &Path,
    log: &Path,
    keep_going: &mut dyn FnMut() -> bool,
) -> RecompilerRun {
    let (exe, config, workdir, output_dir, log) = (
        absolute_path(exe),
        absolute_path(config),
        absolute_path(workdir),
        absolute_path(output_dir),
        absolute_path(log),
    );
    let (exe, config, workdir, output_dir, log) =
        (exe.as_path(), config.as_path(), workdir.as_path(), output_dir.as_path(), log.as_path());
    let command = format!("\"{}\" \"{}\"", exe.display(), config.display());
    let mut run = RecompilerRun {
        executable: exe.to_string_lossy().to_string(),
        command,
        success: false,
        exit_code: None,
        log_path: log.to_string_lossy().to_string(),
        log_tail: vec![],
        generated_files: 0,
        error: None,
    };
    if !exe.is_file() {
        run.error = Some(format!("Recompiler not found at {}", exe.display()));
        return run;
    }
    let log_file = match fs::File::create(log) {
        Ok(f) => f,
        Err(e) => {
            run.error = Some(format!("Cannot create log file: {e}"));
            return run;
        }
    };
    let err_file = match log_file.try_clone() {
        Ok(f) => f,
        Err(e) => {
            run.error = Some(format!("Cannot duplicate log handle: {e}"));
            return run;
        }
    };
    let mut cmd = Command::new(exe);
    cmd.arg(config)
        .current_dir(workdir)
        .stdin(Stdio::null())
        .stdout(Stdio::from(log_file))
        .stderr(Stdio::from(err_file));
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(0x0800_0000); // CREATE_NO_WINDOW
    }
    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            run.error = Some(format!("Could not start {}: {e}", exe.display()));
            return run;
        }
    };
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                run.exit_code = status.code();
                run.success = status.success();
                if !run.success {
                    run.error = Some(format!("exited with {}", status));
                }
                break;
            }
            Ok(None) => {
                if !keep_going() {
                    let _ = child.kill();
                    let _ = child.wait();
                    run.error = Some("Cancelled".into());
                    break;
                }
                std::thread::sleep(Duration::from_millis(100));
            }
            Err(e) => {
                run.error = Some(format!("Waiting for ps2_recomp failed: {e}"));
                break;
            }
        }
    }
    if let Ok(text) = fs::read_to_string(log) {
        let lines: Vec<&str> = text.lines().collect();
        run.log_tail = lines[lines.len().saturating_sub(40)..]
            .iter()
            .map(|s| s.to_string())
            .collect();
    }
    run.generated_files = count_files(output_dir, 0);
    run
}
