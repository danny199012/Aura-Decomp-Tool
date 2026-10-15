//! Package a recompiled PS2 game into a self-contained, double-clickable folder.
//!
//! Input: a workspace written by [`crate::ps2_ingest::ingest_ps2`] (it holds
//! `game.json` and the extracted `disc/` tree) plus a runtime executable the
//! user built from the upstream ps2recomp project.
//!
//! Output: `<workspace>/package/` (or a folder you choose):
//!
//! ```text
//! game.exe                 the runtime (copied, renamed so launchers never
//!                          have to quote an arbitrary name)
//! *.dll                    DLLs found beside the original exe (FFmpeg, ...)
//! disc/                    the extracted disc; the runtime maps `cdrom0:` to
//!                          the directory holding the boot ELF
//! mc0/                     memory-card saves (the runtime looks beside the ELF)
//! launch.json              what the launcher runs (relative paths only)
//! Play <Game>.exe          the double-click launcher (aura-launch), if found
//! Play <Game>.cmd          fallback launcher
//! README.txt
//! ```
//!
//! Why it is shaped like this (verified against upstream ps2xRuntime source):
//! `main()` takes the guest ELF from `argv[1]`, has no file dialog or config
//! file, and has no ISO reader — `cdrom0:` is a host directory defaulting to the
//! ELF's parent directory. So the full disc tree must sit next to the boot ELF,
//! and something must pass that path: the launcher.
//!
//! The package contains code translated from the game plus its assets. It is
//! for the machine that made it; never redistribute it.

use crate::disc;
use serde::Serialize;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

/// Name the runtime exe is given inside the package.
const GAME_EXE: &str = "game.exe";
const LOG_NAME: &str = "aura-last-run.log";

#[derive(Debug, Clone, Serialize)]
pub struct PackageResult {
    pub package_dir: String,
    pub game_exe: String,
    /// The launcher to double-click (`.exe` when available, else `.cmd`).
    pub launcher: String,
    /// `"exe"` or `"cmd"`.
    pub launcher_kind: String,
    /// The fallback `.cmd` launcher, when one could be written safely.
    pub cmd_launcher: Option<String>,
    /// Boot ELF relative to the package folder, `/`-separated.
    pub boot_elf: String,
    pub disc_files: usize,
    pub disc_bytes: u64,
    /// `"hardlink"`, `"copy"`, `"mixed"` or `"in-place"` (package folder is the workspace).
    pub disc_method: String,
    pub dlls: Vec<String>,
    /// False when only the executables were extracted: assets are missing and
    /// the game cannot actually run.
    pub complete: bool,
    pub extract_mode: String,
    pub display_name: String,
    pub serial: Option<String>,
    pub warnings: Vec<String>,
}

/// Progress snapshot for [`package_game`].
#[derive(Debug, Clone, Serialize, Default)]
pub struct PackageProgress {
    pub files_done: usize,
    pub files_total: usize,
    pub bytes_done: u64,
    pub bytes_total: u64,
    pub current: String,
}

#[derive(Debug, Clone)]
pub struct PackageOptions {
    /// Output folder; `None` = `<workspace>/package`.
    pub out_dir: Option<PathBuf>,
    /// Prefer hard links for the disc tree (instant, no extra disk space when
    /// the output is on the same volume); falls back to copying per file.
    pub prefer_links: bool,
    /// The `aura-launch` binary to copy in; `None` = search ([`find_launcher`]).
    pub launcher_exe: Option<PathBuf>,
    /// Additional files to place beside the exe (DLLs, resources).
    pub extra_files: Vec<PathBuf>,
}

impl Default for PackageOptions {
    fn default() -> Self {
        PackageOptions { out_dir: None, prefer_links: true, launcher_exe: None, extra_files: vec![] }
    }
}

// ---------------------------------------------------------------------------
// Launcher discovery
// ---------------------------------------------------------------------------

#[cfg(windows)]
const LAUNCHER_FILE: &str = "aura-launch.exe";
#[cfg(not(windows))]
const LAUNCHER_FILE: &str = "aura-launch";

/// Find the `aura-launch` binary: an explicit path, `AURA_LAUNCHER`, beside
/// the running executable (the CLI and a bundled GUI), then the repo's own
/// `cli/target/{release,debug}` for development builds.
pub fn find_launcher(explicit: Option<&Path>) -> Option<PathBuf> {
    if let Some(p) = explicit {
        return p.is_file().then(|| p.to_path_buf());
    }
    if let Some(p) = std::env::var_os("AURA_LAUNCHER") {
        let p = PathBuf::from(p);
        if p.is_file() {
            return Some(p);
        }
    }
    let mut cands: Vec<PathBuf> = vec![];
    if let Some(dir) = std::env::current_exe().ok().and_then(|e| e.parent().map(|p| p.to_path_buf())) {
        cands.push(dir.join(LAUNCHER_FILE));
        cands.push(dir.join("resources").join(LAUNCHER_FILE));
    }
    // Development builds: the crate that includes this file knows where it was
    // compiled from. In a distributed build these simply do not exist.
    if let Some(m) = option_env!("CARGO_MANIFEST_DIR") {
        let m = PathBuf::from(m);
        for sub in ["target/release", "target/debug"] {
            cands.push(m.join(sub).join(LAUNCHER_FILE));
            cands.push(m.join("..").join("cli").join(sub).join(LAUNCHER_FILE));
        }
    }
    cands.into_iter().find(|p| p.is_file())
}

// ---------------------------------------------------------------------------
// Pure helpers (unit-tested)
// ---------------------------------------------------------------------------

/// True when `s` is safe to embed inside a double-quoted `cmd.exe` string
/// without escaping: no `%` (variable expansion), `^ & | < > !` or quotes.
pub fn cmd_safe(s: &str) -> bool {
    !s.is_empty()
        && s.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, ' ' | '_' | '.' | '-' | '(' | ')' | '[' | ']' | ','))
}

/// Contents of the fallback `.cmd` launcher. `boot_elf` is `/`-separated,
/// relative to the package folder, and must already satisfy [`cmd_safe`] per
/// component.
pub fn render_cmd_launcher(game: &str, boot_elf: &str) -> String {
    let win = boot_elf.replace('/', "\\");
    format!(
        "@echo off\r\n\
         rem Generated by Aura Decomp Tool for {game}. Double-click to play.\r\n\
         cd /d \"%~dp0\"\r\n\
         \"%~dp0{exe}\" \"%~dp0{win}\" > \"%~dp0{log}\" 2>&1\r\n\
         if errorlevel 1 (\r\n\
         \x20 echo.\r\n\
         \x20 echo The game stopped with an error. Details are in {log}\r\n\
         \x20 pause\r\n\
         )\r\n",
        game = game,
        exe = GAME_EXE,
        win = win,
        log = LOG_NAME,
    )
}

fn render_readme(game: &str, serial: Option<&str>, boot_elf: &str, complete: bool) -> String {
    let mut t = String::new();
    t.push_str(&format!("{game}\r\n"));
    t.push_str(&"=".repeat(game.chars().count().max(8)));
    t.push_str("\r\n\r\n");
    if let Some(s) = serial {
        t.push_str(&format!("Serial: {s}\r\n"));
    }
    t.push_str(&format!("Boot file: {boot_elf}\r\n\r\n"));
    t.push_str("HOW TO RUN\r\n  Double-click the \"Play ...\" file in this folder.\r\n\r\n");
    t.push_str(&format!(
        "IF IT DOES NOT START\r\n  Open {LOG_NAME} in this folder; it holds the runtime's output from the last run.\r\n\r\n"
    ));
    t.push_str("SAVES\r\n  Memory-card saves are written to the mc0 folder.\r\n\r\n");
    t.push_str("MOVING THE FOLDER\r\n  The whole folder can be moved or renamed; every path inside it is relative.\r\n\r\n");
    if !complete {
        t.push_str("WARNING\r\n  Only the executables were extracted from the disc. Game data is missing, so the\r\n  game cannot run. Extract the entire disc in Aura and package again.\r\n\r\n");
    }
    t.push_str("IMPORTANT\r\n  This folder contains code translated from the game and the game's own data.\r\n  It is for use on the computer that made it. Do not share or upload it.\r\n");
    t
}

/// Find the boot ELF inside the extracted `disc/` tree. The disc path is
/// re-sanitised exactly like extraction did, then matched case-insensitively.
fn locate_boot_elf(disc_dir: &Path, boot_disc_path: &str) -> Option<String> {
    let mut cur = disc_dir.to_path_buf();
    let mut rel: Vec<String> = vec![];
    for comp in boot_disc_path.split('/').filter(|c| !c.is_empty()) {
        let want = disc::sanitize_component(comp).to_lowercase();
        let found = fs::read_dir(&cur).ok()?.filter_map(|e| e.ok()).find_map(|e| {
            let name = e.file_name().to_string_lossy().to_string();
            (name.to_lowercase() == want).then_some(name)
        })?;
        cur = cur.join(&found);
        rel.push(found);
    }
    cur.is_file().then(|| rel.join("/"))
}

/// True when both paths exist and are the same file/directory on disk.
fn same_path(a: &Path, b: &Path) -> bool {
    match (fs::canonicalize(a), fs::canonicalize(b)) {
        (Ok(x), Ok(y)) => x == y,
        _ => false,
    }
}

// ---------------------------------------------------------------------------
// Disc tree transfer
// ---------------------------------------------------------------------------

#[derive(Default)]
struct Transfer {
    linked: usize,
    copied: usize,
    bytes: u64,
}

fn count_tree(dir: &Path, files: &mut usize, bytes: &mut u64) {
    let Ok(rd) = fs::read_dir(dir) else { return };
    for e in rd.filter_map(|e| e.ok()) {
        let Ok(ft) = e.file_type() else { continue };
        if ft.is_symlink() {
            continue;
        }
        if ft.is_dir() {
            count_tree(&e.path(), files, bytes);
        } else if ft.is_file() {
            *files += 1;
            *bytes += e.metadata().map(|m| m.len()).unwrap_or(0);
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn transfer_tree(
    src: &Path,
    dst: &Path,
    prefer_links: bool,
    t: &mut Transfer,
    prog: &mut PackageProgress,
    last_emit: &mut Instant,
    on_progress: &mut dyn FnMut(&PackageProgress) -> bool,
) -> Result<(), String> {
    fs::create_dir_all(dst).map_err(|e| format!("Cannot create {}: {e}", dst.display()))?;
    let rd = fs::read_dir(src).map_err(|e| format!("Cannot read {}: {e}", src.display()))?;
    for entry in rd.filter_map(|e| e.ok()) {
        let ft = entry.file_type().map_err(|e| format!("Cannot stat {}: {e}", entry.path().display()))?;
        if ft.is_symlink() {
            continue; // never follow links out of the tree
        }
        let (s, d) = (entry.path(), dst.join(entry.file_name()));
        if ft.is_dir() {
            transfer_tree(&s, &d, prefer_links, t, prog, last_emit, on_progress)?;
            continue;
        }
        if !ft.is_file() {
            continue;
        }
        if d.exists() {
            fs::remove_file(&d).map_err(|e| format!("Cannot replace {}: {e}", d.display()))?;
        }
        let size = entry.metadata().map(|m| m.len()).unwrap_or(0);
        if prefer_links && fs::hard_link(&s, &d).is_ok() {
            t.linked += 1;
        } else {
            fs::copy(&s, &d).map_err(|e| format!("Cannot copy {} -> {}: {e}", s.display(), d.display()))?;
            t.copied += 1;
        }
        t.bytes += size;
        prog.files_done += 1;
        prog.bytes_done += size;
        if last_emit.elapsed() >= Duration::from_millis(100) {
            *last_emit = Instant::now();
            prog.current = s.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
            if !on_progress(prog) {
                return Err("Cancelled".into());
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

/// Assemble the double-clickable game folder. `on_progress` returns `false`
/// to cancel.
pub fn package_game(
    workspace: &Path,
    runtime_exe: &Path,
    opts: &PackageOptions,
    on_progress: &mut dyn FnMut(&PackageProgress) -> bool,
) -> Result<PackageResult, String> {
    // ----- inputs ---------------------------------------------------------
    let manifest_path = workspace.join("game.json");
    let manifest: serde_json::Value = serde_json::from_str(
        &fs::read_to_string(&manifest_path).map_err(|e| {
            format!(
                "{} is not an Aura game workspace ({} missing: {e}). Run the disc wizard / `ps2-ingest` first.",
                workspace.display(),
                manifest_path.display()
            )
        })?,
    )
    .map_err(|e| format!("{} is not valid JSON: {e}", manifest_path.display()))?;
    let get = |k: &str| manifest.get(k).and_then(|v| v.as_str()).map(|s| s.to_string());
    let boot_disc = get("boot_file").ok_or("game.json has no boot_file")?;
    let display = get("display_name").unwrap_or_else(|| "PS2 game".to_string());
    let serial = get("serial");
    let extract_mode = get("extract_mode").unwrap_or_else(|| "executables".to_string());

    if !runtime_exe.is_file() {
        return Err(format!(
            "The runtime executable was not found: {}\nBuild it from the upstream ps2recomp project first.",
            runtime_exe.display()
        ));
    }
    let disc_dir = workspace.join("disc");
    let boot_rel = locate_boot_elf(&disc_dir, &boot_disc).ok_or_else(|| {
        format!(
            "The disc folder {} does not contain the boot file `{}`. Run the wizard again to re-extract it.",
            disc_dir.display(),
            boot_disc
        )
    })?;

    let mut warnings: Vec<String> = vec![];
    let complete = extract_mode == "all";
    if !complete {
        warnings.push(
            "Only the executables were extracted from the disc. The game's data files are missing, \
             so it cannot run. Extract the entire disc and package again."
                .into(),
        );
    }

    // ----- layout -----------------------------------------------------------
    let pkg = opts.out_dir.clone().unwrap_or_else(|| workspace.join("package"));
    if pkg.starts_with(&disc_dir) {
        return Err("The package folder cannot be inside the disc folder.".into());
    }
    fs::create_dir_all(&pkg).map_err(|e| format!("Cannot create {}: {e}", pkg.display()))?;

    // game.exe + DLLs found beside the original exe
    let game_exe = pkg.join(GAME_EXE);
    // If the user points at the package's own game.exe (re-packaging), it is
    // already in place; removing it first would delete the source.
    if !same_path(runtime_exe, &game_exe) {
        if game_exe.exists() {
            fs::remove_file(&game_exe).map_err(|e| format!("Cannot replace {}: {e}", game_exe.display()))?;
        }
        fs::copy(runtime_exe, &game_exe).map_err(|e| format!("Cannot copy the runtime exe: {e}"))?;
    }

    let mut dlls: Vec<String> = vec![];
    let mut to_copy: Vec<PathBuf> = opts.extra_files.clone();
    if let Some(dir) = runtime_exe.parent() {
        if let Ok(rd) = fs::read_dir(dir) {
            for e in rd.filter_map(|e| e.ok()) {
                let p = e.path();
                if p.is_file()
                    && p.extension().map(|x| x.eq_ignore_ascii_case("dll")).unwrap_or(false)
                {
                    to_copy.push(p);
                }
            }
        }
    }
    for src in to_copy {
        let Some(name) = src.file_name() else { continue };
        let dst = pkg.join(name);
        if dst == game_exe {
            continue;
        }
        if same_path(&src, &dst) {
            dlls.push(name.to_string_lossy().to_string()); // already in place
            continue;
        }
        if dst.exists() {
            let _ = fs::remove_file(&dst);
        }
        match fs::copy(&src, &dst) {
            Ok(_) => dlls.push(name.to_string_lossy().to_string()),
            Err(e) => warnings.push(format!("Could not copy {}: {e}", src.display())),
        }
    }
    dlls.sort();
    dlls.dedup();

    // disc tree
    let (mut files, mut bytes) = (0usize, 0u64);
    count_tree(&disc_dir, &mut files, &mut bytes);
    let mut prog = PackageProgress { files_total: files, bytes_total: bytes, ..Default::default() };
    let mut t = Transfer::default();
    let mut last = Instant::now() - Duration::from_secs(1);
    if !on_progress(&prog) {
        return Err("Cancelled".into());
    }
    let dst_disc = pkg.join("disc");
    let in_place = same_path(&dst_disc, &disc_dir);
    if in_place {
        // The package folder *is* the workspace: the disc tree is already
        // exactly where the runtime wants it. Transferring would replace each
        // file with itself, deleting the data.
        t.bytes = bytes;
        prog.files_done = files;
        prog.bytes_done = bytes;
    } else {
        transfer_tree(&disc_dir, &dst_disc, opts.prefer_links, &mut t, &mut prog, &mut last, on_progress)?;
    }
    on_progress(&prog);
    let method = if in_place {
        "in-place"
    } else {
        match (t.linked, t.copied) {
            (0, _) => "copy",
            (_, 0) => "hardlink",
            _ => "mixed",
        }
    };
    let disc_files = if in_place { files } else { t.linked + t.copied };

    fs::create_dir_all(pkg.join("mc0")).map_err(|e| format!("Cannot create mc0: {e}"))?;

    // ----- launchers ------------------------------------------------------------
    let boot_pkg_rel = format!("disc/{boot_rel}");
    let launch = serde_json::json!({
        "aura_launch_version": 1,
        "game": display,
        "serial": serial,
        "exe": GAME_EXE,
        "boot_elf": boot_pkg_rel,
        "extra_args": [],
        "log": LOG_NAME,
        "show_console": false,
    });
    fs::write(pkg.join("launch.json"), serde_json::to_string_pretty(&launch).unwrap_or_default())
        .map_err(|e| format!("Cannot write launch.json: {e}"))?;

    let base = disc::sanitize_component(&format!("Play {display}"));

    // Fallback .cmd — only when every component is safe inside cmd.exe quotes.
    let mut cmd_launcher: Option<String> = None;
    if boot_pkg_rel.split('/').all(cmd_safe) && cmd_safe(&display) {
        let p = pkg.join(format!("{base}.cmd"));
        fs::write(&p, render_cmd_launcher(&display, &boot_pkg_rel))
            .map_err(|e| format!("Cannot write {}: {e}", p.display()))?;
        cmd_launcher = Some(p.to_string_lossy().to_string());
    } else {
        warnings.push(
            "The .cmd launcher was skipped because a name on the disc contains characters cmd.exe \
             treats specially. The launcher program is used instead."
                .into(),
        );
    }

    let mut exe_launcher: Option<String> = None;
    match find_launcher(opts.launcher_exe.as_deref()) {
        Some(src) => {
            let dst = pkg.join(format!("{base}.exe"));
            if dst.exists() {
                let _ = fs::remove_file(&dst);
            }
            fs::copy(&src, &dst).map_err(|e| format!("Cannot copy the launcher: {e}"))?;
            exe_launcher = Some(dst.to_string_lossy().to_string());
        }
        None => warnings.push(
            "The aura-launch program was not found, so only the .cmd launcher was written \
             (it briefly shows a console window). Build it with `cargo build --release` in cli/."
                .into(),
        ),
    }

    let (launcher, launcher_kind) = match (&exe_launcher, &cmd_launcher) {
        (Some(e), _) => (e.clone(), "exe"),
        (None, Some(c)) => (c.clone(), "cmd"),
        (None, None) => {
            return Err(
                "No launcher could be created: aura-launch was not found and the disc's file names are \
                 not safe for a .cmd launcher."
                    .into(),
            )
        }
    };

    fs::write(pkg.join("README.txt"), render_readme(&display, serial.as_deref(), &boot_pkg_rel, complete))
        .map_err(|e| format!("Cannot write README.txt: {e}"))?;

    Ok(PackageResult {
        package_dir: pkg.to_string_lossy().to_string(),
        game_exe: game_exe.to_string_lossy().to_string(),
        launcher,
        launcher_kind: launcher_kind.to_string(),
        cmd_launcher,
        boot_elf: boot_pkg_rel,
        disc_files,
        disc_bytes: t.bytes,
        disc_method: method.to_string(),
        dlls,
        complete,
        extract_mode,
        display_name: display,
        serial,
        warnings,
    })
}
