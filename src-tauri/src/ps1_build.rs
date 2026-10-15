//! One-click build for PS1 games, driving PSXRecomp.
//!
//! PSXRecomp is a complete pipeline of its own: a project-setup script reads a
//! disc sheet, probes the game, generates C from the boot executable and
//! builds a native program whose launcher asks for the player's disc on first
//! run. What it expects from the user is a pile of prerequisites (Windows
//! Python, Git's bash first on `PATH`, CMake + Ninja + a C compiler) and a
//! `.cue`. Aura's job is to make that one click:
//!
//! 1. detect what is installed and say exactly what is missing,
//! 2. (with consent) download the portable toolchain bundle and verify its
//!    SHA-256,
//! 3. fetch the pinned PSXRecomp commit into a cache and expose it under a
//!    local branch name, because the setup script pins submodules by branch,
//! 4. run the setup script non-interactively against the workspace's `.cue`,
//! 5. find the built program and gather it into `<workspace>/package`.
//!
//! Nothing is downloaded without consent ([`plan_build`] lists it), no shell
//! is involved (every process gets an argument vector), and cancelling kills
//! the whole process tree. PSXRecomp is licensed PolyForm Noncommercial, so
//! Aura fetches it on the user's behalf and never bundles it.

use crate::build_common::{
    checkout_is_at, ensure_git_checkout, free_space_bytes, os, space_ok, BuildProgress, DownloadItem,
    Runner, ToolStatus,
};
use crate::ps1_patches::{self, ConfigAdditionInfo, PatchInfo, PatchOutcome};
use crate::ps2_ingest;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::ffi::OsString;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

/// The framework Aura builds games with.
pub const FRAMEWORK_URL: &str = "https://github.com/RetroPortingToolKit/psxrecomp.git";
/// Known-good framework commit (2026-10-15).
pub const PINNED_COMMIT: &str = "8d1c983b5910a42347d1af6304b9a68da94652f2";
/// Launcher/UI submodule the generated game links.
pub const UI_URL: &str = "https://github.com/RetroPortingToolKit/recomp-ui.git";
/// Local branch name the cached checkouts are exposed under (the setup
/// script pins submodules by branch, not by commit).
pub const PINNED_BRANCH: &str = "aura-pinned";

/// Portable CMake + Ninja + clang bundle published by the PSXRecomp authors.
pub const TOOLCHAIN_URL: &str =
    "https://github.com/RetroPortingToolKit/RetroPorting-Toolchains/releases/download/v1.0.14/cmake-clang-v1-windows-x64.zip";
pub const TOOLCHAIN_SHA256: &str = "28da9742385e7ff875b3d9311e8ed89dbdc84f27b6ecba2bc0d0acc11f6d2b4d";
pub const TOOLCHAIN_BYTES: u64 = 209_497_009;

/// File that marks a folder as one Aura packaged (and names its program).
pub const PACKAGE_MARKER: &str = "aura-package.json";

/// True when `exe` is the program a package's marker file names.
pub fn is_aura_package_exe(exe: &Path) -> bool {
    let (Some(dir), Some(name)) = (exe.parent(), exe.file_name()) else { return false };
    let Ok(text) = fs::read_to_string(dir.join(PACKAGE_MARKER)) else { return false };
    let Ok(v) = serde_json::from_str::<serde_json::Value>(&text) else { return false };
    v.get("aura_package").is_some()
        && v.get("exe").and_then(|e| e.as_str()).map(|e| e.eq_ignore_ascii_case(&name.to_string_lossy())).unwrap_or(false)
}

/// Setup script, relative to the framework checkout.
pub const SETUP_SCRIPT: &str = "tools/new_project_layout/setup_project.ps1";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize)]
pub struct Ps1Toolchain {
    pub supported_os: bool,
    pub git: ToolStatus,
    pub python: ToolStatus,
    pub powershell: ToolStatus,
    /// Git's `bash`, which the framework's scripts need first on `PATH`.
    pub bash: ToolStatus,
    /// CMake + Ninja + a C compiler, from one of the sources below.
    pub build_tools: ToolStatus,
    /// `"env"` (PSXRECOMP_TOOLCHAIN_DIR), `"cache"` (Aura's download),
    /// `"system"` (cmake, ninja and clang on PATH) or `"missing"`.
    pub build_tools_source: String,
    /// Folder holding `bin/cmake`, `bin/ninja`, `bin/clang` when known.
    pub toolchain_dir: Option<String>,
    /// Everything except the build tools is present (the bundle is a download).
    pub ready_apart_from_build_tools: bool,
    pub problems: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Ps1BuildPlan {
    pub toolchain: Ps1Toolchain,
    pub cache_dir: String,
    pub display_name: String,
    pub serial: Option<String>,
    pub cue_path: String,
    pub downloads: Vec<DownloadItem>,
    pub download_mb: u32,
    pub framework_cached: bool,
    pub toolchain_cached: bool,
    /// Rough wall-clock estimate for this machine, in seconds.
    pub estimate_secs: u64,
    pub cores: usize,
    pub free_bytes: Option<u64>,
    pub required_bytes: u64,
    pub blockers: Vec<String>,
    pub can_build: bool,
    pub pinned_commit: String,
    pub project_dir: String,
    /// Fixes Aura applies to the framework before building (empty with
    /// `no_fixes` or a framework override).
    pub framework_patches: Vec<PatchInfo>,
    /// Title-specific `game.toml` additions for this game's serial.
    pub config_additions: Vec<ConfigAdditionInfo>,
}

#[derive(Debug, Clone, Default)]
pub struct Ps1BuildOptions {
    pub cache_dir: Option<PathBuf>,
    /// The user has agreed to the downloads listed by [`plan_build`].
    pub allow_downloads: bool,
    /// Gather the built program into `<workspace>/package` afterwards.
    pub package: bool,
    pub jobs: Option<usize>,
    // Overrides, mainly for tests and for reusing existing installs.
    pub git: Option<PathBuf>,
    pub python: Option<PathBuf>,
    /// Program that runs the setup script (default: Windows PowerShell). It
    /// receives `-NoProfile … -File <script> <script args>`.
    pub powershell: Option<PathBuf>,
    pub toolchain_dir: Option<PathBuf>,
    pub framework_override: Option<PathBuf>,
    pub ui_override: Option<PathBuf>,
    pub toolchain_url: Option<String>,
    pub toolchain_sha256: Option<String>,
    /// Skip the Windows/bash checks (tests with fake tools).
    pub skip_os_check: bool,
    /// Build the framework and the game config exactly as they are: no
    /// carried framework patches and no title-specific `game.toml` additions.
    pub no_fixes: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct Ps1Package {
    pub package_dir: String,
    pub exe: String,
    pub files: usize,
    pub bytes: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct Ps1BuildResult {
    pub exe: String,
    pub project_dir: String,
    pub build_dir: String,
    pub cache_dir: String,
    pub log_path: String,
    /// The disc image to hand to the game (`--disc`): the user's own file,
    /// which the runtime reads directly (including `.chd`).
    pub source_image: String,
    pub elapsed_secs: f64,
    /// `(stage, seconds)` in execution order.
    pub stage_secs: Vec<(String, f64)>,
    pub package: Option<Ps1Package>,
    /// Framework fixes applied (or found already present) for this build.
    pub framework_patches: Vec<PatchOutcome>,
    /// Title-specific `game.toml` changes made to the project.
    pub config_additions: Vec<String>,
    pub warnings: Vec<String>,
}

// ---------------------------------------------------------------------------
// Detection
// ---------------------------------------------------------------------------

fn exe(base: &str) -> String {
    if cfg!(windows) { format!("{base}.exe") } else { base.to_string() }
}

fn find_on_path(names: &[&str], path_var: &Option<OsString>) -> Option<PathBuf> {
    let pv = path_var.clone().or_else(|| std::env::var_os("PATH"))?;
    ps2_ingest::search_path(names, &pv)
}

fn status(name: &str, path: Option<PathBuf>, detail: &str) -> ToolStatus {
    ToolStatus {
        name: name.to_string(),
        found: path.is_some(),
        path: path.map(|p| p.to_string_lossy().to_string()),
        detail: detail.to_string(),
    }
}

/// `(major, minor)` of the interpreter at `python`, or `None` if it does not
/// run (a Microsoft Store stub, a dangling shim, not Python at all).
pub fn python_version(python: &Path) -> Option<(u32, u32)> {
    let mut cmd = Command::new(python);
    cmd.args(["-c", "import sys;print(sys.version_info[0],sys.version_info[1])"])
        .stdin(Stdio::null())
        .stderr(Stdio::null());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(0x0800_0000);
    }
    let out = cmd.output().ok()?;
    if !out.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&out.stdout).to_string();
    let mut it = text.split_whitespace().filter_map(|t| t.parse::<u32>().ok());
    Some((it.next()?, it.next()?))
}

/// A Python path that is a Windows-native interpreter (not MSYS2, Cygwin or
/// devkitPro, whose `python` the framework's scripts mishandle).
fn is_native_python_path(p: &Path) -> bool {
    let low = p.to_string_lossy().to_ascii_lowercase().replace('\\', "/");
    !(low.contains("/msys") || low.contains("/cygwin") || low.contains("/devkitpro"))
}

fn find_python(explicit: &Option<PathBuf>, path_var: &Option<OsString>, only_path: bool) -> Option<(PathBuf, (u32, u32))> {
    let mut candidates: Vec<PathBuf> = vec![];
    if let Some(p) = explicit.clone().filter(|p| p.is_file()) {
        candidates.push(p);
    }
    if let Some(p) = std::env::var_os("PSXRECOMP_PYTHON").map(PathBuf::from).filter(|p| p.is_file()) {
        candidates.push(p);
    }
    if !only_path {
        // The `py` launcher knows where the real interpreters are.
        if let Some(py) = find_on_path(&["py"], path_var) {
            let mut cmd = Command::new(py);
            cmd.args(["-3", "-c", "import sys;print(sys.executable)"]).stdin(Stdio::null()).stderr(Stdio::null());
            #[cfg(windows)]
            {
                use std::os::windows::process::CommandExt;
                cmd.creation_flags(0x0800_0000);
            }
            if let Ok(o) = cmd.output() {
                let t = String::from_utf8_lossy(&o.stdout).trim().to_string();
                if o.status.success() && !t.is_empty() {
                    candidates.push(PathBuf::from(t));
                }
            }
        }
    }
    for n in ["python", "python3"] {
        if let Some(p) = find_on_path(&[n], path_var) {
            candidates.push(p);
        }
    }
    candidates
        .into_iter()
        .filter(|p| is_native_python_path(p))
        .find_map(|p| python_version(&p).filter(|v| *v >= (3, 8)).map(|v| (p, v)))
}

/// Git for Windows' `bash.exe`, found relative to `git.exe`
/// (`…/Git/cmd/git.exe` → `…/Git/bin/bash.exe`).
fn git_bash(git: &Path) -> Option<PathBuf> {
    let mut dir = git.parent();
    for _ in 0..4 {
        let d = dir?;
        for rel in ["bin/bash.exe", "usr/bin/bash.exe"] {
            let c = d.join(rel);
            if c.is_file() {
                return Some(c);
            }
        }
        dir = d.parent();
    }
    None
}

/// True when `dir` looks like the portable toolchain: `bin/cmake` and `bin/ninja`.
fn is_toolchain_dir(dir: &Path) -> bool {
    dir.join("bin").join(exe("cmake")).is_file() && dir.join("bin").join(exe("ninja")).is_file()
}

/// The toolchain's root: `dir` itself, or its only subfolder when the archive
/// had a single top-level directory.
fn resolve_toolchain_root(dir: &Path) -> Option<PathBuf> {
    if is_toolchain_dir(dir) {
        return Some(dir.to_path_buf());
    }
    let subs: Vec<PathBuf> = fs::read_dir(dir)
        .ok()?
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.is_dir())
        .collect();
    subs.into_iter().find(|p| is_toolchain_dir(p))
}

#[derive(Debug, Clone, Default)]
pub struct Ps1ToolSearch {
    pub path_var: Option<OsString>,
    pub git: Option<PathBuf>,
    pub python: Option<PathBuf>,
    pub powershell: Option<PathBuf>,
    pub toolchain_dir: Option<PathBuf>,
    pub cache_dir: PathBuf,
    /// Look only in `path_var` and the explicit paths.
    pub only_path: bool,
    pub skip_os_check: bool,
}

pub fn toolchain_cache_dir(cache: &Path) -> PathBuf {
    cache.join("toolchain")
}

/// Detect everything the build needs. Never fails: missing pieces are
/// reported with how to get them.
pub fn detect_toolchain(s: &Ps1ToolSearch) -> Ps1Toolchain {
    let supported_os = cfg!(windows) || s.skip_os_check;
    let mut problems = vec![];
    if !supported_os {
        problems.push("Automated PS1 builds are only supported on Windows for now.".to_string());
    }

    let git_path = s.git.clone().filter(|p| p.is_file()).or_else(|| find_on_path(&["git"], &s.path_var)).or_else(|| {
        if s.only_path {
            return None;
        }
        ["ProgramFiles", "ProgramFiles(x86)"]
            .iter()
            .filter_map(|k| std::env::var_os(k))
            .map(PathBuf::from)
            .flat_map(|p| [p.join("Git/cmd").join(exe("git")), p.join("Git/bin").join(exe("git"))])
            .find(|p| p.is_file())
    });
    if git_path.is_none() {
        problems.push("git was not found. Install it from https://git-scm.com/download/win.".into());
    }

    let python = find_python(&s.python, &s.path_var, s.only_path);
    if python.is_none() {
        problems.push(
            "Python 3.8 or newer was not found. Install it from https://www.python.org/downloads/ \
             (the Windows installer, not the Microsoft Store stub)."
                .into(),
        );
    }

    let powershell = s.powershell.clone().filter(|p| p.is_file()).or_else(|| {
        let sys = std::env::var_os("SystemRoot")
            .map(|r| PathBuf::from(r).join("System32/WindowsPowerShell/v1.0/powershell.exe"))
            .filter(|p| p.is_file() && !s.only_path);
        sys.or_else(|| find_on_path(&["powershell"], &s.path_var))
    });
    if powershell.is_none() && cfg!(windows) {
        problems.push("Windows PowerShell was not found.".into());
    }

    let bash = git_path.as_deref().and_then(git_bash);
    if bash.is_none() && git_path.is_some() && cfg!(windows) && !s.skip_os_check {
        problems.push(
            "Git's bash.exe was not found next to git. Reinstall Git for Windows with its default components."
                .into(),
        );
    }

    // Build tools: env override, Aura's cached download, then system.
    let env_dir = std::env::var_os("PSXRECOMP_TOOLCHAIN_DIR").map(PathBuf::from);
    let (source, dir): (&str, Option<PathBuf>) = if let Some(root) =
        s.toolchain_dir.clone().or(env_dir).and_then(|d| resolve_toolchain_root(&d))
    {
        ("env", Some(root))
    } else if let Some(root) = resolve_toolchain_root(&toolchain_cache_dir(&s.cache_dir)) {
        ("cache", Some(root))
    } else if find_on_path(&["cmake"], &s.path_var).is_some()
        && find_on_path(&["ninja"], &s.path_var).is_some()
        && find_on_path(&["clang", "cl"], &s.path_var).is_some()
    {
        ("system", None)
    } else {
        ("missing", None)
    };
    let (bt_path, bt_detail) = match (source, &dir) {
        ("env", Some(d)) => (Some(d.clone()), "your PSXRECOMP_TOOLCHAIN_DIR"),
        ("cache", Some(d)) => (Some(d.clone()), "Aura's downloaded toolchain"),
        ("system", _) => (Some(PathBuf::from("PATH")), "CMake, Ninja and a compiler from PATH"),
        _ => (None, "not installed — Aura can download a portable one"),
    };
    let build_tools = status("CMake + Ninja + clang", bt_path, bt_detail);

    let git = status("git", git_path, "fetches the framework");
    let python_status = status(
        "Python",
        python.as_ref().map(|(p, _)| p.clone()),
        &python.as_ref().map(|(_, v)| format!("Python {}.{}", v.0, v.1)).unwrap_or_else(|| "needed by the framework's tools".into()),
    );
    let powershell = status("PowerShell", powershell, "runs the project setup script");
    let bash = status("bash", bash, "from Git for Windows");
    let ready_apart_from_build_tools =
        supported_os && git.found && python_status.found && powershell.found && (bash.found || s.skip_os_check);

    Ps1Toolchain {
        supported_os,
        git,
        python: python_status,
        powershell,
        bash,
        build_tools,
        build_tools_source: source.to_string(),
        toolchain_dir: dir.map(|d| d.to_string_lossy().to_string()),
        ready_apart_from_build_tools,
        problems,
    }
}

// ---------------------------------------------------------------------------
// Planning
// ---------------------------------------------------------------------------

/// Default cache: `%LOCALAPPDATA%\AuraDecompTool\psxrecomp` (override with
/// `AURA_PS1_BUILD_CACHE`).
pub fn default_cache_dir() -> PathBuf {
    if let Some(p) = std::env::var_os("AURA_PS1_BUILD_CACHE") {
        return PathBuf::from(p);
    }
    let base = std::env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".cache")))
        .unwrap_or_else(std::env::temp_dir);
    base.join("AuraDecompTool").join("psxrecomp")
}

fn cache_of(opts: &Ps1BuildOptions) -> PathBuf {
    ps2_ingest::absolute_path(&opts.cache_dir.clone().unwrap_or_else(default_cache_dir))
}

fn framework_dir(opts: &Ps1BuildOptions, cache: &Path) -> PathBuf {
    opts.framework_override
        .as_deref()
        .map(ps2_ingest::absolute_path)
        .unwrap_or_else(|| cache.join("psxrecomp"))
}

fn ui_dir(opts: &Ps1BuildOptions, cache: &Path) -> PathBuf {
    opts.ui_override
        .as_deref()
        .map(ps2_ingest::absolute_path)
        .unwrap_or_else(|| cache.join("recomp-ui"))
}

fn cores(opts: &Ps1BuildOptions) -> usize {
    opts.jobs
        .unwrap_or_else(|| std::thread::available_parallelism().map(|n| n.get()).unwrap_or(4))
        .max(1)
}

fn search_from(opts: &Ps1BuildOptions, cache: &Path) -> Ps1ToolSearch {
    Ps1ToolSearch {
        path_var: None,
        git: opts.git.clone(),
        python: opts.python.clone(),
        powershell: opts.powershell.clone(),
        toolchain_dir: opts.toolchain_dir.clone(),
        cache_dir: cache.to_path_buf(),
        only_path: false,
        skip_os_check: opts.skip_os_check,
    }
}

/// What the workspace manifest says (`game.json` written by `ps1_ingest`).
#[derive(Debug, Clone)]
struct Manifest {
    title: String,
    display_name: String,
    serial: Option<String>,
    cue: PathBuf,
    boot_file: String,
    region: String,
    /// The image the user picked (a CHD/cue/iso the game can play from).
    source_image: String,
    /// Bytes of program text in the boot PS-X EXE (drives the time estimate).
    text_size: u64,
}

fn read_manifest(workspace: &Path) -> Result<Manifest, String> {
    let path = workspace.join("game.json");
    let text = fs::read_to_string(&path).map_err(|_| {
        format!("{} is not a PS1 workspace (no game.json). Run the disc wizard / `aura-cli ps1-ingest` first.", workspace.display())
    })?;
    let v: serde_json::Value = serde_json::from_str(&text).map_err(|e| format!("{} is not valid JSON: {e}", path.display()))?;
    if v.get("platform").and_then(|p| p.as_str()) != Some("PS1") {
        return Err(format!("{} is not a PS1 workspace (platform is not PS1).", workspace.display()));
    }
    let s = |k: &str| v.get(k).and_then(|x| x.as_str()).map(|x| x.to_string());
    let display_name = s("display_name").unwrap_or_else(|| "Game".into());
    Ok(Manifest {
        title: s("title").filter(|t| !t.trim().is_empty()).unwrap_or_else(|| display_name.clone()),
        display_name,
        serial: s("serial"),
        cue: PathBuf::from(s("cue_path").ok_or_else(|| "game.json has no cue_path".to_string())?),
        boot_file: s("boot_file").unwrap_or_default(),
        region: s("region").unwrap_or_default(),
        source_image: s("source_image").unwrap_or_default(),
        text_size: v
            .get("psx_exe")
            .and_then(|e| e.get("text_size"))
            .and_then(|t| t.as_u64())
            .unwrap_or(0),
    })
}

/// The folder the framework creates for the project (`<workspace>/<repo>`).
fn repo_slug(m: &Manifest) -> String {
    let base = m.serial.clone().unwrap_or_else(|| m.display_name.clone());
    let s: String = base
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c.to_ascii_lowercase() } else { '-' })
        .collect();
    format!("psx-{}", s.trim_matches('-'))
}

/// Rough disk need for the cache, toolchain and one project.
const DISK_BASE_BYTES: u64 = 2_500_000_000;

/// Rough wall-clock estimate in seconds. Code generation is single-threaded
/// and the C compile parallel; both scale with the boot program's size.
/// Calibrated on Mega Man X4 (1.18 MB program, 20 cores, warm toolchain): about
/// 70 s to generate and 130 s to compile, 203 s in all.
pub fn estimate_secs(text_size: u64, cores: usize, cold: bool) -> u64 {
    let f = (text_size as f64 / 1_177_600.0).clamp(0.25, 4.0);
    let generate = 70.0 * f;
    let compile = 2600.0 * f / cores.max(1) as f64;
    let setup = 60.0; // project scaffold, probe, configure, dependency fetch
    let fetch = if cold { 40.0 } else { 0.0 };
    (setup + generate + compile + fetch).round() as u64
}

/// Work out what a build needs and would download, without touching anything.
pub fn plan_build(workspace: &Path, opts: &Ps1BuildOptions) -> Result<Ps1BuildPlan, String> {
    let workspace = ps2_ingest::absolute_path(workspace);
    let m = read_manifest(&workspace)?;
    let cache = cache_of(opts);
    let toolchain = detect_toolchain(&search_from(opts, &cache));

    let mut blockers: Vec<String> = toolchain.problems.clone();
    if !m.cue.is_file() {
        blockers.push(format!(
            "The disc sheet {} is missing (the source image was moved or deleted). Run the wizard again.",
            m.cue.display()
        ));
    }

    let framework = framework_dir(opts, &cache);
    let framework_cached = opts.framework_override.is_some() || checkout_is_at(&framework, PINNED_COMMIT);
    let toolchain_cached = toolchain.build_tools_source != "missing";

    let mut downloads = vec![];
    if !framework_cached {
        downloads.push(DownloadItem {
            what: "PSXRecomp framework and launcher sources (git)".into(),
            from: "github.com/RetroPortingToolKit/psxrecomp, recomp-ui".into(),
            approx_mb: 150,
        });
    }
    if toolchain.build_tools_source == "missing" {
        downloads.push(DownloadItem {
            what: "Portable build toolchain (CMake, Ninja, clang)".into(),
            from: "github.com/RetroPortingToolKit/RetroPorting-Toolchains".into(),
            approx_mb: (TOOLCHAIN_BYTES / 1_000_000) as u32,
        });
    }
    // SDL3 and the nested submodules are fetched while the project is built.
    downloads.push(DownloadItem {
        what: "SDL3 and the framework's nested dependencies (fetched during the build)".into(),
        from: "libsdl.org, github.com".into(),
        approx_mb: 60,
    });
    let download_mb: u32 = downloads.iter().map(|d| d.approx_mb).sum();

    let required_bytes = DISK_BASE_BYTES;
    let free = free_space_bytes(&cache);
    if !space_ok(free, required_bytes) {
        blockers.push(format!(
            "Not enough free disk space for the build cache: about {:.1} GB needed, {:.1} GB free on that drive.",
            required_bytes as f64 / 1e9,
            free.unwrap_or(0) as f64 / 1e9
        ));
    }

    let n = cores(opts);
    let estimate_secs = estimate_secs(m.text_size, n, !(toolchain_cached && framework_cached));
    let slug = repo_slug(&m);
    let can_build = blockers.is_empty() && toolchain.ready_apart_from_build_tools;
    Ok(Ps1BuildPlan {
        toolchain,
        cache_dir: cache.to_string_lossy().to_string(),
        display_name: m.title.clone(),
        serial: m.serial.clone(),
        cue_path: m.cue.to_string_lossy().to_string(),
        downloads,
        download_mb,
        framework_cached,
        toolchain_cached,
        estimate_secs,
        cores: n,
        free_bytes: free,
        required_bytes,
        blockers,
        can_build,
        pinned_commit: PINNED_COMMIT.to_string(),
        project_dir: workspace.join(slug).to_string_lossy().to_string(),
        framework_patches: if opts.no_fixes || opts.framework_override.is_some() { vec![] } else { ps1_patches::planned() },
        config_additions: if opts.no_fixes { vec![] } else { ps1_patches::planned_config(m.serial.as_deref()) },
    })
}

/// "~12 min" / "about 90 seconds" for the UI and CLI.
pub fn describe_estimate(secs: u64) -> String {
    if secs < 90 {
        format!("about {secs} seconds")
    } else {
        format!("about {} minutes", (secs + 30) / 60)
    }
}

// ---------------------------------------------------------------------------
// Downloading, verifying, unpacking
// ---------------------------------------------------------------------------

fn curl_exe() -> PathBuf {
    if let Some(root) = std::env::var_os("SystemRoot") {
        let c = PathBuf::from(root).join("System32").join(exe("curl"));
        if c.is_file() {
            return c;
        }
    }
    PathBuf::from("curl")
}

/// SHA-256 of a file as lowercase hex.
pub fn sha256_file(path: &Path) -> Result<String, String> {
    let mut f = fs::File::open(path).map_err(|e| format!("Cannot open {}: {e}", path.display()))?;
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 1 << 20];
    loop {
        let n = f.read(&mut buf).map_err(|e| format!("Cannot read {}: {e}", path.display()))?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Ok(h.finalize().iter().map(|b| format!("{b:02x}")).collect())
}

/// Download `url` to `dest` with curl, reporting progress from the growing
/// file and honouring cancellation.
fn download(r: &mut Runner, url: &str, dest: &Path, expected: u64, from: f64, to: f64, what: &str) -> Result<(), String> {
    if let Some(p) = dest.parent() {
        fs::create_dir_all(p).map_err(|e| format!("Cannot create {}: {e}", p.display()))?;
    }
    let part = dest.with_extension("part");
    let _ = fs::remove_file(&part);
    r.push_line(&format!("$ curl {url}"));
    let mut cmd = Command::new(curl_exe());
    cmd.args(["-L", "--fail", "--silent", "--show-error", "--retry", "3", "-o"])
        .arg(&part)
        .arg(url)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(0x0800_0000);
    }
    let mut child = cmd.spawn().map_err(|e| format!("Could not start curl to download {what}: {e}"))?;
    let status = loop {
        match child.try_wait() {
            Ok(Some(st)) => break st,
            Ok(None) => {
                let got = fs::metadata(&part).map(|m| m.len()).unwrap_or(0);
                let frac = if expected > 0 { (got as f64 / expected as f64).min(1.0) } else { 0.0 };
                r.fraction = from + (to - from) * frac;
                r.message = format!(
                    "Downloading {what} ({:.0} of {:.0} MB)…",
                    got as f64 / 1e6,
                    expected as f64 / 1e6
                );
                if !r.emit(false) {
                    crate::build_common::kill_tree(child.id());
                    let _ = child.kill();
                    let _ = child.wait();
                    let _ = fs::remove_file(&part);
                    return Err("Cancelled".into());
                }
                std::thread::sleep(Duration::from_millis(150));
            }
            Err(e) => return Err(format!("Waiting for curl failed: {e}")),
        }
    };
    if !status.success() {
        let mut err = String::new();
        if let Some(mut e) = child.stderr.take() {
            let _ = e.read_to_string(&mut err);
        }
        let _ = fs::remove_file(&part);
        return Err(format!("Downloading {what} failed ({status}): {}", err.trim()));
    }
    fs::rename(&part, dest).map_err(|e| format!("Cannot finish {}: {e}", dest.display()))
}

fn tar_exe() -> PathBuf {
    if let Some(root) = std::env::var_os("SystemRoot") {
        let c = PathBuf::from(root).join("System32").join(exe("tar"));
        if c.is_file() {
            return c;
        }
    }
    PathBuf::from("tar")
}

/// Download, verify and unpack the portable toolchain into `<cache>/toolchain`.
fn ensure_toolchain(r: &mut Runner, cache: &Path, opts: &Ps1BuildOptions) -> Result<PathBuf, String> {
    let dest_dir = toolchain_cache_dir(cache);
    if let Some(root) = resolve_toolchain_root(&dest_dir) {
        return Ok(root);
    }
    let url = opts.toolchain_url.clone().unwrap_or_else(|| TOOLCHAIN_URL.to_string());
    let want_sha = opts.toolchain_sha256.clone().unwrap_or_else(|| TOOLCHAIN_SHA256.to_string());
    let zip = cache.join("downloads").join("cmake-clang-v1-windows-x64.zip");

    r.stage("toolchain", "Downloading the portable build toolchain…", 0.02)?;
    let have_valid = zip.is_file() && sha256_file(&zip).map(|h| h.eq_ignore_ascii_case(&want_sha)).unwrap_or(false);
    if !have_valid {
        let expected = if opts.toolchain_url.is_some() {
            fs::metadata(url.trim_start_matches("file:///")).map(|m| m.len()).unwrap_or(0)
        } else {
            TOOLCHAIN_BYTES
        };
        download(r, &url, &zip, expected, 0.02, 0.22, "the build toolchain")?;
    }
    r.stage("toolchain", "Verifying the download…", 0.23)?;
    let got = sha256_file(&zip)?;
    if !got.eq_ignore_ascii_case(&want_sha) {
        let _ = fs::remove_file(&zip);
        return Err(format!(
            "The downloaded toolchain does not match its published checksum (expected {want_sha}, got {got}). \
             It was deleted; try again, and report this if it repeats."
        ));
    }

    r.stage("toolchain", "Unpacking the toolchain…", 0.24)?;
    let _ = fs::remove_dir_all(&dest_dir);
    fs::create_dir_all(&dest_dir).map_err(|e| format!("Cannot create {}: {e}", dest_dir.display()))?;
    r.creep = Some((0.24, 0.30, 60.0));
    r.run("unpack toolchain", &tar_exe(), &[os("-xf"), zip.as_os_str().to_os_string(), os("-C"), dest_dir.as_os_str().to_os_string()], None, |_| None)?;
    resolve_toolchain_root(&dest_dir).ok_or_else(|| {
        format!(
            "The toolchain archive unpacked, but {} has no bin/cmake and bin/ninja. The archive layout may have changed.",
            dest_dir.display()
        )
    })
}

// ---------------------------------------------------------------------------
// Build
// ---------------------------------------------------------------------------

/// `[12/345]` ninja progress → `(12, 345)`.
pub fn parse_ninja_progress(line: &str) -> Option<(u32, u32)> {
    let rest = line.trim_start().strip_prefix('[')?;
    let end = rest.find(']')?;
    let (a, b) = rest[..end].split_once('/')?;
    Some((a.trim().parse().ok()?, b.trim().parse().ok()?))
}

/// Maps the setup script's output to overall progress.
///
/// The script runs several phases that each have their own `[n/m]` ninja
/// counter (the emitter tools, then the game's runtime), so a raw counter
/// would jump backwards. This keeps a high-water mark and gives each phase
/// its own slice of the bar: setup 0.38–0.50, emitters 0.50–0.60, runtime
/// 0.62–0.95.
pub struct ProgressMapper {
    best: f64,
    generated: bool,
}

impl ProgressMapper {
    pub fn new() -> Self {
        ProgressMapper { best: 0.38, generated: false }
    }

    /// New overall fraction if `line` moves progress forward.
    pub fn line(&mut self, line: &str) -> Option<f64> {
        let l = line.trim_start().to_ascii_lowercase();
        let candidate = if l.contains("generate complete") {
            self.generated = true;
            0.62
        } else if let Some((n, m)) = parse_ninja_progress(line).filter(|(_, m)| *m > 0) {
            let f = n.min(m) as f64 / m as f64;
            if self.generated {
                0.62 + 0.33 * f
            } else {
                0.50 + 0.10 * f
            }
        } else if l.starts_with("== adding submodules") {
            0.40
        } else if l.starts_with("== probing disc") {
            0.46
        } else if l.starts_with("== generate") {
            0.50
        } else {
            return None;
        };
        if candidate > self.best {
            self.best = candidate;
            Some(candidate)
        } else {
            None
        }
    }
}

impl Default for ProgressMapper {
    fn default() -> Self {
        Self::new()
    }
}

/// Everything the setup script is told about the game.
pub struct SetupArgs<'a> {
    pub script: &'a Path,
    pub cue: &'a Path,
    pub title: &'a str,
    pub boot_file: &'a str,
    pub out_dir: &'a Path,
    pub repo: &'a str,
    pub framework_url: &'a str,
    pub ui_url: &'a str,
    /// Region as the manifest records it (`NTSC-U/C (North America)`).
    pub region: &'a str,
}

/// The region word the framework's catalog expects.
pub fn marketing_region(region: &str) -> &'static str {
    let r = region.to_ascii_lowercase();
    if r.contains("europe") || r.contains("pal") {
        "Europe"
    } else if r.contains("japan") {
        "Japan"
    } else if r.contains("korea") {
        "Korea"
    } else {
        "USA"
    }
}

/// Arguments for the setup script. Everything the interactive script would
/// prompt for is answered, and everything that would publish or fetch extras
/// (GitHub repo, CI, boxart, netplay) is switched off.
///
/// Description, publisher and year are always non-empty: the script forwards
/// them to a Python tool as `--description $Description`, and Windows
/// PowerShell 5.1 silently drops an empty argument, which leaves that option
/// without its value and makes the disc probe fail.
pub fn setup_script_args(a: &SetupArgs) -> Vec<OsString> {
    let mut out: Vec<OsString> =
        vec![os("-NoProfile"), os("-NonInteractive"), os("-ExecutionPolicy"), os("Bypass"), os("-File")];
    out.push(a.script.as_os_str().to_os_string());
    let mut kv = |k: &str, v: &str| {
        out.push(os(k));
        out.push(os(v));
    };
    kv("-Disc", &a.cue.to_string_lossy());
    kv("-Name", a.title);
    kv("-Dir", &a.out_dir.to_string_lossy());
    kv("-GithubRepo", a.repo);
    if !a.boot_file.is_empty() {
        let stem = a.boot_file.rsplit(['/', '\\']).next().unwrap_or(a.boot_file);
        kv("-BootExe", stem);
    }
    kv("-PsxrecompUrl", a.framework_url);
    kv("-PsxrecompRef", PINNED_BRANCH);
    kv("-RecompUiUrl", a.ui_url);
    kv("-RecompUiRef", PINNED_BRANCH);
    kv("-Region", marketing_region(a.region));
    kv("-Description", &format!("{} (PlayStation)", a.title));
    kv("-Publisher", "Unknown");
    kv("-Year", "Unknown");
    for flag in [
        "-Yes",
        "-EnableRecompUi",
        "-EnableWizard",
        "-NoNetplay",
        "-NoCi",
        "-NoFetchBoxart",
        "-NoGithub",
        "-Generate",
        "-EnableBuild",
    ] {
        out.push(os(flag));
    }
    out
}

/// `PATH` for the child: toolchain `bin`, Git's `bin` (so `bash` is Git's,
/// not whichever happens to come first), then the inherited path.
fn child_path(toolchain: Option<&Path>, bash: Option<&Path>) -> OsString {
    let mut parts: Vec<PathBuf> = vec![];
    if let Some(t) = toolchain {
        parts.push(t.join("bin"));
    }
    if let Some(b) = bash.and_then(|b| b.parent()) {
        parts.push(b.to_path_buf());
    }
    if let Some(p) = std::env::var_os("PATH") {
        parts.extend(std::env::split_paths(&p));
    }
    std::env::join_paths(parts).unwrap_or_default()
}

/// The built program: the name `psxrecomp_exe_name-*.txt` records, else the
/// newest `.exe` directly inside the build directory.
pub fn find_built_exe(build_dir: &Path) -> Option<PathBuf> {
    let rd = fs::read_dir(build_dir).ok()?;
    let entries: Vec<_> = rd.filter_map(|e| e.ok()).collect();
    for e in &entries {
        let name = e.file_name().to_string_lossy().to_string();
        if name.starts_with("psxrecomp_exe_name") && name.ends_with(".txt") {
            if let Ok(t) = fs::read_to_string(e.path()) {
                let n = t.lines().next().unwrap_or("").trim().to_string();
                if !n.is_empty() {
                    let mut p = build_dir.join(&n);
                    if !p.is_file() && p.extension().is_none() {
                        p = build_dir.join(exe(&n));
                    }
                    if p.is_file() {
                        return Some(p);
                    }
                }
            }
        }
    }
    entries
        .iter()
        .filter(|e| {
            let n = e.file_name().to_string_lossy().to_ascii_lowercase();
            n.ends_with(".exe") && !n.contains("test") && !n.starts_with("cmake") && !n.contains("compiler")
        })
        .filter_map(|e| Some((e.metadata().ok()?.modified().ok()?, e.path())))
        .max_by_key(|(t, _)| *t)
        .map(|(_, p)| p)
}

fn is_build_debris(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    n == "cmakefiles"
        || n == "cmakecache.txt"
        || n == "cmake_install.cmake"
        || n == "testing"
        || n == "_deps"
        || n.starts_with(".ninja")
        || n.ends_with(".ninja")
        || n.ends_with(".lib")
        || n.ends_with(".a")
        || n.ends_with(".ilk")
        || n.ends_with(".pdb")
        || n.ends_with(".exp")
        || n.starts_with("psxrecomp_exe_name")
        || n == "compile_commands.json"
}

fn copy_tree(from: &Path, to: &Path, files: &mut usize, bytes: &mut u64) -> Result<(), String> {
    fs::create_dir_all(to).map_err(|e| format!("Cannot create {}: {e}", to.display()))?;
    for e in fs::read_dir(from).map_err(|e| format!("Cannot read {}: {e}", from.display()))?.filter_map(|e| e.ok()) {
        let name = e.file_name().to_string_lossy().to_string();
        if is_build_debris(&name) {
            continue;
        }
        let src = e.path();
        let dst = to.join(&name);
        let ft = e.file_type().map_err(|e| e.to_string())?;
        if ft.is_dir() {
            copy_tree(&src, &dst, files, bytes)?;
        } else if ft.is_file() {
            let n = fs::copy(&src, &dst).map_err(|e| format!("Cannot copy {}: {e}", src.display()))?;
            *files += 1;
            *bytes += n;
        }
    }
    Ok(())
}

/// Gather the built program and everything it needs beside it.
pub fn package_build(build_dir: &Path, exe_path: &Path, out: &Path, title: &str) -> Result<Ps1Package, String> {
    let _ = fs::remove_dir_all(out);
    let (mut files, mut bytes) = (0usize, 0u64);
    copy_tree(build_dir, out, &mut files, &mut bytes)?;
    let name = exe_path.file_name().ok_or("the built exe has no file name")?;
    let packaged = out.join(name);
    if !packaged.is_file() {
        return Err(format!("Packaging lost {} (it was filtered out).", exe_path.display()));
    }
    let readme = format!(
        "{title}\r\n\r\nDouble-click {} to play.\r\n\r\nOn the first run the game asks for your disc image (.cue/.bin, .chd or .iso);\r\n\
         it is not included. This folder contains program code translated from your own disc,\r\n\
         so keep it to yourself and do not share it.\r\n\r\nBuilt with PSXRecomp through Aura Decomp Tool.\r\n",
        name.to_string_lossy()
    );
    let _ = fs::write(out.join("README.txt"), readme);
    let marker = serde_json::json!({
        "aura_package": 1,
        "platform": "PS1",
        "pipeline": "psxrecomp",
        "exe": name.to_string_lossy(),
        "title": title,
    });
    fs::write(out.join(PACKAGE_MARKER), serde_json::to_string_pretty(&marker).unwrap_or_default())
        .map_err(|e| format!("Cannot write {PACKAGE_MARKER}: {e}"))?;
    Ok(Ps1Package {
        package_dir: out.to_string_lossy().to_string(),
        exe: packaged.to_string_lossy().to_string(),
        files,
        bytes,
    })
}

/// Branch name → pinned commit, so `git submodule add -b` can clone it.
fn expose_pinned_branch(r: &mut Runner, git: &Path, dir: &Path, commit: &str) -> Result<(), String> {
    r.run(
        "git branch",
        git,
        &[os("-C"), dir.as_os_str().to_os_string(), os("branch"), os("-f"), os(PINNED_BRANCH), os(commit)],
        None,
        |_| None,
    )
}

/// Resolve the HEAD commit of a checkout (used for an unpinned UI repo).
fn head_commit(git: &Path, dir: &Path) -> Option<String> {
    let mut cmd = Command::new(git);
    cmd.arg("-C").arg(dir).args(["rev-parse", "HEAD"]).stdin(Stdio::null());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(0x0800_0000);
    }
    let out = cmd.output().ok()?;
    out.status.success().then(|| String::from_utf8_lossy(&out.stdout).trim().to_string()).filter(|s| s.len() >= 7)
}

/// Build the game. `progress` returns `false` to cancel.
pub fn build_game(
    workspace: &Path,
    opts: &Ps1BuildOptions,
    progress: &mut dyn FnMut(&BuildProgress) -> bool,
) -> Result<Ps1BuildResult, String> {
    let workspace = ps2_ingest::absolute_path(workspace);
    let plan = plan_build(&workspace, opts)?;
    if !plan.can_build {
        return Err(format!("Cannot build yet:\n- {}", plan.blockers.join("\n- ")));
    }
    if !plan.downloads.is_empty() && !opts.allow_downloads {
        let list: Vec<String> = plan.downloads.iter().map(|d| format!("{} (~{} MB)", d.what, d.approx_mb)).collect();
        return Err(format!(
            "NEEDS_DOWNLOAD_CONSENT: this build downloads about {} MB from GitHub and libsdl.org: {}. Confirm to continue.",
            plan.download_mb,
            list.join("; ")
        ));
    }
    let m = read_manifest(&workspace)?;
    let cache = cache_of(opts);
    fs::create_dir_all(&cache).map_err(|e| format!("Cannot create the build cache {}: {e}", cache.display()))?;
    let log_path = workspace.join("build.log");
    let log_file = fs::File::create(&log_path).ok();
    let mut r = Runner::new(progress, log_file);

    let tc = &plan.toolchain;
    let git = PathBuf::from(tc.git.path.clone().unwrap_or_default());
    let python = tc.python.path.clone().map(PathBuf::from);
    let powershell = PathBuf::from(tc.powershell.path.clone().unwrap_or_default());
    let bash = tc.bash.path.clone().map(PathBuf::from);
    let mut warnings: Vec<String> = vec![];
    let mut framework_patches: Vec<PatchOutcome> = vec![];
    let mut config_additions: Vec<String> = vec![];

    // ----- toolchain -----------------------------------------------------------
    let toolchain_root: Option<PathBuf> = match tc.build_tools_source.as_str() {
        "missing" => Some(ensure_toolchain(&mut r, &cache, opts)?),
        _ => tc.toolchain_dir.clone().map(PathBuf::from),
    };

    // ----- framework + launcher sources ------------------------------------------
    r.stage("source", "Fetching the PSXRecomp framework…", 0.31)?;
    let framework = framework_dir(opts, &cache);
    if opts.framework_override.is_none() {
        ensure_git_checkout(&mut r, &git, &framework, FRAMEWORK_URL, PINNED_COMMIT)?;
        expose_pinned_branch(&mut r, &git, &framework, PINNED_COMMIT)?;
        if !opts.no_fixes {
            // Commit the carried fixes onto the branch the project clones.
            framework_patches =
                ps1_patches::apply_to_base(&git, &framework, PINNED_COMMIT, PINNED_BRANCH, ps1_patches::FRAMEWORK_PATCHES)?;
            for p in &framework_patches {
                r.push_line(&format!("framework fix: {} ({})", p.title, p.state));
            }
        }
    } else if !framework.join(SETUP_SCRIPT).is_file() {
        return Err(format!("{} is not a PSXRecomp checkout (no {SETUP_SCRIPT}).", framework.display()));
    }
    r.stage("source", "Fetching the launcher sources…", 0.35)?;
    let ui = ui_dir(opts, &cache);
    if opts.ui_override.is_none() {
        if !ui.join(".git").exists() {
            fs::create_dir_all(&ui).map_err(|e| format!("Cannot create {}: {e}", ui.display()))?;
            r.run("git clone", &git, &[os("clone"), os("--depth"), os("1"), os(UI_URL), ui.as_os_str().to_os_string()], None, |_| None)?;
        }
        let head = head_commit(&git, &ui).ok_or_else(|| format!("Cannot read the launcher checkout in {}", ui.display()))?;
        expose_pinned_branch(&mut r, &git, &ui, &head)?;
    } else if !ui.is_dir() {
        return Err(format!("{} is not a directory.", ui.display()));
    }

    // ----- project ---------------------------------------------------------------
    let script = framework.join(SETUP_SCRIPT);
    if !script.is_file() {
        return Err(format!("The framework checkout has no {SETUP_SCRIPT} (looked in {}).", framework.display()));
    }
    let repo = repo_slug(&m);
    let project_dir = workspace.join(&repo);
    if project_dir.exists() {
        // A previous (possibly failed) attempt: the script refuses an existing folder.
        fs::remove_dir_all(&project_dir)
            .map_err(|e| format!("Cannot remove the old project {}: {e}", project_dir.display()))?;
    }
    r.stage("project", "Creating the project and generating code…", 0.38)?;
    r.creep = Some((0.38, 0.60, plan.estimate_secs as f64 * 0.3));
    r.env = vec![
        (os("PATH"), child_path(toolchain_root.as_deref(), bash.as_deref())),
        (os("PSXRECOMP_SETUP_YES"), os("1")),
        (os("GIT_TERMINAL_PROMPT"), os("0")),
        // git settings for the whole run (git reads these ahead of any
        // config file). 0: newer git refuses local-path submodules unless
        // told otherwise. 1-2: no CRLF conversion and no CRLF warnings. With a
        // default Git for Windows (`core.autocrlf=true`) every generated file
        // makes `git add` print a warning, and the setup script's
        // `git add generated 2>$null` under `$ErrorActionPreference='Stop'`
        // then never returns in Windows PowerShell 5.1. 3: long paths.
        (os("GIT_CONFIG_COUNT"), os("4")),
        (os("GIT_CONFIG_KEY_0"), os("protocol.file.allow")),
        (os("GIT_CONFIG_VALUE_0"), os("always")),
        (os("GIT_CONFIG_KEY_1"), os("core.autocrlf")),
        (os("GIT_CONFIG_VALUE_1"), os("false")),
        (os("GIT_CONFIG_KEY_2"), os("core.safecrlf")),
        (os("GIT_CONFIG_VALUE_2"), os("false")),
        (os("GIT_CONFIG_KEY_3"), os("core.longpaths")),
        (os("GIT_CONFIG_VALUE_3"), os("true")),
    ];
    if let Some(t) = &toolchain_root {
        r.env.push((os("PSXRECOMP_TOOLCHAIN_DIR"), t.as_os_str().to_os_string()));
    }
    if let Some(py) = &python {
        r.env.push((os("PSXRECOMP_PYTHON"), py.as_os_str().to_os_string()));
    }
    // The framework's shell scripts rely on Git-bash converting `/e/...`
    // paths for native tools; a user environment that switched that off
    // (MSYS_NO_PATHCONV) would break them.
    r.env_remove = vec![os("MSYS_NO_PATHCONV"), os("MSYS2_ARG_CONV_EXCL")];
    let args = setup_script_args(&SetupArgs {
        script: &script,
        cue: &m.cue,
        title: &m.title,
        boot_file: &m.boot_file,
        out_dir: &workspace,
        repo: &repo,
        framework_url: &framework.to_string_lossy(),
        ui_url: &ui.to_string_lossy(),
        region: &m.region,
    });
    let mut mapper = ProgressMapper::new();
    r.run("PSXRecomp project setup", &powershell, &args, Some(&workspace), |line| mapper.line(line))?;
    let build_dir = project_dir.join("build-release");

    // ----- title-specific config -------------------------------------------------
    if !opts.no_fixes {
        if let Some(serial) = m.serial.as_deref() {
            // The project's own game.toml (so a rebuild keeps it) and the copy
            // staged next to the program, which is what gets packaged and read.
            for file in [project_dir.join("game.toml"), build_dir.join("game.toml")] {
                if !file.is_file() {
                    continue;
                }
                match ps1_patches::apply_config_to_file(&file, serial, false) {
                    Ok(changes) => {
                        for c in changes {
                            r.push_line(&format!("title fix in {}: {c}", file.display()));
                            if !config_additions.contains(&c) {
                                config_additions.push(c);
                            }
                        }
                    }
                    Err(e) => warnings.push(format!("Could not add the title-specific fixes to {}: {e}", file.display())),
                }
            }
        }
    }

    // ----- package -------------------------------------------------------------
    let exe_path = find_built_exe(&build_dir).ok_or_else(|| {
        format!(
            "The setup finished but no game program was found in {}. See {} for the build output.",
            build_dir.display(),
            log_path.display()
        )
    })?;
    let package = if opts.package {
        r.stage("package", "Assembling the game folder…", 0.95)?;
        let out = workspace.join("package");
        match package_build(&build_dir, &exe_path, &out, &m.title) {
            Ok(p) => Some(p),
            Err(e) => {
                warnings.push(format!("The game was built but packaging failed: {e}"));
                None
            }
        }
    } else {
        None
    };
    r.stage("done", "Done", 1.0)?;
    r.finish_stage();
    let elapsed = r.started.elapsed().as_secs_f64();
    let stage_secs = r.stage_secs.clone();
    Ok(Ps1BuildResult {
        exe: package.as_ref().map(|p| p.exe.clone()).unwrap_or_else(|| exe_path.to_string_lossy().to_string()),
        project_dir: project_dir.to_string_lossy().to_string(),
        build_dir: build_dir.to_string_lossy().to_string(),
        cache_dir: cache.to_string_lossy().to_string(),
        log_path: log_path.to_string_lossy().to_string(),
        source_image: m.source_image.clone(),
        elapsed_secs: elapsed,
        stage_secs,
        package,
        framework_patches,
        config_additions,
        warnings,
    })
}
