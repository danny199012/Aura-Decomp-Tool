//! One-click build: generated C++ + the upstream ps2recomp runtime -> a game
//! executable -> a double-click folder.
//!
//! This automates the steps that were previously done by hand (and verified on
//! a homebrew and a retail game, with upstream commit [`PINNED_COMMIT`]):
//!
//! 1. find CMake, git and a Visual Studio C++ toolchain,
//! 2. fetch the pinned upstream source into a cache folder,
//! 3. build `ps2_recomp` once (cached),
//! 4. run it on the workspace's `config.toml`,
//! 5. drop the generated `*.cpp` into `ps2xRuntime/src/runner/` and the
//!    generated `*.h` into `ps2xRuntime/include/` (headers in the runner
//!    folder do not compile), configure and build `ps2EntryRunner`,
//! 6. package the result with [`crate::ps2_package`].
//!
//! Nothing is downloaded without consent: [`plan_build`] lists exactly what a
//! build would fetch, and [`build_game`] refuses to start the downloads unless
//! `allow_downloads` is set. No shell is ever involved; every process is
//! spawned with an argument vector.
//!
//! Pure Rust (no Tauri), so the GUI, the CLI and the tests share it.

use crate::build_common::Runner;
pub use crate::build_common::{free_space_bytes, space_ok, BuildProgress, DownloadItem, ToolStatus};
use crate::ps2_ingest;
use crate::ps2_package::{self, PackageOptions, PackageResult};
use serde::Serialize;
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

/// Upstream project the generated code is built against.
pub const UPSTREAM_URL: &str = "https://github.com/ran-j/PS2Recomp.git";
/// Known-good upstream commit (2026-10-14). Aura's config schema, the stub
/// binding syntax and the build recipe below were verified against it.
pub const PINNED_COMMIT: &str = "eb8688b2fd191129f103a39543002c005b33409c";

/// Upstream's default unity-build batch size for the runner target.
const UNITY_BATCH: usize = 32;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize)]
pub struct Toolchain {
    pub supported_os: bool,
    pub cmake: ToolStatus,
    pub git: ToolStatus,
    pub compiler: ToolStatus,
    pub ready: bool,
    /// Human-readable list of what is missing and how to get it.
    pub problems: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct BuildPlan {
    pub toolchain: Toolchain,
    pub cache_dir: String,
    pub downloads: Vec<DownloadItem>,
    pub download_mb: u32,
    pub source_cached: bool,
    pub recompiler_cached: bool,
    pub runtime_configured: bool,
    pub functions: usize,
    /// Rough wall-clock estimate for this machine, in seconds.
    pub estimate_secs: u64,
    pub cores: usize,
    pub free_bytes: Option<u64>,
    pub required_bytes: u64,
    /// Everything that currently prevents the build (empty = can build).
    pub blockers: Vec<String>,
    pub can_build: bool,
    pub pinned_commit: String,
    /// The lean recompiler variant was requested (see [`apply_lean_patch`]).
    pub lean_indirect_calls: bool,
    /// The lean variant is already built in the cache (no extra step needed).
    pub lean_ready: bool,
    /// How much of this game the recompiler will expand, measured at ingest.
    pub indirect_profile: Option<ps2_ingest::IndirectProfile>,
}

#[derive(Debug, Clone, Default)]
pub struct BuildOptions {
    pub cache_dir: Option<PathBuf>,
    /// The user has agreed to the downloads listed by [`plan_build`].
    pub allow_downloads: bool,
    /// Package the built exe into `<workspace>/package` afterwards.
    pub package: bool,
    /// Hide upstream's debug overlay and console window (and its very verbose
    /// logging) so the result looks like a normal program.
    pub native_feel: bool,
    /// Turn on upstream's "fast release" mode (`/GL /LTCG /arch:AVX2 /fp:fast`,
    /// no console subsystem). It sits behind `CMAKE_BUILD_TYPE=Release`, which
    /// the Visual Studio generator leaves empty, so without this flag none of
    /// it applies. Faster game, but a longer and more memory-hungry link.
    pub fast_release: bool,
    /// Use the experimental *lean* recompiler: an ordinary indirect call
    /// (`jalr $ra`) no longer turns every instruction of its function into a
    /// resumable entry point. See [`apply_lean_patch`] for what that changes.
    pub lean_indirect_calls: bool,
    pub jobs: Option<usize>,
    // Overrides, mainly for tests and for reusing an existing checkout/build.
    pub cmake: Option<PathBuf>,
    pub git: Option<PathBuf>,
    pub source_override: Option<PathBuf>,
    pub recompiler: Option<PathBuf>,
    pub launcher_exe: Option<PathBuf>,
    /// Skip the Visual Studio / OS check (tests with a fake cmake).
    pub skip_compiler_check: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct BuildResult {
    pub exe: String,
    pub runtime_build_dir: String,
    pub cache_dir: String,
    pub log_path: String,
    pub generated_sources: usize,
    pub elapsed_secs: f64,
    /// `(stage, seconds)` in execution order.
    pub stage_secs: Vec<(String, f64)>,
    pub native_feel: bool,
    pub fast_release: bool,
    pub lean_indirect_calls: bool,
    pub package: Option<PackageResult>,
    pub warnings: Vec<String>,
}

// ---------------------------------------------------------------------------
// Cache locations
// ---------------------------------------------------------------------------

/// Default cache: `AURA_BUILD_CACHE`, else `%LOCALAPPDATA%\AuraDecompTool\ps2recomp`
/// (or the XDG/HOME equivalent).
pub fn default_cache_dir() -> PathBuf {
    if let Some(p) = std::env::var_os("AURA_BUILD_CACHE") {
        return PathBuf::from(p);
    }
    #[cfg(windows)]
    if let Some(l) = std::env::var_os("LOCALAPPDATA") {
        return PathBuf::from(l).join("AuraDecompTool").join("ps2recomp");
    }
    if let Some(x) = std::env::var_os("XDG_CACHE_HOME") {
        return PathBuf::from(x).join("aura-decomp-tool").join("ps2recomp");
    }
    if let Some(h) = std::env::var_os("HOME") {
        return PathBuf::from(h).join(".cache").join("aura-decomp-tool").join("ps2recomp");
    }
    std::env::temp_dir().join("aura-decomp-tool-ps2recomp")
}

fn cache_of(opts: &BuildOptions) -> PathBuf {
    ps2_ingest::absolute_path(&opts.cache_dir.clone().unwrap_or_else(default_cache_dir))
}

fn source_dir(opts: &BuildOptions, cache: &Path) -> PathBuf {
    opts.source_override
        .as_deref()
        .map(ps2_ingest::absolute_path)
        .unwrap_or_else(|| cache.join("PS2Recomp"))
}

fn exe_name(base: &str) -> String {
    if cfg!(windows) { format!("{base}.exe") } else { base.to_string() }
}

fn recompiler_in(build_dir: &Path) -> Option<PathBuf> {
    ["ps2xRecomp/Release", "ps2xRecomp"]
        .iter()
        .map(|d| build_dir.join(d).join(exe_name("ps2_recomp")))
        .find(|p| p.is_file())
}

fn runtime_exe_in(build_dir: &Path) -> Option<PathBuf> {
    ["ps2xRuntime/Release", "ps2xRuntime"]
        .iter()
        .map(|d| build_dir.join(d).join(exe_name("ps2EntryRunner")))
        .find(|p| p.is_file())
}

/// Is the checkout at `dir` exactly the pinned commit? Read straight from
/// `.git/HEAD` (a detached HEAD holds the hash), so no git process is needed.
fn source_is_pinned(dir: &Path) -> bool {
    fs::read_to_string(dir.join(".git").join("HEAD"))
        .map(|s| s.trim() == PINNED_COMMIT)
        .unwrap_or(false)
        && dir.join("CMakeLists.txt").is_file()
}

// ---------------------------------------------------------------------------
// Toolchain detection
// ---------------------------------------------------------------------------

/// Where to look; the defaults read the real environment.
#[derive(Debug, Clone, Default)]
pub struct ToolSearch {
    pub path_var: Option<OsString>,
    pub cmake: Option<PathBuf>,
    pub git: Option<PathBuf>,
    pub vswhere: Option<PathBuf>,
    pub skip_compiler_check: bool,
    /// Look only in `path_var` and the explicit paths (no Program Files / VS
    /// fallbacks). Lets tests assert "not found" on a machine that has them.
    pub only_path: bool,
}

fn find_on_path(names: &[&str], path_var: &Option<OsString>) -> Option<PathBuf> {
    let pv = path_var.clone().or_else(|| std::env::var_os("PATH"))?;
    ps2_ingest::search_path(names, &pv)
}

/// `ProgramFiles` and `ProgramFiles(x86)` (Windows), as they exist.
fn program_files() -> Vec<PathBuf> {
    ["ProgramFiles", "ProgramFiles(x86)"]
        .iter()
        .filter_map(|k| std::env::var_os(k))
        .map(PathBuf::from)
        .collect()
}

/// CMake that ships inside Visual Studio (any year/edition), newest last.
fn vs_bundled_cmake() -> Option<PathBuf> {
    let mut found: Vec<PathBuf> = vec![];
    for pf in program_files() {
        let root = pf.join("Microsoft Visual Studio");
        let Ok(years) = fs::read_dir(&root) else { continue };
        for y in years.filter_map(|e| e.ok()) {
            let Ok(eds) = fs::read_dir(y.path()) else { continue };
            for ed in eds.filter_map(|e| e.ok()) {
                let c = ed
                    .path()
                    .join("Common7/IDE/CommonExtensions/Microsoft/CMake/CMake/bin")
                    .join(exe_name("cmake"));
                if c.is_file() {
                    found.push(c);
                }
            }
        }
    }
    found.sort();
    found.pop()
}

fn tool(name: &str, path: Option<PathBuf>, detail: &str) -> ToolStatus {
    ToolStatus {
        name: name.to_string(),
        found: path.is_some(),
        path: path.map(|p| p.to_string_lossy().to_string()),
        detail: detail.to_string(),
    }
}

/// Detect CMake, git and a C++ compiler. Never fails: missing pieces are
/// reported with how to obtain them.
pub fn detect_toolchain(s: &ToolSearch) -> Toolchain {
    let supported_os = cfg!(windows) || s.skip_compiler_check;
    let mut problems: Vec<String> = vec![];
    if !supported_os {
        problems.push(
            "Automated builds are only supported on Windows (MSVC). On other systems build upstream's \
             runtime by hand and use the packaging step."
                .into(),
        );
    }

    let cmake_path = s
        .cmake
        .clone()
        .filter(|p| p.is_file())
        .or_else(|| find_on_path(&["cmake"], &s.path_var))
        .or_else(|| {
            if s.only_path {
                return None;
            }
            program_files()
                .into_iter()
                .map(|p| p.join("CMake/bin").join(exe_name("cmake")))
                .find(|p| p.is_file())
        })
        .or_else(|| if s.only_path { None } else { vs_bundled_cmake() });
    if cmake_path.is_none() {
        problems.push("CMake 3.21 or newer was not found. Install it from https://cmake.org/download/ (tick \"Add CMake to the PATH\").".into());
    }

    let git_path = s
        .git
        .clone()
        .filter(|p| p.is_file())
        .or_else(|| find_on_path(&["git"], &s.path_var))
        .or_else(|| {
            if s.only_path {
                return None;
            }
            program_files()
                .into_iter()
                .flat_map(|p| [p.join("Git/cmd").join(exe_name("git")), p.join("Git/bin").join(exe_name("git"))])
                .find(|p| p.is_file())
        });
    if git_path.is_none() {
        problems.push("git was not found. Install it from https://git-scm.com/download/win.".into());
    }

    // Compiler: ask vswhere for an instance with the C++ tools; a developer
    // prompt with cl.exe on PATH also counts.
    let mut compiler_path: Option<PathBuf> = None;
    let mut compiler_detail = String::new();
    if s.skip_compiler_check {
        compiler_detail = "check skipped".into();
        compiler_path = Some(PathBuf::from("(skipped)"));
    } else if cfg!(windows) {
        let vswhere = s.vswhere.clone().filter(|p| p.is_file()).or_else(|| {
            if s.only_path {
                return None;
            }
            std::env::var_os("ProgramFiles(x86)")
                .map(|p| PathBuf::from(p).join("Microsoft Visual Studio/Installer/vswhere.exe"))
                .filter(|p| p.is_file())
        });
        if let Some(vw) = vswhere {
            if let Ok(out) = Command::new(&vw)
                .args(["-latest", "-products", "*", "-requires", "Microsoft.VisualStudio.Component.VC.Tools.x86.x64", "-property", "installationPath"])
                .stdin(Stdio::null())
                .output()
            {
                let p = String::from_utf8_lossy(&out.stdout).lines().next().unwrap_or("").trim().to_string();
                if !p.is_empty() {
                    compiler_detail = "Visual Studio with the C++ tools".into();
                    compiler_path = Some(PathBuf::from(p));
                }
            }
        }
        if compiler_path.is_none() {
            if let Some(cl) = find_on_path(&["cl"], &s.path_var) {
                compiler_detail = "cl.exe on PATH".into();
                compiler_path = Some(cl);
            }
        }
        if compiler_path.is_none() {
            problems.push(
                "No Visual Studio C++ toolchain was found. Install \"Build Tools for Visual Studio\" with the \
                 \"Desktop development with C++\" workload from https://visualstudio.microsoft.com/downloads/."
                    .into(),
            );
        }
    }

    let cmake = tool("CMake", cmake_path, "build system generator");
    let git = tool("git", git_path, "fetches the pinned upstream source");
    let compiler = tool("C++ compiler", compiler_path, &compiler_detail);
    let ready = supported_os && cmake.found && git.found && compiler.found;
    Toolchain { supported_os, cmake, git, compiler, ready, problems }
}

fn search_from(opts: &BuildOptions) -> ToolSearch {
    ToolSearch {
        path_var: None,
        cmake: opts.cmake.clone(),
        git: opts.git.clone(),
        vswhere: None,
        skip_compiler_check: opts.skip_compiler_check,
        only_path: false,
    }
}

fn dir_stats(dir: &Path) -> (usize, u64) {
    let mut n = 0usize;
    let mut bytes = 0u64;
    if let Ok(rd) = fs::read_dir(dir) {
        for e in rd.filter_map(|e| e.ok()) {
            if let Ok(m) = e.metadata() {
                if m.is_file() {
                    n += 1;
                    bytes += m.len();
                }
            }
        }
    }
    (n, bytes)
}

fn cores(opts: &BuildOptions) -> usize {
    opts.jobs
        .unwrap_or_else(|| std::thread::available_parallelism().map(|n| n.get()).unwrap_or(4))
        .max(1)
}

// ---------------------------------------------------------------------------
// Planning (read-only)
// ---------------------------------------------------------------------------

fn manifest(workspace: &Path) -> Result<serde_json::Value, String> {
    let p = workspace.join("game.json");
    let text = fs::read_to_string(&p).map_err(|e| {
        format!("{} is not an Aura game workspace ({} missing: {e}). Run the disc wizard first.", workspace.display(), p.display())
    })?;
    serde_json::from_str(&text).map_err(|e| format!("{} is not valid JSON: {e}", p.display()))
}

/// Describe what building this workspace would do, without doing any of it.
pub fn plan_build(workspace: &Path, opts: &BuildOptions) -> Result<BuildPlan, String> {
    let m = manifest(workspace)?;
    let functions = m
        .get("recomp")
        .and_then(|r| r.get("function_count"))
        .and_then(|v| v.as_u64())
        .unwrap_or(0) as usize;
    let extract_all = m.get("extract_mode").and_then(|v| v.as_str()) == Some("all");

    let toolchain = detect_toolchain(&search_from(opts));
    let cache = cache_of(opts);
    let src = source_dir(opts, &cache);
    let source_cached = opts.source_override.is_some() || source_is_pinned(&src);
    let recompiler_cached = opts.recompiler.as_ref().map(|p| p.is_file()).unwrap_or(false)
        || recompiler_variant(&cache, false).is_file()
        || recompiler_in(&cache.join("build-recomp")).is_some();
    let lean_ready = opts.recompiler.is_some() || recompiler_variant(&cache, true).is_file();
    let indirect_profile = m
        .get("recomp")
        .and_then(|r| r.get("indirect_profile"))
        .and_then(|v| serde_json::from_value::<ps2_ingest::IndirectProfile>(v.clone()).ok());
    let runtime_configured = cache.join("build-runtime").join("CMakeCache.txt").is_file();

    let mut downloads: Vec<DownloadItem> = vec![];
    if !source_cached {
        downloads.push(DownloadItem {
            what: format!("PS2Recomp source at the tested commit {}", &PINNED_COMMIT[..8]),
            from: "github.com/ran-j/PS2Recomp".into(),
            approx_mb: 25,
        });
    }
    if !recompiler_cached {
        downloads.push(DownloadItem {
            what: "Recompiler build dependencies (ELFIO, toml11, fmt, libdwarf, rabbitizer), cloned by CMake".into(),
            from: "github.com (5 repositories)".into(),
            approx_mb: 490,
        });
    }
    if !runtime_configured {
        downloads.push(DownloadItem {
            what: "Runtime dependencies (raylib 5.5, Dear ImGui, rlImGui), cloned by CMake".into(),
            from: "github.com (3 repositories)".into(),
            approx_mb: 525,
        });
        downloads.push(DownloadItem {
            what: "FFmpeg 7.1 prebuilt DLLs for movie playback".into(),
            from: "github.com release archive".into(),
            approx_mb: 34,
        });
    }
    let download_mb: u32 = downloads.iter().map(|d| d.approx_mb).sum();

    // Disk: dependencies (clones are large) + build output + generated sources.
    let (gen_files, gen_bytes) = dir_stats(&workspace.join("recomp").join("generated"));
    let gen_estimate = if gen_bytes > 0 { gen_bytes } else { functions as u64 * 28 * 1024 };
    let required_bytes = (download_mb as u64) * 1_048_576 * 13 / 10
        + 1_500_000_000
        + gen_estimate.saturating_mul(6);
    let free_bytes = free_space_bytes(&cache);

    let n = cores(opts);
    // Observed on a 20-core machine: ~30 s + 0.13 s per function; scale by cores.
    let estimate_secs = (30.0 + 0.13 * functions as f64 * (20.0 / n as f64)) as u64
        + if runtime_configured { 0 } else { 120 }
        + if recompiler_cached { 0 } else { 150 }
        + if opts.lean_indirect_calls && !lean_ready { 45 } else { 0 };

    let mut blockers: Vec<String> = toolchain.problems.clone();
    if !extract_all {
        blockers.push(
            "The entire disc must be extracted first: the runtime reads the game's files from the extracted \
             disc, so a build without them could never run."
                .into(),
        );
    }
    if !space_ok(free_bytes, required_bytes) {
        blockers.push(format!(
            "Not enough free disk space for the build cache at {}: about {:.1} GB needed, {:.1} GB free. \
             Choose another cache folder.",
            cache.display(),
            required_bytes as f64 / 1e9,
            free_bytes.unwrap_or(0) as f64 / 1e9
        ));
    }
    let _ = gen_files;
    let can_build = blockers.is_empty();
    Ok(BuildPlan {
        toolchain,
        cache_dir: cache.to_string_lossy().to_string(),
        downloads,
        download_mb,
        source_cached,
        recompiler_cached,
        runtime_configured,
        functions,
        estimate_secs,
        cores: n,
        free_bytes,
        required_bytes,
        blockers,
        can_build,
        pinned_commit: PINNED_COMMIT.to_string(),
        lean_indirect_calls: opts.lean_indirect_calls,
        lean_ready,
        indirect_profile,
    })
}

// ---------------------------------------------------------------------------
// Command lines (pure, tested)
// ---------------------------------------------------------------------------

fn s(x: &str) -> OsString {
    OsString::from(x)
}

/// Compiler flags for the multi-processor MSVC build: `-MP<n>` is what cut a
/// 13 MB generated source tree from serial to about a minute.
fn msvc_cxx_flags(jobs: usize) -> Option<String> {
    cfg!(windows).then(|| format!("-DWIN32 -D_WINDOWS -EHsc -GR -MP{jobs}"))
}

pub fn recompiler_configure_args(src: &Path, build: &Path, jobs: usize) -> Vec<OsString> {
    let mut a = vec![
        s("-S"),
        src.as_os_str().to_os_string(),
        s("-B"),
        build.as_os_str().to_os_string(),
        s("-DPS2X_BUILD_RUNTIME=OFF"),
        s("-DPS2X_BUILD_ANALYZER=OFF"),
        s("-DPS2X_BUILD_TEST=OFF"),
        s("-DPS2X_BUILD_STUDIO=OFF"),
    ];
    if let Some(f) = msvc_cxx_flags(jobs) {
        a.push(OsString::from(format!("-DCMAKE_CXX_FLAGS={f}")));
    }
    a
}

pub fn runtime_configure_args(
    src: &Path,
    build: &Path,
    jobs: usize,
    native_feel: bool,
    fast_release: bool,
) -> Vec<OsString> {
    let mut a = vec![
        s("-S"),
        src.as_os_str().to_os_string(),
        s("-B"),
        build.as_os_str().to_os_string(),
        s("-DPS2X_BUILD_RECOMP=OFF"),
        s("-DPS2X_BUILD_ANALYZER=OFF"),
        s("-DPS2X_BUILD_TEST=OFF"),
        s("-DPS2X_BUILD_STUDIO=OFF"),
    ];
    if native_feel {
        // Upstream's defaults show a debug overlay, a console window and very
        // verbose logging; hide them so the result behaves like a program.
        a.push(s("-DPS2X_ENABLE_DEBUG_UI=OFF"));
        a.push(s("-DPS2X_SHOW_WINDOWS_CONSOLE=OFF"));
        a.push(s("-DPS2X_ENABLE_AGRESSIVE_LOGS=OFF"));
    }
    if fast_release {
        // Upstream gates EnableFastReleaseMode() and the GUI subsystem on this.
        a.push(s("-DCMAKE_BUILD_TYPE=Release"));
    }
    if let Some(f) = msvc_cxx_flags(jobs) {
        a.push(OsString::from(format!("-DCMAKE_CXX_FLAGS={f}")));
    }
    a
}

pub fn build_args(build: &Path, target: &str, jobs: usize) -> Vec<OsString> {
    vec![
        s("--build"),
        build.as_os_str().to_os_string(),
        s("--config"),
        s("Release"),
        s("--target"),
        s(target),
        s("--parallel"),
        OsString::from(jobs.to_string()),
    ]
}

/// A line like `unity_17_cxx.cxx` from MSBuild: one batch of the runner target.
pub fn is_unity_line(line: &str) -> bool {
    let t = line.trim();
    t.starts_with("unity_") && t.ends_with("_cxx.cxx")
}

// ---------------------------------------------------------------------------
// Pipeline
// ---------------------------------------------------------------------------

fn replace_dir_files(dir: &Path) -> Result<(), String> {
    fs::create_dir_all(dir).map_err(|e| format!("Cannot create {}: {e}", dir.display()))?;
    for e in fs::read_dir(dir).map_err(|e| format!("Cannot read {}: {e}", dir.display()))?.filter_map(|e| e.ok()) {
        if e.file_type().map(|t| t.is_file()).unwrap_or(false) {
            fs::remove_file(e.path()).map_err(|er| format!("Cannot remove {}: {er}", e.path().display()))?;
        }
    }
    Ok(())
}

/// Put a workspace's generated sources where the runtime build reads them:
/// `*.cpp` into `ps2xRuntime/src/runner/` (replacing the committed
/// placeholder), `*.h` into `ps2xRuntime/include/`. Returns `(cpp, headers)`.
pub fn install_generated_sources(generated: &Path, tree: &Path) -> Result<(usize, usize), String> {
    let runner = tree.join("ps2xRuntime").join("src").join("runner");
    let include = tree.join("ps2xRuntime").join("include");
    replace_dir_files(&runner)?;
    fs::create_dir_all(&include).map_err(|e| format!("Cannot create {}: {e}", include.display()))?;
    // Remove headers from a previous game so a stale one can never be picked up.
    if let Ok(rd) = fs::read_dir(&include) {
        for e in rd.filter_map(|e| e.ok()) {
            let n = e.file_name().to_string_lossy().to_string();
            if n.starts_with("ps2_recompiled_") && n.ends_with(".h") {
                let _ = fs::remove_file(e.path());
            }
        }
    }
    let (mut cpp, mut hdr) = (0usize, 0usize);
    for e in fs::read_dir(generated)
        .map_err(|e| format!("Cannot read generated sources {}: {e}", generated.display()))?
        .filter_map(|e| e.ok())
    {
        let p = e.path();
        if !p.is_file() {
            continue;
        }
        let ext = p.extension().map(|x| x.to_string_lossy().to_ascii_lowercase()).unwrap_or_default();
        let name = e.file_name();
        match ext.as_str() {
            "cpp" => {
                fs::copy(&p, runner.join(&name)).map_err(|er| format!("Cannot copy {}: {er}", p.display()))?;
                cpp += 1;
            }
            "h" | "hpp" => {
                fs::copy(&p, include.join(&name)).map_err(|er| format!("Cannot copy {}: {er}", p.display()))?;
                hdr += 1;
            }
            _ => {}
        }
    }
    if cpp == 0 {
        return Err(format!("{} contains no generated .cpp files; the recompiler produced nothing.", generated.display()));
    }
    Ok((cpp, hdr))
}

/// Fetch the pinned upstream source into `<cache>/PS2Recomp`.
fn ensure_source(r: &mut Runner, git: &Path, dir: &Path) -> Result<(), String> {
    if source_is_pinned(dir) {
        return Ok(());
    }
    crate::build_common::ensure_git_checkout(r, git, dir, UPSTREAM_URL, PINNED_COMMIT)?;
    if !source_is_pinned(dir) {
        return Err(format!("The upstream checkout in {} is not at the expected commit {PINNED_COMMIT}.", dir.display()));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Lean indirect calls: an optional, experimental recompiler variant
// ---------------------------------------------------------------------------
//
// Upstream's control-flow analyzer treats every `jalr` as an *unresolved
// jump* that must match a switch-table pattern. A `jalr $ra, rs` is just an
// indirect call (a virtual or function-pointer call) that returns to
// `address + 8`, which upstream already registers as a resume entry. Because
// virtual calls never look like a switch table, one of them makes the
// recompiler promote **every instruction of the function** to a resumable
// entry point. Measured on three retail/homebrew games, 89-100% of all
// "fallback entries" come from functions whose only unresolved jumps are such
// calls; on Midnight Club 3 Remix that was 947,446 entries (7,760 functions).
//
// The lean variant is a one-statement change to that analyzer: a `jalr $ra`
// keeps its resume entry and skips the table search. The change is applied to
// the cached source only while the lean recompiler is being built, and the
// source is restored afterwards, so the pristine pinned tree (also used for
// the runtime build) is never left modified.

/// Source file of the pinned upstream the lean variant changes.
pub const LEAN_PATCH_FILE: &str = "ps2xRecomp/src/lib/control_flow_analyzer.cpp";
/// Present in a patched file; tells the states apart.
pub const LEAN_MARKER: &str = "AURA lean-indirect-calls";

const LEAN_ANCHOR: &str = "                if (jrInst->function == SPECIAL_JALR)\n                {\n                    queueResumeEntryTarget(jrInst->address + 8u);\n                }\n";
const LEAN_REPLACEMENT: &str = "                if (jrInst->function == SPECIAL_JALR)\n                {\n                    queueResumeEntryTarget(jrInst->address + 8u);\n                    // AURA lean-indirect-calls: `jalr $ra, rs` is an ordinary indirect call. It\n                    // returns to address+8 (queued above), so it needs no jump table and must not\n                    // promote every instruction of the function to an entry point.\n                    if (jrInst->rd == 31)\n                    {\n                        continue;\n                    }\n                }\n";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LeanState {
    /// The expected upstream code is present and unmodified.
    Pristine,
    /// Already carries the lean change.
    Patched,
    /// Neither: upstream is not the version the lean change was written for.
    Unavailable,
}

fn with_eol(s: &str, crlf: bool) -> String {
    if crlf { s.replace('\n', "\r\n") } else { s.to_string() }
}

/// Which state the analyzer source text is in.
pub fn lean_patch_state(text: &str) -> LeanState {
    if text.contains(LEAN_MARKER) {
        return LeanState::Patched;
    }
    if text.contains(&with_eol(LEAN_ANCHOR, text.contains("\r\n"))) {
        LeanState::Pristine
    } else {
        LeanState::Unavailable
    }
}

/// The analyzer source with the lean change applied (line endings preserved).
pub fn apply_lean_patch(text: &str) -> Result<String, String> {
    match lean_patch_state(text) {
        LeanState::Patched => Err("The analyzer source already carries the lean change.".into()),
        LeanState::Unavailable => Err(format!(
            "Lean mode is not available: {LEAN_PATCH_FILE} is not the version it was written for \
             (tested against {})",
            &PINNED_COMMIT[..8]
        )),
        LeanState::Pristine => {
            let crlf = text.contains("\r\n");
            Ok(text.replacen(&with_eol(LEAN_ANCHOR, crlf), &with_eol(LEAN_REPLACEMENT, crlf), 1))
        }
    }
}

/// Undo [`apply_lean_patch`].
pub fn revert_lean_patch(text: &str) -> Result<String, String> {
    if !text.contains(LEAN_MARKER) {
        return Err("The analyzer source does not carry the lean change.".into());
    }
    let crlf = text.contains("\r\n");
    let repl = with_eol(LEAN_REPLACEMENT, crlf);
    if !text.contains(&repl) {
        return Err("The lean change in the analyzer source was edited and cannot be reverted automatically.".into());
    }
    Ok(text.replacen(&repl, &with_eol(LEAN_ANCHOR, crlf), 1))
}

/// Where a built recompiler variant is kept: `<cache>/recompiler/<variant>/`.
pub fn recompiler_variant(cache: &Path, lean: bool) -> PathBuf {
    cache
        .join("recompiler")
        .join(if lean { "lean" } else { "standard" })
        .join(exe_name("ps2_recomp"))
}

fn copy_file(from: &Path, to: &Path) -> Result<(), String> {
    if let Some(p) = to.parent() {
        fs::create_dir_all(p).map_err(|e| format!("Cannot create {}: {e}", p.display()))?;
    }
    fs::copy(from, to).map(|_| ()).map_err(|e| format!("Cannot copy {} to {}: {e}", from.display(), to.display()))
}

/// The recompiler to run: the standard one, or (`lean`) the variant built from
/// the lean change. Both are built once and kept in the cache.
pub fn ensure_recompiler(
    r: &mut Runner,
    cmake: &Path,
    src: &Path,
    cache: &Path,
    jobs: usize,
    lean: bool,
) -> Result<PathBuf, String> {
    let build_recomp = cache.join("build-recomp");
    let standard = recompiler_variant(cache, false);
    if !standard.is_file() {
        // Caches from before variants existed already hold the standard build.
        let built = match recompiler_in(&build_recomp) {
            Some(p) => p,
            None => {
                r.stage("recompiler-build", "Building the ps2_recomp recompiler (first time only)…", 0.08)?;
                r.run("CMake configure (recompiler)", cmake, &recompiler_configure_args(src, &build_recomp, jobs), None, |_| None)?;
                r.stage("recompiler-build", "Compiling the recompiler…", 0.16)?;
                r.run("CMake build (recompiler)", cmake, &build_args(&build_recomp, "ps2_recomp", jobs), None, |_| None)?;
                recompiler_in(&build_recomp).ok_or_else(|| {
                    format!("The recompiler build finished but ps2_recomp was not found under {}.", build_recomp.display())
                })?
            }
        };
        copy_file(&built, &standard)?;
    }
    if !lean {
        return Ok(standard);
    }

    let lean_exe = recompiler_variant(cache, true);
    if lean_exe.is_file() {
        return Ok(lean_exe);
    }
    r.stage("recompiler-build", "Building the lean recompiler variant (first time only)…", 0.20)?;
    let file = src.join(LEAN_PATCH_FILE);
    let original = fs::read(&file)
        .map_err(|e| format!("Cannot read {}: {e}", file.display()))
        .and_then(|b| String::from_utf8(b).map_err(|_| format!("{} is not UTF-8 text.", file.display())))?;
    let patched = apply_lean_patch(&original)?;
    fs::write(&file, &patched).map_err(|e| format!("Cannot write {}: {e}", file.display()))?;
    // Whatever happens next, the pristine source goes back.
    let built = r.run("CMake build (lean recompiler)", cmake, &build_args(&build_recomp, "ps2_recomp", jobs), None, |_| None);
    let restored = fs::write(&file, &original).map_err(|e| format!("Cannot restore {}: {e}", file.display()));
    built?;
    restored?;
    let exe = recompiler_in(&build_recomp).ok_or_else(|| {
        format!("The lean recompiler build finished but ps2_recomp was not found under {}.", build_recomp.display())
    })?;
    copy_file(&exe, &lean_exe)?;
    Ok(lean_exe)
}

/// Build the whole game. `progress` returns `false` to cancel.
pub fn build_game(
    workspace: &Path,
    opts: &BuildOptions,
    progress: &mut dyn FnMut(&BuildProgress) -> bool,
) -> Result<BuildResult, String> {
    // CMake, MSBuild and ps2_recomp all run from other directories.
    let workspace_abs = ps2_ingest::absolute_path(workspace);
    let workspace = workspace_abs.as_path();
    let plan = plan_build(workspace, opts)?;
    if !plan.can_build {
        return Err(format!("Cannot build yet:\n- {}", plan.blockers.join("\n- ")));
    }
    if !plan.downloads.is_empty() && !opts.allow_downloads {
        let list: Vec<String> = plan.downloads.iter().map(|d| format!("{} (~{} MB)", d.what, d.approx_mb)).collect();
        return Err(format!(
            "NEEDS_DOWNLOAD_CONSENT: this build downloads about {} MB from GitHub: {}. Confirm to continue.",
            plan.download_mb,
            list.join("; ")
        ));
    }

    let cache = cache_of(opts);
    fs::create_dir_all(&cache).map_err(|e| format!("Cannot create the build cache {}: {e}", cache.display()))?;
    let log_path = workspace.join("recomp").join("build.log");
    let _ = fs::create_dir_all(workspace.join("recomp"));
    let log_file = fs::File::create(&log_path).ok();
    let jobs = cores(opts);
    let mut r = Runner::new(progress, log_file);
    let cmake = PathBuf::from(plan.toolchain.cmake.path.clone().unwrap_or_default());
    let git = PathBuf::from(plan.toolchain.git.path.clone().unwrap_or_default());
    let mut warnings: Vec<String> = vec![];

    // ----- source ------------------------------------------------------------
    r.stage("source", "Fetching the PS2Recomp source…", 0.02)?;
    let src = source_dir(opts, &cache);
    if opts.source_override.is_none() {
        ensure_source(&mut r, &git, &src)?;
    } else if !src.join("CMakeLists.txt").is_file() {
        return Err(format!("{} is not a PS2Recomp source tree (no CMakeLists.txt).", src.display()));
    }

    // ----- recompiler -------------------------------------------------------------
    let recompiler: PathBuf = match opts.recompiler.clone().filter(|p| p.is_file()) {
        Some(p) => p,
        None => ensure_recompiler(&mut r, &cmake, &src, &cache, jobs, opts.lean_indirect_calls)?,
    };
    if opts.lean_indirect_calls {
        warnings.push(
            "Lean indirect calls is experimental: the game was recompiled with a modified recompiler that \
             keeps far fewer resumable entry points and so also generates different code. If it misbehaves, rebuild without it."
                .into(),
        );
    }

    // ----- recompile the game ---------------------------------------------------
    r.stage("recompile", "Recompiling the game's code to C++…", 0.26)?;
    let recomp_dir = workspace.join("recomp");
    let config = recomp_dir.join("config.toml");
    if !config.is_file() {
        return Err(format!("{} is missing; run the disc wizard first.", config.display()));
    }
    let generated = recomp_dir.join("generated");
    replace_dir_files(&generated)?;
    let rr = ps2_ingest::run_recompiler(&recompiler, &config, &recomp_dir, &generated, &recomp_dir.join("ps2_recomp.log"), &mut || true);
    for l in rr.log_tail.iter().rev().take(4).rev() {
        r.push_line(l);
    }
    if !rr.success {
        return Err(format!(
            "ps2_recomp failed: {}\nSee {}",
            rr.error.unwrap_or_else(|| "unknown error".into()),
            rr.log_path
        ));
    }
    let (cpp, hdr) = install_generated_sources(&generated, &src)?;
    r.push_line(&format!("installed {cpp} generated sources and {hdr} headers into the runtime tree"));

    // ----- runtime ---------------------------------------------------------------
    let build_runtime = cache.join("build-runtime");
    r.stage("runtime-configure", "Configuring the runtime build…", 0.32)?;
    r.run("CMake configure (runtime)", &cmake, &runtime_configure_args(&src, &build_runtime, jobs, opts.native_feel, opts.fast_release), None, |_| None)?;

    r.stage("runtime-build", "Compiling the game…", 0.40)?;
    r.creep = Some((0.40, 0.92, plan.estimate_secs as f64 * 0.7));
    let expected_units = (cpp / UNITY_BATCH + 1).max(1);
    let mut seen_units = 0usize;
    r.run("CMake build (runtime)", &cmake, &build_args(&build_runtime, "ps2EntryRunner", jobs), None, |line| {
        if is_unity_line(line) {
            seen_units += 1;
            Some(0.40 + 0.52 * (seen_units as f64 / expected_units as f64).min(1.0))
        } else {
            None
        }
    })?;
    let exe = runtime_exe_in(&build_runtime).ok_or_else(|| {
        format!("The build finished but ps2EntryRunner was not found under {}.", build_runtime.display())
    })?;

    // ----- package ---------------------------------------------------------------
    let mut package: Option<PackageResult> = None;
    if opts.package {
        r.stage("package", "Assembling the game folder…", 0.94)?;
        let popts = PackageOptions { launcher_exe: opts.launcher_exe.clone(), ..Default::default() };
        let pkg = ps2_package::package_game(workspace, &exe, &popts, &mut |_| true)?;
        for w in &pkg.warnings {
            warnings.push(w.clone());
        }
        package = Some(pkg);
    }
    r.stage("done", "Done", 1.0)?;
    r.finish_stage();
    Ok(BuildResult {
        exe: exe.to_string_lossy().to_string(),
        runtime_build_dir: build_runtime.to_string_lossy().to_string(),
        cache_dir: cache.to_string_lossy().to_string(),
        log_path: log_path.to_string_lossy().to_string(),
        generated_sources: cpp,
        elapsed_secs: r.started.elapsed().as_secs_f64(),
        stage_secs: r.stage_secs.clone(),
        native_feel: opts.native_feel,
        fast_release: opts.fast_release,
        lean_indirect_calls: opts.lean_indirect_calls,
        package,
        warnings,
    })
}

/// Names for tools used elsewhere (kept public so the CLI can print them).
pub fn describe_estimate(secs: u64) -> String {
    if secs < 90 {
        "about a minute".to_string()
    } else {
        format!("about {} minutes", (secs + 30) / 60)
    }
}
