//! Tests for the PS1 pipeline: workspace ingest (`ps1_ingest`) and the
//! PSXRecomp build driver (`ps1_build`).
//!
//! The real tools are replaced by small scripts — a fake PowerShell that
//! records its arguments and environment and "builds" a program, a fake Python
//! that prints a version — so consent, toolchain handling, argument
//! construction, environment, progress, failure, cancellation and packaging
//! run in a second on any machine. A real end-to-end build is exercised
//! separately by hand.

use crate::ps1_build::{self, Ps1BuildOptions, Ps1ToolSearch};
use crate::ps1_ingest::{self, Ps1IngestOptions};
use crate::tests_disc::TempDir;
use crate::tests_ps1::{ps1_iso, psx_exe_bytes};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

/// Write an executable script; `win` is a .cmd body, `unix` a /bin/sh body.
fn script(dir: &Path, name: &str, win: &str, unix: &str) -> PathBuf {
    #[cfg(windows)]
    {
        let _ = unix;
        let p = dir.join(format!("{name}.cmd"));
        std::fs::write(&p, win.replace('\n', "\r\n")).unwrap();
        p
    }
    #[cfg(not(windows))]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = win;
        let p = dir.join(name);
        std::fs::write(&p, format!("#!/bin/sh\n{unix}")).unwrap();
        let mut perm = std::fs::metadata(&p).unwrap().permissions();
        perm.set_mode(0o755);
        std::fs::set_permissions(&p, perm).unwrap();
        p
    }
}

#[derive(Clone, Copy, PartialEq)]
enum Setup {
    Ok,
    Fail,
    Slow,
}

/// Fake `powershell`: logs argv and a few env vars next to itself, then (on
/// success) creates `<-Dir>/<-GithubRepo>/build-release/` with an exe, a DLL
/// and some CMake debris, printing ninja-style progress lines.
fn fake_powershell(dir: &Path, mode: Setup) -> PathBuf {
    let tail = match mode {
        Setup::Ok => "",
        Setup::Fail => "echo error: boom while generating\nexit /b 3\n",
        Setup::Slow => "ping -n 30 127.0.0.1 >nul\nexit /b 0\n",
    };
    let win = format!(
        "@echo off\nsetlocal\necho %* >> \"%~dp0setup-args.log\"\necho TOOLCHAIN=%PSXRECOMP_TOOLCHAIN_DIR% >> \"%~dp0env.log\"\necho PYTHON=%PSXRECOMP_PYTHON% >> \"%~dp0env.log\"\necho YES=%PSXRECOMP_SETUP_YES% >> \"%~dp0env.log\"\necho FILEALLOW=%GIT_CONFIG_VALUE_0% >> \"%~dp0env.log\"\necho AUTOCRLF=%GIT_CONFIG_KEY_1%=%GIT_CONFIG_VALUE_1% >> \"%~dp0env.log\"\necho GITCOUNT=%GIT_CONFIG_COUNT% >> \"%~dp0env.log\"\necho PATHCONV=[%MSYS_NO_PATHCONV%] >> \"%~dp0env.log\"\necho PATH=%PATH% >> \"%~dp0env.log\"\nset DIR=\nset REPO=\n:loop\nif \"%~1\"==\"\" goto done\nif \"%~1\"==\"-Dir\" set DIR=%~2\nif \"%~1\"==\"-GithubRepo\" set REPO=%~2\nshift\ngoto loop\n:done\necho [1/4] Probing disc\necho [2/4] Generating C\n{tail}if not exist \"%DIR%\\%REPO%\\build-release\" mkdir \"%DIR%\\%REPO%\\build-release\"\necho MZ> \"%DIR%\\%REPO%\\build-release\\Fake_Recompiled.exe\"\necho Fake_Recompiled> \"%DIR%\\%REPO%\\build-release\\psxrecomp_exe_name-psx-runtime.txt\"\necho dll> \"%DIR%\\%REPO%\\build-release\\SDL3.dll\"\necho cache> \"%DIR%\\%REPO%\\build-release\\CMakeCache.txt\"\nmkdir \"%DIR%\\%REPO%\\build-release\\bios\" 2>nul\necho bios> \"%DIR%\\%REPO%\\build-release\\bios\\openbios.bin\"\nmkdir \"%DIR%\\%REPO%\\build-release\\CMakeFiles\" 2>nul\necho x> \"%DIR%\\%REPO%\\build-release\\CMakeFiles\\junk.txt\"\necho [3/4] Linking\necho [4/4] Done\nexit /b 0\n"
    );
    let unix = format!(
        "echo \"$@\" >> \"$(dirname \"$0\")/setup-args.log\"\n{}",
        match mode {
            Setup::Fail => "echo 'error: boom while generating'\nexit 3\n",
            _ => "exit 0\n",
        }
    );
    script(dir, "powershell", &win, &unix)
}

fn fake_python(dir: &Path) -> PathBuf {
    script(dir, "python", "@echo off\necho 3 12\n", "echo 3 12\n")
}

/// A portable-toolchain stand-in: `bin/cmake` and `bin/ninja`.
fn fake_toolchain(dir: &Path) -> PathBuf {
    let bin = dir.join("bin");
    std::fs::create_dir_all(&bin).unwrap();
    let ext = if cfg!(windows) { ".exe" } else { "" };
    for n in ["cmake", "ninja", "clang"] {
        std::fs::write(bin.join(format!("{n}{ext}")), b"x").unwrap();
    }
    dir.to_path_buf()
}

fn fake_framework(dir: &Path) -> PathBuf {
    let fw = dir.join("psxrecomp");
    std::fs::create_dir_all(fw.join("tools/new_project_layout")).unwrap();
    std::fs::write(fw.join("tools/new_project_layout/setup_project.ps1"), "# fake\n").unwrap();
    fw
}

fn make_workspace(t: &TempDir) -> PathBuf {
    let iso = t.path().join("Some Game (USA).iso");
    std::fs::write(
        &iso,
        ps1_iso("SLUS_004.04", psx_exe_bytes(0x8001_0000, 0x8001_0000, 4096, "Sony Computer Entertainment Inc. for North America area")),
    )
    .unwrap();
    let opts = Ps1IngestOptions { out_root: t.path().join("games").to_string_lossy().to_string() };
    PathBuf::from(ps1_ingest::ingest_ps1(iso.to_str().unwrap(), &opts, &mut |_| true).unwrap().workspace)
}

struct Rig {
    t: TempDir,
    ws: PathBuf,
    opts: Ps1BuildOptions,
    tools: PathBuf,
}

fn rig(mode: Setup) -> Rig {
    let t = TempDir::new("ps1build");
    let ws = make_workspace(&t);
    let tools = t.path().join("tools");
    std::fs::create_dir_all(&tools).unwrap();
    let git = tools.join("git");
    std::fs::write(&git, b"x").unwrap();
    let opts = Ps1BuildOptions {
        cache_dir: Some(t.path().join("cache")),
        allow_downloads: true,
        package: true,
        jobs: Some(4),
        git: Some(git),
        python: Some(fake_python(&tools)),
        powershell: Some(fake_powershell(&tools, mode)),
        toolchain_dir: Some(fake_toolchain(&t.path().join("tc"))),
        framework_override: Some(fake_framework(t.path())),
        ui_override: Some({
            let ui = t.path().join("recomp-ui");
            std::fs::create_dir_all(&ui).unwrap();
            ui
        }),
        skip_os_check: true,
        ..Default::default()
    };
    Rig { t, ws, opts, tools }
}

fn no_cb(_: &crate::build_common::BuildProgress) -> bool {
    true
}

// ===========================================================================
// pure helpers
// ===========================================================================

mod helper_tests {
    use super::*;

    #[test]
    fn titles_are_cleaned_of_region_and_disc_tags() {
        assert_eq!(ps1_ingest::friendly_title("Ace Combat 2 (USA)", "ACECOMBAT2"), "Ace Combat 2");
        assert_eq!(ps1_ingest::friendly_title("Final Fantasy VII (USA) (Disc 1)", "X"), "Final Fantasy VII");
        assert_eq!(ps1_ingest::friendly_title("Wipeout [!] (Europe) (En,Fr)", "X"), "Wipeout");
        assert_eq!(ps1_ingest::friendly_title("Plain Name", "X"), "Plain Name");
        assert_eq!(ps1_ingest::friendly_title("(USA)", "VOLUME"), "VOLUME", "nothing but tags falls back");
        assert_eq!(ps1_ingest::friendly_title("Game - (USA)", "V"), "Game");
        assert_eq!(ps1_ingest::friendly_title("Unbalanced (USA", "V"), "Unbalanced");
    }

    #[test]
    fn disc_numbers_are_read_from_names() {
        assert_eq!(ps1_ingest::disc_number_from_name("Final Fantasy VII (USA) (Disc 2)"), Some(2));
        assert_eq!(ps1_ingest::disc_number_from_name("Game (Disc 3 of 4)"), Some(3));
        assert_eq!(ps1_ingest::disc_number_from_name("Game (USA)"), None);
        assert_eq!(ps1_ingest::disc_number_from_name("Game (Disc 0)"), None);
        assert_eq!(ps1_ingest::disc_number_from_name("Game (Disc )"), None);
    }

    #[test]
    fn ninja_progress_lines_are_parsed() {
        assert_eq!(ps1_build::parse_ninja_progress("[12/345] Building C object x.o"), Some((12, 345)));
        assert_eq!(ps1_build::parse_ninja_progress("  [1/2] Linking"), Some((1, 2)));
        assert_eq!(ps1_build::parse_ninja_progress("[ok] fine"), None);
        assert_eq!(ps1_build::parse_ninja_progress("no brackets 3/4"), None);
        assert_eq!(ps1_build::parse_ninja_progress("[3/x]"), None);
    }

    fn sample_args() -> Vec<String> {
        ps1_build::setup_script_args(&ps1_build::SetupArgs {
            script: Path::new("C:/fw/tools/new_project_layout/setup_project.ps1"),
            cue: Path::new("D:/g/Game.cue"),
            title: "Ace Combat 2",
            boot_file: "SLUS_004.04",
            out_dir: Path::new("D:/g"),
            repo: "psx-slus-00404",
            framework_url: "C:/cache/psxrecomp",
            ui_url: "C:/cache/recomp-ui",
            region: "NTSC-U/C (North America)",
        })
        .iter()
        .map(|s| s.to_string_lossy().to_string())
        .collect()
    }

    #[test]
    fn setup_args_answer_every_prompt_and_switch_off_publishing() {
        let a = sample_args();
        let val = |flag: &str| a.iter().position(|x| x == flag).map(|i| a[i + 1].clone());
        assert_eq!(val("-Disc").as_deref(), Some("D:/g/Game.cue"));
        assert_eq!(val("-Name").as_deref(), Some("Ace Combat 2"), "spaces stay inside one argument");
        assert_eq!(val("-Dir").as_deref(), Some("D:/g"));
        assert_eq!(val("-GithubRepo").as_deref(), Some("psx-slus-00404"));
        assert_eq!(val("-BootExe").as_deref(), Some("SLUS_004.04"));
        assert_eq!(val("-PsxrecompUrl").as_deref(), Some("C:/cache/psxrecomp"));
        assert_eq!(val("-PsxrecompRef").as_deref(), Some(ps1_build::PINNED_BRANCH));
        assert_eq!(val("-RecompUiRef").as_deref(), Some(ps1_build::PINNED_BRANCH));
        assert_eq!(val("-Region").as_deref(), Some("USA"));
        for f in ["-Yes", "-EnableRecompUi", "-EnableWizard", "-Generate", "-EnableBuild", "-NoGithub", "-NoCi", "-NoNetplay", "-NoFetchBoxart"] {
            assert!(a.iter().any(|x| x == f), "{f} missing in {a:?}");
        }
        assert!(!a.iter().any(|x| x == "-CreateGithub" || x == "-EnableCi" || x == "-EnableNetplay"), "{a:?}");
        let pos = a.iter().position(|x| x == "-File").unwrap();
        assert!(a[pos + 1].ends_with("setup_project.ps1"));
        assert!(a.iter().any(|x| x == "Bypass"));
    }

    #[test]
    fn metadata_is_never_empty_because_powershell_5_drops_empty_arguments() {
        let a = sample_args();
        for flag in ["-Name", "-Description", "-Publisher", "-Year", "-Region"] {
            let v = a.iter().position(|x| x == flag).map(|i| a[i + 1].clone());
            assert!(v.map(|v| !v.trim().is_empty()).unwrap_or(false), "{flag} must carry a non-empty value");
        }
        assert!(!a.iter().any(|x| x.is_empty()), "no empty argument anywhere: {a:?}");
    }

    #[test]
    fn regions_map_to_the_catalog_words() {
        assert_eq!(ps1_build::marketing_region("NTSC-U/C (North America)"), "USA");
        assert_eq!(ps1_build::marketing_region("PAL (Europe)"), "Europe");
        assert_eq!(ps1_build::marketing_region("PAL (Europe/Australia)"), "Europe");
        assert_eq!(ps1_build::marketing_region("NTSC-J (Japan)"), "Japan");
        assert_eq!(ps1_build::marketing_region("NTSC-K (Korea)"), "Korea");
        assert_eq!(ps1_build::marketing_region("Unknown"), "USA");
        assert_eq!(ps1_build::marketing_region(""), "USA");
    }

    #[test]
    fn built_exe_is_found_by_its_name_file_or_by_recency() {
        let t = TempDir::new("exe");
        let d = t.path();
        assert!(ps1_build::find_built_exe(d).is_none());
        std::fs::write(d.join("tests.exe"), b"x").unwrap();
        std::fs::write(d.join("cmake_hello.exe"), b"x").unwrap();
        assert!(ps1_build::find_built_exe(d).is_none(), "test helpers are not the game");
        std::fs::write(d.join("Game_Recompiled.exe"), b"x").unwrap();
        assert!(ps1_build::find_built_exe(d).unwrap().ends_with("Game_Recompiled.exe"));
        std::fs::write(d.join("Other.exe"), b"x").unwrap();
        std::fs::write(d.join("psxrecomp_exe_name-psx-runtime.txt"), "Other\n").unwrap();
        assert!(ps1_build::find_built_exe(d).unwrap().ends_with("Other.exe"), "the recorded name wins");
        std::fs::write(d.join("psxrecomp_exe_name-psx-runtime.txt"), "Missing.exe\n").unwrap();
        assert!(ps1_build::find_built_exe(d).is_some(), "a stale name falls back to the newest exe");
    }

    #[test]
    fn progress_only_moves_forward_across_the_scripts_phases() {
        let mut m = ps1_build::ProgressMapper::new();
        let mut last = 0.0f64;
        let mut feed = |line: &str| {
            if let Some(f) = m.line(line) {
                assert!(f > last, "{line:?} went {last} -> {f}");
                last = f;
            }
            last
        };
        assert!(feed("== Adding submodules ==") >= 0.40);
        assert!(feed("== Probing disc (identity + seeds + TOC fp) ==") >= 0.46);
        assert!(feed("== Generate (emitters + OpenBIOS + game C) ==") >= 0.50);
        let emitters_mid = feed("[35/69] Building CXX object x.obj");
        assert!(emitters_mid > 0.50 && emitters_mid < 0.62, "{emitters_mid}");
        feed("[69/69] Linking CXX executable psxrecomp-game.exe");
        // a second ninja run restarts its counter; the bar must not drop
        let before_restart = feed("[69/69] Linking CXX executable psxrecomp-bios.exe");
        assert_eq!(feed("[1/69] Building C object y.obj"), before_restart);
        let after = feed("Generate complete");
        assert!((after - 0.62).abs() < 1e-9);
        let rt = feed("[100/200] Building C object runtime.obj");
        assert!(rt > 0.62 && rt < 0.96, "{rt}");
        let done = feed("[200/200] Linking C executable game.exe");
        assert!((done - 0.95).abs() < 1e-9, "{done}");
    }

    #[test]
    fn unrelated_lines_do_not_move_progress() {
        let mut m = ps1_build::ProgressMapper::new();
        for l in ["", "warning: something", "Saved shard 12 (100 lines)", "[ok] fine", "[0/0] zero total"] {
            assert_eq!(m.line(l), None, "{l:?}");
        }
    }

    #[test]
    fn the_time_estimate_scales_with_program_size_and_cores() {
        let mmx4 = ps1_build::estimate_secs(1_177_600, 20, false);
        assert!((180..=320).contains(&mmx4), "calibrated on a measured 203 s run: {mmx4}");
        assert!(ps1_build::estimate_secs(2_400_000, 20, false) > mmx4, "bigger program, longer build");
        assert!(ps1_build::estimate_secs(1_177_600, 4, false) > mmx4 * 2, "fewer cores, much longer");
        assert!(ps1_build::estimate_secs(1_177_600, 20, true) > mmx4, "first build also downloads");
        assert!(ps1_build::estimate_secs(0, 0, false) > 0, "never zero, never a divide by zero");
        assert!(ps1_build::estimate_secs(u64::MAX, 1, true) < 100_000, "clamped");
    }

    #[test]
    fn estimates_are_human_readable() {
        assert_eq!(ps1_build::describe_estimate(45), "about 45 seconds");
        assert_eq!(ps1_build::describe_estimate(600), "about 10 minutes");
    }

    #[test]
    fn sha256_matches_the_known_digest() {
        let t = TempDir::new("sha");
        let f = t.path().join("a.bin");
        std::fs::write(&f, b"abc").unwrap();
        assert_eq!(
            ps1_build::sha256_file(&f).unwrap(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }
}

// ===========================================================================
// ingest
// ===========================================================================

mod ingest_tests {
    use super::*;
    use crate::tests_ps1::chd_fixture;

    fn opts(t: &TempDir) -> Ps1IngestOptions {
        Ps1IngestOptions { out_root: t.path().join("games").to_string_lossy().to_string() }
    }

    #[test]
    fn a_bare_iso_gets_a_generated_cue_and_a_manifest() {
        let t = TempDir::new("in-iso");
        let iso = t.path().join("Cool Game (Europe).iso");
        std::fs::write(&iso, ps1_iso("SCES_001.23", psx_exe_bytes(0x8001_0000, 0x8001_0000, 64, "Sony Computer Entertainment Inc. for Europe area"))).unwrap();
        let r = ps1_ingest::ingest_ps1(iso.to_str().unwrap(), &opts(&t), &mut |_| true).unwrap();
        assert_eq!(r.source_kind, "generated");
        assert_eq!(r.serial.as_deref(), Some("SCES-00123"));
        assert_eq!(r.title, "Cool Game");
        assert!(Path::new(&r.workspace).ends_with("SCES-00123"));
        let cue = std::fs::read_to_string(&r.cue_path).unwrap();
        assert!(cue.contains("TRACK 01 MODE1/2048"), "{cue}");
        assert!(Path::new(&r.cue_path).parent().unwrap().join("Cool Game (Europe).iso").is_file());
        let m: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(&r.manifest_path).unwrap()).unwrap();
        assert_eq!(m["platform"], "PS1");
        assert_eq!(m["pipeline"], "psxrecomp");
        assert_eq!(m["title"], "Cool Game");
        assert_eq!(m["psx_exe"]["entry_pc"], "0x80010000");
    }

    #[test]
    fn a_chd_is_decompressed_once_and_then_reused() {
        let t = TempDir::new("in-chd");
        let chd = t.path().join("Game (USA).chd");
        std::fs::write(&chd, chd_fixture()).unwrap();
        let first = ps1_ingest::ingest_ps1(chd.to_str().unwrap(), &opts(&t), &mut |_| true).unwrap();
        assert_eq!(first.source_kind, "decompressed");
        let cue = std::fs::read_to_string(&first.cue_path).unwrap();
        assert!(cue.contains("TRACK 01 MODE2/2352"), "{cue}");
        let bin = Path::new(&first.cue_path).with_extension("bin");
        assert!(bin.is_file());
        let stamp = std::fs::metadata(&bin).unwrap().modified().unwrap();

        let second = ps1_ingest::ingest_ps1(chd.to_str().unwrap(), &opts(&t), &mut |_| true).unwrap();
        assert_eq!(second.source_kind, "reused");
        assert_eq!(std::fs::metadata(&bin).unwrap().modified().unwrap(), stamp, "not rewritten");
    }

    #[test]
    fn a_cue_is_passed_through_untouched() {
        let t = TempDir::new("in-cue");
        let raw = crate::tests_disc::wrap_layout(
            &ps1_iso("SLUS_004.04", psx_exe_bytes(0x8001_0000, 0x8001_0000, 64, "x")),
            2352,
            24,
        );
        std::fs::write(t.path().join("g.bin"), raw).unwrap();
        let cue = t.path().join("g.cue");
        std::fs::write(&cue, "FILE \"g.bin\" BINARY\r\n  TRACK 01 MODE2/2352\r\n    INDEX 01 00:00:00\r\n").unwrap();
        let r = ps1_ingest::ingest_ps1(cue.to_str().unwrap(), &opts(&t), &mut |_| true).unwrap();
        assert_eq!(r.source_kind, "original");
        assert_eq!(Path::new(&r.cue_path), crate::ps2_ingest::absolute_path(&cue));
        assert!(!Path::new(&r.workspace).join("source").join("g.bin").exists(), "nothing was copied");
    }

    #[test]
    fn multi_disc_names_produce_a_warning() {
        let t = TempDir::new("in-multi");
        let iso = t.path().join("Big Game (USA) (Disc 2).iso");
        std::fs::write(&iso, ps1_iso("SLUS_004.04", psx_exe_bytes(0x8001_0000, 0x8001_0000, 64, "x"))).unwrap();
        let r = ps1_ingest::ingest_ps1(iso.to_str().unwrap(), &opts(&t), &mut |_| true).unwrap();
        assert_eq!(r.disc_number, Some(2));
        assert!(r.warnings.iter().any(|w| w.contains("disc 2")), "{:?}", r.warnings);
    }

    #[test]
    fn ps2_discs_and_non_exes_are_refused_with_pointers() {
        let t = TempDir::new("in-refuse");
        let ps2 = t.path().join("ps2.iso");
        std::fs::write(&ps2, crate::tests_disc::ps2_disc(true)).unwrap();
        let e = ps1_ingest::ingest_ps1(ps2.to_str().unwrap(), &opts(&t), &mut |_| true).unwrap_err();
        assert!(e.contains("PS2"), "{e}");

        let packed = t.path().join("packed.iso");
        std::fs::write(&packed, ps1_iso("SLUS_004.04", vec![0x11; 4096])).unwrap();
        let e = ps1_ingest::ingest_ps1(packed.to_str().unwrap(), &opts(&t), &mut |_| true).unwrap_err();
        assert!(e.contains("PS-X EXE"), "{e}");

        let junk = t.path().join("junk.iso");
        std::fs::write(&junk, vec![0u8; 50_000]).unwrap();
        assert!(ps1_ingest::ingest_ps1(junk.to_str().unwrap(), &opts(&t), &mut |_| true).is_err());
    }

    #[test]
    fn cancelling_stops_the_chd_export() {
        let t = TempDir::new("in-cancel");
        let chd = t.path().join("g.chd");
        std::fs::write(&chd, chd_fixture()).unwrap();
        let e = ps1_ingest::ingest_ps1(chd.to_str().unwrap(), &opts(&t), &mut |p| p.stage != "export").unwrap_err();
        assert!(e.contains("Cancelled"), "{e}");
    }
}

// ===========================================================================
// toolchain detection and planning
// ===========================================================================

mod plan_tests {
    use super::*;

    #[test]
    fn a_cold_cache_lists_the_toolchain_and_framework_downloads() {
        let mut r = rig(Setup::Ok);
        r.opts.toolchain_dir = None;
        r.opts.framework_override = None;
        let plan = ps1_build::plan_build(&r.ws, &r.opts).unwrap();
        let what: Vec<&str> = plan.downloads.iter().map(|d| d.what.as_str()).collect();
        assert!(what.iter().any(|w| w.contains("toolchain")), "{what:?}");
        assert!(what.iter().any(|w| w.contains("framework")), "{what:?}");
        assert_eq!(plan.toolchain.build_tools_source, "missing");
        assert!(plan.can_build, "a missing toolchain is a download, not a blocker: {:?}", plan.blockers);
        assert!(plan.download_mb >= 200);
        assert_eq!(plan.display_name, "Some Game");
        assert_eq!(plan.serial.as_deref(), Some("SLUS-00404"));
        assert!(plan.project_dir.ends_with("psx-slus-00404"), "{}", plan.project_dir);
    }

    #[test]
    fn a_supplied_toolchain_needs_no_toolchain_download() {
        let r = rig(Setup::Ok);
        let plan = ps1_build::plan_build(&r.ws, &r.opts).unwrap();
        assert_eq!(plan.toolchain.build_tools_source, "env");
        assert!(plan.downloads.iter().all(|d| !d.what.contains("toolchain")), "{:?}", plan.downloads);
        assert!(plan.framework_cached, "an override counts as cached");
    }

    #[test]
    fn the_cached_toolchain_is_found_without_being_told() {
        let t = TempDir::new("tc-cache");
        let cache = t.path().join("cache");
        fake_toolchain(&ps1_build::toolchain_cache_dir(&cache));
        let found = ps1_build::detect_toolchain(&Ps1ToolSearch {
            cache_dir: cache,
            only_path: true,
            skip_os_check: true,
            path_var: Some(std::ffi::OsString::new()),
            ..Default::default()
        });
        assert_eq!(found.build_tools_source, "cache");
    }

    #[test]
    fn a_single_nested_folder_in_the_archive_is_accepted() {
        let t = TempDir::new("tc-nested");
        let cache = t.path().join("cache");
        fake_toolchain(&ps1_build::toolchain_cache_dir(&cache).join("cmake-clang-v1"));
        let found = ps1_build::detect_toolchain(&Ps1ToolSearch {
            cache_dir: cache,
            only_path: true,
            skip_os_check: true,
            path_var: Some(std::ffi::OsString::new()),
            ..Default::default()
        });
        assert_eq!(found.build_tools_source, "cache");
        assert!(found.toolchain_dir.unwrap().ends_with("cmake-clang-v1"));
    }

    #[test]
    fn missing_tools_are_reported_with_how_to_get_them() {
        let t = TempDir::new("tc-none");
        let tc = ps1_build::detect_toolchain(&Ps1ToolSearch {
            cache_dir: t.path().join("cache"),
            only_path: true,
            skip_os_check: true,
            path_var: Some(std::ffi::OsString::new()),
            ..Default::default()
        });
        assert!(!tc.git.found && !tc.python.found);
        let text = tc.problems.join("\n");
        assert!(text.contains("git-scm.com"), "{text}");
        assert!(text.contains("python.org"), "{text}");
        assert!(!tc.ready_apart_from_build_tools);
    }

    #[test]
    fn a_python_that_does_not_run_is_not_accepted() {
        let t = TempDir::new("py-bad");
        let bad = script(t.path(), "python", "@echo off\nexit /b 9\n", "exit 9\n");
        assert!(ps1_build::python_version(&bad).is_none());
        let good = fake_python(t.path());
        assert_eq!(ps1_build::python_version(&good), Some((3, 12)));
    }

    #[test]
    fn plan_rejects_a_folder_that_is_not_a_ps1_workspace() {
        let t = TempDir::new("plan-bad");
        let r = rig(Setup::Ok);
        assert!(ps1_build::plan_build(t.path(), &r.opts).unwrap_err().contains("game.json"));
        std::fs::write(t.path().join("game.json"), r#"{"platform":"PS2","display_name":"x"}"#).unwrap();
        assert!(ps1_build::plan_build(t.path(), &r.opts).unwrap_err().contains("not a PS1 workspace"));
    }

    #[test]
    fn a_missing_cue_is_a_blocker() {
        let t = TempDir::new("plan-cue");
        let iso = t.path().join("g.iso");
        std::fs::write(&iso, ps1_iso("SLUS_004.04", psx_exe_bytes(0x8001_0000, 0x8001_0000, 64, "x"))).unwrap();
        let ws = PathBuf::from(
            ps1_ingest::ingest_ps1(iso.to_str().unwrap(), &Ps1IngestOptions { out_root: t.path().join("w").to_string_lossy().to_string() }, &mut |_| true)
                .unwrap()
                .workspace,
        );
        let r = rig(Setup::Ok);
        for f in std::fs::read_dir(ws.join("source")).unwrap() {
            let _ = std::fs::remove_file(f.unwrap().path());
        }
        let plan = ps1_build::plan_build(&ws, &r.opts).unwrap();
        assert!(!plan.can_build);
        assert!(plan.blockers.iter().any(|b| b.contains("disc sheet")), "{:?}", plan.blockers);
    }
}

// ===========================================================================
// pipeline
// ===========================================================================

mod pipeline_tests {
    use super::*;

    #[test]
    fn build_refuses_to_download_without_consent() {
        let mut r = rig(Setup::Ok);
        r.opts.allow_downloads = false;
        let e = ps1_build::build_game(&r.ws, &r.opts, &mut no_cb).unwrap_err();
        assert!(e.starts_with("NEEDS_DOWNLOAD_CONSENT:"), "{e}");
        assert!(!r.tools.join("setup-args.log").exists(), "nothing ran");
    }

    #[test]
    fn full_build_runs_the_setup_script_with_the_right_arguments_and_environment() {
        let r = rig(Setup::Ok);
        let mut stages: Vec<String> = vec![];
        let mut max = 0.0f64;
        let res = ps1_build::build_game(&r.ws, &r.opts, &mut |p| {
            if stages.last() != Some(&p.stage) {
                stages.push(p.stage.clone());
            }
            assert!(p.fraction + 1e-9 >= max, "progress never goes backwards: {} < {}", p.fraction, max);
            max = max.max(p.fraction);
            true
        })
        .unwrap();
        assert_eq!(stages, ["source", "project", "package", "done"], "{stages:?}");
        assert_eq!(max, 1.0);

        let args = std::fs::read_to_string(r.tools.join("setup-args.log")).unwrap();
        assert!(args.contains("-File"), "{args}");
        assert!(args.contains("setup_project.ps1"), "{args}");
        assert!(args.contains("-Yes") && args.contains("-Generate") && args.contains("-EnableBuild"), "{args}");
        assert!(args.contains("-NoGithub"), "never publishes: {args}");
        assert!(args.contains("-GithubRepo psx-slus-00404"), "{args}");
        assert!(args.contains("-Name Some Game") || args.contains("-Name \"Some Game\""), "{args}");

        let env = std::fs::read_to_string(r.tools.join("env.log")).unwrap();
        let tc = r.opts.toolchain_dir.clone().unwrap();
        assert!(env.contains(&format!("TOOLCHAIN={}", tc.display())), "{env}");
        assert!(env.contains("YES=1"), "{env}");
        assert!(env.contains("FILEALLOW=always"), "local-path submodules need protocol.file.allow: {env}");
        assert!(
            env.contains("AUTOCRLF=core.autocrlf=false") && env.contains("GITCOUNT=4"),
            "CRLF warnings hang the setup script's `git add 2>$null` in PowerShell 5.1: {env}"
        );
        assert!(env.contains("PYTHON="), "{env}");
        assert!(env.contains("PATHCONV=[]") || env.contains("PATHCONV=[%MSYS_NO_PATHCONV%]"), "Git-bash path conversion must stay on: {env}");
        let path_line = env.lines().find(|l| l.starts_with("PATH=")).unwrap();
        assert!(path_line.to_ascii_lowercase().contains(&tc.join("bin").to_string_lossy().to_ascii_lowercase()), "{path_line}");

        // packaged: the exe, its DLL and BIOS, no CMake debris
        let pkg = res.package.expect("packaged");
        let dir = Path::new(&pkg.package_dir);
        assert!(dir.join("Fake_Recompiled.exe").is_file());
        assert!(dir.join("SDL3.dll").is_file());
        assert!(dir.join("bios/openbios.bin").is_file());
        assert!(!dir.join("CMakeCache.txt").exists());
        assert!(!dir.join("CMakeFiles").exists());
        assert!(!dir.join("psxrecomp_exe_name-psx-runtime.txt").exists());
        assert!(dir.join("README.txt").is_file());
        assert!(std::fs::read_to_string(dir.join("README.txt")).unwrap().contains("Some Game"));
        assert!(Path::new(&res.exe).ends_with("Fake_Recompiled.exe"));
        assert!(res.source_image.ends_with("Some Game (USA).iso"), "the user's own image is handed to the game: {}", res.source_image);
        let names: Vec<&str> = res.stage_secs.iter().map(|(n, _)| n.as_str()).collect();
        let mut uniq = names.clone();
        uniq.dedup();
        assert_eq!(names, uniq, "no stage is listed twice in a row: {names:?}");
        assert!(Path::new(&res.exe).parent().unwrap().join(ps1_build::PACKAGE_MARKER).is_file());
        assert!(ps1_build::is_aura_package_exe(Path::new(&res.exe)));
        assert!(!ps1_build::is_aura_package_exe(&r.tools.join("git")), "only a packaged program is accepted");
        assert!(Path::new(&res.log_path).is_file());
        let log = std::fs::read_to_string(&res.log_path).unwrap();
        assert!(log.contains("[3/4] Linking"), "{log}");
    }

    #[test]
    fn packaging_can_be_skipped() {
        let mut r = rig(Setup::Ok);
        r.opts.package = false;
        let res = ps1_build::build_game(&r.ws, &r.opts, &mut no_cb).unwrap();
        assert!(res.package.is_none());
        assert!(!r.ws.join("package").exists());
        assert!(Path::new(&res.exe).is_file());
    }

    #[test]
    fn a_failing_setup_reports_its_output_and_packages_nothing() {
        let r = rig(Setup::Fail);
        let e = ps1_build::build_game(&r.ws, &r.opts, &mut no_cb).unwrap_err();
        assert!(e.contains("PSXRecomp project setup failed"), "{e}");
        assert!(e.contains("boom while generating"), "the tool's own message must be shown: {e}");
        assert!(!r.ws.join("package").exists());
    }

    #[test]
    fn a_previous_project_folder_is_replaced() {
        let r = rig(Setup::Ok);
        let old = r.ws.join("psx-slus-00404");
        std::fs::create_dir_all(old.join("stale")).unwrap();
        std::fs::write(old.join("stale/x.txt"), b"old").unwrap();
        ps1_build::build_game(&r.ws, &r.opts, &mut no_cb).unwrap();
        assert!(!old.join("stale").exists());
        assert!(old.join("build-release/Fake_Recompiled.exe").is_file());
    }

    #[test]
    fn cancelling_stops_the_build_promptly() {
        let r = rig(Setup::Slow);
        let started = Instant::now();
        let e = ps1_build::build_game(&r.ws, &r.opts, &mut |p| p.stage != "project" || started.elapsed() < Duration::from_millis(800))
            .unwrap_err();
        assert!(e.contains("Cancelled"), "{e}");
        assert!(started.elapsed() < Duration::from_secs(15), "took {:?}", started.elapsed());
        assert!(!r.ws.join("package").exists());
    }

    #[test]
    fn relative_workspace_and_cache_paths_work() {
        // The framework's script runs from another directory, so every path
        // handed to it must be absolute.
        let r = rig(Setup::Ok);
        let cwd = std::env::current_dir().unwrap();
        let scratch = cwd.join(format!("target/aura-ps1-rel-{}", std::process::id()));
        std::fs::create_dir_all(&scratch).unwrap();
        struct Cleanup(PathBuf);
        impl Drop for Cleanup {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
        let _c = Cleanup(scratch.clone());
        // a workspace inside the cwd, expressed relative to it
        let ws_abs = scratch.join("ws");
        std::fs::create_dir_all(&ws_abs).unwrap();
        std::fs::copy(r.ws.join("game.json"), ws_abs.join("game.json")).unwrap();
        // the manifest's cue path is absolute and still valid
        let rel_ws = PathBuf::from(format!("target/aura-ps1-rel-{}/ws", std::process::id()));
        let mut o = r.opts.clone();
        o.cache_dir = Some(PathBuf::from(format!("target/aura-ps1-rel-{}/cache", std::process::id())));
        let res = ps1_build::build_game(&rel_ws, &o, &mut no_cb).unwrap();
        assert!(Path::new(&res.project_dir).is_absolute(), "{}", res.project_dir);
        let args = std::fs::read_to_string(r.tools.join("setup-args.log")).unwrap();
        let dir_pos = args.find("-Dir ").unwrap();
        let after = args[dir_pos + 5..].trim_start().trim_start_matches('"');
        assert!(Path::new(after.split_whitespace().next().unwrap().trim_matches('"')).is_absolute(), "{args}");
    }
}

// ===========================================================================
// toolchain download
// ===========================================================================

#[cfg(windows)]
mod download_tests {
    use super::*;

    fn make_zip(t: &TempDir) -> (PathBuf, String) {
        let src = t.path().join("zipsrc");
        fake_toolchain(&src);
        let zip = t.path().join("tc.zip");
        let st = std::process::Command::new("tar")
            .args(["-a", "-cf"])
            .arg(&zip)
            .arg("-C")
            .arg(&src)
            .arg(".")
            .status()
            .expect("tar available");
        assert!(st.success());
        let sha = ps1_build::sha256_file(&zip).unwrap();
        (zip, sha)
    }

    fn file_url(p: &Path) -> String {
        format!("file:///{}", p.to_string_lossy().replace('\\', "/"))
    }

    #[test]
    fn the_toolchain_is_downloaded_verified_and_unpacked() {
        let mut r = rig(Setup::Ok);
        let (zip, sha) = make_zip(&r.t);
        r.opts.toolchain_dir = None;
        r.opts.toolchain_url = Some(file_url(&zip));
        r.opts.toolchain_sha256 = Some(sha);
        let cache = r.opts.cache_dir.clone().unwrap();
        let res = ps1_build::build_game(&r.ws, &r.opts, &mut no_cb).unwrap();
        assert!(Path::new(&res.exe).is_file());
        let env = std::fs::read_to_string(r.tools.join("env.log")).unwrap();
        let unpacked = ps1_build::toolchain_cache_dir(&cache);
        assert!(
            env.to_ascii_lowercase().contains(&unpacked.to_string_lossy().to_ascii_lowercase()),
            "the unpacked toolchain was handed to the script: {env}"
        );
        assert!(unpacked.join("bin").join("cmake.exe").is_file());

        // a second build reuses it: no download needed even with consent withheld
        let mut again = r.opts.clone();
        again.toolchain_url = None; // would 404 if it tried
        again.allow_downloads = true;
        assert!(ps1_build::build_game(&r.ws, &again, &mut no_cb).is_ok());
    }

    #[test]
    fn a_checksum_mismatch_is_refused_and_the_download_deleted() {
        let mut r = rig(Setup::Ok);
        let (zip, _) = make_zip(&r.t);
        r.opts.toolchain_dir = None;
        r.opts.toolchain_url = Some(file_url(&zip));
        r.opts.toolchain_sha256 = Some("0".repeat(64));
        let e = ps1_build::build_game(&r.ws, &r.opts, &mut no_cb).unwrap_err();
        assert!(e.contains("checksum"), "{e}");
        let cache = r.opts.cache_dir.clone().unwrap();
        assert!(!cache.join("downloads").join("cmake-clang-v1-windows-x64.zip").exists());
        assert!(!r.tools.join("setup-args.log").exists(), "the script never ran");
    }

    #[test]
    fn a_failed_download_names_what_failed() {
        let mut r = rig(Setup::Ok);
        r.opts.toolchain_dir = None;
        r.opts.toolchain_url = Some(file_url(&r.t.path().join("does-not-exist.zip")));
        let e = ps1_build::build_game(&r.ws, &r.opts, &mut no_cb).unwrap_err();
        assert!(e.contains("Downloading the build toolchain failed"), "{e}");
    }
}

// ===========================================================================
// A short image: say how much is missing and whether it matters
// ===========================================================================

mod truncation_tests {
    use super::*;
    use crate::ps2_ingest;

    const MARKER: &str = "Sony Computer Entertainment Inc. for North America area";

    /// SYSTEM.CNF (1 sector), the boot program (11 sectors), DATA.BIN (5), in
    /// that order, so DATA.BIN is what a cut reaches first.
    fn image() -> Vec<u8> {
        ps1_iso("SLUS_004.04", psx_exe_bytes(0x8001_0000, 0x8001_0000, 20_000, MARKER))
    }

    fn cut(sectors: usize) -> Vec<u8> {
        let mut b = image();
        b.truncate(b.len() - sectors * 2048);
        b
    }

    fn write(t: &TempDir, bytes: Vec<u8>) -> String {
        let p = t.path().join("Cut Game (USA).iso");
        std::fs::write(&p, bytes).unwrap();
        p.to_string_lossy().to_string()
    }

    fn ingest(t: &TempDir, image: &str) -> ps1_ingest::Ps1IngestResult {
        let opts = Ps1IngestOptions { out_root: t.path().join("games").to_string_lossy().to_string() };
        ps1_ingest::ingest_ps1(image, &opts, &mut |_| true).unwrap()
    }

    #[test]
    fn a_complete_image_has_nothing_to_say() {
        let t = TempDir::new("trunc-none");
        let info = ps2_ingest::inspect_image(&write(&t, image())).unwrap();
        assert!(!info.truncated);
        assert_eq!((info.missing_sectors, info.files_past_cut, info.boot_past_cut), (0, 0, false));
        assert!(info.warnings.is_empty(), "{:?}", info.warnings);
    }

    #[test]
    fn missing_blank_sectors_past_every_file_are_harmless() {
        let t = TempDir::new("trunc-blank");
        // The descriptor claims 10 sectors more than the file holds; nothing lives there.
        let mut b = image();
        let total = (b.len() / 2048) as u32 + 10;
        b[16 * 2048 + 80..16 * 2048 + 84].copy_from_slice(&total.to_le_bytes());
        b[16 * 2048 + 84..16 * 2048 + 88].copy_from_slice(&total.to_be_bytes());
        let path = write(&t, b);

        let info = ps2_ingest::inspect_image(&path).unwrap();
        assert!(info.truncated);
        assert_eq!((info.missing_sectors, info.files_past_cut, info.boot_past_cut), (10, 0, false));
        assert!(info.can_ingest);
        assert_eq!(info.warnings.len(), 1, "{:?}", info.warnings);
        let w = &info.warnings[0];
        assert!(w.contains("10 short"), "{w}");
        assert!(w.contains("No file in the disc's directory reaches into the missing part"), "{w}");
        assert!(w.contains("every file the build needs is readable"), "{w}");
        assert!(!w.contains("cannot work") && !w.contains("unlikely"), "{w}");

        // The workspace carries the same single note, with no blanket verdict added.
        let r = ingest(&t, &path);
        assert_eq!(r.warnings, info.warnings);
    }

    #[test]
    fn a_cut_through_a_data_file_leaves_the_build_intact() {
        let t = TempDir::new("trunc-data");
        let path = write(&t, cut(3));
        let info = ps2_ingest::inspect_image(&path).unwrap();
        assert!(info.truncated && info.can_ingest);
        assert_eq!((info.missing_sectors, info.files_past_cut, info.boot_past_cut), (3, 1, false));
        assert_eq!(info.warnings.len(), 1, "{:?}", info.warnings);
        let w = &info.warnings[0];
        assert!(w.contains("1 of 3 file(s)") && w.contains("DATA.BIN"), "{w}");
        assert!(w.contains("boot program (SLUS_004.04) is intact") && w.contains("build can go ahead"), "{w}");
        assert!(!w.contains("unlikely to work"), "{w}");

        let r = ingest(&t, &path);
        assert_eq!(r.warnings.len(), 1, "one note, not two: {:?}", r.warnings);
        assert!(r.warnings[0].contains("DATA.BIN"));
    }

    #[test]
    fn a_cut_through_the_boot_program_is_called_out_once() {
        let t = TempDir::new("trunc-boot");
        // DATA.BIN (5 sectors) is gone and so are the last 4 of the boot program.
        let path = write(&t, cut(9));
        let info = ps2_ingest::inspect_image(&path).unwrap();
        assert!(info.truncated);
        assert_eq!((info.missing_sectors, info.files_past_cut, info.boot_past_cut), (9, 2, true));
        // Its 2 KiB header is still readable, so the disc is still recognised.
        assert!(info.can_ingest);
        let w = &info.warnings[0];
        assert!(w.contains("boot program (SLUS_004.04) itself reaches past the end of the image"), "{w}");
        assert!(w.contains("cannot work"), "{w}");

        let r = ingest(&t, &path);
        assert_eq!(r.warnings.len(), 1, "{:?}", r.warnings);
        assert!(r.warnings[0].contains("cannot work"));
    }
}
