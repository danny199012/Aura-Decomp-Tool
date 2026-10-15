//! Tests for the one-click build orchestration (`ps2_build`).
//!
//! The real tools (CMake, a compiler, upstream's source) are replaced by small
//! scripts so the whole pipeline — consent, source install, recompile, runtime
//! build, progress, failure, cancellation, packaging — runs in a second and on
//! any machine. A real end-to-end build is exercised separately by hand.

use crate::ps2_build::{self, BuildOptions, ToolSearch};
use crate::ps2_ingest::{self, ExtractMode, IngestOptions};
use crate::tests_disc::{ps2_disc_with_filler, TempDir};
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

fn make_workspace(t: &TempDir, mode: ExtractMode) -> PathBuf {
    let iso = t.path().join("game.iso");
    std::fs::write(&iso, ps2_disc_with_filler(false, 0)).unwrap();
    let opts = IngestOptions {
        out_root: t.path().join("games").to_string_lossy().to_string(),
        mode,
        recompiler: None,
    };
    PathBuf::from(ps2_ingest::ingest_ps2(iso.to_str().unwrap(), &opts, &mut |_| true).unwrap().workspace)
}

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
enum Cmake {
    Ok,
    FailBuild,
    Slow,
}

/// Fake `cmake`: logs its argv to `cmake-args.log`, creates CMakeCache.txt on
/// configure, and on build prints unity lines then creates the exe + a DLL.
fn fake_cmake(dir: &Path, mode: Cmake) -> PathBuf {
    let (win_tail, unix_tail) = match mode {
        Cmake::Ok => (
            "mkdir \"%BDIR%\\ps2xRuntime\\Release\" 2>nul\necho MZ> \"%BDIR%\\ps2xRuntime\\Release\\ps2EntryRunner.exe\"\necho dll> \"%BDIR%\\ps2xRuntime\\Release\\fake-ffmpeg.dll\"\necho   ps2EntryRunner.vcxproj -^> built\nexit /b 0\n",
            "mkdir -p \"$bdir/ps2xRuntime/Release\"\necho MZ > \"$bdir/ps2xRuntime/Release/ps2EntryRunner\"\necho dll > \"$bdir/ps2xRuntime/Release/fake-ffmpeg.dll\"\necho \"  ps2EntryRunner.vcxproj -> built\"\nexit 0\n",
        ),
        Cmake::FailBuild => (
            "echo error C1083: Cannot open include file: 'boom.h': No such file or directory\nexit /b 1\n",
            "echo \"error C1083: Cannot open include file: 'boom.h': No such file or directory\"\nexit 1\n",
        ),
        Cmake::Slow => (
            "ping -n 30 127.0.0.1 >nul\nexit /b 0\n",
            "sleep 30\nexit 0\n",
        ),
    };
    let win = format!(
        "@echo off\nsetlocal\necho %* >> \"%~dp0cmake-args.log\"\nset MODE=configure\nset BDIR=\n:loop\nif \"%~1\"==\"\" goto done\nif \"%~1\"==\"--build\" (\n  set MODE=build\n  set BDIR=%~2\n  shift\n)\nif \"%~1\"==\"-B\" (\n  set BDIR=%~2\n  shift\n)\nshift\ngoto loop\n:done\nif \"%MODE%\"==\"configure\" (\n  mkdir \"%BDIR%\" 2>nul\n  echo ok> \"%BDIR%\\CMakeCache.txt\"\n  echo -- Configuring done\n  exit /b 0\n)\necho   unity_0_cxx.cxx\necho   unity_1_cxx.cxx\n{win_tail}"
    );
    let unix = format!(
        "echo \"$@\" >> \"$(dirname \"$0\")/cmake-args.log\"\nmode=configure\nbdir=\nwhile [ $# -gt 0 ]; do\n  case \"$1\" in\n    --build) mode=build; bdir=\"$2\"; shift ;;\n    -B) bdir=\"$2\"; shift ;;\n  esac\n  shift\ndone\nif [ \"$mode\" = configure ]; then\n  mkdir -p \"$bdir\"\n  echo ok > \"$bdir/CMakeCache.txt\"\n  echo \"-- Configuring done\"\n  exit 0\nfi\necho \"  unity_0_cxx.cxx\"\necho \"  unity_1_cxx.cxx\"\n{unix_tail}"
    );
    script(dir, "cmake", &win, &unix)
}

/// Fake `ps2_recomp`: writes four generated files into ./generated.
fn fake_recompiler(dir: &Path) -> PathBuf {
    script(
        dir,
        "ps2_recomp",
        "@echo off\nif not exist generated mkdir generated\necho // fn> generated\\fn_0x100000.cpp\necho // reg> generated\\register_functions.cpp\necho // h1> generated\\ps2_recompiled_functions.h\necho // h2> generated\\ps2_recompiled_stubs.h\nexit /b 0\n",
        "mkdir -p generated\necho '// fn' > generated/fn_0x100000.cpp\necho '// reg' > generated/register_functions.cpp\necho '// h1' > generated/ps2_recompiled_functions.h\necho '// h2' > generated/ps2_recompiled_stubs.h\nexit 0\n",
    )
}

/// A stand-in upstream checkout with the committed placeholder runner file.
fn fake_source(dir: &Path) -> PathBuf {
    let src = dir.join("PS2Recomp");
    std::fs::create_dir_all(src.join("ps2xRuntime/src/runner")).unwrap();
    std::fs::create_dir_all(src.join("ps2xRuntime/include")).unwrap();
    std::fs::write(src.join("CMakeLists.txt"), "project(fake)\n").unwrap();
    std::fs::write(src.join("ps2xRuntime/src/runner/register_functions.cpp"), "// upstream placeholder\n").unwrap();
    std::fs::write(src.join("ps2xRuntime/include/ps2_recompiled_functions.h"), "// stale header from another game\n").unwrap();
    src
}

struct Rig {
    t: TempDir,
    ws: PathBuf,
    opts: BuildOptions,
    cmake_dir: PathBuf,
}

fn rig(mode: Cmake) -> Rig {
    let t = TempDir::new("build");
    let ws = make_workspace(&t, ExtractMode::All);
    let tools = t.path().join("tools");
    std::fs::create_dir_all(&tools).unwrap();
    let launcher = t.path().join("aura-launch.exe");
    std::fs::write(&launcher, b"MZ launcher").unwrap();
    let git = tools.join("git");
    std::fs::write(&git, b"x").unwrap();
    let opts = BuildOptions {
        cache_dir: Some(t.path().join("cache")),
        allow_downloads: true,
        package: true,
        native_feel: true,
        fast_release: false,
        lean_indirect_calls: false,
        jobs: Some(4),
        cmake: Some(fake_cmake(&tools, mode)),
        git: Some(git),
        source_override: Some(fake_source(t.path())),
        recompiler: Some(fake_recompiler(&tools)),
        launcher_exe: Some(launcher),
        skip_compiler_check: true,
    };
    Rig { t, ws, opts, cmake_dir: tools }
}

fn no_cb(_: &ps2_build::BuildProgress) -> bool {
    true
}

// ===========================================================================
// pure helpers
// ===========================================================================

mod helper_tests {
    use super::*;

    fn lossy(v: &[OsString]) -> Vec<String> {
        v.iter().map(|s| s.to_string_lossy().to_string()).collect()
    }

    #[test]
    fn recompiler_configure_builds_only_the_recompiler() {
        let a = lossy(&ps2_build::recompiler_configure_args(Path::new("src"), Path::new("out"), 8));
        assert_eq!(&a[..4], ["-S", "src", "-B", "out"]);
        for flag in ["-DPS2X_BUILD_RUNTIME=OFF", "-DPS2X_BUILD_ANALYZER=OFF", "-DPS2X_BUILD_TEST=OFF", "-DPS2X_BUILD_STUDIO=OFF"] {
            assert!(a.iter().any(|x| x == flag), "{flag} in {a:?}");
        }
        assert!(!a.iter().any(|x| x.contains("PS2X_BUILD_RECOMP")));
    }

    #[test]
    fn runtime_configure_disables_everything_but_the_runtime() {
        let a = lossy(&ps2_build::runtime_configure_args(Path::new("src"), Path::new("out"), 8, false, false));
        for flag in ["-DPS2X_BUILD_RECOMP=OFF", "-DPS2X_BUILD_ANALYZER=OFF", "-DPS2X_BUILD_TEST=OFF", "-DPS2X_BUILD_STUDIO=OFF"] {
            assert!(a.iter().any(|x| x == flag), "{flag} in {a:?}");
        }
        assert!(!a.iter().any(|x| x.contains("DEBUG_UI")), "upstream defaults untouched: {a:?}");
    }

    #[test]
    fn native_feel_hides_the_overlay_console_and_verbose_logs() {
        let a = lossy(&ps2_build::runtime_configure_args(Path::new("s"), Path::new("o"), 8, true, false));
        for flag in ["-DPS2X_ENABLE_DEBUG_UI=OFF", "-DPS2X_SHOW_WINDOWS_CONSOLE=OFF", "-DPS2X_ENABLE_AGRESSIVE_LOGS=OFF"] {
            assert!(a.iter().any(|x| x == flag), "{flag} in {a:?}");
        }
        // Runtime logs must stay on: the launcher explains failures from them.
        assert!(!a.iter().any(|x| x.contains("RUNTIME_LOGS=OFF")), "{a:?}");
    }

    #[cfg(windows)]
    #[test]
    fn msvc_builds_get_dash_style_parallel_flags_as_one_argument() {
        let a = lossy(&ps2_build::runtime_configure_args(Path::new("s"), Path::new("o"), 12, false, false));
        let f = a.iter().find(|x| x.starts_with("-DCMAKE_CXX_FLAGS=")).expect("flags");
        assert_eq!(f, "-DCMAKE_CXX_FLAGS=-DWIN32 -D_WINDOWS -EHsc -GR -MP12");
    }

    #[test]
    fn fast_release_sets_the_build_type_upstream_gates_its_optimisations_on() {
        let off = lossy(&ps2_build::runtime_configure_args(Path::new("s"), Path::new("o"), 8, true, false));
        assert!(!off.iter().any(|x| x.contains("CMAKE_BUILD_TYPE")), "{off:?}");
        let on = lossy(&ps2_build::runtime_configure_args(Path::new("s"), Path::new("o"), 8, true, true));
        assert!(on.iter().any(|x| x == "-DCMAKE_BUILD_TYPE=Release"), "{on:?}");
    }

    #[test]
    fn build_args_target_release_with_parallelism() {
        let a = lossy(&ps2_build::build_args(Path::new("out"), "ps2EntryRunner", 16));
        assert_eq!(a, ["--build", "out", "--config", "Release", "--target", "ps2EntryRunner", "--parallel", "16"]);
    }

    #[test]
    fn unity_progress_lines_are_recognised() {
        assert!(ps2_build::is_unity_line("  unity_17_cxx.cxx"));
        assert!(ps2_build::is_unity_line("unity_0_cxx.cxx"));
        assert!(!ps2_build::is_unity_line("  fn_0x100000.cpp"));
        assert!(!ps2_build::is_unity_line("Generating Code..."));
    }

    #[test]
    fn disk_space_check() {
        assert!(ps2_build::space_ok(Some(10), 10));
        assert!(!ps2_build::space_ok(Some(9), 10));
        assert!(ps2_build::space_ok(None, u64::MAX), "unknown free space must not block");
    }

    #[test]
    fn estimates_are_human_readable() {
        assert_eq!(ps2_build::describe_estimate(40), "about a minute");
        assert_eq!(ps2_build::describe_estimate(960), "about 16 minutes");
    }
}

// ===========================================================================
// toolchain detection
// ===========================================================================

mod toolchain_tests {
    use super::*;

    #[test]
    fn finds_cmake_and_git_on_path() {
        let t = TempDir::new("tc-found");
        std::fs::write(t.path().join("cmake"), b"x").unwrap();
        std::fs::write(t.path().join("git"), b"x").unwrap();
        let s = ToolSearch {
            path_var: Some(t.path().as_os_str().to_os_string()),
            skip_compiler_check: true,
            only_path: true,
            ..Default::default()
        };
        let tc = ps2_build::detect_toolchain(&s);
        assert!(tc.cmake.found && tc.git.found && tc.compiler.found, "{tc:?}");
        assert!(tc.ready, "{tc:?}");
        assert!(tc.problems.is_empty());
    }

    #[test]
    fn missing_tools_are_reported_with_how_to_get_them() {
        let t = TempDir::new("tc-missing");
        let s = ToolSearch {
            path_var: Some(t.path().as_os_str().to_os_string()),
            skip_compiler_check: true,
            only_path: true,
            ..Default::default()
        };
        let tc = ps2_build::detect_toolchain(&s);
        assert!(!tc.ready);
        assert!(!tc.cmake.found && !tc.git.found);
        let all = tc.problems.join("\n");
        assert!(all.contains("CMake") && all.contains("cmake.org"), "{all}");
        assert!(all.contains("git") && all.contains("git-scm.com"), "{all}");
    }
}

// ===========================================================================
// installing generated sources
// ===========================================================================

mod install_tests {
    use super::*;

    #[test]
    fn cpp_goes_to_runner_and_headers_to_include_and_placeholder_is_replaced() {
        let t = TempDir::new("install");
        let tree = fake_source(t.path());
        let gen = t.path().join("gen");
        std::fs::create_dir_all(&gen).unwrap();
        std::fs::write(gen.join("a_0x100.cpp"), "// a").unwrap();
        std::fs::write(gen.join("register_functions.cpp"), "// generated reg").unwrap();
        std::fs::write(gen.join("ps2_recompiled_functions.h"), "// new header").unwrap();
        std::fs::write(gen.join("notes.txt"), "ignored").unwrap();

        let (cpp, hdr) = ps2_build::install_generated_sources(&gen, &tree).unwrap();
        assert_eq!((cpp, hdr), (2, 1));
        let runner = tree.join("ps2xRuntime/src/runner");
        assert_eq!(std::fs::read_to_string(runner.join("register_functions.cpp")).unwrap(), "// generated reg");
        assert!(runner.join("a_0x100.cpp").is_file());
        assert!(!runner.join("ps2_recompiled_functions.h").exists(), "headers must NOT be in the runner folder");
        assert!(!runner.join("notes.txt").exists());
        let inc = tree.join("ps2xRuntime/include/ps2_recompiled_functions.h");
        assert_eq!(std::fs::read_to_string(inc).unwrap(), "// new header", "stale header replaced");
    }

    #[test]
    fn previous_games_sources_are_cleared() {
        let t = TempDir::new("install-clear");
        let tree = fake_source(t.path());
        let runner = tree.join("ps2xRuntime/src/runner");
        std::fs::write(runner.join("old_game_0xdead.cpp"), "// old").unwrap();
        let gen = t.path().join("gen");
        std::fs::create_dir_all(&gen).unwrap();
        std::fs::write(gen.join("new_0x1.cpp"), "// new").unwrap();
        ps2_build::install_generated_sources(&gen, &tree).unwrap();
        assert!(!runner.join("old_game_0xdead.cpp").exists());
        assert!(runner.join("new_0x1.cpp").exists());
    }

    #[test]
    fn empty_output_is_an_error_not_a_silent_empty_build() {
        let t = TempDir::new("install-empty");
        let tree = fake_source(t.path());
        let gen = t.path().join("gen");
        std::fs::create_dir_all(&gen).unwrap();
        let e = ps2_build::install_generated_sources(&gen, &tree).unwrap_err();
        assert!(e.contains("no generated .cpp"), "{e}");
    }
}

// ===========================================================================
// planning and consent
// ===========================================================================

mod plan_tests {
    use super::*;

    #[test]
    fn plan_lists_downloads_for_a_cold_cache() {
        let r = rig(Cmake::Ok);
        let mut o = r.opts.clone();
        o.source_override = None; // pretend the source is not cached
        o.recompiler = None;
        let p = ps2_build::plan_build(&r.ws, &o).unwrap();
        let what: Vec<&str> = p.downloads.iter().map(|d| d.what.as_str()).collect();
        assert!(what.iter().any(|w| w.contains("PS2Recomp source")), "{what:?}");
        assert!(what.iter().any(|w| w.contains("Recompiler build dependencies")), "{what:?}");
        assert!(what.iter().any(|w| w.contains("raylib")), "{what:?}");
        assert!(what.iter().any(|w| w.contains("FFmpeg")), "{what:?}");
        assert!(p.download_mb > 900, "honest sizes: {}", p.download_mb);
        assert!(p.estimate_secs > 60);
        assert_eq!(p.pinned_commit, ps2_build::PINNED_COMMIT);
    }

    #[test]
    fn plan_has_no_downloads_when_everything_is_cached() {
        let r = rig(Cmake::Ok);
        // cache markers: runtime already configured
        let rt = r.t.path().join("cache").join("build-runtime");
        std::fs::create_dir_all(&rt).unwrap();
        std::fs::write(rt.join("CMakeCache.txt"), "x").unwrap();
        let p = ps2_build::plan_build(&r.ws, &r.opts).unwrap();
        assert!(p.downloads.is_empty(), "{:?}", p.downloads.iter().map(|d| &d.what).collect::<Vec<_>>());
        assert!(p.can_build, "{:?}", p.blockers);
    }

    #[test]
    fn plan_blocks_when_the_disc_was_not_fully_extracted() {
        let t = TempDir::new("plan-partial");
        let ws = make_workspace(&t, ExtractMode::Executables);
        let tools = t.path().join("tools");
        std::fs::create_dir_all(&tools).unwrap();
        let git = tools.join("git");
        std::fs::write(&git, b"x").unwrap();
        let o = BuildOptions {
            cache_dir: Some(t.path().join("cache")),
            cmake: Some(fake_cmake(&tools, Cmake::Ok)),
            git: Some(git),
            skip_compiler_check: true,
            ..Default::default()
        };
        let p = ps2_build::plan_build(&ws, &o).unwrap();
        assert!(!p.can_build);
        assert!(p.blockers.iter().any(|b| b.contains("entire disc")), "{:?}", p.blockers);
    }

    #[test]
    fn plan_rejects_a_folder_that_is_not_a_workspace() {
        let t = TempDir::new("plan-bad");
        let e = ps2_build::plan_build(t.path(), &BuildOptions::default()).unwrap_err();
        assert!(e.contains("game.json"), "{e}");
    }

    #[test]
    fn build_refuses_to_download_without_consent() {
        let r = rig(Cmake::Ok);
        let mut o = r.opts.clone();
        o.allow_downloads = false;
        let e = ps2_build::build_game(&r.ws, &o, &mut no_cb).unwrap_err();
        assert!(e.starts_with("NEEDS_DOWNLOAD_CONSENT"), "{e}");
        assert!(e.contains("raylib") && e.contains("MB"), "{e}");
        assert!(!r.t.path().join("cache").join("build-runtime").exists(), "nothing may start before consent");
    }
}

// ===========================================================================
// the pipeline with fake tools
// ===========================================================================

mod pipeline_tests {
    use super::*;

    #[test]
    fn full_build_installs_sources_compiles_and_packages() {
        let r = rig(Cmake::Ok);
        let mut stages: Vec<String> = vec![];
        let mut max_fraction = 0.0f64;
        let res = ps2_build::build_game(&r.ws, &r.opts, &mut |p| {
            if stages.last() != Some(&p.stage) {
                stages.push(p.stage.clone());
            }
            assert!(p.fraction + 1e-9 >= max_fraction, "progress must never go backwards: {} < {}", p.fraction, max_fraction);
            max_fraction = max_fraction.max(p.fraction);
            true
        })
        .unwrap();

        assert_eq!(
            stages,
            ["source", "recompile", "runtime-configure", "runtime-build", "package", "done"],
            "the recompiler build is skipped when one is supplied"
        );
        assert_eq!(max_fraction, 1.0);
        assert!(Path::new(&res.exe).is_file());
        assert_eq!(res.generated_sources, 2, "fn + register_functions");

        // generated sources landed where upstream reads them
        let src = r.opts.source_override.clone().unwrap();
        assert!(src.join("ps2xRuntime/src/runner/fn_0x100000.cpp").is_file());
        assert!(src.join("ps2xRuntime/include/ps2_recompiled_stubs.h").is_file());
        assert_eq!(
            std::fs::read_to_string(src.join("ps2xRuntime/include/ps2_recompiled_functions.h")).unwrap().trim(),
            "// h1",
            "the stale header from another game was replaced"
        );

        // packaged
        let pkg = res.package.expect("packaged");
        assert!(Path::new(&pkg.launcher).is_file());
        assert!(Path::new(&pkg.package_dir).join("game.exe").is_file());
        assert_eq!(pkg.dlls, ["fake-ffmpeg.dll"], "DLLs beside the built exe are bundled");
        assert!(pkg.complete);

        // log written, stage timings recorded
        assert!(Path::new(&res.log_path).is_file());
        let log = std::fs::read_to_string(&res.log_path).unwrap();
        assert!(log.contains("unity_1_cxx.cxx") && log.contains("Configuring done"), "{log}");
        assert!(res.stage_secs.iter().any(|(s, _)| s == "runtime-build"));
    }

    #[test]
    fn native_feel_flags_reach_cmake_only_when_requested() {
        let r = rig(Cmake::Ok);
        ps2_build::build_game(&r.ws, &r.opts, &mut no_cb).unwrap();
        let args = std::fs::read_to_string(r.cmake_dir.join("cmake-args.log")).unwrap();
        assert!(args.contains("-DPS2X_ENABLE_DEBUG_UI=OFF"), "{args}");
        assert!(args.contains("--target ps2EntryRunner"), "{args}");
        assert!(args.contains("-DPS2X_BUILD_RECOMP=OFF"), "{args}");

        let r2 = rig(Cmake::Ok);
        let mut o = r2.opts.clone();
        o.native_feel = false;
        ps2_build::build_game(&r2.ws, &o, &mut no_cb).unwrap();
        let args2 = std::fs::read_to_string(r2.cmake_dir.join("cmake-args.log")).unwrap();
        assert!(!args2.contains("DEBUG_UI"), "{args2}");
    }

    #[test]
    fn package_step_can_be_skipped() {
        let r = rig(Cmake::Ok);
        let mut o = r.opts.clone();
        o.package = false;
        let res = ps2_build::build_game(&r.ws, &o, &mut no_cb).unwrap();
        assert!(res.package.is_none());
        assert!(!r.ws.join("package").exists());
        assert!(Path::new(&res.exe).is_file());
    }

    #[test]
    fn a_compile_error_is_reported_with_its_output_and_nothing_is_packaged() {
        let r = rig(Cmake::FailBuild);
        let e = ps2_build::build_game(&r.ws, &r.opts, &mut no_cb).unwrap_err();
        assert!(e.contains("CMake build (runtime) failed"), "{e}");
        assert!(e.contains("boom.h"), "the compiler's own message must be shown: {e}");
        assert!(!r.ws.join("package").exists());
    }

    #[test]
    fn cancelling_stops_the_build_promptly_and_kills_the_child() {
        let r = rig(Cmake::Slow);
        let started = Instant::now();
        let mut in_build_since: Option<Instant> = None;
        let e = ps2_build::build_game(&r.ws, &r.opts, &mut |p| {
            if p.stage == "runtime-build" {
                let t = *in_build_since.get_or_insert_with(Instant::now);
                // cancel half a second into the (30 s) compile
                return t.elapsed() < Duration::from_millis(500);
            }
            true
        })
        .unwrap_err();
        assert!(e.to_lowercase().contains("cancel"), "{e}");
        assert!(started.elapsed() < Duration::from_secs(15), "took {:?}: the 30 s fake compile must have been killed", started.elapsed());
        assert!(!r.ws.join("package").exists());
    }

    #[test]
    fn a_missing_config_is_a_clear_error() {
        let r = rig(Cmake::Ok);
        std::fs::remove_file(r.ws.join("recomp").join("config.toml")).unwrap();
        let e = ps2_build::build_game(&r.ws, &r.opts, &mut no_cb).unwrap_err();
        assert!(e.contains("config.toml"), "{e}");
    }

    #[test]
    fn the_source_override_must_be_a_real_tree() {
        let r = rig(Cmake::Ok);
        let mut o = r.opts.clone();
        let empty = r.t.path().join("not-a-tree");
        std::fs::create_dir_all(&empty).unwrap();
        o.source_override = Some(empty);
        let e = ps2_build::build_game(&r.ws, &o, &mut no_cb).unwrap_err();
        assert!(e.contains("CMakeLists.txt"), "{e}");
    }

    #[test]
    fn rebuilding_for_another_game_reuses_the_cache_and_asks_for_no_downloads() {
        let r = rig(Cmake::Ok);
        ps2_build::build_game(&r.ws, &r.opts, &mut no_cb).unwrap();
        // the runtime is now "configured": a second build needs no consent
        let mut o = r.opts.clone();
        o.allow_downloads = false;
        let p = ps2_build::plan_build(&r.ws, &o).unwrap();
        assert!(p.downloads.is_empty(), "{:?}", p.downloads.iter().map(|d| &d.what).collect::<Vec<_>>());
        ps2_build::build_game(&r.ws, &o, &mut no_cb).expect("second build without consent");
    }
}

// ===========================================================================
// relative paths (`--out ./games`, `--cache ./cache`)
// ===========================================================================

mod relative_path_tests {
    use super::*;

    /// A scratch folder *inside* the current directory, so that a genuinely
    /// relative path to it exists (the system temp dir may be on another drive).
    struct CwdDir(PathBuf);
    impl CwdDir {
        fn new(tag: &str) -> Self {
            let p = PathBuf::from(format!("target/aura-rel-{tag}-{}", std::process::id()));
            std::fs::create_dir_all(&p).unwrap();
            CwdDir(p)
        }
    }
    impl Drop for CwdDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn iso_in(t: &TempDir) -> PathBuf {
        let iso = t.path().join("game.iso");
        std::fs::write(&iso, ps2_disc_with_filler(false, 0)).unwrap();
        iso
    }

    #[test]
    fn ingest_into_a_relative_folder_writes_absolute_config_paths() {
        let t = TempDir::new("rel-ingest");
        let scratch = CwdDir::new("ingest");
        let opts = IngestOptions {
            out_root: scratch.0.join("games").to_string_lossy().to_string(),
            mode: ExtractMode::All,
            recompiler: None,
        };
        assert!(!Path::new(&opts.out_root).is_absolute());
        let r = ps2_ingest::ingest_ps2(iso_in(&t).to_str().unwrap(), &opts, &mut |_| true).unwrap();
        assert!(Path::new(&r.workspace).is_absolute(), "{}", r.workspace);

        let cfg = std::fs::read_to_string(&r.config_toml).unwrap();
        for key in ["input", "output", "ghidra_output"] {
            let line = cfg.lines().find(|l| l.starts_with(&format!("{key} = "))).unwrap_or_else(|| panic!("{key} missing"));
            let value = line.split('"').nth(1).unwrap();
            assert!(Path::new(value).is_absolute(), "{key} = {value} would not resolve from the recompiler's directory");
        }
    }

    #[test]
    fn build_with_a_relative_workspace_and_cache_hands_absolute_paths_to_the_tools() {
        let t = TempDir::new("rel-build");
        let scratch = CwdDir::new("build");
        let tools = t.path().join("tools");
        std::fs::create_dir_all(&tools).unwrap();

        // Records the config path it was given, then behaves like the fake recompiler.
        let recorder = script(
            &tools,
            "ps2_recomp",
            "@echo off\necho %1> \"%~dp0config-arg.log\"\nif not exist generated mkdir generated\necho // fn> generated\\fn_0x100000.cpp\necho // reg> generated\\register_functions.cpp\necho // h1> generated\\ps2_recompiled_functions.h\necho // h2> generated\\ps2_recompiled_stubs.h\nexit /b 0\n",
            "echo \"$1\" > \"$(dirname \"$0\")/config-arg.log\"\nmkdir -p generated\necho '// fn' > generated/fn_0x100000.cpp\necho '// reg' > generated/register_functions.cpp\necho '// h1' > generated/ps2_recompiled_functions.h\necho '// h2' > generated/ps2_recompiled_stubs.h\nexit 0\n",
        );
        let git = tools.join("git");
        std::fs::write(&git, b"x").unwrap();
        let launcher = t.path().join("aura-launch.exe");
        std::fs::write(&launcher, b"MZ launcher").unwrap();

        let ingest = IngestOptions {
            out_root: scratch.0.join("games").to_string_lossy().to_string(),
            mode: ExtractMode::All,
            recompiler: None,
        };
        let ing = ps2_ingest::ingest_ps2(iso_in(&t).to_str().unwrap(), &ingest, &mut |_| true).unwrap();
        let serial_dir = Path::new(&ing.workspace).file_name().unwrap().to_owned();

        // The caller's view: both paths relative to the current directory.
        let rel_ws = scratch.0.join("games").join(serial_dir);
        let rel_cache = scratch.0.join("cache");
        assert!(rel_ws.is_relative() && rel_cache.is_relative());

        let opts = BuildOptions {
            cache_dir: Some(rel_cache),
            allow_downloads: true,
            package: false,
            native_feel: true,
            fast_release: false,
        lean_indirect_calls: false,
            jobs: Some(2),
            cmake: Some(fake_cmake(&tools, Cmake::Ok)),
            git: Some(git),
            source_override: Some(fake_source(t.path())),
            recompiler: Some(recorder),
            launcher_exe: Some(launcher),
            skip_compiler_check: true,
        };
        let res = ps2_build::build_game(&rel_ws, &opts, &mut no_cb).unwrap();
        assert!(Path::new(&res.exe).is_file());

        let seen = std::fs::read_to_string(tools.join("config-arg.log")).unwrap();
        let seen = seen.trim().trim_matches('"');
        assert!(Path::new(seen).is_absolute(), "ps2_recomp was given {seen:?}");
        assert!(res.cache_dir.contains("aura-rel-build") && Path::new(&res.cache_dir).is_absolute(), "{}", res.cache_dir);
    }
}
