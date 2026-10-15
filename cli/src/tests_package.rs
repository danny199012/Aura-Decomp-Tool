//! Tests for game packaging (`ps2_package`) and the launcher core
//! (`launcher_core`). Workspaces are produced by the real ingest pipeline from
//! synthetic discs; the "runtime" is a throwaway script/file, so nothing here
//! needs a compiler or a game.

use crate::launcher_core;
use crate::ps2_ingest::{self, ExtractMode, IngestOptions};
use crate::ps2_package::{self, PackageOptions};
use crate::tests_disc::{build_iso, ps2_disc_with_filler, ps2_elf, Node, TempDir};
use std::path::{Path, PathBuf};

/// Run the real ingest on a synthetic disc and return the workspace path.
fn make_workspace(t: &TempDir, mode: ExtractMode, filler: usize) -> PathBuf {
    let iso = t.path().join("game.iso");
    std::fs::write(&iso, ps2_disc_with_filler(false, filler)).unwrap();
    let opts = IngestOptions {
        out_root: t.path().join("games").to_string_lossy().to_string(),
        mode,
        recompiler: None,
    };
    let res = ps2_ingest::ingest_ps2(iso.to_str().unwrap(), &opts, &mut |_| true).unwrap();
    PathBuf::from(res.workspace)
}

/// A stand-in for the built runtime: a file, with DLL neighbours.
fn fake_runtime(dir: &Path) -> PathBuf {
    std::fs::create_dir_all(dir).unwrap();
    let exe = dir.join("ps2EntryRunner.exe");
    std::fs::write(&exe, b"MZ fake runtime").unwrap();
    std::fs::write(dir.join("avcodec-61.dll"), b"dll1").unwrap();
    std::fs::write(dir.join("avformat-61.dll"), b"dll2").unwrap();
    std::fs::write(dir.join("notes.txt"), b"not a dll").unwrap();
    exe
}

fn no_progress(_: &ps2_package::PackageProgress) -> bool {
    true
}

// ===========================================================================
// pure helpers
// ===========================================================================

mod helper_tests {
    use super::*;

    #[test]
    fn cmd_safe_accepts_normal_names_and_rejects_cmd_metacharacters() {
        for ok in ["SLUS_203.12", "Play The Urbz", "Game (USA) [v1.1]", "a-b_c.d"] {
            assert!(ps2_package::cmd_safe(ok), "{ok}");
        }
        for bad in ["", "50%", "a&b", "a^b", "a|b", "a<b", "a>b", "boom!", "say \"hi\"", "x;y"] {
            assert!(!ps2_package::cmd_safe(bad), "{bad}");
        }
    }

    #[test]
    fn cmd_launcher_uses_relative_paths_and_logs() {
        let s = ps2_package::render_cmd_launcher("TEST GAME", "disc/SLUS_203.12");
        assert!(s.contains("cd /d \"%~dp0\""));
        assert!(s.contains("\"%~dp0game.exe\" \"%~dp0disc\\SLUS_203.12\""));
        assert!(s.contains("aura-last-run.log"));
        assert!(s.contains("\r\n"), "batch files need CRLF");
        assert!(!s.contains("C:\\"), "must not embed an absolute path: {s}");
    }

    #[test]
    fn resolve_inside_blocks_escapes() {
        let d = Path::new("pkg");
        assert!(launcher_core::resolve_inside(d, "disc/SLUS_203.12").is_ok());
        assert!(launcher_core::resolve_inside(d, "./game.exe").is_ok());
        for bad in ["../evil.exe", "disc/../../x", "/etc/passwd", "\\\\server\\share\\x", "C:\\Windows\\x.exe", "", "  "] {
            assert!(launcher_core::resolve_inside(d, bad).is_err(), "{bad:?} must be refused");
        }
    }

    #[test]
    fn exit_codes_are_readable() {
        assert_eq!(launcher_core::describe_exit(Some(0)), "0");
        assert_eq!(launcher_core::describe_exit(Some(3)), "3");
        assert_eq!(launcher_core::describe_exit(Some(-1073741819)), "0xC0000005");
        assert!(launcher_core::describe_exit(None).contains("unknown"));
    }
}

// ===========================================================================
// package_game
// ===========================================================================

mod package_tests {
    use super::*;

    #[test]
    fn packages_a_complete_game_folder() {
        let t = TempDir::new("pkg-ok");
        let ws = make_workspace(&t, ExtractMode::All, 0);
        let exe = fake_runtime(&t.path().join("build"));
        let launcher = t.path().join("aura-launch.exe");
        std::fs::write(&launcher, b"MZ launcher").unwrap();

        let opts = PackageOptions { launcher_exe: Some(launcher), ..Default::default() };
        let r = ps2_package::package_game(&ws, &exe, &opts, &mut no_progress).unwrap();

        let pkg = PathBuf::from(&r.package_dir);
        assert!(r.complete && r.extract_mode == "all");
        assert_eq!(pkg, ws.join("package"));
        assert_eq!(std::fs::read(pkg.join("game.exe")).unwrap(), b"MZ fake runtime");
        assert_eq!(r.dlls, ["avcodec-61.dll", "avformat-61.dll"], "only DLLs beside the exe are bundled");
        assert!(!pkg.join("notes.txt").exists());
        assert!(pkg.join("mc0").is_dir());
        assert_eq!(r.boot_elf, "disc/SLUS_203.12");
        assert_eq!(std::fs::read(pkg.join("disc").join("SLUS_203.12")).unwrap(), ps2_elf(false));
        assert_eq!(r.disc_files, 5);
        assert!(pkg.join("disc").join("DATA").join("BIG.DAT").is_file());
        assert!(pkg.join("README.txt").is_file());

        assert_eq!(r.launcher_kind, "exe");
        assert!(r.launcher.ends_with("Play TEST GAME.exe"), "{}", r.launcher);
        assert_eq!(std::fs::read(&r.launcher).unwrap(), b"MZ launcher");
        let cmd = std::fs::read_to_string(r.cmd_launcher.as_ref().unwrap()).unwrap();
        assert!(cmd.contains("disc\\SLUS_203.12"));

        // launch.json is what the launcher consumes and must round-trip.
        let cfg = launcher_core::read_config(&pkg).unwrap();
        assert_eq!(cfg.exe, "game.exe");
        assert_eq!(cfg.boot_elf, "disc/SLUS_203.12");
        assert!(!cfg.show_console);
        assert!(launcher_core::resolve_inside(&pkg, &cfg.boot_elf).unwrap().is_file());
    }

    #[test]
    fn executables_only_workspace_is_flagged_incomplete() {
        let t = TempDir::new("pkg-partial");
        let ws = make_workspace(&t, ExtractMode::Executables, 0);
        let exe = fake_runtime(&t.path().join("build"));
        let r = ps2_package::package_game(&ws, &exe, &PackageOptions::default(), &mut no_progress).unwrap();
        assert!(!r.complete);
        assert_eq!(r.extract_mode, "executables");
        assert!(r.warnings.iter().any(|w| w.to_lowercase().contains("entire disc")), "{:?}", r.warnings);
        let readme = std::fs::read_to_string(Path::new(&r.package_dir).join("README.txt")).unwrap();
        assert!(readme.contains("WARNING"));
        assert!(!Path::new(&r.package_dir).join("disc").join("DATA").exists());
    }

    #[test]
    fn refuses_when_the_boot_elf_is_missing_from_disc() {
        let t = TempDir::new("pkg-noboot");
        let ws = make_workspace(&t, ExtractMode::All, 0);
        std::fs::remove_file(ws.join("disc").join("SLUS_203.12")).unwrap();
        let exe = fake_runtime(&t.path().join("build"));
        let err = ps2_package::package_game(&ws, &exe, &PackageOptions::default(), &mut no_progress).unwrap_err();
        assert!(err.contains("boot file") && err.contains("SLUS_203.12"), "{err}");
        assert!(!ws.join("package").join("game.exe").exists(), "nothing may be half-written before the check");
    }

    #[test]
    fn refuses_a_missing_runtime_and_a_non_workspace() {
        let t = TempDir::new("pkg-bad");
        let ws = make_workspace(&t, ExtractMode::All, 0);
        let e = ps2_package::package_game(&ws, &t.path().join("nope.exe"), &PackageOptions::default(), &mut no_progress)
            .unwrap_err();
        assert!(e.contains("not found"), "{e}");

        let empty = t.path().join("empty");
        std::fs::create_dir_all(&empty).unwrap();
        let exe = fake_runtime(&t.path().join("build"));
        let e = ps2_package::package_game(&empty, &exe, &PackageOptions::default(), &mut no_progress).unwrap_err();
        assert!(e.contains("game.json"), "{e}");
    }

    #[test]
    fn repackaging_is_idempotent_and_replaces_stale_files() {
        let t = TempDir::new("pkg-twice");
        let ws = make_workspace(&t, ExtractMode::All, 0);
        let exe = fake_runtime(&t.path().join("build"));
        let a = ps2_package::package_game(&ws, &exe, &PackageOptions::default(), &mut no_progress).unwrap();
        std::fs::write(&exe, b"MZ rebuilt runtime v2").unwrap();
        let b = ps2_package::package_game(&ws, &exe, &PackageOptions::default(), &mut no_progress).unwrap();
        assert_eq!(a.package_dir, b.package_dir);
        assert_eq!(std::fs::read(Path::new(&b.game_exe)).unwrap(), b"MZ rebuilt runtime v2");
        assert_eq!(a.disc_files, b.disc_files);
    }

    #[test]
    fn copy_mode_produces_independent_files_and_link_mode_shares_data() {
        let t = TempDir::new("pkg-linkcopy");
        let ws = make_workspace(&t, ExtractMode::All, 0);
        let exe = fake_runtime(&t.path().join("build"));

        let copy_opts = PackageOptions { prefer_links: false, out_dir: Some(t.path().join("p-copy")), ..Default::default() };
        let c = ps2_package::package_game(&ws, &exe, &copy_opts, &mut no_progress).unwrap();
        assert_eq!(c.disc_method, "copy");
        // Mutating the source must not leak into an independent copy.
        let src = ws.join("disc").join("DATA").join("MOVIE.PSS");
        let before = std::fs::read(&src).unwrap();
        std::fs::write(&src, vec![0x11u8; before.len()]).unwrap();
        assert_eq!(std::fs::read(Path::new(&c.package_dir).join("disc/DATA/MOVIE.PSS")).unwrap(), before);
        std::fs::write(&src, &before).unwrap();

        let link_opts = PackageOptions { prefer_links: true, out_dir: Some(t.path().join("p-link")), ..Default::default() };
        let l = ps2_package::package_game(&ws, &exe, &link_opts, &mut no_progress).unwrap();
        // Same volume here, so linking must work; the data is then shared.
        assert_eq!(l.disc_method, "hardlink", "hard links should succeed within one temp volume");
        std::fs::write(&src, vec![0x22u8; before.len()]).unwrap();
        assert_eq!(
            std::fs::read(Path::new(&l.package_dir).join("disc/DATA/MOVIE.PSS")).unwrap(),
            vec![0x22u8; before.len()],
            "a hard-linked file shares storage with its source"
        );
    }

    #[test]
    fn progress_is_reported_and_cancellable() {
        let t = TempDir::new("pkg-progress");
        let ws = make_workspace(&t, ExtractMode::All, 400);
        let exe = fake_runtime(&t.path().join("build"));
        let opts = PackageOptions { prefer_links: false, ..Default::default() };
        let mut calls = 0;
        let mut last = ps2_package::PackageProgress::default();
        let r = ps2_package::package_game(&ws, &exe, &opts, &mut |p| {
            calls += 1;
            last = p.clone();
            true
        })
        .unwrap();
        assert!(calls >= 2, "{calls}");
        assert_eq!(last.files_total, r.disc_files);
        assert_eq!(last.files_done, r.disc_files);
        assert_eq!(last.bytes_done, last.bytes_total);

        // Cancel from the very first callback: nothing gets copied.
        let t2 = TempDir::new("pkg-cancel");
        let ws2 = make_workspace(&t2, ExtractMode::All, 50);
        let exe2 = fake_runtime(&t2.path().join("build"));
        let err = ps2_package::package_game(&ws2, &exe2, &PackageOptions::default(), &mut |_| false).unwrap_err();
        assert!(err.to_lowercase().contains("cancel"), "{err}");
    }

    #[test]
    fn unsafe_disc_names_skip_the_cmd_launcher_but_keep_the_exe_launcher() {
        // Build a workspace by hand with a boot ELF whose name has cmd metacharacters.
        let t = TempDir::new("pkg-unsafe");
        let ws = t.path().join("ws");
        std::fs::create_dir_all(ws.join("disc")).unwrap();
        std::fs::write(ws.join("disc").join("A&B.ELF"), ps2_elf(false)).unwrap();
        std::fs::write(
            ws.join("game.json"),
            r#"{"display_name":"Odd Game","boot_file":"A&B.ELF","extract_mode":"all","serial":null}"#,
        )
        .unwrap();
        let exe = fake_runtime(&t.path().join("build"));
        let launcher = t.path().join("aura-launch.exe");
        std::fs::write(&launcher, b"MZ").unwrap();
        let opts = PackageOptions { launcher_exe: Some(launcher), ..Default::default() };
        let r = ps2_package::package_game(&ws, &exe, &opts, &mut no_progress).unwrap();
        assert!(r.cmd_launcher.is_none());
        assert_eq!(r.launcher_kind, "exe");
        assert!(r.warnings.iter().any(|w| w.contains("cmd.exe")));
    }

    #[test]
    fn no_launcher_at_all_is_an_error_not_a_silent_dud() {
        let t = TempDir::new("pkg-nolauncher");
        let ws = t.path().join("ws");
        std::fs::create_dir_all(ws.join("disc")).unwrap();
        std::fs::write(ws.join("disc").join("A&B.ELF"), ps2_elf(false)).unwrap();
        std::fs::write(ws.join("game.json"), r#"{"display_name":"Odd","boot_file":"A&B.ELF","extract_mode":"all"}"#).unwrap();
        let exe = fake_runtime(&t.path().join("build"));
        // An explicit launcher path that does not exist => find_launcher says None.
        let opts = PackageOptions { launcher_exe: Some(t.path().join("missing.exe")), ..Default::default() };
        let err = ps2_package::package_game(&ws, &exe, &opts, &mut no_progress).unwrap_err();
        assert!(err.contains("No launcher"), "{err}");
    }

    #[test]
    fn package_folder_may_not_live_inside_the_disc_tree() {
        let t = TempDir::new("pkg-inside");
        let ws = make_workspace(&t, ExtractMode::All, 0);
        let exe = fake_runtime(&t.path().join("build"));
        let opts = PackageOptions { out_dir: Some(ws.join("disc").join("pkg")), ..Default::default() };
        let err = ps2_package::package_game(&ws, &exe, &opts, &mut no_progress).unwrap_err();
        assert!(err.contains("inside the disc"), "{err}");
    }

    /// Regression for a data-loss bug: re-packaging with the package's own
    /// game.exe (or its DLLs) as the source used to delete the source first.
    #[test]
    fn repackaging_from_the_package_itself_does_not_destroy_the_exe_or_dlls() {
        let t = TempDir::new("pkg-self");
        let ws = make_workspace(&t, ExtractMode::All, 0);
        let exe = fake_runtime(&t.path().join("build"));
        let first = ps2_package::package_game(&ws, &exe, &PackageOptions::default(), &mut no_progress).unwrap();
        let again_exe = PathBuf::from(&first.game_exe);
        let r = ps2_package::package_game(&ws, &again_exe, &PackageOptions::default(), &mut no_progress).unwrap();
        assert_eq!(std::fs::read(&r.game_exe).unwrap(), b"MZ fake runtime", "game.exe must survive");
        assert_eq!(std::fs::read(Path::new(&r.package_dir).join("avcodec-61.dll")).unwrap(), b"dll1");
        assert_eq!(r.dlls, ["avcodec-61.dll", "avformat-61.dll"]);
    }

    /// Regression for a data-loss bug: `--out <workspace>` made the disc tree
    /// "replace itself", deleting every extracted file.
    #[test]
    fn packaging_into_the_workspace_itself_keeps_the_disc_data() {
        let t = TempDir::new("pkg-inplace");
        let ws = make_workspace(&t, ExtractMode::All, 0);
        let exe = fake_runtime(&t.path().join("build"));
        let big = ws.join("disc").join("DATA").join("BIG.DAT");
        let before = std::fs::read(&big).unwrap();
        let opts = PackageOptions { out_dir: Some(ws.clone()), ..Default::default() };
        let r = ps2_package::package_game(&ws, &exe, &opts, &mut no_progress).unwrap();
        assert_eq!(r.disc_method, "in-place");
        assert_eq!(r.disc_files, 5);
        assert_eq!(std::fs::read(&big).unwrap(), before, "disc data must be untouched");
        assert!(ws.join("disc").join("SLUS_203.12").is_file());
        assert!(ws.join("game.exe").is_file() && ws.join("launch.json").is_file());
    }

    #[test]
    fn boot_file_is_located_case_insensitively_in_subdirectories() {
        let t = TempDir::new("pkg-case");
        let root = vec![
            ("SYSTEM.CNF".to_string(), Node::File(b"BOOT2 = cdrom0:\\Main\\Game.Elf;1\r\n".to_vec())),
            ("MAIN".to_string(), Node::Dir(vec![("GAME.ELF".to_string(), Node::File(ps2_elf(false)))])),
        ];
        let iso = t.path().join("g.iso");
        std::fs::write(&iso, build_iso("CASE_TEST", &root)).unwrap();
        let opts = IngestOptions { out_root: t.path().join("g").to_string_lossy().to_string(), mode: ExtractMode::All, recompiler: None };
        let res = ps2_ingest::ingest_ps2(iso.to_str().unwrap(), &opts, &mut |_| true).unwrap();
        let exe = fake_runtime(&t.path().join("build"));
        let r = ps2_package::package_game(Path::new(&res.workspace), &exe, &PackageOptions::default(), &mut no_progress).unwrap();
        assert_eq!(r.boot_elf, "disc/MAIN/GAME.ELF");
    }
}

// ===========================================================================
// launcher_core::run — executes a real child process
// ===========================================================================

mod launcher_run_tests {
    use super::*;

    /// A fake game: records its cwd and arguments into a file, then exits `code`.
    fn fake_game(dir: &Path, code: i32) -> &'static str {
        #[cfg(windows)]
        {
            let body = format!("@echo off\r\ncd > cwd.txt\r\necho %1 > args.txt\r\necho hello from the game\r\nexit /b {code}\r\n");
            std::fs::write(dir.join("game.cmd"), body).unwrap();
            "game.cmd"
        }
        #[cfg(not(windows))]
        {
            use std::os::unix::fs::PermissionsExt;
            let body = format!("#!/bin/sh\npwd > cwd.txt\necho \"$1\" > args.txt\necho hello from the game\nexit {code}\n");
            let p = dir.join("game.sh");
            std::fs::write(&p, body).unwrap();
            let mut perm = std::fs::metadata(&p).unwrap().permissions();
            perm.set_mode(0o755);
            std::fs::set_permissions(&p, perm).unwrap();
            "game.sh"
        }
    }

    fn write_launch(dir: &Path, exe: &str) {
        std::fs::create_dir_all(dir.join("disc")).unwrap();
        std::fs::write(dir.join("disc").join("BOOT.ELF"), b"elf").unwrap();
        std::fs::write(
            dir.join("launch.json"),
            format!(r#"{{"exe":"{exe}","boot_elf":"disc/BOOT.ELF","log":"aura-last-run.log","game":"Test"}}"#),
        )
        .unwrap();
    }

    #[test]
    fn runs_the_game_in_its_folder_with_an_absolute_elf_argument_and_logs() {
        let t = TempDir::new("launch-ok");
        let exe = fake_game(t.path(), 0);
        write_launch(t.path(), exe);
        let o = launcher_core::run(t.path()).unwrap();
        assert_eq!(o.exit_code, Some(0));
        let args = std::fs::read_to_string(t.path().join("args.txt")).unwrap();
        assert!(args.contains("BOOT.ELF"), "{args}");
        assert!(Path::new(args.trim().trim_matches('"')).is_absolute(), "argv[1] must be absolute: {args}");
        let cwd = std::fs::read_to_string(t.path().join("cwd.txt")).unwrap();
        let leaf = t.path().file_name().unwrap().to_string_lossy().to_lowercase();
        assert!(cwd.trim().to_lowercase().ends_with(&leaf), "{cwd}");
        let log = std::fs::read_to_string(t.path().join("aura-last-run.log")).unwrap();
        assert!(log.contains("hello from the game"));
        assert!(o.log_tail.iter().any(|l| l.contains("hello")));
    }

    #[test]
    fn nonzero_exit_is_reported_with_the_log_tail() {
        let t = TempDir::new("launch-fail");
        let exe = fake_game(t.path(), 7);
        write_launch(t.path(), exe);
        let o = launcher_core::run(t.path()).unwrap();
        assert_eq!(o.exit_code, Some(7));
        assert!(!o.log_tail.is_empty());
    }

    #[test]
    fn missing_pieces_give_clear_errors() {
        let t = TempDir::new("launch-missing");
        assert!(launcher_core::run(t.path()).unwrap_err().contains("launch.json"));
        write_launch(t.path(), "game.exe");
        assert!(launcher_core::run(t.path()).unwrap_err().contains("executable is missing"));
        let exe = fake_game(t.path(), 0);
        write_launch(t.path(), exe);
        std::fs::remove_file(t.path().join("disc").join("BOOT.ELF")).unwrap();
        assert!(launcher_core::run(t.path()).unwrap_err().contains("boot file is missing"));
    }

    #[test]
    fn launch_json_cannot_point_outside_the_folder() {
        let t = TempDir::new("launch-escape");
        std::fs::write(t.path().join("launch.json"), r#"{"exe":"../evil.exe","boot_elf":"disc/x"}"#).unwrap();
        let e = launcher_core::run(t.path()).unwrap_err();
        assert!(e.contains("may not leave"), "{e}");
    }
}

// ===========================================================================
// launcher_core — a runtime that logs a fatal error but exits 0
// ===========================================================================

mod early_failure_tests {
    use super::*;

    fn game_printing(dir: &Path, line: &str, code: i32) -> &'static str {
        #[cfg(windows)]
        {
            let body = format!("@echo off\r\necho {line}\r\nexit /b {code}\r\n");
            std::fs::write(dir.join("game.cmd"), body).unwrap();
            "game.cmd"
        }
        #[cfg(not(windows))]
        {
            use std::os::unix::fs::PermissionsExt;
            let body = format!("#!/bin/sh\necho '{line}'\nexit {code}\n");
            let p = dir.join("game.sh");
            std::fs::write(&p, body).unwrap();
            let mut perm = std::fs::metadata(&p).unwrap().permissions();
            perm.set_mode(0o755);
            std::fs::set_permissions(&p, perm).unwrap();
            "game.sh"
        }
    }

    fn write_launch(dir: &Path, exe: &str) {
        std::fs::create_dir_all(dir.join("disc")).unwrap();
        std::fs::write(dir.join("disc").join("BOOT.ELF"), b"elf").unwrap();
        std::fs::write(
            dir.join("launch.json"),
            format!(r#"{{"exe":"{exe}","boot_elf":"disc/BOOT.ELF","game":"T"}}"#),
        )
        .unwrap();
    }

    #[test]
    fn find_failure_line_recognises_the_runtimes_own_fatal_messages() {
        let log = "INFO: all fine\n[SetupHeap] base=0x1\nError during program execution: Unimplemented PS2 stub called: sceSdTransToIOP\nINFO: exiting";
        assert_eq!(
            launcher_core::find_failure_line(log).as_deref(),
            Some("Error during program execution: Unimplemented PS2 stub called: sceSdTransToIOP")
        );
        assert!(launcher_core::find_failure_line("[main] fatal exception: boom").is_some());
        assert!(launcher_core::find_failure_line("Failed to load ELF file: x").is_some());
    }

    #[test]
    fn ordinary_log_lines_do_not_look_like_failures() {
        let log = "INFO: Device initialized\nLoading segment: 0x100000\n[run:tick] tick=120 pc=0x12c7f8\nERROR is a word in a texture name";
        assert!(launcher_core::find_failure_line(log).is_none());
    }

    #[test]
    fn exit_zero_with_a_fatal_log_line_is_reported_as_an_early_failure() {
        let t = TempDir::new("early-fail");
        let exe = game_printing(t.path(), "Error during program execution: Unimplemented PS2 stub called: sceSdTransToIOP", 0);
        write_launch(t.path(), exe);
        let o = launcher_core::run(t.path()).unwrap();
        assert_eq!(o.exit_code, Some(0));
        let f = o.early_failure.expect("must be flagged");
        assert!(f.contains("sceSdTransToIOP"), "{f}");
        assert!(o.elapsed < launcher_core::EARLY_EXIT);
    }

    #[test]
    fn clean_exit_zero_is_not_flagged() {
        let t = TempDir::new("clean-exit");
        let exe = game_printing(t.path(), "INFO: closed by the user", 0);
        write_launch(t.path(), exe);
        let o = launcher_core::run(t.path()).unwrap();
        assert_eq!(o.exit_code, Some(0));
        assert!(o.early_failure.is_none());
    }

    #[test]
    fn nonzero_exit_is_not_double_reported_as_early_failure() {
        let t = TempDir::new("nonzero");
        let exe = game_printing(t.path(), "Error during program execution: boom", 5);
        write_launch(t.path(), exe);
        let o = launcher_core::run(t.path()).unwrap();
        assert_eq!(o.exit_code, Some(5));
        assert!(o.early_failure.is_none(), "the non-zero exit code already carries the failure");
    }
}

mod explain_tests {
    use super::*;
    use std::time::Duration;

    // The line from a real run of the one-click-built homebrew game.
    const REAL: &str = "Warning: Unimplemented PS2 stub called. name=sceSdTransToIOP PC=0x102d44, RA=0x102d44, Stub# guess (from $v0)=0x0";

    #[test]
    fn stub_name_is_read_from_the_runtimes_warning() {
        assert_eq!(launcher_core::stub_name(REAL), Some("sceSdTransToIOP"));
        assert_eq!(launcher_core::stub_name("Warning: name= PC=0x1"), None);
        assert_eq!(launcher_core::stub_name("no such field"), None);
        assert_eq!(launcher_core::stub_name("name=sceCdRead"), Some("sceCdRead"), "name at end of line");
    }

    #[test]
    fn an_unimplemented_stub_is_explained_in_plain_words() {
        let msg = launcher_core::explain_early_failure(
            Duration::from_millis(1200),
            REAL,
            Some(Path::new("C:/g/aura-last-run.log")),
        );
        assert!(msg.starts_with("The game stopped 1 second after starting."), "{msg}");
        assert!(msg.contains("sceSdTransToIOP (sound)"), "{msg}");
        assert!(msg.contains("not a problem with your game files"), "{msg}");
        assert!(!msg.contains("PC=0x") && !msg.contains("Stub# guess"), "register noise stays in the log: {msg}");
        assert!(msg.ends_with("Full log: C:/g/aura-last-run.log"), "{msg}");
    }

    #[test]
    fn durations_are_worded_not_pluralised_wrongly() {
        let say = |ms| launcher_core::explain_early_failure(Duration::from_millis(ms), "Error during program execution: x", None);
        assert!(say(200).starts_with("The game stopped less than a second after starting."));
        assert!(say(1000).starts_with("The game stopped 1 second after"));
        assert!(say(7400).starts_with("The game stopped 7 seconds after"));
    }

    #[test]
    fn other_failures_quote_the_runtimes_own_line() {
        let msg = launcher_core::explain_early_failure(
            Duration::from_secs(3),
            "Error during program execution: bad opcode at 0x100",
            None,
        );
        assert!(msg.contains("Error during program execution: bad opcode at 0x100"), "{msg}");
        assert!(!msg.contains("Full log"), "no log, no log line: {msg}");
    }

    #[test]
    fn an_unrecognised_function_still_gets_the_explanation() {
        let msg = launcher_core::explain_early_failure(
            Duration::from_secs(2),
            "Warning: Unimplemented PS2 stub called. name=sceFooBar PC=0x1",
            None,
        );
        assert!(msg.contains("sceFooBar."), "no area in parentheses when unknown: {msg}");
    }
}
