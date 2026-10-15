//! Tests for `ps1_patches`: the title-specific `game.toml` additions (pure
//! text), and applying framework patches to a pinned commit (real `git` in a
//! scratch repository; those tests skip themselves when git is not installed).

use crate::ps1_patches::{self as pp, ConfigAddition, FrameworkPatch};
use crate::tests_disc::TempDir;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

// ---------------------------------------------------------------------------
// Config additions
// ---------------------------------------------------------------------------

const HP: &str = "[game]\nname = \"Harry Potter and the Sorcerer's Stone\"\nid = \"SLUS-01415\"\nplayers = 2\n\n\
[runtime]\nwindow_title = \"Harry Potter and the Sorcerer's Stone Recompiled\"\nmemcard_dir = \"saves\"\noverlay_cache = true\n\n\
[video]\nrenderer = \"opengl\"\n";

fn adds(serial: &str) -> Vec<&'static ConfigAddition> {
    pp::additions_for(serial)
}

#[test]
fn additions_match_the_serial_however_it_is_written() {
    for s in ["SLUS-01415", "slus-01415", "SLUS_014.15", "SLUS01415", " SLUS-01415 "] {
        assert_eq!(adds(s).len(), 1, "{s}");
    }
    assert!(adds("SLUS-00561").is_empty());
    assert!(adds("").is_empty());
    assert!(adds("---").is_empty());
}

#[test]
fn a_missing_key_is_added_at_the_end_of_its_table() {
    let (out, changes) = pp::merge_additions(HP, &adds("SLUS-01415"));
    assert_eq!(changes.len(), 1, "{changes:?}");
    assert!(
        out.contains("overlay_cache = true\noverlay_native_block = [\"0x00010CDC\"]\n\n[video]"),
        "{out}"
    );
    // Nothing else moved.
    assert!(out.starts_with("[game]\nname = "));
    assert!(out.ends_with("[video]\nrenderer = \"opengl\"\n"));
}

#[test]
fn merging_twice_changes_nothing_the_second_time() {
    let (once, c1) = pp::merge_additions(HP, &adds("SLUS-01415"));
    assert!(!c1.is_empty());
    let (twice, c2) = pp::merge_additions(&once, &adds("SLUS-01415"));
    assert!(c2.is_empty(), "{c2:?}");
    assert_eq!(twice, once);
}

#[test]
fn an_existing_list_is_extended_not_replaced() {
    let t = "[runtime]\noverlay_native_block = [\"0x80020000\"]  # mine\nmemcard_dir = \"saves\"\n";
    let (out, c) = pp::merge_additions(t, &adds("SLUS-01415"));
    assert_eq!(c.len(), 1);
    assert!(out.contains("overlay_native_block = [\"0x80020000\", \"0x00010CDC\"]\nmemcard_dir"), "{out}");
}

#[test]
fn an_address_already_listed_in_another_spelling_is_recognised() {
    for spelling in ["0x10cdc", "0x00010cdc", "0X00010CDC"] {
        let t = format!("[runtime]\noverlay_native_block = [\"{spelling}\"]\n");
        let (out, c) = pp::merge_additions(&t, &adds("SLUS-01415"));
        assert!(c.is_empty(), "{spelling}: {c:?}");
        assert_eq!(out, t);
    }
}

#[test]
fn a_list_spread_over_several_lines_is_read_and_collapsed() {
    let t = "[runtime]\noverlay_native_block = [\n  \"0x80020000\",\n  \"0x80030000\", # two\n]\noverlay_cache = true\n";
    let (out, c) = pp::merge_additions(t, &adds("SLUS-01415"));
    assert_eq!(c.len(), 1);
    assert!(
        out.contains("overlay_native_block = [\"0x80020000\", \"0x80030000\", \"0x00010CDC\"]\noverlay_cache = true"),
        "{out}"
    );
}

#[test]
fn a_missing_table_is_appended() {
    let t = "[game]\nid = \"SLUS-01415\"\n";
    let (out, c) = pp::merge_additions(t, &adds("SLUS-01415"));
    assert_eq!(c.len(), 1);
    assert_eq!(out, "[game]\nid = \"SLUS-01415\"\n\n[runtime]\noverlay_native_block = [\"0x00010CDC\"]\n");
}

#[test]
fn a_value_that_is_not_a_list_is_left_alone() {
    let t = "[runtime]\noverlay_native_block = \"none\"\n";
    let (out, c) = pp::merge_additions(t, &adds("SLUS-01415"));
    assert!(c.is_empty());
    assert_eq!(out, t);
}

#[test]
fn line_endings_are_kept() {
    let crlf = HP.replace('\n', "\r\n");
    let (out, c) = pp::merge_additions(&crlf, &adds("SLUS-01415"));
    assert_eq!(c.len(), 1);
    assert!(out.contains("overlay_cache = true\r\noverlay_native_block = [\"0x00010CDC\"]\r\n"), "{out:?}");
    assert!(!out.replace("\r\n", "").contains('\n'), "no bare LF may appear");
}

#[test]
fn the_same_key_in_another_table_is_not_confused_with_ours() {
    let t = "[other]\noverlay_native_block = [\"0x1\"]\n\n[runtime]\nmemcard_dir = \"saves\"\n";
    let (out, c) = pp::merge_additions(t, &adds("SLUS-01415"));
    assert_eq!(c.len(), 1);
    assert!(out.contains("[other]\noverlay_native_block = [\"0x1\"]"));
    assert!(out.contains("[runtime]\nmemcard_dir = \"saves\"\noverlay_native_block = [\"0x00010CDC\"]"), "{out}");
}

fn package(dir: &Path, game_toml: &str) {
    fs::write(dir.join("game.exe"), b"MZ").unwrap();
    fs::write(dir.join("aura-package.json"), r#"{"aura_package":1,"platform":"PS1","exe":"game.exe","title":"T"}"#).unwrap();
    fs::write(dir.join("game.toml"), game_toml).unwrap();
}

#[test]
fn a_built_package_is_fixed_once_and_its_original_kept() {
    let t = TempDir::new("pp-pkg");
    package(t.path(), HP);
    let r = pp::fix_package(t.path()).unwrap();
    assert_eq!(r.serial.as_deref(), Some("SLUS-01415"));
    assert_eq!(r.changes.len(), 1, "{:?}", r.changes);
    assert!(fs::read_to_string(t.path().join("game.toml")).unwrap().contains("overlay_native_block"));
    assert_eq!(fs::read_to_string(t.path().join("game.toml.aura-backup")).unwrap(), HP);
    assert!(r.backup_path.is_some());

    let again = pp::fix_package(t.path()).unwrap();
    assert!(again.changes.is_empty());
    assert!(again.notes.iter().any(|n| n.contains("already has the fixes")), "{:?}", again.notes);
    assert!(again.backup_path.is_none());
    assert_eq!(fs::read_to_string(t.path().join("game.toml.aura-backup")).unwrap(), HP, "backup is the first version");
}

#[test]
fn packages_without_known_fixes_or_a_marker_are_left_alone() {
    let t = TempDir::new("pp-unknown");
    package(t.path(), "[game]\nid = \"SLUS-00561\"\n");
    let r = pp::fix_package(t.path()).unwrap();
    assert!(r.changes.is_empty());
    assert!(r.notes.iter().any(|n| n.contains("No known title-specific fixes for SLUS-00561")), "{:?}", r.notes);
    assert!(!t.path().join("game.toml.aura-backup").exists());

    let t2 = TempDir::new("pp-noid");
    package(t2.path(), "[runtime]\nmemcard_dir = \"saves\"\n");
    assert!(pp::fix_package(t2.path()).unwrap().notes.iter().any(|n| n.contains("no [game] id")));

    let t3 = TempDir::new("pp-nomarker");
    fs::write(t3.path().join("game.toml"), HP).unwrap();
    assert!(pp::fix_package(t3.path()).unwrap_err().contains("not a game folder Aura built"));
}

#[test]
fn the_embedded_patch_is_a_clean_lf_diff_of_the_framework_root() {
    assert!(!pp::FRAMEWORK_PATCHES.is_empty());
    for p in pp::FRAMEWORK_PATCHES {
        assert!(!p.text.contains('\r'), "{}: patch must be LF", p.id);
        assert!(p.text.starts_with("diff --git a/runtime/"), "{}: paths are relative to the framework root", p.id);
        assert!(!p.title.is_empty() && !p.why.is_empty());
    }
    assert_eq!(pp::planned().len(), pp::FRAMEWORK_PATCHES.len());
}

// ---------------------------------------------------------------------------
// Framework patches (real git)
// ---------------------------------------------------------------------------

fn find_git() -> Option<PathBuf> {
    let probe = Command::new("git").arg("--version").output().ok()?;
    probe.status.success().then(|| PathBuf::from("git"))
}

fn git(repo: &Path, args: &[&str]) -> String {
    let out = Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(args)
        .env("GIT_AUTHOR_NAME", "t")
        .env("GIT_AUTHOR_EMAIL", "t@t")
        .env("GIT_COMMITTER_NAME", "t")
        .env("GIT_COMMITTER_EMAIL", "t@t")
        .output()
        .expect("git runs");
    assert!(out.status.success(), "git {args:?}: {}", String::from_utf8_lossy(&out.stderr));
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

fn git_ok(repo: &Path, args: &[&str]) -> bool {
    Command::new("git").arg("-C").arg(repo).args(args).output().map(|o| o.status.success()).unwrap_or(false)
}

const FILE: &str = "alpha\nbeta\ngamma\ndelta\n";

const PATCH_BETA: FrameworkPatch = FrameworkPatch {
    id: "beta-upper",
    title: "Upper-case beta",
    why: "test",
    text: "diff --git a/runtime/src/cdrom.c b/runtime/src/cdrom.c\n--- a/runtime/src/cdrom.c\n+++ b/runtime/src/cdrom.c\n\
@@ -1,4 +1,4 @@\n alpha\n-beta\n+BETA\n gamma\n delta\n",
};

const PATCH_DELTA: FrameworkPatch = FrameworkPatch {
    id: "delta-upper",
    title: "Upper-case delta",
    why: "test",
    text: "diff --git a/runtime/src/cdrom.c b/runtime/src/cdrom.c\n--- a/runtime/src/cdrom.c\n+++ b/runtime/src/cdrom.c\n\
@@ -3,2 +3,2 @@\n gamma\n-delta\n+DELTA\n",
};

/// A repository with one commit holding runtime/src/cdrom.c = FILE.
fn repo_with(content: &str) -> Option<(TempDir, PathBuf, String)> {
    find_git()?;
    let t = TempDir::new("pp-git");
    let repo = t.path().to_path_buf();
    git(&repo, &["init", "-q"]);
    git(&repo, &["config", "core.autocrlf", "false"]);
    fs::create_dir_all(repo.join("runtime/src")).unwrap();
    fs::write(repo.join("runtime/src/cdrom.c"), content).unwrap();
    git(&repo, &["add", "."]);
    git(&repo, &["commit", "-q", "-m", "base"]);
    let base = git(&repo, &["rev-parse", "HEAD"]);
    Some((t, repo, base))
}

#[test]
fn a_patch_lands_on_a_branch_and_leaves_the_checkout_alone() {
    let Some((_t, repo, base)) = repo_with(FILE) else { return };
    let out = pp::apply_to_base(Path::new("git"), &repo, &base, "aura-pinned", &[PATCH_BETA]).unwrap();
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].state, "applied");

    assert_eq!(git(&repo, &["show", "aura-pinned:runtime/src/cdrom.c"]), "alpha\nBETA\ngamma\ndelta");
    assert_eq!(git(&repo, &["rev-parse", "aura-pinned^"]), base, "one commit on top of the pinned one");
    assert!(git(&repo, &["log", "-1", "--format=%s", "aura-pinned"]).starts_with("Aura: fixes carried"));
    // The checkout is exactly as it was: same HEAD, clean tree, original file.
    assert_eq!(git(&repo, &["rev-parse", "HEAD"]), base);
    assert_eq!(git(&repo, &["status", "--porcelain"]), "");
    assert_eq!(fs::read_to_string(repo.join("runtime/src/cdrom.c")).unwrap(), FILE);
}

#[test]
fn applying_again_from_the_pinned_commit_gives_the_same_tree() {
    let Some((_t, repo, base)) = repo_with(FILE) else { return };
    pp::apply_to_base(Path::new("git"), &repo, &base, "aura-pinned", &[PATCH_BETA]).unwrap();
    let tree1 = git(&repo, &["rev-parse", "aura-pinned^{tree}"]);
    let out = pp::apply_to_base(Path::new("git"), &repo, &base, "aura-pinned", &[PATCH_BETA]).unwrap();
    assert_eq!(out[0].state, "applied", "always from the pinned commit, never stacked");
    assert_eq!(git(&repo, &["rev-parse", "aura-pinned^{tree}"]), tree1);
    assert_eq!(git(&repo, &["rev-parse", "aura-pinned^"]), base);
}

#[test]
fn a_patch_upstream_already_has_is_recognised_and_creates_no_commit() {
    let Some((_t, repo, base)) = repo_with("alpha\nBETA\ngamma\ndelta\n") else { return };
    let out = pp::apply_to_base(Path::new("git"), &repo, &base, "aura-pinned", &[PATCH_BETA]).unwrap();
    assert_eq!(out[0].state, "already in the pinned framework");
    assert!(!git_ok(&repo, &["rev-parse", "--verify", "refs/heads/aura-pinned"]), "no branch was made");
}

#[test]
fn some_present_and_some_missing_only_the_missing_one_is_committed() {
    let Some((_t, repo, base)) = repo_with("alpha\nBETA\ngamma\ndelta\n") else { return };
    let out = pp::apply_to_base(Path::new("git"), &repo, &base, "aura-pinned", &[PATCH_BETA, PATCH_DELTA]).unwrap();
    assert_eq!(out[0].state, "already in the pinned framework");
    assert_eq!(out[1].state, "applied");
    assert_eq!(git(&repo, &["show", "aura-pinned:runtime/src/cdrom.c"]), "alpha\nBETA\ngamma\nDELTA");
    assert!(git(&repo, &["log", "-1", "--format=%B", "aura-pinned"]).contains("Upper-case delta"));
    assert!(!git(&repo, &["log", "-1", "--format=%B", "aura-pinned"]).contains("Upper-case beta"));
}

#[test]
fn a_patch_that_no_longer_applies_stops_the_build_and_changes_nothing() {
    let Some((_t, repo, base)) = repo_with("alpha\nSOMETHING ELSE\ngamma\ndelta\n") else { return };
    // Pre-existing branch must survive a failed attempt untouched.
    git(&repo, &["branch", "aura-pinned", &base]);
    let err = pp::apply_to_base(Path::new("git"), &repo, &base, "aura-pinned", &[PATCH_BETA]).unwrap_err();
    assert!(err.contains("Upper-case beta") && err.contains("does not apply"), "{err}");
    assert!(err.contains("--no-fixes"), "{err}");
    assert_eq!(git(&repo, &["rev-parse", "aura-pinned"]), base);
    assert_eq!(git(&repo, &["status", "--porcelain"]), "");
}

#[test]
fn a_crlf_working_tree_does_not_get_in_the_way() {
    let Some((_t, repo, base)) = repo_with(FILE) else { return };
    // A Windows checkout with autocrlf: the working file has CRLF, the blob is LF.
    fs::write(repo.join("runtime/src/cdrom.c"), FILE.replace('\n', "\r\n")).unwrap();
    let out = pp::apply_to_base(Path::new("git"), &repo, &base, "aura-pinned", &[PATCH_BETA]).unwrap();
    assert_eq!(out[0].state, "applied");
    assert_eq!(git(&repo, &["show", "aura-pinned:runtime/src/cdrom.c"]), "alpha\nBETA\ngamma\ndelta");
}

#[test]
fn a_crlf_patch_text_is_normalised_before_use() {
    let Some((_t, repo, base)) = repo_with(FILE) else { return };
    let crlf = Box::leak(PATCH_BETA.text.replace('\n', "\r\n").into_boxed_str());
    let p = FrameworkPatch { id: "crlf", title: "CRLF copy", why: "t", text: crlf };
    let out = pp::apply_to_base(Path::new("git"), &repo, &base, "aura-pinned", &[p]).unwrap();
    assert_eq!(out[0].state, "applied");
}

#[test]
fn an_unknown_base_commit_is_a_clear_error() {
    let Some((_t, repo, _base)) = repo_with(FILE) else { return };
    let err = pp::apply_to_base(Path::new("git"), &repo, "0123456789abcdef0123456789abcdef01234567", "aura-pinned", &[PATCH_BETA])
        .unwrap_err();
    assert!(err.contains("has no commit"), "{err}");
}

#[test]
fn no_patches_is_a_no_op() {
    let Some((_t, repo, base)) = repo_with(FILE) else { return };
    assert!(pp::apply_to_base(Path::new("git"), &repo, &base, "aura-pinned", &[]).unwrap().is_empty());
    assert!(!git_ok(&repo, &["rev-parse", "--verify", "refs/heads/aura-pinned"]));
}

/// Manual check against a real pinned framework checkout:
/// `AURA_TEST_PSXRECOMP=<dir> cargo test --lib real_framework -- --ignored`.
#[test]
#[ignore]
fn real_framework_accepts_the_embedded_patches() {
    let dir = std::env::var("AURA_TEST_PSXRECOMP").expect("set AURA_TEST_PSXRECOMP to a PSXRecomp checkout");
    let repo = Path::new(&dir);
    let head = git(repo, &["rev-parse", "HEAD"]);
    // AURA_TEST_BRANCH keeps the result (to clone it and look); by default a throw-away branch.
    let keep = std::env::var("AURA_TEST_BRANCH").ok();
    let branch = keep.clone().unwrap_or_else(|| "aura-test-branch".to_string());
    let out = pp::apply_to_base(Path::new("git"), repo, &head, &branch, pp::FRAMEWORK_PATCHES).unwrap();
    eprintln!("outcomes: {out:?}");
    assert!(!out.is_empty());
    if keep.is_none() {
        let _ = Command::new("git").arg("-C").arg(repo).args(["branch", "-D", &branch]).output();
    }
}

// ---------------------------------------------------------------------------
// Through the build driver (fake setup script; Windows runs the .cmd stand-in)
// ---------------------------------------------------------------------------

#[cfg(windows)]
mod build_flow {
    use crate::ps1_build::{self, Ps1BuildOptions};
    use crate::ps1_ingest::{self, Ps1IngestOptions};
    use crate::tests_disc::TempDir;
    use crate::tests_ps1::{ps1_iso, psx_exe_bytes};
    use std::fs;
    use std::path::{Path, PathBuf};

    /// A setup script that, like the real one, leaves a project with a
    /// `game.toml` and a `build-release/` holding the program and its staged
    /// copy of `game.toml`.
    fn fake_powershell(dir: &Path) -> PathBuf {
        let body = r#"@echo off
setlocal
set DIR=
set REPO=
:loop
if "%~1"=="" goto done
if "%~1"=="-Dir" set DIR=%~2
if "%~1"=="-GithubRepo" set REPO=%~2
shift
goto loop
:done
mkdir "%DIR%\%REPO%\build-release" 2>nul
echo [game]> "%DIR%\%REPO%\game.toml"
echo id = "SLUS-01415">> "%DIR%\%REPO%\game.toml"
echo [runtime]>> "%DIR%\%REPO%\game.toml"
echo overlay_cache = true>> "%DIR%\%REPO%\game.toml"
copy /y "%DIR%\%REPO%\game.toml" "%DIR%\%REPO%\build-release\game.toml" >nul
echo MZ> "%DIR%\%REPO%\build-release\Fake_Recompiled.exe"
echo Fake_Recompiled> "%DIR%\%REPO%\build-release\psxrecomp_exe_name-psx-runtime.txt"
exit /b 0
"#;
        let p = dir.join("powershell.cmd");
        fs::write(&p, body.replace('\n', "\r\n")).unwrap();
        p
    }

    fn setup(t: &TempDir, no_fixes: bool) -> (PathBuf, Ps1BuildOptions) {
        let iso = t.path().join("Harry Potter (USA).iso");
        fs::write(
            &iso,
            ps1_iso("SLUS_014.15", psx_exe_bytes(0x8001_0000, 0x8001_0000, 4096, "Sony Computer Entertainment Inc. for North America area")),
        )
        .unwrap();
        let ws = PathBuf::from(
            ps1_ingest::ingest_ps1(
                iso.to_str().unwrap(),
                &Ps1IngestOptions { out_root: t.path().join("games").to_string_lossy().to_string() },
                &mut |_| true,
            )
            .unwrap()
            .workspace,
        );
        let tools = t.path().join("tools");
        fs::create_dir_all(&tools).unwrap();
        fs::write(tools.join("git"), b"x").unwrap();
        fs::write(tools.join("python.cmd"), "@echo off\r\necho 3 12\r\n").unwrap();
        let tc = t.path().join("tc");
        fs::create_dir_all(tc.join("bin")).unwrap();
        for n in ["cmake", "ninja", "clang"] {
            fs::write(tc.join("bin").join(format!("{n}.exe")), b"x").unwrap();
        }
        let fw = t.path().join("psxrecomp");
        fs::create_dir_all(fw.join("tools/new_project_layout")).unwrap();
        fs::write(fw.join("tools/new_project_layout/setup_project.ps1"), "# fake\n").unwrap();
        let ui = t.path().join("recomp-ui");
        fs::create_dir_all(&ui).unwrap();
        let opts = Ps1BuildOptions {
            cache_dir: Some(t.path().join("cache")),
            allow_downloads: true,
            package: true,
            jobs: Some(4),
            git: Some(tools.join("git")),
            python: Some(tools.join("python.cmd")),
            powershell: Some(fake_powershell(&tools)),
            toolchain_dir: Some(tc),
            framework_override: Some(fw),
            ui_override: Some(ui),
            skip_os_check: true,
            no_fixes,
            ..Default::default()
        };
        (ws, opts)
    }

    fn text(p: &Path) -> String {
        fs::read_to_string(p).unwrap_or_default()
    }

    #[test]
    fn the_title_fix_reaches_the_project_the_staged_copy_and_the_package() {
        let t = TempDir::new("pp-flow");
        let (ws, opts) = setup(&t, false);

        let plan = ps1_build::plan_build(&ws, &opts).unwrap();
        assert_eq!(plan.serial.as_deref(), Some("SLUS-01415"));
        assert_eq!(plan.config_additions.len(), 1, "{:?}", plan.config_additions);
        assert!(plan.config_additions[0].setting.contains("overlay_native_block"));
        assert!(plan.framework_patches.is_empty(), "a user-supplied framework is never patched");

        let r = ps1_build::build_game(&ws, &opts, &mut |_| true).unwrap();
        assert_eq!(r.config_additions.len(), 1, "{:?}", r.config_additions);
        assert!(r.framework_patches.is_empty());
        for f in [
            PathBuf::from(&r.project_dir).join("game.toml"),
            PathBuf::from(&r.build_dir).join("game.toml"),
            ws.join("package").join("game.toml"),
        ] {
            assert!(text(&f).contains("overlay_native_block = [\"0x00010CDC\"]"), "{}: {}", f.display(), text(&f));
            assert!(text(&f).contains("overlay_cache = true"), "existing keys survive in {}", f.display());
        }
    }

    #[test]
    fn no_fixes_builds_the_config_exactly_as_generated() {
        let t = TempDir::new("pp-flow-off");
        let (ws, opts) = setup(&t, true);
        let plan = ps1_build::plan_build(&ws, &opts).unwrap();
        assert!(plan.config_additions.is_empty() && plan.framework_patches.is_empty());
        let r = ps1_build::build_game(&ws, &opts, &mut |_| true).unwrap();
        assert!(r.config_additions.is_empty());
        assert!(!text(&ws.join("package").join("game.toml")).contains("overlay_native_block"));
    }
}
