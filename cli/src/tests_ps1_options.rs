//! Tests for `ps1_options`: reading and editing a packaged game's settings,
//! switching enhancements, diagnosing a folder and resetting generated state.
//!
//! Everything runs against small fake package folders; no game is started.

use crate::ps1_options::{self as opt, PlayOptions};
use crate::tests_disc::TempDir;
use std::fs;
use std::path::Path;
use std::time::{Duration, SystemTime};

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

fn package(dir: &Path) {
    fs::write(dir.join("game.exe"), b"MZ").unwrap();
    fs::write(
        dir.join("aura-package.json"),
        r#"{"aura_package":1,"platform":"PS1","pipeline":"psxrecomp","exe":"game.exe","title":"Test Game"}"#,
    )
    .unwrap();
}

fn put(dir: &Path, rel: &str, text: &str) {
    let p = dir.join(rel);
    fs::create_dir_all(p.parent().unwrap()).unwrap();
    fs::write(p, text).unwrap();
}

fn read(dir: &Path, rel: &str) -> String {
    fs::read_to_string(dir.join(rel)).unwrap()
}

const SETTINGS: &str = "# psxrecomp user settings - written by the launcher. Safe to hand-edit.\r\n\
\r\n\
[video]\r\n\
renderer          = \"opengl\"\r\n\
supersampling     = 4\r\n\
internal_resolution = \"4k\"   # chosen in the launcher\r\n\
window_width      = 1600\r\n\
fullscreen        = 1\r\n\
vsync             = \"on\"\r\n\
aspect_ratio      = \"4:3\"\r\n\
\r\n\
[audio]\r\n\
frequency = 44100\r\n\
\r\n\
[disc]\r\n\
path = \"F:/PS1/Game.chd\"\r\n";

fn manifest(id: &str, features: &[(&str, &str, &str, bool)]) -> String {
    let mut s = format!("format_version = 5\nid = \"{id}\"\nversion = \"1.0.0\"\nname = \"{id}\"\n\n[[target]]\ngame_id = \"*\"\n");
    for (fid, name, desc, default) in features {
        s.push_str(&format!(
            "\n[[feature]]\nid = \"{fid}\"\nname = \"{name}\"\ndescription = \"{desc}\"\ndefault_enabled = {default}\n"
        ));
    }
    s
}

fn add_mod(dir: &Path, id: &str, features: &[(&str, &str, &str, bool)]) {
    put(dir, &format!("mods/bundled/{id}/1.0.0/manifest.toml"), &manifest(id, features));
}

const STATE: &str = "format_version = 2\n\n\
[[package]]\nid = \"psx.enhancement.fast-loading\"\n\n\
[[package]]\nid = \"psx.enhancement.hd-textures\"\n\n\
[[feature]]\npackage_id = \"psx.enhancement.fast-loading\"\nid = \"fast-loading\"\nenabled = true\n\n\
[[feature]]\npackage_id = \"psx.enhancement.hd-textures\"\nid = \"hd-textures\"\nenabled = true\n\
[feature.resources]\npack = \"E:\\\\pack\"\n";

fn mods_fixture(dir: &Path) {
    add_mod(
        dir,
        "psx.enhancement.fast-loading",
        &[("fast-loading", "Fast Loading (host pacing)", "Deprecated generic loading detector.", false)],
    );
    add_mod(dir, "psx.enhancement.hd-textures", &[("hd-textures", "HD Textures", "Replaces textures.", false)]);
    add_mod(dir, "psx.enhancement.pgxp", &[("pgxp", "PGXP", "Precise geometry.", false)]);
    put(dir, "mods/state.toml", STATE);
}

fn safe_options() -> PlayOptions {
    PlayOptions::default()
}

// ---------------------------------------------------------------------------
// Reading
// ---------------------------------------------------------------------------

#[test]
fn only_aura_packages_are_accepted() {
    let t = TempDir::new("opt-marker");
    assert!(opt::read_options(t.path()).unwrap_err().contains("not a game folder Aura built"));
    assert!(opt::write_options(t.path(), &safe_options()).is_err());
    assert!(opt::reset_state(t.path(), false).is_err());
    assert!(opt::set_mod_enabled(t.path(), "a", "b", true).is_err());
}

#[test]
fn marker_cannot_point_outside_the_folder() {
    let t = TempDir::new("opt-escape");
    put(t.path(), "aura-package.json", r#"{"aura_package":1,"exe":"..\\evil.exe"}"#);
    assert!(opt::read_options(t.path()).is_err());
}

#[test]
fn defaults_apply_when_no_settings_file_exists() {
    let t = TempDir::new("opt-defaults");
    package(t.path());
    let info = opt::read_options(t.path()).unwrap();
    assert_eq!(info.title, "Test Game");
    assert!(!info.settings_exists);
    assert_eq!(info.options, PlayOptions::default());
    assert_eq!(info.internal_scale, Some(1));
}

#[test]
fn reads_settings_and_falls_back_to_legacy_supersampling() {
    let t = TempDir::new("opt-read");
    package(t.path());
    put(t.path(), "settings.toml", SETTINGS);
    let info = opt::read_options(t.path()).unwrap();
    assert_eq!(info.options.renderer, "opengl");
    assert_eq!(info.options.internal_resolution, "4k");
    assert_eq!(info.options.fullscreen, 1);
    assert_eq!(info.options.window_width, 1600);
    assert_eq!(info.internal_scale, Some(9));
    assert_eq!(info.disc_path.as_deref(), Some("F:/PS1/Game.chd"));

    let t2 = TempDir::new("opt-legacy");
    package(t2.path());
    put(t2.path(), "settings.toml", "[video]\nsupersampling = 3\n");
    assert_eq!(opt::read_options(t2.path()).unwrap().options.internal_resolution, "3x");
}

#[test]
fn game_toml_supplies_values_and_the_reference_height() {
    let t = TempDir::new("opt-game");
    package(t.path());
    put(t.path(), "game.toml", "[video]\nrenderer = \"software\"\nresolution_reference_lines = 480\n");
    put(t.path(), "settings.toml", "[video]\ninternal_resolution = \"4k\"\n");
    let info = opt::read_options(t.path()).unwrap();
    assert_eq!(info.options.renderer, "software");
    // 2160 / 480 lines, rounded up.
    assert_eq!(info.internal_scale, Some(5));
}

#[test]
fn internal_scale_matches_the_runtime_table() {
    let s = |r: &str| opt::internal_scale(r, 240);
    assert_eq!(s("native"), Some(1));
    assert_eq!(s("720p"), Some(3));
    assert_eq!(s("1080p"), Some(5));
    assert_eq!(s("1440p"), Some(6));
    assert_eq!(s("4k"), Some(9));
    assert_eq!(s("5K"), Some(12));
    assert_eq!(s("8k"), Some(18));
    assert_eq!(s("display"), None);
    assert_eq!(s("3x"), Some(3));
    assert_eq!(s("540"), Some(3));
    assert_eq!(s("0x"), None);
    assert_eq!(s("33x"), None);
    assert_eq!(s("banana"), None);
}

// ---------------------------------------------------------------------------
// Writing
// ---------------------------------------------------------------------------

#[test]
fn write_keeps_comments_order_and_line_endings_and_backs_up_once() {
    let t = TempDir::new("opt-write");
    package(t.path());
    put(t.path(), "settings.toml", SETTINGS);

    let mut o = opt::read_options(t.path()).unwrap().options;
    opt::apply_preset(&mut o, "balanced").unwrap();
    o.renderer = "vulkan".into();
    let r = opt::write_options(t.path(), &o).unwrap();
    assert!(r.changed.iter().any(|c| c == "renderer: opengl -> vulkan"), "{:?}", r.changed);
    assert!(r.changed.iter().any(|c| c == "internal_resolution: 4k -> 720p"), "{:?}", r.changed);
    assert!(r.backup_path.is_some());

    let text = read(t.path(), "settings.toml");
    assert!(text.contains("renderer          = \"vulkan\"\r\n"), "{text:?}");
    // The comment on the changed line and the rest of the file survive.
    assert!(text.contains("internal_resolution = \"720p\"   # chosen in the launcher\r\n"), "{text:?}");
    assert!(text.starts_with("# psxrecomp user settings"));
    assert!(text.contains("[audio]\r\nfrequency = 44100\r\n"));
    assert!(text.contains("path = \"F:/PS1/Game.chd\"\r\n"));
    assert!(!text.replace("\r\n", "").contains('\n'), "line endings must stay CRLF");
    assert_eq!(text.matches("[video]").count(), 1);

    // The original is kept, and a second write does not replace it.
    assert_eq!(read(t.path(), "settings.toml.aura-backup"), SETTINGS);
    o.vsync = "off".into();
    let r2 = opt::write_options(t.path(), &o).unwrap();
    assert!(r2.backup_path.is_none());
    assert_eq!(read(t.path(), "settings.toml.aura-backup"), SETTINGS);
}

#[test]
fn write_keeps_legacy_supersampling_consistent() {
    let t = TempDir::new("opt-ss");
    package(t.path());
    put(t.path(), "settings.toml", SETTINGS);
    for (res, want) in [("native", "1"), ("720p", "3"), ("1080p", "4"), ("4k", "4")] {
        let mut o = safe_options();
        o.internal_resolution = res.into();
        opt::write_options(t.path(), &o).unwrap();
        let text = read(t.path(), "settings.toml");
        assert!(text.contains(&format!("supersampling     = {want}")), "{res}: {text}");
    }
}

#[test]
fn write_creates_settings_and_the_video_table_when_missing() {
    let t = TempDir::new("opt-create");
    package(t.path());
    let mut o = safe_options();
    o.fullscreen = 2;
    let r = opt::write_options(t.path(), &o).unwrap();
    assert!(r.backup_path.is_none());
    let text = read(t.path(), "settings.toml");
    assert!(text.starts_with("[video]"), "{text}");
    assert!(text.contains("fullscreen = 2"));
    assert!(text.contains("renderer = \"opengl\""));
    // A table that exists without a [video] section gets one appended.
    put(t.path(), "settings.toml", "[audio]\nfrequency = 44100\n");
    opt::write_options(t.path(), &o).unwrap();
    let text = read(t.path(), "settings.toml");
    assert!(text.contains("[audio]\nfrequency = 44100\n"));
    assert!(text.contains("[video]\nrenderer"));
}

#[test]
fn values_the_runtime_would_reject_or_ignore_are_refused() {
    let t = TempDir::new("opt-validate");
    package(t.path());
    let bad = |f: &dyn Fn(&mut PlayOptions)| {
        let mut o = safe_options();
        f(&mut o);
        opt::write_options(t.path(), &o)
    };
    assert!(bad(&|o| o.renderer = "directx12".into()).unwrap_err().contains("renderer must be"));
    assert!(bad(&|o| o.internal_resolution = "ludicrous".into()).is_err());
    assert!(bad(&|o| o.fullscreen = 3).is_err());
    assert!(bad(&|o| o.vsync = "maybe".into()).is_err());
    assert!(bad(&|o| o.window_width = 100).is_err());
    assert!(bad(&|o| o.window_width = 9000).is_err());
    assert!(bad(&|o| o.aspect_ratio = "sixteen:nine".into()).is_err());
    assert!(bad(&|o| o.aspect_ratio = "2:1".into()).unwrap_err().contains("no widescreen mod"), "2:1 needs a mod too");
    assert!(bad(&|o| o.aspect_ratio = "3:4".into()).unwrap_err().contains("between 4:3 and 32:9"));
    assert!(bad(&|o| o.aspect_ratio = "64:9".into()).unwrap_err().contains("between 4:3 and 32:9"));
    // Nothing was written by any of the refused calls.
    assert!(!t.path().join("settings.toml").exists());
}

#[test]
fn widescreen_is_accepted_only_when_the_game_has_a_widescreen_mod() {
    let t = TempDir::new("opt-wide");
    package(t.path());
    let mut o = safe_options();
    o.aspect_ratio = "16:9".into();
    let err = opt::write_options(t.path(), &o).unwrap_err();
    assert!(err.contains("no generic stretch"), "{err}");

    add_mod(t.path(), "psx.presentation.widescreen", &[("widescreen", "Widescreen", "Wider view.", false)]);
    let info = opt::read_options(t.path()).unwrap();
    assert!(info.widescreen_available);
    opt::write_options(t.path(), &o).unwrap();
    assert!(read(t.path(), "settings.toml").contains("aspect_ratio = \"16:9\""));
}

#[test]
fn choosing_vulkan_also_offers_it_in_game_toml() {
    let t = TempDir::new("opt-vulkan");
    package(t.path());
    put(t.path(), "game.toml", "[video]\nrenderer = \"opengl\"\naspect_ratio = \"4:3\"\n\n[controller]\ndefault_mode = \"digital\"\n");
    assert!(!opt::read_options(t.path()).unwrap().vulkan_offered);

    let mut o = safe_options();
    o.renderer = "vulkan".into();
    let r = opt::write_options(t.path(), &o).unwrap();
    assert!(r.changed.iter().any(|c| c.contains("offer_vulkan")), "{:?}", r.changed);

    let game = read(t.path(), "game.toml");
    assert!(game.contains("[video]\nrenderer = \"opengl\"\naspect_ratio = \"4:3\"\noffer_vulkan = true\n"), "{game}");
    assert!(game.contains("[controller]\ndefault_mode = \"digital\""));
    assert!(t.path().join("game.toml.aura-backup").is_file());
    assert!(opt::read_options(t.path()).unwrap().vulkan_offered);
    assert!(read(t.path(), "settings.toml").contains("renderer = \"vulkan\""));

    // Not rewritten once it is offered, and other renderers leave it alone.
    let backup_before = read(t.path(), "game.toml.aura-backup");
    let r = opt::write_options(t.path(), &o).unwrap();
    assert!(!r.changed.iter().any(|c| c.contains("offer_vulkan")), "{:?}", r.changed);
    assert_eq!(read(t.path(), "game.toml.aura-backup"), backup_before);
    o.renderer = "software".into();
    opt::write_options(t.path(), &o).unwrap();
    assert!(read(t.path(), "game.toml").contains("offer_vulkan = true"), "offer stays so Vulkan can be picked again");
}

#[test]
fn opengl_and_software_never_touch_game_toml() {
    let t = TempDir::new("opt-novulkan");
    package(t.path());
    let game = "[video]\nrenderer = \"opengl\"\n";
    put(t.path(), "game.toml", game);
    for r in ["opengl", "software"] {
        let mut o = safe_options();
        o.renderer = r.into();
        opt::write_options(t.path(), &o).unwrap();
    }
    assert_eq!(read(t.path(), "game.toml"), game);
    assert!(!t.path().join("game.toml.aura-backup").exists());
}

#[test]
fn vulkan_without_a_game_toml_is_a_warning_not_a_new_file() {
    let t = TempDir::new("opt-vulkan-nogame");
    package(t.path());
    let mut o = safe_options();
    o.renderer = "vulkan".into();
    let r = opt::write_options(t.path(), &o).unwrap();
    assert!(r.warnings.iter().any(|w| w.contains("game.toml was not found")), "{:?}", r.warnings);
    assert!(!t.path().join("game.toml").exists());
}

#[test]
fn a_hand_edited_vulkan_setting_the_runtime_would_ignore_is_flagged() {
    let t = TempDir::new("opt-vulkan-flag");
    package(t.path());
    put(t.path(), "game.toml", "[video]\nrenderer = \"opengl\"\n");
    put(t.path(), "settings.toml", "[video]\nrenderer = \"vulkan\"\n");
    assert!(codes(t.path()).contains(&"vulkan-not-offered".to_string()));

    put(t.path(), "game.toml", "[video]\nrenderer = \"opengl\"\noffer_vulkan = true\n");
    let c = codes(t.path());
    assert!(!c.contains(&"vulkan-not-offered".to_string()), "{c:?}");
    assert!(c.contains(&"renderer-vulkan".to_string()), "{c:?}");
}

// ---------------------------------------------------------------------------
// Presets and choices
// ---------------------------------------------------------------------------

#[test]
fn presets_change_only_what_they_say() {
    let mut o = safe_options();
    o.renderer = "vulkan".into();
    o.fullscreen = 2;
    o.window_width = 1280;
    opt::apply_preset(&mut o, "sharp").unwrap();
    assert_eq!(o.internal_resolution, "1080p");
    assert_eq!((o.renderer.as_str(), o.fullscreen, o.window_width), ("vulkan", 2, 1280));
    opt::apply_preset(&mut o, "safe").unwrap();
    assert_eq!((o.renderer.as_str(), o.internal_resolution.as_str(), o.vsync.as_str()), ("opengl", "native", "on"));
    assert_eq!(o.fullscreen, 2);
    assert!(opt::apply_preset(&mut o, "ludicrous").unwrap_err().contains("Unknown preset"));
    for p in opt::presets() {
        let mut x = safe_options();
        opt::apply_preset(&mut x, &p.id).unwrap();
        assert!(opt::validate_options(&x, false).is_ok(), "preset {} must be valid", p.id);
    }
}

#[test]
fn offered_choices_are_all_valid_and_directx12_is_not_among_them() {
    let c = opt::choices();
    for r in &c.renderers {
        assert!(opt::RENDERERS.contains(&r.value.as_str()), "{}", r.value);
    }
    for r in &c.resolutions {
        assert!(opt::internal_scale(&r.value, 240).is_some(), "{}", r.value);
    }
    for v in &c.vsync {
        assert!(opt::VSYNC_MODES.contains(&v.value.as_str()), "{}", v.value);
    }
    assert!(!c.renderers.iter().any(|r| r.value.contains("12")));
    assert!(c.unavailable.iter().any(|u| u.value == "direct3d12"));
}

// ---------------------------------------------------------------------------
// Enhancements
// ---------------------------------------------------------------------------

#[test]
fn enhancements_are_read_with_their_defaults_and_switches() {
    let t = TempDir::new("opt-mods");
    package(t.path());
    mods_fixture(t.path());
    let mods = opt::read_mods(t.path());
    let get = |id: &str| mods.iter().find(|m| m.feature_id == id).unwrap();
    assert!(get("fast-loading").enabled);
    assert!(get("fast-loading").deprecated);
    assert!(get("hd-textures").enabled);
    assert!(!get("hd-textures").deprecated);
    // Declared by a manifest but absent from state.toml: its default applies.
    assert!(!get("pgxp").enabled);
    assert!(!get("pgxp").default_enabled);
}

#[test]
fn switching_an_enhancement_edits_only_its_line() {
    let t = TempDir::new("opt-toggle");
    package(t.path());
    mods_fixture(t.path());
    let r = opt::set_mod_enabled(t.path(), "psx.enhancement.fast-loading", "fast-loading", false).unwrap();
    assert!(r.changed);
    let text = read(t.path(), "mods/state.toml");
    let want = STATE.replacen("fast-loading\"\nenabled = true", "fast-loading\"\nenabled = false", 1);
    assert_eq!(text, want);
    assert_eq!(read(t.path(), "mods/state.toml.aura-backup"), STATE);

    // Already off: nothing to do and no rewrite.
    let again = opt::set_mod_enabled(t.path(), "psx.enhancement.fast-loading", "fast-loading", false).unwrap();
    assert!(!again.changed);

    // A feature with a sub-table keeps it.
    opt::set_mod_enabled(t.path(), "psx.enhancement.hd-textures", "hd-textures", false).unwrap();
    let text = read(t.path(), "mods/state.toml");
    assert!(text.contains("id = \"hd-textures\"\nenabled = false\n[feature.resources]\npack = \"E:\\\\pack\""), "{text}");
}

#[test]
fn a_feature_missing_from_state_is_added_and_unknown_ones_are_refused() {
    let t = TempDir::new("opt-add");
    package(t.path());
    mods_fixture(t.path());
    opt::set_mod_enabled(t.path(), "psx.enhancement.pgxp", "pgxp", true).unwrap();
    let text = read(t.path(), "mods/state.toml");
    assert!(text.contains("[[package]]\nid = \"psx.enhancement.pgxp\""), "{text}");
    assert!(text.contains("[[feature]]\npackage_id = \"psx.enhancement.pgxp\"\nid = \"pgxp\"\nenabled = true"), "{text}");
    assert!(opt::read_mods(t.path()).iter().find(|m| m.feature_id == "pgxp").unwrap().enabled);

    let err = opt::set_mod_enabled(t.path(), "psx.enhancement.nope", "nope", true).unwrap_err();
    assert!(err.contains("no mod feature"), "{err}");
}

// ---------------------------------------------------------------------------
// Diagnosis
// ---------------------------------------------------------------------------

fn codes(dir: &Path) -> Vec<String> {
    opt::read_options(dir).unwrap().findings.into_iter().map(|f| f.code).collect()
}

fn dump(pc: &str, frame: u64, epoch: u64) -> String {
    format!(
        r#"{{"frame_count":{frame},"wall_clock_epoch":{epoch},"current_func":"0x00002970","wedge_kind_name":"hard_freeze","cpu":{{"pc":"{pc}"}}}}"#
    )
}

#[test]
fn a_clean_package_has_no_findings() {
    let t = TempDir::new("opt-clean");
    package(t.path());
    assert!(codes(t.path()).is_empty());
}

#[test]
fn heavy_resolution_deprecated_mod_and_missing_disc_are_reported() {
    let t = TempDir::new("opt-find");
    package(t.path());
    mods_fixture(t.path());
    put(t.path(), "settings.toml", SETTINGS);
    let c = codes(t.path());
    assert!(c.contains(&"resolution-heavy".to_string()), "{c:?}");
    assert!(c.contains(&"mod-deprecated".to_string()), "{c:?}");
    assert!(c.contains(&"disc-missing".to_string()), "{c:?}");
    // Errors come first.
    assert_eq!(c[0], "disc-missing");

    // At a moderate resolution with the mod off, the first two go away.
    let mut o = safe_options();
    opt::apply_preset(&mut o, "balanced").unwrap();
    opt::write_options(t.path(), &o).unwrap();
    opt::set_mod_enabled(t.path(), "psx.enhancement.fast-loading", "fast-loading", false).unwrap();
    let c = codes(t.path());
    assert!(!c.contains(&"resolution-heavy".to_string()), "{c:?}");
    assert!(!c.contains(&"mod-deprecated".to_string()), "{c:?}");
}

#[test]
fn an_existing_disc_is_not_reported_missing() {
    let t = TempDir::new("opt-disc");
    package(t.path());
    let disc = t.path().join("game.chd");
    fs::write(&disc, b"x").unwrap();
    put(
        t.path(),
        "settings.toml",
        &format!("[disc]\npath = \"{}\"\n", disc.to_string_lossy().replace('\\', "/")),
    );
    assert!(!codes(t.path()).contains(&"disc-missing".to_string()));
}

#[test]
fn freeze_reports_are_summarised_and_a_repeated_place_is_called_out() {
    let t = TempDir::new("opt-freeze");
    package(t.path());
    put(t.path(), "psx_freeze_dump_a_0.json", &dump("0x00000000", 157, 1000));
    put(t.path(), "psx_freeze_dump_b_1.json", &dump("0x00066554", 7467, 2000));
    let f = opt::read_options(t.path()).unwrap().findings;
    let one = f.iter().find(|f| f.code == "freeze-dumps").expect("freeze finding");
    assert!(one.title.starts_with("2 freeze report"), "{}", one.title);
    assert!(one.detail.contains("hard_freeze in 0x00002970 (pc 0x00066554) x1"), "{}", one.detail);
    assert!(one.detail.contains("(pc 0x00000000) x1"), "{}", one.detail);
    assert!(!one.detail.contains("came back"), "{}", one.detail);

    // A second run that stops in the same place is called out.
    put(t.path(), "psx_freeze_dump_c_2.json", &dump("0x00066554", 5062, 3000));
    let one = opt::read_options(t.path()).unwrap().findings.into_iter().find(|f| f.code == "freeze-dumps").unwrap();
    assert!(one.detail.contains("(pc 0x00066554) x2"), "{}", one.detail);
    assert!(one.detail.contains("came back in more than one run"), "{}", one.detail);
}

#[test]
fn two_dumps_of_one_freeze_are_one_event() {
    // The runtime writes a slow-frames note and a hard-freeze dump together.
    let t = TempDir::new("opt-freeze-pair");
    package(t.path());
    put(t.path(), "psx_freeze_dump_x_0.json", &dump("0x00066554", 1064, 5000));
    put(t.path(), "psx_freeze_dump_x_1.json", &dump("0x00066554", 1064, 5001));
    let one = opt::read_options(t.path()).unwrap().findings.into_iter().find(|f| f.code == "freeze-dumps").unwrap();
    assert!(one.title.starts_with("2 freeze report"), "{}", one.title);
    assert!(one.detail.contains("(pc 0x00066554) x1"), "{}", one.detail);
    assert!(!one.detail.contains("came back"), "{}", one.detail);
}

#[test]
fn a_repeated_pc_of_zero_is_not_a_pointer_to_anything() {
    let t = TempDir::new("opt-freeze0");
    package(t.path());
    put(t.path(), "psx_freeze_dump_a_0.json", &dump("0x00000000", 1, 1000));
    put(t.path(), "psx_freeze_dump_b_0.json", &dump("0x00000000", 2, 9000));
    let d = opt::read_options(t.path()).unwrap().findings.into_iter().find(|f| f.code == "freeze-dumps").unwrap();
    assert!(d.detail.contains("(pc 0x00000000) x2"), "{}", d.detail);
    assert!(!d.detail.contains("came back"), "{}", d.detail);
}

#[test]
fn only_old_lock_files_count_as_stale() {
    let t = TempDir::new("opt-lock");
    package(t.path());
    put(t.path(), "cache/fresh.lock", "");
    assert!(!codes(t.path()).contains(&"stale-locks".to_string()));

    let old = t.path().join("cache").join("old.lock");
    fs::write(&old, "").unwrap();
    let f = fs::OpenOptions::new().write(true).open(&old).unwrap();
    f.set_modified(SystemTime::now() - Duration::from_secs(3600)).unwrap();
    drop(f);
    assert!(codes(t.path()).contains(&"stale-locks".to_string()));
    assert_eq!(opt::read_options(t.path()).unwrap().state.stale_locks, 1);
}

#[test]
fn an_ignored_aspect_ratio_is_explained() {
    let t = TempDir::new("opt-aspect");
    package(t.path());
    put(t.path(), "settings.toml", "[video]\naspect_ratio = \"16:9\"\n");
    assert!(codes(t.path()).contains(&"aspect-ignored".to_string()));
}

// ---------------------------------------------------------------------------
// Reset
// ---------------------------------------------------------------------------

fn generated(dir: &Path) {
    put(dir, "cache/SLUS/ovl_1.dll", "dll");
    put(dir, "cache/SLUS/ovl_1.c", "int x;");
    put(dir, "overlay_captures.json", "{}");
    put(dir, "overlay_captures.json.d/a.bin", "x");
    put(dir, "psx_freeze_dump_x_0.json", &dump("0x1", 1, 1));
    put(dir, "psx_freeze_heartbeat.json", "{}");
    put(dir, "psx_last_run_report.json", "{}");
    put(dir, "saves/card1.mcd", "SAVE");
    put(dir, "settings.toml", SETTINGS);
}

#[test]
fn reset_moves_generated_state_and_keeps_saves_and_settings() {
    let t = TempDir::new("opt-reset");
    package(t.path());
    generated(t.path());

    let r = opt::reset_state(t.path(), false).unwrap();
    let backup = std::path::PathBuf::from(r.backup_dir.clone().unwrap());
    assert!(r.skipped.is_empty(), "{:?}", r.skipped);
    assert_eq!(r.moved.len(), 6, "{:?}", r.moved);

    for gone in ["cache", "overlay_captures.json", "overlay_captures.json.d", "psx_freeze_dump_x_0.json", "psx_freeze_heartbeat.json", "psx_last_run_report.json"] {
        assert!(!t.path().join(gone).exists(), "{gone} should have been moved");
        assert!(backup.join(gone).exists(), "{gone} should be in the backup");
    }
    // Nothing was destroyed: the content is intact in the backup.
    assert_eq!(fs::read_to_string(backup.join("cache/SLUS/ovl_1.c")).unwrap(), "int x;");
    // Saves, settings and the program stay where they are.
    assert_eq!(read(t.path(), "saves/card1.mcd"), "SAVE");
    assert_eq!(read(t.path(), "settings.toml"), SETTINGS);
    assert!(t.path().join("game.exe").exists());
    assert!(r.bytes > 0);

    // Resetting a clean folder is a no-op that makes no backup folder.
    let again = opt::reset_state(t.path(), false).unwrap();
    assert!(again.backup_dir.is_none() && again.moved.is_empty());
}

#[test]
fn reset_moves_saves_only_when_asked() {
    let t = TempDir::new("opt-reset-saves");
    package(t.path());
    generated(t.path());
    let r = opt::reset_state(t.path(), true).unwrap();
    assert!(r.moved.contains(&"saves".to_string()));
    assert!(!t.path().join("saves").exists());
    assert_eq!(fs::read_to_string(Path::new(&r.backup_dir.unwrap()).join("saves/card1.mcd")).unwrap(), "SAVE");
}

#[test]
fn consecutive_resets_get_their_own_backup_folders() {
    let t = TempDir::new("opt-reset-twice");
    package(t.path());
    generated(t.path());
    let a = opt::reset_state(t.path(), false).unwrap().backup_dir.unwrap();
    put(t.path(), "psx_last_run_report.json", "{}");
    let b = opt::reset_state(t.path(), false).unwrap().backup_dir.unwrap();
    assert_ne!(a, b);
    assert!(Path::new(&a).is_dir() && Path::new(&b).is_dir());
}

#[test]
fn a_program_that_is_not_running_is_not_reported_as_running() {
    let t = TempDir::new("opt-running");
    package(t.path());
    assert!(!opt::game_running(&t.path().join("game.exe")));
    assert!(!opt::game_running(&t.path().join("missing.exe")));
    assert!(!opt::read_options(t.path()).unwrap().game_running);
}
