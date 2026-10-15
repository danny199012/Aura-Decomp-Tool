//! Play options for a packaged PS1 game: change how the game looks, find out
//! why it misbehaves, and put its generated state back to a clean slate.
//!
//! A package Aura built is a PSXRecomp runtime. It keeps the player's choices
//! in `settings.toml` (the `[video]` table), the optional enhancements in
//! `mods/state.toml`, and everything it learns while running -- compiled
//! overlay code, captured overlays, freeze reports -- in the package folder.
//! This module reads and edits those files, so the same logic serves the
//! command line and the app.
//!
//! What it can and cannot offer is decided by the runtime, not by Aura:
//!
//! * renderers are `software`, `opengl` and `vulkan` (Vulkan is experimental);
//!   there is no Direct3D 12 renderer for PS1,
//! * the picture is only widened when the title has a widescreen *mod*; the
//!   runtime clamps any other aspect to 4:3 before the game starts, so a
//!   generic "stretch" or "16:9" setting does nothing and is refused here,
//! * "internal resolution" renders the 3D scene at an integer multiple of the
//!   PS1's native size, which gets expensive quickly.
//!
//! Edits are line based: comments, ordering and line endings in the player's
//! files survive, and the first version of a file is kept beside it as
//! `<name>.aura-backup`.

use crate::ps1_build::PACKAGE_MARKER;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

// ---------------------------------------------------------------------------
// Value sets (taken from the runtime's `docs/config_schema.md`)
// ---------------------------------------------------------------------------

pub const RENDERERS: &[&str] = &["software", "opengl", "vulkan"];
pub const VSYNC_MODES: &[&str] = &["on", "off", "immediate", "adaptive", "vrr"];
pub const RESOLUTION_PRESETS: &[&str] = &["native", "720p", "1080p", "1440p", "4k", "5k", "8k", "display"];
/// `window_width` accepts 640 to 7680.
pub const WINDOW_WIDTH_RANGE: (u32, u32) = (640, 7680);
/// The title's usual display height when its `game.toml` does not say.
pub const DEFAULT_REFERENCE_LINES: u32 = 240;
/// A freeze or compile lock older than this was left by a run that did not
/// finish; a live run touches its lock files continuously.
const STALE_LOCK_AGE: Duration = Duration::from_secs(10 * 60);

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// The player-facing video choices. Field values are the runtime's own
/// vocabulary, so what is shown is exactly what lands in `settings.toml`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PlayOptions {
    /// `software`, `opengl` or `vulkan`.
    pub renderer: String,
    /// A preset (`native`, `720p`, `1080p`, `1440p`, `4k`, `5k`, `8k`,
    /// `display`), a scale such as `3x`, or a number of lines.
    pub internal_resolution: String,
    /// `W:H` between 4:3 and 32:9. Only honoured when a widescreen mod exists.
    pub aspect_ratio: String,
    /// 0 windowed, 1 borderless fullscreen, 2 exclusive fullscreen.
    pub fullscreen: u8,
    /// `on`, `off`, `immediate`, `adaptive` or `vrr`.
    pub vsync: String,
    /// Window width in pixels; 0 leaves the runtime's own choice alone.
    pub window_width: u32,
}

impl Default for PlayOptions {
    fn default() -> Self {
        PlayOptions {
            renderer: "opengl".into(),
            internal_resolution: "native".into(),
            aspect_ratio: "4:3".into(),
            fullscreen: 0,
            vsync: "on".into(),
            window_width: 0,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Choice {
    pub value: String,
    pub label: String,
    pub detail: String,
}

fn choice(value: &str, label: &str, detail: &str) -> Choice {
    Choice { value: value.into(), label: label.into(), detail: detail.into() }
}

/// What the interface may offer, so it never lists a value the runtime would
/// reject or silently ignore.
#[derive(Debug, Clone, Serialize)]
pub struct Choices {
    pub renderers: Vec<Choice>,
    pub resolutions: Vec<Choice>,
    pub fullscreen: Vec<Choice>,
    pub vsync: Vec<Choice>,
    /// Things people ask for that this runtime does not have, with the reason.
    pub unavailable: Vec<Choice>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PresetInfo {
    pub id: String,
    pub label: String,
    pub detail: String,
    /// What the preset sets; `None` leaves the current value alone.
    pub renderer: Option<String>,
    pub internal_resolution: String,
    pub vsync: Option<String>,
}

/// An optional enhancement of the runtime, read from the package's mod
/// manifests and `mods/state.toml`.
#[derive(Debug, Clone, Serialize)]
pub struct ModFeature {
    pub package_id: String,
    pub feature_id: String,
    pub name: String,
    pub description: String,
    pub enabled: bool,
    pub default_enabled: bool,
    /// The package itself says the feature is deprecated or only a heuristic.
    pub deprecated: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    /// `error`, `warn` or `info`.
    pub severity: String,
    pub code: String,
    pub title: String,
    pub detail: String,
    pub fix: Option<String>,
}

fn finding(severity: &str, code: &str, title: &str, detail: String, fix: Option<&str>) -> Finding {
    Finding {
        severity: severity.into(),
        code: code.into(),
        title: title.into(),
        detail,
        fix: fix.map(str::to_string),
    }
}

/// What a clean-up would touch, so the interface can show it before asking.
#[derive(Debug, Clone, Default, Serialize)]
pub struct StateSummary {
    pub cache_bytes: u64,
    pub cache_files: usize,
    pub overlay_captures: bool,
    pub freeze_dumps: usize,
    pub has_last_report: bool,
    pub stale_locks: usize,
    pub saves_bytes: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct Ps1OptionsInfo {
    pub package_dir: String,
    pub title: String,
    pub exe: String,
    pub game_running: bool,
    pub settings_path: String,
    pub settings_exists: bool,
    pub options: PlayOptions,
    /// How heavy the chosen internal resolution is, in words.
    pub resolution_label: String,
    /// Render scale per axis (None for "match display").
    pub internal_scale: Option<u32>,
    pub disc_path: Option<String>,
    pub widescreen_available: bool,
    pub widescreen_mods: Vec<String>,
    /// The game's `game.toml` offers Vulkan (`[video] offer_vulkan`). Without
    /// it the runtime ignores `renderer = "vulkan"` and uses OpenGL.
    pub vulkan_offered: bool,
    pub mods: Vec<ModFeature>,
    pub choices: Choices,
    pub presets: Vec<PresetInfo>,
    pub findings: Vec<Finding>,
    pub state: StateSummary,
}

#[derive(Debug, Clone, Serialize)]
pub struct WriteReport {
    pub settings_path: String,
    pub backup_path: Option<String>,
    /// `key: old -> new` for every value that actually changed.
    pub changed: Vec<String>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ModReport {
    pub state_path: String,
    pub backup_path: Option<String>,
    pub package_id: String,
    pub feature_id: String,
    pub enabled: bool,
    pub changed: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct ResetReport {
    pub backup_dir: Option<String>,
    pub moved: Vec<String>,
    pub bytes: u64,
    pub skipped: Vec<String>,
}

// ---------------------------------------------------------------------------
// A TOML file kept as lines
// ---------------------------------------------------------------------------

/// Settings files are edited in place: keys we do not know, comments and the
/// order the launcher wrote them in must come out the way they went in.
struct Doc {
    lines: Vec<String>,
    crlf: bool,
    final_newline: bool,
}

/// Where a `[section]` or `[[array]]` header line points.
enum Header {
    Table(String),
    Array(String),
}

fn header_of(line: &str) -> Option<Header> {
    let t = line.trim();
    if let Some(rest) = t.strip_prefix("[[") {
        let name = rest.split("]]").next()?.trim();
        return Some(Header::Array(name.to_string()));
    }
    let rest = t.strip_prefix('[')?;
    let name = rest.split(']').next()?.trim();
    Some(Header::Table(name.to_string()))
}

/// `key = value  # comment` -> (key, value text, comment tail incl. spacing).
fn split_assignment(line: &str) -> Option<(String, String, String)> {
    let t = line.trim_start();
    if t.starts_with('#') || t.starts_with('[') {
        return None;
    }
    let eq = t.find('=')?;
    let key = t[..eq].trim().trim_matches('"').to_string();
    if key.is_empty() {
        return None;
    }
    let rest = &t[eq + 1..];
    // The comment starts at the first '#' that is outside a quoted string.
    let (mut in_str, mut quote, mut esc) = (false, '"', false);
    let mut cut = rest.len();
    for (i, c) in rest.char_indices() {
        if in_str {
            if esc {
                esc = false;
            } else if c == '\\' && quote == '"' {
                esc = true;
            } else if c == quote {
                in_str = false;
            }
        } else if c == '"' || c == '\'' {
            in_str = true;
            quote = c;
        } else if c == '#' {
            cut = i;
            break;
        }
    }
    let value_part = rest[..cut].trim_end();
    let comment_start = value_part.len();
    Some((key, unquote(value_part.trim()), rest[comment_start..].to_string()))
}

fn unquote(v: &str) -> String {
    let v = v.trim();
    if v.len() >= 2 {
        let (f, l) = (v.as_bytes()[0], v.as_bytes()[v.len() - 1]);
        if (f == b'"' && l == b'"') || (f == b'\'' && l == b'\'') {
            let inner = &v[1..v.len() - 1];
            return inner.replace("\\\\", "\u{0}").replace("\\\"", "\"").replace('\u{0}', "\\");
        }
    }
    v.to_string()
}

fn quote(v: &str) -> String {
    format!("\"{}\"", v.replace('\\', "\\\\").replace('"', "\\\""))
}

impl Doc {
    fn parse(text: &str) -> Doc {
        Doc {
            lines: text.lines().map(str::to_string).collect(),
            crlf: text.contains("\r\n"),
            final_newline: text.ends_with('\n') || text.is_empty(),
        }
    }

    fn read(path: &Path) -> Result<Doc, String> {
        match fs::read(path) {
            Ok(b) => Ok(Doc::parse(&String::from_utf8_lossy(&b))),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Doc::parse("")),
            Err(e) => Err(format!("Cannot read {}: {e}", path.display())),
        }
    }

    fn render(&self) -> String {
        let eol = if self.crlf { "\r\n" } else { "\n" };
        let mut s = self.lines.join(eol);
        if self.final_newline && !self.lines.is_empty() {
            s.push_str(eol);
        }
        s
    }

    /// Line range `(first body line, end)` of the named `[table]`.
    fn table_range(&self, name: &str) -> Option<(usize, usize)> {
        let mut start = None;
        for (i, l) in self.lines.iter().enumerate() {
            match header_of(l) {
                Some(Header::Table(n)) if start.is_none() && n == name => start = Some(i + 1),
                Some(_) if start.is_some() => return Some((start.unwrap(), i)),
                _ => {}
            }
        }
        start.map(|s| (s, self.lines.len()))
    }

    fn get(&self, table: &str, key: &str) -> Option<String> {
        let (s, e) = self.table_range(table)?;
        self.lines[s..e].iter().find_map(|l| {
            let (k, v, _) = split_assignment(l)?;
            (k == key).then_some(v)
        })
    }

    /// Every `[[name]]` block as a line range (header line through the line
    /// before the next header).
    fn blocks(&self, name: &str) -> Vec<(usize, usize)> {
        let mut out = Vec::new();
        let mut open: Option<usize> = None;
        for (i, l) in self.lines.iter().enumerate() {
            if let Some(h) = header_of(l) {
                if let Some(s) = open.take() {
                    out.push((s, i));
                }
                if matches!(&h, Header::Array(n) if n == name) {
                    open = Some(i);
                }
            }
        }
        if let Some(s) = open {
            out.push((s, self.lines.len()));
        }
        out
    }

    fn block_get(&self, (s, e): (usize, usize), key: &str) -> Option<String> {
        self.lines[s + 1..e].iter().find_map(|l| {
            let (k, v, _) = split_assignment(l)?;
            (k == key).then_some(v)
        })
    }

    /// Put `key = value` into `lines[s..e]` (a table body or a block), keeping
    /// an existing line's layout and trailing comment. Returns the old value.
    fn set_in(&mut self, s: usize, e: usize, key: &str, value: &str) -> Option<String> {
        for i in s..e {
            if let Some((k, old, comment)) = split_assignment(&self.lines[i]) {
                if k == key {
                    let line = &self.lines[i];
                    let eq = line.find('=').unwrap_or(0);
                    self.lines[i] = format!("{} {value}{comment}", &line[..=eq]);
                    return Some(old);
                }
            }
        }
        // Not there yet: append after the last non-blank line of the range.
        let mut at = e;
        while at > s && self.lines[at - 1].trim().is_empty() {
            at -= 1;
        }
        self.lines.insert(at, format!("{key} = {value}"));
        None
    }

    fn set(&mut self, table: &str, key: &str, value: &str) -> Option<String> {
        match self.table_range(table) {
            Some((s, e)) => self.set_in(s, e, key, value),
            None => {
                if self.lines.last().map(|l| !l.trim().is_empty()).unwrap_or(false) {
                    self.lines.push(String::new());
                }
                self.lines.push(format!("[{table}]"));
                self.lines.push(format!("{key} = {value}"));
                self.final_newline = true;
                None
            }
        }
    }
}

/// Write beside the target and swap in, keeping the first version of the file.
fn write_with_backup(path: &Path, text: &str) -> Result<Option<PathBuf>, String> {
    let mut backup = None;
    if path.is_file() {
        let b = PathBuf::from(format!("{}.aura-backup", path.display()));
        if !b.exists() {
            fs::copy(path, &b).map_err(|e| format!("Cannot back up {}: {e}", path.display()))?;
            backup = Some(b);
        }
    }
    let tmp = PathBuf::from(format!("{}.aura-tmp", path.display()));
    fs::write(&tmp, text).map_err(|e| format!("Cannot write {}: {e}", tmp.display()))?;
    fs::rename(&tmp, path).map_err(|e| {
        let _ = fs::remove_file(&tmp);
        format!("Cannot replace {}: {e}", path.display())
    })?;
    Ok(backup)
}

// ---------------------------------------------------------------------------
// The package
// ---------------------------------------------------------------------------

struct PackageMarker {
    exe: PathBuf,
    title: String,
}

/// The folder must be one Aura packaged (its marker names a program that is
/// present). Everything else in this module refuses other folders, so the
/// interface cannot be used to edit arbitrary files.
fn load_marker(dir: &Path) -> Result<PackageMarker, String> {
    let text = fs::read_to_string(dir.join(PACKAGE_MARKER)).map_err(|_| {
        format!(
            "{} is not a game folder Aura built (no {PACKAGE_MARKER} in it).",
            dir.display()
        )
    })?;
    let v: serde_json::Value = serde_json::from_str(&text).map_err(|e| format!("{PACKAGE_MARKER} is unreadable: {e}"))?;
    if v.get("aura_package").is_none() {
        return Err(format!("{PACKAGE_MARKER} in {} is not an Aura package marker.", dir.display()));
    }
    let exe = v.get("exe").and_then(|e| e.as_str()).ok_or("The package marker names no program.")?;
    // The marker is data: keep it to a file name so it can't point elsewhere.
    if Path::new(exe).file_name().map(|n| n != std::ffi::OsStr::new(exe)).unwrap_or(true) {
        return Err("The package marker names a program outside the folder.".into());
    }
    let title = v.get("title").and_then(|t| t.as_str()).unwrap_or(exe).to_string();
    Ok(PackageMarker { exe: dir.join(exe), title })
}

/// Best effort: a program that is running cannot be opened for writing.
pub fn game_running(exe: &Path) -> bool {
    if !exe.is_file() {
        return false;
    }
    match fs::OpenOptions::new().write(true).open(exe) {
        Ok(_) => false,
        Err(e) => matches!(e.raw_os_error(), Some(32) | Some(26)),
    }
}

fn dir_stats(dir: &Path) -> (u64, usize) {
    let (mut bytes, mut files) = (0u64, 0usize);
    let Ok(rd) = fs::read_dir(dir) else { return (0, 0) };
    for e in rd.flatten() {
        let Ok(md) = e.metadata() else { continue };
        if md.is_dir() {
            let (b, f) = dir_stats(&e.path());
            bytes += b;
            files += f;
        } else {
            bytes += md.len();
            files += 1;
        }
    }
    (bytes, files)
}

// ---------------------------------------------------------------------------
// Resolution arithmetic
// ---------------------------------------------------------------------------

/// Integer render scale per axis for an `internal_resolution` value, given the
/// title's reference height. `None` for "match display" (it depends on the
/// monitor) and for values that are not understood.
pub fn internal_scale(res: &str, reference_lines: u32) -> Option<u32> {
    let reference = reference_lines.clamp(120, 1024);
    let lines = |target: u32| target.div_ceil(reference);
    let r = res.trim().to_ascii_lowercase();
    match r.as_str() {
        "native" => Some(1),
        "720p" => Some(lines(720)),
        "1080p" => Some(lines(1080)),
        "1440p" => Some(lines(1440)),
        "4k" => Some(lines(2160)),
        "5k" => Some(lines(2880)),
        "8k" => Some(lines(4320)),
        "display" => None,
        _ => {
            if let Some(n) = r.strip_suffix('x') {
                return n.parse::<u32>().ok().filter(|n| (1..=32).contains(n));
            }
            r.parse::<u32>().ok().filter(|l| (120..=8640).contains(l)).map(lines)
        }
    }
}

/// The `supersampling` value an older runtime would use for the same preset;
/// the launcher writes it beside the preset (`min(scale, 4)`).
fn legacy_supersampling(scale: u32) -> u32 {
    scale.clamp(1, 4)
}

pub fn describe_resolution(res: &str, reference_lines: u32) -> String {
    match internal_scale(res, reference_lines) {
        Some(1) => "Native: the PS1's own resolution (lightest).".into(),
        Some(s) => format!(
            "{s}x per side, about {}x the pixels of native ({}).",
            s * s,
            if s >= 9 {
                "very demanding: lower this first if the game stutters or hangs"
            } else if s >= 5 {
                "demanding"
            } else {
                "moderate"
            }
        ),
        None if res.eq_ignore_ascii_case("display") => {
            "Matches your monitor's height; on a 4K screen that is as heavy as 4K.".into()
        }
        None => "Unrecognised value.".into(),
    }
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

fn parse_aspect(a: &str) -> Option<(u32, u32)> {
    let (w, h) = a.trim().split_once(':')?;
    let (w, h) = (w.trim().parse::<u32>().ok()?, h.trim().parse::<u32>().ok()?);
    (w > 0 && h > 0).then_some((w, h))
}

/// Refuse values the runtime would reject, ignore or clamp. `widescreen`
/// says whether the package carries a widescreen mod.
pub fn validate_options(o: &PlayOptions, widescreen: bool) -> Result<(), String> {
    if !RENDERERS.contains(&o.renderer.as_str()) {
        return Err(format!("renderer must be one of {} (got \"{}\").", RENDERERS.join(", "), o.renderer));
    }
    if internal_scale(&o.internal_resolution, DEFAULT_REFERENCE_LINES).is_none()
        && !o.internal_resolution.eq_ignore_ascii_case("display")
    {
        return Err(format!(
            "internal_resolution must be one of {}, a scale such as 3x, or a number of lines from 120 to 8640 (got \"{}\").",
            RESOLUTION_PRESETS.join(", "),
            o.internal_resolution
        ));
    }
    if o.fullscreen > 2 {
        return Err("fullscreen must be 0 (windowed), 1 (borderless) or 2 (exclusive).".into());
    }
    if !VSYNC_MODES.contains(&o.vsync.as_str()) {
        return Err(format!("vsync must be one of {} (got \"{}\").", VSYNC_MODES.join(", "), o.vsync));
    }
    if o.window_width != 0 && !(WINDOW_WIDTH_RANGE.0..=WINDOW_WIDTH_RANGE.1).contains(&o.window_width) {
        return Err(format!(
            "window_width must be 0 (leave alone) or {} to {}.",
            WINDOW_WIDTH_RANGE.0, WINDOW_WIDTH_RANGE.1
        ));
    }
    let (w, h) = parse_aspect(&o.aspect_ratio)
        .ok_or_else(|| format!("aspect_ratio must look like 16:9 (got \"{}\").", o.aspect_ratio))?;
    // Between 4:3 and 32:9, compared without floating point.
    if w * 3 < h * 4 || w * 9 > h * 32 {
        return Err("aspect_ratio must be between 4:3 and 32:9.".into());
    }
    if (w * 3 != h * 4) && !widescreen {
        return Err(format!(
            "This game has no widescreen mod, so the runtime would put {} back to 4:3 at start-up. \
             The picture is only widened by a per-game widescreen mod; there is no generic stretch.",
            o.aspect_ratio
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Presets and choices
// ---------------------------------------------------------------------------

pub fn presets() -> Vec<PresetInfo> {
    let p = |id: &str, label: &str, detail: &str, renderer: Option<&str>, res: &str, vsync: Option<&str>| PresetInfo {
        id: id.into(),
        label: label.into(),
        detail: detail.into(),
        renderer: renderer.map(str::to_string),
        internal_resolution: res.into(),
        vsync: vsync.map(str::to_string),
    };
    vec![
        p(
            "safe",
            "Safe",
            "OpenGL, native resolution, vsync on. The lightest setup; use it to see whether a problem is caused by the video settings.",
            Some("opengl"),
            "native",
            Some("on"),
        ),
        p("balanced", "Balanced (720p)", "3x internal resolution: sharper than native, still light.", None, "720p", None),
        p("sharp", "Sharp (1080p)", "5x internal resolution. Needs a reasonable GPU.", None, "1080p", None),
        p(
            "max",
            "Maximum (1440p)",
            "6x internal resolution. Heavy. 4K and above are available by hand but are the most likely to stutter or hang.",
            None,
            "1440p",
            None,
        ),
    ]
}

/// Apply a preset to `o` (only the resolution, plus renderer and vsync for
/// "safe"; fullscreen, window size and aspect are left as they are).
#[allow(dead_code)] // the app applies presets in the UI from `presets()`; the CLI calls this
pub fn apply_preset(o: &mut PlayOptions, id: &str) -> Result<(), String> {
    let all = presets();
    let Some(p) = all.iter().find(|p| p.id == id) else {
        return Err(format!(
            "Unknown preset \"{id}\" (use {}).",
            all.iter().map(|p| p.id.clone()).collect::<Vec<_>>().join(", ")
        ));
    };
    if let Some(r) = &p.renderer {
        o.renderer = r.clone();
    }
    o.internal_resolution = p.internal_resolution.clone();
    if let Some(v) = &p.vsync {
        o.vsync = v.clone();
    }
    Ok(())
}

pub fn choices() -> Choices {
    Choices {
        renderers: vec![
            choice("opengl", "OpenGL", "The default and the best tested."),
            choice(
                "vulkan",
                "Vulkan",
                "Experimental in PSXRecomp. Worth trying if OpenGL stutters or glitches. Choosing it also sets offer_vulkan in the game's game.toml, which the runtime requires.",
            ),
            choice("software", "Software", "CPU rendering: slowest, but independent of the graphics driver. Useful to rule the GPU out."),
        ],
        resolutions: vec![
            choice("native", "Native", "The PS1's own resolution."),
            choice("720p", "720p (3x)", "Moderate."),
            choice("1080p", "1080p (5x)", "Demanding."),
            choice("1440p", "1440p (6x)", "Heavy."),
            choice("4k", "4K (9x)", "Very heavy: 81x the pixels of native."),
        ],
        fullscreen: vec![
            choice("0", "Windowed", ""),
            choice("1", "Borderless fullscreen", "Fills the desktop; alt-tab friendly."),
            choice("2", "Exclusive fullscreen", "Takes over the display."),
        ],
        vsync: vec![
            choice("on", "On", "Tear-free, locked to the monitor."),
            choice("adaptive", "Adaptive", "Tears instead of stuttering when it falls behind."),
            choice("vrr", "VRR", "For variable-refresh-rate monitors."),
            choice("immediate", "Immediate", "No waiting for the monitor."),
            choice("off", "Off", "Uncapped; can tear."),
        ],
        unavailable: vec![
            choice(
                "direct3d12",
                "DirectX 12",
                "PSXRecomp has no Direct3D renderer for PS1 games (Direct3D 12 exists only for N64 recompilations). OpenGL and Vulkan are the GPU choices.",
            ),
            choice(
                "stretch",
                "Stretch / 16:9",
                "The runtime widens the picture only through a per-game widescreen mod; without one it stays 4:3. Stretching 4:3 art to 16:9 is not offered.",
            ),
        ],
    }
}

// ---------------------------------------------------------------------------
// Reading the package
// ---------------------------------------------------------------------------

/// The runtime only honours `renderer = "vulkan"` when the game's own
/// `game.toml` opts in; otherwise it logs a note and uses OpenGL.
fn vulkan_offered(game: &Doc) -> bool {
    game.get("video", "offer_vulkan").map(|v| truthy(&v)).unwrap_or(false)
}

fn reference_lines(game: &Doc) -> u32 {
    game.get("video", "resolution_reference_lines")
        .and_then(|v| v.trim().parse::<u32>().ok())
        .unwrap_or(DEFAULT_REFERENCE_LINES)
}

/// settings.toml, then the game's own game.toml, then the runtime default.
fn lookup(settings: &Doc, game: &Doc, key: &str) -> Option<String> {
    settings.get("video", key).or_else(|| game.get("video", key))
}

fn read_play_options(settings: &Doc, game: &Doc) -> PlayOptions {
    let d = PlayOptions::default();
    let resolution = lookup(settings, game, "internal_resolution")
        .filter(|v| !v.trim().is_empty())
        .or_else(|| {
            // Older files carry only the legacy factor.
            lookup(settings, game, "supersampling")
                .and_then(|v| v.trim().parse::<u32>().ok())
                .filter(|n| *n > 1)
                .map(|n| format!("{n}x"))
        })
        .unwrap_or(d.internal_resolution);
    PlayOptions {
        renderer: lookup(settings, game, "renderer").unwrap_or(d.renderer).to_ascii_lowercase(),
        internal_resolution: resolution,
        aspect_ratio: lookup(settings, game, "aspect_ratio").unwrap_or(d.aspect_ratio),
        fullscreen: lookup(settings, game, "fullscreen")
            .and_then(|v| v.trim().parse::<u8>().ok())
            .unwrap_or(d.fullscreen),
        vsync: lookup(settings, game, "vsync").unwrap_or(d.vsync).to_ascii_lowercase(),
        window_width: lookup(settings, game, "window_width")
            .and_then(|v| v.trim().parse::<u32>().ok())
            .unwrap_or(d.window_width),
    }
}

/// Packages whose id or folder name says "widescreen" (or similar). The
/// runtime widens the picture only through such a mod.
fn find_widescreen_mods(dir: &Path) -> Vec<String> {
    let mut found = Vec::new();
    for sub in ["mods/bundled", "mods/installed"] {
        let Ok(rd) = fs::read_dir(dir.join(sub)) else { continue };
        for e in rd.flatten() {
            let name = e.file_name().to_string_lossy().to_string();
            let l = name.to_ascii_lowercase();
            if ["widescreen", "ultrawide", "wide-view", "aspect"].iter().any(|k| l.contains(k)) {
                found.push(name);
            }
        }
    }
    found.sort();
    found.dedup();
    found
}

/// Highest-numbered version folder of a bundled package.
fn newest_version_dir(pkg: &Path) -> Option<PathBuf> {
    let mut dirs: Vec<PathBuf> = fs::read_dir(pkg).ok()?.flatten().map(|e| e.path()).filter(|p| p.is_dir()).collect();
    dirs.sort();
    dirs.pop()
}

fn truthy(v: &str) -> bool {
    matches!(v.trim().to_ascii_lowercase().as_str(), "true" | "1" | "yes" | "on")
}

/// Every feature the package's manifests declare, with its current switch.
pub fn read_mods(dir: &Path) -> Vec<ModFeature> {
    let state = Doc::read(&dir.join("mods").join("state.toml")).unwrap_or_else(|_| Doc::parse(""));
    let state_blocks = state.blocks("feature");
    let mut out = Vec::new();
    let Ok(rd) = fs::read_dir(dir.join("mods").join("bundled")) else { return out };
    let mut pkgs: Vec<PathBuf> = rd.flatten().map(|e| e.path()).filter(|p| p.is_dir()).collect();
    pkgs.sort();
    for pkg in pkgs {
        let Some(ver) = newest_version_dir(&pkg) else { continue };
        let Ok(doc) = Doc::read(&ver.join("manifest.toml")) else { continue };
        let package_id = doc
            .lines
            .iter()
            .find_map(|l| {
                let (k, v, _) = split_assignment(l)?;
                (k == "id").then_some(v)
            })
            .unwrap_or_else(|| pkg.file_name().unwrap_or_default().to_string_lossy().to_string());
        for b in doc.blocks("feature") {
            let Some(feature_id) = doc.block_get(b, "id") else { continue };
            let default_enabled = doc.block_get(b, "default_enabled").map(|v| truthy(&v)).unwrap_or(false);
            let name = doc.block_get(b, "name").unwrap_or_else(|| feature_id.clone());
            let description = doc.block_get(b, "description").unwrap_or_default();
            let switched = state_blocks.iter().find_map(|sb| {
                (state.block_get(*sb, "package_id").as_deref() == Some(package_id.as_str())
                    && state.block_get(*sb, "id").as_deref() == Some(feature_id.as_str()))
                .then(|| state.block_get(*sb, "enabled").map(|v| truthy(&v)))
                .flatten()
            });
            let lower = format!("{name} {description}").to_ascii_lowercase();
            out.push(ModFeature {
                package_id: package_id.clone(),
                feature_id,
                name,
                description,
                enabled: switched.unwrap_or(default_enabled),
                default_enabled,
                deprecated: lower.contains("deprecated") || lower.contains("heuristic"),
            });
        }
    }
    out
}

/// Parse a freeze dump or run report into a few comparable facts.
struct Dump {
    file: String,
    frame: Option<u64>,
    pc: Option<String>,
    func: Option<String>,
    kind: Option<String>,
    /// Wall-clock second the dump was written; dumps of one freeze share it.
    epoch: Option<u64>,
}

fn read_dump(path: &Path) -> Option<Dump> {
    let v: serde_json::Value = serde_json::from_slice(&fs::read(path).ok()?).ok()?;
    let s = |p: &str| v.pointer(p).and_then(|x| x.as_str()).map(str::to_string);
    Some(Dump {
        file: path.file_name()?.to_string_lossy().to_string(),
        frame: v.get("frame_count").or_else(|| v.get("frame")).and_then(|x| x.as_u64()),
        pc: s("/cpu/pc"),
        func: s("/current_func").or_else(|| s("/last_func_addr")),
        kind: s("/wedge_kind_name"),
        epoch: v.get("wall_clock_epoch").and_then(|x| x.as_u64()),
    })
}

fn freeze_dump_paths(dir: &Path) -> Vec<PathBuf> {
    let mut v: Vec<PathBuf> = fs::read_dir(dir)
        .map(|rd| {
            rd.flatten()
                .map(|e| e.path())
                .filter(|p| {
                    let n = p.file_name().map(|n| n.to_string_lossy().to_ascii_lowercase()).unwrap_or_default();
                    n.starts_with("psx_freeze_dump_") && n.ends_with(".json")
                })
                .collect()
        })
        .unwrap_or_default();
    v.sort();
    v
}

fn stale_locks(cache: &Path) -> usize {
    let Ok(rd) = fs::read_dir(cache) else { return 0 };
    rd.flatten()
        .filter(|e| {
            let n = e.file_name().to_string_lossy().to_ascii_lowercase();
            n.ends_with(".lock") || n.ends_with(".pair-lock")
        })
        .filter(|e| {
            e.metadata()
                .and_then(|m| m.modified())
                .ok()
                .and_then(|t| SystemTime::now().duration_since(t).ok())
                .map(|age| age >= STALE_LOCK_AGE)
                .unwrap_or(false)
        })
        .count()
}

fn summarize_state(dir: &Path) -> StateSummary {
    let (cache_bytes, cache_files) = dir_stats(&dir.join("cache"));
    StateSummary {
        cache_bytes,
        cache_files,
        overlay_captures: dir.join("overlay_captures.json").exists() || dir.join("overlay_captures.json.d").exists(),
        freeze_dumps: freeze_dump_paths(dir).len(),
        has_last_report: dir.join("psx_last_run_report.json").is_file(),
        stale_locks: stale_locks(&dir.join("cache")),
        saves_bytes: dir_stats(&dir.join("saves")).0,
    }
}

/// What looks wrong with this package, most important first.
pub fn diagnose(dir: &Path, o: &PlayOptions, mods: &[ModFeature], widescreen: bool, reference: u32) -> Vec<Finding> {
    let mut f = Vec::new();
    let state = summarize_state(dir);

    // The disc the game points at.
    if let Ok(s) = Doc::read(&dir.join("settings.toml")) {
        if let Some(p) = s.get("disc", "path").filter(|p| !p.trim().is_empty()) {
            if !Path::new(&p).is_file() {
                f.push(finding(
                    "error",
                    "disc-missing",
                    "The disc image can't be found",
                    format!("The game is set to read {p}, which is not there (moved, renamed or on a drive that is not connected)."),
                    Some("Reconnect the drive or put the image back; the game asks for it again if it cannot find it."),
                ));
            }
        }
    }

    // Resolution.
    if let Some(s) = internal_scale(&o.internal_resolution, reference) {
        if s >= 6 {
            f.push(finding(
                if s >= 9 { "warn" } else { "info" },
                "resolution-heavy",
                "The internal resolution is very high",
                format!(
                    "{} ({}x per side, {}x the pixels of native). Every frame is drawn that large before it is shrunk to the window, \
                     which costs GPU time and video memory. Stutter, slow loading screens and stalls are the usual symptoms.",
                    o.internal_resolution, s, s * s
                ),
                Some("Pick Balanced (720p) or Sharp (1080p); Safe rules the video settings out."),
            ));
        }
    }

    // Mods.
    for m in mods.iter().filter(|m| m.enabled) {
        if m.deprecated {
            f.push(finding(
                "warn",
                "mod-deprecated",
                &format!("\"{}\" is switched on", m.name),
                "The package describes it as deprecated / a heuristic, not a verified setting for this game. \
                 Features like this change timing, so audio glitches, movie (FMV) problems and freezes around loading screens \
                 are things to try switching it off for."
                    .to_string(),
                Some("Switch it off in the Enhancements list and play again."),
            ));
        } else if m.package_id.ends_with(".pgxp") {
            f.push(finding(
                "info",
                "mod-pgxp",
                "PGXP is switched on",
                "PGXP changes how 3D geometry is calculated. It removes wobble in many games but is a known source of glitches in some."
                    .into(),
                Some("Switch it off to compare."),
            ));
        }
    }

    // Past freezes. The runtime writes two dumps for one freeze (a slow-frames
    // note, then the hard freeze), so dumps within half a minute of each other
    // count as one event.
    let dumps: Vec<Dump> = freeze_dump_paths(dir).iter().filter_map(|p| read_dump(p)).collect();
    if !dumps.is_empty() {
        struct Place {
            label: String,
            nonzero_pc: bool,
            epochs: Vec<u64>,
        }
        let mut places: Vec<Place> = Vec::new();
        for d in &dumps {
            let pc = d.pc.clone().unwrap_or_else(|| "?".into());
            let label = format!(
                "{} in {} (pc {pc})",
                d.kind.clone().unwrap_or_else(|| "freeze".into()),
                d.func.clone().unwrap_or_else(|| "?".into())
            );
            let nonzero_pc = pc.trim_start_matches("0x").trim_start_matches('0') != "" && pc != "?";
            match places.iter_mut().find(|x| x.label == label) {
                Some(x) => x.epochs.push(d.epoch.unwrap_or(0)),
                None => places.push(Place { label, nonzero_pc, epochs: vec![d.epoch.unwrap_or(0)] }),
            }
        }
        let events = |e: &Vec<u64>| {
            let mut sorted = e.clone();
            sorted.sort_unstable();
            let mut n = 0;
            let mut last: Option<u64> = None;
            for x in sorted {
                if last.map(|l| x.saturating_sub(l) >= 30).unwrap_or(true) {
                    n += 1;
                    last = Some(x);
                }
            }
            n
        };
        let summary = places.iter().map(|x| format!("{} x{}", x.label, events(&x.epochs))).collect::<Vec<_>>().join("; ");
        let repeated = places.iter().any(|x| x.nonzero_pc && events(&x.epochs) >= 2);
        let latest = dumps.last().unwrap();
        f.push(finding(
            "warn",
            "freeze-dumps",
            &format!("{} freeze report(s) from earlier runs", dumps.len()),
            format!(
                "The runtime's watchdog recorded that the game stopped making progress: {summary}. The latest ({}) was at frame {}.{}",
                latest.file,
                latest.frame.map(|n| n.to_string()).unwrap_or_else(|| "?".into()),
                if repeated {
                    " The same place came back in more than one run, which points at the recompiled game rather than at your settings."
                } else {
                    ""
                }
            ),
            Some("Reset the recompiler state. If it stops at the same place again, send the freeze report to PSXRecomp."),
        ));
    }

    // Leftovers of a killed run.
    if state.stale_locks > 0 {
        f.push(finding(
            "warn",
            "stale-locks",
            "Compile locks were left behind",
            format!(
                "{} lock file(s) in the overlay cache are older than {} minutes. They are left by a run that was killed in the middle of \
                 compiling an overlay and can keep later runs from using the cache.",
                state.stale_locks,
                STALE_LOCK_AGE.as_secs() / 60
            ),
            Some("Reset the recompiler state (saves are kept)."),
        ));
    }

    // Aspect ratio that will not take effect.
    if parse_aspect(&o.aspect_ratio).map(|(w, h)| w * 3 != h * 4).unwrap_or(false) && !widescreen {
        f.push(finding(
            "info",
            "aspect-ignored",
            "The aspect ratio setting has no effect",
            format!(
                "settings.toml asks for {}, but this game has no widescreen mod, so the runtime starts it at 4:3 anyway.",
                o.aspect_ratio
            ),
            None,
        ));
    }

    if o.renderer == "vulkan" {
        let game = Doc::read(&dir.join("game.toml")).unwrap_or_else(|_| Doc::parse(""));
        if vulkan_offered(&game) {
            f.push(finding(
                "info",
                "renderer-vulkan",
                "Vulkan is experimental",
                "PSXRecomp marks the Vulkan renderer experimental. If the picture or stability is worse than OpenGL, switch back.".into(),
                None,
            ));
        } else {
            f.push(finding(
                "warn",
                "vulkan-not-offered",
                "Vulkan is selected but this game does not offer it",
                "settings.toml asks for Vulkan, but the game's game.toml does not set offer_vulkan, so the runtime ignores the \
                 setting and starts on OpenGL."
                    .into(),
                Some("Save the video settings from this screen again: choosing Vulkan sets offer_vulkan for you."),
            ));
        }
    }

    let order = |s: &str| match s {
        "error" => 0,
        "warn" => 1,
        _ => 2,
    };
    f.sort_by_key(|x| order(&x.severity));
    f
}

/// Everything the options screen needs, in one call.
pub fn read_options(dir: &Path) -> Result<Ps1OptionsInfo, String> {
    let marker = load_marker(dir)?;
    let settings_path = dir.join("settings.toml");
    let settings = Doc::read(&settings_path)?;
    let game = Doc::read(&dir.join("game.toml")).unwrap_or_else(|_| Doc::parse(""));
    let reference = reference_lines(&game);
    let options = read_play_options(&settings, &game);
    let widescreen_mods = find_widescreen_mods(dir);
    let widescreen_available = !widescreen_mods.is_empty();
    let mods = read_mods(dir);
    let findings = diagnose(dir, &options, &mods, widescreen_available, reference);
    Ok(Ps1OptionsInfo {
        package_dir: dir.to_string_lossy().to_string(),
        title: marker.title,
        exe: marker.exe.to_string_lossy().to_string(),
        game_running: game_running(&marker.exe),
        settings_path: settings_path.to_string_lossy().to_string(),
        settings_exists: settings_path.is_file(),
        resolution_label: describe_resolution(&options.internal_resolution, reference),
        internal_scale: internal_scale(&options.internal_resolution, reference),
        disc_path: settings.get("disc", "path").filter(|p| !p.is_empty()),
        options,
        widescreen_available,
        widescreen_mods,
        vulkan_offered: vulkan_offered(&game),
        mods,
        choices: choices(),
        presets: presets(),
        findings,
        state: summarize_state(dir),
    })
}

// ---------------------------------------------------------------------------
// Writing
// ---------------------------------------------------------------------------

/// Save `o` into the package's settings.toml. Only the keys this module owns
/// are touched.
pub fn write_options(dir: &Path, o: &PlayOptions) -> Result<WriteReport, String> {
    let marker = load_marker(dir)?;
    let widescreen = !find_widescreen_mods(dir).is_empty();
    validate_options(o, widescreen)?;

    let path = dir.join("settings.toml");
    let mut doc = Doc::read(&path)?;
    let game = Doc::read(&dir.join("game.toml")).unwrap_or_else(|_| Doc::parse(""));
    let reference = reference_lines(&game);
    let mut changed = Vec::new();
    let mut put = |doc: &mut Doc, key: &str, value: String, shown: String| {
        let old = doc.set("video", key, &value);
        let old_shown = old.unwrap_or_else(|| "(not set)".into());
        if old_shown != shown {
            changed.push(format!("{key}: {old_shown} -> {shown}"));
        }
    };
    put(&mut doc, "renderer", quote(&o.renderer), o.renderer.clone());
    let res = o.internal_resolution.trim().to_ascii_lowercase();
    put(&mut doc, "internal_resolution", quote(&res), res.clone());
    if let Some(scale) = internal_scale(&res, reference) {
        // Keep the legacy factor consistent so an older runtime agrees.
        let ss = legacy_supersampling(scale);
        put(&mut doc, "supersampling", ss.to_string(), ss.to_string());
    }
    put(&mut doc, "aspect_ratio", quote(o.aspect_ratio.trim()), o.aspect_ratio.trim().to_string());
    put(&mut doc, "fullscreen", o.fullscreen.to_string(), o.fullscreen.to_string());
    put(&mut doc, "vsync", quote(&o.vsync), o.vsync.clone());
    if o.window_width != 0 {
        put(&mut doc, "window_width", o.window_width.to_string(), o.window_width.to_string());
    }

    let mut warnings = Vec::new();
    if o.renderer == "vulkan" && !vulkan_offered(&game) {
        // The runtime ignores the setting unless the game offers Vulkan.
        let game_path = dir.join("game.toml");
        if game_path.is_file() {
            let mut g = Doc::read(&game_path)?;
            g.set("video", "offer_vulkan", "true");
            write_with_backup(&game_path, &g.render())?;
            changed.push("game.toml offer_vulkan: (not set) -> true".to_string());
        } else {
            warnings.push(
                "game.toml was not found, so Vulkan could not be offered; the runtime may start on OpenGL instead.".to_string(),
            );
        }
    }
    if game_running(&marker.exe) {
        warnings.push(
            "The game is running. It saves its own settings when it closes and may overwrite this change: close it first, then apply again."
                .to_string(),
        );
    }
    let backup = write_with_backup(&path, &doc.render())?;
    Ok(WriteReport {
        settings_path: path.to_string_lossy().to_string(),
        backup_path: backup.map(|b| b.to_string_lossy().to_string()),
        changed,
        warnings,
    })
}

/// Switch one optional enhancement on or off in `mods/state.toml`. The
/// feature must be declared by one of the package's own mod manifests.
pub fn set_mod_enabled(dir: &Path, package_id: &str, feature_id: &str, enabled: bool) -> Result<ModReport, String> {
    load_marker(dir)?;
    if !read_mods(dir).iter().any(|m| m.package_id == package_id && m.feature_id == feature_id) {
        return Err(format!("This game has no mod feature \"{feature_id}\" in package \"{package_id}\"."));
    }
    let path = dir.join("mods").join("state.toml");
    let mut doc = if path.is_file() { Doc::read(&path)? } else { Doc::parse("format_version = 2\n") };
    let value = if enabled { "true" } else { "false" };

    let existing = doc.blocks("feature").into_iter().find(|b| {
        doc.block_get(*b, "package_id").as_deref() == Some(package_id) && doc.block_get(*b, "id").as_deref() == Some(feature_id)
    });
    let mut changed = true;
    match existing {
        Some((s, e)) => {
            // `[feature.resources]` and other sub-tables sit after the keys we
            // want; stop at the first sub-header so `enabled` lands above it.
            let body_end = (s + 1..e).find(|i| header_of(&doc.lines[*i]).is_some()).unwrap_or(e);
            let old = doc.set_in(s + 1, body_end, "enabled", value);
            changed = old.map(|o| truthy(&o) != enabled).unwrap_or(true);
        }
        None => {
            let has_package = doc.blocks("package").into_iter().any(|b| doc.block_get(b, "id").as_deref() == Some(package_id));
            if !has_package {
                doc.lines.push(String::new());
                doc.lines.push("[[package]]".into());
                doc.lines.push(format!("id = {}", quote(package_id)));
            }
            doc.lines.push(String::new());
            doc.lines.push("[[feature]]".into());
            doc.lines.push(format!("package_id = {}", quote(package_id)));
            doc.lines.push(format!("id = {}", quote(feature_id)));
            doc.lines.push(format!("enabled = {value}"));
            doc.final_newline = true;
        }
    }
    let backup = if changed { write_with_backup(&path, &doc.render())? } else { None };
    Ok(ModReport {
        state_path: path.to_string_lossy().to_string(),
        backup_path: backup.map(|b| b.to_string_lossy().to_string()),
        package_id: package_id.to_string(),
        feature_id: feature_id.to_string(),
        enabled,
        changed,
    })
}

// ---------------------------------------------------------------------------
// Resetting generated state
// ---------------------------------------------------------------------------

fn path_bytes(p: &Path) -> u64 {
    match fs::metadata(p) {
        Ok(m) if m.is_dir() => dir_stats(p).0,
        Ok(m) => m.len(),
        Err(_) => 0,
    }
}

/// Move what the runtime generated while playing -- compiled overlay code,
/// captured overlays, freeze reports -- into `aura-state-backup-<time>/`, so
/// the next run starts from the program as built. Nothing is deleted. Save
/// games stay unless `include_saves` is set.
pub fn reset_state(dir: &Path, include_saves: bool) -> Result<ResetReport, String> {
    let marker = load_marker(dir)?;
    if game_running(&marker.exe) {
        return Err("The game is running. Close it first, then reset.".into());
    }
    let mut items: Vec<PathBuf> = vec![
        dir.join("cache"),
        dir.join("overlay_captures.json"),
        dir.join("overlay_captures.json.d"),
        dir.join("psx_freeze_heartbeat.json"),
        dir.join("psx_last_run_report.json"),
    ];
    items.extend(freeze_dump_paths(dir));
    if include_saves {
        items.push(dir.join("saves"));
    }
    items.retain(|p| p.exists());
    if items.is_empty() {
        return Ok(ResetReport { backup_dir: None, moved: vec![], bytes: 0, skipped: vec![] });
    }

    let stamp = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    let mut backup = dir.join(format!("aura-state-backup-{stamp}"));
    let mut n = 1;
    while backup.exists() {
        backup = dir.join(format!("aura-state-backup-{stamp}-{n}"));
        n += 1;
    }
    fs::create_dir_all(&backup).map_err(|e| format!("Cannot create {}: {e}", backup.display()))?;

    let (mut moved, mut skipped, mut bytes) = (Vec::new(), Vec::new(), 0u64);
    for p in items {
        let name = p.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
        let size = path_bytes(&p);
        match fs::rename(&p, backup.join(&name)) {
            Ok(()) => {
                moved.push(name);
                bytes += size;
            }
            Err(e) => skipped.push(format!("{name}: {e}")),
        }
    }
    Ok(ResetReport {
        backup_dir: Some(backup.to_string_lossy().to_string()),
        moved,
        bytes,
        skipped,
    })
}
