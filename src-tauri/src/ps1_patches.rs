//! Fixes Aura carries on top of the pinned PSXRecomp framework.
//!
//! Two kinds, both small and both found by running a real game:
//!
//! * **Framework patches** -- unified diffs against the pinned commit,
//!   embedded in this crate. They are applied to the framework *commit*, not to
//!   its working tree: the diff is applied to a throw-away index
//!   (`GIT_INDEX_FILE`), written out as a commit on top of the pinned one, and
//!   the local `aura-pinned` branch is pointed at it. The project setup script
//!   clones that branch, so the generated project's `psxrecomp/` submodule
//!   carries the fix, while the cache checkout itself stays at the pinned
//!   commit (no line-ending or dirty-tree surprises, and the next build starts
//!   clean). A patch that upstream already contains is detected and skipped; one
//!   that no longer applies stops the build with a clear message instead of
//!   producing a half-fixed game.
//! * **Per-title config** -- extra lines for a game's `game.toml`, keyed by
//!   serial (for example keeping one overlay function on the interpreter).
//!   They are merged without clobbering what the project already has.
//!
//! Nothing here downloads anything.

use crate::ps1_build::PACKAGE_MARKER;
use serde::Serialize;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};

// ---------------------------------------------------------------------------
// Framework patches
// ---------------------------------------------------------------------------

/// A unified diff against the pinned framework, relative to its root.
pub struct FrameworkPatch {
    pub id: &'static str,
    pub title: &'static str,
    /// What goes wrong without it, in a sentence.
    pub why: &'static str,
    pub text: &'static str,
}

/// Every patch Aura carries, in the order they are applied.
pub const FRAMEWORK_PATCHES: &[FrameworkPatch] = &[FrameworkPatch {
    id: "cdrom-keep-announced-sector",
    title: "CD-ROM: keep the announced sector when a read starts",
    why: "Starting a read wiped the sector the last data-ready interrupt announced, so a driver that \
          issues the next ReadN from inside that interrupt and then fetches the sector hung forever \
          (Harry Potter, SLUS-01415, freezes within the first minutes of play).",
    text: include_str!("ps1_patches/cdrom-keep-announced-sector.patch"),
}];

#[derive(Debug, Clone, Serialize)]
pub struct PatchInfo {
    pub id: String,
    pub title: String,
    pub why: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct PatchOutcome {
    pub id: String,
    pub title: String,
    /// `applied` or `already in the pinned framework`.
    pub state: String,
}

/// What a build would carry, for the plan.
pub fn planned() -> Vec<PatchInfo> {
    FRAMEWORK_PATCHES
        .iter()
        .map(|p| PatchInfo { id: p.id.into(), title: p.title.into(), why: p.why.into() })
        .collect()
}

static SCRATCH_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Temporary files (a private index, patch files) removed when dropped.
struct Scratch(Vec<PathBuf>);

impl Scratch {
    fn path(&mut self, tag: &str) -> PathBuf {
        let n = SCRATCH_COUNTER.fetch_add(1, Ordering::SeqCst);
        let p = std::env::temp_dir().join(format!("aura-psxpatch-{}-{n}-{tag}", std::process::id()));
        self.0.push(p.clone());
        p
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        for p in &self.0 {
            let _ = fs::remove_file(p);
        }
    }
}

fn git_cmd(git: &Path, repo: &Path) -> Command {
    let mut c = Command::new(git);
    c.arg("-C").arg(repo).stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped());
    c.env("GIT_TERMINAL_PROMPT", "0");
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        c.creation_flags(0x0800_0000);
    }
    c
}

/// Run `c`; stdout (trimmed) on success, stderr (trimmed) on failure.
fn run(mut c: Command) -> Result<String, String> {
    let out = c.output().map_err(|e| format!("Cannot run git: {e}"))?;
    if out.status.success() {
        Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
    } else {
        let err = String::from_utf8_lossy(&out.stderr).trim().to_string();
        Err(if err.is_empty() { format!("git exited with {}", out.status) } else { err })
    }
}

/// Patches are applied against LF blobs; a checkout that converted the file
/// to CRLF must not break them.
fn lf(text: &str) -> String {
    text.replace("\r\n", "\n")
}

/// Apply `patches` on top of `base` inside `repo` and point `branch` at the
/// result. The working tree and the repository's own index are not touched.
/// Returns what happened to each patch; when nothing needed applying the
/// branch is left alone.
pub fn apply_to_base(
    git: &Path,
    repo: &Path,
    base: &str,
    branch: &str,
    patches: &[FrameworkPatch],
) -> Result<Vec<PatchOutcome>, String> {
    if patches.is_empty() {
        return Ok(vec![]);
    }
    let mut scratch = Scratch(vec![]);
    let index = scratch.path("index");
    let base_full = run({
        let mut c = git_cmd(git, repo);
        c.args(["rev-parse", "--verify", &format!("{base}^{{commit}}")]);
        c
    })
    .map_err(|e| format!("The framework checkout has no commit {base}: {e}"))?;
    run({
        let mut c = git_cmd(git, repo);
        c.env("GIT_INDEX_FILE", &index).args(["read-tree", &base_full]);
        c
    })?;

    let mut outcomes = Vec::new();
    let mut applied: Vec<&FrameworkPatch> = Vec::new();
    for p in patches {
        let file = scratch.path(&format!("{}.patch", p.id));
        fs::write(&file, lf(p.text)).map_err(|e| format!("Cannot write {}: {e}", file.display()))?;
        let apply = |extra: &[&str]| {
            let mut c = git_cmd(git, repo);
            c.env("GIT_INDEX_FILE", &index).arg("apply").arg("--cached").args(extra).arg(&file);
            run(c)
        };
        // Already in the pinned framework: the reverse of the patch applies.
        if apply(&["--reverse", "--check"]).is_ok() {
            outcomes.push(PatchOutcome {
                id: p.id.into(),
                title: p.title.into(),
                state: "already in the pinned framework".into(),
            });
            continue;
        }
        if let Err(e) = apply(&["--check"]) {
            return Err(format!(
                "A PSXRecomp fix Aura carries (\"{}\") does not apply to the framework commit {}: {e}\n\
                 The build was stopped rather than producing a game without it. This means the pinned \
                 framework changed under the patch; build with --no-fixes to use the framework as it is.",
                p.title,
                &base_full[..base_full.len().min(10)]
            ));
        }
        apply(&[])?;
        applied.push(p);
        outcomes.push(PatchOutcome { id: p.id.into(), title: p.title.into(), state: "applied".into() });
    }

    if !applied.is_empty() {
        let tree = run({
            let mut c = git_cmd(git, repo);
            c.env("GIT_INDEX_FILE", &index).arg("write-tree");
            c
        })?;
        let mut msg = format!("Aura: fixes carried on top of {}\n\n", &base_full[..base_full.len().min(10)]);
        for p in &applied {
            msg.push_str(&format!("- {}\n", p.title));
        }
        let commit = run({
            let mut c = git_cmd(git, repo);
            c.env("GIT_AUTHOR_NAME", "Aura Decomp Tool")
                .env("GIT_AUTHOR_EMAIL", "aura@localhost")
                .env("GIT_COMMITTER_NAME", "Aura Decomp Tool")
                .env("GIT_COMMITTER_EMAIL", "aura@localhost")
                .args(["commit-tree", &tree, "-p", &base_full, "-m", &msg]);
            c
        })?;
        run({
            let mut c = git_cmd(git, repo);
            c.args(["update-ref", &format!("refs/heads/{branch}"), &commit]);
            c
        })?;
    }
    Ok(outcomes)
}

// ---------------------------------------------------------------------------
// Per-title config
// ---------------------------------------------------------------------------

/// A list-valued key added to a table of a game's `game.toml`.
pub struct ConfigAddition {
    pub serial: &'static str,
    pub table: &'static str,
    pub key: &'static str,
    /// Items to make sure are in the list (merged with what is there).
    pub values: &'static [&'static str],
    pub why: &'static str,
}

/// Known per-title additions. Keep entries here small and each one explained:
/// they are workarounds for a specific game, not framework behaviour.
pub const CONFIG_ADDITIONS: &[ConfigAddition] = &[ConfigAddition {
    serial: "SLUS-01415",
    table: "runtime",
    key: "overlay_native_block",
    values: &["0x00010CDC"],
    why: "Harry Potter and the Sorcerer's Stone: after the intro the game enters a wait loop in an \
          overlay function that the runtime compiles natively without an interrupt check, so no \
          interrupt is delivered again and the picture stays black. Keeping that one function on the \
          interpreter avoids it.",
}];

#[derive(Debug, Clone, Serialize)]
pub struct ConfigAdditionInfo {
    pub serial: String,
    /// `[runtime] overlay_native_block += 0x00010CDC`
    pub setting: String,
    pub why: String,
}

fn norm_serial(s: &str) -> String {
    s.chars().filter(|c| c.is_ascii_alphanumeric()).map(|c| c.to_ascii_uppercase()).collect()
}

/// The additions that apply to a game with this serial.
pub fn additions_for(serial: &str) -> Vec<&'static ConfigAddition> {
    let want = norm_serial(serial);
    if want.is_empty() {
        return vec![];
    }
    CONFIG_ADDITIONS.iter().filter(|a| norm_serial(a.serial) == want).collect()
}

fn describe(a: &ConfigAddition) -> String {
    format!("[{}] {} += {}", a.table, a.key, a.values.join(", "))
}

pub fn planned_config(serial: Option<&str>) -> Vec<ConfigAdditionInfo> {
    serial
        .map(|s| {
            additions_for(s)
                .into_iter()
                .map(|a| ConfigAdditionInfo { serial: a.serial.into(), setting: describe(a), why: a.why.into() })
                .collect()
        })
        .unwrap_or_default()
}

/// `[name]` (not `[[name]]`), spacing inside the brackets ignored.
fn is_table_header(line: &str, name: &str) -> bool {
    let t = line.trim();
    t.starts_with('[') && !t.starts_with("[[") && t.ends_with(']') && t[1..t.len() - 1].trim() == name
}

fn is_any_header(line: &str) -> bool {
    line.trim_start().starts_with('[')
}

fn key_of(line: &str) -> Option<&str> {
    let t = line.trim_start();
    if t.starts_with('#') || t.starts_with('[') {
        return None;
    }
    let eq = t.find('=')?;
    Some(t[..eq].trim().trim_matches('"'))
}

/// Quoted strings in `s`, ignoring `#` comments outside quotes.
fn quoted_items(s: &str) -> Vec<String> {
    let mut items = Vec::new();
    let mut cur = String::new();
    let (mut in_str, mut q) = (false, '"');
    let mut esc = false;
    for c in s.chars() {
        if in_str {
            if esc {
                cur.push(c);
                esc = false;
            } else if c == '\\' && q == '"' {
                esc = true;
            } else if c == q {
                in_str = false;
                items.push(std::mem::take(&mut cur));
            } else {
                cur.push(c);
            }
        } else if c == '"' || c == '\'' {
            in_str = true;
            q = c;
        } else if c == '#' {
            break;
        }
    }
    items
}

/// Bracket balance of `s` outside quotes and comments.
fn bracket_delta(s: &str) -> i32 {
    let (mut in_str, mut q) = (false, '"');
    let mut d = 0;
    for c in s.chars() {
        if in_str {
            if c == q {
                in_str = false;
            }
        } else if c == '"' || c == '\'' {
            in_str = true;
            q = c;
        } else if c == '#' {
            break;
        } else if c == '[' {
            d += 1;
        } else if c == ']' {
            d -= 1;
        }
    }
    d
}

/// Same item? Hex addresses compare by value, anything else case-insensitively.
fn same_item(a: &str, b: &str) -> bool {
    let hex = |s: &str| u64::from_str_radix(s.trim().trim_start_matches("0x").trim_start_matches("0X"), 16).ok();
    match (hex(a), hex(b)) {
        (Some(x), Some(y)) if a.trim().to_ascii_lowercase().starts_with("0x") && b.trim().to_ascii_lowercase().starts_with("0x") => x == y,
        _ => a.trim().eq_ignore_ascii_case(b.trim()),
    }
}

fn render_list(key: &str, items: &[String]) -> String {
    let body: Vec<String> = items.iter().map(|i| format!("\"{}\"", i.replace('\\', "\\\\").replace('"', "\\\""))).collect();
    format!("{key} = [{}]", body.join(", "))
}

/// Merge `adds` into `text`. Returns the new text and a description of each
/// change made (empty when everything was already there).
pub fn merge_additions(text: &str, adds: &[&ConfigAddition]) -> (String, Vec<String>) {
    let eol = if text.contains("\r\n") { "\r\n" } else { "\n" };
    let had_final_newline = text.ends_with('\n');
    let mut lines: Vec<String> = text.lines().map(str::to_string).collect();
    let mut changes = Vec::new();

    for a in adds {
        let wanted: Vec<String> = a.values.iter().map(|v| v.to_string()).collect();
        let Some(ti) = lines.iter().position(|l| is_table_header(l, a.table)) else {
            if lines.last().map(|l| !l.trim().is_empty()).unwrap_or(false) {
                lines.push(String::new());
            }
            lines.push(format!("[{}]", a.table));
            lines.push(render_list(a.key, &wanted));
            changes.push(format!("added {}", describe(a)));
            continue;
        };
        let end = (ti + 1..lines.len()).find(|&i| is_any_header(&lines[i])).unwrap_or(lines.len());
        match (ti + 1..end).find(|&i| key_of(&lines[i]) == Some(a.key)) {
            Some(ki) => {
                // The value may run over several lines.
                let first = &lines[ki];
                let after_eq = first.find('=').map(|p| &first[p + 1..]).unwrap_or("");
                if !after_eq.trim_start().starts_with('[') {
                    continue; // not a list: leave the user's value alone
                }
                let mut depth = bracket_delta(after_eq);
                let mut last = ki;
                let mut value = after_eq.to_string();
                while depth > 0 && last + 1 < end {
                    last += 1;
                    value.push('\n');
                    value.push_str(&lines[last]);
                    depth += bracket_delta(&lines[last]);
                }
                let mut items = quoted_items(&value);
                let mut added = Vec::new();
                for w in &wanted {
                    if !items.iter().any(|e| same_item(e, w)) {
                        items.push(w.clone());
                        added.push(w.clone());
                    }
                }
                if added.is_empty() {
                    continue;
                }
                lines.splice(ki..=last, [render_list(a.key, &items)]);
                changes.push(format!("extended [{}] {} with {}", a.table, a.key, added.join(", ")));
            }
            None => {
                let mut at = end;
                while at > ti + 1 && lines[at - 1].trim().is_empty() {
                    at -= 1;
                }
                lines.insert(at, render_list(a.key, &wanted));
                changes.push(format!("added {}", describe(a)));
            }
        }
    }

    let mut out = lines.join(eol);
    if had_final_newline || (!changes.is_empty() && !out.is_empty()) {
        out.push_str(eol);
    }
    if changes.is_empty() {
        return (text.to_string(), changes);
    }
    (out, changes)
}

/// Merge the additions for `serial` into the game.toml at `path`. With
/// `backup`, the first version of the file is kept as `<path>.aura-backup`.
pub fn apply_config_to_file(path: &Path, serial: &str, backup: bool) -> Result<Vec<String>, String> {
    let adds = additions_for(serial);
    if adds.is_empty() {
        return Ok(vec![]);
    }
    let text = fs::read_to_string(path).map_err(|e| format!("Cannot read {}: {e}", path.display()))?;
    let (merged, changes) = merge_additions(&text, &adds);
    if changes.is_empty() {
        return Ok(vec![]);
    }
    if backup {
        let b = PathBuf::from(format!("{}.aura-backup", path.display()));
        if !b.exists() {
            fs::copy(path, &b).map_err(|e| format!("Cannot back up {}: {e}", path.display()))?;
        }
    }
    fs::write(path, merged).map_err(|e| format!("Cannot write {}: {e}", path.display()))?;
    Ok(changes)
}

// ---------------------------------------------------------------------------
// An already-built package
// ---------------------------------------------------------------------------

/// Result of [`fix_package`] (used by the `ps1-fix` command).
#[allow(dead_code)]
#[derive(Debug, Clone, Serialize)]
pub struct FixReport {
    pub package_dir: String,
    pub serial: Option<String>,
    pub game_toml: String,
    /// What was changed; empty when nothing was needed.
    pub changes: Vec<String>,
    pub backup_path: Option<String>,
    pub notes: Vec<String>,
}

/// The `[game] id` of a game.toml (the serial).
#[allow(dead_code)]
fn game_id(text: &str) -> Option<String> {
    let lines: Vec<&str> = text.lines().collect();
    let start = lines.iter().position(|l| is_table_header(l, "game"))?;
    for l in &lines[start + 1..] {
        if is_any_header(l) {
            break;
        }
        if key_of(l) == Some("id") {
            let after = l.split_once('=')?.1;
            return quoted_items(after).into_iter().next();
        }
    }
    None
}

/// Apply the known per-title additions to a built game folder's game.toml.
/// Only folders Aura packaged (marker file present) are accepted.
#[allow(dead_code)] // the app has no button for it yet; the CLI does
pub fn fix_package(dir: &Path) -> Result<FixReport, String> {
    let marker = fs::read_to_string(dir.join(PACKAGE_MARKER)).map_err(|_| {
        format!("{} is not a game folder Aura built (no {PACKAGE_MARKER} in it).", dir.display())
    })?;
    let v: serde_json::Value =
        serde_json::from_str(&marker).map_err(|e| format!("{PACKAGE_MARKER} is unreadable: {e}"))?;
    if v.get("aura_package").is_none() {
        return Err(format!("{PACKAGE_MARKER} in {} is not an Aura package marker.", dir.display()));
    }
    let game_toml = dir.join("game.toml");
    let text = fs::read_to_string(&game_toml)
        .map_err(|e| format!("Cannot read {}: {e}", game_toml.display()))?;
    let serial = game_id(&text);
    let mut report = FixReport {
        package_dir: dir.to_string_lossy().to_string(),
        serial: serial.clone(),
        game_toml: game_toml.to_string_lossy().to_string(),
        changes: vec![],
        backup_path: None,
        notes: vec![],
    };
    let Some(serial) = serial else {
        report.notes.push("game.toml has no [game] id, so no title-specific fixes could be chosen.".into());
        return Ok(report);
    };
    if additions_for(&serial).is_empty() {
        report.notes.push(format!("No known title-specific fixes for {serial}."));
        return Ok(report);
    }
    let backup = PathBuf::from(format!("{}.aura-backup", game_toml.display()));
    let had_backup = backup.exists();
    report.changes = apply_config_to_file(&game_toml, &serial, true)?;
    if report.changes.is_empty() {
        report.notes.push(format!("{serial}: already has the fixes."));
    } else if !had_backup && backup.exists() {
        report.backup_path = Some(backup.to_string_lossy().to_string());
    }
    Ok(report)
}
