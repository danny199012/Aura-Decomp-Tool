//! Launcher core for packaged games.
//!
//! A packaged game folder contains a recompiled runtime executable that wants
//! the guest ELF's path as `argv[1]` and has no file dialog or settings file
//! (upstream ps2xRuntime), so double-clicking it does nothing useful. The small
//! `aura-launch` binary sits beside it, reads `launch.json` from its own folder,
//! and starts the game with the right working directory and arguments — no
//! command prompt, relocatable folder, with a log file and an error message
//! instead of a silent failure.
//!
//! Std + `serde_json` only, and deliberately tiny: the launcher binary includes
//! this file directly rather than the whole analysis library.

use serde::Deserialize;
use std::fs;
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// File name the launcher looks for beside itself.
pub const CONFIG_NAME: &str = "launch.json";

fn default_log() -> String {
    "aura-last-run.log".to_string()
}

/// Contents of `launch.json`.
#[derive(Debug, Clone, Deserialize)]
pub struct LaunchConfig {
    /// Game executable, relative to the package folder.
    pub exe: String,
    /// Guest ELF, relative to the package folder. Passed to the exe as an
    /// absolute path (the runtime uses its directory as the disc root).
    pub boot_elf: String,
    /// Extra arguments appended after the ELF path.
    #[serde(default)]
    pub extra_args: Vec<String>,
    /// Log file (relative) that receives stdout+stderr.
    #[serde(default = "default_log")]
    pub log: String,
    /// Keep the console window and print to it instead of logging to a file.
    #[serde(default)]
    pub show_console: bool,
    /// Display name, used in error messages.
    #[serde(default)]
    pub game: String,
}

/// What happened when the game ran.
#[derive(Debug, Clone)]
pub struct RunOutcome {
    pub exit_code: Option<i32>,
    pub log_path: Option<PathBuf>,
    /// Last lines of the log (empty when no log was written).
    pub log_tail: Vec<String>,
    /// How long the game ran.
    pub elapsed: Duration,
    /// Set when the game exited "successfully" almost immediately but its log
    /// shows it failed: the first log line that says so. The upstream runtime
    /// reports its own fatal errors and still returns exit code 0, so without
    /// this the window would just vanish with no explanation.
    pub early_failure: Option<String>,
}

/// A run shorter than this that logged a failure is reported as one.
pub const EARLY_EXIT: Duration = Duration::from_secs(20);

/// First log line that reads like the runtime reporting its own failure.
pub fn find_failure_line(log: &str) -> Option<String> {
    log.lines()
        .map(|l| l.trim())
        .find(|l| {
            let low = l.to_ascii_lowercase();
            low.contains("error during program execution")
                || low.contains("fatal exception")
                || low.contains("unable to determine executable path")
                || low.contains("failed to load elf")
                || low.contains("unimplemented ps2 stub called")
        })
        .map(|l| l.to_string())
}

/// The function name in the runtime's "Unimplemented PS2 stub called. name=…" line.
pub fn stub_name(line: &str) -> Option<&str> {
    let rest = &line[line.find("name=")? + "name=".len()..];
    let end = rest.find(char::is_whitespace).unwrap_or(rest.len());
    Some(&rest[..end]).filter(|n| !n.is_empty())
}

/// Which part of the console an SDK function belongs to, for the message only.
fn stub_area(name: &str) -> Option<&'static str> {
    const AREAS: &[(&str, &str)] = &[
        ("sceSd", "sound"),
        ("sceSSyn", "sound"),
        ("sceAudio", "sound"),
        ("sceCd", "disc drive"),
        ("scePad", "controller"),
        ("sceMc", "memory card"),
        ("sceMpeg", "video playback"),
        ("sceDeci2", "debug console"),
        ("sceTty", "debug console"),
        ("sceGs", "graphics"),
        ("sceDma", "DMA"),
        ("sceVif", "graphics"),
        ("sceGif", "graphics"),
        ("sceIpu", "video decoding"),
    ];
    AREAS.iter().find(|(p, _)| name.starts_with(p)).map(|(_, a)| *a)
}

/// The length of a run in words: "less than a second", "1 second", "7 seconds".
fn describe_duration(d: Duration) -> String {
    match d.as_secs_f64().round() as u64 {
        0 => "less than a second".to_string(),
        1 => "1 second".to_string(),
        n => format!("{n} seconds"),
    }
}

/// What to tell the user when the game stopped moments after starting and its
/// log says why (see [`RunOutcome::early_failure`]).
pub fn explain_early_failure(elapsed: Duration, failure: &str, log: Option<&Path>) -> String {
    let mut msg = format!("The game stopped {} after starting.\n\n", describe_duration(elapsed));
    if failure.to_ascii_lowercase().contains("unimplemented ps2 stub called") {
        match stub_name(failure) {
            Some(name) => {
                let area = stub_area(name).map(|a| format!(" ({a})")).unwrap_or_default();
                msg.push_str(&format!(
                    "It called a PlayStation 2 system function that the PS2 runtime does not implement yet: {name}{area}.\n\nThat is a gap in the runtime this game was built with, not a problem with your game files."
                ));
            }
            None => msg.push_str(&format!(
                "It called a PlayStation 2 system function that the PS2 runtime does not implement yet.\n\n{failure}"
            )),
        }
    } else {
        msg.push_str(failure);
    }
    if let Some(p) = log {
        msg.push_str(&format!("\n\nFull log: {}", p.display()));
    }
    msg
}

/// Resolve `rel` inside `dir`, refusing anything that could escape it
/// (absolute paths, drive prefixes, `..`). `launch.json` is the user's own
/// file, but the launcher still never follows a path outside its folder.
pub fn resolve_inside(dir: &Path, rel: &str) -> Result<PathBuf, String> {
    if rel.trim().is_empty() {
        return Err("empty path in launch.json".into());
    }
    let p = Path::new(rel);
    if p.is_absolute() || rel.starts_with('/') || rel.starts_with('\\') || rel.contains(':') {
        return Err(format!("`{rel}` in launch.json must be a relative path"));
    }
    for c in p.components() {
        match c {
            Component::Normal(_) | Component::CurDir => {}
            _ => return Err(format!("`{rel}` in launch.json may not leave the game folder")),
        }
    }
    Ok(dir.join(p))
}

/// Read and parse `launch.json` from `dir`.
pub fn read_config(dir: &Path) -> Result<LaunchConfig, String> {
    let path = dir.join(CONFIG_NAME);
    let text = fs::read_to_string(&path)
        .map_err(|e| format!("Cannot read {}: {e}", path.display()))?;
    serde_json::from_str(&text).map_err(|e| format!("{} is not valid: {e}", path.display()))
}

fn tail_lines(path: &Path, n: usize) -> Vec<String> {
    match fs::read(path) {
        Ok(bytes) => {
            let text = String::from_utf8_lossy(&bytes);
            let lines: Vec<&str> = text.lines().collect();
            lines[lines.len().saturating_sub(n)..].iter().map(|s| s.to_string()).collect()
        }
        Err(_) => vec![],
    }
}

/// Start the game described by `dir/launch.json` and wait for it to exit.
pub fn run(dir: &Path) -> Result<RunOutcome, String> {
    let cfg = read_config(dir)?;
    let exe = resolve_inside(dir, &cfg.exe)?;
    let elf = resolve_inside(dir, &cfg.boot_elf)?;
    if !exe.is_file() {
        return Err(format!("The game executable is missing: {}", exe.display()));
    }
    if !elf.is_file() {
        return Err(format!(
            "The game's boot file is missing: {}\nThe disc folder may be incomplete.",
            elf.display()
        ));
    }

    let mut cmd = Command::new(&exe);
    cmd.arg(&elf).args(&cfg.extra_args).current_dir(dir).stdin(Stdio::null());

    let mut log_path = None;
    if cfg.show_console {
        cmd.stdout(Stdio::inherit()).stderr(Stdio::inherit());
    } else {
        let lp = resolve_inside(dir, &cfg.log)?;
        let out = fs::File::create(&lp)
            .map_err(|e| format!("Cannot create log file {}: {e}", lp.display()))?;
        let err = out.try_clone().map_err(|e| format!("Cannot duplicate log handle: {e}"))?;
        cmd.stdout(Stdio::from(out)).stderr(Stdio::from(err));
        log_path = Some(lp);
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            cmd.creation_flags(0x0800_0000); // CREATE_NO_WINDOW: don't flash a console
        }
    }

    let started = Instant::now();
    let status = cmd
        .spawn()
        .map_err(|e| format!("Could not start {}: {e}", exe.display()))?
        .wait()
        .map_err(|e| format!("Waiting for the game failed: {e}"))?;
    let elapsed = started.elapsed();

    let log_tail = log_path.as_deref().map(|p| tail_lines(p, 12)).unwrap_or_default();
    let early_failure = if status.code() == Some(0) && elapsed < EARLY_EXIT {
        log_path.as_deref().and_then(|p| {
            // Only the last 256 KiB: a failure message is near the end.
            let bytes = fs::read(p).ok()?;
            let start = bytes.len().saturating_sub(256 * 1024);
            find_failure_line(&String::from_utf8_lossy(&bytes[start..]))
        })
    } else {
        None
    };
    Ok(RunOutcome { exit_code: status.code(), log_path, log_tail, elapsed, early_failure })
}

/// Human-readable exit code (`0xC0000005` style for Windows NTSTATUS values).
pub fn describe_exit(code: Option<i32>) -> String {
    match code {
        Some(c) if c < 0 || c > 255 => format!("{:#010X}", c as u32),
        Some(c) => c.to_string(),
        None => "unknown (terminated by a signal)".to_string(),
    }
}
