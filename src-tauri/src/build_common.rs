//! Plumbing shared by the one-click build pipelines (PS2 and PS1).
//!
//! * [`Runner`] — start a child process with an argument vector (never a
//!   shell), stream its output into a rolling tail and a log file, report
//!   progress, and kill the whole process tree on cancel.
//! * [`BuildProgress`], [`ToolStatus`], [`DownloadItem`] — the shapes the UI
//!   and the CLI render.
//! * [`free_space_bytes`] / [`space_ok`] — disk-space checks for the planner.
//!
//! Pure std + serde so the GUI, the CLI and the tests share it.

use serde::Serialize;
use std::collections::VecDeque;
use std::ffi::OsString;
use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

/// Lines of output kept for the UI.
pub(crate) const TAIL_LINES: usize = 12;
/// Minimum gap between two progress callbacks.
pub(crate) const EMIT_INTERVAL: Duration = Duration::from_millis(150);

#[derive(Debug, Clone, Serialize)]
pub struct ToolStatus {
    pub name: String,
    pub found: bool,
    pub path: Option<String>,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct DownloadItem {
    pub what: String,
    pub from: String,
    pub approx_mb: u32,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct BuildProgress {
    /// `toolchain` | `source` | `recompiler-build` | `recompile` |
    /// `runtime-configure` | `runtime-build` | `package` | `done`
    pub stage: String,
    pub message: String,
    /// Overall completion in `0.0..=1.0`.
    pub fraction: f64,
    pub elapsed_secs: f64,
    pub log_tail: Vec<String>,
}

// ---------------------------------------------------------------------------
// Disk space
// ---------------------------------------------------------------------------

/// Free bytes on the volume holding `path` (or its nearest existing parent).
/// `None` when it cannot be determined (non-Windows).
pub fn free_space_bytes(path: &Path) -> Option<u64> {
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        extern "system" {
            fn GetDiskFreeSpaceExW(dir: *const u16, avail: *mut u64, total: *mut u64, free: *mut u64) -> i32;
        }
        let mut p = path.to_path_buf();
        while !p.exists() {
            if !p.pop() {
                return None;
            }
        }
        let wide: Vec<u16> = p.as_os_str().encode_wide().chain(Some(0)).collect();
        let (mut avail, mut total, mut free) = (0u64, 0u64, 0u64);
        let ok = unsafe { GetDiskFreeSpaceExW(wide.as_ptr(), &mut avail, &mut total, &mut free) };
        (ok != 0).then_some(avail)
    }
    #[cfg(not(windows))]
    {
        let _ = path;
        None
    }
}

/// Pure check used by the planner (and tested): is `free` enough for `required`?
pub fn space_ok(free: Option<u64>, required: u64) -> bool {
    free.map(|f| f >= required).unwrap_or(true)
}

// ---------------------------------------------------------------------------
// Process runner with live output, progress and cancellation
// ---------------------------------------------------------------------------

pub(crate) struct Runner<'a> {
    pub(crate) cb: &'a mut dyn FnMut(&BuildProgress) -> bool,
    pub(crate) started: Instant,
    pub(crate) last_emit: Option<Instant>,
    pub(crate) tail: VecDeque<String>,
    pub(crate) log: Option<fs::File>,
    pub(crate) cancelled: bool,
    pub(crate) stage: String,
    pub(crate) message: String,
    pub(crate) fraction: f64,
    pub(crate) stage_started: Instant,
    pub(crate) stage_secs: Vec<(String, f64)>,
    /// `(from, to, expected_secs)`: while a long compile prints nothing (its
    /// output is block-buffered through the pipe) creep from `from` towards
    /// `to` over `expected_secs`, so the bar does not sit still.
    pub(crate) creep: Option<(f64, f64, f64)>,
    /// Extra environment for every child process this runner starts.
    pub(crate) env: Vec<(OsString, OsString)>,
    /// Variables removed from the inherited environment of every child.
    pub(crate) env_remove: Vec<OsString>,
}

impl<'a> Runner<'a> {
    pub(crate) fn new(cb: &'a mut dyn FnMut(&BuildProgress) -> bool, log: Option<fs::File>) -> Self {
        Runner {
            cb,
            started: Instant::now(),
            last_emit: None,
            tail: VecDeque::new(),
            log,
            cancelled: false,
            stage: String::new(),
            message: String::new(),
            fraction: 0.0,
            stage_started: Instant::now(),
            stage_secs: vec![],
            creep: None,
            env: Vec::new(),
            env_remove: Vec::new(),
        }
    }

    pub(crate) fn snapshot(&self) -> BuildProgress {
        let mut fraction = self.fraction;
        if let Some((from, to, expected)) = self.creep {
            let t = (self.stage_started.elapsed().as_secs_f64() / expected.max(1.0)).min(0.97);
            fraction = fraction.max(from + (to - from) * t);
        }
        BuildProgress {
            stage: self.stage.clone(),
            message: self.message.clone(),
            fraction: fraction.clamp(0.0, 1.0),
            elapsed_secs: self.started.elapsed().as_secs_f64(),
            log_tail: self.tail.iter().cloned().collect(),
        }
    }

    /// Report progress; throttled unless `force`. Returns `false` once cancelled.
    pub(crate) fn emit(&mut self, force: bool) -> bool {
        if self.cancelled {
            return false;
        }
        let due = force || self.last_emit.map_or(true, |t| t.elapsed() >= EMIT_INTERVAL);
        if due {
            self.last_emit = Some(Instant::now());
            let snap = self.snapshot();
            if !(self.cb)(&snap) {
                self.cancelled = true;
                return false;
            }
        }
        true
    }

    pub(crate) fn stage(&mut self, stage: &str, message: &str, fraction: f64) -> Result<(), String> {
        if !self.stage.is_empty() && self.stage != stage {
            self.stage_secs.push((self.stage.clone(), self.stage_started.elapsed().as_secs_f64()));
            self.stage_started = Instant::now();
        }
        self.stage = stage.to_string();
        self.message = message.to_string();
        self.fraction = fraction;
        self.creep = None;
        if self.emit(true) { Ok(()) } else { Err("Cancelled".into()) }
    }

    pub(crate) fn finish_stage(&mut self) {
        if !self.stage.is_empty() {
            self.stage_secs.push((self.stage.clone(), self.stage_started.elapsed().as_secs_f64()));
            self.stage_started = Instant::now();
        }
    }

    pub(crate) fn push_line(&mut self, line: &str) {
        if let Some(f) = self.log.as_mut() {
            let _ = writeln!(f, "{line}");
        }
        if !line.trim().is_empty() {
            self.tail.push_back(line.trim_end().to_string());
            while self.tail.len() > TAIL_LINES {
                self.tail.pop_front();
            }
        }
    }

    /// Run `program args` with live output. `on_line` may return a new
    /// overall progress fraction.
    pub(crate) fn run(
        &mut self,
        label: &str,
        program: &Path,
        args: &[OsString],
        cwd: Option<&Path>,
        mut on_line: impl FnMut(&str) -> Option<f64>,
    ) -> Result<(), String> {
        self.push_line(&format!("$ {} {}", program.display(), args.iter().map(|a| a.to_string_lossy()).collect::<Vec<_>>().join(" ")));
        let mut cmd = Command::new(program);
        cmd.args(args).stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped());
        for k in &self.env_remove {
            cmd.env_remove(k);
        }
        for (k, v) in &self.env {
            cmd.env(k, v);
        }
        if let Some(c) = cwd {
            cmd.current_dir(c);
        }
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            cmd.creation_flags(0x0800_0000); // CREATE_NO_WINDOW
        }
        let mut child = cmd.spawn().map_err(|e| format!("Could not start {label} ({}): {e}", program.display()))?;

        let (tx, rx) = mpsc::channel::<String>();
        let mut readers = vec![];
        for pipe in [child.stdout.take().map(|p| Box::new(p) as Box<dyn std::io::Read + Send>),
                     child.stderr.take().map(|p| Box::new(p) as Box<dyn std::io::Read + Send>)]
            .into_iter()
            .flatten()
        {
            let tx = tx.clone();
            readers.push(std::thread::spawn(move || {
                let mut r = BufReader::new(pipe);
                let mut buf = Vec::new();
                loop {
                    buf.clear();
                    match r.read_until(b'\n', &mut buf) {
                        Ok(0) | Err(_) => break,
                        Ok(_) => {
                            let line = String::from_utf8_lossy(&buf).trim_end_matches(['\r', '\n']).to_string();
                            if tx.send(line).is_err() {
                                break;
                            }
                        }
                    }
                }
            }));
        }
        drop(tx);

        let mut killed = false;
        loop {
            match rx.recv_timeout(Duration::from_millis(100)) {
                Ok(line) => {
                    self.push_line(&line);
                    if let Some(f) = on_line(&line) {
                        self.fraction = f;
                    }
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {}
                Err(mpsc::RecvTimeoutError::Disconnected) => break,
            }
            if !self.emit(false) && !killed {
                killed = true;
                kill_tree(child.id());
                let _ = child.kill();
            }
        }
        for r in readers {
            let _ = r.join();
        }
        let status = child.wait().map_err(|e| format!("Waiting for {label} failed: {e}"))?;
        if killed || self.cancelled {
            return Err("Cancelled".into());
        }
        if !status.success() {
            let tail: Vec<String> = self.tail.iter().cloned().collect();
            return Err(format!(
                "{label} failed ({status}). Last output:\n{}",
                tail.join("\n")
            ));
        }
        Ok(())
    }
}

/// Kill a process and everything it started (CMake spawns MSBuild which spawns
/// compiler processes; killing only the parent leaves workers running).
pub(crate) fn kill_tree(pid: u32) {
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        let _ = Command::new("taskkill")
            .args(["/PID", &pid.to_string(), "/T", "/F"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .creation_flags(0x0800_0000)
            .status();
    }
    #[cfg(not(windows))]
    {
        let _ = Command::new("pkill").args(["-TERM", "-P", &pid.to_string()]).status();
    }
}

// ---------------------------------------------------------------------------
// Pinned git checkouts
// ---------------------------------------------------------------------------

/// `&str` -> `OsString`, for building argument vectors tersely.
pub(crate) fn os(x: &str) -> OsString {
    OsString::from(x)
}

/// True when `dir` is a git checkout detached at exactly `commit`.
pub(crate) fn checkout_is_at(dir: &Path, commit: &str) -> bool {
    fs::read_to_string(dir.join(".git").join("HEAD"))
        .map(|s| s.trim() == commit)
        .unwrap_or(false)
}

/// Check out exactly `commit` of `url` into `dir`, detached and (when the
/// server allows fetching a single commit, as GitHub does) shallow.
pub(crate) fn ensure_git_checkout(
    r: &mut Runner,
    git: &Path,
    dir: &Path,
    url: &str,
    commit: &str,
) -> Result<(), String> {
    if checkout_is_at(dir, commit) {
        return Ok(());
    }
    fs::create_dir_all(dir).map_err(|e| format!("Cannot create {}: {e}", dir.display()))?;
    let d = dir.as_os_str().to_os_string();
    let g = |extra: &[&str]| -> Vec<OsString> {
        let mut v = vec![os("-C"), d.clone()];
        v.extend(extra.iter().map(|x| os(x)));
        v
    };
    if !dir.join(".git").exists() {
        r.run("git init", git, &g(&["init", "-q"]), None, |_| None)?;
        r.run("git remote", git, &g(&["remote", "add", "origin", url]), None, |_| None)?;
    }
    let shallow = r.run("git fetch", git, &g(&["fetch", "--depth", "1", "origin", commit]), None, |_| None);
    if shallow.is_err() {
        r.run("git fetch", git, &g(&["fetch", "origin"]), None, |_| None)?;
        r.run("git checkout", git, &g(&["checkout", "-q", "--detach", commit]), None, |_| None)?;
    } else {
        r.run("git checkout", git, &g(&["checkout", "-q", "--detach", "FETCH_HEAD"]), None, |_| None)?;
    }
    if !checkout_is_at(dir, commit) {
        return Err(format!("The checkout in {} is not at the expected commit {commit}.", dir.display()));
    }
    Ok(())
}
