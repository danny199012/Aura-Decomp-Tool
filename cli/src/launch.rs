//! `aura-launch` — the double-click launcher copied into packaged game folders.
//!
//! Reads `launch.json` beside itself and starts the game (see
//! `launcher_core`). It is a GUI-subsystem program on Windows, so it never
//! flashes a console, and it reports failures in a message box rather than
//! failing silently.
//!
//! Usage: `aura-launch` (uses its own folder) or `aura-launch --dir <folder>`.

#![cfg_attr(windows, windows_subsystem = "windows")]

#[path = "../../src-tauri/src/launcher_core.rs"]
mod launcher_core;

use std::path::PathBuf;

#[cfg(windows)]
fn show_error(title: &str, text: &str) {
    use std::os::windows::ffi::OsStrExt;
    #[link(name = "user32")]
    extern "system" {
        fn MessageBoxW(hwnd: *mut core::ffi::c_void, text: *const u16, caption: *const u16, utype: u32) -> i32;
    }
    let wide = |s: &str| -> Vec<u16> { std::ffi::OsStr::new(s).encode_wide().chain(Some(0)).collect() };
    let (t, c) = (wide(text), wide(title));
    // MB_OK | MB_ICONERROR
    unsafe {
        MessageBoxW(std::ptr::null_mut(), t.as_ptr(), c.as_ptr(), 0x10);
    }
}

#[cfg(not(windows))]
fn show_error(title: &str, text: &str) {
    eprintln!("{title}\n{text}");
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let dir: PathBuf = match args.iter().position(|a| a == "--dir") {
        Some(i) => PathBuf::from(args.get(i + 1).cloned().unwrap_or_default()),
        None => std::env::current_exe()
            .ok()
            .and_then(|p| p.parent().map(|p| p.to_path_buf()))
            .unwrap_or_else(|| PathBuf::from(".")),
    };

    let game = launcher_core::read_config(&dir).map(|c| c.game).unwrap_or_default();
    let title = if game.is_empty() { "Aura game launcher".to_string() } else { game };

    match launcher_core::run(&dir) {
        Ok(o) if o.exit_code == Some(0) && o.early_failure.is_none() => {}
        Ok(o) if o.exit_code == Some(0) => {
            // Exit code 0, but the runtime logged its own fatal error moments
            // after starting (it does not set a failing exit code).
            let msg = launcher_core::explain_early_failure(
                o.elapsed,
                o.early_failure.as_deref().unwrap_or_default(),
                o.log_path.as_deref(),
            );
            show_error(&title, &msg);
            std::process::exit(3);
        }
        Ok(o) => {
            let mut msg = format!("The game stopped with exit code {}.", launcher_core::describe_exit(o.exit_code));
            if let Some(p) = &o.log_path {
                msg.push_str(&format!("\n\nLog: {}", p.display()));
            }
            if !o.log_tail.is_empty() {
                msg.push_str("\n\nLast lines:\n");
                msg.push_str(&o.log_tail.join("\n"));
            }
            show_error(&title, &msg);
            std::process::exit(o.exit_code.unwrap_or(1).max(1));
        }
        Err(e) => {
            show_error(&title, &e);
            std::process::exit(2);
        }
    }
}
