//! PS1 disc ingest: from "a file the user owns" to a workspace the PSXRecomp
//! build can start from.
//!
//! PSXRecomp does its own disc analysis, but its project setup only accepts a
//! `.cue` sheet, while most collections are CHDs (or lone `.bin`/`.iso`).
//! This step therefore:
//!
//! 1. inspects the image (platform, serial, region, boot PS-X EXE),
//! 2. produces a `.cue` + `.bin` for the data track — decompressing a CHD,
//!    pairing a bare image with a generated sheet, or passing a `.cue` through
//!    untouched — and
//! 3. writes a `game.json` manifest recording what it found.
//!
//! Layout: `<out>/<SERIAL>/{source/, game.json}`; the build adds `project/`.
//! Nothing is downloaded and the user's image is never modified.

use crate::chd_disc;
use crate::disc;
use crate::ps2_ingest::{self, absolute_path, report, IngestProgress, Throttle};
use crate::psx_exe::PsxExeInfo;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Deserialize)]
pub struct Ps1IngestOptions {
    /// Parent folder; a per-game workspace is created beneath it.
    pub out_root: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct Ps1IngestResult {
    pub workspace: String,
    pub manifest_path: String,
    pub display_name: String,
    /// Readable title taken from the file name (`Ace Combat 2`).
    pub title: String,
    pub serial: Option<String>,
    pub region: String,
    pub platform: String,
    pub boot_file: String,
    pub psx_exe: PsxExeInfo,
    /// The image the user picked.
    pub source_image: String,
    /// The `.cue` the build hands to PSXRecomp.
    pub cue_path: String,
    /// How `cue_path` came to be: `"original"` (the user's own cue),
    /// `"decompressed"` (CHD → bin/cue), `"generated"` (bare image + new
    /// sheet) or `"reused"` (an earlier export was still valid).
    pub source_kind: String,
    pub source_bytes: u64,
    /// `Some(n)` when the file name says this is disc `n` of a set.
    pub disc_number: Option<u32>,
    pub next_steps: Vec<String>,
    pub warnings: Vec<String>,
}

/// Disc number from a `(Disc 2)` / `(Disc 2 of 3)` style marker in a file name.
pub fn disc_number_from_name(name: &str) -> Option<u32> {
    let lower = name.to_ascii_lowercase();
    let i = lower.find("(disc ")?;
    let digits: String = lower[i + 6..].chars().take_while(|c| c.is_ascii_digit()).collect();
    digits.parse().ok().filter(|n| *n > 0 && *n < 100)
}

/// A readable game title from a dump's file name: `Ace Combat 2 (USA) (Disc 1)`
/// becomes `Ace Combat 2`. Falls back to `fallback` (the volume label) when the
/// name is nothing but tags.
pub fn friendly_title(stem: &str, fallback: &str) -> String {
    let mut out = String::new();
    let mut depth = 0u32;
    for c in stem.chars() {
        match c {
            '(' | '[' => depth += 1,
            ')' | ']' => depth = depth.saturating_sub(1),
            _ if depth == 0 => out.push(c),
            _ => {}
        }
    }
    let t: String = out.split_whitespace().collect::<Vec<_>>().join(" ");
    let t = t.trim_matches(|c: char| c == '-' || c == '_' || c.is_whitespace()).to_string();
    if t.is_empty() { fallback.to_string() } else { t }
}

/// A `.cue` sheet for one data file of the given track type.
pub fn cue_text(bin_file_name: &str, cue_mode: &str) -> String {
    format!("FILE \"{bin_file_name}\" BINARY\r\n  TRACK 01 {cue_mode}\r\n    INDEX 01 00:00:00\r\n")
}

/// The cue `TRACK` mode word for a detected sector layout.
fn cue_mode_for(layout: disc::SectorLayout) -> &'static str {
    match (layout.stride, layout.data_offset) {
        (2048, _) => "MODE1/2048",
        (2336, _) => "MODE2/2336",
        (_, 16) => "MODE1/2352",
        _ => "MODE2/2352",
    }
}

/// Hard-link `from` to `to`, or copy when they are on different volumes.
fn link_or_copy(from: &Path, to: &Path) -> Result<(), String> {
    let _ = fs::remove_file(to);
    if fs::hard_link(from, to).is_ok() {
        return Ok(());
    }
    fs::copy(from, to)
        .map(|_| ())
        .map_err(|e| format!("Cannot copy {} to {}: {e}", from.display(), to.display()))
}

fn file_name_stem(p: &Path) -> String {
    p.file_stem().map(|s| s.to_string_lossy().to_string()).unwrap_or_else(|| "game".into())
}

/// Prepare a PS1 workspace for `image_path`.
pub fn ingest_ps1(
    image_path: &str,
    opts: &Ps1IngestOptions,
    progress: &mut dyn FnMut(&IngestProgress) -> bool,
) -> Result<Ps1IngestResult, String> {
    let mut throttle = Throttle::new(progress);
    let progress = &mut throttle;
    report(progress, "open", "Opening disc image…", 0.0)?;

    let info = ps2_ingest::inspect_image(image_path)?;
    match info.platform.as_str() {
        "PS1" => {}
        "PS2" => {
            return Err(
                "This is a PS2 disc (SYSTEM.CNF has BOOT2=). Use the PS2 pipeline (`aura-cli ps2-ingest`).".into(),
            )
        }
        _ => {
            return Err(
                "This does not look like a PlayStation game disc (no SYSTEM.CNF with a BOOT line).".into(),
            )
        }
    }
    let exe = info.psx_exe.clone().ok_or_else(|| {
        format!(
            "The boot file `{}` is not a PS-X EXE, so this disc cannot be recompiled directly \
             (it may be packed or use a custom loader).",
            info.boot_file.clone().unwrap_or_default()
        )
    })?;
    let boot_file = info.boot_file.clone().unwrap_or_default();
    let title = friendly_title(&file_name_stem(Path::new(image_path)), &info.display_name);
    // `info.warnings` already says how much of a short image is missing and
    // whether the boot program is among it; repeating a blanket "unlikely to
    // work" would contradict builds that are fine (the boot file is intact).
    let mut warnings = info.warnings.clone();

    // ----- workspace -----------------------------------------------------------
    let src = Path::new(image_path);
    let stem = file_name_stem(src);
    let id = disc::sanitize_component(info.serial.as_deref().unwrap_or(&stem));
    let ws = absolute_path(Path::new(&opts.out_root)).join(&id);
    let source_dir = ws.join("source");
    fs::create_dir_all(&source_dir).map_err(|e| format!("Cannot create {}: {e}", source_dir.display()))?;

    // ----- the cue sheet PSXRecomp will read ------------------------------------
    let ext = src.extension().map(|e| e.to_string_lossy().to_ascii_lowercase()).unwrap_or_default();
    let safe_stem = disc::sanitize_component(&stem);
    let (cue_path, source_kind, source_bytes): (PathBuf, &str, u64) = match ext.as_str() {
        "cue" => {
            let abs = absolute_path(src);
            (abs, "original", info.image_size)
        }
        "chd" => {
            let cue = source_dir.join(format!("{safe_stem}.cue"));
            let bin = source_dir.join(format!("{safe_stem}.bin"));
            let fresh = match (fs::metadata(&cue), fs::metadata(&bin), fs::metadata(src)) {
                (Ok(_), Ok(b), Ok(s)) => match (b.modified(), s.modified()) {
                    (Ok(bm), Ok(sm)) => bm >= sm && b.len() > 0,
                    _ => false,
                },
                _ => false,
            };
            if fresh {
                let bytes = fs::metadata(&bin).map(|m| m.len()).unwrap_or(0);
                (cue, "reused", bytes)
            } else {
                report(progress, "export", "Decompressing the disc's data track…", 0.05)?;
                let exported = chd_disc::export_data_track(src, &source_dir, &safe_stem, &mut |done, total| {
                    let frac = if total > 0 { done as f64 / total as f64 } else { 1.0 };
                    progress.call(&IngestProgress {
                        stage: "export".into(),
                        message: "Decompressing the disc's data track…".into(),
                        fraction: 0.05 + 0.85 * frac,
                        bytes_done: done,
                        bytes_total: total,
                        ..Default::default()
                    })
                })?;
                let cue = exported.cue_path.map(PathBuf::from).ok_or_else(|| {
                    "This CHD has no CD track information, so a cue sheet cannot be made for it.".to_string()
                })?;
                (cue, "decompressed", exported.bytes)
            }
        }
        _ => {
            // A bare .bin/.iso/.img: pair it with a generated sheet.
            report(progress, "export", "Preparing the disc image…", 0.1)?;
            let (img, opened) = disc::open_disc_file(image_path)?;
            let mode = cue_mode_for(img.layout());
            let bin_name = format!(
                "{safe_stem}.{}",
                opened.extension().map(|e| e.to_string_lossy().to_string()).unwrap_or_else(|| "bin".into())
            );
            let bin = source_dir.join(&bin_name);
            link_or_copy(&opened, &bin)?;
            let cue = source_dir.join(format!("{safe_stem}.cue"));
            fs::write(&cue, cue_text(&bin_name, mode))
                .map_err(|e| format!("Cannot write {}: {e}", cue.display()))?;
            (cue, "generated", info.image_size)
        }
    };

    // ----- multi-disc games ---------------------------------------------------
    let disc_number = disc_number_from_name(&stem);
    if let Some(n) = disc_number {
        warnings.push(format!(
            "This is disc {n} of a multi-disc game. Aura builds from this disc; the other discs can be \
             registered with PSXRecomp's `update_disc_set.py` once the project exists."
        ));
    }

    let mut next_steps = vec![
        "Build the game: `aura-cli ps1-build <workspace> --plan` lists what a first build downloads; add \
         `--yes` to run it."
            .to_string(),
        "The generated game asks for your disc image the first time it starts; the image stays where it is."
            .to_string(),
    ];
    if source_kind == "decompressed" {
        next_steps.push(
            "The decompressed data track in `source/` is only needed while the project is being created; \
             it can be deleted afterwards."
                .into(),
        );
    }

    // ----- manifest -----------------------------------------------------------
    let manifest_path = ws.join("game.json");
    let manifest = serde_json::json!({
        "aura_ingest_version": 1,
        "created_unix": SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0),
        "platform": "PS1",
        "pipeline": "psxrecomp",
        "source_image": image_path,
        "display_name": info.display_name,
        "title": title,
        "volume_id": info.volume_id,
        "serial": info.serial,
        "region": info.region,
        "boot_file": boot_file,
        "psx_exe": {
            "entry_pc": format!("0x{:08X}", exe.entry_pc),
            "load_addr": format!("0x{:08X}", exe.load_addr),
            "text_size": exe.text_size,
            "region_marker": exe.region_marker,
        },
        "cue_path": cue_path.to_string_lossy(),
        "source_kind": source_kind,
        "disc_number": disc_number,
        "next_steps": next_steps,
        "warnings": warnings,
    });
    fs::write(&manifest_path, serde_json::to_string_pretty(&manifest).unwrap_or_default())
        .map_err(|e| format!("Cannot write {}: {e}", manifest_path.display()))?;

    report(progress, "done", "Done", 1.0)?;

    Ok(Ps1IngestResult {
        workspace: ws.to_string_lossy().to_string(),
        manifest_path: manifest_path.to_string_lossy().to_string(),
        display_name: info.display_name,
        title,
        serial: info.serial,
        region: info.region,
        platform: "PS1".into(),
        boot_file,
        psx_exe: exe,
        source_image: image_path.to_string(),
        cue_path: cue_path.to_string_lossy().to_string(),
        source_kind: source_kind.to_string(),
        source_bytes,
        disc_number,
        next_steps,
        warnings,
    })
}
