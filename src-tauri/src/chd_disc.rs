//! CHD (MAME "compressed hunks of data") disc images, read-only.
//!
//! Most retro disc collections are CHDs: `chdman createcd` stores a CD as a
//! sequence of 2448-byte frames (2352 bytes of sector data + 96 of subcode),
//! compressed per hunk (8 frames) with LZMA/zlib/FLAC/zstd. This module opens
//! one with the pure-Rust `chd` crate and presents the **first data track** as
//! a plain `Read + Seek` byte stream of sectors, which is exactly what
//! [`crate::disc::DiscImage`] already knows how to parse. Nothing is
//! decompressed up front: hunks are inflated on demand and the current one is
//! cached.
//!
//! What is deliberately not handled (reported, never mis-read): CHDs that need
//! a parent file, GD-ROM (Dreamcast) layouts, and hard-disk images.
//!
//! The text parsing and track arithmetic are pure functions so they can be
//! tested without a CHD on disk.

use chd::Chd;
use serde::Serialize;
use std::fs::File;
use std::io::{self, BufReader, Read, Seek, SeekFrom, Write};
use std::path::Path;

/// Bytes of one CD frame inside a CHD: 2352 sector bytes + 96 subcode bytes.
pub const CD_FRAME_BYTES: u64 = 2448;
/// `chdman` pads every track to a multiple of this many frames.
const CD_TRACK_PADDING: u64 = 4;
/// Cap on tracks read from metadata (the CD spec allows 99).
const MAX_TRACKS: usize = 99;

/// True when `head` begins with the CHD magic.
pub fn is_chd(head: &[u8]) -> bool {
    head.len() >= 8 && &head[..8] == b"MComprHD"
}

// ---------------------------------------------------------------------------
// Track metadata
// ---------------------------------------------------------------------------

/// One CD track as described by the CHD's `CHT2`/`CHTR` metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CdTrack {
    pub number: u32,
    /// Normalised type: `MODE1`, `MODE1_RAW`, `MODE2`, `MODE2_FORM1`,
    /// `MODE2_FORM2`, `MODE2_FORM_MIX`, `MODE2_RAW` or `AUDIO`.
    pub kind: String,
    pub frames: u32,
    pub pregap: u32,
    /// True when the pregap frames are stored in the CHD (not virtual).
    pub pregap_stored: bool,
    /// First stored frame of this track within the CHD.
    pub start_frame: u64,
}

fn normalise_kind(v: &str) -> String {
    match v.to_ascii_uppercase().as_str() {
        "MODE1/2048" => "MODE1".into(),
        "MODE1/2352" => "MODE1_RAW".into(),
        "MODE2/2336" => "MODE2".into(),
        "MODE2/2048" => "MODE2_FORM1".into(),
        "MODE2/2324" => "MODE2_FORM2".into(),
        "MODE2/2352" => "MODE2_RAW".into(),
        other => other.to_string(),
    }
}

impl CdTrack {
    pub fn is_data(&self) -> bool {
        self.kind.starts_with("MODE")
    }

    /// Bytes of each 2448-byte frame that belong to one sector of this type.
    pub fn sector_bytes(&self) -> Option<u32> {
        match self.kind.as_str() {
            "MODE1" | "MODE2_FORM1" => Some(2048),
            "MODE2_FORM2" => Some(2324),
            "MODE2" | "MODE2_FORM_MIX" => Some(2336),
            "MODE1_RAW" | "MODE2_RAW" | "AUDIO" => Some(2352),
            _ => None,
        }
    }

    /// The `TRACK nn <mode>` word a `.cue` sheet uses for this type.
    pub fn cue_mode(&self) -> Option<&'static str> {
        Some(match self.kind.as_str() {
            "MODE1" => "MODE1/2048",
            "MODE1_RAW" => "MODE1/2352",
            "MODE2" | "MODE2_FORM_MIX" => "MODE2/2336",
            "MODE2_FORM1" => "MODE2/2048",
            "MODE2_FORM2" => "MODE2/2324",
            "MODE2_RAW" => "MODE2/2352",
            "AUDIO" => "AUDIO",
            _ => return None,
        })
    }
}

/// Parse one metadata string such as
/// `TRACK:1 TYPE:MODE2_RAW SUBTYPE:NONE FRAMES:233860 PREGAP:0 PGTYPE:MODE1 PGSUB:NONE POSTGAP:0`
/// (`CHT2`) or its older four-field form (`CHTR`). `start_frame` is filled in
/// later by [`assign_start_frames`].
pub fn parse_track_text(text: &str) -> Option<CdTrack> {
    let (mut number, mut kind, mut frames) = (None, None, None);
    let (mut pregap, mut pgtype) = (0u32, String::new());
    for tok in text.trim_end_matches('\0').split_whitespace() {
        let Some((k, v)) = tok.split_once(':') else { continue };
        match k {
            "TRACK" => number = v.parse::<u32>().ok(),
            "TYPE" => kind = Some(normalise_kind(v)),
            "FRAMES" => frames = v.parse::<u32>().ok(),
            "PREGAP" => pregap = v.parse().unwrap_or(0),
            "PGTYPE" => pgtype = v.to_string(),
            _ => {}
        }
    }
    let pregap_stored = pregap > 0 && !pgtype.starts_with('V');
    Some(CdTrack {
        number: number?,
        kind: kind?,
        frames: frames?,
        pregap,
        pregap_stored,
        start_frame: 0,
    })
}

/// Compute each track's first stored frame: tracks follow one another, each
/// padded up to a multiple of four frames.
pub fn assign_start_frames(tracks: &mut [CdTrack]) {
    let mut running = 0u64;
    for t in tracks.iter_mut() {
        t.start_frame = running;
        let frames = t.frames as u64;
        let padded = frames.div_ceil(CD_TRACK_PADDING) * CD_TRACK_PADDING;
        running = running.saturating_add(padded);
    }
}

/// True when `sector` (as exposed by a track view) starts an ISO9660 primary
/// volume descriptor at any of the data offsets disc layouts use.
fn has_volume_descriptor(sector: &[u8]) -> bool {
    [0usize, 8, 16, 24].iter().any(|&o| {
        sector.len() >= o + 7 && sector[o] == 1 && &sector[o + 1..o + 6] == b"CD001" && sector[o + 6] == 1
    })
}

// ---------------------------------------------------------------------------
// Hunk-cached byte access
// ---------------------------------------------------------------------------

fn other<E: std::fmt::Display>(e: E) -> io::Error {
    io::Error::new(io::ErrorKind::Other, e.to_string())
}

struct HunkReader<F: Read + Seek> {
    chd: Chd<F>,
    hunk_size: u64,
    logical_bytes: u64,
    current: Option<u32>,
    hunk: Vec<u8>,
    compressed: Vec<u8>,
}

impl<F: Read + Seek> HunkReader<F> {
    fn new(chd: Chd<F>) -> Self {
        let hunk_size = chd.header().hunk_size() as u64;
        let logical_bytes = chd.header().logical_bytes();
        let hunk = chd.get_hunksized_buffer();
        HunkReader { chd, hunk_size, logical_bytes, current: None, hunk, compressed: Vec::new() }
    }

    /// Fill `out` from logical offset `off`; returns how many bytes were read
    /// (less than `out.len()` only at the end of the stream).
    fn read_at(&mut self, mut off: u64, out: &mut [u8]) -> io::Result<usize> {
        let mut done = 0usize;
        while done < out.len() && off < self.logical_bytes {
            let index = (off / self.hunk_size) as u32;
            if self.current != Some(index) {
                self.current = None;
                let mut h = self.chd.hunk(index).map_err(other)?;
                h.read_hunk_in(&mut self.compressed, &mut self.hunk).map_err(other)?;
                self.current = Some(index);
            }
            let in_hunk = (off % self.hunk_size) as usize;
            let n = (out.len() - done)
                .min(self.hunk_size as usize - in_hunk)
                .min((self.logical_bytes - off) as usize);
            out[done..done + n].copy_from_slice(&self.hunk[in_hunk..in_hunk + n]);
            done += n;
            off += n as u64;
        }
        Ok(done)
    }
}

// ---------------------------------------------------------------------------
// The sector view
// ---------------------------------------------------------------------------

/// What [`open_data_track`] learned about the image.
#[derive(Debug, Clone, Serialize)]
pub struct ChdInfo {
    pub tracks: Vec<CdTrack>,
    /// Track number the view exposes (`None` for a flat DVD-style CHD).
    pub data_track: Option<u32>,
    /// Bytes exposed per sector by the view.
    pub stride: u32,
    pub sectors: u64,
    pub hunk_bytes: u32,
    pub logical_bytes: u64,
    /// True when the CHD has no CD track metadata and is read as a flat image.
    pub flat: bool,
    /// The `TRACK … <mode>` word for a `.cue` describing the exposed stream.
    pub cue_mode: Option<String>,
}

/// A data track (or a flat image) as a `Read + Seek` stream of sectors.
pub struct ChdTrackView<F: Read + Seek> {
    hunks: HunkReader<F>,
    /// Logical byte offset of the first exposed sector.
    base: u64,
    /// Bytes between sector starts in the CHD (2448 for CD, `stride` if flat).
    frame: u64,
    /// Bytes exposed per sector.
    stride: u64,
    sectors: u64,
    pos: u64,
}

impl<F: Read + Seek> Read for ChdTrackView<F> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let len = self.sectors * self.stride;
        if buf.is_empty() || self.pos >= len {
            return Ok(0);
        }
        let sector = self.pos / self.stride;
        let in_sector = self.pos % self.stride;
        let n = (buf.len() as u64).min(self.stride - in_sector).min(len - self.pos) as usize;
        let off = self.base + sector * self.frame + in_sector;
        let got = self.hunks.read_at(off, &mut buf[..n])?;
        if got < n {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "CHD ended inside a track"));
        }
        self.pos += got as u64;
        Ok(got)
    }
}

impl<F: Read + Seek> Seek for ChdTrackView<F> {
    fn seek(&mut self, to: SeekFrom) -> io::Result<u64> {
        let len = (self.sectors * self.stride) as i128;
        let target = match to {
            SeekFrom::Start(n) => n as i128,
            SeekFrom::End(d) => len + d as i128,
            SeekFrom::Current(d) => self.pos as i128 + d as i128,
        };
        if target < 0 {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "seek before the start of the track"));
        }
        self.pos = target as u64;
        Ok(self.pos)
    }
}

/// Read the CD track list out of an open CHD. Empty when the CHD carries no CD
/// metadata (a DVD or hard-disk image).
fn read_tracks<F: Read + Seek>(chd: &mut Chd<F>) -> Result<Vec<CdTrack>, String> {
    use chd::metadata::{KnownMetadata, MetadataTag};
    let refs: Vec<_> = chd.metadata_refs().collect();
    let mut tracks = Vec::new();
    for r in refs {
        let tag = r.metatag();
        if tag == KnownMetadata::GdRomTrack as u32 || tag == KnownMetadata::GdRomOld as u32 {
            return Err("This CHD is a GD-ROM (Dreamcast) image, which is not supported.".into());
        }
        if tag == KnownMetadata::CdRomOld as u32 {
            return Err(
                "This CHD uses the legacy binary CD metadata (written by very old chdman). \
                 Re-create it with a current `chdman createcd`."
                    .into(),
            );
        }
        if tag != KnownMetadata::CdRomTrack2 as u32 && tag != KnownMetadata::CdRomTrack as u32 {
            continue;
        }
        let meta = r.read(chd.inner()).map_err(|e| format!("Cannot read CHD track metadata: {e}"))?;
        let text = String::from_utf8_lossy(&meta.value).to_string();
        if let Some(t) = parse_track_text(&text) {
            tracks.push(t);
        }
        if tracks.len() > MAX_TRACKS {
            return Err("This CHD lists more than 99 tracks — it looks corrupt.".into());
        }
    }
    tracks.sort_by_key(|t| t.number);
    assign_start_frames(&mut tracks);
    Ok(tracks)
}

/// Open the first data track of a CHD (or the whole stream of a flat CHD).
pub fn open_data_track(path: &Path) -> Result<(ChdTrackView<BufReader<File>>, ChdInfo), String> {
    let file = File::open(path).map_err(|e| format!("Cannot open {}: {e}", path.display()))?;
    open_data_track_from(BufReader::with_capacity(256 * 1024, file))
}

/// [`open_data_track`] over any seekable source (used by the tests).
pub fn open_data_track_from<F: Read + Seek>(src: F) -> Result<(ChdTrackView<F>, ChdInfo), String> {
    let mut chd = Chd::open(src, None).map_err(|e| format!("Not a readable CHD image: {e}"))?;
    if chd.header().has_parent() {
        return Err("This CHD needs a parent image (a delta CHD), which is not supported.".into());
    }
    let hunk_bytes = chd.header().hunk_size();
    let logical_bytes = chd.header().logical_bytes();
    let tracks = read_tracks(&mut chd)?;
    let mut hunks = HunkReader::new(chd);

    // A CHD with no CD metadata is a flat image (DVD): expose it as 2048-byte sectors.
    if tracks.is_empty() {
        let stride = 2048u64;
        let sectors = logical_bytes / stride;
        let info = ChdInfo {
            tracks,
            data_track: None,
            stride: stride as u32,
            sectors,
            hunk_bytes,
            logical_bytes,
            flat: true,
            cue_mode: None,
        };
        let view = ChdTrackView { hunks, base: 0, frame: stride, stride, sectors, pos: 0 };
        return Ok((view, info));
    }

    let track = tracks
        .iter()
        .find(|t| t.is_data() && t.sector_bytes().is_some() && t.cue_mode() != Some("MODE2/2324"))
        .cloned()
        .ok_or_else(|| "This CHD has no data track (it looks like an audio CD).".to_string())?;
    let stride = track.sector_bytes().unwrap() as u64;

    // A stored pregap shifts where LBA 0 sits; pick whichever base holds the
    // ISO9660 volume descriptor at LBA 16.
    let mut bases = vec![track.start_frame];
    if track.pregap_stored {
        bases.push(track.start_frame + track.pregap as u64);
    }
    let mut chosen = bases[0];
    for &b in &bases {
        let mut s = vec![0u8; stride as usize];
        let off = (b + 16) * CD_FRAME_BYTES;
        if hunks.read_at(off, &mut s).map(|n| n == s.len()).unwrap_or(false) && has_volume_descriptor(&s) {
            chosen = b;
            break;
        }
    }
    let used_pregap = if chosen > track.start_frame { track.pregap as u64 } else { 0 };
    let sectors = (track.frames as u64).saturating_sub(used_pregap);
    let info = ChdInfo {
        data_track: Some(track.number),
        stride: stride as u32,
        sectors,
        hunk_bytes,
        logical_bytes,
        flat: false,
        cue_mode: track.cue_mode().map(|s| s.to_string()),
        tracks,
    };
    let view = ChdTrackView {
        hunks,
        base: chosen * CD_FRAME_BYTES,
        frame: CD_FRAME_BYTES,
        stride,
        sectors,
        pos: 0,
    };
    Ok((view, info))
}

/// Result of [`export_data_track`].
#[derive(Debug, Clone, Serialize)]
pub struct ExportedTrack {
    pub bin_path: String,
    /// `None` for a flat CHD (the output is a plain `.iso`).
    pub cue_path: Option<String>,
    pub bytes: u64,
    pub sectors: u64,
    pub mode: Option<String>,
}

/// Write the first data track of `chd` to `<out_dir>/<stem>.bin` plus a
/// one-track `<stem>.cue` (or a plain `<stem>.iso` for a flat CHD).
///
/// Tools that only accept `.cue`/`.bin` input (PSXRecomp's project setup)
/// can then read the game without the user installing `chdman`. `progress`
/// gets `(bytes_done, bytes_total)` and returns `false` to cancel.
pub fn export_data_track(
    chd: &Path,
    out_dir: &Path,
    stem: &str,
    progress: &mut dyn FnMut(u64, u64) -> bool,
) -> Result<ExportedTrack, String> {
    let (mut view, info) = open_data_track(chd)?;
    std::fs::create_dir_all(out_dir).map_err(|e| format!("Cannot create {}: {e}", out_dir.display()))?;
    let ext = if info.flat { "iso" } else { "bin" };
    let bin_path = out_dir.join(format!("{stem}.{ext}"));
    let total = info.sectors * info.stride as u64;
    let tmp = out_dir.join(format!("{stem}.{ext}.part"));
    {
        let mut out = std::io::BufWriter::with_capacity(
            1 << 20,
            File::create(&tmp).map_err(|e| format!("Cannot create {}: {e}", tmp.display()))?,
        );
        let mut buf = vec![0u8; 1 << 20];
        let mut done = 0u64;
        while done < total {
            let want = ((total - done) as usize).min(buf.len());
            view.read_exact(&mut buf[..want]).map_err(|e| format!("Reading the CHD failed: {e}"))?;
            out.write_all(&buf[..want]).map_err(|e| format!("Writing {} failed: {e}", tmp.display()))?;
            done += want as u64;
            if !progress(done, total) {
                drop(out);
                let _ = std::fs::remove_file(&tmp);
                return Err("Cancelled.".into());
            }
        }
        out.flush().map_err(|e| format!("Writing {} failed: {e}", tmp.display()))?;
    }
    std::fs::rename(&tmp, &bin_path).map_err(|e| format!("Cannot finish {}: {e}", bin_path.display()))?;

    let cue_path = match &info.cue_mode {
        Some(mode) if !info.flat => {
            let cue = out_dir.join(format!("{stem}.cue"));
            let bin_name = bin_path.file_name().unwrap().to_string_lossy();
            let text = format!(
                "FILE \"{bin_name}\" BINARY\r\n  TRACK 01 {mode}\r\n    INDEX 01 00:00:00\r\n"
            );
            std::fs::write(&cue, text).map_err(|e| format!("Cannot write {}: {e}", cue.display()))?;
            Some(cue.to_string_lossy().to_string())
        }
        _ => None,
    };
    Ok(ExportedTrack {
        bin_path: bin_path.to_string_lossy().to_string(),
        cue_path,
        bytes: total,
        sectors: info.sectors,
        mode: info.cue_mode,
    })
}
