//! Disc-image ingest layer: a streaming ISO9660 reader.
//!
//! This is the "point it at an ISO" half of Aura's one-click pipeline. It reads
//! the ISO9660 volume out of the container layouts console disc images use,
//! lists the file tree, and extracts files — all without loading the whole
//! image into memory (a PS2 DVD is up to ~8 GB).
//!
//! Supported sector layouts (auto-detected by looking for the `CD001` volume
//! descriptor at LBA 16):
//!
//! | layout                         | stride | data offset | typical file        |
//! |--------------------------------|--------|-------------|---------------------|
//! | cooked                         | 2048   | 0           | `.iso`              |
//! | raw MODE1                      | 2352   | 16          | `.bin` / `.img`     |
//! | raw MODE2 form 1               | 2352   | 24          | `.bin` (PS1/PS2 CD) |
//! | MODE2                          | 2336   | 8           | rare                |
//! | raw + subchannel               | 2448   | 16 / 24     | rare                |
//!
//! CHD images (`chdman createcd`, the usual format of retro collections) are
//! read directly through [`crate::chd_disc`]: the first data track is
//! decompressed on demand and parsed like any `.bin`.
//!
//! Not supported (reported with an actionable message, never silently
//! mis-read): CSO/ZSO and archives — convert to `.iso`/`.bin` first.
//!
//! Pure Rust, no Tauri dependency, generic over `Read + Seek` so it can be
//! unit-tested against in-memory images. Every length read from the image is
//! bounds-checked: a malformed or hostile image yields an `Err`, not a panic,
//! an unbounded allocation, or an infinite directory walk.

use serde::Serialize;
use std::collections::HashSet;
use std::fs;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

/// Bytes of user data in one logical (cooked) sector.
pub const SECTOR_DATA: u64 = 2048;
/// Largest single file we will read fully into memory (ELFs, SYSTEM.CNF…).
pub const MAX_IN_MEMORY: u64 = 256 * 1024 * 1024;
/// Largest directory extent we will parse.
const MAX_DIR_BYTES: u64 = 64 * 1024 * 1024;
/// Hard caps that keep a hostile image from exhausting memory or time.
const MAX_ENTRIES: usize = 500_000;
const MAX_DEPTH: usize = 32;
/// Sectors fetched per read while streaming (512 KiB of user data).
const CHUNK_SECTORS: u64 = 256;

// ---------------------------------------------------------------------------
// Sector layouts
// ---------------------------------------------------------------------------

/// How user data is laid out inside the image file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct SectorLayout {
    /// Bytes from the start of one sector to the start of the next.
    pub stride: u32,
    /// Offset of the 2048 user-data bytes inside a sector.
    pub data_offset: u32,
}

/// Probed in order; the first whose LBA-16 holds a primary volume descriptor wins.
const LAYOUTS: [SectorLayout; 6] = [
    SectorLayout { stride: 2048, data_offset: 0 },
    SectorLayout { stride: 2352, data_offset: 16 },
    SectorLayout { stride: 2352, data_offset: 24 },
    SectorLayout { stride: 2336, data_offset: 8 },
    SectorLayout { stride: 2448, data_offset: 16 },
    SectorLayout { stride: 2448, data_offset: 24 },
];

impl SectorLayout {
    /// Human-readable description for UIs and logs.
    pub fn label(&self) -> &'static str {
        match (self.stride, self.data_offset) {
            (2048, 0) => "cooked 2048-byte sectors (.iso)",
            (2352, 16) => "raw MODE1 2352-byte sectors (.bin)",
            (2352, 24) => "raw MODE2/form1 2352-byte sectors (.bin)",
            (2336, 8) => "MODE2 2336-byte sectors",
            (2448, 16) | (2448, 24) => "raw sectors with subchannel (2448 bytes)",
            _ => "custom sector layout",
        }
    }
}

// ---------------------------------------------------------------------------
// Public data types
// ---------------------------------------------------------------------------

/// Fields of the ISO9660 primary volume descriptor that matter to Aura.
#[derive(Debug, Clone, Default, Serialize)]
pub struct VolumeInfo {
    pub system_id: String,
    pub volume_id: String,
    /// Declared volume size in logical blocks.
    pub volume_sectors: u32,
    pub block_size: u16,
    pub root_lba: u32,
    pub root_size: u32,
}

/// One file or directory in the volume.
#[derive(Debug, Clone, Serialize)]
pub struct DiscEntry {
    /// `/`-joined path from the volume root, no leading slash, with the
    /// ISO9660 `;1` version suffix removed.
    pub path: String,
    pub is_dir: bool,
    pub size: u64,
    /// First extent's starting LBA (0 for directories we did not descend into).
    pub lba: u32,
    /// All `(lba, bytes)` extents. Almost always one; >1 for multi-extent files.
    pub extents: Vec<(u32, u64)>,
}

impl DiscEntry {
    /// Final path component.
    pub fn name(&self) -> &str {
        self.path.rsplit('/').next().unwrap_or(&self.path)
    }
}

/// Progress snapshot handed to extraction callbacks.
#[derive(Debug, Clone, Serialize, Default)]
pub struct ExtractProgress {
    pub files_done: usize,
    pub files_total: usize,
    pub bytes_done: u64,
    pub bytes_total: u64,
    /// Disc path of the file being written.
    pub current: String,
}

/// One extracted file, as it landed on the host.
#[derive(Debug, Clone, Serialize)]
pub struct ExtractedFile {
    pub disc_path: String,
    /// Path relative to the extraction root (sanitised for the host OS).
    pub rel_path: String,
    pub size: u64,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct ExtractSummary {
    pub root: String,
    pub files: Vec<ExtractedFile>,
    pub bytes: u64,
}

// ---------------------------------------------------------------------------
// Opening an image
// ---------------------------------------------------------------------------

/// A parsed disc image positioned on an ISO9660 volume.
pub struct DiscImage<R: Read + Seek> {
    src: R,
    layout: SectorLayout,
    image_len: u64,
    total_sectors: u64,
    volume: VolumeInfo,
}

fn io_err(e: std::io::Error) -> String {
    format!("I/O error reading disc image: {e}")
}

fn ascii_trim(b: &[u8]) -> String {
    String::from_utf8_lossy(b)
        .trim_matches(|c: char| c == '\0' || c == ' ')
        .to_string()
}

/// Find the layout whose LBA 16 begins with a primary volume descriptor
/// (`01 "CD001" 01`).
fn detect_layout<R: Read + Seek>(src: &mut R, len: u64) -> Option<SectorLayout> {
    for l in LAYOUTS {
        let off = 16 * l.stride as u64 + l.data_offset as u64;
        if off + 8 > len {
            continue;
        }
        let mut b = [0u8; 8];
        if src.seek(SeekFrom::Start(off)).is_err() || src.read_exact(&mut b).is_err() {
            continue;
        }
        if b[0] == 1 && &b[1..6] == b"CD001" && b[6] == 1 {
            return Some(l);
        }
    }
    None
}

fn parse_pvd(s: &[u8]) -> Result<VolumeInfo, String> {
    if s.len() < 190 || s[0] != 1 || &s[1..6] != b"CD001" {
        return Err("Primary volume descriptor not found".into());
    }
    let block_size = u16::from_le_bytes([s[128], s[129]]);
    if block_size != SECTOR_DATA as u16 {
        return Err(format!("Unsupported logical block size {block_size} (expected 2048)"));
    }
    let le32 = |o: usize| u32::from_le_bytes([s[o], s[o + 1], s[o + 2], s[o + 3]]);
    Ok(VolumeInfo {
        system_id: ascii_trim(&s[8..40]),
        volume_id: ascii_trim(&s[40..72]),
        volume_sectors: le32(80),
        block_size,
        root_lba: le32(156 + 2),
        root_size: le32(156 + 10),
    })
}

impl<R: Read + Seek> DiscImage<R> {
    /// Detect the sector layout and parse the primary volume descriptor.
    pub fn open(mut src: R) -> Result<Self, String> {
        let image_len = src.seek(SeekFrom::End(0)).map_err(io_err)?;
        let layout = detect_layout(&mut src, image_len).ok_or_else(|| {
            "No ISO9660 volume found (tried 2048, 2336, 2352 and 2448-byte sector layouts). \
             The file may be a compressed/proprietary format or not a data disc."
                .to_string()
        })?;
        let total_sectors = image_len / layout.stride as u64;
        let mut img = DiscImage {
            src,
            layout,
            image_len,
            total_sectors,
            volume: VolumeInfo::default(),
        };
        let mut pvd = Vec::new();
        img.read_sectors(16, 1, &mut pvd)?;
        img.volume = parse_pvd(&pvd)?;
        Ok(img)
    }

    pub fn layout(&self) -> SectorLayout {
        self.layout
    }

    pub fn volume(&self) -> &VolumeInfo {
        &self.volume
    }

    pub fn image_len(&self) -> u64 {
        self.image_len
    }

    /// True when the volume descriptor claims more sectors than the file holds
    /// (an incomplete download/dump). Files stored before the cut still read.
    pub fn is_truncated(&self) -> bool {
        self.missing_sectors() > 0
    }

    /// Sectors the image actually holds.
    pub fn held_sectors(&self) -> u64 {
        self.total_sectors
    }

    /// How many sectors the volume descriptor claims beyond what the image
    /// holds (0 for a complete image). A dump that only lacks trailing blank
    /// sectors is a small number that no file reaches into.
    pub fn missing_sectors(&self) -> u64 {
        (self.volume.volume_sectors as u64).saturating_sub(self.total_sectors)
    }

    /// True when any part of the file's data lies at or past the end of the
    /// image, so it cannot be read in full. Directories are never "cut".
    pub fn entry_is_cut(&self, e: &DiscEntry) -> bool {
        if e.is_dir || e.size == 0 {
            return false;
        }
        let whole = [(e.lba, e.size)];
        let extents: &[(u32, u64)] = if e.extents.is_empty() { &whole } else { &e.extents };
        extents.iter().any(|(lba, bytes)| {
            *bytes > 0 && (*lba as u64).saturating_add(bytes.div_ceil(SECTOR_DATA)) > self.total_sectors
        })
    }

    /// Append `count` sectors of user data starting at `lba` to `out`.
    fn read_sectors(&mut self, lba: u64, count: u64, out: &mut Vec<u8>) -> Result<(), String> {
        if count == 0 {
            return Ok(());
        }
        let end = lba
            .checked_add(count)
            .ok_or_else(|| "Sector range overflow".to_string())?;
        if end > self.total_sectors {
            return Err(format!(
                "Read of sectors {lba}..{end} is past the end of the image \
                 ({} sectors) — the image looks truncated",
                self.total_sectors
            ));
        }
        let stride = self.layout.stride as u64;
        self.src.seek(SeekFrom::Start(lba * stride)).map_err(io_err)?;
        if self.layout.stride == 2048 && self.layout.data_offset == 0 {
            let start = out.len();
            out.resize(start + (count * SECTOR_DATA) as usize, 0);
            self.src.read_exact(&mut out[start..]).map_err(io_err)?;
        } else {
            let mut raw = vec![0u8; (count * stride) as usize];
            self.src.read_exact(&mut raw).map_err(io_err)?;
            let off = self.layout.data_offset as u64;
            for i in 0..count {
                let s = (i * stride + off) as usize;
                out.extend_from_slice(&raw[s..s + SECTOR_DATA as usize]);
            }
        }
        Ok(())
    }

    /// Read `size` bytes starting at sector `lba` into memory (bounded by `limit`).
    pub fn read_extent(&mut self, lba: u32, size: u64, limit: u64) -> Result<Vec<u8>, String> {
        if size > limit {
            return Err(format!(
                "Refusing to load {size} bytes into memory (limit {limit}); extract it to disk instead"
            ));
        }
        let sectors = (size + SECTOR_DATA - 1) / SECTOR_DATA;
        let mut out = Vec::with_capacity((sectors * SECTOR_DATA) as usize);
        let mut cur = lba as u64;
        let mut left = sectors;
        while left > 0 {
            let n = left.min(CHUNK_SECTORS);
            self.read_sectors(cur, n, &mut out)?;
            cur += n;
            left -= n;
        }
        out.truncate(size as usize);
        Ok(out)
    }

    /// Read a whole file into memory (bounded by [`MAX_IN_MEMORY`]).
    pub fn read_file(&mut self, e: &DiscEntry) -> Result<Vec<u8>, String> {
        if e.is_dir {
            return Err(format!("{} is a directory", e.path));
        }
        if e.size > MAX_IN_MEMORY {
            return Err(format!("{} is too large to load into memory ({} bytes)", e.path, e.size));
        }
        let mut out = Vec::with_capacity(e.size as usize);
        for &(lba, sz) in &e.extents {
            out.extend_from_slice(&self.read_extent(lba, sz, MAX_IN_MEMORY)?);
        }
        Ok(out)
    }

    /// Read at most the first `n` bytes of a file (cheap magic sniffing).
    pub fn read_file_head(&mut self, e: &DiscEntry, n: usize) -> Result<Vec<u8>, String> {
        let Some(&(lba, sz)) = e.extents.first() else {
            return Ok(Vec::new());
        };
        self.read_extent(lba, sz.min(n as u64), MAX_IN_MEMORY)
    }

    /// Recursively list every file and directory in the volume.
    ///
    /// Directory loops (a record pointing at one of its ancestors) are broken
    /// by remembering visited extents; nesting is capped at [`MAX_DEPTH`].
    pub fn list_entries(&mut self) -> Result<Vec<DiscEntry>, String> {
        let mut out: Vec<DiscEntry> = Vec::new();
        let mut visited: HashSet<u32> = HashSet::new();
        let root = (self.volume.root_lba, self.volume.root_size as u64);
        visited.insert(root.0);
        let mut stack: Vec<(String, u32, u64, usize)> = vec![(String::new(), root.0, root.1, 0)];

        while let Some((prefix, lba, size, depth)) = stack.pop() {
            if depth > MAX_DEPTH {
                return Err(format!("Directory nesting deeper than {MAX_DEPTH} levels — refusing to continue"));
            }
            let bytes = self.read_extent(lba, size, MAX_DIR_BYTES)?;
            for rec in parse_dir_records(&bytes) {
                let path = if prefix.is_empty() {
                    rec.name.clone()
                } else {
                    format!("{prefix}/{}", rec.name)
                };
                let (first_lba, _) = rec.extents[0];
                if rec.is_dir {
                    if visited.insert(first_lba) {
                        stack.push((path.clone(), first_lba, rec.size, depth + 1));
                    }
                    out.push(DiscEntry { path, is_dir: true, size: rec.size, lba: first_lba, extents: vec![] });
                } else {
                    out.push(DiscEntry {
                        path,
                        is_dir: false,
                        size: rec.size,
                        lba: first_lba,
                        extents: rec.extents,
                    });
                }
                if out.len() > MAX_ENTRIES {
                    return Err(format!("Volume has more than {MAX_ENTRIES} entries — refusing to continue"));
                }
            }
        }
        out.sort_by(|a, b| a.path.to_lowercase().cmp(&b.path.to_lowercase()));
        Ok(out)
    }

    /// Stream one file to `w`. `on_bytes` is told how many bytes each chunk
    /// carried and returns `false` to cancel.
    pub fn copy_entry(
        &mut self,
        e: &DiscEntry,
        w: &mut dyn Write,
        on_bytes: &mut dyn FnMut(u64) -> bool,
    ) -> Result<u64, String> {
        if e.is_dir {
            return Err(format!("{} is a directory", e.path));
        }
        let mut total = 0u64;
        let mut buf: Vec<u8> = Vec::new();
        for &(lba, size) in &e.extents {
            let mut cur = lba as u64;
            let mut remaining = size;
            while remaining > 0 {
                let want = ((remaining + SECTOR_DATA - 1) / SECTOR_DATA).min(CHUNK_SECTORS);
                buf.clear();
                self.read_sectors(cur, want, &mut buf)?;
                let take = remaining.min(buf.len() as u64) as usize;
                w.write_all(&buf[..take])
                    .map_err(|e| format!("Write failed: {e}"))?;
                total += take as u64;
                remaining -= take as u64;
                cur += want;
                if !on_bytes(take as u64) {
                    return Err("Extraction cancelled".into());
                }
            }
        }
        Ok(total)
    }

    /// Extract `entries` (directories are ignored) under `out_dir`, preserving
    /// the disc's directory structure with host-safe names.
    ///
    /// `on_progress` is throttled (≈10 Hz plus file boundaries) and returns
    /// `false` to cancel; a cancelled extraction removes its partial file.
    pub fn extract_entries(
        &mut self,
        entries: &[DiscEntry],
        out_dir: &Path,
        on_progress: &mut dyn FnMut(&ExtractProgress) -> bool,
    ) -> Result<ExtractSummary, String> {
        let files: Vec<&DiscEntry> = entries.iter().filter(|e| !e.is_dir).collect();
        let mut prog = ExtractProgress {
            files_total: files.len(),
            bytes_total: files.iter().map(|e| e.size).sum(),
            ..Default::default()
        };
        let mut summary = ExtractSummary { root: out_dir.to_string_lossy().to_string(), ..Default::default() };
        let mut used: HashSet<String> = HashSet::new();
        fs::create_dir_all(out_dir).map_err(|e| format!("Cannot create {}: {e}", out_dir.display()))?;

        let mut last_emit = Instant::now() - Duration::from_secs(1);
        for e in files {
            let rel = unique_rel_path(&e.path, &mut used);
            let dest: PathBuf = rel.split('/').fold(out_dir.to_path_buf(), |p, c| p.join(c));
            if let Some(parent) = dest.parent() {
                fs::create_dir_all(parent)
                    .map_err(|er| format!("Cannot create {}: {er}", parent.display()))?;
            }
            prog.current = e.path.clone();
            if !on_progress(&prog) {
                return Err("Extraction cancelled".into());
            }

            // Chunks arrive already large (up to 512 KiB), so write straight to
            // the file: a per-file buffer only adds an allocation per file.
            let mut w = fs::File::create(&dest)
                .map_err(|er| format!("Cannot create {}: {er}", dest.display()))?;
            let mut cancelled = false;
            let base = prog.bytes_done;
            let mut file_bytes = 0u64;
            let result = {
                let mut cb = |n: u64| {
                    file_bytes += n;
                    prog.bytes_done = base + file_bytes;
                    if last_emit.elapsed() >= Duration::from_millis(100) {
                        last_emit = Instant::now();
                        if !on_progress(&prog) {
                            cancelled = true;
                            return false;
                        }
                    }
                    true
                };
                self.copy_entry(e, &mut w, &mut cb)
            };
            let flushed = w.flush();
            drop(w);
            match result {
                Ok(n) => {
                    flushed.map_err(|er| format!("Write failed for {}: {er}", dest.display()))?;
                    prog.files_done += 1;
                    prog.bytes_done = base + n;
                    summary.bytes += n;
                    summary.files.push(ExtractedFile { disc_path: e.path.clone(), rel_path: rel, size: n });
                }
                Err(err) => {
                    let _ = fs::remove_file(&dest);
                    return Err(if cancelled { "Extraction cancelled".into() } else { err });
                }
            }
        }
        on_progress(&prog);
        Ok(summary)
    }
}

// ---------------------------------------------------------------------------
// Directory record parsing
// ---------------------------------------------------------------------------

struct RawRecord {
    name: String,
    is_dir: bool,
    extents: Vec<(u32, u64)>,
    size: u64,
}

/// Strip the `;N` version suffix and a dangling `.` from an ISO9660 name.
fn clean_name(raw: &[u8]) -> String {
    let mut s = String::from_utf8_lossy(raw).to_string();
    if let Some(i) = s.rfind(';') {
        if s[i + 1..].chars().all(|c| c.is_ascii_digit()) {
            s.truncate(i);
        }
    }
    if s.ends_with('.') && s.len() > 1 {
        s.pop();
    }
    s
}

/// Parse the records of one directory extent. Malformed records end the walk
/// of that directory rather than aborting the whole listing.
fn parse_dir_records(buf: &[u8]) -> Vec<RawRecord> {
    let mut recs: Vec<RawRecord> = Vec::new();
    let mut pending: Option<RawRecord> = None;
    let mut pos = 0usize;
    while pos < buf.len() {
        let len = buf[pos] as usize;
        if len == 0 {
            // Records never straddle sectors: a zero length means "skip to the
            // next sector boundary".
            pos = (pos / SECTOR_DATA as usize + 1) * SECTOR_DATA as usize;
            continue;
        }
        if len < 34 || pos + len > buf.len() {
            break;
        }
        let r = &buf[pos..pos + len];
        pos += len;
        let name_len = r[32] as usize;
        if 33 + name_len > len {
            continue;
        }
        let name_bytes = &r[33..33 + name_len];
        if name_len == 1 && (name_bytes[0] == 0 || name_bytes[0] == 1) {
            continue; // "." and ".."
        }
        let name = clean_name(name_bytes);
        if name.is_empty() {
            continue;
        }
        let flags = r[25];
        let lba = u32::from_le_bytes([r[2], r[3], r[4], r[5]]);
        let size = u32::from_le_bytes([r[10], r[11], r[12], r[13]]) as u64;
        let is_dir = flags & 0x02 != 0;
        let more = flags & 0x80 != 0 && !is_dir;
        let rec = RawRecord { name, is_dir, extents: vec![(lba, size)], size };

        if let Some(mut p) = pending.take() {
            if p.name == rec.name && !rec.is_dir {
                p.extents.extend(rec.extents.iter().copied());
                p.size += rec.size;
                if more {
                    pending = Some(p);
                } else {
                    recs.push(p);
                }
                continue;
            }
            recs.push(p); // unterminated multi-extent run: keep what we have
        }
        if more {
            pending = Some(rec);
        } else {
            recs.push(rec);
        }
    }
    if let Some(p) = pending {
        recs.push(p);
    }
    recs
}

// ---------------------------------------------------------------------------
// Path helpers
// ---------------------------------------------------------------------------

/// Make one path component safe to create on Windows/macOS/Linux: no
/// separators or reserved characters, no `.`/`..`, no trailing dot/space and
/// no Windows device names.
pub fn sanitize_component(name: &str) -> String {
    let mut s: String = name
        .chars()
        .map(|c| match c {
            '<' | '>' | ':' | '"' | '/' | '\\' | '|' | '?' | '*' => '_',
            c if (c as u32) < 0x20 || c as u32 == 0x7f => '_',
            c => c,
        })
        .collect();
    while s.ends_with('.') || s.ends_with(' ') {
        s.pop();
    }
    let mut s = s.trim_start().to_string();
    if s.is_empty() {
        return "_".into();
    }
    let stem = s.split('.').next().unwrap_or("").to_ascii_uppercase();
    let is_com_lpt = stem.len() == 4
        && (stem.starts_with("COM") || stem.starts_with("LPT"))
        && stem.as_bytes()[3].is_ascii_digit();
    if matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL") || is_com_lpt {
        s.insert(0, '_');
    }
    s
}

/// Sanitise a disc path component-by-component and make it unique (case-
/// insensitively) among `used`, so two disc names that collapse to the same
/// host name never overwrite each other.
fn unique_rel_path(disc_path: &str, used: &mut HashSet<String>) -> String {
    let base: Vec<String> = disc_path.split('/').filter(|c| !c.is_empty()).map(sanitize_component).collect();
    let mut candidate = base.join("/");
    let mut n = 1;
    while !used.insert(candidate.to_lowercase()) {
        let mut parts = base.clone();
        if let Some(last) = parts.last_mut() {
            let (stem, ext) = match last.rfind('.') {
                Some(i) if i > 0 => (last[..i].to_string(), last[i..].to_string()),
                _ => (last.clone(), String::new()),
            };
            *last = format!("{stem}_{n}{ext}");
        }
        candidate = parts.join("/");
        n += 1;
    }
    candidate
}

/// Normalise a path for case-insensitive comparison against a listing:
/// forward slashes, no leading slash, no `;N` version suffix.
pub fn normalize_lookup(path: &str) -> String {
    let p = path.replace('\\', "/");
    let p = p.trim_start_matches('/');
    let p = match p.rfind(';') {
        Some(i) if p[i + 1..].chars().all(|c| c.is_ascii_digit()) => &p[..i],
        _ => p,
    };
    p.to_lowercase()
}

/// Case-insensitive file lookup in a listing.
pub fn find_entry<'a>(entries: &'a [DiscEntry], path: &str) -> Option<&'a DiscEntry> {
    let want = normalize_lookup(path);
    entries.iter().find(|e| !e.is_dir && e.path.to_lowercase() == want)
}

// ---------------------------------------------------------------------------
// Opening from the filesystem
// ---------------------------------------------------------------------------

/// Reject containers we recognise but cannot read, with an actionable message.
fn check_unsupported_container(head: &[u8], path: &str) -> Result<(), String> {
    if head.len() >= 8 && &head[0..8] == b"MComprHD" {
        return Err("This is a CHD compressed image. Convert it first with MAME's `chdman extractcd` \
                    (CD) or `chdman extractdvd` (DVD), then open the resulting .iso/.bin."
            .into());
    }
    if head.len() >= 4 && (&head[0..4] == b"CISO" || &head[0..4] == b"ZISO") {
        return Err("This is a compressed ISO (CSO/ZSO). Decompress it to a plain .iso first \
                    (for example with `maxcso --decompress`)."
            .into());
    }
    if head.len() >= 2 && head[0] == 0x1f && head[1] == 0x8b {
        return Err("This file is gzip-compressed. Decompress it first.".into());
    }
    if head.len() >= 4 && (&head[0..4] == b"PK\x03\x04" || &head[0..4] == b"7z\xBC\xAF" || &head[0..4] == b"Rar!") {
        return Err(format!(
            "{path} is an archive, not a disc image. Extract the .iso/.bin from it first."
        ));
    }
    Ok(())
}

/// Resolve every `FILE` referenced by a `.cue` sheet, relative to its folder.
fn cue_files(cue_path: &Path) -> Result<Vec<PathBuf>, String> {
    let text = fs::read_to_string(cue_path)
        .or_else(|_| fs::read(cue_path).map(|b| String::from_utf8_lossy(&b).to_string()))
        .map_err(|e| format!("Cannot read {}: {e}", cue_path.display()))?;
    let dir = cue_path.parent().unwrap_or_else(|| Path::new("."));
    let mut out = Vec::new();
    for line in text.lines() {
        let l = line.trim();
        if !l.to_ascii_uppercase().starts_with("FILE ") {
            continue;
        }
        let rest = l[5..].trim();
        let name = if let Some(stripped) = rest.strip_prefix('"') {
            stripped.split('"').next().unwrap_or("").to_string()
        } else {
            rest.split_whitespace().next().unwrap_or("").to_string()
        };
        if !name.is_empty() {
            out.push(dir.join(name));
        }
    }
    if out.is_empty() {
        return Err(format!("{} lists no FILE entries", cue_path.display()));
    }
    Ok(out)
}

/// Anything a [`DiscImage`] can read from: a plain file, or a CHD data track.
pub trait ReadSeek: Read + Seek {}
impl<T: Read + Seek> ReadSeek for T {}
/// The boxed source [`open_disc_file`] returns.
pub type DiscSource = Box<dyn ReadSeek>;

/// Open a disc image from disk. `.cue` sheets are followed to their data
/// track and `.chd` images are read through their first data track. Returns
/// the image plus the path that was actually opened.
pub fn open_disc_file(path: &str) -> Result<(DiscImage<DiscSource>, PathBuf), String> {
    let p = Path::new(path);
    let is_cue = p
        .extension()
        .map(|e| e.eq_ignore_ascii_case("cue"))
        .unwrap_or(false);
    let candidates: Vec<PathBuf> = if is_cue { cue_files(p)? } else { vec![p.to_path_buf()] };

    let mut first_err: Option<String> = None;
    for cand in candidates {
        let mut f = fs::File::open(&cand)
            .map_err(|e| format!("Cannot open {}: {e}", cand.display()))?;
        let mut head = [0u8; 16];
        let n = f.read(&mut head).map_err(io_err)?;
        let source: DiscSource = if crate::chd_disc::is_chd(&head[..n]) {
            drop(f);
            let (view, _info) = crate::chd_disc::open_data_track(&cand)?;
            Box::new(view)
        } else {
            if let Err(e) = check_unsupported_container(&head[..n], &cand.to_string_lossy()) {
                return Err(e);
            }
            Box::new(f)
        };
        match DiscImage::open(source) {
            Ok(img) => return Ok((img, cand)),
            Err(e) => {
                first_err.get_or_insert(e);
            }
        }
    }
    Err(first_err.unwrap_or_else(|| "Could not open disc image".into()))
}
