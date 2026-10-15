//! Tests for the PS1 side: PS-X EXE parsing, CHD reading (`chd_disc`) and PS1
//! disc recognition. CHD fixtures are written by a tiny uncompressed-V5 CHD
//! writer below, so the whole path (header, map, metadata, hunks, track
//! arithmetic, ISO9660 parsing) runs without `chdman` or a real image. Real
//! compressed CHDs are exercised separately by hand against a collection.

use crate::chd_disc::{self, CdTrack, CD_FRAME_BYTES};
use crate::disc::DiscImage;
use crate::psx_exe;
use crate::tests_disc::{build_iso, wrap_layout, Node, TempDir};
use std::io::{Cursor, Read, Seek, SeekFrom};

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

/// A PS-X EXE: 0x800-byte header plus `text` bytes of program.
pub(crate) fn psx_exe_bytes(entry: u32, load: u32, text: usize, marker: &str) -> Vec<u8> {
    let mut b = vec![0u8; 0x800 + text];
    b[..8].copy_from_slice(psx_exe::MAGIC);
    b[0x10..0x14].copy_from_slice(&entry.to_le_bytes());
    b[0x14..0x18].copy_from_slice(&0x8007_0000u32.to_le_bytes());
    b[0x18..0x1C].copy_from_slice(&load.to_le_bytes());
    b[0x1C..0x20].copy_from_slice(&(text as u32).to_le_bytes());
    b[0x30..0x34].copy_from_slice(&0x801F_FFF0u32.to_le_bytes());
    b[0x4C..0x4C + marker.len()].copy_from_slice(marker.as_bytes());
    for (i, x) in b[0x800..].iter_mut().enumerate() {
        *x = (i % 251) as u8;
    }
    b
}

/// A cooked ISO9660 image of a PS1 game.
pub(crate) fn ps1_iso(boot_name: &str, exe: Vec<u8>) -> Vec<u8> {
    let cnf = format!("BOOT = cdrom:\\{boot_name};1\r\nTCB = 4\r\nEVENT = 10\r\nSTACK = 801FFF00\r\n");
    build_iso(
        "PS1_TEST",
        &[
            ("SYSTEM.CNF".to_string(), Node::File(cnf.into_bytes())),
            (boot_name.to_string(), Node::File(exe)),
            ("DATA.BIN".to_string(), Node::File(vec![0x5A; 10_000])),
        ],
    )
}

fn tag(s: &[u8; 4]) -> [u8; 4] {
    *s
}

/// An uncompressed CHD V5 holding `logical` bytes, `hunk_bytes` per hunk, with
/// the given metadata entries.
fn chd_v5(logical: &[u8], hunk_bytes: usize, unit_bytes: u32, metadata: &[([u8; 4], Vec<u8>)]) -> Vec<u8> {
    let hunk_count = logical.len().div_ceil(hunk_bytes);
    let map_off = 124usize;
    let meta_off = map_off + hunk_count * 4;

    let mut meta = Vec::new();
    for (i, (t, data)) in metadata.iter().enumerate() {
        let entry_len = 16 + data.len();
        let next = if i + 1 < metadata.len() { (meta_off + meta.len() + entry_len) as u64 } else { 0 };
        meta.extend_from_slice(t);
        meta.extend_from_slice(&((1u32 << 24) | data.len() as u32).to_be_bytes());
        meta.extend_from_slice(&next.to_be_bytes());
        meta.extend_from_slice(data);
    }
    let data_start = (meta_off + meta.len()).div_ceil(hunk_bytes) * hunk_bytes;

    let mut out = Vec::new();
    out.extend_from_slice(b"MComprHD");
    out.extend_from_slice(&124u32.to_be_bytes());
    out.extend_from_slice(&5u32.to_be_bytes());
    out.extend_from_slice(&[0u8; 16]); // compressors: none
    out.extend_from_slice(&(logical.len() as u64).to_be_bytes());
    out.extend_from_slice(&(map_off as u64).to_be_bytes());
    out.extend_from_slice(&(if metadata.is_empty() { 0u64 } else { meta_off as u64 }).to_be_bytes());
    out.extend_from_slice(&(hunk_bytes as u32).to_be_bytes());
    out.extend_from_slice(&unit_bytes.to_be_bytes());
    out.extend_from_slice(&[0u8; 60]); // rawsha1, sha1, parentsha1
    assert_eq!(out.len(), 124);
    for i in 0..hunk_count {
        out.extend_from_slice(&((data_start / hunk_bytes + i) as u32).to_be_bytes());
    }
    out.extend_from_slice(&meta);
    out.resize(data_start, 0);
    out.extend_from_slice(logical);
    out.resize(data_start + hunk_count * hunk_bytes, 0);
    out
}

/// Turn raw 2352-byte sectors into 2448-byte CHD frames (zero subcode) padded
/// to a multiple of four frames.
fn to_frames(raw: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    for s in raw.chunks(2352) {
        let mut f = vec![0u8; 2448];
        f[..s.len()].copy_from_slice(s);
        out.extend_from_slice(&f);
    }
    while (out.len() / 2448) % 4 != 0 {
        out.extend_from_slice(&[0u8; 2448]);
    }
    out
}

fn cht2(track: u32, kind: &str, frames: usize) -> ([u8; 4], Vec<u8>) {
    let mut s = format!(
        "TRACK:{track} TYPE:{kind} SUBTYPE:NONE FRAMES:{frames} PREGAP:0 PGTYPE:MODE1 PGSUB:NONE POSTGAP:0"
    )
    .into_bytes();
    s.push(0);
    (tag(b"CHT2"), s)
}

/// A one-data-track PS1 CD as a CHD, plus the raw 2352-byte track it holds.
fn ps1_chd() -> (Vec<u8>, Vec<u8>) {
    let iso = ps1_iso("SLUS_004.04", psx_exe_bytes(0x8001_0000, 0x8001_0000, 4096, "Sony Computer Entertainment Inc. for North America area"));
    let raw = wrap_layout(&iso, 2352, 24);
    let frames = raw.len() / 2352;
    let chd = chd_v5(&to_frames(&raw), 8 * 2448, 2448, &[cht2(1, "MODE2_RAW", frames)]);
    (chd, raw)
}

/// A valid one-track PS1 CHD (for other test modules).
pub(crate) fn chd_fixture() -> Vec<u8> {
    ps1_chd().0
}

// ---------------------------------------------------------------------------
// PS-X EXE
// ---------------------------------------------------------------------------

mod psx_exe_tests {
    use super::*;

    #[test]
    fn header_fields_are_read() {
        let b = psx_exe_bytes(0x8001_2345, 0x8001_0000, 0x4000, "Sony Computer Entertainment Inc. for Europe area");
        let i = psx_exe::parse(&b[..0x800]).unwrap();
        assert_eq!(i.entry_pc, 0x8001_2345);
        assert_eq!(i.load_addr, 0x8001_0000);
        assert_eq!(i.text_size, 0x4000);
        assert_eq!(i.gp, 0x8007_0000);
        assert_eq!(i.initial_sp, 0x801F_FFF0);
        assert_eq!(i.marker_region(), Some("PAL (Europe)"));
        assert!(i.entry_in_text());
    }

    #[test]
    fn regions_come_from_the_licence_marker() {
        let mk = |m: &str| psx_exe::parse(&psx_exe_bytes(0x8001_0000, 0x8001_0000, 16, m)[..0x800]).unwrap();
        assert_eq!(mk("Sony Computer Entertainment Inc. for Japan area").marker_region(), Some("NTSC-J (Japan)"));
        assert_eq!(mk("Sony Computer Entertainment Inc. for North America area").marker_region(), Some("NTSC-U/C (North America)"));
        assert_eq!(mk("Licensed by someone else").marker_region(), None);
        assert_eq!(mk("").marker_region(), None);
    }

    #[test]
    fn entry_outside_the_text_is_flagged() {
        let i = psx_exe::parse(&psx_exe_bytes(0x8002_0000, 0x8001_0000, 0x1000, "x")[..0x800]).unwrap();
        assert!(!i.entry_in_text());
    }

    #[test]
    fn non_exes_and_short_buffers_are_rejected_not_panicked_on() {
        assert!(psx_exe::parse(b"").is_none());
        assert!(psx_exe::parse(b"PS-X EXE").is_none(), "needs at least the fixed header fields");
        assert!(psx_exe::parse(&[0u8; 0x800]).is_none());
        assert!(psx_exe::parse(b"\x7fELF\x01\x01\x01").is_none());
        assert!(!psx_exe::is_psx_exe(b"PS-X EX"));
        // exactly the minimum parses
        let mut m = vec![0u8; psx_exe::MIN_PARSE_BYTES];
        m[..8].copy_from_slice(psx_exe::MAGIC);
        assert!(psx_exe::parse(&m).is_some());
    }

    #[test]
    fn an_unterminated_marker_is_bounded() {
        let mut b = psx_exe_bytes(0x8001_0000, 0x8001_0000, 16, "");
        for x in &mut b[0x4C..0x800] {
            *x = b'A';
        }
        let i = psx_exe::parse(&b[..0x800]).unwrap();
        assert!(i.region_marker.len() <= 128);
    }
}

// ---------------------------------------------------------------------------
// CHD metadata and track arithmetic
// ---------------------------------------------------------------------------

mod track_tests {
    use super::*;

    #[test]
    fn cht2_text_is_parsed() {
        let t = chd_disc::parse_track_text(
            "TRACK:2 TYPE:AUDIO SUBTYPE:NONE FRAMES:20000 PREGAP:150 PGTYPE:VAUDIO PGSUB:NONE POSTGAP:0\0",
        )
        .unwrap();
        assert_eq!((t.number, t.kind.as_str(), t.frames, t.pregap), (2, "AUDIO", 20000, 150));
        assert!(!t.pregap_stored, "a V-prefixed pregap type is virtual");
        assert!(!t.is_data());
    }

    #[test]
    fn stored_pregap_is_recognised() {
        let t = chd_disc::parse_track_text("TRACK:1 TYPE:MODE2_RAW SUBTYPE:NONE FRAMES:100 PREGAP:150 PGTYPE:MODE2_RAW PGSUB:NONE POSTGAP:0").unwrap();
        assert!(t.pregap_stored);
        assert!(t.is_data());
    }

    #[test]
    fn the_older_four_field_form_and_slash_spellings_work() {
        let t = chd_disc::parse_track_text("TRACK:1 TYPE:MODE2/2352 SUBTYPE:NONE FRAMES:42").unwrap();
        assert_eq!(t.kind, "MODE2_RAW");
        assert_eq!(t.sector_bytes(), Some(2352));
        assert_eq!(t.cue_mode(), Some("MODE2/2352"));
        let m1 = chd_disc::parse_track_text("TRACK:1 TYPE:MODE1 SUBTYPE:NONE FRAMES:42").unwrap();
        assert_eq!((m1.sector_bytes(), m1.cue_mode()), (Some(2048), Some("MODE1/2048")));
    }

    #[test]
    fn incomplete_or_garbled_text_is_rejected() {
        assert!(chd_disc::parse_track_text("").is_none());
        assert!(chd_disc::parse_track_text("TRACK:1 TYPE:MODE1").is_none(), "no FRAMES");
        assert!(chd_disc::parse_track_text("TRACK:x TYPE:MODE1 FRAMES:5").is_none());
        assert!(chd_disc::parse_track_text("\u{1}\u{2}\u{3}").is_none());
    }

    #[test]
    fn tracks_are_padded_to_four_frames() {
        let mk = |n, frames| CdTrack { number: n, kind: "MODE2_RAW".into(), frames, pregap: 0, pregap_stored: false, start_frame: 0 };
        let mut v = vec![mk(1, 10), mk(2, 8), mk(3, 5)];
        chd_disc::assign_start_frames(&mut v);
        assert_eq!(v.iter().map(|t| t.start_frame).collect::<Vec<_>>(), [0, 12, 20]);
    }
}

// ---------------------------------------------------------------------------
// Reading a CHD
// ---------------------------------------------------------------------------

mod chd_tests {
    use super::*;

    #[test]
    fn the_data_track_reads_back_exactly_the_original_sectors() {
        let (chd, raw) = ps1_chd();
        let (mut view, info) = chd_disc::open_data_track_from(Cursor::new(chd)).unwrap();
        assert_eq!(info.data_track, Some(1));
        assert_eq!(info.stride, 2352);
        assert_eq!(info.sectors as usize, raw.len() / 2352);
        assert_eq!(info.cue_mode.as_deref(), Some("MODE2/2352"));
        assert!(!info.flat);

        let mut got = Vec::new();
        view.read_to_end(&mut got).unwrap();
        assert_eq!(got.len(), raw.len());
        assert!(got == raw, "track bytes differ from the source sectors");
    }

    #[test]
    fn seeking_lands_on_the_right_bytes_across_hunks() {
        let (chd, raw) = ps1_chd();
        let (mut view, _) = chd_disc::open_data_track_from(Cursor::new(chd)).unwrap();
        // sector 17 starts in the 3rd hunk (8 frames each)
        for &(at, len) in &[(17 * 2352 + 100u64, 700usize), (2352 * 3 - 5, 20), (0, 1), ((raw.len() - 9) as u64, 9)] {
            view.seek(SeekFrom::Start(at)).unwrap();
            let mut b = vec![0u8; len];
            view.read_exact(&mut b).unwrap();
            assert_eq!(&b[..], &raw[at as usize..at as usize + len], "at {at}");
        }
        // SeekFrom::End / Current
        assert_eq!(view.seek(SeekFrom::End(0)).unwrap(), raw.len() as u64);
        assert_eq!(view.seek(SeekFrom::Current(-2352)).unwrap(), raw.len() as u64 - 2352);
        assert!(view.seek(SeekFrom::Current(-(raw.len() as i64) - 1)).is_err());
        // reading at the end yields EOF, not an error
        view.seek(SeekFrom::End(0)).unwrap();
        let mut one = [0u8; 1];
        assert_eq!(view.read(&mut one).unwrap(), 0);
    }

    #[test]
    fn disc_image_parses_a_ps1_chd_like_any_bin() {
        let (chd, _) = ps1_chd();
        let (view, _) = chd_disc::open_data_track_from(Cursor::new(chd)).unwrap();
        let mut img = DiscImage::open(view).unwrap();
        assert_eq!(img.layout().stride, 2352);
        assert_eq!(img.volume().volume_id, "PS1_TEST");
        let entries = img.list_entries().unwrap();
        let cnf = entries.iter().find(|e| e.path == "SYSTEM.CNF").unwrap().clone();
        let text = String::from_utf8(img.read_file(&cnf).unwrap()).unwrap();
        assert!(text.contains("BOOT = cdrom:\\SLUS_004.04;1"), "{text}");
    }

    #[test]
    fn open_disc_file_reads_chd_files_and_inspect_recognises_ps1() {
        let t = TempDir::new("chd-inspect");
        let (chd, _) = ps1_chd();
        let p = t.path().join("Some Game (USA).chd");
        std::fs::write(&p, &chd).unwrap();
        let info = crate::ps2_ingest::inspect_image(p.to_str().unwrap()).unwrap();
        assert_eq!(info.platform, "PS1");
        assert_eq!(info.serial.as_deref(), Some("SLUS-00404"));
        assert_eq!(info.region, "NTSC-U/C (North America)");
        assert_eq!(info.boot_file.as_deref(), Some("SLUS_004.04"));
        assert!(info.boot_is_psx_exe);
        assert!(!info.boot_is_ps2_elf);
        let exe = info.psx_exe.as_ref().unwrap();
        assert_eq!((exe.load_addr, exe.entry_pc), (0x8001_0000, 0x8001_0000));
        assert!(info.can_ingest, "PS1 discs with a PS-X EXE are processable");
    }

    #[test]
    fn region_falls_back_to_the_licence_marker_when_the_boot_name_has_no_serial() {
        let t = TempDir::new("chd-marker");
        let iso = ps1_iso("LSP90901.500", psx_exe_bytes(0x8001_0000, 0x8001_0000, 64, "Sony Computer Entertainment Inc. for Japan area"));
        let p = t.path().join("odd.iso");
        std::fs::write(&p, iso).unwrap();
        let info = crate::ps2_ingest::inspect_image(p.to_str().unwrap()).unwrap();
        assert_eq!(info.platform, "PS1");
        assert_eq!(info.serial, None);
        assert_eq!(info.region, "NTSC-J (Japan)");
        assert!(info.can_ingest);
    }

    #[test]
    fn a_boot_file_that_is_not_a_psx_exe_is_flagged_and_not_ingestable() {
        let t = TempDir::new("chd-packed");
        let iso = ps1_iso("SLUS_004.04", vec![0x11; 4096]);
        let p = t.path().join("packed.iso");
        std::fs::write(&p, iso).unwrap();
        let info = crate::ps2_ingest::inspect_image(p.to_str().unwrap()).unwrap();
        assert_eq!(info.platform, "PS1");
        assert!(!info.boot_is_psx_exe);
        assert!(!info.can_ingest);
        assert!(info.warnings.iter().any(|w| w.contains("PS-X EXE")), "{:?}", info.warnings);
    }

    #[test]
    fn a_cooked_mode1_track_is_exposed_as_2048_byte_sectors() {
        let iso = ps1_iso("SLUS_004.04", psx_exe_bytes(0x8001_0000, 0x8001_0000, 64, "x"));
        // cooked MODE1: each 2048-byte sector sits at the start of a 2448-byte frame
        let mut frames = Vec::new();
        for s in iso.chunks(2048) {
            let mut f = vec![0u8; 2448];
            f[..s.len()].copy_from_slice(s);
            frames.extend_from_slice(&f);
        }
        let n = frames.len() / 2448;
        while (frames.len() / 2448) % 4 != 0 {
            frames.extend_from_slice(&[0u8; 2448]);
        }
        let chd = chd_v5(&frames, 8 * 2448, 2448, &[cht2(1, "MODE1", n)]);
        let (view, info) = chd_disc::open_data_track_from(Cursor::new(chd)).unwrap();
        assert_eq!(info.stride, 2048);
        let img = DiscImage::open(view).unwrap();
        assert_eq!(img.layout().stride, 2048);
        assert_eq!(info.cue_mode.as_deref(), Some("MODE1/2048"));
    }

    #[test]
    fn the_first_data_track_is_chosen_after_audio_and_data_follows_audio_padding() {
        // track 1 = 5 audio frames (padded to 8), track 2 = the data track.
        let iso = ps1_iso("SLUS_004.04", psx_exe_bytes(0x8001_0000, 0x8001_0000, 64, "x"));
        let raw = wrap_layout(&iso, 2352, 24);
        let data_frames = raw.len() / 2352;
        let mut logical = Vec::new();
        for _ in 0..5 {
            logical.extend_from_slice(&vec![0x77u8; 2448]);
        }
        logical.extend_from_slice(&vec![0u8; 3 * 2448]); // padding to 8 frames
        logical.extend_from_slice(&to_frames(&raw));
        let chd = chd_v5(&logical, 8 * 2448, 2448, &[cht2(1, "AUDIO", 5), cht2(2, "MODE2_RAW", data_frames)]);
        let (view, info) = chd_disc::open_data_track_from(Cursor::new(chd)).unwrap();
        assert_eq!(info.data_track, Some(2));
        let img = DiscImage::open(view).unwrap();
        assert_eq!(img.volume().volume_id, "PS1_TEST");
    }

    #[test]
    fn an_audio_only_cd_is_reported_as_such() {
        let logical = to_frames(&vec![0x33u8; 2352 * 4]);
        let chd = chd_v5(&logical, 8 * 2448, 2448, &[cht2(1, "AUDIO", 4)]);
        let e = chd_disc::open_data_track_from(Cursor::new(chd)).err().unwrap();
        assert!(e.contains("no data track"), "{e}");
    }

    #[test]
    fn a_flat_chd_without_cd_metadata_is_read_as_a_cooked_iso() {
        let iso = ps1_iso("SLUS_004.04", psx_exe_bytes(0x8001_0000, 0x8001_0000, 64, "x"));
        let chd = chd_v5(&iso, 4 * 2048, 2048, &[]);
        let (view, info) = chd_disc::open_data_track_from(Cursor::new(chd)).unwrap();
        assert!(info.flat);
        assert_eq!(info.stride, 2048);
        let img = DiscImage::open(view).unwrap();
        assert_eq!(img.volume().volume_id, "PS1_TEST");
    }

    #[test]
    fn gdrom_and_garbage_are_refused_with_clear_messages() {
        let logical = to_frames(&vec![0u8; 2352 * 4]);
        let gd = chd_v5(&logical, 8 * 2448, 2448, &[(tag(b"CHGD"), b"TRACK:1 TYPE:MODE1_RAW FRAMES:4\0".to_vec())]);
        let e = chd_disc::open_data_track_from(Cursor::new(gd)).err().unwrap();
        assert!(e.contains("GD-ROM"), "{e}");

        let e = chd_disc::open_data_track_from(Cursor::new(b"MComprHD".to_vec())).err().unwrap();
        assert!(e.contains("CHD"), "{e}");
        let e = chd_disc::open_data_track_from(Cursor::new(vec![0u8; 1000])).err().unwrap();
        assert!(e.contains("CHD"), "{e}");
    }

    #[test]
    fn a_track_that_runs_off_the_end_is_an_error_not_a_panic() {
        // metadata claims 100 frames, the file holds 8
        let logical = to_frames(&vec![0u8; 2352 * 8]);
        let chd = chd_v5(&logical, 8 * 2448, 2448, &[cht2(1, "MODE2_RAW", 100)]);
        let (mut view, _) = chd_disc::open_data_track_from(Cursor::new(chd)).unwrap();
        let mut sink = Vec::new();
        assert!(view.read_to_end(&mut sink).is_err());
    }
}

// ---------------------------------------------------------------------------
// Exporting the data track (what PSXRecomp's setup script needs)
// ---------------------------------------------------------------------------

mod export_tests {
    use super::*;

    #[test]
    fn export_writes_a_bin_identical_to_the_track_and_a_matching_cue() {
        let t = TempDir::new("chd-export");
        let (chd, raw) = ps1_chd();
        let src = t.path().join("g.chd");
        std::fs::write(&src, chd).unwrap();
        let out = t.path().join("out");
        let mut last = (0u64, 0u64);
        let r = chd_disc::export_data_track(&src, &out, "Game", &mut |d, total| {
            last = (d, total);
            true
        })
        .unwrap();
        assert_eq!(std::fs::read(&r.bin_path).unwrap(), raw);
        assert_eq!(last.0, last.1, "progress reaches 100%");
        let cue = std::fs::read_to_string(r.cue_path.unwrap()).unwrap();
        assert!(cue.contains("FILE \"Game.bin\" BINARY"), "{cue}");
        assert!(cue.contains("TRACK 01 MODE2/2352"), "{cue}");
        assert!(cue.contains("INDEX 01 00:00:00"), "{cue}");
        assert!(!out.join("Game.bin.part").exists());

        // and the exported cue is a first-class input again
        let info = crate::ps2_ingest::inspect_image(out.join("Game.cue").to_str().unwrap()).unwrap();
        assert_eq!(info.serial.as_deref(), Some("SLUS-00404"));
    }

    #[test]
    fn cancelling_leaves_no_partial_file_behind() {
        let t = TempDir::new("chd-export-cancel");
        let (chd, _) = ps1_chd();
        let src = t.path().join("g.chd");
        std::fs::write(&src, chd).unwrap();
        let out = t.path().join("out");
        let e = chd_disc::export_data_track(&src, &out, "Game", &mut |_, _| false).unwrap_err();
        assert!(e.contains("Cancelled"), "{e}");
        assert!(!out.join("Game.bin").exists());
        assert!(!out.join("Game.bin.part").exists());
    }

    #[test]
    fn a_flat_chd_exports_as_a_plain_iso_with_no_cue() {
        let t = TempDir::new("chd-export-flat");
        let iso = ps1_iso("SLUS_004.04", psx_exe_bytes(0x8001_0000, 0x8001_0000, 64, "x"));
        let src = t.path().join("g.chd");
        std::fs::write(&src, chd_v5(&iso, 4 * 2048, 2048, &[])).unwrap();
        let r = chd_disc::export_data_track(&src, &t.path().join("o"), "G", &mut |_, _| true).unwrap();
        assert!(r.cue_path.is_none());
        assert!(r.bin_path.ends_with("G.iso"));
        let back = std::fs::read(&r.bin_path).unwrap();
        assert_eq!(&back[..iso.len()], &iso[..]);
    }

    #[test]
    fn frame_constant_matches_the_chd_spec() {
        assert_eq!(CD_FRAME_BYTES, 2352 + 96);
    }
}
