//! Tests for the disc-image ingest layer (`disc`) and the one-click PS2
//! pipeline (`ps2_ingest`).
//!
//! No real game data is used or needed: every image here is synthesised in
//! memory by a small ISO9660 writer, so the tests are hermetic and run on any
//! machine. The writer supports nested directories, multi-sector directories
//! and multi-extent files, and can wrap the cooked image in the raw CD sector
//! layouts (MODE1/2352, MODE2 form 1/2352, MODE2/2336, 2448).

use crate::disc::{self, DiscImage, ExtractProgress};
use crate::engine;
use crate::ps2_ingest::{self, ExtractMode, IngestOptions};
use std::io::Cursor;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};

// ---------------------------------------------------------------------------
// Synthetic ISO9660 writer
// ---------------------------------------------------------------------------

pub(crate) enum Node {
    File(Vec<u8>),
    /// One logical file stored as several extents (ISO9660 multi-extent).
    Multi(Vec<Vec<u8>>),
    Dir(Vec<(String, Node)>),
}

fn dir_record(name: &[u8], lba: u32, size: u32, is_dir: bool, more: bool) -> Vec<u8> {
    let mut len = 33 + name.len();
    if len % 2 == 1 {
        len += 1;
    }
    let mut r = vec![0u8; len];
    r[0] = len as u8;
    r[2..6].copy_from_slice(&lba.to_le_bytes());
    r[6..10].copy_from_slice(&lba.to_be_bytes());
    r[10..14].copy_from_slice(&size.to_le_bytes());
    r[14..18].copy_from_slice(&size.to_be_bytes());
    r[25] = (if is_dir { 2 } else { 0 }) | (if more { 0x80 } else { 0 });
    r[28] = 1;
    r[31] = 1;
    r[32] = name.len() as u8;
    r[33..33 + name.len()].copy_from_slice(name);
    r
}

/// Pack records into 2048-byte sectors; a record never straddles a boundary.
fn pack(recs: &[Vec<u8>]) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::new();
    for r in recs {
        let used = out.len() % 2048;
        if used + r.len() > 2048 {
            out.resize(out.len() + (2048 - used), 0);
        }
        out.extend_from_slice(r);
    }
    let rem = out.len() % 2048;
    if rem != 0 || out.is_empty() {
        out.resize(out.len() + (2048 - rem) % 2048 + if out.is_empty() { 2048 } else { 0 }, 0);
    }
    out
}

fn child_name(name: &str, node: &Node) -> Vec<u8> {
    match node {
        Node::Dir(_) => name.as_bytes().to_vec(),
        _ => format!("{name};1").into_bytes(),
    }
}

fn dir_size(children: &[(String, Node)]) -> u32 {
    let mut recs = vec![dir_record(&[0], 0, 0, true, false), dir_record(&[1], 0, 0, true, false)];
    for (n, node) in children {
        match node {
            Node::Multi(parts) => {
                for i in 0..parts.len() {
                    recs.push(dir_record(&child_name(n, node), 0, 0, false, i + 1 < parts.len()));
                }
            }
            _ => recs.push(dir_record(&child_name(n, node), 0, 0, matches!(node, Node::Dir(_)), false)),
        }
    }
    pack(&recs).len() as u32
}

fn sectors_for(len: usize) -> u32 {
    ((len + 2047) / 2048) as u32
}

fn place(
    children: &[(String, Node)],
    my_lba: u32,
    parent_lba: u32,
    alloc: &mut u32,
    out: &mut Vec<(u32, Vec<u8>)>,
) {
    let size = dir_size(children);
    let mut recs = vec![
        dir_record(&[0], my_lba, size, true, false),
        dir_record(&[1], parent_lba, size, true, false),
    ];
    let mut subdirs: Vec<(&[(String, Node)], u32)> = vec![];
    for (name, node) in children {
        match node {
            Node::File(data) => {
                let lba = *alloc;
                *alloc += sectors_for(data.len());
                out.push((lba, data.clone()));
                recs.push(dir_record(&child_name(name, node), lba, data.len() as u32, false, false));
            }
            Node::Multi(parts) => {
                for (i, p) in parts.iter().enumerate() {
                    let lba = *alloc;
                    *alloc += sectors_for(p.len());
                    out.push((lba, p.clone()));
                    recs.push(dir_record(
                        &child_name(name, node),
                        lba,
                        p.len() as u32,
                        false,
                        i + 1 < parts.len(),
                    ));
                }
            }
            Node::Dir(kids) => {
                let lba = *alloc;
                let sz = dir_size(kids);
                *alloc += sz / 2048;
                recs.push(dir_record(name.as_bytes(), lba, sz, true, false));
                subdirs.push((kids, lba));
            }
        }
    }
    out.push((my_lba, pack(&recs)));
    for (kids, lba) in subdirs {
        place(kids, lba, my_lba, alloc, out);
    }
}

fn padded(s: &str, n: usize) -> Vec<u8> {
    let mut v = s.as_bytes().to_vec();
    v.resize(n, b' ');
    v
}

/// Build a cooked (2048-byte-sector) ISO9660 image.
pub(crate) fn build_iso(volume_id: &str, root: &[(String, Node)]) -> Vec<u8> {
    let root_lba = 18u32;
    let root_size = dir_size(root);
    let mut alloc = root_lba + root_size / 2048;
    let mut extents: Vec<(u32, Vec<u8>)> = vec![];
    place(root, root_lba, root_lba, &mut alloc, &mut extents);
    let total = alloc;

    let mut img = vec![0u8; total as usize * 2048];
    // Primary volume descriptor at LBA 16.
    let pvd = &mut img[16 * 2048..17 * 2048];
    pvd[0] = 1;
    pvd[1..6].copy_from_slice(b"CD001");
    pvd[6] = 1;
    pvd[8..40].copy_from_slice(&padded("PLAYSTATION", 32));
    pvd[40..72].copy_from_slice(&padded(volume_id, 32));
    pvd[80..84].copy_from_slice(&total.to_le_bytes());
    pvd[84..88].copy_from_slice(&total.to_be_bytes());
    pvd[128..130].copy_from_slice(&2048u16.to_le_bytes());
    pvd[130..132].copy_from_slice(&2048u16.to_be_bytes());
    let rec = dir_record(&[0], root_lba, root_size, true, false);
    pvd[156..156 + rec.len()].copy_from_slice(&rec);
    // Terminator at LBA 17.
    img[17 * 2048] = 255;
    img[17 * 2048 + 1..17 * 2048 + 6].copy_from_slice(b"CD001");
    img[17 * 2048 + 6] = 1;

    for (lba, data) in extents {
        let s = lba as usize * 2048;
        img[s..s + data.len()].copy_from_slice(&data);
    }
    img
}

/// Re-wrap a cooked image in raw CD sectors. Everything outside the 2048 data
/// bytes is filled with 0xAA so a reader that mishandles offsets fails loudly.
pub(crate) fn wrap_layout(cooked: &[u8], stride: usize, data_off: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(cooked.len() / 2048 * stride);
    for (i, sec) in cooked.chunks(2048).enumerate() {
        let mut raw = vec![0xAAu8; stride];
        if stride >= 2352 {
            raw[0] = 0;
            for b in &mut raw[1..11] {
                *b = 0xFF;
            }
            raw[11] = 0;
            raw[12] = 0;
            raw[13] = 2 + (i / 4500) as u8;
            raw[14] = ((i / 75) % 60) as u8;
            raw[15] = if data_off == 16 { 1 } else { 2 };
        }
        raw[data_off..data_off + 2048].copy_from_slice(sec);
        out.extend_from_slice(&raw);
    }
    out
}

fn files(list: &[(&str, &[u8])]) -> Vec<(String, Node)> {
    list.iter().map(|(n, d)| (n.to_string(), Node::File(d.to_vec()))).collect()
}

// ---------------------------------------------------------------------------
// Synthetic PS2 ELF
// ---------------------------------------------------------------------------

const TEXT_ADDR: u32 = 0x0010_0000;

fn mips_text() -> Vec<u8> {
    let jal = |target: u32| 0x0C00_0000u32 | ((target >> 2) & 0x03FF_FFFF);
    let words: [u32; 16] = [
        jal(TEXT_ADDR + 0x20), // 0x00: jal sub_20
        0,                     // 0x04: nop (delay slot)
        jal(TEXT_ADDR + 0x30), // 0x08: jal sub_30
        0,                     // 0x0C
        0x03E0_0008,           // 0x10: jr $ra
        0,                     // 0x14
        0, 0,                  // 0x18, 0x1C padding
        0x27BD_FFF0,           // 0x20: addiu sp,sp,-16
        0x03E0_0008,           // 0x24: jr $ra
        0,                     // 0x28
        0,                     // 0x2C
        0x27BD_FFE0,           // 0x30: addiu sp,sp,-32
        0x03E0_0008,           // 0x34: jr $ra
        0,                     // 0x38
        0,                     // 0x3C
    ];
    words.iter().flat_map(|w| w.to_le_bytes()).collect()
}

/// An ELF32 little-endian MIPS executable. `with_sections=false` produces the
/// retail-style layout (program headers only, `e_shnum == 0`).
pub(crate) fn ps2_elf(with_sections: bool) -> Vec<u8> {
    let text = mips_text();
    let text_off = 0x100usize;
    let mut buf = vec![0u8; text_off];
    buf[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
    buf[4] = 1; // ELFCLASS32
    buf[5] = 1; // little-endian
    buf[6] = 1;
    buf[16..18].copy_from_slice(&2u16.to_le_bytes()); // ET_EXEC
    buf[18..20].copy_from_slice(&8u16.to_le_bytes()); // EM_MIPS
    buf[20..24].copy_from_slice(&1u32.to_le_bytes());
    buf[24..28].copy_from_slice(&TEXT_ADDR.to_le_bytes()); // entry
    buf[28..32].copy_from_slice(&52u32.to_le_bytes()); // phoff
    buf[40..42].copy_from_slice(&52u16.to_le_bytes()); // ehsize
    buf[42..44].copy_from_slice(&32u16.to_le_bytes()); // phentsize
    buf[44..46].copy_from_slice(&1u16.to_le_bytes()); // phnum
    buf[46..48].copy_from_slice(&40u16.to_le_bytes()); // shentsize
    // Program header: PT_LOAD, R+X.
    let ph = 52;
    buf[ph..ph + 4].copy_from_slice(&1u32.to_le_bytes());
    buf[ph + 4..ph + 8].copy_from_slice(&(text_off as u32).to_le_bytes());
    buf[ph + 8..ph + 12].copy_from_slice(&TEXT_ADDR.to_le_bytes());
    buf[ph + 12..ph + 16].copy_from_slice(&TEXT_ADDR.to_le_bytes());
    buf[ph + 16..ph + 20].copy_from_slice(&(text.len() as u32).to_le_bytes());
    buf[ph + 20..ph + 24].copy_from_slice(&(text.len() as u32).to_le_bytes());
    buf[ph + 24..ph + 28].copy_from_slice(&5u32.to_le_bytes());
    buf[ph + 28..ph + 32].copy_from_slice(&16u32.to_le_bytes());
    buf.extend_from_slice(&text);

    if with_sections {
        let shstr = b"\0.text\0.shstrtab\0".to_vec();
        let shstr_off = buf.len();
        buf.extend_from_slice(&shstr);
        while buf.len() % 4 != 0 {
            buf.push(0);
        }
        let sh_off = buf.len();
        let mut sh = |name: u32, ty: u32, flags: u32, addr: u32, off: u32, size: u32| {
            let mut s = vec![0u8; 40];
            s[0..4].copy_from_slice(&name.to_le_bytes());
            s[4..8].copy_from_slice(&ty.to_le_bytes());
            s[8..12].copy_from_slice(&flags.to_le_bytes());
            s[12..16].copy_from_slice(&addr.to_le_bytes());
            s[16..20].copy_from_slice(&off.to_le_bytes());
            s[20..24].copy_from_slice(&size.to_le_bytes());
            buf.extend_from_slice(&s);
        };
        sh(0, 0, 0, 0, 0, 0);
        sh(1, 1, 6, TEXT_ADDR, text_off as u32, text.len() as u32);
        sh(7, 3, 0, 0, shstr_off as u32, shstr.len() as u32);
        buf[32..36].copy_from_slice(&(sh_off as u32).to_le_bytes());
        buf[48..50].copy_from_slice(&3u16.to_le_bytes());
        buf[50..52].copy_from_slice(&2u16.to_le_bytes());
    }
    buf
}

/// A tiny IOP module: ELF32 LE MIPS with e_type 0xFF80.
fn irx() -> Vec<u8> {
    let mut b = ps2_elf(false);
    b[16..18].copy_from_slice(&0xFF80u16.to_le_bytes());
    b
}

pub(crate) fn ps2_disc(with_sections: bool) -> Vec<u8> {
    ps2_disc_with_filler(with_sections, 0)
}

/// Like [`ps2_disc`] plus `filler` small asset files spread over many
/// directories — a disc shaped like a real game, which has thousands of files.
pub(crate) fn ps2_disc_with_filler(with_sections: bool, filler: usize) -> Vec<u8> {
    let mut assets: Vec<(String, Node)> = Vec::new();
    for d in 0..filler.div_ceil(200) {
        let mut kids = Vec::new();
        for i in (d * 200)..((d + 1) * 200).min(filler) {
            // 200 B .. ~24 KB, deterministic.
            let len = 200 + (i * 7919) % 24_000;
            kids.push((format!("F{i:05}.DAT"), Node::File(vec![(i % 251) as u8; len])));
        }
        assets.push((format!("D{d:03}"), Node::Dir(kids)));
    }
    let mut root = vec![
        ("SYSTEM.CNF".to_string(), Node::File(b"BOOT2 = cdrom0:\\SLUS_203.12;1\r\nVER = 1.00\r\nVMODE = NTSC\r\n".to_vec())),
        ("SLUS_203.12".to_string(), Node::File(ps2_elf(with_sections))),
        ("IOP".to_string(), Node::Dir(vec![("SIO2MAN.IRX".to_string(), Node::File(irx()))])),
        (
            "DATA".to_string(),
            Node::Dir(vec![
                ("BIG.DAT".to_string(), Node::File((0..5000u32).map(|i| (i % 251) as u8).collect())),
                ("MOVIE.PSS".to_string(), Node::File(vec![0xAB; 3000])),
            ]),
        ),
    ];
    if filler > 0 {
        root.push(("FILES".to_string(), Node::Dir(assets)));
    }
    build_iso("TEST_GAME", &root)
}

// ---------------------------------------------------------------------------
// Temp dirs
// ---------------------------------------------------------------------------

static COUNTER: AtomicU32 = AtomicU32::new(0);

pub(crate) struct TempDir(PathBuf);

impl TempDir {
    pub(crate) fn new(tag: &str) -> Self {
        let p = std::env::temp_dir().join(format!(
            "aura-disc-test-{tag}-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::SeqCst)
        ));
        std::fs::create_dir_all(&p).unwrap();
        TempDir(p)
    }
    pub(crate) fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn open_mem(bytes: Vec<u8>) -> DiscImage<Cursor<Vec<u8>>> {
    DiscImage::open(Cursor::new(bytes)).expect("synthetic image should open")
}

// ===========================================================================
// disc.rs — layout detection and reading
// ===========================================================================

mod layout_tests {
    use super::*;

    fn sample() -> Vec<u8> {
        let root = vec![
            ("README.TXT".to_string(), Node::File(b"hello disc".to_vec())),
            ("NEST".to_string(), Node::Dir(vec![
                ("INNER".to_string(), Node::Dir(vec![("DEEP.BIN".to_string(), Node::File(vec![7u8; 4100]))])),
            ])),
        ];
        build_iso("SAMPLE_VOL", &root)
    }

    fn check(img: &mut DiscImage<Cursor<Vec<u8>>>) {
        assert_eq!(img.volume().volume_id, "SAMPLE_VOL");
        let list = img.list_entries().unwrap();
        let readme = disc::find_entry(&list, "readme.txt").expect("case-insensitive lookup");
        assert_eq!(img.read_file(readme).unwrap(), b"hello disc");
        let deep = disc::find_entry(&list, "NEST\\INNER\\DEEP.BIN;1").expect("backslash + version lookup");
        assert_eq!(deep.size, 4100);
        assert_eq!(img.read_file(deep).unwrap(), vec![7u8; 4100]);
        assert!(list.iter().any(|e| e.is_dir && e.path == "NEST/INNER"));
    }

    #[test]
    fn cooked_2048() {
        let mut img = open_mem(sample());
        assert_eq!(img.layout().stride, 2048);
        check(&mut img);
    }

    #[test]
    fn raw_mode1_2352() {
        let mut img = open_mem(wrap_layout(&sample(), 2352, 16));
        assert_eq!((img.layout().stride, img.layout().data_offset), (2352, 16));
        check(&mut img);
    }

    #[test]
    fn raw_mode2_form1_2352() {
        let mut img = open_mem(wrap_layout(&sample(), 2352, 24));
        assert_eq!((img.layout().stride, img.layout().data_offset), (2352, 24));
        check(&mut img);
    }

    #[test]
    fn mode2_2336() {
        let mut img = open_mem(wrap_layout(&sample(), 2336, 8));
        assert_eq!((img.layout().stride, img.layout().data_offset), (2336, 8));
        check(&mut img);
    }

    #[test]
    fn raw_with_subchannel_2448() {
        let mut img = open_mem(wrap_layout(&sample(), 2448, 24));
        assert_eq!(img.layout().stride, 2448);
        check(&mut img);
    }

    #[test]
    fn multi_sector_directory_lists_every_file() {
        // 150 files with long-ish names force the root directory across
        // several sectors; none may be lost at a sector boundary.
        let mut root: Vec<(String, Node)> = Vec::new();
        for i in 0..150 {
            root.push((format!("FILE_NUMBER_{i:04}.DAT"), Node::File(vec![(i % 256) as u8; 10])));
        }
        let mut img = open_mem(build_iso("MANY", &root));
        let list = img.list_entries().unwrap();
        assert_eq!(list.len(), 150);
        let last = disc::find_entry(&list, "FILE_NUMBER_0149.DAT").unwrap();
        assert_eq!(img.read_file(last).unwrap(), vec![149u8; 10]);
    }

    #[test]
    fn multi_extent_file_is_reassembled() {
        let a = vec![1u8; 4096];
        let b = vec![2u8; 1000];
        let root = vec![("SPLIT.BIN".to_string(), Node::Multi(vec![a.clone(), b.clone()]))];
        let mut img = open_mem(build_iso("MULTI", &root));
        let list = img.list_entries().unwrap();
        assert_eq!(list.len(), 1, "extents must merge into one entry");
        assert_eq!(list[0].size, 5096);
        assert_eq!(list[0].extents.len(), 2);
        let mut expect = a;
        expect.extend(b);
        assert_eq!(img.read_file(&list[0]).unwrap(), expect);
    }

    #[test]
    fn zero_length_file_and_empty_dir() {
        let root = vec![
            ("EMPTY.TXT".to_string(), Node::File(vec![])),
            ("NOTHING".to_string(), Node::Dir(vec![])),
        ];
        let mut img = open_mem(build_iso("EMPTY", &root));
        let list = img.list_entries().unwrap();
        let e = disc::find_entry(&list, "EMPTY.TXT").unwrap();
        assert_eq!(img.read_file(e).unwrap(), Vec::<u8>::new());
        assert!(list.iter().any(|e| e.is_dir && e.path == "NOTHING"));
    }
}

// ===========================================================================
// disc.rs — hostile / malformed input must never panic or hang
// ===========================================================================

mod robustness_tests {
    use super::*;

    #[test]
    fn rejects_non_iso() {
        let junk: Vec<u8> = (0..100_000u32).map(|i| (i.wrapping_mul(2654435761) >> 24) as u8).collect();
        let err = DiscImage::open(Cursor::new(junk)).err().expect("must fail");
        assert!(err.contains("No ISO9660"), "{err}");
    }

    #[test]
    fn rejects_tiny_input() {
        assert!(DiscImage::open(Cursor::new(vec![0u8; 10])).is_err());
        assert!(DiscImage::open(Cursor::new(Vec::<u8>::new())).is_err());
    }

    #[test]
    fn truncated_image_reports_clearly_instead_of_panicking() {
        let root = files(&[("A.BIN", &[1u8; 100]), ("B.BIN", &vec![9u8; 20_000])]);
        let mut bytes = build_iso("CUT", &root);
        bytes.truncate(bytes.len() - 6 * 2048); // chop most of B.BIN
        let mut img = open_mem(bytes);
        assert!(img.is_truncated());
        let list = img.list_entries().unwrap();
        let a = disc::find_entry(&list, "A.BIN").unwrap();
        assert_eq!(img.read_file(a).unwrap(), vec![1u8; 100], "files before the cut still read");
        let b = disc::find_entry(&list, "B.BIN").unwrap();
        let err = img.read_file(b).unwrap_err();
        assert!(err.contains("truncated"), "{err}");
    }

    #[test]
    fn directory_loop_terminates() {
        // Root contains "LOOP", a directory record that points back at root.
        let root_lba = 18u32;
        let recs = vec![
            dir_record(&[0], root_lba, 2048, true, false),
            dir_record(&[1], root_lba, 2048, true, false),
            dir_record(b"LOOP", root_lba, 2048, true, false),
            dir_record(b"A.TXT;1", 19, 4, false, false),
        ];
        let mut img_bytes = build_iso("LOOPY", &files(&[("A.TXT", b"data")]));
        let dir = pack(&recs);
        img_bytes[root_lba as usize * 2048..root_lba as usize * 2048 + dir.len()].copy_from_slice(&dir);
        let mut img = open_mem(img_bytes);
        let list = img.list_entries().expect("loop must be broken, not followed forever");
        assert!(list.iter().any(|e| e.path == "LOOP"));
        assert_eq!(list.len(), 2);
    }

    #[test]
    fn garbage_directory_does_not_panic() {
        let mut bytes = build_iso("GARBAGE", &files(&[("A.TXT", b"x")]));
        // Fill the root directory sector with pseudo-random bytes.
        let mut x = 0x1234_5678u32;
        for b in &mut bytes[18 * 2048..19 * 2048] {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            *b = x as u8;
        }
        let mut img = open_mem(bytes);
        let _ = img.list_entries(); // Ok or Err — just must not panic/hang.
    }

    #[test]
    fn directory_pointing_past_end_is_an_error() {
        let mut bytes = build_iso("PAST", &files(&[("A.TXT", b"x")]));
        let bad = dir_record(b"GHOST", 9_000_000, 2048, true, false);
        let recs = vec![dir_record(&[0], 18, 2048, true, false), dir_record(&[1], 18, 2048, true, false), bad];
        let dir = pack(&recs);
        bytes[18 * 2048..18 * 2048 + dir.len()].copy_from_slice(&dir);
        let mut img = open_mem(bytes);
        assert!(img.list_entries().is_err());
    }

    #[test]
    fn oversized_extent_is_refused_not_allocated() {
        let mut img = open_mem(build_iso("BIG", &files(&[("A.TXT", b"x")])));
        let err = img.read_extent(18, u64::MAX / 2, disc::MAX_IN_MEMORY).unwrap_err();
        assert!(err.contains("Refusing"), "{err}");
    }

    #[test]
    fn unsupported_containers_get_actionable_errors() {
        let t = TempDir::new("containers");
        let chd = t.path().join("game.chd");
        let mut b = b"MComprHD".to_vec();
        b.resize(4096, 0);
        std::fs::write(&chd, &b).unwrap();
        // CHDs are read natively now; a file that only has the magic is a
        // *corrupt* CHD and says so rather than asking for a conversion.
        let e = disc::open_disc_file(chd.to_str().unwrap()).err().unwrap();
        assert!(e.contains("CHD"), "{e}");

        let cso = t.path().join("game.cso");
        let mut b = b"CISO".to_vec();
        b.resize(4096, 0);
        std::fs::write(&cso, &b).unwrap();
        let e = disc::open_disc_file(cso.to_str().unwrap()).err().unwrap();
        assert!(e.contains("CSO"), "{e}");

        let zip = t.path().join("game.zip");
        let mut b = b"PK\x03\x04".to_vec();
        b.resize(4096, 0);
        std::fs::write(&zip, &b).unwrap();
        let e = disc::open_disc_file(zip.to_str().unwrap()).err().unwrap();
        assert!(e.contains("archive"), "{e}");
    }

    #[test]
    fn cue_sheet_is_followed_to_its_data_track() {
        let t = TempDir::new("cue");
        let bin_name = "My Game (Track 1).bin";
        let raw = wrap_layout(&ps2_disc(true), 2352, 24);
        std::fs::write(t.path().join(bin_name), raw).unwrap();
        let cue = format!("FILE \"{bin_name}\" BINARY\r\n  TRACK 01 MODE2/2352\r\n    INDEX 01 00:00:00\r\n");
        let cue_path = t.path().join("game.cue");
        std::fs::write(&cue_path, cue).unwrap();
        let (mut img, opened) = disc::open_disc_file(cue_path.to_str().unwrap()).unwrap();
        assert!(opened.ends_with(bin_name));
        assert_eq!(img.layout().stride, 2352);
        assert!(disc::find_entry(&img.list_entries().unwrap(), "SYSTEM.CNF").is_some());
    }
}

// ===========================================================================
// disc.rs — extraction + path safety
// ===========================================================================

mod extraction_tests {
    use super::*;

    #[test]
    fn sanitize_blocks_traversal_and_reserved_names() {
        assert_eq!(disc::sanitize_component(".."), "_");
        assert_eq!(disc::sanitize_component("."), "_");
        assert_eq!(disc::sanitize_component(""), "_");
        assert_eq!(disc::sanitize_component("a/b\\c"), "a_b_c");
        assert_eq!(disc::sanitize_component("what?.dat"), "what_.dat");
        assert_eq!(disc::sanitize_component("name. "), "name");
        assert_eq!(disc::sanitize_component("CON"), "_CON");
        assert_eq!(disc::sanitize_component("nul.txt"), "_nul.txt");
        assert_eq!(disc::sanitize_component("COM3"), "_COM3");
        assert_eq!(disc::sanitize_component("COMMON.DAT"), "COMMON.DAT");
        for c in ["..", "../..", "a/../b", "C:\\evil", "/etc/passwd"] {
            let s = disc::sanitize_component(c);
            assert!(!s.contains('/') && !s.contains('\\') && !s.contains(':') && s != "..", "{c} -> {s}");
        }
    }

    #[test]
    fn extracts_tree_with_identical_bytes() {
        let t = TempDir::new("extract");
        let mut img = open_mem(wrap_layout(&ps2_disc(true), 2352, 24));
        let list = img.list_entries().unwrap();
        let mut seen = 0;
        let summary = img
            .extract_entries(&list, t.path(), &mut |p: &ExtractProgress| {
                seen += 1;
                assert!(p.files_done <= p.files_total);
                true
            })
            .unwrap();
        assert!(seen >= 5);
        assert_eq!(summary.files.len(), 5);
        let big = std::fs::read(t.path().join("DATA").join("BIG.DAT")).unwrap();
        assert_eq!(big, (0..5000u32).map(|i| (i % 251) as u8).collect::<Vec<u8>>());
        assert_eq!(std::fs::read(t.path().join("SLUS_203.12")).unwrap(), ps2_elf(true));
        assert_eq!(std::fs::read(t.path().join("IOP").join("SIO2MAN.IRX")).unwrap(), irx());
    }

    #[test]
    fn colliding_host_names_do_not_overwrite_each_other() {
        // "A?.TXT" and "A_.TXT" both sanitise to "A_.TXT".
        let root = files(&[("A?.TXT", b"first"), ("A_.TXT", b"second")]);
        let mut img = open_mem(build_iso("COLLIDE", &root));
        let list = img.list_entries().unwrap();
        let t = TempDir::new("collide");
        let summary = img.extract_entries(&list, t.path(), &mut |_| true).unwrap();
        let rels: Vec<&str> = summary.files.iter().map(|f| f.rel_path.as_str()).collect();
        assert_eq!(rels.len(), 2);
        assert_ne!(rels[0].to_lowercase(), rels[1].to_lowercase());
        let mut contents: Vec<Vec<u8>> = rels.iter().map(|r| std::fs::read(t.path().join(r)).unwrap()).collect();
        contents.sort();
        assert_eq!(contents, vec![b"first".to_vec(), b"second".to_vec()]);
    }

    #[test]
    fn cancel_stops_extraction() {
        let t = TempDir::new("cancel");
        let mut img = open_mem(ps2_disc(true));
        let list = img.list_entries().unwrap();
        let mut calls = 0;
        let err = img
            .extract_entries(&list, t.path(), &mut |_| {
                calls += 1;
                calls < 3
            })
            .unwrap_err();
        assert!(err.contains("cancel"), "{err}");
    }
}

// ===========================================================================
// ps2_ingest.rs — SYSTEM.CNF, serials, boot resolution
// ===========================================================================

mod cnf_tests {
    use super::*;

    #[test]
    fn parses_typical_ps2_cnf() {
        let c = ps2_ingest::parse_system_cnf("BOOT2 = cdrom0:\\SLUS_203.12;1\r\nVER = 1.00\r\nVMODE = NTSC\r\nHDDUNITPOWER = NICHDD\r\n");
        assert_eq!(c.boot2.as_deref(), Some("cdrom0:\\SLUS_203.12;1"));
        assert_eq!(c.ver.as_deref(), Some("1.00"));
        assert_eq!(c.vmode.as_deref(), Some("NTSC"));
        assert!(c.boot.is_none());
    }

    #[test]
    fn tolerates_odd_formatting() {
        let c = ps2_ingest::parse_system_cnf("; comment\n\nboot2=cdrom0:SLES_500.01;1\0\0\n  Ver =  2.00  \n");
        assert_eq!(c.boot2.as_deref(), Some("cdrom0:SLES_500.01;1"));
        assert_eq!(c.ver.as_deref(), Some("2.00"));
    }

    #[test]
    fn ps1_uses_boot_not_boot2() {
        let c = ps2_ingest::parse_system_cnf("BOOT = cdrom:\\SLUS_005.94;1\nTCB = 4\nEVENT = 10\nSTACK = 801FFF00\n");
        assert_eq!(c.boot.as_deref(), Some("cdrom:\\SLUS_005.94;1"));
        assert!(c.boot2.is_none());
    }

    #[test]
    fn boot_path_variants_resolve() {
        assert_eq!(ps2_ingest::boot_disc_path("cdrom0:\\SLUS_203.12;1"), "SLUS_203.12");
        assert_eq!(ps2_ingest::boot_disc_path("cdrom0:SLUS_203.12;1"), "SLUS_203.12");
        assert_eq!(ps2_ingest::boot_disc_path("cdrom0:\\SLUS_203.12"), "SLUS_203.12");
        assert_eq!(ps2_ingest::boot_disc_path("cdrom:\\DIR\\MAIN.ELF;1"), "DIR/MAIN.ELF");
        assert_eq!(ps2_ingest::boot_disc_path("CDROM0:/SLPS_250.00;1"), "SLPS_250.00");
    }

    #[test]
    fn serial_and_region() {
        assert_eq!(ps2_ingest::serial_from_filename("SLUS_203.12").as_deref(), Some("SLUS-20312"));
        assert_eq!(ps2_ingest::serial_from_filename("DIR/slus_203.12").as_deref(), Some("SLUS-20312"));
        assert_eq!(ps2_ingest::serial_from_filename("MAIN.ELF"), None);
        assert_eq!(ps2_ingest::serial_from_filename("SLUS_2031.2"), None);
        assert!(ps2_ingest::region_from_serial("SLUS-20312").starts_with("NTSC-U"));
        assert!(ps2_ingest::region_from_serial("SLES-50001").starts_with("PAL"));
        assert!(ps2_ingest::region_from_serial("SLPS-25000").starts_with("NTSC-J"));
        assert_eq!(ps2_ingest::region_from_serial("XXXX-00000"), "Unknown");
    }
}

// ===========================================================================
// engine.rs — retail-style ELFs with no section headers
// ===========================================================================

mod elf_fallback_tests {
    use super::*;

    #[test]
    fn program_headers_become_code_sections_when_no_section_headers() {
        let info = engine::parse_elf_data(&ps2_elf(false), "SLUS_203.12").unwrap();
        assert_eq!(info.sections.len(), 1);
        let s = &info.sections[0];
        assert_eq!(s.name, ".text");
        assert_eq!(s.address, TEXT_ADDR);
        assert_ne!(s.flags & 0x4, 0, "must carry SHF_EXECINSTR so function scans see it");
        assert_eq!(s.data.len(), 0x40);
    }

    #[test]
    fn real_section_headers_still_win_over_the_fallback() {
        let info = engine::parse_elf_data(&ps2_elf(true), "x.elf").unwrap();
        assert_eq!(info.sections.len(), 1);
        assert_eq!(info.sections[0].name, ".text");
        assert_eq!(info.sections[0].offset, 0x100);
    }

    #[test]
    fn functions_are_detected_from_segment_only_elf() {
        let info = engine::parse_elf_data(&ps2_elf(false), "x.elf").unwrap();
        let funcs = engine::detect_functions_inner(&info).unwrap();
        let starts: Vec<u32> = funcs.iter().map(|f| f.start).collect();
        assert!(starts.contains(&TEXT_ADDR), "entry point: {starts:x?}");
        assert!(starts.contains(&(TEXT_ADDR + 0x20)), "jal target 1: {starts:x?}");
        assert!(starts.contains(&(TEXT_ADDR + 0x30)), "jal target 2: {starts:x?}");
    }
}

// ===========================================================================
// ps2_ingest.rs / engine.rs — BIOS-patching routines are bound to ret0
// ===========================================================================

mod stub_binding_tests {
    use super::*;
    use crate::engine::FunctionEntry;

    fn fe(name: &str, start: u32) -> FunctionEntry {
        FunctionEntry { name: name.to_string(), start, end: start + 0x100, size: 0x100 }
    }

    #[test]
    fn only_listed_kernel_patch_routines_are_bound() {
        let funcs = vec![
            fe("InitSystemCallTableAddress", 0x0012_C770),
            fe("printf", 0x0010_0000),
            fe("sub_00100100", 0x0010_0100),
            fe("InitTLB", 0x0010_0200), // known to upstream already; not ours to bind
        ];
        assert_eq!(ps2_ingest::kernel_stub_bindings(&funcs), vec!["ret0@0x12c770".to_string()]);
    }

    #[test]
    fn nothing_is_bound_when_no_such_routine_exists() {
        let funcs = vec![fe("printf", 0x0010_0000), fe("sub_00100100", 0x0010_0100)];
        assert!(ps2_ingest::kernel_stub_bindings(&funcs).is_empty());
    }

    #[test]
    fn duplicate_matches_are_bound_once_per_address() {
        let funcs = vec![fe("InitSystemCallTableAddress", 0x360140), fe("InitSystemCallTableAddress", 0x360140)];
        assert_eq!(ps2_ingest::kernel_stub_bindings(&funcs), vec!["ret0@0x360140".to_string()]);
    }

    fn config_for(stubs: &[String]) -> String {
        let info = engine::parse_elf_data(&ps2_elf(false), "g.elf").unwrap();
        let funcs = engine::detect_functions_inner(&info).unwrap();
        engine::build_config_toml_with_stubs("g.elf", "out", "f.csv", &info, &funcs, 0, 0, 0, &[], stubs)
    }

    #[test]
    fn config_writes_stub_bindings_as_a_toml_array() {
        let cfg = config_for(&["ret0@0x12c770".to_string(), "ret0@0x360140".to_string()]);
        assert!(cfg.contains("stubs = [\n    \"ret0@0x12c770\",\n    \"ret0@0x360140\",\n]\n"), "{cfg}");
        assert!(!cfg.contains("
stubs = []"), "{cfg}");
    }

    #[test]
    fn config_without_stubs_keeps_the_empty_array_and_the_old_signature_still_works() {
        assert!(config_for(&[]).contains("stubs = []\n"));
        let info = engine::parse_elf_data(&ps2_elf(false), "g.elf").unwrap();
        let funcs = engine::detect_functions_inner(&info).unwrap();
        let legacy = engine::build_config_toml("g.elf", "out", "f.csv", &info, &funcs, 0, 0, 0, &[]);
        assert!(legacy.contains("stubs = []\n"));
    }

    #[test]
    fn generated_comments_describe_untracked_stubs_correctly() {
        let cfg = config_for(&[]);
        assert!(!cfg.contains("ignored by the recompiler"), "stale claim: {cfg}");
        assert!(cfg.contains("entry-point hints"), "{cfg}");
        assert!(cfg.contains("ps2_recomp config.toml"), "{cfg}");
    }
}

// ===========================================================================
// engine.rs — functions reachable only through pointers (ctors, vtables)
// ===========================================================================

mod pointer_scan_tests {
    use super::*;

    /// ELF32-LE MIPS with a code segment at 0x100000 and a data segment at
    /// 0x200000 holding `data_words`.
    fn elf_with_data(code: &[u32], data_words: &[u32]) -> Vec<u8> {
        let code: Vec<u8> = code.iter().flat_map(|w| w.to_le_bytes()).collect();
        let data: Vec<u8> = data_words.iter().flat_map(|w| w.to_le_bytes()).collect();
        let (code_off, data_off) = (0x100usize, 0x100 + ((code.len() + 15) & !15));
        let mut b = vec![0u8; data_off + data.len()];
        b[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
        b[4] = 1;
        b[5] = 1;
        b[6] = 1;
        b[16..18].copy_from_slice(&2u16.to_le_bytes());
        b[18..20].copy_from_slice(&8u16.to_le_bytes());
        b[24..28].copy_from_slice(&0x0010_0000u32.to_le_bytes()); // entry
        b[28..32].copy_from_slice(&52u32.to_le_bytes());
        b[40..42].copy_from_slice(&52u16.to_le_bytes());
        b[42..44].copy_from_slice(&32u16.to_le_bytes());
        b[44..46].copy_from_slice(&2u16.to_le_bytes());
        let mut ph = |i: usize, off: usize, va: u32, sz: usize, flags: u32| {
            let o = 52 + i * 32;
            b[o..o + 4].copy_from_slice(&1u32.to_le_bytes());
            b[o + 4..o + 8].copy_from_slice(&(off as u32).to_le_bytes());
            b[o + 8..o + 12].copy_from_slice(&va.to_le_bytes());
            b[o + 12..o + 16].copy_from_slice(&va.to_le_bytes());
            b[o + 16..o + 20].copy_from_slice(&(sz as u32).to_le_bytes());
            b[o + 20..o + 24].copy_from_slice(&(sz as u32).to_le_bytes());
            b[o + 24..o + 28].copy_from_slice(&flags.to_le_bytes());
            b[o + 28..o + 32].copy_from_slice(&16u32.to_le_bytes());
        };
        ph(0, code_off, 0x0010_0000, code.len(), 5); // R+X
        ph(1, data_off, 0x0020_0000, data.len(), 6); // R+W
        b[code_off..code_off + code.len()].copy_from_slice(&code);
        b[data_off..data_off + data.len()].copy_from_slice(&data);
        b
    }

    const PROLOGUE_16: u32 = 0x27BD_FFF0; // addiu sp,sp,-16
    const PROLOGUE_32: u32 = 0x27BD_FFE0; // addiu sp,sp,-32
    const JR_RA: u32 = 0x03E0_0008;
    const NOP: u32 = 0;

    fn starts_of(elf: &[u8]) -> Vec<u32> {
        let info = engine::parse_elf_data(elf, "t.elf").unwrap();
        let f = engine::detect_functions_in_sections(&info.sections, info.entry_point, info.is_little_endian);
        f.iter().map(|f| f.start).collect()
    }

    fn code() -> Vec<u32> {
        vec![
            PROLOGUE_16, JR_RA, NOP, NOP,          // 0x100000: A (entry), never calls B
            PROLOGUE_32, 0x2402_0001, JR_RA, 0x27BD_0020, // 0x100010: B; 0x100014 is mid-function
            NOP, NOP, NOP, NOP,
        ]
    }

    #[test]
    fn function_reached_only_through_a_data_pointer_is_discovered() {
        // data: [ &B, &mid-B, &data, &A ]
        let elf = elf_with_data(&code(), &[0x0010_0010, 0x0010_0014, 0x0020_0000, 0x0010_0000]);
        let s = starts_of(&elf);
        assert!(s.contains(&0x0010_0000), "entry point: {s:x?}");
        assert!(s.contains(&0x0010_0010), "ctor/vtable target with a prologue must be found: {s:x?}");
    }

    #[test]
    fn pointers_to_mid_function_code_and_to_data_are_ignored() {
        let elf = elf_with_data(&code(), &[0x0010_0010, 0x0010_0014, 0x0020_0000, 0x0010_0000]);
        let s = starts_of(&elf);
        assert!(!s.contains(&0x0010_0014), "a jump-table-style label inside a function is not a function: {s:x?}");
        assert!(!s.contains(&0x0020_0000), "a pointer into data is not a function: {s:x?}");
        assert_eq!(s.len(), 2, "{s:x?}");
    }

    /// Code for the thunk cases: function A (prologue), then a frameless thunk
    /// at 0x100010 that sets arguments and tail-calls, directly after A's
    /// `jr ra` + delay slot. A pointer-only reference must find the thunk.
    fn code_with_thunk() -> Vec<u32> {
        vec![
            PROLOGUE_16, JR_RA, NOP, NOP,                 // 0x100000: A ... jr ra @0x100004, delay @0x100008
            0x3C04_0039, 0x3C05_003F, 0x2484_3E10, 0x0804_3374, // 0x100010: thunk: lui,lui,addiu,j
            NOP, NOP, NOP, NOP,
        ]
    }

    #[test]
    fn frameless_thunk_after_a_return_is_found_through_a_pointer() {
        // Layout: 0x100008 `jr ra`, 0x10000C its delay slot, 0x100010 the
        // thunk. Nothing calls the thunk; only a data word points at it.
        let mut c = code_with_thunk();
        c[1] = NOP;
        c[2] = JR_RA;
        c[3] = NOP;
        let elf = elf_with_data(&c, &[0x0010_0010]);
        let s = starts_of(&elf);
        assert!(s.contains(&0x0010_0010), "callback-table thunk must be discovered: {s:x?}");
    }

    #[test]
    fn a_pointer_to_unrelated_non_prologue_code_without_a_preceding_return_is_ignored() {
        // Same thunk bytes, but the preceding instructions are plain code, so
        // nothing says a function starts there.
        let mut c = code_with_thunk();
        c[1] = 0x2402_0001; // addiu v0,zero,1
        c[2] = 0x2403_0002; // addiu v1,zero,2
        c[3] = 0x2404_0003;
        let elf = elf_with_data(&c, &[0x0010_0010]);
        let s = starts_of(&elf);
        assert!(!s.contains(&0x0010_0010), "{s:x?}");
    }

    #[test]
    fn unaligned_values_and_values_outside_the_image_are_ignored() {
        let elf = elf_with_data(&code(), &[0x0010_0011, 0x0010_0012, 0x0030_0000, 0xFFFF_FFFC, 0]);
        assert_eq!(starts_of(&elf), vec![0x0010_0000]);
    }

    #[test]
    fn no_pointer_means_no_extra_functions() {
        let elf = elf_with_data(&code(), &[1, 2, 3, 4]);
        assert_eq!(starts_of(&elf), vec![0x0010_0000]);
    }

    /// The full chain: a retail-style ELF whose only link to a function is a
    /// pointer must end up in the generated ps2_recomp function map, or the
    /// recompiler rejects the config.
    #[test]
    fn pointer_only_function_reaches_the_generated_function_csv() {
        let t = TempDir::new("ptr-csv");
        let root = vec![
            ("SYSTEM.CNF".to_string(), Node::File(b"BOOT2 = cdrom0:\\SLUS_203.12;1\r\n".to_vec())),
            (
                "SLUS_203.12".to_string(),
                Node::File(elf_with_data(&code(), &[0x0010_0010, 0x0010_0000])),
            ),
        ];
        let iso = t.path().join("g.iso");
        std::fs::write(&iso, build_iso("PTR", &root)).unwrap();
        let opts = IngestOptions { out_root: t.path().join("o").to_string_lossy().to_string(), mode: ExtractMode::Executables, recompiler: None };
        let res = ps2_ingest::ingest_ps2(iso.to_str().unwrap(), &opts, &mut |_| true).unwrap();
        let csv = std::fs::read_to_string(&res.functions_csv).unwrap();
        assert!(csv.contains("0x00100010"), "{csv}");
        assert_eq!(res.function_count, 2);
    }
}

// ===========================================================================
// ps2_ingest.rs — inspect + full pipeline
// ===========================================================================

mod pipeline_tests {
    use super::*;

    fn write_image(t: &TempDir, name: &str, bytes: &[u8]) -> String {
        let p = t.path().join(name);
        std::fs::write(&p, bytes).unwrap();
        p.to_string_lossy().to_string()
    }

    #[test]
    fn inspect_identifies_a_ps2_disc() {
        let t = TempDir::new("inspect");
        let img = write_image(&t, "game.iso", &ps2_disc(false));
        let info = ps2_ingest::inspect_image(&img).unwrap();
        assert_eq!(info.platform, "PS2");
        assert_eq!(info.serial.as_deref(), Some("SLUS-20312"));
        assert!(info.region.starts_with("NTSC-U"));
        assert_eq!(info.boot_file.as_deref(), Some("SLUS_203.12"));
        assert!(info.boot_is_ps2_elf);
        assert_eq!(info.display_name, "TEST GAME");
        assert_eq!(info.vmode.as_deref(), Some("NTSC"));
        assert_eq!(info.file_count, 5);
        assert_eq!(info.executable_count, 2, "boot ELF + one IRX: {:?}", info.executables);
        assert!(info.executables.iter().any(|e| e.kind == "IRX"));
        assert!(info.can_ingest);
        assert!(!info.truncated);
    }

    #[test]
    fn inspect_flags_ps1_and_non_playstation_discs() {
        let t = TempDir::new("notps2");
        let mut exe = b"PS-X EXE".to_vec();
        exe.resize(4096, 0);
        let ps1 = build_iso(
            "PS1_GAME",
            &files(&[("SYSTEM.CNF", b"BOOT = cdrom:\\SLUS_005.94;1\r\n"), ("SLUS_005.94", &exe)]),
        );
        let info = ps2_ingest::inspect_image(&write_image(&t, "ps1.iso", &ps1)).unwrap();
        assert_eq!(info.platform, "PS1");
        assert!(info.boot_is_psx_exe, "a PS-X EXE boot file makes a PS1 disc processable");
        assert!(info.can_ingest);
        assert!(!info.boot_is_ps2_elf);
        // ...but the PS2 ingest still refuses it and points at the PS1 pipeline.
        let e = ps2_ingest::ingest_ps2(
            &write_image(&t, "ps1.iso", &ps1),
            &ps2_ingest::IngestOptions {
                out_root: t.path().join("out").to_string_lossy().to_string(),
                mode: ps2_ingest::ExtractMode::Executables,
                recompiler: None,
            },
            &mut |_| true,
        )
        .unwrap_err();
        assert!(e.contains("ps1-ingest"), "{e}");

        // a PS1 disc whose boot file is not a PS-X EXE cannot be built
        let packed = build_iso(
            "PS1_PACKED",
            &files(&[("SYSTEM.CNF", b"BOOT = cdrom:\\SLUS_005.94;1\r\n"), ("SLUS_005.94", &[0x42u8; 4096])]),
        );
        let info = ps2_ingest::inspect_image(&write_image(&t, "packed.iso", &packed)).unwrap();
        assert_eq!(info.platform, "PS1");
        assert!(!info.can_ingest);

        let other = build_iso("PHOTOS", &files(&[("A.JPG", b"jpeg")]));
        let info = ps2_ingest::inspect_image(&write_image(&t, "other.iso", &other)).unwrap();
        assert_eq!(info.platform, "Unknown");
        assert!(!info.can_ingest);
        assert!(info.warnings.iter().any(|w| w.contains("SYSTEM.CNF")));
    }

    #[test]
    fn boot_entry_missing_from_disc_is_reported() {
        let t = TempDir::new("noboot");
        let bytes = build_iso("MISSING", &files(&[("SYSTEM.CNF", b"BOOT2 = cdrom0:\\SLUS_999.99;1\r\n")]));
        let img = write_image(&t, "m.iso", &bytes);
        let info = ps2_ingest::inspect_image(&img).unwrap();
        assert!(!info.can_ingest);
        assert!(info.warnings.iter().any(|w| w.contains("SLUS_999.99")));
        let opts = IngestOptions { out_root: t.path().join("out").to_string_lossy().to_string(), mode: ExtractMode::Executables, recompiler: None };
        let err = ps2_ingest::ingest_ps2(&img, &opts, &mut |_| true).unwrap_err();
        assert!(err.contains("SLUS_999.99"), "{err}");
    }

    #[test]
    fn ingest_refuses_ps1_with_a_clear_message() {
        let t = TempDir::new("ps1refuse");
        let mut exe = b"PS-X EXE".to_vec();
        exe.resize(4096, 0);
        let ps1 = build_iso("PS1_GAME", &files(&[("SYSTEM.CNF", b"BOOT = cdrom:\\SLUS_005.94;1\r\n"), ("SLUS_005.94", &exe)]));
        let img = write_image(&t, "ps1.iso", &ps1);
        let opts = IngestOptions { out_root: t.path().join("out").to_string_lossy().to_string(), mode: ExtractMode::Executables, recompiler: None };
        let err = ps2_ingest::ingest_ps2(&img, &opts, &mut |_| true).unwrap_err();
        assert!(err.contains("PS1"), "{err}");
    }

    #[test]
    fn ingest_executables_only_builds_a_ps2recomp_project() {
        let t = TempDir::new("ingest-exe");
        let img = write_image(&t, "game.iso", &wrap_layout(&ps2_disc(false), 2352, 24));
        let out = t.path().join("out");
        let opts = IngestOptions { out_root: out.to_string_lossy().to_string(), mode: ExtractMode::Executables, recompiler: None };
        let mut stages: Vec<String> = vec![];
        let res = ps2_ingest::ingest_ps2(&img, &opts, &mut |p| {
            if stages.last() != Some(&p.stage) {
                stages.push(p.stage.clone());
            }
            true
        })
        .unwrap();

        assert_eq!(stages, ["open", "inspect", "extract", "analyze", "config", "done"]);
        assert_eq!(res.serial.as_deref(), Some("SLUS-20312"));
        assert!(res.workspace.ends_with("SLUS-20312"));
        assert_eq!(res.extracted_files, 3, "SYSTEM.CNF + boot ELF + IRX only");

        let ws = out.join("SLUS-20312");
        assert!(ws.join("disc").join("SYSTEM.CNF").is_file());
        assert!(ws.join("disc").join("SLUS_203.12").is_file());
        assert!(ws.join("disc").join("IOP").join("SIO2MAN.IRX").is_file());
        assert!(!ws.join("disc").join("DATA").exists(), "assets must not be copied in executables mode");

        // The segment-only ELF must still produce functions.
        assert!(res.function_count >= 3, "functions: {}", res.function_count);
        let csv = std::fs::read_to_string(&res.functions_csv).unwrap();
        assert!(csv.starts_with("Name,Start,End,Size\n"));
        assert!(csv.contains("0x00100020"), "{csv}");

        let cfg = std::fs::read_to_string(&res.config_toml).unwrap();
        assert!(cfg.contains("[general]"));
        assert!(cfg.contains("SLUS_203.12.elf"), "input path must point at the ELF copy: {cfg}");
        assert!(cfg.contains("functions.csv"));
        assert!(cfg.contains("entry_point = \"0x00100000\""));
        assert!(Path::new(&res.recomp_output_dir).is_dir());

        let manifest: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&res.manifest_path).unwrap()).unwrap();
        assert_eq!(manifest["serial"], "SLUS-20312");
        assert_eq!(manifest["platform"], "PS2");
        assert_eq!(manifest["extract_mode"], "executables");
        assert_eq!(manifest["recomp"]["function_count"].as_u64().unwrap() as usize, res.function_count);
        assert!(ws.join("recomp").join("README.md").is_file());
        assert!(res.recompiler.is_none());
        assert!(res.next_steps.iter().any(|s| s.contains("ps2xRuntime")));
    }

    #[test]
    fn ingest_all_copies_assets_too() {
        let t = TempDir::new("ingest-all");
        let img = write_image(&t, "game.iso", &ps2_disc(true));
        let opts = IngestOptions { out_root: t.path().join("out").to_string_lossy().to_string(), mode: ExtractMode::All, recompiler: None };
        let res = ps2_ingest::ingest_ps2(&img, &opts, &mut |_| true).unwrap();
        assert_eq!(res.extracted_files, 5);
        let big = std::fs::read(Path::new(&res.disc_dir).join("DATA").join("BIG.DAT")).unwrap();
        assert_eq!(big.len(), 5000);
    }

    /// Regression: a real disc has thousands of small files and extraction used
    /// to report once per file, i.e. hundreds of callbacks per second (8,101
    /// webview events for an 8,005-file disc), each one a re-render in the GUI.
    #[test]
    fn progress_is_rate_limited_for_many_small_files() {
        let t = TempDir::new("ingest-flood");
        let files = 3000;
        let img = write_image(&t, "big.iso", &ps2_disc_with_filler(false, files));
        let opts = IngestOptions { out_root: t.path().join("out").to_string_lossy().to_string(), mode: ExtractMode::All, recompiler: None };
        let mut calls = 0usize;
        let mut stages: Vec<String> = vec![];
        let mut last: Option<ps2_ingest::IngestProgress> = None;
        let res = ps2_ingest::ingest_ps2(&img, &opts, &mut |p| {
            calls += 1;
            if stages.last() != Some(&p.stage) {
                stages.push(p.stage.clone());
            }
            last = Some(p.clone());
            true
        })
        .unwrap();
        assert_eq!(res.extracted_files, files + 5);
        assert!(calls >= 6, "every stage must still be reported, got {calls} calls");
        assert!(
            calls < files / 10,
            "progress must be throttled: {calls} callbacks for {files} files"
        );
        assert_eq!(stages, ["open", "inspect", "extract", "analyze", "config", "done"]);
        let last = last.unwrap();
        assert_eq!(last.stage, "done");
        assert_eq!(last.fraction, 1.0);
    }

    #[test]
    fn cancel_is_honoured_when_it_arrives_on_a_later_stage() {
        let t = TempDir::new("ingest-cancel-late");
        let img = write_image(&t, "game.iso", &ps2_disc_with_filler(false, 400));
        let opts = IngestOptions { out_root: t.path().join("out").to_string_lossy().to_string(), mode: ExtractMode::All, recompiler: None };
        // Cancel only once extraction is over. Extraction's own calls were
        // throttled away, but the stage change must still get through.
        let err = ps2_ingest::ingest_ps2(&img, &opts, &mut |p| p.stage != "analyze").unwrap_err();
        assert!(err.to_lowercase().contains("cancel"), "{err}");
    }

    #[test]
    fn ingest_can_be_cancelled() {
        let t = TempDir::new("ingest-cancel");
        let img = write_image(&t, "game.iso", &ps2_disc(true));
        let opts = IngestOptions { out_root: t.path().join("out").to_string_lossy().to_string(), mode: ExtractMode::All, recompiler: None };
        let err = ps2_ingest::ingest_ps2(&img, &opts, &mut |p| p.stage != "extract").unwrap_err();
        assert!(err.to_lowercase().contains("cancel"), "{err}");
    }

    #[test]
    fn rerunning_ingest_is_idempotent() {
        let t = TempDir::new("ingest-twice");
        let img = write_image(&t, "game.iso", &ps2_disc(false));
        let opts = IngestOptions { out_root: t.path().join("out").to_string_lossy().to_string(), mode: ExtractMode::Executables, recompiler: None };
        let a = ps2_ingest::ingest_ps2(&img, &opts, &mut |_| true).unwrap();
        let b = ps2_ingest::ingest_ps2(&img, &opts, &mut |_| true).unwrap();
        assert_eq!(a.workspace, b.workspace);
        assert_eq!(a.function_count, b.function_count);
    }

    #[test]
    fn missing_recompiler_is_a_warning_not_a_failure() {
        let t = TempDir::new("ingest-norecomp");
        let img = write_image(&t, "game.iso", &ps2_disc(false));
        let ghost = t.path().join("no-such-ps2_recomp");
        let opts = IngestOptions {
            out_root: t.path().join("out").to_string_lossy().to_string(),
            mode: ExtractMode::Executables,
            recompiler: Some(ghost.to_string_lossy().to_string()),
        };
        let res = ps2_ingest::ingest_ps2(&img, &opts, &mut |_| true).unwrap();
        let run = res.recompiler.expect("run recorded");
        assert!(!run.success);
        assert!(run.error.unwrap().contains("not found"));
        assert!(res.warnings.iter().any(|w| w.contains("ps2_recomp")));
        assert!(Path::new(&res.config_toml).is_file(), "project must still be written");
    }
}

// ===========================================================================
// ps2_ingest.rs — recompiler discovery and execution
// ===========================================================================

mod recompiler_tests {
    use super::*;

    #[test]
    fn search_path_finds_binary_in_listed_dirs() {
        let t = TempDir::new("path");
        let empty = TempDir::new("path-empty");
        std::fs::write(t.path().join("ps2_recomp"), b"x").unwrap();
        let joined = std::env::join_paths([empty.path(), t.path()]).unwrap();
        let found = ps2_ingest::search_path(&["ps2_recomp"], &joined).unwrap();
        assert!(found.starts_with(t.path()));
        assert!(ps2_ingest::search_path(&["definitely_not_here"], &joined).is_none());
    }

    #[test]
    fn explicit_path_must_exist() {
        let t = TempDir::new("explicit");
        assert!(ps2_ingest::find_recompiler(Some(t.path().join("nope").to_str().unwrap())).is_none());
        let f = t.path().join("ps2_recomp");
        std::fs::write(&f, b"x").unwrap();
        assert_eq!(ps2_ingest::find_recompiler(Some(f.to_str().unwrap())), Some(f));
    }

    /// Write a throwaway script standing in for `ps2_recomp`: it records its
    /// argument, drops one "generated" file into `out_dir`, and exits `code`.
    fn fake_recompiler(dir: &Path, out_dir: &Path, code: i32) -> PathBuf {
        #[cfg(windows)]
        {
            let p = dir.join("fake_ps2_recomp.bat");
            let body = format!(
                "@echo off\r\necho recompiling %1\r\necho generated> \"{}\\out.cpp\"\r\nexit /b {}\r\n",
                out_dir.display(),
                code
            );
            std::fs::write(&p, body).unwrap();
            p
        }
        #[cfg(not(windows))]
        {
            use std::os::unix::fs::PermissionsExt;
            let p = dir.join("fake_ps2_recomp.sh");
            let body = format!(
                "#!/bin/sh\necho \"recompiling $1\"\necho generated > \"{}/out.cpp\"\nexit {}\n",
                out_dir.display(),
                code
            );
            std::fs::write(&p, body).unwrap();
            let mut perm = std::fs::metadata(&p).unwrap().permissions();
            perm.set_mode(0o755);
            std::fs::set_permissions(&p, perm).unwrap();
            p
        }
    }

    #[test]
    fn runs_recompiler_and_captures_log() {
        let t = TempDir::new("run-ok");
        let out = t.path().join("generated");
        std::fs::create_dir_all(&out).unwrap();
        let exe = fake_recompiler(t.path(), &out, 0);
        let cfg = t.path().join("config.toml");
        std::fs::write(&cfg, "[general]\n").unwrap();
        let log = t.path().join("run.log");
        let run = ps2_ingest::run_recompiler(&exe, &cfg, t.path(), &out, &log, &mut || true);
        assert!(run.success, "{run:?}");
        assert_eq!(run.exit_code, Some(0));
        assert_eq!(run.generated_files, 1);
        assert!(run.log_tail.iter().any(|l| l.contains("recompiling")), "{:?}", run.log_tail);
        assert!(run.log_tail.iter().any(|l| l.contains("config.toml")), "{:?}", run.log_tail);
    }

    #[test]
    fn nonzero_exit_is_reported_as_failure() {
        let t = TempDir::new("run-fail");
        let out = t.path().join("generated");
        std::fs::create_dir_all(&out).unwrap();
        let exe = fake_recompiler(t.path(), &out, 3);
        let cfg = t.path().join("config.toml");
        std::fs::write(&cfg, "[general]\n").unwrap();
        let run = ps2_ingest::run_recompiler(&exe, &cfg, t.path(), &out, &t.path().join("run.log"), &mut || true);
        assert!(!run.success);
        assert_eq!(run.exit_code, Some(3));
        assert!(run.error.is_some());
    }

    #[test]
    fn missing_binary_is_reported() {
        let t = TempDir::new("run-missing");
        let run = ps2_ingest::run_recompiler(
            &t.path().join("nope"),
            &t.path().join("c.toml"),
            t.path(),
            t.path(),
            &t.path().join("l.log"),
            &mut || true,
        );
        assert!(!run.success);
        assert!(run.error.unwrap().contains("not found"));
    }
}

// ===========================================================================
// Manual-testing helper
// ===========================================================================

/// Writes a small synthetic PS2 disc image so the CLI and the GUI wizard can be
/// tried without owning a game:
///
/// ```text
/// cargo test --manifest-path cli/Cargo.toml write_sample_ps2_iso -- --ignored
/// ```
///
/// Output path: `$AURA_SAMPLE_ISO_OUT`, else `<temp dir>/aura-sample-ps2.iso`.
/// Set `AURA_SAMPLE_ISO_FILES=N` to add N small filler files (a real game has
/// thousands) for exercising progress reporting and extraction speed.
/// The image has a valid `SYSTEM.CNF`, a tiny MIPS boot ELF (no section
/// headers, like many retail executables) and some filler "assets". It contains
/// no game code or data.
#[test]
#[ignore = "writes a file; run explicitly to get a sample disc for manual testing"]
fn write_sample_ps2_iso() {
    let out = std::env::var_os("AURA_SAMPLE_ISO_OUT")
        .map(PathBuf::from)
        .unwrap_or_else(|| std::env::temp_dir().join("aura-sample-ps2.iso"));
    let filler: usize = std::env::var("AURA_SAMPLE_ISO_FILES")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    std::fs::write(&out, ps2_disc_with_filler(false, filler)).expect("write sample iso");
    println!("sample PS2 disc ({filler} filler files) written to {}", out.display());
}
