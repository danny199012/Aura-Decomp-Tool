//! Pure-Rust Microsoft LZX decompressor.
//!
//! This is a faithful port of libmspack's `lzxd.c` — the LZX variant used by
//! XEX images, CAB and CHM files. It is used by the Xbox 360 backend to expand
//! XEX images whose optional `FILE_FORMAT_INFO` header declares
//! `compression_type == 2` ("normal (LZX)").
//!
//! Port notes vs. the C reference:
//! * the whole compressed stream is held in memory and the full decompressed
//!   length is known up front (both true for XEX image decompression);
//! * the optional Intel `0xE8` preprocessing step is implemented for spec
//!   completeness. It is switched on by a single header bit; XEX images carry
//!   PowerPC (not x86) code, so it is effectively never used here.
//! * LZX DELTA (reference-data) mode is out of scope: XEX block decompression
//!   always asks for regular LZX with no reference data.

/// Errors returned by the decompressor.
///
/// The variants mirror libmspack's `MSPACK_ERR_*` semantics so callers can
/// report why a stream failed. In the XEX pipeline a `Decrunched`/`Read`
/// result usually means the input region is corrupt or was not actually LZX.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LzxError {
    /// Invalid arguments (window size not in the 15..=21 bit range).
    Args,
    /// Could not fully decode the stream (bad/truncated data).
    Decrunched,
    /// Ran off the end of the input while still needing bits.
    Read,
}

// ---- LZX specification constants ----
const LZX_MIN_MATCH: usize = 2;
const LZX_MAX_MATCH: usize = 257;
const LZX_NUM_CHARS: usize = 256;

const LZX_BLOCKTYPE_INVALID: u8 = 0;
const LZX_BLOCKTYPE_VERBATIM: u8 = 1;
const LZX_BLOCKTYPE_ALIGNED: u8 = 2;
const LZX_BLOCKTYPE_UNCOMPRESSED: u8 = 3;

const LZX_PRETREE_NUM_ELEMENTS: usize = 20;
const LZX_ALIGNED_NUM_ELEMENTS: usize = 8;
const LZX_NUM_PRIMARY_LENGTHS: usize = 7;
const LZX_NUM_SECONDARY_LENGTHS: usize = 249;

const LZX_PRETREE_TABLEBITS: u32 = 6;
const LZX_MAINTREE_TABLEBITS: u32 = 12;
const LZX_LENGTH_TABLEBITS: u32 = 12;
const LZX_ALIGNED_TABLEBITS: u32 = 7;

const LZX_MAINTREE_MAXSYMBOLS: usize = 256 + 290 * 8;
const LZX_LENGTH_MAXSYMBOLS: usize = 250;

const LZX_FRAME_SIZE: usize = 32768;

/// Extra safety margin on the length arrays (as in libmspack).
const LZX_LENTABLE_SAFETY: usize = 64;

/// Number of position slots per window size (index `window_bits - 15`).
const POSITION_SLOTS: [usize; 11] = [
    30, 32, 34, 36, 38, 42, 50, 66, 98, 162, 290,
];

const EXTRA_BITS: [u32; 36] = [
    0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10,
    11, 11, 12, 12, 13, 13, 14, 14, 15, 15, 16, 16,
];

const POSITION_BASE: [u32; 290] = [
    0, 1, 2, 3, 4, 6, 8, 12, 16, 24, 32, 48, 64, 96, 128, 192, 256, 384, 512,
    768, 1024, 1536, 2048, 3072, 4096, 6144, 8192, 12288, 16384, 24576, 32768,
    49152, 65536, 98304, 131072, 196608, 262144, 393216, 524288, 655360,
    786432, 917504, 1048576, 1179648, 1310720, 1441792, 1572864, 1703936,
    1835008, 1966080, 2097152, 2228224, 2359296, 2490368, 2621440, 2752512,
    2883584, 3014656, 3145728, 3276800, 3407872, 3538944, 3670016, 3801088,
    3932160, 4063232, 4194304, 4325376, 4456448, 4587520, 4718592, 4849664,
    4980736, 5111808, 5242880, 5373952, 5505024, 5636096, 5767168, 5898240,
    6029312, 6160384, 6291456, 6422528, 6553600, 6684672, 6815744, 6946816,
    7077888, 7208960, 7340032, 7471104, 7602176, 7733248, 7864320, 7995392,
    8126464, 8257536, 8388608, 8519680, 8650752, 8781824, 8912896, 9043968,
    9175040, 9306112, 9437184, 9568256, 9699328, 9830400, 9961472, 10092544,
    10223616, 10354688, 10485760, 10616832, 10747904, 10878976, 11010048,
    11141120, 11272192, 11403264, 11534336, 11665408, 11796480, 11927552,
    12058624, 12189696, 12320768, 12451840, 12582912, 12713984, 12845056,
    12976128, 13107200, 13238272, 13369344, 13500416, 13631488, 13762560,
    13893632, 14024704, 14155776, 14286848, 14417920, 14548992, 14680064,
    14811136, 14942208, 15073280, 15204352, 15335424, 15466496, 15597568,
    15728640, 15859712, 15990784, 16121856, 16252928, 16384000, 16515072,
    16646144, 16777216, 16908288, 17039360, 17170432, 17301504, 17432576,
    17563648, 17694720, 17825792, 17956864, 18087936, 18219008, 18350080,
    18481152, 18612224, 18743296, 18874368, 19005440, 19136512, 19267584,
    19398656, 19529728, 19660800, 19791872, 19922944, 20054016, 20185088,
    20316160, 20447232, 20578304, 20709376, 20840448, 20971520, 21102592,
    21233664, 21364736, 21495808, 21626880, 21757952, 21889024, 22020096,
    22151168, 22282240, 22413312, 22544384, 22675456, 22806528, 22937600,
    23068672, 23199744, 23330816, 23461888, 23592960, 23724032, 23855104,
    23986176, 24117248, 24248320, 24379392, 24510464, 24641536, 24772608,
    24903680, 25034752, 25165824, 25296896, 25427968, 25559040, 25690112,
    25821184, 25952256, 26083328, 26214400, 26345472, 26476544, 26607616,
    26738688, 26869760, 27000832, 27131904, 27262976, 27394048, 27525120,
    27656192, 27787264, 27918336, 28049408, 28180480, 28311552, 28442624,
    28573696, 28704768, 28835840, 28966912, 29097984, 29229056, 29360128,
    29491200, 29622272, 29753344, 29884416, 30015488, 30146560, 30277632,
    30408704, 30539776, 30670848, 30801920, 30932992, 31064064, 31195136,
    31326208, 31457280, 31588352, 31719424, 31850496, 31981568, 32112640,
    32243712, 32374784, 32505856, 32636928, 32768000, 32899072, 33030144,
    33161216, 33292288, 33423360,
];

// ============================================================================
// Huffman fast-lookup table construction
// ============================================================================
/// Build a canonical Huffman fast-lookup table (libmspack `make_decode_table`,
/// MSB variant). `length[sym]` is the code length (0 = unused). On success the
/// table holds direct symbol entries, `0xFFFF` markers for unused slots and
/// links for long codes, exactly like the C version. Returns `true` on failure.
fn make_decode_table(nsyms: usize, nbits: u32, length: &[u8], table: &mut Vec<u16>) -> bool {
    let table_size: usize = 1usize << nbits;
    table.clear();
    table.resize(table_size, 0u16);

    let mut pos: u64 = 0;
    let table_mask: u64 = table_size as u64;
    let mut bit_mask: u64 = table_mask >> 1;

    // Symbols short enough for a direct mapping.
    for bit_num in 1..=nbits {
        for sym in 0..nsyms {
            if length[sym] != bit_num as u8 {
                continue;
            }
            let mut leaf = pos as usize;
            pos += bit_mask;
            if pos > table_mask {
                return true; // overrun
            }
            let mut fill = bit_mask;
            while fill > 0 {
                table[leaf] = sym as u16;
                leaf += 1;
                fill -= 1;
            }
        }
        bit_mask >>= 1;
    }

    if pos == table_mask {
        return false; // complete
    }

    // Mark remaining direct entries as unused.
    for sym in (pos as usize)..table_size {
        table[sym] = 0xFFFF;
    }

    // Long-code section. `next_symbol` is the base of the extension area.
    let mut next_symbol: usize = if (table_mask >> 1) < nsyms as u64 {
        nsyms
    } else {
        (table_mask >> 1) as usize
    };

    pos <<= 16;
    let table_mask = table_mask << 16;
    let mut bit_mask: u64 = 1u64 << 15;

    for bit_num in (nbits + 1)..=16u32 {
        for sym in 0..nsyms {
            if length[sym] != bit_num as u8 {
                continue;
            }
            if pos >= table_mask {
                return true; // overflow
            }
            let mut leaf = (pos >> 16) as usize;
            for fill in 0..(bit_num - nbits) {
                if table[leaf] == 0xFFFF {
                    let ne = next_symbol;
                    if table.len() <= ne * 2 + 1 {
                        table.resize(ne * 2 + 2, 0xFFFF);
                    }
                    table[ne * 2] = 0xFFFF;
                    table[ne * 2 + 1] = 0xFFFF;
                    table[leaf] = ne as u16;
                    next_symbol += 1;
                }
                leaf = (table[leaf] as usize) * 2;
                if ((pos >> (15 - fill)) & 1) != 0 {
                    leaf += 1;
                }
            }
            table[leaf] = sym as u16;
            pos += bit_mask;
        }
        bit_mask >>= 1;
    }

    pos != table_mask
}

// ============================================================================
// Decompressor state
// ============================================================================
struct LzxState<'a> {
    bits: BitReader<'a>,
    output: Vec<u8>,

    window_size: usize,
    window: Vec<u8>,
    num_offsets: usize,
    window_posn: usize,
    frame_posn: usize,
    frame: usize,
    offset: usize,
    length: usize,

    r0: u32,
    r1: u32,
    r2: u32,
    block_length: usize,
    block_remaining: usize,
    block_type: u8,

    intel_filesize: i32,
    intel_curpos: i32,
    intel_started: bool,
    header_read: bool,

    // Huffman code lengths and fast-lookup tables.
    pretree_len: Vec<u8>,
    maintree_len: Vec<u8>,
    length_len: Vec<u8>,
    aligned_len: Vec<u8>,
    length_empty: bool,
    pretree_table: Vec<u16>,
    maintree_table: Vec<u16>,
    length_table: Vec<u16>,
    aligned_table: Vec<u16>,

    // Scratch buffer used for the Intel E8 transform.
    e8_buf: Vec<u8>,
}

/// Decompress an LZX stream. See the module docs for parameters.
pub fn lzx_decompress(
    input: &[u8],
    window_size: u32,
    output_length: usize,
) -> Result<Vec<u8>, LzxError> {
    if window_size == 0 || (window_size & (window_size - 1)) != 0 {
        return Err(LzxError::Args);
    }
    let window_bits = window_size.trailing_zeros() as u32;
    if !(15..=21).contains(&window_bits) {
        return Err(LzxError::Args);
    }
    let num_offsets = POSITION_SLOTS[(window_bits - 15) as usize] << 3;

    let mut st = LzxState {
        bits: BitReader::new(input),
        output: Vec::new(),
        window_size: window_size as usize,
        window: vec![0u8; window_size as usize],
        num_offsets,
        window_posn: 0,
        frame_posn: 0,
        frame: 0,
        offset: 0,
        length: output_length,
        r0: 1,
        r1: 1,
        r2: 1,
        block_length: 0,
        block_remaining: 0,
        block_type: LZX_BLOCKTYPE_INVALID,
        intel_filesize: 0,
        intel_curpos: 0,
        intel_started: false,
        header_read: false,
        pretree_len: vec![0u8; LZX_PRETREE_NUM_ELEMENTS + LZX_LENTABLE_SAFETY],
        maintree_len: vec![0u8; LZX_MAINTREE_MAXSYMBOLS + LZX_LENTABLE_SAFETY],
        length_len: vec![0u8; LZX_LENGTH_MAXSYMBOLS + LZX_LENTABLE_SAFETY],
        aligned_len: vec![0u8; LZX_ALIGNED_NUM_ELEMENTS + LZX_LENTABLE_SAFETY],
        length_empty: false,
        pretree_table: Vec::new(),
        maintree_table: Vec::new(),
        length_table: Vec::new(),
        aligned_table: Vec::new(),
        e8_buf: vec![0u8; LZX_FRAME_SIZE],
    };
    st.run_decompress()
}
/// Build a fast-lookup table for the tree with `nsyms` symbols and `tablebits`
/// look-up bits; returns `Err` on an invalid/corrupt length set.
fn build_lzx_table(
    len: &[u8],
    nsyms: usize,
    tablebits: u32,
    table: &mut Vec<u16>,
) -> Result<(), LzxError> {
    if make_decode_table(nsyms, tablebits, len, table) {
        return Err(LzxError::Decrunched);
    }
    Ok(())
}

/// Read code lengths `first..last` in LZX's delta/run encoding scheme.
fn read_lens(bits: &mut BitReader, lens: &mut [u8], first: usize, last: usize) -> Result<(), LzxError> {
    let mut pretree_len = vec![0u8; LZX_PRETREE_NUM_ELEMENTS + LZX_LENTABLE_SAFETY];
    for x in 0..LZX_PRETREE_NUM_ELEMENTS {
        pretree_len[x] = bits.read_bits(4)? as u8;
    }
    let mut pretree_table = Vec::new();
    build_lzx_table(&pretree_len, LZX_PRETREE_NUM_ELEMENTS, LZX_PRETREE_TABLEBITS, &mut pretree_table)?;

    let mut x = first;
    while x < last {
        let z = bits.read_huffsym(&pretree_table, LZX_PRETREE_NUM_ELEMENTS, LZX_PRETREE_TABLEBITS, &pretree_len)? as u32;
        if z == 17 {
            let mut y = bits.read_bits(4)? + 4;
            while y > 0 {
                lens[x] = 0;
                x += 1;
                y -= 1;
            }
        } else if z == 18 {
            let mut y = bits.read_bits(5)? + 20;
            while y > 0 {
                lens[x] = 0;
                x += 1;
                y -= 1;
            }
        } else if z == 19 {
            let mut y = bits.read_bits(1)? + 4;
            let zz = bits.read_huffsym(&pretree_table, LZX_PRETREE_NUM_ELEMENTS, LZX_PRETREE_TABLEBITS, &pretree_len)? as u32;
            let mut zv = lens[x] as i32 - zz as i32;
            if zv < 0 {
                zv += 17;
            }
            while y > 0 {
                lens[x] = zv as u8;
                x += 1;
                y -= 1;
            }
        } else {
            let mut zv = lens[x] as i32 - z as i32;
            if zv < 0 {
                zv += 17;
            }
            lens[x] = zv as u8;
            x += 1;
        }
    }
    Ok(())
}

impl LzxState<'_> {

    /// Read the main + length tree lengths for a VERBATIM (or, after the
    /// aligned tree, ALIGNED) block.
    fn read_len_block(&mut self) -> Result<(), LzxError> {
        let num_offsets = self.num_offsets;
        let total_main = LZX_NUM_CHARS + num_offsets;
        read_lens(&mut self.bits, &mut self.maintree_len[..], 0, LZX_NUM_CHARS)?;
        read_lens(&mut self.bits, &mut self.maintree_len[..], LZX_NUM_CHARS, total_main)?;

        if self.maintree_len[0xE8] != 0 {
            self.intel_started = true;
        }
        let mt = self.maintree_len.clone();
        build_lzx_table(&mt, LZX_MAINTREE_MAXSYMBOLS, LZX_MAINTREE_TABLEBITS, &mut self.maintree_table)?;

        read_lens(&mut self.bits, &mut self.length_len[..], 0, LZX_NUM_SECONDARY_LENGTHS)?;
        let lt = self.length_len.clone();
        // A fully empty length tree is tolerated (no matches present).
        self.length_empty = false;
        if make_decode_table(
            LZX_LENGTH_MAXSYMBOLS,
            LZX_LENGTH_TABLEBITS,
            &lt,
            &mut self.length_table,
        ) {
            let mut some_nonzero = false;
            for i in 0..LZX_LENGTH_MAXSYMBOLS {
                if lt[i] > 0 {
                    some_nonzero = true;
                    break;
                }
            }
            if some_nonzero {
                return Err(LzxError::Decrunched);
            }
            self.length_empty = true;
        }
        Ok(())
    }

    /// Start a new LZX block: read its type/length and whatever tree lengths
    /// its type requires.
    fn new_block(&mut self) -> Result<(), LzxError> {
        // Realign if the previous block was an odd-sized UNCOMPRESSED block
        // (the C reference skips a single input byte here).
        if self.block_type == LZX_BLOCKTYPE_UNCOMPRESSED && (self.block_length & 1) != 0 {
            if self.bits.i_ptr >= self.bits.input.len() {
                if self.bits.eof_padded {
                    return Err(LzxError::Read);
                }
                self.bits.eof_padded = true;
            } else {
                self.bits.i_ptr += 1;
            }
        }

        let bt = self.bits.read_bits(3)? as u8;
        self.block_type = bt;
        let hi = self.bits.read_bits(16)?;
        let lo = self.bits.read_bits(8)?;
        self.block_remaining = ((hi << 8) | lo) as usize;
        self.block_length = self.block_remaining;

        match self.block_type {
            LZX_BLOCKTYPE_ALIGNED => {
                // Aligned offset tree first, then shared with VERBATIM.
                for i in 0..LZX_ALIGNED_NUM_ELEMENTS {
                    let v = self.bits.read_bits(3)? as u8;
                    self.aligned_len[i] = v;
                }
                let al = self.aligned_len.clone();
                build_lzx_table(&al, LZX_ALIGNED_NUM_ELEMENTS, LZX_ALIGNED_TABLEBITS, &mut self.aligned_table)?;
                self.read_len_block()
            }
            LZX_BLOCKTYPE_VERBATIM => self.read_len_block(),
            LZX_BLOCKTYPE_UNCOMPRESSED => {
                self.intel_started = true;
                // Align to a byte boundary.
                if self.bits.bits_left == 0 {
                    self.bits.ensure_bits(16)?;
                }
                self.bits.bits_left = 0;
                self.bits.bit_buffer = 0;
                // Read 12 bytes of stored R0/R1/R2 (little-endian each).
                let mut buf = [0u8; 12];
                for b in buf.iter_mut() {
                    if let Some(&v) = self.bits.input.get(self.bits.i_ptr) {
                        *b = v;
                        self.bits.i_ptr += 1;
                    } else {
                        if self.bits.eof_padded {
                            return Err(LzxError::Read);
                        }
                        self.bits.eof_padded = true;
                        *b = 0;
                    }
                }
                self.r0 = u32::from_le_bytes(buf[0..4].try_into().unwrap());
                self.r1 = u32::from_le_bytes(buf[4..8].try_into().unwrap());
                self.r2 = u32::from_le_bytes(buf[8..12].try_into().unwrap());
                Ok(())
            }
            _ => Err(LzxError::Decrunched),
        }
    }
/// Decode literals/matches, writing into the window. `this_run` may be
    /// driven negative by a match that overshoots its byte budget.
    fn decode_verbatim_or_aligned(
        &mut self,
        aligned: bool,
        this_run: &mut i64,
    ) -> Result<(), LzxError> {
        let window_size = self.window_size;
        let mut wpos = self.window_posn;
        let mut remaining_run = *this_run; // signed, mirrors C's `this_run`

        while remaining_run > 0 {
            let main_element = self.bits.read_huffsym(
                &self.maintree_table,
                LZX_MAINTREE_MAXSYMBOLS,
                LZX_MAINTREE_TABLEBITS,
                &self.maintree_len,
            )? as usize;

            if main_element < LZX_NUM_CHARS {
                self.window[wpos] = main_element as u8;
                wpos += 1;
                remaining_run -= 1;
            } else {
                let me = main_element - LZX_NUM_CHARS;
                let mut match_length = me & LZX_NUM_PRIMARY_LENGTHS;
                if match_length == LZX_NUM_PRIMARY_LENGTHS {
                    if self.length_empty {
                        return Err(LzxError::Decrunched);
                    }
                    let footer = self.bits.read_huffsym(
                        &self.length_table,
                        LZX_LENGTH_MAXSYMBOLS,
                        LZX_LENGTH_TABLEBITS,
                        &self.length_len,
                    )? as usize;
                    match_length += footer;
                }
                match_length += LZX_MIN_MATCH;

                // Resolve the match offset.
                let slot = me >> 3;
                let match_offset: u32 = if slot == 0 {
                    self.r0
                } else if slot == 1 {
                    let mo = self.r1;
                    self.r1 = self.r0;
                    self.r0 = mo;
                    mo
                } else if slot == 2 {
                    let mo = self.r2;
                    self.r2 = self.r0;
                    self.r0 = mo;
                    mo
                } else if slot == 3 {
                    let mo = 1u32;
                    self.r2 = self.r1;
                    self.r1 = self.r0;
                    self.r0 = mo;
                    mo
                } else {
                    let extra = if slot >= 36 { 17 } else { EXTRA_BITS[slot] };
                    let base = POSITION_BASE[slot] - 2;
                    let mo = if aligned {
                        let mut m = base;
                        if extra > 3 {
                            let vb = self.bits.read_bits((extra - 3) as i32)?;
                            let ab = self.bits.read_huffsym(
                                &self.aligned_table,
                                LZX_ALIGNED_NUM_ELEMENTS,
                                LZX_ALIGNED_TABLEBITS,
                                &self.aligned_len,
                            )? as u32;
                            m += (vb << 3) + ab;
                        } else if extra == 3 {
                            let ab = self.bits.read_huffsym(
                                &self.aligned_table,
                                LZX_ALIGNED_NUM_ELEMENTS,
                                LZX_ALIGNED_TABLEBITS,
                                &self.aligned_len,
                            )? as u32;
                            m += ab;
                        } else if extra > 0 {
                            m += self.bits.read_bits(extra as i32)?;
                        } else {
                            m = 1; // undefined in the spec, as in libmspack
                        }
                        m
                    } else {
                        base.wrapping_add(self.bits.read_bits(extra as i32)?)
                    };
                    self.r2 = self.r1;
                    self.r1 = self.r0;
                    self.r0 = mo;
                    mo
                };

                // Guard: the match must stay inside the window.
                if wpos + match_length > window_size {
                    return Err(LzxError::Decrunched);
                }

                copy_match(&mut self.window, wpos, match_offset, match_length);

                wpos += match_length;
                // `this_run` (signed) is reduced by the whole match length.
                remaining_run -= match_length as i64;
            }
        }
        *this_run = remaining_run;
        self.window_posn = wpos;
        Ok(())
    }
    fn run_decompress(&mut self) -> Result<Vec<u8>, LzxError> {
        let out_len = self.length;
        if out_len == 0 {
            return Ok(self.output.clone());
        }
        self.output = vec![0u8; out_len];

        // Number of 32k frames needed to produce the whole output.
        let end_frame = self.offset / LZX_FRAME_SIZE + (out_len / LZX_FRAME_SIZE) + 1;
        let window_size = self.window_size;

        while self.frame < end_frame {
            // (XEX LZX uses reset_interval == 0, so no resets are performed.)

            // Read the single intel header bit (and 32-bit filesize if set).
            if !self.header_read {
                let one = self.bits.read_bits(1)?;
                let h = if one != 0 {
                    (self.bits.read_bits(16)? << 16) | self.bits.read_bits(16)?
                } else {
                    0
                };
                self.intel_filesize = h as i32;
                self.header_read = true;
            }

            // Size of this frame: 32k, except possibly the final one.
            let mut frame_size = LZX_FRAME_SIZE;
            if self.length > 0 && self.length - self.offset < frame_size {
                frame_size = self.length - self.offset;
            }
            if frame_size == 0 {
                break;
            }

            // Decode until one more frame is available.
            let mut bytes_todo = self.frame_posn + frame_size - self.window_posn;

            'frame: loop {
                while bytes_todo > 0 {
                    if self.block_remaining == 0 {
                        self.new_block()?;
                    }

                    let run = self.block_remaining.min(bytes_todo);
                    bytes_todo -= run;
                    self.block_remaining -= run;

                    let mut this_run = run as i64;
                    match self.block_type {
                        LZX_BLOCKTYPE_VERBATIM | LZX_BLOCKTYPE_ALIGNED => {
                            let aligned = self.block_type == LZX_BLOCKTYPE_ALIGNED;
                            self.decode_verbatim_or_aligned(aligned, &mut this_run)?;
                        }
                        LZX_BLOCKTYPE_UNCOMPRESSED => {
                            self.decode_uncompressed(&mut this_run)?;
                        }
                        _ => return Err(LzxError::Decrunched),
                    }

                    // A match may legally overshoot `this_run`; account for it.
                    if this_run < 0 {
                        let over = (-this_run) as usize;
                        if over > self.block_remaining {
                            return Err(LzxError::Decrunched);
                        }
                        self.block_remaining -= over;
                        this_run = 0;
                    }
                }

                // Streams must not extend over frame boundaries.
                if self.window_posn.checked_sub(self.frame_posn) != Some(frame_size) {
                    return Err(LzxError::Decrunched);
                }
                break 'frame;
            }

            // Re-align the input bitstream to the next byte.
            if self.bits.bits_left > 0 {
                self.bits.ensure_bits(16)?;
            }
            if (self.bits.bits_left & 15) != 0 {
                self.bits.remove_bits(self.bits.bits_left & 15);
            }

            // Produce this frame's worth of output (possibly E8-transformed).
            self.emit_frame(frame_size)?;
            self.offset += frame_size;
            self.frame += 1;

            if self.offset >= out_len {
                break;
            }
        }

        if self.offset < out_len {
            return Err(LzxError::Decrunched);
        }
        Ok(std::mem::take(&mut self.output))
    }

    /// Copy raw (uncompressed) bytes straight into the window.
    fn decode_uncompressed(&mut self, this_run: &mut i64) -> Result<(), LzxError> {
        let mut run = *this_run as usize;
        let mut dst = self.window_posn;
        while run > 0 {
            let src = self.bits.i_ptr;
            if src >= self.bits.input.len() {
                if self.bits.eof_padded {
                    return Err(LzxError::Read);
                }
                self.bits.eof_padded = true;
                self.window[dst] = 0;
                self.bits.i_ptr += 1;
                dst += 1;
                run -= 1;
            } else {
                let avail = self.bits.input.len() - src;
                let n = avail.min(run);
                self.window[dst..dst + n].copy_from_slice(&self.bits.input[src..src + n]);
                self.bits.i_ptr += n;
                dst += n;
                run -= n;
            }
        }
        self.window_posn = dst;
        *this_run = 0;
        Ok(())
    }

    /// Copy this frame's bytes into `self.output`, applying the Intel E8
    /// transform when active, and advance the wrap-around window cursors.
    fn emit_frame(&mut self, frame_size: usize) -> Result<(), LzxError> {
        let out_start = self.offset;
        let window_start = self.frame_posn;

        let use_e8 = self.intel_started
            && self.intel_filesize != 0
            && self.frame <= 32768
            && frame_size > 10;

        if use_e8 {
            let e8 = &mut self.e8_buf[..frame_size];
            e8.copy_from_slice(&self.window[window_start..window_start + frame_size]);

            let dataend = frame_size - 10;
            let mut data = 0usize;
            let mut curpos = self.intel_curpos as i64;
            let filesize = self.intel_filesize as i64;

            while data < dataend {
                if e8[data] != 0xE8 {
                    data += 1;
                    curpos += 1;
                    continue;
                }
                data += 1; // now just past the 0xE8 byte
                let aoff = (e8[data] as i64)
                    | ((e8[data + 1] as i64) << 8)
                    | ((e8[data + 2] as i64) << 16)
                    | ((e8[data + 3] as i64) << 24);
                if aoff >= -curpos && aoff < filesize {
                    let rel = if aoff >= 0 { aoff - curpos } else { aoff + filesize };
                    e8[data] = rel as u8;
                    e8[data + 1] = (rel >> 8) as u8;
                    e8[data + 2] = (rel >> 16) as u8;
                    e8[data + 3] = (rel >> 24) as u8;
                }
                data += 4;
                curpos += 5;
            }
            self.intel_curpos += frame_size as i32;
            self.output[out_start..out_start + frame_size].copy_from_slice(&self.e8_buf[..frame_size]);
        } else {
            self.output[out_start..out_start + frame_size]
                .copy_from_slice(&self.window[window_start..window_start + frame_size]);
            if self.intel_filesize != 0 {
                self.intel_curpos += frame_size as i32;
            }
        }

        // Advance within the wrap-around window. The decode phase already
        // positioned `window_posn` at frame_posn + frame_size; adding
        // frame_size AGAIN here would corrupt the ring cursor on multi-frame
        // streams. Only wrap it, and advance the frame cursor.
        if self.window_posn == self.window_size {
            self.window_posn = 0;
        }
        self.frame_posn += frame_size;
        if self.frame_posn == self.window_size {
            self.frame_posn = 0;
        }
        Ok(())
    }
}

/// Copy a match into the window using LZ77 semantics (source and destination
/// may overlap; a match may extend beyond the back-reference distance).
fn copy_match(window: &mut [u8], dst: usize, offset: u32, len: usize) {
    let window_size = window.len();
    if (offset as usize) <= dst {
        // Source lies within the already-written region; overlapping copy.
        let mut s = dst - offset as usize;
        let mut d = dst;
        for _ in 0..len {
            window[d] = window[s];
            d += 1;
            s += 1;
        }
    } else {
        // The match wraps around the ring buffer.
        let j = (offset as usize) - dst; // bytes from dst back to the source
        let mut src = window_size - j;
        let mut i = len;
        if j < i {
            // First chunk wraps around; copy the tail of the window.
            i -= j;
            for k in 0..j {
                window[dst + k] = window[src + k];
            }
            src = 0;
        }
        for k in 0..i {
            window[dst + (len - i) + k] = window[src + k];
        }
    }
}

// ============================================================================
// Bit-level reader (MSB order, as LZX requires)
// ============================================================================
struct BitReader<'a> {
    input: &'a [u8],
    i_ptr: usize,
    bit_buffer: u32,
    bits_left: i32,
    /// Mirrors libmspack's `input_end`: once we fake zero bytes for a read
    /// that runs past end-of-input, a second overrun is an error.
    eof_padded: bool,
}

impl<'a> BitReader<'a> {
    fn new(input: &'a [u8]) -> Self {
        BitReader {
            input,
            i_ptr: 0,
            bit_buffer: 0,
            bits_left: 0,
            eof_padded: false,
        }
    }

    #[inline]
    fn ensure_bits(&mut self, n: i32) -> Result<(), LzxError> {
        while self.bits_left < n {
            self.read_bytes()?;
        }
        Ok(())
    }

    #[inline]
    fn peek_bits(&self, n: i32) -> u32 {
        self.bit_buffer >> (32 - n)
    }

    #[inline]
    fn remove_bits(&mut self, n: i32) {
        self.bit_buffer <<= n;
        self.bits_left -= n;
    }

    #[inline]
    fn read_bits(&mut self, n: i32) -> Result<u32, LzxError> {
        if n <= 0 {
            return Ok(0);
        }
        self.ensure_bits(n)?;
        let v = self.peek_bits(n);
        self.remove_bits(n);
        Ok(v)
    }

    /// Inject up to two bytes into the bit buffer. Past the end of the input
    /// the bytes are faked as zero (exactly as libmspack does); a second
    /// overrun is an error.
    fn read_bytes(&mut self) -> Result<(), LzxError> {
        let (b0, b1) = if self.i_ptr + 2 <= self.input.len() {
            let b0 = self.input[self.i_ptr] as u32;
            let b1 = self.input[self.i_ptr + 1] as u32;
            self.i_ptr += 2;
            (b0, b1)
        } else {
            // Grab whatever trailing real bytes remain, then fake zeros.
            let mut got = 0u32;
            let mut val = 0u32;
            while self.i_ptr < self.input.len() && got < 2 {
                val |= (self.input[self.i_ptr] as u32) << (8 * got);
                got += 1;
                self.i_ptr += 1;
            }
            if got == 2 {
                (val & 0xFF, (val >> 8) & 0xFF)
            } else {
                if self.eof_padded {
                    return Err(LzxError::Read);
                }
                self.eof_padded = true;
                (if got >= 1 { val & 0xFF } else { 0 }, 0)
            }
        };
        self.bit_buffer |= ((b1 << 8) | b0) << (16 - self.bits_left);
        self.bits_left += 16;
        Ok(())
    }

    /// Decode one Huffman symbol from `table` (fast-lookup table built by
    /// [`make_decode_table`]) with code lengths `len`.
    #[inline]
    fn read_huffsym(
        &mut self,
        table: &[u16],
        nsyms: usize,
        tablebits: u32,
        len: &[u8],
    ) -> Result<u16, LzxError> {
        self.ensure_bits(16)?;
        let mut sym = table[self.peek_bits(tablebits as i32) as usize];
        if (sym as usize) >= nsyms {
            // Traverse the long-code extension of the table (MSB variant).
            let mut probe: u32 = 1 << (32 - tablebits);
            loop {
                probe >>= 1;
                if probe == 0 {
                    return Err(LzxError::Decrunched);
                }
                let bit = if (self.bit_buffer & probe) != 0 { 1 } else { 0 };
                sym = table[((sym as usize) << 1) | bit];
                if (sym as usize) < nsyms {
                    break;
                }
            }
        }
        let codelen = len[sym as usize] as i32;
        self.remove_bits(codelen);
        Ok(sym)
    }
}
