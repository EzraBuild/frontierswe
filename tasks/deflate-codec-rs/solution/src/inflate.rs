//! DEFLATE decoder (RFC 1951).
//!
//! The decoder reads the whole compressed stream from a byte slice and returns
//! the decompressed bytes together with the number of input bytes consumed, so
//! container formats can locate their trailers.
//!
//! Huffman decoding uses one flat lookup table per code indexed by the next
//! `max_len` bits of input (bit-reversed, because DEFLATE packs Huffman codes
//! most-significant-bit first into a least-significant-bit-first stream).

use std::fmt;
use std::sync::OnceLock;

/// Order in which the code-length code lengths are transmitted (RFC 1951 3.2.7).
pub const CL_ORDER: [usize; 19] = [16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15];

pub const LEN_BASE: [u16; 29] = [
    3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131,
    163, 195, 227, 258,
];
pub const LEN_EXTRA: [u8; 29] = [
    0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0,
];
pub const DIST_BASE: [u16; 30] = [
    1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537,
    2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577,
];
pub const DIST_EXTRA: [u8; 30] = [
    0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13,
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InflateError {
    Truncated,
    BadBlockType,
    BadStoredLength,
    BadCodeLengths(&'static str),
    OversubscribedCode,
    BadSymbol,
    DistanceTooFar,
}

impl fmt::Display for InflateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated => write!(f, "unexpected end of compressed data"),
            Self::BadBlockType => write!(f, "invalid block type"),
            Self::BadStoredLength => write!(f, "stored block length check failed"),
            Self::BadCodeLengths(why) => write!(f, "invalid code lengths: {why}"),
            Self::OversubscribedCode => write!(f, "over-subscribed Huffman code"),
            Self::BadSymbol => write!(f, "invalid Huffman code or symbol"),
            Self::DistanceTooFar => write!(f, "match distance reaches before start of output"),
        }
    }
}

impl std::error::Error for InflateError {}

/// Result of a successful inflate: the output and how many input bytes were used.
pub struct Inflated {
    pub data: Vec<u8>,
    pub consumed: usize,
}

struct BitReader<'a> {
    data: &'a [u8],
    pos: usize,
    buf: u64,
    cnt: u32,
}

impl<'a> BitReader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0, buf: 0, cnt: 0 }
    }

    #[inline]
    fn refill(&mut self) {
        while self.cnt <= 56 && self.pos < self.data.len() {
            self.buf |= u64::from(self.data[self.pos]) << self.cnt;
            self.pos += 1;
            self.cnt += 8;
        }
    }

    /// Consume `n` (<= 32) bits.
    #[inline]
    fn bits(&mut self, n: u32) -> Result<u32, InflateError> {
        if self.cnt < n {
            self.refill();
            if self.cnt < n {
                return Err(InflateError::Truncated);
            }
        }
        let v = (self.buf & ((1u64 << n) - 1)) as u32;
        self.buf >>= n;
        self.cnt -= n;
        Ok(v)
    }

    /// Look at the next `n` bits without consuming them. Near the end of the
    /// input fewer bits may exist; the missing ones read as zero and the
    /// number actually available is returned alongside.
    #[inline]
    fn peek(&mut self, n: u32) -> (u32, u32) {
        if self.cnt < n {
            self.refill();
        }
        ((self.buf & ((1u64 << n) - 1)) as u32, self.cnt.min(n))
    }

    #[inline]
    fn consume(&mut self, n: u32) {
        self.buf >>= n;
        self.cnt -= n;
    }

    fn align_to_byte(&mut self) {
        self.consume(self.cnt % 8);
    }

    /// Index of the next unread byte. Only meaningful when byte aligned.
    fn byte_pos(&self) -> usize {
        self.pos - (self.cnt / 8) as usize
    }
}

/// A canonical Huffman code turned into a direct lookup table.
struct Huffman {
    /// Indexed by the next `max_len` input bits; entry = symbol << 4 | length.
    table: Vec<u32>,
    max_len: u32,
}

impl Huffman {
    fn new(lengths: &[u8]) -> Result<Self, InflateError> {
        let mut bl_count = [0u32; 16];
        for &l in lengths {
            if l > 15 {
                return Err(InflateError::BadCodeLengths("length > 15"));
            }
            bl_count[l as usize] += 1;
        }
        bl_count[0] = 0;
        let max_len = (1..16).rev().find(|&l| bl_count[l] > 0).unwrap_or(0) as u32;
        if max_len == 0 {
            // No codes at all. Decoding any symbol from this table is an error,
            // which is the right behaviour for e.g. an unused distance tree.
            return Ok(Self { table: Vec::new(), max_len: 0 });
        }
        // Reject over-subscribed codes (Kraft sum > 1). Incomplete codes are
        // tolerated: their unused table slots stay zero and fail at decode time.
        let mut left: i64 = 1;
        for l in 1..16 {
            left = (left << 1) - i64::from(bl_count[l]);
            if left < 0 {
                return Err(InflateError::OversubscribedCode);
            }
        }
        let mut next_code = [0u32; 16];
        let mut code = 0u32;
        for l in 1..16 {
            code = (code + bl_count[l - 1]) << 1;
            next_code[l] = code;
        }
        let size = 1usize << max_len;
        let mut table = vec![0u32; size];
        for (sym, &l) in lengths.iter().enumerate() {
            if l == 0 {
                continue;
            }
            let l = l as usize;
            let code = next_code[l];
            next_code[l] += 1;
            let entry = ((sym as u32) << 4) | l as u32;
            let mut i = reverse_bits(code, l as u32) as usize;
            while i < size {
                table[i] = entry;
                i += 1 << l;
            }
        }
        Ok(Self { table, max_len })
    }

    #[inline]
    fn decode(&self, br: &mut BitReader) -> Result<u32, InflateError> {
        if self.max_len == 0 {
            return Err(InflateError::BadSymbol);
        }
        let (bits, avail) = br.peek(self.max_len);
        let entry = self.table[bits as usize];
        let len = entry & 0xF;
        if len == 0 {
            return Err(InflateError::BadSymbol);
        }
        if len > avail {
            return Err(InflateError::Truncated);
        }
        br.consume(len);
        Ok(entry >> 4)
    }
}

fn reverse_bits(mut code: u32, len: u32) -> u32 {
    let mut rev = 0;
    for _ in 0..len {
        rev = (rev << 1) | (code & 1);
        code >>= 1;
    }
    rev
}

/// The fixed literal/length and distance code lengths of RFC 1951 3.2.6.
pub fn fixed_lengths() -> (Vec<u8>, Vec<u8>) {
    let mut lit = vec![8u8; 288];
    lit[144..256].fill(9);
    lit[256..280].fill(7);
    (lit, vec![5u8; 32])
}

fn fixed_tables() -> &'static (Huffman, Huffman) {
    static TABLES: OnceLock<(Huffman, Huffman)> = OnceLock::new();
    TABLES.get_or_init(|| {
        let (lit, dist) = fixed_lengths();
        (Huffman::new(&lit).unwrap(), Huffman::new(&dist).unwrap())
    })
}

/// Decompress a raw DEFLATE stream.
pub fn inflate(input: &[u8]) -> Result<Inflated, InflateError> {
    let mut br = BitReader::new(input);
    let mut out: Vec<u8> = Vec::with_capacity(input.len().saturating_mul(3));
    loop {
        let bfinal = br.bits(1)?;
        match br.bits(2)? {
            0 => stored_block(&mut br, &mut out)?,
            1 => {
                let (lit, dist) = fixed_tables();
                huffman_block(&mut br, &mut out, lit, dist)?
            }
            2 => {
                let (lit, dist) = read_dynamic_tables(&mut br)?;
                huffman_block(&mut br, &mut out, &lit, &dist)?
            }
            _ => return Err(InflateError::BadBlockType),
        }
        if bfinal == 1 {
            break;
        }
    }
    br.align_to_byte();
    Ok(Inflated { data: out, consumed: br.byte_pos() })
}

fn stored_block(br: &mut BitReader, out: &mut Vec<u8>) -> Result<(), InflateError> {
    br.align_to_byte();
    let len = br.bits(16)? as usize;
    let nlen = br.bits(16)? as usize;
    if len != (!nlen & 0xFFFF) {
        return Err(InflateError::BadStoredLength);
    }
    // Drop the bit buffer and copy straight from the input slice.
    let start = br.byte_pos();
    br.buf = 0;
    br.cnt = 0;
    let end = start.checked_add(len).ok_or(InflateError::Truncated)?;
    if end > br.data.len() {
        return Err(InflateError::Truncated);
    }
    out.extend_from_slice(&br.data[start..end]);
    br.pos = end;
    Ok(())
}

fn read_dynamic_tables(br: &mut BitReader) -> Result<(Huffman, Huffman), InflateError> {
    let hlit = br.bits(5)? as usize + 257;
    let hdist = br.bits(5)? as usize + 1;
    let hclen = br.bits(4)? as usize + 4;
    if hlit > 286 || hdist > 30 {
        return Err(InflateError::BadCodeLengths("too many codes"));
    }
    let mut cl_lengths = [0u8; 19];
    for &idx in CL_ORDER.iter().take(hclen) {
        cl_lengths[idx] = br.bits(3)? as u8;
    }
    let cl = Huffman::new(&cl_lengths)?;

    let total = hlit + hdist;
    let mut lengths = vec![0u8; total];
    let mut i = 0;
    while i < total {
        let sym = cl.decode(br)?;
        let (value, repeat) = match sym {
            0..=15 => (sym as u8, 1),
            16 => {
                if i == 0 {
                    return Err(InflateError::BadCodeLengths("repeat with no previous length"));
                }
                (lengths[i - 1], 3 + br.bits(2)? as usize)
            }
            17 => (0, 3 + br.bits(3)? as usize),
            _ => (0, 11 + br.bits(7)? as usize),
        };
        if i + repeat > total {
            return Err(InflateError::BadCodeLengths("repeat runs past end"));
        }
        lengths[i..i + repeat].fill(value);
        i += repeat;
    }
    if lengths[256] == 0 {
        return Err(InflateError::BadCodeLengths("missing end-of-block code"));
    }
    Ok((Huffman::new(&lengths[..hlit])?, Huffman::new(&lengths[hlit..])?))
}

fn huffman_block(
    br: &mut BitReader,
    out: &mut Vec<u8>,
    lit: &Huffman,
    dist: &Huffman,
) -> Result<(), InflateError> {
    loop {
        let sym = lit.decode(br)?;
        if sym < 256 {
            out.push(sym as u8);
            continue;
        }
        if sym == 256 {
            return Ok(());
        }
        let li = (sym - 257) as usize;
        if li >= 29 {
            return Err(InflateError::BadSymbol);
        }
        let len = LEN_BASE[li] as usize + br.bits(u32::from(LEN_EXTRA[li]))? as usize;
        let di = dist.decode(br)? as usize;
        if di >= 30 {
            return Err(InflateError::BadSymbol);
        }
        let d = DIST_BASE[di] as usize + br.bits(u32::from(DIST_EXTRA[di]))? as usize;
        if d > out.len() {
            return Err(InflateError::DistanceTooFar);
        }
        let start = out.len() - d;
        if d >= len {
            out.extend_from_within(start..start + len);
        } else {
            // Overlapping copy: the classic run-length trick, byte by byte.
            for k in 0..len {
                let b = out[start + k];
                out.push(b);
            }
        }
    }
}
