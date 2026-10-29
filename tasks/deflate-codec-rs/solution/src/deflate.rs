//! DEFLATE encoder (RFC 1951).
//!
//! Pipeline: LZ77 with hash chains and lazy evaluation produces a token
//! stream (literals and length/distance pairs); every ~32K tokens the block
//! is emitted using whichever of dynamic Huffman, fixed Huffman or stored
//! encoding is smallest. Code lengths are limited to 15 bits (7 for the
//! code-length code) with the same overflow repair zlib uses.

use crate::inflate::{fixed_lengths, CL_ORDER, DIST_BASE, DIST_EXTRA, LEN_BASE, LEN_EXTRA};
use std::cmp::Reverse;
use std::collections::BinaryHeap;

const MIN_MATCH: usize = 3;
const MAX_MATCH: usize = 258;
const WINDOW: usize = 32 * 1024;
const WMASK: usize = WINDOW - 1;
const HASH_BITS: u32 = 16;
const NIL: u32 = u32::MAX;
/// Length-3 matches further back than this cost more than three literals.
const TOO_FAR: usize = 4096;
/// Tokens per block before a Huffman block is emitted.
const BLOCK_TOKENS: usize = 32 * 1024;
const MAX_STORED: usize = 65535;

/// Match-finder tuning, mirroring zlib's configuration table.
#[derive(Clone, Copy)]
struct Config {
    /// Shorten the chain search by 4x once a match at least this long is held.
    good: usize,
    /// Do not search for a better match once one at least this long is held.
    max_lazy: usize,
    /// Stop the chain search at a match at least this long.
    nice: usize,
    /// Maximum hash-chain candidates examined per position.
    chain: u32,
    lazy: bool,
}

fn config(level: u8) -> Config {
    let (good, max_lazy, nice, chain, lazy) = match level {
        1 => (4, 4, 8, 4, false),
        2 => (4, 5, 16, 8, false),
        3 => (4, 6, 32, 32, false),
        4 => (4, 4, 16, 16, true),
        5 => (8, 16, 32, 32, true),
        6 => (8, 16, 128, 128, true),
        7 => (8, 32, 128, 256, true),
        8 => (32, 128, 258, 1024, true),
        _ => (32, 258, 258, 4096, true),
    };
    Config { good, max_lazy, nice, chain, lazy }
}

/// Compress `input` as a raw DEFLATE stream appended to `out`.
pub fn deflate(input: &[u8], level: u8, out: &mut Vec<u8>) {
    let mut w = BitWriter::new(out);
    if level == 0 {
        write_stored(&mut w, input, true);
        w.finish();
        return;
    }
    let tables = SymbolTables::new();
    let mut lz = Lz77::new(input, config(level));
    let mut tokens: Vec<Token> = Vec::with_capacity(BLOCK_TOKENS + 2);
    let mut block_start = 0;
    loop {
        let block_end = lz.fill(&mut tokens, BLOCK_TOKENS);
        let is_last = block_end == input.len();
        write_block(&mut w, &tables, &tokens, &input[block_start..block_end], is_last);
        tokens.clear();
        block_start = block_end;
        if is_last {
            break;
        }
    }
    w.finish();
}

// ---------------------------------------------------------------------------
// LZ77
// ---------------------------------------------------------------------------

/// A literal byte (`len == 0`) or a back-reference.
#[derive(Clone, Copy)]
struct Token {
    len: u16,
    /// Literal byte when `len == 0`, otherwise distance (1..=32768).
    val: u16,
}

impl Token {
    fn literal(b: u8) -> Self {
        Token { len: 0, val: u16::from(b) }
    }
    fn matched(len: usize, dist: usize) -> Self {
        Token { len: len as u16, val: (dist - 1) as u16 }
    }
    fn dist(self) -> usize {
        self.val as usize + 1
    }
}

struct Lz77<'a> {
    input: &'a [u8],
    cfg: Config,
    head: Vec<u32>,
    prev: Vec<u32>,
    pos: usize,
    /// Lazy state: when set, the byte at `pos - 1` is still unemitted and
    /// `prev_len`/`prev_dist` is the best match starting there (0 = none).
    pending: bool,
    prev_len: usize,
    prev_dist: usize,
}

impl<'a> Lz77<'a> {
    fn new(input: &'a [u8], cfg: Config) -> Self {
        Self {
            input,
            cfg,
            head: vec![NIL; 1 << HASH_BITS],
            prev: vec![NIL; WINDOW],
            pos: 0,
            pending: false,
            prev_len: 0,
            prev_dist: 0,
        }
    }

    #[inline]
    fn hash(&self, p: usize) -> usize {
        let v = u32::from(self.input[p])
            | (u32::from(self.input[p + 1]) << 8)
            | (u32::from(self.input[p + 2]) << 16);
        (v.wrapping_mul(0x9E37_79B1) >> (32 - HASH_BITS)) as usize
    }

    /// Record position `p` in the hash chains and return the previous head.
    #[inline]
    fn insert(&mut self, p: usize) -> u32 {
        if p + MIN_MATCH > self.input.len() {
            return NIL;
        }
        let h = self.hash(p);
        let old = self.head[h];
        self.prev[p & WMASK] = old;
        self.head[h] = p as u32;
        old
    }

    /// Longest match for the string at `pos`, walking the chain from `cand`.
    fn longest_match(&self, pos: usize, mut cand: u32, held: usize) -> (usize, usize) {
        let input = self.input;
        let max_len = MAX_MATCH.min(input.len() - pos);
        if max_len < MIN_MATCH {
            return (0, 0);
        }
        let nice = self.cfg.nice.min(max_len);
        let mut chain = self.cfg.chain;
        if held >= self.cfg.good {
            chain >>= 2;
        }
        let mut best_len = MIN_MATCH - 1;
        let mut best_dist = 0;
        let cur = &input[pos..pos + max_len];
        while cand != NIL && chain > 0 {
            let c = cand as usize;
            let dist = pos - c;
            if dist >= WINDOW {
                break;
            }
            // Cheap rejection before the full compare: the byte that would
            // extend the current best must match, as must the first byte.
            if input[c + best_len] == cur[best_len] && input[c] == cur[0] {
                let l = common_prefix(&input[c..c + max_len], cur);
                if l > best_len {
                    best_len = l;
                    best_dist = dist;
                    if l >= nice {
                        break;
                    }
                }
            }
            chain -= 1;
            cand = self.prev[c & WMASK];
        }
        if best_len >= MIN_MATCH {
            (best_len, best_dist)
        } else {
            (0, 0)
        }
    }

    fn find(&mut self, pos: usize, held: usize) -> (usize, usize) {
        let head = self.insert(pos);
        if head == NIL {
            return (0, 0);
        }
        let (len, dist) = self.longest_match(pos, head, held);
        if len == MIN_MATCH && dist > TOO_FAR {
            (0, 0)
        } else {
            (len, dist)
        }
    }

    /// Insert the hashes of a match's remaining positions.
    fn insert_range(&mut self, from: usize, to: usize) {
        for p in from..to {
            self.insert(p);
        }
    }

    /// Append tokens until at least `limit` are buffered or input is exhausted.
    /// Returns the input offset the tokens cover up to.
    fn fill(&mut self, tokens: &mut Vec<Token>, limit: usize) -> usize {
        let n = self.input.len();
        if self.cfg.lazy {
            while tokens.len() < limit {
                if self.pos >= n {
                    if self.pending {
                        tokens.push(Token::literal(self.input[self.pos - 1]));
                        self.pending = false;
                    }
                    return n;
                }
                let pos = self.pos;
                let (cur_len, cur_dist) = if self.pending && self.prev_len >= self.cfg.max_lazy {
                    self.insert(pos);
                    (0, 0)
                } else {
                    self.find(pos, self.prev_len)
                };
                if self.pending && self.prev_len >= MIN_MATCH && cur_len <= self.prev_len {
                    // The match held for pos-1 wins: emit it and skip past it.
                    let end = pos - 1 + self.prev_len;
                    tokens.push(Token::matched(self.prev_len, self.prev_dist));
                    self.insert_range(pos + 1, end);
                    self.pos = end;
                    self.pending = false;
                    self.prev_len = 0;
                } else {
                    if self.pending {
                        tokens.push(Token::literal(self.input[pos - 1]));
                    }
                    self.pending = true;
                    self.prev_len = cur_len;
                    self.prev_dist = cur_dist;
                    self.pos = pos + 1;
                }
            }
            if self.pending {
                self.pos - 1
            } else {
                self.pos
            }
        } else {
            while tokens.len() < limit && self.pos < n {
                let pos = self.pos;
                let (len, dist) = self.find(pos, 0);
                if len >= MIN_MATCH {
                    tokens.push(Token::matched(len, dist));
                    self.insert_range(pos + 1, pos + len);
                    self.pos = pos + len;
                } else {
                    tokens.push(Token::literal(self.input[pos]));
                    self.pos = pos + 1;
                }
            }
            self.pos
        }
    }
}

/// Length of the common prefix of two equal-length slices, 8 bytes at a time.
#[inline]
fn common_prefix(a: &[u8], b: &[u8]) -> usize {
    let n = a.len().min(b.len());
    let mut i = 0;
    while i + 8 <= n {
        let x = u64::from_le_bytes(a[i..i + 8].try_into().unwrap());
        let y = u64::from_le_bytes(b[i..i + 8].try_into().unwrap());
        if x != y {
            return i + ((x ^ y).trailing_zeros() / 8) as usize;
        }
        i += 8;
    }
    while i < n && a[i] == b[i] {
        i += 1;
    }
    i
}

// ---------------------------------------------------------------------------
// Bit output
// ---------------------------------------------------------------------------

struct BitWriter<'a> {
    out: &'a mut Vec<u8>,
    buf: u64,
    cnt: u32,
}

impl<'a> BitWriter<'a> {
    fn new(out: &'a mut Vec<u8>) -> Self {
        Self { out, buf: 0, cnt: 0 }
    }

    /// Write the low `n` (<= 32) bits of `v`, least significant bit first.
    #[inline]
    fn bits(&mut self, v: u32, n: u32) {
        self.buf |= u64::from(v) << self.cnt;
        self.cnt += n;
        while self.cnt >= 8 {
            self.out.push(self.buf as u8);
            self.buf >>= 8;
            self.cnt -= 8;
        }
    }

    /// Write a Huffman code: `code` is stored bit-reversed so the MSB-first
    /// code lands in LSB-first order.
    #[inline]
    fn code(&mut self, c: Code) {
        self.bits(u32::from(c.bits), u32::from(c.len));
    }

    fn align(&mut self) {
        if self.cnt > 0 {
            self.out.push(self.buf as u8);
            self.buf = 0;
            self.cnt = 0;
        }
    }

    fn finish(&mut self) {
        self.align();
    }
}

// ---------------------------------------------------------------------------
// Huffman code construction
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Default)]
struct Code {
    /// Bit-reversed canonical code.
    bits: u16,
    len: u8,
}

/// Build length-limited Huffman code lengths for `freq`.
///
/// At least two symbols always receive a code: DEFLATE needs at least one
/// distance code, and a lone code of length zero would be unrepresentable.
fn build_lengths(freq: &[u32], max_bits: usize) -> Vec<u8> {
    let n = freq.len();
    let mut leaves: Vec<usize> = (0..n).filter(|&i| freq[i] > 0).collect();
    let mut i = 0;
    while leaves.len() < 2 {
        if freq[i] == 0 {
            leaves.push(i);
        }
        i += 1;
    }
    // Standard Huffman tree over the leaves; ties broken by depth so the tree
    // stays as shallow as possible.
    let total = 2 * leaves.len() - 1;
    let mut parent = vec![usize::MAX; total];
    let mut depth = vec![0u32; total];
    let mut heap: BinaryHeap<Reverse<(u64, u32, usize)>> = BinaryHeap::new();
    for (node, &sym) in leaves.iter().enumerate() {
        heap.push(Reverse((u64::from(freq[sym]), 0, node)));
    }
    let mut next = leaves.len();
    while heap.len() > 1 {
        let Reverse((f1, d1, a)) = heap.pop().unwrap();
        let Reverse((f2, d2, b)) = heap.pop().unwrap();
        parent[a] = next;
        parent[b] = next;
        depth[next] = d1.max(d2) + 1;
        heap.push(Reverse((f1 + f2, depth[next], next)));
        next += 1;
    }
    let root = next - 1;

    let mut bl_count = vec![0u32; max_bits + 2];
    let mut lengths = vec![0u8; n];
    let mut overflow: i64 = 0;
    let mut leaf_len = vec![0usize; leaves.len()];
    for node in 0..leaves.len() {
        let mut l = 0;
        let mut p = node;
        while p != root {
            p = parent[p];
            l += 1;
        }
        if l > max_bits {
            l = max_bits;
            overflow += 1;
        }
        leaf_len[node] = l;
        bl_count[l] += 1;
    }
    if overflow > 0 {
        // zlib's repair: repeatedly move one code from the deepest non-full
        // level down one step, which frees room for an overflowing leaf.
        loop {
            let mut bits = max_bits - 1;
            while bl_count[bits] == 0 {
                bits -= 1;
            }
            bl_count[bits] -= 1;
            bl_count[bits + 1] += 2;
            bl_count[max_bits] -= 1;
            overflow -= 2;
            if overflow <= 0 {
                break;
            }
        }
        // Reassign lengths: least frequent symbols get the longest codes.
        let mut order: Vec<usize> = (0..leaves.len()).collect();
        order.sort_by_key(|&node| (freq[leaves[node]], Reverse(leaf_len[node])));
        let mut idx = 0;
        for bits in (1..=max_bits).rev() {
            for _ in 0..bl_count[bits] {
                leaf_len[order[idx]] = bits;
                idx += 1;
            }
        }
    }
    for (node, &sym) in leaves.iter().enumerate() {
        lengths[sym] = leaf_len[node] as u8;
    }
    lengths
}

/// Canonical codes from code lengths (RFC 1951 3.2.2), stored bit-reversed.
fn canonical_codes(lengths: &[u8]) -> Vec<Code> {
    let mut bl_count = [0u32; 16];
    for &l in lengths {
        bl_count[l as usize] += 1;
    }
    bl_count[0] = 0;
    let mut next_code = [0u32; 16];
    let mut code = 0u32;
    for bits in 1..16 {
        code = (code + bl_count[bits - 1]) << 1;
        next_code[bits] = code;
    }
    lengths
        .iter()
        .map(|&l| {
            if l == 0 {
                return Code::default();
            }
            let c = next_code[l as usize];
            next_code[l as usize] += 1;
            let mut rev = 0u32;
            let mut v = c;
            for _ in 0..l {
                rev = (rev << 1) | (v & 1);
                v >>= 1;
            }
            Code { bits: rev as u16, len: l }
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Block encoding
// ---------------------------------------------------------------------------

/// Lookup tables from match length / distance to symbol index.
struct SymbolTables {
    /// Indexed by length - 3.
    len_sym: [u8; 256],
    /// Indexed by distance - 1.
    dist_sym: Vec<u8>,
}

impl SymbolTables {
    fn new() -> Self {
        let mut len_sym = [0u8; 256];
        for (s, (&base, &extra)) in LEN_BASE.iter().zip(LEN_EXTRA.iter()).enumerate() {
            let base = base as usize;
            for l in base..base + (1 << extra) {
                if l <= MAX_MATCH {
                    len_sym[l - MIN_MATCH] = s as u8;
                }
            }
        }
        let mut dist_sym = vec![0u8; WINDOW];
        for (s, (&base, &extra)) in DIST_BASE.iter().zip(DIST_EXTRA.iter()).enumerate() {
            let base = base as usize;
            for d in base..base + (1 << extra) {
                if d <= WINDOW {
                    dist_sym[d - 1] = s as u8;
                }
            }
        }
        Self { len_sym, dist_sym }
    }
}

/// One entry of the run-length-encoded code-length sequence.
#[derive(Clone, Copy)]
struct ClItem {
    sym: u8,
    extra: u8,
    extra_bits: u8,
}

/// RFC 1951 3.2.7 run-length encoding of the combined lit/len + dist lengths.
fn rle_code_lengths(seq: &[u8]) -> Vec<ClItem> {
    let mut items = Vec::with_capacity(seq.len());
    let mut i = 0;
    while i < seq.len() {
        let l = seq[i];
        let mut run = 1;
        while i + run < seq.len() && seq[i + run] == l {
            run += 1;
        }
        if l == 0 {
            let mut r = run;
            while r >= 11 {
                let k = r.min(138);
                items.push(ClItem { sym: 18, extra: (k - 11) as u8, extra_bits: 7 });
                r -= k;
            }
            if r >= 3 {
                items.push(ClItem { sym: 17, extra: (r - 3) as u8, extra_bits: 3 });
                r = 0;
            }
            for _ in 0..r {
                items.push(ClItem { sym: 0, extra: 0, extra_bits: 0 });
            }
        } else {
            items.push(ClItem { sym: l, extra: 0, extra_bits: 0 });
            let mut r = run - 1;
            while r >= 3 {
                let k = r.min(6);
                items.push(ClItem { sym: 16, extra: (k - 3) as u8, extra_bits: 2 });
                r -= k;
            }
            for _ in 0..r {
                items.push(ClItem { sym: l, extra: 0, extra_bits: 0 });
            }
        }
        i += run;
    }
    items
}

struct DynamicPlan {
    lit_len: Vec<u8>,
    dist_len: Vec<u8>,
    cl_len: Vec<u8>,
    items: Vec<ClItem>,
    hlit: usize,
    hdist: usize,
    hclen: usize,
    header_bits: u64,
}

fn plan_dynamic(lit_freq: &[u32; 286], dist_freq: &[u32; 30]) -> DynamicPlan {
    let lit_len = build_lengths(lit_freq, 15);
    let dist_len = build_lengths(dist_freq, 15);
    let hlit = (lit_len.iter().rposition(|&l| l != 0).unwrap() + 1).max(257);
    let hdist = (dist_len.iter().rposition(|&l| l != 0).unwrap() + 1).max(1);
    let mut seq = Vec::with_capacity(hlit + hdist);
    seq.extend_from_slice(&lit_len[..hlit]);
    seq.extend_from_slice(&dist_len[..hdist]);
    let items = rle_code_lengths(&seq);
    let mut cl_freq = [0u32; 19];
    for it in &items {
        cl_freq[it.sym as usize] += 1;
    }
    let cl_len = build_lengths(&cl_freq, 7);
    let hclen = (CL_ORDER.iter().rposition(|&s| cl_len[s] != 0).unwrap() + 1).max(4);
    let mut header_bits = 3 + 5 + 5 + 4 + 3 * hclen as u64;
    for it in &items {
        header_bits += u64::from(cl_len[it.sym as usize]) + u64::from(it.extra_bits);
    }
    DynamicPlan { lit_len, dist_len, cl_len, items, hlit, hdist, hclen, header_bits }
}

/// Bits needed to code the block body with the given lengths.
fn body_bits(lit_freq: &[u32; 286], dist_freq: &[u32; 30], lit_len: &[u8], dist_len: &[u8]) -> u64 {
    let mut bits = 0u64;
    for (s, &f) in lit_freq.iter().enumerate() {
        if f == 0 {
            continue;
        }
        let extra = if s >= 257 { LEN_EXTRA[s - 257] } else { 0 };
        bits += u64::from(f) * (u64::from(lit_len[s]) + u64::from(extra));
    }
    for (s, &f) in dist_freq.iter().enumerate() {
        if f == 0 {
            continue;
        }
        bits += u64::from(f) * (u64::from(dist_len[s]) + u64::from(DIST_EXTRA[s]));
    }
    bits
}

fn write_block(w: &mut BitWriter, t: &SymbolTables, tokens: &[Token], raw: &[u8], is_last: bool) {
    let mut lit_freq = [0u32; 286];
    let mut dist_freq = [0u32; 30];
    for tok in tokens {
        if tok.len == 0 {
            lit_freq[tok.val as usize] += 1;
        } else {
            lit_freq[257 + t.len_sym[tok.len as usize - MIN_MATCH] as usize] += 1;
            dist_freq[t.dist_sym[tok.val as usize] as usize] += 1;
        }
    }
    lit_freq[256] += 1;

    let plan = plan_dynamic(&lit_freq, &dist_freq);
    let dynamic_bits = plan.header_bits + body_bits(&lit_freq, &dist_freq, &plan.lit_len, &plan.dist_len);
    let (fixed_lit, fixed_dist) = fixed_lengths();
    let fixed_bits = 3 + body_bits(&lit_freq, &dist_freq, &fixed_lit, &fixed_dist);
    let chunks = raw.len().div_ceil(MAX_STORED).max(1) as u64;
    let stored_bits = 8 * raw.len() as u64 + 40 * chunks;

    if stored_bits <= dynamic_bits && stored_bits <= fixed_bits {
        write_stored(w, raw, is_last);
        return;
    }
    let (lit_codes, dist_codes) = if fixed_bits <= dynamic_bits {
        w.bits(u32::from(is_last), 1);
        w.bits(1, 2);
        (canonical_codes(&fixed_lit), canonical_codes(&fixed_dist))
    } else {
        w.bits(u32::from(is_last), 1);
        w.bits(2, 2);
        w.bits((plan.hlit - 257) as u32, 5);
        w.bits((plan.hdist - 1) as u32, 5);
        w.bits((plan.hclen - 4) as u32, 4);
        for &s in CL_ORDER.iter().take(plan.hclen) {
            w.bits(u32::from(plan.cl_len[s]), 3);
        }
        let cl_codes = canonical_codes(&plan.cl_len);
        for it in &plan.items {
            w.code(cl_codes[it.sym as usize]);
            if it.extra_bits > 0 {
                w.bits(u32::from(it.extra), u32::from(it.extra_bits));
            }
        }
        (canonical_codes(&plan.lit_len), canonical_codes(&plan.dist_len))
    };
    for tok in tokens {
        if tok.len == 0 {
            w.code(lit_codes[tok.val as usize]);
        } else {
            let len = tok.len as usize;
            let ls = t.len_sym[len - MIN_MATCH] as usize;
            w.code(lit_codes[257 + ls]);
            if LEN_EXTRA[ls] > 0 {
                w.bits((len - LEN_BASE[ls] as usize) as u32, u32::from(LEN_EXTRA[ls]));
            }
            let dist = tok.dist();
            let ds = t.dist_sym[dist - 1] as usize;
            w.code(dist_codes[ds]);
            if DIST_EXTRA[ds] > 0 {
                w.bits((dist - DIST_BASE[ds] as usize) as u32, u32::from(DIST_EXTRA[ds]));
            }
        }
    }
    w.code(lit_codes[256]);
}

/// Emit `raw` as one or more stored blocks (65535 bytes max each).
fn write_stored(w: &mut BitWriter, raw: &[u8], is_last: bool) {
    let mut chunks: Vec<&[u8]> = raw.chunks(MAX_STORED).collect();
    if chunks.is_empty() {
        chunks.push(&[]);
    }
    let count = chunks.len();
    for (i, chunk) in chunks.into_iter().enumerate() {
        let final_bit = is_last && i + 1 == count;
        w.bits(u32::from(final_bit), 1);
        w.bits(0, 2);
        w.align();
        let len = chunk.len() as u32;
        w.bits(len, 16);
        w.bits(!len & 0xFFFF, 16);
        w.out.extend_from_slice(chunk);
    }
}
