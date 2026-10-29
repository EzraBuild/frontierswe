# Implement a DEFLATE, zlib and gzip codec in Rust with no dependencies

The Cargo project at `/app/dz` builds a command-line tool called `dz`. Right
now it only parses its arguments; every command exits with status 2 and the
message "unimplemented". Your job is to turn it into a complete, correct and
competitive implementation of DEFLATE (RFC 1951) together with the zlib
(RFC 1950) and gzip (RFC 1952) container formats.

The crate must build with `cargo build --release --offline` using the installed
stable toolchain and nothing but the Rust standard library. The grader builds it
offline against an empty crate registry, so any external dependency will fail the
build and score zero. Treat the toolchain as the only thing you have.

## Command-line contract

`dz <command> [-l LEVEL]` reads all of standard input and writes the result to
standard output. On malformed input it must exit with a non-zero status and
print a short message to standard error.

| command   | input                     | output                                    |
|-----------|---------------------------|-------------------------------------------|
| `deflate` | raw bytes                 | raw DEFLATE stream (RFC 1951)             |
| `inflate` | raw DEFLATE stream        | raw bytes                                 |
| `zlib`    | raw bytes                 | zlib stream (RFC 1950)                    |
| `unzlib`  | zlib stream               | raw bytes, Adler-32 verified              |
| `gzip`    | raw bytes                 | gzip member (RFC 1952)                    |
| `gunzip`  | one or more gzip members  | raw bytes, CRC-32 and ISIZE verified      |

`-l LEVEL` (0 to 9, default 6) is accepted by the three compressors. Level 0
must produce stored blocks only. Other levels are yours to tune, but level 6
is the one that is measured for compression ratio and speed.

Decoder requirements:

- `inflate` must handle stored, fixed-Huffman and dynamic-Huffman blocks,
  including empty stored blocks produced by sync/full flushes, matches that
  reach back the full 32 KiB window, and the maximum match length of 258.
- `unzlib` must validate the header check bits and the Adler-32 trailer, and
  must reject streams that request a preset dictionary.
- `gunzip` must parse every optional header field (FEXTRA, FNAME, FCOMMENT,
  FHCRC), verify CRC-32 and ISIZE, and concatenate the output of multiple
  members in one input.
- Truncated input, invalid block types, over-subscribed or otherwise invalid
  code-length sets, and back-references before the start of the output must
  all be rejected with a non-zero exit status.

Encoder requirements:

- Output must be decodable by any conforming decoder. The grader uses the
  zlib library bundled with Python as the reference.
- `gzip` must emit a header with no optional fields, MTIME 0 and OS 3 (Unix).
- The `zlib` header must carry a valid FCHECK and no FDICT flag.

## Rules

Your crate is rebuilt from `/app/dz/Cargo.toml` and `/app/dz/src` by the
grader, so put everything there. The following cause a score of zero:

- any entry under `[dependencies]`, `[dev-dependencies]`,
  `[build-dependencies]` or a target-specific dependency table;
- a `build.rs`, a `package.build` key, a `rust-toolchain` file, or a `.cargo`
  directory under `/app`;
- `extern "C"` or other foreign-function declarations, `#[link]`, `dlopen`, or
  any reference to `libz`;
- spawning other processes (`std::process::Command`);
- `include_bytes!` / `include_str!` of paths outside `src/`.

`unsafe` Rust is allowed. The built binary must not link against `libz`.

## Scoring

The score is a number between 0 and 1 made of four parts:

- **Inflate correctness, weight 0.30.** A hidden corpus of about forty inputs
  (empty, single bytes, long runs, random data, English-like text,
  structured text, periodic patterns with periods from 1 to 300, matches
  crossing the window boundary, 258-byte matches, inputs over 65535 bytes, a
  16 MiB mixed file, and more) is compressed by the reference zlib at levels
  0, 1, 6 and 9, as raw deflate, as gzip, and with sync-flush and full-flush
  boundaries every 7 KiB. Each stream must decode byte-for-byte. Hand-built
  fixed-Huffman, multi-member gzip and optional-header gzip streams are added,
  as are eleven malformed streams that must be rejected. The part score is the
  fraction of cases passed, except that credit for rejecting malformed
  streams is scaled by your pass rate on the valid streams, so a decoder that
  rejects everything earns nothing.
- **Deflate interoperability, weight 0.25.** For every corpus item, your
  `zlib` output at levels 0, 6 and 9, `deflate` output at level 6 and `gzip`
  output at level 6 must decode with the reference zlib to the original. The
  part score is the fraction of cases passed.
- **Compression ratio, weight 0.35.** R is the total size of your `zlib -l 6`
  output over the corpus (items of two bytes or more) divided by the total
  size of the reference zlib at level 6. The part score is 1.0 when
  R <= 1.03, 0.0 when R >= 1.35, and linear in between. This part is then
  multiplied by the smaller of the two correctness part scores, so a codec
  that is not lossless earns no ratio credit.
- **Throughput, weight 0.10.** Half credit if `zlib -l 6` on the 16 MiB item
  finishes within 20 seconds, half credit if `unzlib` of the reference
  compression of that item finishes within 8 seconds.

Invocations are run with a time limit; a hang counts as a failure for that
case. The sample files under `/app/samples` are only there to help you test by
hand and are not part of the corpus.
