# deflate-codec-rs

FrontierSWE-style long-horizon task: reimplement DEFLATE (RFC 1951) plus the
zlib and gzip containers in Rust with no dependencies, interoperate with the
real zlib in both directions, and get within 3% of zlib's level-6 ratio.

## Layout

```
instruction.md            agent-facing task statement (contract, rules, scoring formula)
task.toml                 Harbor config: 20h agent budget, no network, verifier env (DZ_SEED)
environment/Dockerfile    rust:1.91-slim-bookworm + python3, non-root `agent` user
environment/workspace/    what the agent sees at /app: skeleton crate, README, 6 sample files
tests/test.sh             verifier entry point (hidden from the agent, uploaded after the agent phase)
tests/verify.py           all grading logic
solution/solve.sh         reference solution: copies solution/src into the crate and builds it
solution/src/             reference codec (inflate.rs, deflate.rs, checksum.rs, main.rs)
```

## Why this is hard

- Full RFC 1951 conformance has many edge cases that a quick implementation
  misses: empty stored blocks from flushes, 258-byte matches, matches at the
  exact edge of the 32 KiB window, incomplete and over-subscribed code sets,
  the `16` repeat code at the start of a length table, FHCRC gzip headers,
  multi-member gzip files.
- Matching zlib's ratio within 3% needs real engineering: hash chains with
  lazy evaluation, dynamic Huffman trees with length-limited code
  construction, correct code-length RLE, sensible block splitting and a
  stored-block fallback. A naive greedy LZ77 with fixed Huffman codes lands
  around R = 1.15 to 1.25 and earns only partial ratio credit.
- The throughput gate rules out quadratic match finders and bit-at-a-time
  Huffman decoding on the 16 MiB input.
- The agent must do all this offline, with only the Rust standard library and
  the spec in its head: there is no crate to vendor and no zlib to call.

## What the verifier does

1. Static rules: no dependencies, no build script, no FFI/`#[link]`/`dlopen`,
   no process spawning, no includes from outside `src/`, no `.cargo` config
   that could inject linker flags. Violations score 0.
2. Fresh `cargo build --release --offline` of `/app/dz` in a root-owned
   scratch directory with a fresh `CARGO_HOME`, and an `ldd` check that the
   binary does not link `libz`.
3. Builds a 42-item, ~34 MiB corpus deterministically from `DZ_SEED` in
   memory. Nothing from the corpus exists in the image.
4. Inflate correctness (0.30): 8 reference streams per item (zlib levels
   0/1/6/9, raw, gzip, sync-flush, full-flush) + 4 hand-built streams + 11
   malformed streams that must be rejected.
5. Deflate interoperability (0.25): 5 encodings per item decoded by Python's
   zlib; gzip header fields checked.
6. Ratio (0.35): R = total `dz zlib -l 6` bytes / total zlib-6 bytes. Linear
   from full credit at R <= 1.03 to zero at R >= 1.35; multiplied by
   min(inflate, interop) so lossy output gets no ratio credit.
7. Throughput (0.10): 16 MiB compress <= 20 s, decompress <= 8 s.

Every invocation has a timeout and the verifier has a global soft deadline,
so a hanging binary scores what it has earned so far instead of erroring.
Reward goes to `/logs/verifier/reward.txt` (4 decimals) with a breakdown in
`reward.json` and every case in `evidence.json`.

The verifier runs in the agent's container after the agent phase (Harbor's
shared mode). It uses absolute paths, its own PATH and a fresh CARGO_HOME, and
rebuilds from source, so agent-left state in `target/`, `PATH` or
`/usr/local/cargo/config.toml` does not affect grading.

## Reference solution

`solution/src` is a from-scratch codec written for this task:

- `inflate.rs`: table-driven canonical Huffman decoding (one flat table per
  code sized to its longest code), stored/fixed/dynamic blocks, strict
  validation (over-subscribed sets, bad stored lengths, distance checks,
  truncation detection down to the last bit).
- `deflate.rs`: LZ77 with 64K-bucket hash chains, lazy matching, zlib's
  per-level tuning table, 32K-token blocks, dynamic trees via Huffman +
  zlib-style length-limit repair, RFC code-length RLE, and per-block choice
  between dynamic, fixed and stored encodings.
- `main.rs`: CLI plus the zlib and gzip containers (FEXTRA/FNAME/FCOMMENT/
  FHCRC parsing, multi-member gzip, zero-padding tolerance).

Measured on the hidden corpus: R = 1.011, 16 MiB compress ~1.1 s,
decompress ~0.3 s, all correctness cases pass, reward 1.0000.

## Running

```
harbor run -p tasks/deflate-codec-rs -a oracle   # expect Mean: 1.000
harbor run -p tasks/deflate-codec-rs -a nop      # expect Mean: 0.000
```

A no-op agent scores 0 because the skeleton binary exits 2 on every command,
so every correctness case fails and the ratio and throughput parts are gated
to zero.
