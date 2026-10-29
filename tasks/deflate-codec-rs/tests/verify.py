#!/usr/bin/env python3
"""Verifier for deflate-codec-rs.

Rebuilds the agent's crate from source, then grades the resulting `dz` binary
against Python's bundled zlib/gzip on a corpus generated in-process from
DZ_SEED. Nothing in this file is visible to the agent while it works.

Reward = 0.30 * inflate + 0.25 * interop + 0.35 * ratio + 0.10 * speed
with ratio multiplied by min(inflate, interop) so a lossy codec earns no
ratio credit. Any static-rule violation or build failure scores 0.
"""

from __future__ import annotations

import json
import os
import random
import re
import shutil
import struct
import subprocess
import sys
import time
import tomllib
import traceback
import zlib

VDIR = "/logs/verifier"
APP = "/app/dz"
BUILD_DIR = "/root/dz-verify-build"
CARGO_HOME = "/root/dz-verify-cargo-home"
PATH = "/usr/local/cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

SEED = int(os.environ.get("DZ_SEED", "20261029"))
DEADLINE_SEC = float(os.environ.get("DZ_DEADLINE_SEC", "2400"))
CALL_TIMEOUT = float(os.environ.get("DZ_CALL_TIMEOUT_SEC", "120"))
BUILD_TIMEOUT = 600

# Ratio targets: R = sum(dz zlib -l 6) / sum(zlib level 6). Full credit at or
# below R_FULL, none at or above R_ZERO, linear between.
R_FULL = 1.03
R_ZERO = 1.35
COMPRESS_16M_LIMIT_SEC = 20.0
DECOMPRESS_16M_LIMIT_SEC = 8.0
WEIGHTS = {"inflate": 0.30, "interop": 0.25, "ratio": 0.35, "speed": 0.10}

FORBIDDEN_SRC = [
    (r'extern\s+"(C|system|C-unwind|system-unwind)"', "foreign function interface"),
    (r"#\s*!?\s*\[\s*link\b", "#[link] attribute"),
    (r"\bdlopen\b", "dlopen"),
    (r"\blibz\b", "reference to libz"),
    (r"process::Command|\bCommand::new\b", "spawning processes"),
    (r'include_(bytes|str)!\s*\(\s*"(/|\.\.)', "include of a file outside src/"),
    (r'include_(bytes|str)!\s*\(\s*concat!', "include of a computed path"),
]

T0 = time.monotonic()
EVIDENCE: dict = {"seed": SEED, "cases": [], "notes": []}


# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------

def write_reward(reward: float, components: dict, extra: dict | None = None) -> None:
    os.makedirs(VDIR, exist_ok=True)
    reward = max(0.0, min(1.0, reward))
    with open(os.path.join(VDIR, "reward.txt"), "w") as f:
        f.write(f"{reward:.4f}\n")
    # Harbor parses reward.json as a FLAT dict of metric_name -> number and shows
    # each key as a column, so it must contain only numeric values. The primary
    # score is the "reward" key. All structured detail (weights, R thresholds,
    # byte counts, timings, per-case results) goes to evidence.json instead.
    payload = {"reward": round(reward, 4)}
    for k, v in components.items():
        payload[k] = round(float(v), 4)
    with open(os.path.join(VDIR, "reward.json"), "w") as f:
        json.dump(payload, f, indent=2)
    EVIDENCE["reward"] = round(reward, 4)
    EVIDENCE["components"] = components
    EVIDENCE["weights"] = WEIGHTS
    if extra:
        EVIDENCE["summary"] = extra
    with open(os.path.join(VDIR, "evidence.json"), "w") as f:
        json.dump(EVIDENCE, f, indent=1)


def fail_all(reason: str) -> None:
    EVIDENCE["notes"].append(reason)
    print(f"VERIFIER: {reason}")
    write_reward(0.0, {"inflate": 0, "interop": 0, "ratio": 0, "speed": 0}, {"fatal": reason})


def note(msg: str) -> None:
    EVIDENCE["notes"].append(msg)
    print(msg, flush=True)


def record(name: str, variant: str, ok: bool, detail: str = "", ms: float = 0.0) -> bool:
    EVIDENCE["cases"].append(
        {"case": name, "variant": variant, "ok": ok, "detail": detail, "ms": round(ms, 1)}
    )
    if not ok:
        print(f"  FAIL {name} [{variant}]: {detail}")
    return ok


def past_deadline() -> bool:
    return time.monotonic() - T0 > DEADLINE_SEC


# ---------------------------------------------------------------------------
# Static checks and build
# ---------------------------------------------------------------------------

def static_checks() -> str | None:
    manifest = os.path.join(APP, "Cargo.toml")
    if not os.path.isfile(manifest):
        return "Cargo.toml missing"
    try:
        with open(manifest, "rb") as f:
            cargo = tomllib.load(f)
    except Exception as e:  # noqa: BLE001
        return f"Cargo.toml does not parse: {e}"

    def walk(node, path):
        if isinstance(node, dict):
            for k, v in node.items():
                if k.endswith("dependencies") and isinstance(v, dict) and v:
                    return f"dependencies declared at {'.'.join(path + [k])}"
                r = walk(v, path + [k])
                if r:
                    return r
        return None

    r = walk(cargo, [])
    if r:
        return r
    if "build" in cargo.get("package", {}):
        return "package.build (custom build script) is not allowed"
    for name in ("build.rs", "rust-toolchain", "rust-toolchain.toml"):
        if os.path.exists(os.path.join(APP, name)):
            return f"{name} is not allowed"
    for cfg in (os.path.join(APP, ".cargo"), "/app/.cargo"):
        if os.path.exists(cfg):
            return f"{cfg} is not allowed"
    src = os.path.join(APP, "src")
    if not os.path.isdir(src):
        return "src/ missing"
    rs_files = []
    for root, _dirs, files in os.walk(src):
        for fn in files:
            if fn.endswith(".rs"):
                rs_files.append(os.path.join(root, fn))
    if not rs_files:
        return "no .rs files in src/"
    for path in rs_files:
        try:
            text = open(path, encoding="utf-8", errors="replace").read()
        except OSError as e:
            return f"cannot read {path}: {e}"
        for pattern, why in FORBIDDEN_SRC:
            if re.search(pattern, text):
                return f"{os.path.relpath(path, APP)}: {why}"
    return None


def build_binary() -> tuple[str | None, str | None]:
    shutil.rmtree(BUILD_DIR, ignore_errors=True)
    shutil.rmtree(CARGO_HOME, ignore_errors=True)
    os.makedirs(BUILD_DIR)
    os.makedirs(CARGO_HOME)
    shutil.copy(os.path.join(APP, "Cargo.toml"), BUILD_DIR)
    lock = os.path.join(APP, "Cargo.lock")
    if os.path.isfile(lock):
        shutil.copy(lock, BUILD_DIR)
    shutil.copytree(os.path.join(APP, "src"), os.path.join(BUILD_DIR, "src"))
    env = {
        "PATH": PATH,
        "HOME": "/root",
        "CARGO_HOME": CARGO_HOME,
        "RUSTUP_HOME": os.environ.get("RUSTUP_HOME", "/usr/local/rustup"),
        "CARGO_NET_OFFLINE": "true",
        "RUSTFLAGS": "",
        "CARGO_TERM_COLOR": "never",
    }
    try:
        p = subprocess.run(
            ["cargo", "build", "--release", "--offline"],
            cwd=BUILD_DIR, env=env, capture_output=True, text=True, timeout=BUILD_TIMEOUT,
        )
    except subprocess.TimeoutExpired:
        return None, "build timed out"
    with open(os.path.join(VDIR, "build.log"), "w") as f:
        f.write(p.stdout)
        f.write(p.stderr)
    if p.returncode != 0:
        return None, "cargo build failed (see build.log)"
    binary = os.path.join(BUILD_DIR, "target", "release", "dz")
    if not os.path.isfile(binary):
        return None, "no binary named dz produced"
    ldd = subprocess.run(["ldd", binary], capture_output=True, text=True)
    if "libz" in ldd.stdout:
        return None, "binary links against libz"
    return binary, None


# ---------------------------------------------------------------------------
# Corpus
# ---------------------------------------------------------------------------

def gen_words(rng: random.Random, count: int) -> list[str]:
    syll = ["ka", "to", "ri", "ne", "sa", "mu", "lo", "ve", "da", "pi", "su", "ren", "tal", "ox", "en", "ar", "um", "ish"]
    return ["".join(rng.choice(syll) for _ in range(rng.randint(1, 4))) for _ in range(count)]


def markov_text(rng: random.Random, n: int) -> bytes:
    vocab = gen_words(rng, 400)
    # First-order chain with a skewed successor list per word.
    nxt = {w: [rng.choice(vocab) for _ in range(6)] for w in vocab}
    out, size, w = [], 0, rng.choice(vocab)
    while size < n:
        w = rng.choice(nxt[w]) if rng.random() < 0.8 else rng.choice(vocab)
        piece = w + (". " if rng.random() < 0.08 else (",\n" if rng.random() < 0.05 else " "))
        out.append(piece)
        size += len(piece)
    return "".join(out).encode()[:n]


def jsonish(rng: random.Random, n: int) -> bytes:
    vocab = gen_words(rng, 60)
    out, size, i = [], 0, 0
    while size < n:
        rec = {
            "id": i,
            "name": rng.choice(vocab),
            "tags": [rng.choice(vocab) for _ in range(rng.randint(0, 4))],
            "score": round(rng.random() * 100, 3),
            "active": rng.random() < 0.5,
        }
        line = json.dumps(rec, separators=(",", ":")) + "\n"
        out.append(line)
        size += len(line)
        i += 1
    return "".join(out).encode()[:n]


def log_lines(rng: random.Random, n: int) -> bytes:
    hosts = [f"10.{rng.randint(0, 255)}.{rng.randint(0, 255)}.{rng.randint(1, 254)}" for _ in range(40)]
    paths = ["/", "/index.html", "/api/v1/items", "/static/app.js", "/login", "/health"]
    out, size, t = [], 0, 1_700_000_000
    while size < n:
        t += rng.randint(0, 3)
        line = f"{t} {rng.choice(hosts)} GET {rng.choice(paths)} {rng.choice([200, 200, 200, 304, 404, 500])} {rng.randint(100, 90000)}\n"
        out.append(line)
        size += len(line)
    return "".join(out).encode()[:n]


def periodic(rng: random.Random, period: int, n: int) -> bytes:
    unit = rng.randbytes(period)
    return (unit * (n // period + 1))[:n]


def build_corpus(rng: random.Random) -> list[tuple[str, bytes]]:
    items: list[tuple[str, bytes]] = []
    add = lambda name, data: items.append((name, data))  # noqa: E731
    add("empty", b"")
    add("one_byte", b"a")
    add("two_bytes", b"ab")
    add("three_same", b"aaa")
    add("short_text", b"hello, hello, hello world. hello again!\n")
    add("short_run", b"z" * 100)
    add("random_1k", rng.randbytes(1000))
    add("zeros_1m", bytes(1 << 20))
    add("ff_300k", b"\xff" * 300_000)
    add("random_2m", rng.randbytes(2 << 20))
    add("text_4m", markov_text(rng, 4 << 20))
    add("text_200k", markov_text(rng, 200_000))
    add("json_1m", jsonish(rng, 1 << 20))
    add("log_1m", log_lines(rng, 1 << 20))
    for p in (1, 2, 3, 4, 5, 7, 13, 64, 257, 258, 259, 300):
        add(f"period_{p}", periodic(rng, p, 200_000))
    # Matches that must reach back exactly to the edge of the 32 KiB window.
    marker = rng.randbytes(600)
    add("window_cross", rng.randbytes(20_000) + marker + rng.randbytes(32_768 - 600) + marker + rng.randbytes(5_000))
    add("window_edge", marker + rng.randbytes(32_768 - 600) + marker)
    add("window_beyond", marker + rng.randbytes(32_769 - 600) + marker)
    # Max-match-length edge cases: runs of exactly 257/258/259 then a change.
    mm = b"".join(rng.randbytes(1) * k + bytes([k & 0xFF]) for k in (256, 257, 258, 259, 260, 515, 516, 517) for _ in range(40))
    add("max_match", mm)
    add("long_literals", b"".join((rng.randbytes(3000), periodic(rng, 11, 2000)) [i % 2] for i in range(400)))
    add("stored_split_70000", rng.randbytes(70_000))
    add("stored_split_65535", rng.randbytes(65_535))
    add("stored_split_65536", rng.randbytes(65_536))
    add("stored_split_131071", rng.randbytes(131_071))
    add("alphabet", bytes(range(256)) * 1000)
    sparse = bytearray(1 << 20)
    for i in range(0, len(sparse), 1000):
        sparse[i] = rng.randrange(256)
    add("sparse_1m", bytes(sparse))
    add("ints_le", b"".join(struct.pack("<I", i) for i in range(250_000)))
    add("dna_1m", bytes(rng.choice(b"ACGT") for _ in range(1 << 20)))
    add("half_random_half_zero", rng.randbytes(512 << 10) + bytes(512 << 10))
    add("utf8_300k", "".join(chr(rng.choice([0x41, 0x3B1, 0x4E2D, 0x1F600, 0x20AC, 0x61, 0x20])) for _ in range(120_000)).encode()[:300_000])
    big = b"".join(
        (markov_text(rng, 1 << 16) if i % 4 else rng.randbytes(1 << 16)) for i in range(256)
    )
    add("big_16m", big)
    return items


# ---------------------------------------------------------------------------
# Hand-built DEFLATE streams for cases zlib would not naturally emit
# ---------------------------------------------------------------------------

class BitWriter:
    def __init__(self) -> None:
        self.out = bytearray()
        self.buf = 0
        self.cnt = 0

    def bits(self, value: int, n: int) -> None:
        self.buf |= value << self.cnt
        self.cnt += n
        while self.cnt >= 8:
            self.out.append(self.buf & 0xFF)
            self.buf >>= 8
            self.cnt -= 8

    def code(self, code: int, length: int) -> None:
        for i in range(length - 1, -1, -1):
            self.bits((code >> i) & 1, 1)

    def finish(self) -> bytes:
        if self.cnt:
            self.out.append(self.buf & 0xFF)
        return bytes(self.out)


def fixed_lit(w: BitWriter, sym: int) -> None:
    if sym <= 143:
        w.code(0x30 + sym, 8)
    elif sym <= 255:
        w.code(0x190 + sym - 144, 9)
    elif sym <= 279:
        w.code(sym - 256, 7)
    else:
        w.code(0xC0 + sym - 280, 8)


def fixed_block_stream() -> tuple[bytes, bytes]:
    """A fixed-Huffman block: 'abcabcabcabcabc' + 'xyz' then EOB."""
    w = BitWriter()
    w.bits(1, 1)
    w.bits(1, 2)
    for b in b"abc":
        fixed_lit(w, b)
    # length 12 (symbol 265, 1 extra bit = 1), distance 3 (symbol 2)
    fixed_lit(w, 265)
    w.bits(1, 1)
    w.code(2, 5)
    for b in b"xyz":
        fixed_lit(w, b)
    fixed_lit(w, 256)
    return w.finish(), b"abc" * 5 + b"xyz"


def distance_too_far_stream() -> bytes:
    w = BitWriter()
    w.bits(1, 1)
    w.bits(1, 2)
    fixed_lit(w, ord("a"))
    fixed_lit(w, 257)  # length 3
    w.code(13, 5)      # distance code 13: base 97, 3 extra bits
    w.bits(3, 3)       # distance 100 with only 1 byte of history
    fixed_lit(w, 256)
    return w.finish()


def oversubscribed_stream() -> bytes:
    w = BitWriter()
    w.bits(1, 1)
    w.bits(2, 2)
    w.bits(0, 5)   # HLIT = 257
    w.bits(0, 5)   # HDIST = 1
    w.bits(15, 4)  # HCLEN = 19
    # Code-length code: symbols 16, 17, 18 all get length 1 (three 1-bit codes).
    for i in range(19):
        w.bits(1 if i < 3 else 0, 3)
    w.bits(0, 16)
    return w.finish()


def gzip_with_optional_fields(data: bytes) -> bytes:
    body = zlib.compress(data, 6, -15)
    hdr = bytearray([0x1F, 0x8B, 8, 0x02 | 0x04 | 0x08 | 0x10, 1, 2, 3, 4, 0, 255])
    extra = b"AB\x03\x00xyz"
    hdr += struct.pack("<H", len(extra)) + extra
    hdr += b"file.txt\x00" + b"a comment\x00"
    hdr += struct.pack("<H", zlib.crc32(bytes(hdr)) & 0xFFFF)
    return bytes(hdr) + body + struct.pack("<II", zlib.crc32(data) & 0xFFFFFFFF, len(data) & 0xFFFFFFFF)


def flushed_stream(data: bytes, level: int, flush: int) -> bytes:
    c = zlib.compressobj(level, zlib.DEFLATED, 15)
    out = bytearray()
    for i in range(0, max(len(data), 1), 7 * 1024):
        out += c.compress(data[i:i + 7 * 1024])
        out += c.flush(flush)
    out += c.flush(zlib.Z_FINISH)
    return bytes(out)


# ---------------------------------------------------------------------------
# Running the candidate
# ---------------------------------------------------------------------------

class Runner:
    def __init__(self, binary: str) -> None:
        self.binary = binary

    def run(self, args: list[str], data: bytes, timeout: float = CALL_TIMEOUT):
        t = time.monotonic()
        try:
            p = subprocess.run(
                [self.binary, *args], input=data, capture_output=True, timeout=timeout,
                env={"PATH": PATH, "HOME": "/root"},
            )
            return p.returncode, p.stdout, p.stderr[:200].decode(errors="replace"), (time.monotonic() - t) * 1000
        except subprocess.TimeoutExpired:
            return None, b"", "timeout", (time.monotonic() - t) * 1000


def decode_ok(r: Runner, name: str, variant: str, cmd: str, stream: bytes, expect: bytes) -> bool:
    if past_deadline():
        return record(name, variant, False, "skipped: verifier deadline")
    rc, out, err, ms = r.run([cmd], stream)
    if rc != 0:
        return record(name, variant, False, f"exit {rc}: {err.strip()}", ms)
    if out != expect:
        return record(name, variant, False, f"output differs ({len(out)} vs {len(expect)} bytes)", ms)
    return record(name, variant, True, "", ms)


def must_reject(r: Runner, name: str, cmd: str, stream: bytes) -> bool:
    if past_deadline():
        return record(name, "malformed", False, "skipped: verifier deadline")
    rc, _out, err, ms = r.run([cmd], stream)
    if rc is None or rc == 0:
        return record(name, "malformed", False, f"accepted malformed input (exit {rc})", ms)
    return record(name, "malformed", True, err.strip(), ms)


def score_inflate(r: Runner, corpus: list[tuple[str, bytes]]) -> float:
    print("== inflate / unzlib / gunzip correctness ==", flush=True)
    results = []
    for name, data in corpus:
        for level in (0, 1, 6, 9):
            results.append(decode_ok(r, name, f"unzlib L{level}", "unzlib", zlib.compress(data, level), data))
        results.append(decode_ok(r, name, "inflate raw L6", "inflate", zlib.compress(data, 6, -15), data))
        results.append(decode_ok(r, name, "gunzip L6", "gunzip", zlib.compress(data, 6, 31), data))
        results.append(decode_ok(r, name, "unzlib sync-flush", "unzlib", flushed_stream(data, 6, zlib.Z_SYNC_FLUSH), data))
        results.append(decode_ok(r, name, "unzlib full-flush", "unzlib", flushed_stream(data, 9, zlib.Z_FULL_FLUSH), data))
    # Streams zlib does not naturally produce.
    fixed, fixed_plain = fixed_block_stream()
    results.append(decode_ok(r, "handmade", "fixed-huffman block", "inflate", fixed, fixed_plain))
    members = [corpus[4][1], corpus[11][1], corpus[6][1]]
    multi = b"".join(zlib.compress(m, 6, 31) for m in members)
    results.append(decode_ok(r, "handmade", "multi-member gzip", "gunzip", multi, b"".join(members)))
    results.append(decode_ok(r, "handmade", "gzip optional header fields", "gunzip", gzip_with_optional_fields(corpus[12][1]), corpus[12][1]))
    results.append(decode_ok(r, "handmade", "empty stored block stream", "inflate", b"\x01\x00\x00\xff\xff", b""))
    positives = list(results)
    n_positive = len(results)
    # Malformed inputs must be rejected with a non-zero exit.
    print("== malformed inputs ==", flush=True)
    sample = corpus[11][1][:40_000]
    z = zlib.compress(sample, 6)
    g = zlib.compress(sample, 6, 31)
    raw = zlib.compress(sample, 6, -15)
    results.append(must_reject(r, "bad adler32", "unzlib", z[:-1] + bytes([z[-1] ^ 0xFF])))
    results.append(must_reject(r, "bad gzip crc32", "gunzip", g[:-5] + bytes([g[-5] ^ 0xFF]) + g[-4:]))
    results.append(must_reject(r, "bad gzip isize", "gunzip", g[:-1] + bytes([g[-1] ^ 0x01])))
    results.append(must_reject(r, "truncated zlib", "unzlib", z[: len(z) // 2]))
    results.append(must_reject(r, "truncated raw deflate", "inflate", raw[:-3]))
    results.append(must_reject(r, "block type 3", "inflate", b"\x07"))
    results.append(must_reject(r, "oversubscribed code lengths", "inflate", oversubscribed_stream()))
    results.append(must_reject(r, "distance too far back", "inflate", distance_too_far_stream()))
    results.append(must_reject(r, "bad zlib header check", "unzlib", b"\x78\x9d" + z[2:]))
    results.append(must_reject(r, "zlib preset dictionary", "unzlib", b"\x78\xbb\x00\x00\x00\x01" + z[2:]))
    results.append(must_reject(r, "empty input", "unzlib", b""))
    rejections = results[n_positive:]
    # Rejecting malformed input only counts for a decoder that also accepts
    # valid input: scale that credit by the pass rate on the positive cases,
    # so a binary that exits non-zero on everything scores exactly 0 here.
    positive_rate = sum(positives) / len(positives)
    EVIDENCE["inflate_positive_rate"] = positive_rate
    EVIDENCE["inflate_rejection_rate"] = sum(rejections) / len(rejections)
    credit = sum(positives) + sum(rejections) * positive_rate
    return credit / len(results)


def score_interop(r: Runner, corpus: list[tuple[str, bytes]]) -> tuple[float, dict[str, int]]:
    print("== deflate / zlib / gzip interoperability ==", flush=True)
    results = []
    zlib6_sizes: dict[str, int] = {}
    for name, data in corpus:
        variants = [
            ("zlib L6", ["zlib", "-l", "6"], lambda s: zlib.decompress(s)),
            ("zlib L0", ["zlib", "-l", "0"], lambda s: zlib.decompress(s)),
            ("zlib L9", ["zlib", "-l", "9"], lambda s: zlib.decompress(s)),
            ("deflate L6", ["deflate", "-l", "6"], lambda s: zlib.decompress(s, -15)),
            ("gzip L6", ["gzip", "-l", "6"], lambda s: zlib.decompress(s, 31)),
        ]
        for variant, args, dec in variants:
            if past_deadline():
                results.append(record(name, variant, False, "skipped: verifier deadline"))
                continue
            rc, out, err, ms = r.run(args, data)
            if rc != 0:
                results.append(record(name, variant, False, f"exit {rc}: {err.strip()}", ms))
                if variant == "zlib L6":
                    zlib6_sizes[name] = 8 * (len(data) + 1)
                continue
            try:
                plain = dec(out)
            except Exception as e:  # noqa: BLE001
                results.append(record(name, variant, False, f"reference decoder rejected output: {e}", ms))
                if variant == "zlib L6":
                    zlib6_sizes[name] = len(out)
                continue
            ok = plain == data
            detail = "" if ok else "round trip differs"
            if ok and variant == "gzip L6":
                hdr = out[:10]
                if len(hdr) < 10 or hdr[:4] != b"\x1f\x8b\x08\x00" or hdr[4:8] != b"\x00\x00\x00\x00" or hdr[9] != 3:
                    ok, detail = False, f"gzip header fields wrong: {hdr.hex()}"
            if variant == "zlib L6":
                zlib6_sizes[name] = len(out)
            results.append(record(name, variant, ok, detail, ms))
    return sum(results) / len(results), zlib6_sizes


def score_ratio(corpus: list[tuple[str, bytes]], ours: dict[str, int]) -> tuple[float, float, int, int]:
    total_ours = total_ref = 0
    for name, data in corpus:
        if len(data) <= 1:
            continue
        total_ours += ours.get(name, 8 * (len(data) + 1))
        total_ref += len(zlib.compress(data, 6))
    ratio = total_ours / total_ref
    if ratio <= R_FULL:
        score = 1.0
    elif ratio >= R_ZERO:
        score = 0.0
    else:
        score = (R_ZERO - ratio) / (R_ZERO - R_FULL)
    return score, ratio, total_ours, total_ref


def score_speed(r: Runner, corpus: list[tuple[str, bytes]]) -> float:
    print("== throughput ==", flush=True)
    big = dict(corpus)["big_16m"]
    rc, out, err, ms = r.run(["zlib", "-l", "6"], big, timeout=COMPRESS_16M_LIMIT_SEC + 5)
    comp_ok = rc == 0 and ms <= COMPRESS_16M_LIMIT_SEC * 1000
    record("big_16m", "compress within limit", comp_ok, f"{ms / 1000:.2f}s (limit {COMPRESS_16M_LIMIT_SEC}s)", ms)
    rc, out, err, ms = r.run(["unzlib"], zlib.compress(big, 6), timeout=DECOMPRESS_16M_LIMIT_SEC + 5)
    dec_ok = rc == 0 and out == big and ms <= DECOMPRESS_16M_LIMIT_SEC * 1000
    record("big_16m", "decompress within limit", dec_ok, f"{ms / 1000:.2f}s (limit {DECOMPRESS_16M_LIMIT_SEC}s)", ms)
    return 0.5 * comp_ok + 0.5 * dec_ok


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    os.makedirs(VDIR, exist_ok=True)
    print(f"deflate-codec-rs verifier, seed={SEED}", flush=True)
    problem = static_checks()
    if problem:
        fail_all(f"static rule violated: {problem}")
        return
    binary, problem = build_binary()
    if problem:
        fail_all(problem)
        return
    note(f"built {binary} in {time.monotonic() - T0:.1f}s")

    rng = random.Random(SEED)
    corpus = build_corpus(rng)
    note(f"corpus: {len(corpus)} items, {sum(len(d) for _, d in corpus) / 2**20:.1f} MiB")
    r = Runner(binary)

    inflate = score_inflate(r, corpus)
    interop, zlib6_sizes = score_interop(r, corpus)
    ratio_raw, ratio, total_ours, total_ref = score_ratio(corpus, zlib6_sizes)
    gate = min(inflate, interop)
    ratio_score = ratio_raw * gate
    speed = score_speed(r, corpus)

    components = {
        "inflate": round(inflate, 4),
        "interop": round(interop, 4),
        "ratio": round(ratio_score, 4),
        "ratio_unscaled": round(ratio_raw, 4),
        "speed": round(speed, 4),
    }
    reward = (
        WEIGHTS["inflate"] * inflate
        + WEIGHTS["interop"] * interop
        + WEIGHTS["ratio"] * ratio_score
        + WEIGHTS["speed"] * speed
    )
    extra = {
        "R": round(ratio, 5),
        "R_FULL": R_FULL,
        "R_ZERO": R_ZERO,
        "bytes_ours_zlib6": total_ours,
        "bytes_ref_zlib6": total_ref,
        "elapsed_sec": round(time.monotonic() - T0, 1),
    }
    print("== summary ==")
    for k, v in components.items():
        print(f"  {k:15s} {v:.4f}")
    print(f"  R = {ratio:.5f} (full credit <= {R_FULL}, zero >= {R_ZERO})")
    print(f"  reward = {reward:.4f}  ({extra['elapsed_sec']}s)")
    write_reward(reward, components, extra)


if __name__ == "__main__":
    try:
        main()
    except Exception:  # noqa: BLE001
        traceback.print_exc()
        fail_all("verifier crashed: " + traceback.format_exc().strip().splitlines()[-1])
