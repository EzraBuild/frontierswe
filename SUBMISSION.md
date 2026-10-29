# Sample submission — Ezra

Two Harbor / FrontierSWE-style task folders, each verified with all three required checks on
2026-10-29. Harbor 0.25, Docker 29.1.3 (WSL Ubuntu). One trial per run, so Harbor's mean equals
the single-trial reward.

Each run reported **0 exceptions**. The checker was run with `python3 -I frontierswe-check.py <folder>`.

---

## Task 1 — `tasks/deflate-codec-rs`  (long-horizon SWE, FrontierSWE "optimise a codec")

Implement a dependency-free DEFLATE (RFC 1951) codec in Rust with zlib and gzip framing, as a CLI
`dz`. Graded on inflate correctness vs Python's zlib (0.30), compression interop (0.25), compression
ratio vs zlib level 6 (0.35), and throughput (0.10). The verifier rebuilds the crate offline with an
empty registry and forbids all external crates, FFI, build scripts and process spawning, so the work
cannot be outsourced to a library. Reference compressor lands at R = 1.011 of zlib-6 (full credit at
R ≤ 1.03, zero at R ≥ 1.35).

- **Checker:** `FSWE-CHECK v1 PASS ezra-samples/deflate-codec-rs 83b1acd04aa0`
- **Oracle:** `harbor run -p tasks/deflate-codec-rs -a oracle` → Mean **1.000** (inflate 1.000, interop 1.000, ratio 1.000, speed 1.000)
- **Nop:** `harbor run -p tasks/deflate-codec-rs -a nop` → Mean **0.000**
- **Folder:** `tasks/deflate-codec-rs/`

## Task 2 — `tasks/webshop-incident-response`  (security: incident response + forensics)

A frozen, fully synthetic snapshot of a compromised Linux host that ran a Flask shop behind nginx.
The agent reconstructs the intrusion into a structured `findings.json`, writes `remediation.md`, and
eradicates the compromise on a restorable copy of the host. Graded on investigation accuracy (0.45),
eradication that removes each attacker artifact while preserving the matching legitimate one (0.45),
and remediation write-up (0.10). Ground truth is re-derived from a seed inside the verifier and is
never shipped in the image. All IPs are TEST-NET, all secrets are `SYNTHETIC-` prefixed, the webshell
and beacon are inert and labeled, and no real credentials or exploit code appear anywhere.

- **Checker:** `FSWE-CHECK v1 PASS ezra-samples/webshop-incident-response 1835a6b30ca0`
- **Oracle:** `harbor run -p tasks/webshop-incident-response -a oracle` → Mean **1.000** (investigation 0.450, eradication 0.450, remediation 0.100)
- **Nop:** `harbor run -p tasks/webshop-incident-response -a nop` → Mean **0.000**
- **Folder:** `tasks/webshop-incident-response/`

---

### Notes for the reviewer
- Both tasks commit `network_mode = "public"`. The verifiers need no network and enforce the real
  constraints themselves (depless offline build for the codec; static on-disk evidence for the
  forensics lab). This machine's WSL2 kernel lacks `CONFIG_NFT_FIB_INET`, so Harbor's Docker provider
  cannot enforce `no-network`/`allowlist` locally; `public` runs on any host. On egress-capable
  grading infra these can be tightened to `allowlist` with no other change.
- `[agent] timeout_sec = 72000` (20 h) on both, matching FrontierSWE's budget.
- The checker used is `frontierswe-check.py` in this repo root. If the form ships a different copy,
  re-run it against each folder and use that PASS line.
- Full Harbor output tables are saved in `tools/harbor-out/RESULTS.txt`.
