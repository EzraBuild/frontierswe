#!/bin/bash
# Reference solution: install the complete codec sources into the agent's
# crate and build it. The sources live next to this script in src/.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"

rm -rf /app/dz/src
cp -r "$HERE/src" /app/dz/src

cd /app/dz
cargo build --release --offline

# Smoke test on the shipped samples: every file must round-trip in all three
# container formats and interoperate with the system zlib.
for f in /app/samples/*; do
    ./target/release/dz zlib   < "$f" | ./target/release/dz unzlib | cmp -s - "$f"
    ./target/release/dz gzip   < "$f" | ./target/release/dz gunzip | cmp -s - "$f"
    ./target/release/dz deflate < "$f" | ./target/release/dz inflate | cmp -s - "$f"
    ./target/release/dz zlib < "$f" | python3 -c 'import sys, zlib; sys.stdout.buffer.write(zlib.decompress(sys.stdin.buffer.read()))' | cmp -s - "$f"
done
echo "reference codec built and smoke-tested"
