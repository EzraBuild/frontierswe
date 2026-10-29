# dz: DEFLATE / zlib / gzip codec

`dz <command> [-l LEVEL]` reads all of stdin and writes to stdout.

| command   | does                                                      |
|-----------|-----------------------------------------------------------|
| `deflate` | raw bytes -> raw DEFLATE stream (RFC 1951)                |
| `inflate` | raw DEFLATE stream -> raw bytes                           |
| `zlib`    | raw bytes -> zlib stream (RFC 1950, Adler-32 trailer)     |
| `unzlib`  | zlib stream -> raw bytes, Adler-32 verified               |
| `gzip`    | raw bytes -> gzip member (RFC 1952, CRC-32 + ISIZE)       |
| `gunzip`  | one or more gzip members -> raw bytes, CRC-32 verified    |

`-l LEVEL` is 0..9 (default 6). Level 0 emits stored blocks only.
Malformed input: non-zero exit status and a message on stderr.

Build: `cargo build --release --offline` (no network, no dependencies).

Quick manual checks with the files in `/app/samples`:

```
cargo build --release --offline
./target/release/dz zlib   < ../samples/text.txt | python3 -c "import sys,zlib; sys.stdout.buffer.write(zlib.decompress(sys.stdin.buffer.read()))" | cmp - ../samples/text.txt
python3 -c "import sys,zlib; sys.stdout.buffer.write(zlib.compress(open('../samples/text.txt','rb').read(), 9))" | ./target/release/dz unzlib | cmp - ../samples/text.txt
./target/release/dz gzip   < ../samples/random.bin | ./target/release/dz gunzip | cmp - ../samples/random.bin
```
