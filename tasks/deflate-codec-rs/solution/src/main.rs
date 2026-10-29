//! `dz`: a dependency-free DEFLATE / zlib / gzip codec.
//!
//! Usage: `dz <deflate|inflate|zlib|unzlib|gzip|gunzip> [-l LEVEL]`
//! Reads stdin, writes stdout. Exits 1 with a message on stderr if the input
//! is malformed, 2 on usage errors.

mod checksum;
mod deflate;
mod inflate;

use std::fmt;
use std::io::{self, Read, Write};

#[derive(Clone, Copy, PartialEq, Eq)]
enum Command {
    Deflate,
    Inflate,
    Zlib,
    Unzlib,
    Gzip,
    Gunzip,
}

#[derive(Debug)]
enum Error {
    Io(io::Error),
    Inflate(inflate::InflateError),
    Format(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "i/o error: {e}"),
            Self::Inflate(e) => write!(f, "{e}"),
            Self::Format(m) => write!(f, "{m}"),
        }
    }
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

impl From<inflate::InflateError> for Error {
    fn from(e: inflate::InflateError) -> Self {
        Self::Inflate(e)
    }
}

fn usage() -> ! {
    eprintln!("usage: dz <deflate|inflate|zlib|unzlib|gzip|gunzip> [-l LEVEL]");
    std::process::exit(2)
}

fn parse_args() -> (Command, u8) {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let Some(cmd) = args.first() else { usage() };
    let command = match cmd.as_str() {
        "deflate" => Command::Deflate,
        "inflate" => Command::Inflate,
        "zlib" => Command::Zlib,
        "unzlib" => Command::Unzlib,
        "gzip" => Command::Gzip,
        "gunzip" => Command::Gunzip,
        _ => usage(),
    };
    let mut level = 6u8;
    let mut i = 1;
    while i < args.len() {
        let arg = &args[i];
        let value = if arg == "-l" || arg == "--level" {
            i += 1;
            args.get(i).cloned().unwrap_or_else(|| usage())
        } else if let Some(v) = arg.strip_prefix("-l") {
            v.to_string()
        } else {
            usage()
        };
        level = match value.parse::<u8>() {
            Ok(l) if l <= 9 => l,
            _ => usage(),
        };
        i += 1;
    }
    (command, level)
}

fn main() {
    let (command, level) = parse_args();
    let result = (|| -> Result<(), Error> {
        let mut input = Vec::new();
        io::stdin().lock().read_to_end(&mut input)?;
        let output = match command {
            Command::Deflate => {
                let mut out = Vec::with_capacity(input.len() / 2 + 64);
                deflate::deflate(&input, level, &mut out);
                out
            }
            Command::Inflate => inflate::inflate(&input)?.data,
            Command::Zlib => zlib_compress(&input, level),
            Command::Unzlib => zlib_decompress(&input)?,
            Command::Gzip => gzip_compress(&input, level),
            Command::Gunzip => gzip_decompress(&input)?,
        };
        let stdout = io::stdout();
        let mut lock = stdout.lock();
        lock.write_all(&output)?;
        lock.flush()?;
        Ok(())
    })();
    if let Err(e) = result {
        eprintln!("dz: {e}");
        std::process::exit(1);
    }
}

// ---------------------------------------------------------------------------
// zlib container (RFC 1950)
// ---------------------------------------------------------------------------

fn zlib_compress(input: &[u8], level: u8) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len() / 2 + 64);
    let cmf = 0x78u32; // CM = 8 (deflate), CINFO = 7 (32K window)
    let flevel = match level {
        0 | 1 => 0,
        2..=5 => 1,
        6 => 2,
        _ => 3,
    };
    let mut flg = flevel << 6;
    flg |= (31 - ((cmf << 8 | flg) % 31)) % 31;
    out.push(cmf as u8);
    out.push(flg as u8);
    deflate::deflate(input, level, &mut out);
    out.extend_from_slice(&checksum::adler32(input).to_be_bytes());
    out
}

fn zlib_decompress(input: &[u8]) -> Result<Vec<u8>, Error> {
    if input.len() < 2 {
        return Err(Error::Format("zlib header truncated".into()));
    }
    let (cmf, flg) = (input[0], input[1]);
    if cmf & 0x0F != 8 {
        return Err(Error::Format("zlib: unsupported compression method".into()));
    }
    if cmf >> 4 > 7 {
        return Err(Error::Format("zlib: invalid window size".into()));
    }
    if (u16::from(cmf) << 8 | u16::from(flg)) % 31 != 0 {
        return Err(Error::Format("zlib: header check failed".into()));
    }
    if flg & 0x20 != 0 {
        return Err(Error::Format("zlib: preset dictionaries are not supported".into()));
    }
    let body = inflate::inflate(&input[2..])?;
    let trailer = &input[2 + body.consumed..];
    if trailer.len() < 4 {
        return Err(Error::Format("zlib: trailer truncated".into()));
    }
    let expected = u32::from_be_bytes([trailer[0], trailer[1], trailer[2], trailer[3]]);
    if checksum::adler32(&body.data) != expected {
        return Err(Error::Format("zlib: Adler-32 mismatch".into()));
    }
    Ok(body.data)
}

// ---------------------------------------------------------------------------
// gzip container (RFC 1952)
// ---------------------------------------------------------------------------

const GZIP_MAGIC: [u8; 2] = [0x1F, 0x8B];

fn gzip_compress(input: &[u8], level: u8) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len() / 2 + 64);
    let xfl = match level {
        9 => 2,
        1 => 4,
        _ => 0,
    };
    // ID1 ID2 CM FLG MTIME(4) XFL OS: no optional fields, mtime 0, OS = Unix.
    out.extend_from_slice(&[GZIP_MAGIC[0], GZIP_MAGIC[1], 8, 0, 0, 0, 0, 0, xfl, 3]);
    deflate::deflate(input, level, &mut out);
    out.extend_from_slice(&checksum::crc32(input).to_le_bytes());
    out.extend_from_slice(&(input.len() as u32).to_le_bytes());
    out
}

fn gzip_decompress(input: &[u8]) -> Result<Vec<u8>, Error> {
    let mut out = Vec::new();
    let mut pos = 0;
    let mut members = 0;
    while pos < input.len() {
        // gzip tolerates zero padding after the last member.
        if members > 0 && input[pos..].iter().all(|&b| b == 0) {
            break;
        }
        pos = gzip_member(input, pos, &mut out)?;
        members += 1;
    }
    if members == 0 {
        return Err(Error::Format("gzip: empty input".into()));
    }
    Ok(out)
}

/// Decode one member starting at `pos`; returns the offset after its trailer.
fn gzip_member(input: &[u8], start: usize, out: &mut Vec<u8>) -> Result<usize, Error> {
    let hdr = &input[start..];
    if hdr.len() < 10 {
        return Err(Error::Format("gzip: header truncated".into()));
    }
    if hdr[0..2] != GZIP_MAGIC {
        return Err(Error::Format("gzip: bad magic number".into()));
    }
    if hdr[2] != 8 {
        return Err(Error::Format("gzip: unsupported compression method".into()));
    }
    let flg = hdr[3];
    if flg & 0xE0 != 0 {
        return Err(Error::Format("gzip: reserved header flag set".into()));
    }
    let mut pos = 10;
    let need = |pos: usize, n: usize| -> Result<(), Error> {
        if pos + n > hdr.len() {
            Err(Error::Format("gzip: header truncated".into()))
        } else {
            Ok(())
        }
    };
    if flg & 0x04 != 0 {
        need(pos, 2)?;
        let xlen = usize::from(u16::from_le_bytes([hdr[pos], hdr[pos + 1]]));
        pos += 2;
        need(pos, xlen)?;
        pos += xlen;
    }
    for mask in [0x08u8, 0x10] {
        if flg & mask != 0 {
            match hdr[pos..].iter().position(|&b| b == 0) {
                Some(i) => pos += i + 1,
                None => return Err(Error::Format("gzip: header truncated".into())),
            }
        }
    }
    if flg & 0x02 != 0 {
        need(pos, 2)?;
        let expected = u16::from_le_bytes([hdr[pos], hdr[pos + 1]]);
        if (checksum::crc32(&hdr[..pos]) & 0xFFFF) as u16 != expected {
            return Err(Error::Format("gzip: header CRC mismatch".into()));
        }
        pos += 2;
    }
    let body = inflate::inflate(&hdr[pos..])?;
    pos += body.consumed;
    need(pos, 8)?;
    let crc = u32::from_le_bytes([hdr[pos], hdr[pos + 1], hdr[pos + 2], hdr[pos + 3]]);
    let isize = u32::from_le_bytes([hdr[pos + 4], hdr[pos + 5], hdr[pos + 6], hdr[pos + 7]]);
    if checksum::crc32(&body.data) != crc {
        return Err(Error::Format("gzip: CRC-32 mismatch".into()));
    }
    if body.data.len() as u32 != isize {
        return Err(Error::Format("gzip: length mismatch".into()));
    }
    out.extend_from_slice(&body.data);
    Ok(start + pos + 8)
}
