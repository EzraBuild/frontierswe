//! `dz`: a DEFLATE / zlib / gzip codec with no dependencies.
//!
//! Usage: `dz <deflate|inflate|zlib|unzlib|gzip|gunzip> [-l LEVEL]`
//! Reads all of stdin, writes the result to stdout.
//!
//! This is the starting skeleton: argument parsing is done, every command
//! still has to be implemented. See /app/README.md for the full contract.

use std::io::{self, Read, Write};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Command {
    Deflate,
    Inflate,
    Zlib,
    Unzlib,
    Gzip,
    Gunzip,
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
    let (command, _level) = parse_args();
    let mut input = Vec::new();
    if let Err(e) = io::stdin().lock().read_to_end(&mut input) {
        eprintln!("dz: failed to read stdin: {e}");
        std::process::exit(1);
    }
    let output: Option<Vec<u8>> = match command {
        Command::Deflate | Command::Inflate | Command::Zlib | Command::Unzlib | Command::Gzip | Command::Gunzip => None,
    };
    match output {
        Some(bytes) => {
            let stdout = io::stdout();
            let mut lock = stdout.lock();
            if lock.write_all(&bytes).and_then(|_| lock.flush()).is_err() {
                std::process::exit(1);
            }
        }
        None => {
            eprintln!("dz: {command:?} is unimplemented");
            std::process::exit(2);
        }
    }
}
