//! # rar-hex
//!
//! A CLI tool that reads a byte range from a file inside a RAR archive and
//! prints it as a hex dump to stdout.
//!
//! ## Usage
//!
//! ```text
//! rar-hex [OPTIONS] <ARCHIVE> <SELECTOR> <START> <LENGTH>
//!
//! Arguments:
//!   <ARCHIVE>   Path to the RAR archive file
//!   <SELECTOR>  File selector: a zero-based integer index OR a file path
//!               (e.g. "0", "1", "readme.txt", "subdir/file.bin")
//!   <START>     Byte offset to start reading from (decimal or 0x-prefixed hex)
//!   <LENGTH>    Number of bytes to read (decimal or 0x-prefixed hex)
//!
//! Options:
//!   -p, --password <PASSWORD>  Password for encrypted archives
//!   -l, --list                 List all entries in the archive and exit
//!   -h, --help                 Print this help message
//!
//! ## Examples
//!
//! List entries:
//!   rar-hex --list archive.rar
//!
//! Read first 64 bytes of entry 0:
//!   rar-hex archive.rar 0 0 64
//!
//! Read 32 bytes at offset 1024 from a file by path:
//!   rar-hex archive.rar "readme.txt" 1024 32
//!
//! Read from an encrypted archive:
//!   rar-hex -p secret archive.rar 0 0 64
//! ```

use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::process;

use rar_access::{Archive, EntrySelector, RarError, RarVersion};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    match run(&args) {
        Ok(()) => {}
        Err(e) => {
            eprintln!("error: {}", e);
            process::exit(1);
        }
    }
}

fn run(args: &[String]) -> Result<(), String> {
    // Parse arguments manually (no external crates).
    let mut password: Option<String> = None;
    let mut list_mode = false;
    let mut positional: Vec<&str> = Vec::new();

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "-h" | "--help" => {
                print_help();
                return Ok(());
            }
            "-l" | "--list" => {
                list_mode = true;
            }
            "-p" | "--password" => {
                i += 1;
                if i >= args.len() {
                    return Err("--password requires an argument".into());
                }
                password = Some(args[i].clone());
            }
            arg if arg.starts_with("--password=") => {
                password = Some(arg["--password=".len()..].to_owned());
            }
            arg if arg.starts_with("-p") && arg.len() > 2 => {
                password = Some(arg[2..].to_owned());
            }
            arg => {
                positional.push(arg);
            }
        }
        i += 1;
    }

    // Require at least the archive path.
    if positional.is_empty() {
        print_help();
        return Ok(());
    }

    let archive_path = positional[0];

    // Open the archive.
    let file = File::open(archive_path)
        .map_err(|e| format!("cannot open '{}': {}", archive_path, e))?;

    let mut archive = Archive::open(file)
        .map_err(|e| format!("cannot parse archive '{}': {}", archive_path, e))?;

    if let Some(pw) = &password {
        archive.set_password(pw.as_bytes().to_vec());
    }

    // --list mode: print all entries and exit.
    if list_mode {
        let version = match archive.version() {
            RarVersion::V4 => "RAR v4",
            RarVersion::V5 => "RAR v5",
        };
        println!("Archive: {} ({})", archive_path, version);
        println!("Multi-volume: {}", archive.is_multi_volume());
        println!();
        println!("{:>4}  {:>12}  {:>12}  {:>9}  {:>9}  {}", 
            "IDX", "SIZE", "PACKED", "ENC", "SPLIT", "PATH");
        println!("{}", "-".repeat(72));
        for entry in archive.entries() {
            println!("{:>4}  {:>12}  {:>12}  {:>9}  {:>9}  {}",
                entry.index(),
                entry.size(),
                entry.compressed_size(),
                if entry.is_encrypted() { "yes" } else { "no" },
                if entry.is_split() { "yes" } else { "no" },
                entry.path(),
            );
        }
        return Ok(());
    }

    // Require selector, start, length for hex dump mode.
    if positional.len() < 4 {
        return Err(format!(
            "usage: rar-hex [OPTIONS] <ARCHIVE> <SELECTOR> <START> <LENGTH>\n\
             Run 'rar-hex --help' for more information."
        ));
    }

    let selector_str = positional[1];
    let start_str = positional[2];
    let length_str = positional[3];

    let start = parse_number(start_str)
        .map_err(|_| format!("invalid start offset '{}': expected decimal or 0x-prefixed hex", start_str))?;
    let length = parse_number(length_str)
        .map_err(|_| format!("invalid length '{}': expected decimal or 0x-prefixed hex", length_str))?;

    if length == 0 {
        return Err("length must be greater than 0".into());
    }

    // Build the entry selector.
    let selector: EntrySelector = if let Ok(idx) = selector_str.parse::<usize>() {
        EntrySelector::ByIndex(idx)
    } else {
        EntrySelector::ByPath(selector_str)
    };

    // Open the entry reader.
    let mut reader = archive.entry_reader(selector).map_err(|e| match e {
        RarError::FileNotFound(p) => format!("file not found in archive: '{}'", p),
        RarError::IndexOutOfRange { index, count } => {
            format!("index {} out of range (archive has {} entries)", index, count)
        }
        RarError::PasswordRequired => {
            "archive is encrypted; use -p <PASSWORD> to provide a password".into()
        }
        RarError::IncorrectPassword => "incorrect password".into(),
        RarError::UnsupportedCompression(m) => {
            format!("unsupported compression method {:#04x}; only STORE is supported", m)
        }
        other => format!("{}", other),
    })?;

    // Seek to the start position.
    reader.seek(SeekFrom::Start(start))
        .map_err(|e| format!("seek to offset {} failed: {}", start, e))?;

    // Read the requested bytes.
    let mut buf = vec![0u8; length as usize];
    let n = read_exact_or_eof(&mut reader, &mut buf)
        .map_err(|e| format!("read failed: {}", e))?;

    if n == 0 {
        return Err(format!("offset {} is past the end of the entry", start));
    }

    let buf = &buf[..n];

    // Print hex dump.
    print_hex_dump(buf, start);

    Ok(())
}

/// Read up to `buf.len()` bytes, returning the number of bytes actually read.
/// Unlike `read_exact`, this does not error on EOF.
fn read_exact_or_eof<R: Read>(reader: &mut R, buf: &mut [u8]) -> std::io::Result<usize> {
    let mut total = 0;
    while total < buf.len() {
        match reader.read(&mut buf[total..]) {
            Ok(0) => break,
            Ok(n) => total += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(total)
}

/// Print a hex dump of `data` starting at `base_offset`.
///
/// Format:
/// ```text
/// 00000000  52 61 72 21 1a 07 01 00  4f d6 b7 6b 0c 01 05 08  |Rar!....O..k....|
/// ```
fn print_hex_dump(data: &[u8], base_offset: u64) {
    let stdout = std::io::stdout();
    let mut out = stdout.lock();

    for (chunk_idx, chunk) in data.chunks(16).enumerate() {
        let offset = base_offset + (chunk_idx * 16) as u64;

        // Offset column.
        write!(out, "{:08x}  ", offset).unwrap();

        // Hex bytes (two groups of 8).
        for (i, &byte) in chunk.iter().enumerate() {
            if i == 8 {
                write!(out, " ").unwrap();
            }
            write!(out, "{:02x} ", byte).unwrap();
        }

        // Padding if the last chunk is shorter than 16 bytes.
        let padding = 16 - chunk.len();
        for i in 0..padding {
            if chunk.len() + i == 8 {
                write!(out, " ").unwrap();
            }
            write!(out, "   ").unwrap();
        }

        // ASCII column.
        write!(out, " |").unwrap();
        for &byte in chunk {
            let c = if byte.is_ascii_graphic() || byte == b' ' {
                byte as char
            } else {
                '.'
            };
            write!(out, "{}", c).unwrap();
        }
        writeln!(out, "|").unwrap();
    }
}

/// Parse a number that may be decimal or `0x`-prefixed hexadecimal.
fn parse_number(s: &str) -> Result<u64, ()> {
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16).map_err(|_| ())
    } else {
        s.parse::<u64>().map_err(|_| ())
    }
}

fn print_help() {
    println!("rar-hex — read byte ranges from files inside RAR archives");
    println!();
    println!("USAGE:");
    println!("  rar-hex [OPTIONS] <ARCHIVE> <SELECTOR> <START> <LENGTH>");
    println!("  rar-hex --list [OPTIONS] <ARCHIVE>");
    println!();
    println!("ARGUMENTS:");
    println!("  <ARCHIVE>   Path to the RAR archive (.rar file)");
    println!("  <SELECTOR>  Entry selector:");
    println!("                - Integer index (0-based): e.g. 0, 1, 2");
    println!("                - File path: e.g. \"readme.txt\", \"subdir/file.bin\"");
    println!("                  (case-insensitive, forward or backslash separators)");
    println!("  <START>     Byte offset to start reading (decimal or 0x-prefixed hex)");
    println!("  <LENGTH>    Number of bytes to read (decimal or 0x-prefixed hex)");
    println!();
    println!("OPTIONS:");
    println!("  -p, --password <PW>  Password for encrypted archives");
    println!("  -l, --list           List all entries in the archive and exit");
    println!("  -h, --help           Print this help message");
    println!();
    println!("EXAMPLES:");
    println!("  # List all entries in an archive");
    println!("  rar-hex --list archive.rar");
    println!();
    println!("  # Read first 64 bytes of entry 0");
    println!("  rar-hex archive.rar 0 0 64");
    println!();
    println!("  # Read 32 bytes at offset 0x400 from a file by path");
    println!("  rar-hex archive.rar \"readme.txt\" 0x400 32");
    println!();
    println!("  # Read from an encrypted archive with password '1'");
    println!("  rar-hex -p 1 encrypted.rar 0 0 64");
    println!();
    println!("  # Read last 16 bytes (use --list to find the file size first)");
    println!("  rar-hex archive.rar 0 3168633 16");
}
