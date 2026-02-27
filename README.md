# rar-stream / rar-access

A Rust library providing **streaming and seekable access** to files inside RAR archives (both v4 and v5 formats).

## Features

- **RAR v4** (RAR 2.0–4.x): STORE (non-compressed) entries, AES-128 encrypted entries, multi-volume archives
- **RAR v5** (RAR 5.0+): STORE entries, AES-256 encrypted entries
- **Seekable access**: All entry readers implement `Read + Seek`, allowing arbitrary byte-range access
- **Streaming**: STORE entries are read directly from the archive file without buffering
- **Auto-detection**: `Archive::open()` automatically detects RAR v4 vs v5 format

## Quick start

```rust
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use rar_access::{Archive, EntrySelector};

// Open an archive (auto-detects v4 vs v5).
let file = File::open("archive.rar").unwrap();
let mut archive = Archive::open(file).unwrap();

// List all entries.
for entry in archive.entries() {
    println!("{} ({} bytes, {})", entry.path(), entry.size(), entry.compression_method());
}

// Read a specific file by path.
let mut reader = archive.entry_reader("readme.txt").unwrap();
let mut contents = String::new();
reader.read_to_string(&mut contents).unwrap();

// Seek to a specific byte range.
let mut reader = archive.entry_reader(0usize).unwrap();
reader.seek(SeekFrom::Start(1024)).unwrap();
let mut buf = [0u8; 512];
reader.read_exact(&mut buf).unwrap();
```

## Password-protected archives

```rust
use std::fs::File;
use rar_access::Archive;

let file = File::open("encrypted.rar").unwrap();
let mut archive = Archive::open(file).unwrap();
archive.set_password("secret");

let mut reader = archive.entry_reader("secret.txt").unwrap();
```

## Entry selection

Entries can be selected by:
- **Index**: `archive.entry_reader(0usize)` — zero-based
- **Path**: `archive.entry_reader("subdir/file.txt")` — case-insensitive, forward or backslash separators

## Project structure

```
rar-access/
├── Cargo.toml
└── src/
    ├── lib.rs           # Public API + Archive auto-detector + tests
    ├── error.rs         # RarError enum + Result type alias
    ├── entry.rs         # ArchiveEntry, EntrySelector
    ├── multi_volume.rs  # MultiVolumeReader (spans multiple .rar/.r00/... files)
    ├── v4/
    │   ├── mod.rs
    │   ├── header.rs    # RAR v4 block parser
    │   └── reader.rs    # RarV4Archive, EntryReader, StoreReader, InMemoryReader
    └── v5/
        ├── mod.rs
        ├── header.rs    # RAR v5 vint parser, block parser, EncryptionParams
        └── reader.rs    # RarV5Archive
```

## Supported features

| Feature | RAR v4 | RAR v5 |
|---------|--------|--------|
| STORE (no compression) | ✅ | ✅ |
| AES encryption | ✅ AES-128 | ✅ AES-256 |
| Multi-volume archives | ✅ | ✅ (detection) |
| Seekable reads | ✅ | ✅ |
| CRC32 verification | ✅ | ✅ |
| BLAKE2sp verification | — | ✅ |
| Compressed entries | ❌ | ❌ |

> **Note**: Compressed entries (methods other than STORE) return `RarError::UnsupportedCompression`.
> RAR compression is proprietary and requires a licensed implementation.

## Dependencies

| Crate | Purpose |
|-------|---------|
| `crc32fast` | CRC32 verification |
| `blake2` | BLAKE2s-256 checksums (RAR v5) |
| `aes` + `cbc` | AES-128/256-CBC decryption |
| `sha1` | RAR v4 KDF |
| `sha2` + `pbkdf2` + `hmac` | RAR v5 PBKDF2 KDF |
| `byteorder` | Little-endian field reading |
| `bitflags` | Archive/file flag fields |
| `thiserror` | Ergonomic error types |

## License

Licensed under either of:
- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.
