//! # rar-access
//!
//! A Rust library providing streaming and seekable access to files inside
//! RAR archives (both v4 and v5 formats).
//!
//! ## Features
//!
//! - **RAR v4** (RAR 2.0–4.x): STORE (non-compressed) entries, AES-128
//!   encrypted entries, multi-volume archives.
//! - **RAR v5** (RAR 5.0+): STORE entries, AES-256 encrypted entries.
//! - **Seekable access**: All entry readers implement [`std::io::Read`] and
//!   [`std::io::Seek`], allowing arbitrary byte-range access.
//! - **Streaming**: Entries can be read sequentially without loading the
//!   entire file into memory (for STORE entries).
//!
//! ## Quick start
//!
//! ```rust,no_run
//! use std::fs::File;
//! use std::io::{Read, Seek, SeekFrom};
//! use rar_access::{Archive, EntrySelector};
//!
//! // Open an archive (auto-detects v4 vs v5).
//! let file = File::open("archive.rar").unwrap();
//! let mut archive = Archive::open(file).unwrap();
//!
//! // List all entries.
//! for entry in archive.entries() {
//!     println!("{} ({} bytes)", entry.path(), entry.size());
//! }
//!
//! // Read a specific file by path.
//! let mut reader = archive.entry_reader("readme.txt").unwrap();
//! let mut contents = String::new();
//! reader.read_to_string(&mut contents).unwrap();
//!
//! // Seek to a specific byte range.
//! let mut reader = archive.entry_reader(0usize).unwrap();
//! reader.seek(SeekFrom::Start(1024)).unwrap();
//! let mut buf = [0u8; 512];
//! reader.read_exact(&mut buf).unwrap();
//! ```
//!
//! ## Password-protected archives
//!
//! ```rust,no_run
//! use std::fs::File;
//! use rar_access::Archive;
//!
//! let file = File::open("encrypted.rar").unwrap();
//! let mut archive = Archive::open(file).unwrap();
//! archive.set_password("secret");
//!
//! let mut reader = archive.entry_reader("secret.txt").unwrap();
//! ```

#![warn(missing_docs)]
#![warn(clippy::all)]

pub mod entry;
pub mod error;
pub mod multi_volume;
pub mod v4;
pub mod v5;

pub use entry::{ArchiveEntry, EntrySelector};
pub use error::{RarError, Result};
pub use v4::reader::EntryReader;

use std::io::{Read, Seek, SeekFrom};

use v4::header::RAR4_SIGNATURE;
use v5::header::RAR5_SIGNATURE;

/// A RAR archive that auto-detects the format version (v4 or v5).
///
/// This is the primary entry point for the library.
pub struct Archive<R: Read + Seek> {
    inner: ArchiveInner<R>,
}

enum ArchiveInner<R: Read + Seek> {
    V4(v4::reader::RarV4Archive<R>),
    V5(v5::reader::RarV5Archive<R>),
}

impl<R: Read + Seek> Archive<R> {
    /// Open a RAR archive from a reader, auto-detecting the format version.
    ///
    /// # Errors
    ///
    /// Returns [`RarError::InvalidSignature`] if the reader does not start
    /// with a valid RAR signature.
    pub fn open(mut inner: R) -> Result<Self> {
        let mut sig = [0u8; 8];
        inner.read_exact(&mut sig)?;
        inner.seek(SeekFrom::Start(0))?;

        if sig[..7] == RAR4_SIGNATURE {
            let archive = v4::reader::RarV4Archive::open(inner)?;
            Ok(Archive { inner: ArchiveInner::V4(archive) })
        } else if sig == RAR5_SIGNATURE {
            let archive = v5::reader::RarV5Archive::open(inner)?;
            Ok(Archive { inner: ArchiveInner::V5(archive) })
        } else {
            Err(RarError::InvalidSignature)
        }
    }

    /// Set the password for decrypting encrypted entries.
    pub fn set_password(&mut self, password: impl Into<Vec<u8>>) {
        let pw = password.into();
        match &mut self.inner {
            ArchiveInner::V4(a) => a.set_password(pw),
            ArchiveInner::V5(a) => a.set_password(pw),
        }
    }

    /// Return an iterator over the file entries in the archive.
    pub fn entries(&self) -> impl Iterator<Item = ArchiveEntry<'_>> {
        match &self.inner {
            ArchiveInner::V4(a) => {
                let v: Vec<ArchiveEntry<'_>> = a.entries().collect();
                v.into_iter()
            }
            ArchiveInner::V5(a) => {
                let v: Vec<ArchiveEntry<'_>> = a.entries().collect();
                v.into_iter()
            }
        }
    }

    /// Return the number of file entries in the archive.
    pub fn len(&self) -> usize {
        match &self.inner {
            ArchiveInner::V4(a) => a.len(),
            ArchiveInner::V5(a) => a.len(),
        }
    }

    /// Return `true` if the archive contains no file entries.
    pub fn is_empty(&self) -> bool {
        match &self.inner {
            ArchiveInner::V4(a) => a.is_empty(),
            ArchiveInner::V5(a) => a.is_empty(),
        }
    }

    /// Return `true` if this is a multi-volume archive.
    pub fn is_multi_volume(&self) -> bool {
        match &self.inner {
            ArchiveInner::V4(a) => a.is_multi_volume(),
            ArchiveInner::V5(a) => a.is_multi_volume(),
        }
    }

    /// Return the RAR format version of this archive.
    pub fn version(&self) -> RarVersion {
        match &self.inner {
            ArchiveInner::V4(_) => RarVersion::V4,
            ArchiveInner::V5(_) => RarVersion::V5,
        }
    }

    /// Select a file entry and return a seekable reader for it.
    ///
    /// The `selector` can be:
    /// - A `usize` index (zero-based)
    /// - A `&str` or `&String` path (case-insensitive, forward or backslash separators)
    ///
    /// # Errors
    ///
    /// - [`RarError::FileNotFound`] – no entry matches the selector
    /// - [`RarError::IndexOutOfRange`] – index is out of bounds
    /// - [`RarError::PasswordRequired`] – entry is encrypted and no password is set
    /// - [`RarError::IncorrectPassword`] – the set password is wrong
    /// - [`RarError::UnsupportedCompression`] – entry uses a compressed method
    pub fn entry_reader<'a, S>(&'a mut self, selector: S) -> Result<EntryReader<'a>>
    where
        S: Into<EntrySelector<'a>>,
    {
        let sel = selector.into();
        match &mut self.inner {
            ArchiveInner::V4(a) => a.entry_reader(sel),
            ArchiveInner::V5(a) => a.entry_reader(sel),
        }
    }
}

/// The RAR format version of an archive.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RarVersion {
    /// RAR v4 (RAR 2.0–4.x).
    V4,
    /// RAR v5 (RAR 5.0+).
    V5,
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::io::{Cursor, Read, Seek, SeekFrom};

    use super::*;

    // -----------------------------------------------------------------------
    // Test fixture builders
    // -----------------------------------------------------------------------

    /// CRC16 used in RAR v4 headers (CRC-32 truncated to 16 bits).
    fn crc16_rar4(data: &[u8]) -> u16 {
        let mut crc: u32 = 0xFFFF_FFFF;
        for &b in data {
            crc ^= b as u32;
            for _ in 0..8 {
                if crc & 1 != 0 {
                    crc = (crc >> 1) ^ 0xEDB8_8320;
                } else {
                    crc >>= 1;
                }
            }
        }
        (!crc) as u16
    }

    /// Build a minimal RAR v4 STORE archive with a single file.
    fn build_rar4_store(filename: &str, content: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();

        // RAR4 signature
        out.extend_from_slice(&[0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x00]);

        // Archive header block (type 0x73, no flags, size=13)
        {
            let arch_flags: u16 = 0x0000;
            let arch_size: u16 = 13;
            let reserved: [u8; 6] = [0; 6];
            let mut crc_input = Vec::new();
            crc_input.push(0x73u8);
            crc_input.extend_from_slice(&arch_flags.to_le_bytes());
            crc_input.extend_from_slice(&arch_size.to_le_bytes());
            crc_input.extend_from_slice(&reserved);
            let crc = crc16_rar4(&crc_input);
            out.extend_from_slice(&crc.to_le_bytes());
            out.extend_from_slice(&crc_input);
        }

        // File header block (type 0x74)
        {
            let fname = filename.as_bytes();
            let packed_size = content.len() as u32;
            let unpacked_size = content.len() as u32;
            let file_crc32 = crc32fast::hash(content);
            let file_flags: u16 = 0x8000; // HAS_DATA
            let method: u8 = 0x30; // STORE

            let mut file_body = Vec::new();
            file_body.extend_from_slice(&unpacked_size.to_le_bytes());
            file_body.push(0x00); // os
            file_body.extend_from_slice(&file_crc32.to_le_bytes());
            file_body.extend_from_slice(&0u32.to_le_bytes()); // ftime
            file_body.push(20u8); // required_version
            file_body.push(method);
            file_body.extend_from_slice(&(fname.len() as u16).to_le_bytes());
            file_body.extend_from_slice(&0x20u32.to_le_bytes()); // attributes
            file_body.extend_from_slice(fname);

            // header_size = 7 (common) + len(file_body)
            // Note: ADD_SIZE (4 bytes) is NOT counted in header_size
            let header_size: u16 = 7 + file_body.len() as u16;

            let mut crc_input = Vec::new();
            crc_input.push(0x74u8); // type
            crc_input.extend_from_slice(&file_flags.to_le_bytes());
            crc_input.extend_from_slice(&header_size.to_le_bytes());
            crc_input.extend_from_slice(&packed_size.to_le_bytes()); // ADD_SIZE
            crc_input.extend_from_slice(&file_body);

            let crc = crc16_rar4(&crc_input);
            out.extend_from_slice(&crc.to_le_bytes());
            out.extend_from_slice(&crc_input);
            out.extend_from_slice(content);
        }

        // End-of-archive block (type 0x7B, no flags, size=7)
        {
            let eoa_input: &[u8] = &[0x7Bu8, 0x00, 0x00, 0x07, 0x00];
            let crc = crc16_rar4(eoa_input);
            out.extend_from_slice(&crc.to_le_bytes());
            out.extend_from_slice(eoa_input);
        }

        out
    }

    /// Write a RAR v5 variable-length integer to a buffer.
    fn write_vint(buf: &mut Vec<u8>, mut v: u64) {
        loop {
            let byte = (v & 0x7F) as u8;
            v >>= 7;
            if v == 0 {
                buf.push(byte);
                break;
            } else {
                buf.push(byte | 0x80);
            }
        }
    }

    /// Build a minimal RAR v5 STORE archive with a single file.
    fn build_rar5_store(filename: &str, content: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();

        // RAR5 signature
        out.extend_from_slice(&[0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x01, 0x00]);

        // Archive header block
        {
            let mut header_data = Vec::new();
            write_vint(&mut header_data, 1); // HEADER_TYPE = ArchiveHeader
            write_vint(&mut header_data, 0); // HEADER_FLAGS = 0
            write_vint(&mut header_data, 0); // archive_flags = 0

            let mut block = Vec::new();
            write_vint(&mut block, header_data.len() as u64);
            block.extend_from_slice(&header_data);

            let crc = crc32fast::hash(&block);
            out.extend_from_slice(&crc.to_le_bytes());
            out.extend_from_slice(&block);
        }

        // File header block
        {
            let fname = filename.as_bytes();
            let unpacked_size = content.len() as u64;
            let packed_size = content.len() as u64;
            let file_crc32 = crc32fast::hash(content);

            // Block flags: DATA_AREA (0x0002)
            let block_flags: u64 = 0x0002;
            // File flags: CRC32_PRESENT (0x0004) | UNIX_TIME (0x0002)
            let file_flags: u64 = 0x0004 | 0x0002;

            let mut header_data = Vec::new();
            write_vint(&mut header_data, 2); // HEADER_TYPE = FileHeader
            write_vint(&mut header_data, block_flags);
            // DATA_AREA_SIZE (present because block_flags has DATA_AREA)
            write_vint(&mut header_data, packed_size);

            // File-specific fields
            write_vint(&mut header_data, file_flags);
            write_vint(&mut header_data, unpacked_size);
            write_vint(&mut header_data, 0x20); // attributes
            // mtime (u32, present because UNIX_TIME flag)
            header_data.extend_from_slice(&0u32.to_le_bytes());
            // crc32 (u32, present because CRC32_PRESENT flag)
            header_data.extend_from_slice(&file_crc32.to_le_bytes());
            // compression_info: version=50 (bits 6-11), method=0 (bits 0-5)
            write_vint(&mut header_data, 50 << 6);
            write_vint(&mut header_data, 0); // host_os
            write_vint(&mut header_data, fname.len() as u64);
            header_data.extend_from_slice(fname);

            let mut block = Vec::new();
            write_vint(&mut block, header_data.len() as u64);
            block.extend_from_slice(&header_data);

            let crc = crc32fast::hash(&block);
            out.extend_from_slice(&crc.to_le_bytes());
            out.extend_from_slice(&block);
            out.extend_from_slice(content);
        }

        // End-of-archive block
        {
            let mut header_data = Vec::new();
            write_vint(&mut header_data, 5); // HEADER_TYPE = EndOfArchive
            write_vint(&mut header_data, 0); // HEADER_FLAGS = 0
            write_vint(&mut header_data, 0); // eoa_flags = 0

            let mut block = Vec::new();
            write_vint(&mut block, header_data.len() as u64);
            block.extend_from_slice(&header_data);

            let crc = crc32fast::hash(&block);
            out.extend_from_slice(&crc.to_le_bytes());
            out.extend_from_slice(&block);
        }

        out
    }

    // -----------------------------------------------------------------------
    // RAR v4 tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_rar4_invalid_signature() {
        let data = b"not a rar file at all";
        let result = Archive::open(Cursor::new(data.to_vec()));
        assert!(matches!(result, Err(RarError::InvalidSignature)));
    }

    #[test]
    fn test_rar4_open_store_archive() {
        let content = b"Hello, RAR world!";
        let archive_data = build_rar4_store("hello.txt", content);
        let archive = Archive::open(Cursor::new(archive_data)).unwrap();

        assert_eq!(archive.version(), RarVersion::V4);
        assert_eq!(archive.len(), 1);
        assert!(!archive.is_empty());
        assert!(!archive.is_multi_volume());
    }

    #[test]
    fn test_rar4_entry_metadata() {
        let content = b"Hello, RAR world!";
        let archive_data = build_rar4_store("hello.txt", content);
        let archive = Archive::open(Cursor::new(archive_data)).unwrap();

        let entries: Vec<_> = archive.entries().collect();
        assert_eq!(entries.len(), 1);

        let entry = &entries[0];
        assert_eq!(entry.path(), "hello.txt");
        assert_eq!(entry.size(), content.len() as u64);
        assert_eq!(entry.compressed_size(), content.len() as u64);
        assert!(!entry.is_encrypted());
        assert!(!entry.is_split());
        assert_eq!(entry.index(), 0);
        assert_eq!(entry.compression_method(), "store");
    }

    #[test]
    fn test_rar4_read_by_index() {
        let content = b"Hello, RAR world! This is test content.";
        let archive_data = build_rar4_store("test.txt", content);
        let mut archive = Archive::open(Cursor::new(archive_data)).unwrap();

        let mut reader = archive.entry_reader(0usize).unwrap();
        let mut buf = Vec::new();
        reader.read_to_end(&mut buf).unwrap();
        assert_eq!(buf, content);
    }

    #[test]
    fn test_rar4_read_by_path() {
        let content = b"Content of readme.txt";
        let archive_data = build_rar4_store("readme.txt", content);
        let mut archive = Archive::open(Cursor::new(archive_data)).unwrap();

        let mut reader = archive.entry_reader("readme.txt").unwrap();
        let mut buf = Vec::new();
        reader.read_to_end(&mut buf).unwrap();
        assert_eq!(buf, content);
    }

    #[test]
    fn test_rar4_path_case_insensitive() {
        let content = b"Case insensitive path test";
        let archive_data = build_rar4_store("MyFile.TXT", content);
        let mut archive = Archive::open(Cursor::new(archive_data)).unwrap();

        let mut reader = archive.entry_reader("myfile.txt").unwrap();
        let mut buf = Vec::new();
        reader.read_to_end(&mut buf).unwrap();
        assert_eq!(buf, content);
    }

    #[test]
    fn test_rar4_file_not_found() {
        let content = b"some content";
        let archive_data = build_rar4_store("existing.txt", content);
        let mut archive = Archive::open(Cursor::new(archive_data)).unwrap();

        let result = archive.entry_reader("nonexistent.txt");
        assert!(matches!(result, Err(RarError::FileNotFound(_))));
    }

    #[test]
    fn test_rar4_index_out_of_range() {
        let content = b"some content";
        let archive_data = build_rar4_store("file.txt", content);
        let mut archive = Archive::open(Cursor::new(archive_data)).unwrap();

        let result = archive.entry_reader(99usize);
        assert!(matches!(result, Err(RarError::IndexOutOfRange { .. })));
    }

    #[test]
    fn test_rar4_seek_from_start() {
        let content = b"0123456789abcdefghij";
        let archive_data = build_rar4_store("data.bin", content);
        let mut archive = Archive::open(Cursor::new(archive_data)).unwrap();

        let mut reader = archive.entry_reader(0usize).unwrap();
        reader.seek(SeekFrom::Start(5)).unwrap();
        let mut buf = [0u8; 5];
        reader.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"56789");
    }

    #[test]
    fn test_rar4_seek_from_end() {
        let content = b"0123456789abcdefghij";
        let archive_data = build_rar4_store("data.bin", content);
        let mut archive = Archive::open(Cursor::new(archive_data)).unwrap();

        let mut reader = archive.entry_reader(0usize).unwrap();
        reader.seek(SeekFrom::End(-5)).unwrap();
        let mut buf = [0u8; 5];
        reader.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"fghij");
    }

    #[test]
    fn test_rar4_seek_from_current() {
        let content = b"0123456789abcdefghij";
        let archive_data = build_rar4_store("data.bin", content);
        let mut archive = Archive::open(Cursor::new(archive_data)).unwrap();

        let mut reader = archive.entry_reader(0usize).unwrap();
        let mut buf = [0u8; 5];
        reader.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"01234");

        reader.seek(SeekFrom::Current(5)).unwrap();
        reader.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"abcde");
    }

    #[test]
    fn test_rar4_seek_and_reread() {
        let content = b"Hello, World!";
        let archive_data = build_rar4_store("hello.txt", content);
        let mut archive = Archive::open(Cursor::new(archive_data)).unwrap();

        let mut reader = archive.entry_reader(0usize).unwrap();
        let mut buf = Vec::new();
        reader.read_to_end(&mut buf).unwrap();
        assert_eq!(buf, content);

        reader.seek(SeekFrom::Start(0)).unwrap();
        buf.clear();
        reader.read_to_end(&mut buf).unwrap();
        assert_eq!(buf, content);
    }

    #[test]
    fn test_rar4_partial_read() {
        let content = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        let archive_data = build_rar4_store("alpha.txt", content);
        let mut archive = Archive::open(Cursor::new(archive_data)).unwrap();

        let mut reader = archive.entry_reader(0usize).unwrap();
        let mut result = Vec::new();
        let mut chunk = [0u8; 5];
        loop {
            let n = reader.read(&mut chunk).unwrap();
            if n == 0 {
                break;
            }
            result.extend_from_slice(&chunk[..n]);
        }
        assert_eq!(result, content);
    }

    // -----------------------------------------------------------------------
    // RAR v5 tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_rar5_open_store_archive() {
        let content = b"Hello from RAR v5!";
        let archive_data = build_rar5_store("hello.txt", content);
        let archive = Archive::open(Cursor::new(archive_data)).unwrap();

        assert_eq!(archive.version(), RarVersion::V5);
        assert_eq!(archive.len(), 1);
    }

    #[test]
    fn test_rar5_read_by_path() {
        let content = b"RAR v5 content here";
        let archive_data = build_rar5_store("test.txt", content);
        let mut archive = Archive::open(Cursor::new(archive_data)).unwrap();

        let mut reader = archive.entry_reader("test.txt").unwrap();
        let mut buf = Vec::new();
        reader.read_to_end(&mut buf).unwrap();
        assert_eq!(buf, content);
    }

    #[test]
    fn test_rar5_seek() {
        let content = b"0123456789abcdefghij";
        let archive_data = build_rar5_store("data.bin", content);
        let mut archive = Archive::open(Cursor::new(archive_data)).unwrap();

        let mut reader = archive.entry_reader(0usize).unwrap();
        reader.seek(SeekFrom::Start(10)).unwrap();
        let mut buf = [0u8; 5];
        reader.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"abcde");
    }

    #[test]
    fn test_rar5_entry_metadata() {
        let content = b"RAR v5 metadata test";
        let archive_data = build_rar5_store("meta.txt", content);
        let archive = Archive::open(Cursor::new(archive_data)).unwrap();

        let entries: Vec<_> = archive.entries().collect();
        assert_eq!(entries.len(), 1);

        let entry = &entries[0];
        assert_eq!(entry.path(), "meta.txt");
        assert_eq!(entry.size(), content.len() as u64);
        assert!(!entry.is_encrypted());
        assert_eq!(entry.compression_method(), "store");
    }

    // -----------------------------------------------------------------------
    // Multi-volume tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_multi_volume_reader_single_segment() {
        use crate::multi_volume::MultiVolumeReader;
        use std::io::Write;
        use tempfile::NamedTempFile;

        let mut tmp = NamedTempFile::new().unwrap();
        let data = b"Hello, multi-volume world!";
        tmp.write_all(data).unwrap();
        tmp.flush().unwrap();

        let path = tmp.path().to_path_buf();
        let mut reader = MultiVolumeReader::new(vec![(path, 0, data.len() as u64)]);

        let mut buf = Vec::new();
        reader.read_to_end(&mut buf).unwrap();
        assert_eq!(buf, data);
    }

    #[test]
    fn test_multi_volume_reader_seek() {
        use crate::multi_volume::MultiVolumeReader;
        use std::io::Write;
        use tempfile::NamedTempFile;

        let mut tmp = NamedTempFile::new().unwrap();
        let data = b"0123456789";
        tmp.write_all(data).unwrap();
        tmp.flush().unwrap();

        let path = tmp.path().to_path_buf();
        let mut reader = MultiVolumeReader::new(vec![(path, 0, data.len() as u64)]);

        reader.seek(SeekFrom::Start(5)).unwrap();
        let mut buf = [0u8; 5];
        reader.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"56789");
    }
}

// ---------------------------------------------------------------------------
// Integration tests using real RAR test files
// ---------------------------------------------------------------------------

/// Path to the test fixtures directory (relative to the crate root).
#[cfg(test)]
const TEST_FILES_DIR: &str = "../rar_test_files";

#[cfg(test)]
mod integration_tests {
    use std::fs::File;
    use std::io::{Read, Seek, SeekFrom};
    use std::path::Path;

    use super::*;

    /// Return the path to a test fixture file.
    fn fixture(name: &str) -> std::path::PathBuf {
        Path::new(TEST_FILES_DIR).join(name)
    }

    /// Return `true` if the test fixture files are available.
    fn fixtures_available() -> bool {
        fixture("store_nopass.rar").exists()
    }

    // -----------------------------------------------------------------------
    // store_nopass.rar — RAR v5, single file, no password
    // Contains: store_pass_1.rar (3,168,991 bytes)
    // -----------------------------------------------------------------------

    #[test]
    fn test_real_store_nopass_open() {
        if !fixtures_available() { return; }
        let f = File::open(fixture("store_nopass.rar")).unwrap();
        let archive = Archive::open(f).unwrap();
        assert_eq!(archive.version(), RarVersion::V5);
        assert_eq!(archive.len(), 1);
        assert!(!archive.is_empty());
        assert!(!archive.is_multi_volume());
    }

    #[test]
    fn test_real_store_nopass_entry_metadata() {
        if !fixtures_available() { return; }
        let f = File::open(fixture("store_nopass.rar")).unwrap();
        let archive = Archive::open(f).unwrap();
        let entries: Vec<_> = archive.entries().collect();
        assert_eq!(entries.len(), 1);
        let entry = &entries[0];
        assert_eq!(entry.path(), "store_pass_1.rar");
        assert_eq!(entry.size(), 3168991);
        assert!(!entry.is_encrypted());
        assert!(!entry.is_split());
        assert_eq!(entry.compression_method(), "store");
    }

    #[test]
    fn test_real_store_nopass_read_content() {
        if !fixtures_available() { return; }
        let f = File::open(fixture("store_nopass.rar")).unwrap();
        let mut archive = Archive::open(f).unwrap();
        let mut reader = archive.entry_reader(0usize).unwrap();

        // The content is another RAR file, so it should start with the RAR v5 signature.
        let mut buf = [0u8; 8];
        reader.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, &[0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x01, 0x00],
            "inner file should be a RAR v5 archive");
    }

    #[test]
    fn test_real_store_nopass_seek() {
        if !fixtures_available() { return; }
        let f = File::open(fixture("store_nopass.rar")).unwrap();
        let mut archive = Archive::open(f).unwrap();
        let mut reader = archive.entry_reader(0usize).unwrap();

        // Seek to position 4 and read 4 bytes (should be "!..." part of RAR sig).
        reader.seek(SeekFrom::Start(4)).unwrap();
        let mut buf = [0u8; 4];
        reader.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, &[0x1A, 0x07, 0x01, 0x00]);
    }

    #[test]
    fn test_real_store_nopass_seek_from_end() {
        if !fixtures_available() { return; }
        let f = File::open(fixture("store_nopass.rar")).unwrap();
        let mut archive = Archive::open(f).unwrap();
        let mut reader = archive.entry_reader(0usize).unwrap();

        // Read the last 8 bytes.
        reader.seek(SeekFrom::End(-8)).unwrap();
        let mut buf = [0u8; 8];
        reader.read_exact(&mut buf).unwrap();
        // Just verify we can read without error.
        assert_eq!(buf.len(), 8);
    }

    #[test]
    fn test_real_store_nopass_read_by_path() {
        if !fixtures_available() { return; }
        let f = File::open(fixture("store_nopass.rar")).unwrap();
        let mut archive = Archive::open(f).unwrap();
        let mut reader = archive.entry_reader("store_pass_1.rar").unwrap();
        let mut buf = [0u8; 8];
        reader.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, &[0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x01, 0x00]);
    }

    #[test]
    fn test_real_store_nopass_file_not_found() {
        if !fixtures_available() { return; }
        let f = File::open(fixture("store_nopass.rar")).unwrap();
        let mut archive = Archive::open(f).unwrap();
        let result = archive.entry_reader("nonexistent.txt");
        assert!(matches!(result, Err(RarError::FileNotFound(_))));
    }

    #[test]
    fn test_real_store_nopass_password_not_required() {
        if !fixtures_available() { return; }
        let f = File::open(fixture("store_nopass.rar")).unwrap();
        let mut archive = Archive::open(f).unwrap();
        // Should work without a password.
        let result = archive.entry_reader(0usize);
        assert!(result.is_ok());
    }

    // -----------------------------------------------------------------------
    // store_pass_1.rar — RAR v5, single file, password="1"
    // Contains: The Great Ideas of Philosophy, 2nd Edition.pdf (3,168,649 bytes)
    // -----------------------------------------------------------------------

    #[test]
    fn test_real_store_pass_open() {
        if !fixtures_available() { return; }
        let f = File::open(fixture("store_pass_1.rar")).unwrap();
        let archive = Archive::open(f).unwrap();
        assert_eq!(archive.version(), RarVersion::V5);
        assert_eq!(archive.len(), 1);
        assert!(!archive.is_multi_volume());
    }

    #[test]
    fn test_real_store_pass_entry_metadata() {
        if !fixtures_available() { return; }
        let f = File::open(fixture("store_pass_1.rar")).unwrap();
        let archive = Archive::open(f).unwrap();
        let entries: Vec<_> = archive.entries().collect();
        assert_eq!(entries.len(), 1);
        let entry = &entries[0];
        assert_eq!(entry.path(), "The Great Ideas of Philosophy, 2nd Edition.pdf");
        assert_eq!(entry.size(), 3168649);
        assert!(entry.is_encrypted());
        assert!(!entry.is_split());
    }

    #[test]
    fn test_real_store_pass_requires_password() {
        if !fixtures_available() { return; }
        let f = File::open(fixture("store_pass_1.rar")).unwrap();
        let mut archive = Archive::open(f).unwrap();
        let result = archive.entry_reader(0usize);
        assert!(matches!(result, Err(RarError::PasswordRequired)));
    }

    #[test]
    fn test_real_store_pass_correct_password() {
        if !fixtures_available() { return; }
        let f = File::open(fixture("store_pass_1.rar")).unwrap();
        let mut archive = Archive::open(f).unwrap();
        archive.set_password("1");
        let mut reader = archive.entry_reader(0usize).unwrap();

        // The PDF should start with %PDF
        let mut buf = [0u8; 4];
        reader.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"%PDF", "decrypted content should be a PDF");
    }

    #[test]
    fn test_real_store_pass_read_full_size() {
        if !fixtures_available() { return; }
        let f = File::open(fixture("store_pass_1.rar")).unwrap();
        let mut archive = Archive::open(f).unwrap();
        archive.set_password("1");
        let mut reader = archive.entry_reader(0usize).unwrap();

        // Read the entire file and verify size.
        let mut buf = Vec::new();
        reader.read_to_end(&mut buf).unwrap();
        assert_eq!(buf.len(), 3168649);
        assert_eq!(&buf[..4], b"%PDF");
    }

    #[test]
    fn test_real_store_pass_seek_and_read() {
        if !fixtures_available() { return; }
        let f = File::open(fixture("store_pass_1.rar")).unwrap();
        let mut archive = Archive::open(f).unwrap();
        archive.set_password("1");
        let mut reader = archive.entry_reader(0usize).unwrap();

        // Seek to position 1024 and read 8 bytes.
        reader.seek(SeekFrom::Start(1024)).unwrap();
        let mut buf = [0u8; 8];
        reader.read_exact(&mut buf).unwrap();
        // Just verify we can seek and read without error.
        assert_eq!(buf.len(), 8);
    }

    #[test]
    fn test_real_store_pass_seek_from_end() {
        if !fixtures_available() { return; }
        let f = File::open(fixture("store_pass_1.rar")).unwrap();
        let mut archive = Archive::open(f).unwrap();
        archive.set_password("1");
        let mut reader = archive.entry_reader(0usize).unwrap();

        // Seek to 4 bytes before the end and read.
        reader.seek(SeekFrom::End(-4)).unwrap();
        let mut buf = [0u8; 4];
        reader.read_exact(&mut buf).unwrap();
        // PDF files end with %%EOF (or similar).
        assert_eq!(buf.len(), 4);
    }

    // -----------------------------------------------------------------------
    // store_multi.part1.rar — RAR v5, multi-volume (4 parts), no password
    // Contains: The Great Ideas of Philosophy, 2nd Edition.pdf (3,168,649 bytes, split)
    // -----------------------------------------------------------------------

    #[test]
    fn test_real_store_multi_open() {
        if !fixtures_available() { return; }
        let f = File::open(fixture("store_multi.part1.rar")).unwrap();
        let archive = Archive::open(f).unwrap();
        assert_eq!(archive.version(), RarVersion::V5);
        assert_eq!(archive.len(), 1);
        assert!(archive.is_multi_volume());
    }

    #[test]
    fn test_real_store_multi_entry_metadata() {
        if !fixtures_available() { return; }
        let f = File::open(fixture("store_multi.part1.rar")).unwrap();
        let archive = Archive::open(f).unwrap();
        let entries: Vec<_> = archive.entries().collect();
        assert_eq!(entries.len(), 1);
        let entry = &entries[0];
        assert_eq!(entry.path(), "The Great Ideas of Philosophy, 2nd Edition.pdf");
        assert_eq!(entry.size(), 3168649);
        assert!(!entry.is_encrypted());
        assert!(entry.is_split());
    }

    #[test]
    fn test_real_store_multi_read_first_part() {
        if !fixtures_available() { return; }
        let f = File::open(fixture("store_multi.part1.rar")).unwrap();
        let mut archive = Archive::open(f).unwrap();
        let mut reader = archive.entry_reader(0usize).unwrap();

        // The first part should start with %PDF.
        let mut buf = [0u8; 4];
        reader.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"%PDF", "first part should start with PDF header");
    }

    #[test]
    fn test_real_store_multi_resolve_volumes() {
        if !fixtures_available() { return; }
        use crate::multi_volume::resolve_volumes;
        let first = fixture("store_multi.part1.rar");
        let volumes = resolve_volumes(&first).unwrap();
        assert_eq!(volumes.len(), 4, "should find all 4 volumes");
        assert!(volumes[0].ends_with("store_multi.part1.rar"));
        assert!(volumes[1].ends_with("store_multi.part2.rar"));
        assert!(volumes[2].ends_with("store_multi.part3.rar"));
        assert!(volumes[3].ends_with("store_multi.part4.rar"));
    }

    // -----------------------------------------------------------------------
    // store_multi_pass1.part1.rar — RAR v5, multi-volume (4 parts), password="1"
    // Contains: The Great Ideas of Philosophy, 2nd Edition.pdf (3,168,649 bytes, split+encrypted)
    // -----------------------------------------------------------------------

    #[test]
    fn test_real_store_multi_pass_open() {
        if !fixtures_available() { return; }
        let f = File::open(fixture("store_multi_pass1.part1.rar")).unwrap();
        let archive = Archive::open(f).unwrap();
        assert_eq!(archive.version(), RarVersion::V5);
        assert_eq!(archive.len(), 1);
        assert!(archive.is_multi_volume());
    }

    #[test]
    fn test_real_store_multi_pass_entry_metadata() {
        if !fixtures_available() { return; }
        let f = File::open(fixture("store_multi_pass1.part1.rar")).unwrap();
        let archive = Archive::open(f).unwrap();
        let entries: Vec<_> = archive.entries().collect();
        assert_eq!(entries.len(), 1);
        let entry = &entries[0];
        assert_eq!(entry.path(), "The Great Ideas of Philosophy, 2nd Edition.pdf");
        assert_eq!(entry.size(), 3168649);
        assert!(entry.is_encrypted());
        assert!(entry.is_split());
    }

    #[test]
    fn test_real_store_multi_pass_requires_password() {
        if !fixtures_available() { return; }
        let f = File::open(fixture("store_multi_pass1.part1.rar")).unwrap();
        let mut archive = Archive::open(f).unwrap();
        let result = archive.entry_reader(0usize);
        assert!(matches!(result, Err(RarError::PasswordRequired)));
    }

    #[test]
    fn test_real_store_multi_pass_resolve_volumes() {
        if !fixtures_available() { return; }
        use crate::multi_volume::resolve_volumes;
        let first = fixture("store_multi_pass1.part1.rar");
        let volumes = resolve_volumes(&first).unwrap();
        assert_eq!(volumes.len(), 4, "should find all 4 volumes");
        assert!(volumes[0].ends_with("store_multi_pass1.part1.rar"));
        assert!(volumes[1].ends_with("store_multi_pass1.part2.rar"));
        assert!(volumes[2].ends_with("store_multi_pass1.part3.rar"));
        assert!(volumes[3].ends_with("store_multi_pass1.part4.rar"));
    }
}
