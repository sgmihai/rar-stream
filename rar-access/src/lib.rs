//! # rar-access
//!
//! A Rust library providing streaming and seekable access to files inside
//! RAR archives (both v4 and v5 formats), backed by the
//! [`rar-stream`](https://github.com/doom-fish/rar-stream) library for
//! full decompression support.
//!
//! ## Features
//!
//! - **RAR v4** (RAR 2.0–4.x): STORE, LZSS, PPMd, AES-128 encryption
//! - **RAR v5** (RAR 5.0+): STORE, LZSS + filters, AES-256 encryption
//! - **Seekable access**: All entry readers implement [`std::io::Read`] and
//!   [`std::io::Seek`], allowing arbitrary byte-range access
//! - **HTTP sources**: Read archives directly from HTTP/HTTPS URLs using
//!   range requests — no need to download the entire file
//! - **Multi-volume archives**: Automatically stitches split archives
//!
//! ## Quick start — local file
//!
//! ```rust,no_run
//! use std::io::{Read, Seek, SeekFrom};
//! use rar_access::Archive;
//!
//! let mut archive = Archive::open_path("archive.rar").unwrap();
//!
//! for entry in archive.entries() {
//!     println!("{} ({} bytes)", entry.name(), entry.size());
//! }
//!
//! // Read a file by path.
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
//! ## Quick start — HTTP source
//!
//! ```rust,no_run
//! use rar_access::{Archive, HttpFileMedia};
//!
//! let media = HttpFileMedia::new("https://example.com/archive.rar").unwrap();
//! let mut archive = Archive::open_media(media).unwrap();
//!
//! let mut reader = archive.entry_reader("video.mkv").unwrap();
//! // Seek directly to byte 1_000_000 — only that range is fetched via HTTP
//! use std::io::{Read, Seek, SeekFrom};
//! reader.seek(SeekFrom::Start(1_000_000)).unwrap();
//! let mut buf = vec![0u8; 65536];
//! reader.read_exact(&mut buf).unwrap();
//! ```
//!
//! ## Password-protected archives
//!
//! ```rust,no_run
//! use rar_access::Archive;
//!
//! let mut archive = Archive::open_path("encrypted.rar").unwrap();
//! archive.set_password("secret");
//!
//! let mut reader = archive.entry_reader("secret.txt").unwrap();
//! ```

#![warn(clippy::all)]

pub mod error;
pub mod http_media;

pub use error::{RarError, Result};
pub use http_media::HttpFileMedia;

use std::io::{self, Read, Seek, SeekFrom};
use std::path::Path;
use std::sync::Arc;

use rar_stream::{FileMedia, InnerFile, LocalFileMedia, ParseOptions, RarFilesPackage, ReadInterval};
use tokio::runtime::Runtime;

// ---------------------------------------------------------------------------
// Archive
// ---------------------------------------------------------------------------

/// A RAR archive opened from a local file, HTTP URL, or any [`FileMedia`] source.
///
/// This is the primary entry point for the library.
pub struct Archive {
    /// Parsed file entries (directories excluded).
    files: Vec<InnerFile>,
    /// Optional password for encrypted entries.
    password: Option<String>,
    /// The media volumes (kept for re-parsing with password).
    volumes: Vec<Arc<dyn FileMedia>>,
    /// Tokio runtime for bridging async rar-stream calls to sync.
    rt: Arc<Runtime>,
}

impl Archive {
    /// Open a RAR archive from a local file path.
    ///
    /// For multi-volume archives, pass the first volume (e.g. `archive.part1.rar`
    /// or `archive.rar`). The library will automatically discover and read
    /// subsequent volumes in the same directory.
    pub fn open_path(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        // Discover multi-volume siblings.
        let volume_paths = discover_volumes(path)?;
        let volumes: Vec<Arc<dyn FileMedia>> = volume_paths
            .iter()
            .map(|p| -> Result<Arc<dyn FileMedia>> {
                Ok(Arc::new(LocalFileMedia::new(p.to_str().unwrap_or("")).map_err(RarError::Io)?))
            })
            .collect::<Result<_>>()?;

        let rt = Arc::new(
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|e| RarError::Backend(e.to_string()))?,
        );

        let files = rt.block_on(parse_package(volumes.clone(), None))?;

        Ok(Archive { files, password: None, volumes, rt })
    }

    /// Open a RAR archive from any [`FileMedia`] source (local file, HTTP, etc.).
    ///
    /// For multi-volume archives, use [`Archive::open_volumes`] instead.
    pub fn open_media<M: FileMedia + 'static>(media: M) -> Result<Self> {
        let rt = Arc::new(
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|e| RarError::Backend(e.to_string()))?,
        );

        let volumes: Vec<Arc<dyn FileMedia>> = vec![Arc::new(media)];
        let files = rt.block_on(parse_package(volumes.clone(), None))?;

        Ok(Archive { files, password: None, volumes, rt })
    }

    /// Open a multi-volume RAR archive from an ordered list of [`FileMedia`] sources.
    ///
    /// Volumes must be provided in order (part1, part2, ...).
    pub fn open_volumes(volumes: Vec<Arc<dyn FileMedia>>) -> Result<Self> {
        let rt = Arc::new(
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|e| RarError::Backend(e.to_string()))?,
        );

        let files = rt.block_on(parse_package(volumes.clone(), None))?;

        Ok(Archive { files, password: None, volumes, rt })
    }

    /// Set the password for decrypting encrypted entries.
    ///
    /// This re-parses the archive with the password so that encrypted file
    /// metadata and data can be accessed.
    pub fn set_password(&mut self, password: impl Into<String>) {
        let pw = password.into();
        self.password = Some(pw.clone());
        // Re-parse with the password so rar-stream can decrypt file headers.
        if let Ok(files) = self.rt.block_on(parse_package(self.volumes.clone(), Some(pw))) {
            self.files = files;
        }
    }

    /// Return an iterator over the file entries in the archive.
    pub fn entries(&self) -> impl Iterator<Item = EntryInfo<'_>> {
        self.files.iter().enumerate().map(|(i, f)| EntryInfo {
            inner: f,
            index: i,
        })
    }

    /// Return the number of file entries in the archive.
    pub fn len(&self) -> usize {
        self.files.len()
    }

    /// Return `true` if the archive contains no file entries.
    pub fn is_empty(&self) -> bool {
        self.files.is_empty()
    }

    /// Select a file entry and return a seekable reader for it.
    ///
    /// The `selector` can be:
    /// - A `usize` index (zero-based)
    /// - A `&str` or `&String` path (case-insensitive, forward or backslash separators)
    ///
    /// # Errors
    ///
    /// - [`RarError::FileNotFound`] — no entry matches the selector
    /// - [`RarError::IndexOutOfRange`] — index is out of bounds
    /// - [`RarError::PasswordRequired`] — entry is encrypted and no password is set
    /// - [`RarError::IncorrectPassword`] — the set password is wrong
    pub fn entry_reader<'a, S>(&'a self, selector: S) -> Result<EntryReader<'a>>
    where
        S: Into<EntrySelector<'a>>,
    {
        let sel = selector.into();
        let (idx, file) = self.find_entry(sel)?;

        if file.is_encrypted() && self.password.is_none() {
            return Err(RarError::PasswordRequired);
        }

        Ok(EntryReader {
            file,
            pos: 0,
            rt: Arc::clone(&self.rt),
            _index: idx,
        })
    }

    // -----------------------------------------------------------------------
    // Private helpers
    // -----------------------------------------------------------------------

    fn find_entry(&self, selector: EntrySelector<'_>) -> Result<(usize, &InnerFile)> {
        match selector {
            EntrySelector::ByIndex(i) => {
                self.files
                    .get(i)
                    .map(|f| (i, f))
                    .ok_or_else(|| RarError::IndexOutOfRange {
                        index: i,
                        count: self.files.len(),
                    })
            }
            EntrySelector::ByPath(path) => {
                let normalized = normalize_path(path);
                self.files
                    .iter()
                    .enumerate()
                    .find(|(_, f)| normalize_path(&f.name) == normalized)
                    .ok_or_else(|| RarError::FileNotFound(path.to_owned()))
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Async helpers
// ---------------------------------------------------------------------------

async fn parse_package(
    volumes: Vec<Arc<dyn FileMedia>>,
    password: Option<String>,
) -> Result<Vec<InnerFile>> {
    let package = RarFilesPackage::new(volumes);
    let opts = ParseOptions {
        password,
        ..Default::default()
    };
    let files = package.parse(opts).await.map_err(RarError::from)?;
    // Filter out directories (zero-length entries with trailing slash).
    let files = files
        .into_iter()
        .filter(|f| !f.name.ends_with('/') && !f.name.ends_with('\\'))
        .collect();
    Ok(files)
}

// ---------------------------------------------------------------------------
// Volume discovery
// ---------------------------------------------------------------------------

/// Discover all volumes of a multi-volume archive starting from `first`.
fn discover_volumes(first: &Path) -> Result<Vec<std::path::PathBuf>> {
    let mut volumes = vec![first.to_path_buf()];

    let ext = first
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_lowercase();

    if ext != "rar" {
        return Ok(volumes);
    }

    let stem = first
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("");
    let dir = first.parent().unwrap_or(Path::new("."));

    // New-style: archive.part1.rar, archive.part2.rar, ...
    if let Some(part_num) = parse_part_number(stem) {
        let base = &stem[..stem.rfind('.').unwrap_or(stem.len())];
        let mut n = part_num + 1;
        loop {
            let next = dir.join(format!("{base}.part{n}.rar"));
            if next.exists() {
                volumes.push(next);
                n += 1;
            } else {
                break;
            }
        }
        return Ok(volumes);
    }

    // Old-style: archive.rar, archive.r00, archive.r01, ...
    let letters = b"rstuvwxyz";
    'outer: for &letter in letters.iter() {
        for i in 0u32..100 {
            let next = dir.join(format!("{stem}.{}{i:02}", letter as char));
            if next.exists() {
                volumes.push(next);
            } else if i == 0 {
                break 'outer;
            } else {
                break;
            }
        }
    }

    Ok(volumes)
}

fn parse_part_number(stem: &str) -> Option<u32> {
    let dot_pos = stem.rfind('.')?;
    let suffix = &stem[dot_pos + 1..];
    if suffix.starts_with("part") {
        suffix[4..].parse::<u32>().ok()
    } else {
        None
    }
}

// ---------------------------------------------------------------------------
// EntrySelector
// ---------------------------------------------------------------------------

/// Selects a file entry within an archive.
#[derive(Debug, Clone)]
pub enum EntrySelector<'a> {
    /// Select by zero-based index.
    ByIndex(usize),
    /// Select by relative path (case-insensitive, forward or backslash separators).
    ByPath(&'a str),
}

impl<'a> From<usize> for EntrySelector<'a> {
    fn from(i: usize) -> Self {
        EntrySelector::ByIndex(i)
    }
}

impl<'a> From<&'a str> for EntrySelector<'a> {
    fn from(s: &'a str) -> Self {
        EntrySelector::ByPath(s)
    }
}

impl<'a> From<&'a String> for EntrySelector<'a> {
    fn from(s: &'a String) -> Self {
        EntrySelector::ByPath(s.as_str())
    }
}

// ---------------------------------------------------------------------------
// EntryInfo
// ---------------------------------------------------------------------------

/// Metadata about a single file entry in an archive.
pub struct EntryInfo<'a> {
    inner: &'a InnerFile,
    index: usize,
}

impl<'a> EntryInfo<'a> {
    /// The relative path of the file within the archive.
    pub fn name(&self) -> &str {
        &self.inner.name
    }

    /// The uncompressed size of the file in bytes.
    pub fn size(&self) -> u64 {
        self.inner.length
    }

    /// Whether the file is encrypted.
    pub fn is_encrypted(&self) -> bool {
        self.inner.is_encrypted()
    }

    /// Whether the file uses compression (not STORE).
    pub fn is_compressed(&self) -> bool {
        self.inner.is_compressed()
    }

    /// Whether the file is split across multiple volumes.
    pub fn is_split(&self) -> bool {
        self.inner.chunk_count() > 1
    }

    /// The zero-based index of this entry in the archive.
    pub fn index(&self) -> usize {
        self.index
    }
}

// ---------------------------------------------------------------------------
// EntryReader
// ---------------------------------------------------------------------------

/// A seekable reader for a single file entry within a RAR archive.
///
/// Implements both [`Read`] and [`Seek`], allowing arbitrary byte-range access.
///
/// For STORE (uncompressed, unencrypted) entries, reads are performed directly
/// against the underlying media (file or HTTP) — only the requested bytes are
/// fetched.
///
/// For compressed or encrypted entries, the first read triggers full
/// decompression/decryption; the result is cached by `rar-stream` so
/// subsequent seeks and reads are O(1).
pub struct EntryReader<'a> {
    file: &'a InnerFile,
    pos: u64,
    rt: Arc<Runtime>,
    _index: usize,
}

impl<'a> EntryReader<'a> {
    /// Return the uncompressed size of the entry in bytes.
    pub fn size(&self) -> u64 {
        self.file.length
    }
}

impl<'a> Read for EntryReader<'a> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let len = self.file.length;
        if self.pos >= len {
            return Ok(0);
        }

        let remaining = len - self.pos;
        let to_read = (buf.len() as u64).min(remaining);
        let end = self.pos + to_read - 1;

        // For encrypted or compressed files, use read_decompressed() which
        // handles decryption and decompression, then slice the result.
        // For plain STORE files, use read_range() for efficient range reads.
        let data = if self.file.is_encrypted() || self.file.is_compressed() {
            let all = self
                .rt
                .block_on(self.file.read_decompressed())
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
            let start = self.pos as usize;
            let end_idx = (end + 1) as usize;
            all[start..end_idx.min(all.len())].to_vec()
        } else {
            let interval = ReadInterval {
                start: self.pos,
                end,
            };
            self.rt
                .block_on(self.file.read_range(interval))
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?
        };

        let n = data.len().min(buf.len());
        buf[..n].copy_from_slice(&data[..n]);
        self.pos += n as u64;
        Ok(n)
    }
}

impl<'a> Seek for EntryReader<'a> {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let len = self.file.length as i64;
        let new_pos = match pos {
            SeekFrom::Start(n) => n as i64,
            SeekFrom::End(n) => len + n,
            SeekFrom::Current(n) => self.pos as i64 + n,
        };

        if new_pos < 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "seek before start of entry",
            ));
        }
        if new_pos > len {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "seek past end of entry",
            ));
        }

        self.pos = new_pos as u64;
        Ok(self.pos)
    }
}

// ---------------------------------------------------------------------------
// Path normalization
// ---------------------------------------------------------------------------

fn normalize_path(path: &str) -> String {
    path.replace('\\', "/")
        .trim_start_matches('/')
        .to_lowercase()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::io::{Read, Seek, SeekFrom};
    use std::path::Path;

    use super::*;

    /// Path to the test fixtures directory.
    const TEST_FILES_DIR: &str = "../rar_test_files";

    fn fixture(name: &str) -> std::path::PathBuf {
        Path::new(TEST_FILES_DIR).join(name)
    }

    fn fixtures_available() -> bool {
        fixture("store_nopass.rar").exists()
    }

    // -----------------------------------------------------------------------
    // store_nopass.rar — RAR v5, single file, no password
    // -----------------------------------------------------------------------

    #[test]
    fn test_store_nopass_open() {
        if !fixtures_available() { return; }
        let archive = Archive::open_path(fixture("store_nopass.rar")).unwrap();
        assert_eq!(archive.len(), 1);
        assert!(!archive.is_empty());
    }

    #[test]
    fn test_store_nopass_entry_metadata() {
        if !fixtures_available() { return; }
        let archive = Archive::open_path(fixture("store_nopass.rar")).unwrap();
        let entries: Vec<_> = archive.entries().collect();
        assert_eq!(entries.len(), 1);
        let entry = &entries[0];
        assert_eq!(entry.name(), "store_pass_1.rar");
        assert_eq!(entry.size(), 3168991);
        assert!(!entry.is_encrypted());
        assert_eq!(entry.index(), 0);
    }

    #[test]
    fn test_store_nopass_read_content() {
        if !fixtures_available() { return; }
        let archive = Archive::open_path(fixture("store_nopass.rar")).unwrap();
        let mut reader = archive.entry_reader(0usize).unwrap();
        let mut buf = [0u8; 8];
        reader.read_exact(&mut buf).unwrap();
        // Inner file is another RAR v5 archive.
        assert_eq!(&buf, &[0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x01, 0x00]);
    }

    #[test]
    fn test_store_nopass_seek_from_start() {
        if !fixtures_available() { return; }
        let archive = Archive::open_path(fixture("store_nopass.rar")).unwrap();
        let mut reader = archive.entry_reader(0usize).unwrap();
        reader.seek(SeekFrom::Start(4)).unwrap();
        let mut buf = [0u8; 4];
        reader.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, &[0x1A, 0x07, 0x01, 0x00]);
    }

    #[test]
    fn test_store_nopass_seek_from_end() {
        if !fixtures_available() { return; }
        let archive = Archive::open_path(fixture("store_nopass.rar")).unwrap();
        let mut reader = archive.entry_reader(0usize).unwrap();
        reader.seek(SeekFrom::End(-8)).unwrap();
        let mut buf = [0u8; 8];
        reader.read_exact(&mut buf).unwrap();
        assert_eq!(buf.len(), 8);
    }

    #[test]
    fn test_store_nopass_read_by_path() {
        if !fixtures_available() { return; }
        let archive = Archive::open_path(fixture("store_nopass.rar")).unwrap();
        let mut reader = archive.entry_reader("store_pass_1.rar").unwrap();
        let mut buf = [0u8; 8];
        reader.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, &[0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x01, 0x00]);
    }

    #[test]
    fn test_store_nopass_path_case_insensitive() {
        if !fixtures_available() { return; }
        let archive = Archive::open_path(fixture("store_nopass.rar")).unwrap();
        let result = archive.entry_reader("STORE_PASS_1.RAR");
        assert!(result.is_ok());
    }

    #[test]
    fn test_store_nopass_file_not_found() {
        if !fixtures_available() { return; }
        let archive = Archive::open_path(fixture("store_nopass.rar")).unwrap();
        let result = archive.entry_reader("nonexistent.txt");
        assert!(matches!(result, Err(RarError::FileNotFound(_))));
    }

    #[test]
    fn test_store_nopass_index_out_of_range() {
        if !fixtures_available() { return; }
        let archive = Archive::open_path(fixture("store_nopass.rar")).unwrap();
        let result = archive.entry_reader(99usize);
        assert!(matches!(result, Err(RarError::IndexOutOfRange { .. })));
    }

    // -----------------------------------------------------------------------
    // store_pass_1.rar — RAR v5, single file, password="1"
    // -----------------------------------------------------------------------

    #[test]
    fn test_store_pass_requires_password() {
        if !fixtures_available() { return; }
        let archive = Archive::open_path(fixture("store_pass_1.rar")).unwrap();
        let result = archive.entry_reader(0usize);
        assert!(matches!(result, Err(RarError::PasswordRequired)));
    }

    #[test]
    fn test_store_pass_correct_password() {
        if !fixtures_available() { return; }
        let mut archive = Archive::open_path(fixture("store_pass_1.rar")).unwrap();
        archive.set_password("1");
        let mut reader = archive.entry_reader(0usize).unwrap();
        let mut buf = [0u8; 4];
        reader.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"%PDF", "decrypted content should be a PDF");
    }

    #[test]
    fn test_store_pass_seek_and_read() {
        if !fixtures_available() { return; }
        let mut archive = Archive::open_path(fixture("store_pass_1.rar")).unwrap();
        archive.set_password("1");
        let mut reader = archive.entry_reader(0usize).unwrap();
        reader.seek(SeekFrom::Start(1024)).unwrap();
        let mut buf = [0u8; 8];
        reader.read_exact(&mut buf).unwrap();
        assert_eq!(buf.len(), 8);
    }

    // -----------------------------------------------------------------------
    // store_multi.part1.rar — RAR v5, multi-volume (4 parts), no password
    // -----------------------------------------------------------------------

    #[test]
    fn test_store_multi_open() {
        if !fixtures_available() { return; }
        let archive = Archive::open_path(fixture("store_multi.part1.rar")).unwrap();
        assert_eq!(archive.len(), 1);
    }

    #[test]
    fn test_store_multi_entry_metadata() {
        if !fixtures_available() { return; }
        let archive = Archive::open_path(fixture("store_multi.part1.rar")).unwrap();
        let entries: Vec<_> = archive.entries().collect();
        assert_eq!(entries.len(), 1);
        let entry = &entries[0];
        assert_eq!(entry.name(), "The Great Ideas of Philosophy, 2nd Edition.pdf");
        assert_eq!(entry.size(), 3168649);
        assert!(!entry.is_encrypted());
    }

    #[test]
    fn test_store_multi_read_full() {
        if !fixtures_available() { return; }
        let archive = Archive::open_path(fixture("store_multi.part1.rar")).unwrap();
        let mut reader = archive.entry_reader(0usize).unwrap();
        let mut buf = [0u8; 4];
        reader.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"%PDF", "multi-volume content should be a PDF");
    }

    #[test]
    fn test_store_multi_seek() {
        if !fixtures_available() { return; }
        let archive = Archive::open_path(fixture("store_multi.part1.rar")).unwrap();
        let mut reader = archive.entry_reader(0usize).unwrap();
        reader.seek(SeekFrom::Start(1024)).unwrap();
        let mut buf = [0u8; 8];
        reader.read_exact(&mut buf).unwrap();
        assert_eq!(buf.len(), 8);
    }

    // -----------------------------------------------------------------------
    // store_multi_pass1.part1.rar — RAR v5, multi-volume (4 parts), password="1"
    // -----------------------------------------------------------------------

    #[test]
    fn test_store_multi_pass_requires_password() {
        if !fixtures_available() { return; }
        let archive = Archive::open_path(fixture("store_multi_pass1.part1.rar")).unwrap();
        let result = archive.entry_reader(0usize);
        assert!(matches!(result, Err(RarError::PasswordRequired)));
    }

    #[test]
    fn test_store_multi_pass_metadata() {
        if !fixtures_available() { return; }
        let archive = Archive::open_path(fixture("store_multi_pass1.part1.rar")).unwrap();
        let entries: Vec<_> = archive.entries().collect();
        assert_eq!(entries.len(), 1);
        assert!(entries[0].is_encrypted());
    }
}
