//! Public entry types and selectors for archive file access.

use crate::v4::header::{CompressionMethod, FileFlags};
use crate::v4::reader::FileEntry as V4FileEntry;
use crate::v5::header::FileEntry as V5FileEntry;

/// Selects a file entry within an archive.
///
/// Can be constructed from a `usize` (index) or `&str` / `&String` (path).
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

/// Metadata about a single file entry in an archive.
#[derive(Debug, Clone)]
pub struct ArchiveEntry<'a> {
    inner: EntryInner<'a>,
}

#[derive(Debug, Clone)]
enum EntryInner<'a> {
    V4(&'a V4FileEntry),
    V5(&'a V5FileEntry),
}

impl<'a> ArchiveEntry<'a> {
    pub(crate) fn from_v4(entry: &'a V4FileEntry) -> Self {
        ArchiveEntry { inner: EntryInner::V4(entry) }
    }

    pub(crate) fn from_v5(entry: &'a V5FileEntry) -> Self {
        ArchiveEntry { inner: EntryInner::V5(entry) }
    }

    /// The relative path of the file within the archive.
    pub fn path(&self) -> &str {
        match &self.inner {
            EntryInner::V4(e) => &e.header.name,
            EntryInner::V5(e) => &e.name,
        }
    }

    /// The uncompressed size of the file in bytes.
    pub fn size(&self) -> u64 {
        match &self.inner {
            EntryInner::V4(e) => e.header.unpacked_size,
            EntryInner::V5(e) => e.unpacked_size,
        }
    }

    /// The compressed (packed) size of the file in bytes.
    pub fn compressed_size(&self) -> u64 {
        match &self.inner {
            EntryInner::V4(e) => e.header.packed_size,
            EntryInner::V5(e) => e.packed_size,
        }
    }

    /// Whether the file is encrypted.
    pub fn is_encrypted(&self) -> bool {
        match &self.inner {
            EntryInner::V4(e) => e.header.flags.contains(FileFlags::ENCRYPTED),
            EntryInner::V5(e) => e.is_encrypted,
        }
    }

    /// Whether the file is split across multiple volumes.
    pub fn is_split(&self) -> bool {
        match &self.inner {
            EntryInner::V4(e) => e.header.is_split,
            EntryInner::V5(e) => e.is_split,
        }
    }

    /// The zero-based index of this entry in the archive.
    pub fn index(&self) -> usize {
        match &self.inner {
            EntryInner::V4(e) => e.index,
            EntryInner::V5(e) => e.index,
        }
    }

    /// The compression method name.
    pub fn compression_method(&self) -> &'static str {
        match &self.inner {
            EntryInner::V4(e) => match e.header.method {
                CompressionMethod::Store => "store",
                CompressionMethod::Fastest => "fastest",
                CompressionMethod::Fast => "fast",
                CompressionMethod::Normal => "normal",
                CompressionMethod::Good => "good",
                CompressionMethod::Best => "best",
                CompressionMethod::Unknown(_) => "unknown",
            },
            EntryInner::V5(e) => match e.compression_method {
                0 => "store",
                1 => "fastest",
                2 => "fast",
                3 => "normal",
                4 => "good",
                5 => "best",
                _ => "unknown",
            },
        }
    }
}
