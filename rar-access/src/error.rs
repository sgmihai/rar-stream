//! Error types for the rar-access library.

use std::io;
use thiserror::Error;

/// The main error type for RAR archive operations.
#[derive(Debug, Error)]
pub enum RarError {
    /// An I/O error occurred while reading the archive.
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),

    /// The archive signature is invalid or not recognized.
    #[error("invalid archive signature")]
    InvalidSignature,

    /// The archive format version is not supported.
    #[error("unsupported archive version: {0}")]
    UnsupportedVersion(u8),

    /// A header checksum mismatch was detected.
    #[error("header checksum mismatch (expected {expected:#010x}, got {actual:#010x})")]
    HeaderChecksumMismatch {
        /// The expected CRC32 value from the header.
        expected: u32,
        /// The actual computed CRC32 value.
        actual: u32,
    },

    /// A file data checksum mismatch was detected.
    #[error("file data checksum mismatch (expected {expected:#010x}, got {actual:#010x})")]
    DataChecksumMismatch {
        /// The expected CRC32 value from the header.
        expected: u32,
        /// The actual computed CRC32 value.
        actual: u32,
    },

    /// The requested file was not found in the archive.
    #[error("file not found in archive: {0}")]
    FileNotFound(String),

    /// The file index is out of range.
    #[error("file index {index} out of range (archive has {count} files)")]
    IndexOutOfRange {
        /// The requested index.
        index: usize,
        /// The number of entries in the archive.
        count: usize,
    },

    /// The archive is encrypted and a password is required.
    #[error("archive is encrypted; a password is required")]
    PasswordRequired,

    /// The provided password is incorrect.
    #[error("incorrect password")]
    IncorrectPassword,

    /// The compression method is not supported.
    #[error("unsupported compression method: {0:#04x}")]
    UnsupportedCompression(u8),

    /// A multi-volume archive part is missing.
    #[error("missing archive volume: {0}")]
    MissingVolume(String),

    /// The archive is corrupt or truncated.
    #[error("archive is corrupt or truncated: {0}")]
    Corrupt(String),

    /// A seek operation is not supported for this entry.
    #[error("seek not supported: {0}")]
    SeekNotSupported(String),

    /// An invalid seek position was requested.
    #[error("invalid seek position")]
    InvalidSeekPosition,

    /// The archive uses an unsupported feature.
    #[error("unsupported feature: {0}")]
    UnsupportedFeature(String),
}

/// A specialized `Result` type for RAR operations.
pub type Result<T> = std::result::Result<T, RarError>;
