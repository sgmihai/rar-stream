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

    /// The archive is corrupt or has an invalid header.
    #[error("invalid or corrupt archive header: {0}")]
    InvalidHeader(String),

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
    #[error("unsupported compression method: {0}")]
    UnsupportedCompression(String),

    /// An HTTP error occurred while fetching archive data.
    #[error("HTTP error: {0}")]
    Http(String),

    /// An invalid seek position was requested.
    #[error("invalid seek position: offset {offset} is out of range [0, {length})")]
    InvalidSeekPosition {
        /// The requested offset.
        offset: u64,
        /// The length of the entry.
        length: u64,
    },

    /// The archive uses an unsupported feature.
    #[error("unsupported feature: {0}")]
    UnsupportedFeature(String),

    /// An error from the underlying rar-stream library.
    #[error("rar-stream error: {0}")]
    Backend(String),
}

/// A specialized `Result` type for RAR operations.
pub type Result<T> = std::result::Result<T, RarError>;

impl From<rar_stream::RarError> for RarError {
    fn from(e: rar_stream::RarError) -> Self {
        match e {
            rar_stream::RarError::InvalidSignature => RarError::InvalidSignature,
            rar_stream::RarError::InvalidHeader => RarError::InvalidHeader("malformed header".into()),
            rar_stream::RarError::PasswordRequired => RarError::PasswordRequired,
            rar_stream::RarError::DecryptionFailed(_) => RarError::IncorrectPassword,
            rar_stream::RarError::Io(io_err) => RarError::Io(io_err),
            other => RarError::Backend(other.to_string()),
        }
    }
}
