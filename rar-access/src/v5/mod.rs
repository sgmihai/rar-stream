//! RAR v5 (RAR 5.0+) format parser.

pub mod header;
pub mod reader;

pub use header::{FileEntry, RarV5Header};
pub use reader::RarV5Archive;
