//! RAR v4 (RAR 2.0–4.x) format parser.

pub mod header;
pub mod reader;

pub use header::{ArchiveHeader, BlockType, FileHeader, RarV4Header};
pub use reader::RarV4Archive;
