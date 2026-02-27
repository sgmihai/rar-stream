//! RAR v4 header structures and parsing.
//!
//! Every block starts with a common 7-byte header:
//! ```text
//! CRC16   (2 bytes, LE) – CRC of the header fields that follow
//! TYPE    (1 byte)      – block type
//! FLAGS   (2 bytes, LE) – block flags
//! SIZE    (2 bytes, LE) – total header size (including CRC16 + TYPE + FLAGS + SIZE)
//! ```
//! Some blocks have an additional 4-byte `ADD_SIZE` field (when `FLAG_HAS_DATA` is set)
//! that gives the size of the data that follows the header.

use std::io::{Read, Seek, SeekFrom};

use bitflags::bitflags;
use byteorder::{LittleEndian, ReadBytesExt};

use crate::error::{RarError, Result};

/// RAR v4 magic signature bytes.
pub const RAR4_SIGNATURE: [u8; 7] = [0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x00];

/// Block type constants for RAR v4.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockType {
    /// Marker / magic block (pseudo-block, not a real block).
    Marker,
    /// Archive header block.
    ArchiveHeader,
    /// File header block.
    FileHeader,
    /// Comment header (old style).
    CommentHeader,
    /// Extra information (old style).
    ExtraInfo,
    /// Sub-block (old style).
    SubBlock,
    /// Recovery record.
    RecoveryRecord,
    /// Archive authentication.
    ArchiveAuthentication,
    /// New-style sub-block (NTFS streams, etc.).
    NewSubBlock,
    /// End-of-archive block.
    EndOfArchive,
    /// Unknown block type.
    Unknown(u8),
}

impl From<u8> for BlockType {
    fn from(v: u8) -> Self {
        match v {
            0x72 => BlockType::Marker,
            0x73 => BlockType::ArchiveHeader,
            0x74 => BlockType::FileHeader,
            0x75 => BlockType::CommentHeader,
            0x76 => BlockType::ExtraInfo,
            0x77 => BlockType::SubBlock,
            0x78 => BlockType::RecoveryRecord,
            0x79 => BlockType::ArchiveAuthentication,
            0x7A => BlockType::NewSubBlock,
            0x7B => BlockType::EndOfArchive,
            other => BlockType::Unknown(other),
        }
    }
}

bitflags! {
    /// Flags for the archive header block.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct ArchiveFlags: u16 {
        /// Archive volume (part of a multi-volume set).
        const VOLUME            = 0x0001;
        /// Archive comment present.
        const COMMENT           = 0x0002;
        /// Archive is locked.
        const LOCKED            = 0x0004;
        /// Solid archive.
        const SOLID             = 0x0008;
        /// New volume naming scheme (volname.partN.rar).
        const NEW_VOLUME_NAME   = 0x0010;
        /// Authenticity information present.
        const AUTH_INFO         = 0x0020;
        /// Recovery record present.
        const RECOVERY          = 0x0040;
        /// Archive is encrypted (headers encrypted).
        const ENCRYPTED         = 0x0080;
        /// First volume (only set for volumes).
        const FIRST_VOLUME      = 0x0100;
    }
}

bitflags! {
    /// Flags for file header blocks.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct FileFlags: u16 {
        /// File continued from previous volume.
        const SPLIT_BEFORE      = 0x0001;
        /// File continued in next volume.
        const SPLIT_AFTER       = 0x0002;
        /// File is encrypted with password.
        const ENCRYPTED         = 0x0004;
        /// File comment present (old style).
        const COMMENT           = 0x0008;
        /// Solid flag (for solid archives).
        const SOLID             = 0x0010;
        /// Dictionary size bits (3 bits: bits 5-7).
        const DICT_MASK         = 0x00E0;
        /// High-precision time fields present.
        const HIGH_PRECISION_TIME = 0x0100;
        /// File has 64-bit size fields.
        const SIZE_64           = 0x0200;
        /// File has Unicode name.
        const UNICODE_NAME      = 0x0400;
        /// File has salt (for AES encryption).
        const SALT              = 0x0800;
        /// File is a version.
        const VERSION           = 0x1000;
        /// Extended time field present.
        const EXT_TIME          = 0x2000;
        /// Reserved.
        const RESERVED          = 0x4000;
        /// Block has additional data (inherited from common flags).
        const HAS_DATA          = 0x8000;
    }
}

/// Compression method constants for RAR v4.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompressionMethod {
    /// No compression (store).
    Store,
    /// Fastest compression.
    Fastest,
    /// Fast compression.
    Fast,
    /// Normal compression.
    Normal,
    /// Good compression.
    Good,
    /// Best compression.
    Best,
    /// Unknown method.
    Unknown(u8),
}

impl From<u8> for CompressionMethod {
    fn from(v: u8) -> Self {
        match v {
            0x30 => CompressionMethod::Store,
            0x31 => CompressionMethod::Fastest,
            0x32 => CompressionMethod::Fast,
            0x33 => CompressionMethod::Normal,
            0x34 => CompressionMethod::Good,
            0x35 => CompressionMethod::Best,
            other => CompressionMethod::Unknown(other),
        }
    }
}

impl CompressionMethod {
    /// Return the byte value of this compression method.
    pub fn as_byte(self) -> u8 {
        match self {
            CompressionMethod::Store => 0x30,
            CompressionMethod::Fastest => 0x31,
            CompressionMethod::Fast => 0x32,
            CompressionMethod::Normal => 0x33,
            CompressionMethod::Good => 0x34,
            CompressionMethod::Best => 0x35,
            CompressionMethod::Unknown(b) => b,
        }
    }
}

/// The common 7-byte block header present in every RAR v4 block.
#[derive(Debug, Clone)]
pub struct BlockHeader {
    /// CRC16 of the header (excluding the CRC16 field itself).
    pub crc16: u16,
    /// Block type.
    pub block_type: BlockType,
    /// Block flags.
    pub flags: u16,
    /// Total header size in bytes (including the 7-byte common header).
    pub header_size: u16,
    /// Size of the data following the header (0 if `HAS_DATA` flag is not set).
    pub data_size: u64,
    /// Absolute offset of this block in the archive file.
    pub block_offset: u64,
}

impl BlockHeader {
    /// Read a block header from the current position of `reader`.
    pub fn read<R: Read + Seek>(reader: &mut R) -> Result<Self> {
        let block_offset = reader.stream_position()?;
        let crc16 = reader.read_u16::<LittleEndian>()?;
        let block_type_byte = reader.read_u8()?;
        let block_type = BlockType::from(block_type_byte);
        let flags = reader.read_u16::<LittleEndian>()?;
        let header_size = reader.read_u16::<LittleEndian>()?;

        if header_size < 7 {
            return Err(RarError::Corrupt(format!(
                "block header size {header_size} is too small (minimum 7)"
            )));
        }

        // If HAS_DATA flag is set, read the 4-byte ADD_SIZE field.
        let data_size = if flags & 0x8000 != 0 {
            reader.read_u32::<LittleEndian>()? as u64
        } else {
            0
        };

        Ok(BlockHeader {
            crc16,
            block_type,
            flags,
            header_size,
            data_size,
            block_offset,
        })
    }
}

/// Parsed archive header block.
#[derive(Debug, Clone)]
pub struct ArchiveHeader {
    /// Archive-level flags.
    pub flags: ArchiveFlags,
    /// Absolute offset of the archive header block in the file.
    pub block_offset: u64,
}

/// Parsed file header block (block type 0x74 or 0x7A).
#[derive(Debug, Clone)]
pub struct FileHeader {
    /// Unpacked (decompressed) file size in bytes.
    pub unpacked_size: u64,
    /// Operating system that created the file.
    pub os: u8,
    /// CRC32 of the unpacked data.
    pub file_crc32: u32,
    /// File modification time (MS-DOS format).
    pub file_time: u32,
    /// RAR version needed to unpack.
    pub required_version: u8,
    /// Compression method.
    pub method: CompressionMethod,
    /// Length of the file name field.
    pub name_len: u16,
    /// File attributes.
    pub attributes: u32,
    /// High 32 bits of the packed size (only when `SIZE_64` flag is set).
    pub packed_size_high: u32,
    /// High 32 bits of the unpacked size (only when `SIZE_64` flag is set).
    pub unpacked_size_high: u32,
    /// File name (UTF-8 decoded).
    pub name: String,
    /// Salt for AES encryption (16 bytes, only when `SALT` flag is set).
    pub salt: Option<[u8; 16]>,
    /// File-level flags.
    pub flags: FileFlags,
    /// Packed (compressed) size in bytes.
    pub packed_size: u64,
    /// Absolute offset of the packed data in the archive file.
    pub data_offset: u64,
    /// Whether this file entry is a directory.
    pub is_directory: bool,
    /// Whether this file is split across volumes.
    pub is_split: bool,
}

/// A generic parsed RAR v4 block.
#[derive(Debug, Clone)]
pub enum RarV4Header {
    /// An archive header block.
    Archive(ArchiveHeader),
    /// A file header block.
    File(FileHeader),
    /// An end-of-archive block.
    EndOfArchive,
    /// Any other block type (skipped during parsing).
    Other {
        /// The block type identifier.
        block_type: BlockType,
        /// Size of the data area following the header.
        data_size: u64,
        /// Absolute offset of this block in the archive file.
        block_offset: u64,
        /// Total size of the header in bytes.
        header_size: u16,
    },
}

/// Read and parse the next block from `reader`, returning the parsed header
/// and leaving the reader positioned at the start of the *next* block.
pub fn read_next_block<R: Read + Seek>(reader: &mut R) -> Result<RarV4Header> {
    let common = BlockHeader::read(reader)?;

    match common.block_type {
        BlockType::ArchiveHeader => {
            let flags = ArchiveFlags::from_bits_truncate(common.flags);
            let remaining = common.header_size as i64 - 7;
            if remaining > 0 {
                reader.seek(SeekFrom::Current(remaining))?;
            }
            Ok(RarV4Header::Archive(ArchiveHeader {
                flags,
                block_offset: common.block_offset,
            }))
        }

        BlockType::FileHeader | BlockType::NewSubBlock => {
            parse_file_header(reader, &common)
        }

        BlockType::EndOfArchive => {
            let remaining = common.header_size as i64 - 7;
            if remaining > 0 {
                reader.seek(SeekFrom::Current(remaining))?;
            }
            Ok(RarV4Header::EndOfArchive)
        }

        other => {
            let remaining_header = common.header_size as i64 - 7;
            if remaining_header > 0 {
                reader.seek(SeekFrom::Current(remaining_header))?;
            }
            if common.data_size > 0 {
                reader.seek(SeekFrom::Current(common.data_size as i64))?;
            }
            Ok(RarV4Header::Other {
                block_type: other,
                data_size: common.data_size,
                block_offset: common.block_offset,
                header_size: common.header_size,
            })
        }
    }
}

fn parse_file_header<R: Read + Seek>(
    reader: &mut R,
    common: &BlockHeader,
) -> Result<RarV4Header> {
    let flags = FileFlags::from_bits_truncate(common.flags);
    let packed_size_low = common.data_size as u32;

    let unpacked_size_low = reader.read_u32::<LittleEndian>()?;
    let os = reader.read_u8()?;
    let file_crc32 = reader.read_u32::<LittleEndian>()?;
    let file_time = reader.read_u32::<LittleEndian>()?;
    let required_version = reader.read_u8()?;
    let method_byte = reader.read_u8()?;
    let method = CompressionMethod::from(method_byte);
    let name_len = reader.read_u16::<LittleEndian>()?;
    let attributes = reader.read_u32::<LittleEndian>()?;

    // bytes read from body (after common 7 + ADD_SIZE 4):
    let mut body_bytes_read: u16 = 21;

    let (packed_size_high, unpacked_size_high) = if flags.contains(FileFlags::SIZE_64) {
        let ph = reader.read_u32::<LittleEndian>()?;
        let uh = reader.read_u32::<LittleEndian>()?;
        body_bytes_read += 8;
        (ph, uh)
    } else {
        (0, 0)
    };

    let mut name_bytes = vec![0u8; name_len as usize];
    reader.read_exact(&mut name_bytes)?;
    body_bytes_read += name_len;

    let name = if flags.contains(FileFlags::UNICODE_NAME) {
        let null_pos = name_bytes.iter().position(|&b| b == 0).unwrap_or(name_bytes.len());
        let standard_name = String::from_utf8_lossy(&name_bytes[..null_pos]).into_owned();
        if null_pos < name_bytes.len() {
            decode_unicode_name(&standard_name, &name_bytes[null_pos + 1..])
        } else {
            standard_name
        }
    } else {
        String::from_utf8_lossy(&name_bytes).into_owned()
    };

    let salt = if flags.contains(FileFlags::SALT) {
        let mut s = [0u8; 16];
        reader.read_exact(&mut s)?;
        body_bytes_read += 16;
        Some(s)
    } else {
        None
    };

    // Skip remaining header bytes.
    // Total read = 7 (common) + 4 (ADD_SIZE) + body_bytes_read
    let total_read = 7u16 + 4 + body_bytes_read;
    let remaining = common.header_size as i64 - total_read as i64;
    if remaining > 0 {
        reader.seek(SeekFrom::Current(remaining))?;
    }

    let data_offset = reader.stream_position()?;

    let packed_size = ((packed_size_high as u64) << 32) | (packed_size_low as u64);
    let unpacked_size = ((unpacked_size_high as u64) << 32) | (unpacked_size_low as u64);

    if packed_size > 0 {
        reader.seek(SeekFrom::Current(packed_size as i64))?;
    }

    let dict_bits = (common.flags & 0x00E0) >> 5;
    let is_directory = dict_bits == 7;
    let is_split = flags.contains(FileFlags::SPLIT_BEFORE) || flags.contains(FileFlags::SPLIT_AFTER);

    Ok(RarV4Header::File(FileHeader {
        unpacked_size,
        os,
        file_crc32,
        file_time,
        required_version,
        method,
        name_len,
        attributes,
        packed_size_high,
        unpacked_size_high,
        name,
        salt,
        flags,
        packed_size,
        data_offset,
        is_directory,
        is_split,
    }))
}

fn decode_unicode_name(standard: &str, unicode_ext: &[u8]) -> String {
    if unicode_ext.is_empty() {
        return standard.to_owned();
    }

    let std_bytes: Vec<u8> = standard.bytes().collect();
    let mut result = Vec::<u16>::new();
    let mut pos = 0usize;
    let mut std_pos = 0usize;

    if pos >= unicode_ext.len() {
        return standard.to_owned();
    }
    let high_byte = unicode_ext[pos] as u16;
    pos += 1;

    while pos < unicode_ext.len() {
        let flag_byte = unicode_ext[pos];
        pos += 1;

        for bit in (0..8).rev() {
            if pos > unicode_ext.len() {
                break;
            }
            if (flag_byte >> bit) & 1 == 0 {
                let low = if std_pos < std_bytes.len() { std_bytes[std_pos] } else { 0 };
                std_pos += 1;
                result.push((high_byte << 8) | low as u16);
            } else {
                if pos + 1 >= unicode_ext.len() {
                    break;
                }
                let lo = unicode_ext[pos] as u16;
                let hi = unicode_ext[pos + 1] as u16;
                pos += 2;
                let ch = (hi << 8) | lo;
                if hi == high_byte {
                    let std_byte = if std_pos < std_bytes.len() { std_bytes[std_pos] } else { 0 };
                    std_pos += 1;
                    result.push(((high_byte << 8) | std_byte as u16).wrapping_add(lo));
                } else {
                    result.push(ch);
                }
            }
        }
    }

    String::from_utf16_lossy(&result)
}
