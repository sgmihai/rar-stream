//! RAR v5 header structures and parsing.
//!
//! RAR v5 uses variable-length integers (vint) for most fields.
//! Each byte contributes 7 bits (LSB first); the MSB indicates continuation.

use std::io::{Read, Seek, SeekFrom};

use bitflags::bitflags;
use byteorder::{LittleEndian, ReadBytesExt};

use crate::error::{RarError, Result};

/// RAR v5 magic signature bytes.
pub const RAR5_SIGNATURE: [u8; 8] = [0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x01, 0x00];

/// RAR v5 block type constants.
#[derive(Debug, Clone, Copy)]
pub enum BlockType {
    /// Archive header.
    ArchiveHeader,
    /// File header.
    FileHeader,
    /// Service header (NTFS streams, etc.).
    ServiceHeader,
    /// Encryption header (archive-level encryption).
    EncryptionHeader,
    /// End-of-archive header.
    EndOfArchive,
    /// Unknown block type.
    Unknown(u64),
}

impl From<u64> for BlockType {
    fn from(v: u64) -> Self {
        match v {
            1 => BlockType::ArchiveHeader,
            2 => BlockType::FileHeader,
            3 => BlockType::ServiceHeader,
            4 => BlockType::EncryptionHeader,
            5 => BlockType::EndOfArchive,
            other => BlockType::Unknown(other),
        }
    }
}

impl PartialEq for BlockType {
    fn eq(&self, other: &Self) -> bool {
        matches!(
            (self, other),
            (BlockType::ArchiveHeader, BlockType::ArchiveHeader)
                | (BlockType::FileHeader, BlockType::FileHeader)
                | (BlockType::ServiceHeader, BlockType::ServiceHeader)
                | (BlockType::EncryptionHeader, BlockType::EncryptionHeader)
                | (BlockType::EndOfArchive, BlockType::EndOfArchive)
        ) || matches!((self, other), (BlockType::Unknown(a), BlockType::Unknown(b)) if a == b)
    }
}

impl Eq for BlockType {}

bitflags! {
    /// Common block flags for RAR v5.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct BlockFlags: u64 {
        /// Extra area is present.
        const EXTRA_DATA    = 0x0001;
        /// Data area is present.
        const DATA_AREA     = 0x0002;
        /// Skip unknown extra areas.
        const SKIP_UNKNOWN  = 0x0004;
        /// Data area continues from previous volume.
        const SPLIT_BEFORE  = 0x0008;
        /// Data area continues in next volume.
        const SPLIT_AFTER   = 0x0010;
        /// Block depends on preceding file block.
        const CHILD         = 0x0020;
        /// Preserve child block if host is modified.
        const PRESERVE_CHILD = 0x0040;
    }
}

bitflags! {
    /// Archive header flags for RAR v5.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct ArchiveFlags: u64 {
        /// Archive is a volume (part of multi-volume set).
        const VOLUME            = 0x0001;
        /// Volume number field is present.
        const VOLUME_NUMBER     = 0x0002;
        /// Solid archive.
        const SOLID             = 0x0004;
        /// Recovery record is present.
        const RECOVERY          = 0x0008;
        /// Locked archive.
        const LOCKED            = 0x0010;
    }
}

bitflags! {
    /// File header flags for RAR v5.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct FileHeaderFlags: u64 {
        /// Directory entry.
        const DIRECTORY         = 0x0001;
        /// Time field in Unix format.
        const UNIX_TIME         = 0x0002;
        /// CRC32 of unpacked data is present.
        const CRC32_PRESENT     = 0x0004;
        /// Unpacked size is unknown.
        const UNKNOWN_SIZE      = 0x0008;
    }
}

/// Checksum value for a RAR v5 file entry.
#[derive(Debug, Clone)]
pub enum Checksum {
    /// CRC32 checksum of the unpacked data.
    Crc32(u32),
    /// BLAKE2sp checksum of the unpacked data (32 bytes).
    Blake2sp([u8; 32]),
}

/// Encryption parameters for a RAR v5 file entry.
#[derive(Debug, Clone)]
pub struct EncryptionParams {
    /// Encryption version (0 = AES-256).
    pub version: u64,
    /// KDF count (iterations = 2^kdf_count).
    pub kdf_count: u8,
    /// Salt for PBKDF2 key derivation (16 bytes).
    pub salt: [u8; 16],
    /// Initialization vector for AES-256-CBC (16 bytes).
    pub iv: [u8; 16],
    /// Whether a password check value is present.
    pub has_check_value: bool,
    /// Password check value (8 bytes, optional).
    pub check_value: Option<[u8; 8]>,
}

/// A parsed RAR v5 file entry.
#[derive(Debug, Clone)]
pub struct FileEntry {
    /// File name (UTF-8).
    pub name: String,
    /// Unpacked (decompressed) size in bytes.
    pub unpacked_size: u64,
    /// Packed (compressed) size in bytes.
    pub packed_size: u64,
    /// Absolute offset of the packed data in the archive file.
    pub data_offset: u64,
    /// Compression method (0 = store, 1–5 = various levels).
    pub compression_method: u8,
    /// Compression algorithm version.
    pub compression_version: u8,
    /// Whether the file is encrypted.
    pub is_encrypted: bool,
    /// Whether the file is split across volumes.
    pub is_split: bool,
    /// Whether this is a directory entry.
    pub is_directory: bool,
    /// Checksum of the unpacked data.
    pub checksum: Option<Checksum>,
    /// Encryption parameters (if encrypted).
    pub encryption: Option<EncryptionParams>,
    /// Zero-based index in the archive.
    pub index: usize,
    /// OS-specific attributes.
    pub attributes: u64,
    /// Modification time (Unix timestamp, seconds).
    pub mtime: Option<u64>,
}

/// A parsed RAR v5 block.
#[derive(Debug)]
pub enum RarV5Header {
    /// An archive header block.
    Archive {
        /// Archive-level flags.
        flags: ArchiveFlags,
        /// Volume number (only present in multi-volume archives).
        volume_number: Option<u64>,
    },
    /// A file header block.
    File(FileEntry),
    /// An end-of-archive block.
    EndOfArchive {
        /// Whether the archive continues in the next volume.
        has_next_volume: bool,
    },
    /// Any other block type (skipped during parsing).
    Other {
        /// The block type identifier.
        block_type: BlockType,
        /// Size of the data area following the header.
        data_size: u64,
        /// Absolute offset of this block in the archive file.
        block_offset: u64,
    },
}

// ---------------------------------------------------------------------------
// Variable-length integer decoding
// ---------------------------------------------------------------------------

/// Read a RAR v5 variable-length integer from `reader`.
///
/// Each byte contributes 7 bits (LSB first); the MSB indicates continuation.
/// Maximum 8 bytes (56 bits) are read.
pub fn read_vint<R: Read>(reader: &mut R) -> Result<u64> {
    let mut result = 0u64;
    let mut shift = 0u32;

    for _ in 0..8 {
        let byte = reader.read_u8()?;
        result |= ((byte & 0x7F) as u64) << shift;
        shift += 7;
        if byte & 0x80 == 0 {
            return Ok(result);
        }
    }

    Err(RarError::Corrupt("vint too long".into()))
}

// ---------------------------------------------------------------------------
// Block reading
// ---------------------------------------------------------------------------

/// Read and parse the next RAR v5 block from `reader`.
pub fn read_next_block<R: Read + Seek>(reader: &mut R) -> Result<RarV5Header> {
    let block_offset = reader.stream_position()?;

    let _header_crc32 = reader.read_u32::<LittleEndian>()?;
    let header_size = read_vint(reader)?;
    let header_data_start = reader.stream_position()?;

    let block_type_raw = read_vint(reader)?;
    let block_type = BlockType::from(block_type_raw);
    let block_flags_raw = read_vint(reader)?;
    let block_flags = BlockFlags::from_bits_truncate(block_flags_raw);

    let extra_data_size = if block_flags.contains(BlockFlags::EXTRA_DATA) {
        read_vint(reader)?
    } else {
        0
    };

    let data_area_size = if block_flags.contains(BlockFlags::DATA_AREA) {
        read_vint(reader)?
    } else {
        0
    };

    let result = match block_type {
        BlockType::ArchiveHeader => parse_archive_header(reader)?,
        BlockType::FileHeader | BlockType::ServiceHeader => {
            parse_file_header(
                reader,
                block_type,
                block_flags,
                extra_data_size,
                data_area_size,
                header_data_start,
                header_size,
                block_offset,
            )?
        }
        BlockType::EndOfArchive => {
            let eoa_flags = read_vint(reader)?;
            let has_next_volume = eoa_flags & 0x0001 != 0;
            RarV5Header::EndOfArchive { has_next_volume }
        }
        other => RarV5Header::Other {
            block_type: other,
            data_size: data_area_size,
            block_offset,
        },
    };

    // Skip to the end of the header data.
    let header_end = header_data_start + header_size;
    let current = reader.stream_position()?;
    if current < header_end {
        reader.seek(SeekFrom::Start(header_end))?;
    }

    // Skip the data area (unless it's a file, where we recorded the offset).
    if data_area_size > 0 {
        match &result {
            RarV5Header::File(_) => {}
            _ => {
                reader.seek(SeekFrom::Current(data_area_size as i64))?;
            }
        }
    }

    Ok(result)
}

fn parse_archive_header<R: Read + Seek>(reader: &mut R) -> Result<RarV5Header> {
    let archive_flags_raw = read_vint(reader)?;
    let archive_flags = ArchiveFlags::from_bits_truncate(archive_flags_raw);

    let volume_number = if archive_flags.contains(ArchiveFlags::VOLUME_NUMBER) {
        Some(read_vint(reader)?)
    } else {
        None
    };

    Ok(RarV5Header::Archive {
        flags: archive_flags,
        volume_number,
    })
}

#[allow(clippy::too_many_arguments)]
fn parse_file_header<R: Read + Seek>(
    reader: &mut R,
    block_type: BlockType,
    block_flags: BlockFlags,
    extra_data_size: u64,
    data_area_size: u64,
    header_data_start: u64,
    header_size: u64,
    _block_offset: u64,
) -> Result<RarV5Header> {
    let file_flags_raw = read_vint(reader)?;
    let file_flags = FileHeaderFlags::from_bits_truncate(file_flags_raw);

    let unpacked_size = if file_flags.contains(FileHeaderFlags::UNKNOWN_SIZE) {
        0
    } else {
        read_vint(reader)?
    };

    let attributes = read_vint(reader)?;

    let mtime = if file_flags.contains(FileHeaderFlags::UNIX_TIME) {
        Some(reader.read_u32::<LittleEndian>()? as u64)
    } else {
        None
    };

    let file_crc32 = if file_flags.contains(FileHeaderFlags::CRC32_PRESENT) {
        Some(reader.read_u32::<LittleEndian>()?)
    } else {
        None
    };

    let compression_info = read_vint(reader)?;
    let compression_version = ((compression_info >> 6) & 0x3F) as u8;
    let compression_method = (compression_info & 0x3F) as u8;

    let _host_os = read_vint(reader)?;

    let name_len = read_vint(reader)?;
    let mut name_bytes = vec![0u8; name_len as usize];
    reader.read_exact(&mut name_bytes)?;
    let name = String::from_utf8_lossy(&name_bytes).into_owned();

    // Parse extra data area.
    let header_end = header_data_start + header_size;
    let extra_start = header_end - extra_data_size;

    let mut checksum: Option<Checksum> = file_crc32.map(Checksum::Crc32);
    let mut encryption: Option<EncryptionParams> = None;

    if extra_data_size > 0 {
        let current = reader.stream_position()?;
        if current <= extra_start {
            reader.seek(SeekFrom::Start(extra_start))?;
            parse_extra_data(reader, header_end, &mut checksum, &mut encryption)?;
        }
    }

    // Position at the data area.
    reader.seek(SeekFrom::Start(header_end))?;
    let data_offset = reader.stream_position()?;

    // Skip the data area.
    if data_area_size > 0 {
        reader.seek(SeekFrom::Current(data_area_size as i64))?;
    }

    let is_directory = file_flags.contains(FileHeaderFlags::DIRECTORY)
        || block_type == BlockType::ServiceHeader;
    let is_split = block_flags.contains(BlockFlags::SPLIT_BEFORE)
        || block_flags.contains(BlockFlags::SPLIT_AFTER);
    let is_encrypted = encryption.is_some();

    Ok(RarV5Header::File(FileEntry {
        name,
        unpacked_size,
        packed_size: data_area_size,
        data_offset,
        compression_method,
        compression_version,
        is_encrypted,
        is_split,
        is_directory,
        checksum,
        encryption,
        index: 0,
        attributes,
        mtime,
    }))
}

fn parse_extra_data<R: Read + Seek>(
    reader: &mut R,
    extra_end: u64,
    checksum: &mut Option<Checksum>,
    encryption: &mut Option<EncryptionParams>,
) -> Result<()> {
    while reader.stream_position()? < extra_end {
        let record_size = read_vint(reader)?;
        if record_size == 0 {
            break;
        }
        let record_start = reader.stream_position()?;
        let record_type = read_vint(reader)?;

        match record_type {
            // Encryption record (type 0x01).
            0x01 => {
                let version = read_vint(reader)?;
                let enc_flags = read_vint(reader)?;
                let kdf_count = reader.read_u8()?;
                let mut salt = [0u8; 16];
                reader.read_exact(&mut salt)?;
                let mut iv = [0u8; 16];
                reader.read_exact(&mut iv)?;
                let has_check_value = enc_flags & 0x0001 != 0;
                let check_value = if has_check_value {
                    let mut cv = [0u8; 8];
                    reader.read_exact(&mut cv)?;
                    Some(cv)
                } else {
                    None
                };
                *encryption = Some(EncryptionParams {
                    version,
                    kdf_count,
                    salt,
                    iv,
                    has_check_value,
                    check_value,
                });
            }
            // File hash record (type 0x02).
            0x02 => {
                let hash_type = read_vint(reader)?;
                if hash_type == 0x00 {
                    let mut hash = [0u8; 32];
                    reader.read_exact(&mut hash)?;
                    *checksum = Some(Checksum::Blake2sp(hash));
                }
            }
            _ => {}
        }

        let record_end = record_start + record_size;
        let current = reader.stream_position()?;
        if current < record_end {
            reader.seek(SeekFrom::Start(record_end))?;
        }
    }

    Ok(())
}
