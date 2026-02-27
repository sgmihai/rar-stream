//! High-level RAR v4 archive reader.

use std::io::{self, BufReader, Read, Seek, SeekFrom};

use aes::Aes128;
use cbc::cipher::{BlockDecryptMut, KeyIvInit};
use sha1::{Digest, Sha1};

use crate::entry::{ArchiveEntry, EntrySelector};
use crate::error::{RarError, Result};

use super::header::{
    read_next_block, ArchiveFlags, CompressionMethod, FileFlags, FileHeader, RarV4Header,
    RAR4_SIGNATURE,
};

type Aes128CbcDec = cbc::Decryptor<Aes128>;

/// A RAR v4 archive opened from a reader.
///
/// Supports:
/// - STORE (non-compressed) entries
/// - AES-128 encrypted entries (password-protected)
/// - Multi-volume archives
pub struct RarV4Archive<R: Read + Seek> {
    reader: BufReader<R>,
    entries: Vec<FileEntry>,
    archive_flags: ArchiveFlags,
    password: Option<Vec<u8>>,
}

/// Internal representation of a file entry within the archive.
#[derive(Debug, Clone)]
pub(crate) struct FileEntry {
    /// The parsed file header.
    pub header: FileHeader,
    /// Index of this entry in the `entries` list.
    pub index: usize,
}

impl<R: Read + Seek> RarV4Archive<R> {
    /// Open a RAR v4 archive from a reader.
    pub fn open(inner: R) -> Result<Self> {
        let mut reader = BufReader::new(inner);
        let archive_flags = Self::read_headers(&mut reader)?;
        let entries = Self::scan_entries(&mut reader)?;

        Ok(RarV4Archive {
            reader,
            entries,
            archive_flags,
            password: None,
        })
    }

    /// Set the password used to decrypt encrypted entries.
    pub fn set_password(&mut self, password: impl Into<Vec<u8>>) {
        self.password = Some(password.into());
    }

    /// Return an iterator over the file entries in the archive.
    pub fn entries(&self) -> impl Iterator<Item = ArchiveEntry<'_>> {
        self.entries.iter().map(|e| ArchiveEntry::from_v4(e))
    }

    /// Return the number of file entries in the archive.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Return `true` if the archive contains no file entries.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Return `true` if the archive is encrypted at the header level.
    pub fn is_encrypted(&self) -> bool {
        self.archive_flags.contains(ArchiveFlags::ENCRYPTED)
    }

    /// Return `true` if this is a multi-volume archive.
    pub fn is_multi_volume(&self) -> bool {
        self.archive_flags.contains(ArchiveFlags::VOLUME)
    }

    /// Select a file entry and return a seekable reader for it.
    pub fn entry_reader(&mut self, selector: EntrySelector<'_>) -> Result<EntryReader<'_>> {
        let entry = self.find_entry(selector)?;
        let header = entry.header.clone();

        if header.flags.contains(FileFlags::ENCRYPTED) {
            let password = self
                .password
                .as_deref()
                .ok_or(RarError::PasswordRequired)?
                .to_vec();
            return self.make_encrypted_reader(header, password);
        }

        match header.method {
            CompressionMethod::Store => self.make_store_reader(header),
            other => Err(RarError::UnsupportedCompression(other.as_byte())),
        }
    }

    // -----------------------------------------------------------------------
    // Private helpers
    // -----------------------------------------------------------------------

    fn read_headers(reader: &mut BufReader<R>) -> Result<ArchiveFlags> {
        let mut sig = [0u8; 7];
        reader.read_exact(&mut sig).map_err(|_| RarError::InvalidSignature)?;
        if sig != RAR4_SIGNATURE {
            return Err(RarError::InvalidSignature);
        }

        match read_next_block(reader)? {
            RarV4Header::Archive(ah) => Ok(ah.flags),
            _ => Err(RarError::Corrupt("expected archive header block".into())),
        }
    }

    fn scan_entries(reader: &mut BufReader<R>) -> Result<Vec<FileEntry>> {
        let mut entries = Vec::new();
        let mut index = 0usize;

        loop {
            match read_next_block(reader) {
                Ok(RarV4Header::File(fh)) => {
                    if !fh.is_directory {
                        entries.push(FileEntry { header: fh, index });
                        index += 1;
                    }
                }
                Ok(RarV4Header::EndOfArchive) => break,
                Ok(_) => {}
                Err(RarError::Io(e)) if e.kind() == io::ErrorKind::UnexpectedEof => break,
                Err(e) => return Err(e),
            }
        }

        Ok(entries)
    }

    fn find_entry(&self, selector: EntrySelector<'_>) -> Result<&FileEntry> {
        match selector {
            EntrySelector::ByIndex(i) => self.entries.get(i).ok_or_else(|| {
                RarError::IndexOutOfRange {
                    index: i,
                    count: self.entries.len(),
                }
            }),
            EntrySelector::ByPath(path) => {
                let normalized = normalize_path(path);
                self.entries
                    .iter()
                    .find(|e| normalize_path(&e.header.name) == normalized)
                    .ok_or_else(|| RarError::FileNotFound(path.to_owned()))
            }
        }
    }

    fn make_store_reader(&mut self, header: FileHeader) -> Result<EntryReader<'_>> {
        self.reader.seek(SeekFrom::Start(header.data_offset))?;
        Ok(EntryReader::Store(StoreReader::new(
            &mut self.reader,
            header.data_offset,
            header.unpacked_size,
            header.file_crc32,
        )))
    }

    fn make_encrypted_reader(
        &mut self,
        header: FileHeader,
        password: Vec<u8>,
    ) -> Result<EntryReader<'_>> {
        let salt = header.salt.ok_or_else(|| {
            RarError::Corrupt("encrypted file missing salt".into())
        })?;

        // RAR4 uses an 8-byte salt (the first 8 bytes of the 16-byte salt field).
        let salt8: [u8; 8] = salt[..8].try_into().unwrap();
        let (key, iv) = derive_rar4_key(&password, &salt8);

        self.reader.seek(SeekFrom::Start(header.data_offset))?;
        let mut encrypted = vec![0u8; header.packed_size as usize];
        self.reader.read_exact(&mut encrypted)?;

        let decryptor = Aes128CbcDec::new_from_slices(&key, &iv)
            .map_err(|_| RarError::Corrupt("invalid AES key/IV length".into()))?;

        let mut decrypted = encrypted.clone();
        decryptor
            .decrypt_padded_mut::<cbc::cipher::block_padding::NoPadding>(&mut decrypted)
            .map_err(|_| RarError::IncorrectPassword)?;

        decrypted.truncate(header.unpacked_size as usize);

        let actual_crc = crc32fast::hash(&decrypted);
        if actual_crc != header.file_crc32 {
            return Err(RarError::IncorrectPassword);
        }

        Ok(EntryReader::InMemory(InMemoryReader::new(decrypted)))
    }
}

// ---------------------------------------------------------------------------
// Key derivation for RAR v4
// ---------------------------------------------------------------------------

/// Derive the AES-128 key and IV for RAR v4 encryption.
///
/// RAR v4 uses a custom SHA-1-based KDF that iterates 0x40000 times.
fn derive_rar4_key(password: &[u8], salt: &[u8; 8]) -> ([u8; 16], [u8; 16]) {
    const ITER_COUNT: usize = 0x40000;

    let mut hasher = Sha1::new();
    let mut aes_key = [0u8; 16];
    let mut aes_iv = [0u8; 16];

    let mut raw_bytes = Vec::with_capacity((password.len() + 8 + 3) * ITER_COUNT);

    for i in 0..ITER_COUNT {
        raw_bytes.extend_from_slice(password);
        raw_bytes.extend_from_slice(salt);
        raw_bytes.push((i & 0xFF) as u8);
        raw_bytes.push(((i >> 8) & 0xFF) as u8);
        raw_bytes.push(((i >> 16) & 0xFF) as u8);
    }

    hasher.update(&raw_bytes);
    let hash = hasher.finalize();

    for (i, &b) in hash.iter().take(16).enumerate() {
        aes_key[i] = b;
    }

    let mut iv_hasher = Sha1::new();
    iv_hasher.update(&hash);
    iv_hasher.update(salt);
    let iv_hash = iv_hasher.finalize();
    for (i, &b) in iv_hash.iter().take(16).enumerate() {
        aes_iv[i] = b;
    }

    (aes_key, aes_iv)
}

// ---------------------------------------------------------------------------
// Entry readers
// ---------------------------------------------------------------------------

/// A seekable reader for a single file entry within a RAR archive.
///
/// Implements both [`Read`] and [`Seek`], allowing arbitrary byte-range access.
pub enum EntryReader<'a> {
    /// Direct (STORE) reader backed by the archive file.
    Store(StoreReader<'a>),
    /// In-memory reader for decrypted or small entries.
    InMemory(InMemoryReader),
}

impl<'a> Read for EntryReader<'a> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            EntryReader::Store(r) => r.read(buf),
            EntryReader::InMemory(r) => r.read(buf),
        }
    }
}

impl<'a> Seek for EntryReader<'a> {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        match self {
            EntryReader::Store(r) => r.seek(pos),
            EntryReader::InMemory(r) => r.seek(pos),
        }
    }
}

// ---------------------------------------------------------------------------
// StoreReader
// ---------------------------------------------------------------------------

/// A seekable reader for a STORE (non-compressed) entry.
///
/// Reads directly from the archive file, supporting arbitrary seeks.
pub struct StoreReader<'a> {
    reader: &'a mut dyn ReadSeek,
    data_offset: u64,
    size: u64,
    pos: u64,
    expected_crc32: u32,
}

impl<'a> StoreReader<'a> {
    /// Create a new `StoreReader`.
    pub fn new(
        reader: &'a mut dyn ReadSeek,
        data_offset: u64,
        size: u64,
        expected_crc32: u32,
    ) -> Self {
        StoreReader {
            reader,
            data_offset,
            size,
            pos: 0,
            expected_crc32,
        }
    }

    /// Return the uncompressed size of the entry in bytes.
    pub fn size(&self) -> u64 {
        self.size
    }

    /// Verify the CRC32 of the entire entry data.
    ///
    /// This reads the entire entry from the beginning and computes the CRC32,
    /// then restores the reader position.
    pub fn verify_crc32(&mut self) -> Result<()> {
        let saved_pos = self.pos;
        self.seek(SeekFrom::Start(0))?;

        let mut hasher = crc32fast::Hasher::new();
        let mut buf = [0u8; 8192];
        loop {
            let n = self.read(&mut buf)?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
        }
        let actual = hasher.finalize();

        self.seek(SeekFrom::Start(saved_pos))?;

        if actual != self.expected_crc32 {
            return Err(RarError::DataChecksumMismatch {
                expected: self.expected_crc32,
                actual,
            });
        }
        Ok(())
    }
}

impl<'a> Read for StoreReader<'a> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.pos >= self.size {
            return Ok(0);
        }
        let remaining = self.size - self.pos;
        let to_read = buf.len().min(remaining as usize);

        self.reader
            .seek(SeekFrom::Start(self.data_offset + self.pos))?;
        let n = self.reader.read(&mut buf[..to_read])?;
        self.pos += n as u64;
        Ok(n)
    }
}

impl<'a> Seek for StoreReader<'a> {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let new_pos = match pos {
            SeekFrom::Start(n) => n,
            SeekFrom::End(n) => {
                if n >= 0 {
                    self.size.saturating_add(n as u64)
                } else {
                    self.size.checked_sub((-n) as u64).ok_or_else(|| {
                        io::Error::new(io::ErrorKind::InvalidInput, "seek before start")
                    })?
                }
            }
            SeekFrom::Current(n) => {
                if n >= 0 {
                    self.pos.saturating_add(n as u64)
                } else {
                    self.pos.checked_sub((-n) as u64).ok_or_else(|| {
                        io::Error::new(io::ErrorKind::InvalidInput, "seek before start")
                    })?
                }
            }
        };
        if new_pos > self.size {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "seek past end of entry",
            ));
        }
        self.pos = new_pos;
        Ok(self.pos)
    }
}

// ---------------------------------------------------------------------------
// InMemoryReader
// ---------------------------------------------------------------------------

/// A seekable reader backed by an in-memory buffer.
///
/// Used for decrypted entries where the entire content must be loaded into
/// memory for decryption.
pub struct InMemoryReader {
    data: Vec<u8>,
    pos: usize,
}

impl InMemoryReader {
    /// Create a new `InMemoryReader` from a byte vector.
    pub fn new(data: Vec<u8>) -> Self {
        InMemoryReader { data, pos: 0 }
    }

    /// Return the size of the data in bytes.
    pub fn size(&self) -> usize {
        self.data.len()
    }
}

impl Read for InMemoryReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let remaining = self.data.len().saturating_sub(self.pos);
        let to_read = buf.len().min(remaining);
        buf[..to_read].copy_from_slice(&self.data[self.pos..self.pos + to_read]);
        self.pos += to_read;
        Ok(to_read)
    }
}

impl Seek for InMemoryReader {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let len = self.data.len() as i64;
        let new_pos = match pos {
            SeekFrom::Start(n) => n as i64,
            SeekFrom::End(n) => len + n,
            SeekFrom::Current(n) => self.pos as i64 + n,
        };
        if new_pos < 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "seek before start",
            ));
        }
        if new_pos > len {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "seek past end of entry",
            ));
        }
        self.pos = new_pos as usize;
        Ok(self.pos as u64)
    }
}

// ---------------------------------------------------------------------------
// Helper trait
// ---------------------------------------------------------------------------

/// Combined `Read + Seek` trait object helper.
///
/// This trait is automatically implemented for all types that implement both
/// [`Read`] and [`Seek`].
pub trait ReadSeek: Read + Seek {}
impl<T: Read + Seek> ReadSeek for T {}

// ---------------------------------------------------------------------------
// Path normalization
// ---------------------------------------------------------------------------

fn normalize_path(path: &str) -> String {
    path.replace('\\', "/")
        .trim_start_matches('/')
        .to_lowercase()
}
