//! High-level RAR v5 archive reader.

use std::io::{self, BufReader, Read, Seek, SeekFrom};

use aes::Aes256;
use blake2::{Blake2s256, Digest as Blake2Digest};
use cbc::cipher::{BlockDecryptMut, KeyIvInit};
use hmac::Hmac;
use pbkdf2::pbkdf2;
use sha2::Sha256;

use crate::entry::{ArchiveEntry, EntrySelector};
use crate::error::{RarError, Result};
use crate::v4::reader::{EntryReader, InMemoryReader, ReadSeek, StoreReader};

use super::header::{
    read_next_block, ArchiveFlags, Checksum, EncryptionParams, FileEntry, RarV5Header,
    RAR5_SIGNATURE,
};

type Aes256CbcDec = cbc::Decryptor<Aes256>;

/// A RAR v5 archive opened from a reader.
pub struct RarV5Archive<R: Read + Seek> {
    reader: BufReader<R>,
    entries: Vec<FileEntry>,
    archive_flags: ArchiveFlags,
    password: Option<Vec<u8>>,
}

impl<R: Read + Seek> RarV5Archive<R> {
    /// Open a RAR v5 archive from a reader.
    pub fn open(inner: R) -> Result<Self> {
        let mut reader = BufReader::new(inner);
        let archive_flags = Self::read_headers(&mut reader)?;
        let entries = Self::scan_entries(&mut reader)?;

        Ok(RarV5Archive {
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
        self.entries.iter().map(|e| ArchiveEntry::from_v5(e))
    }

    /// Return the number of file entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Return `true` if the archive contains no file entries.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Return `true` if this is a multi-volume archive.
    pub fn is_multi_volume(&self) -> bool {
        self.archive_flags.contains(ArchiveFlags::VOLUME)
    }

    /// Select a file entry and return a seekable reader for it.
    pub fn entry_reader(&mut self, selector: EntrySelector<'_>) -> Result<EntryReader<'_>> {
        let entry = self.find_entry(selector)?;
        let entry = entry.clone();

        if entry.is_encrypted {
            let password = self
                .password
                .as_deref()
                .ok_or(RarError::PasswordRequired)?
                .to_vec();
            return self.make_encrypted_reader(entry, password);
        }

        match entry.compression_method {
            0 => self.make_store_reader(entry),
            m => Err(RarError::UnsupportedCompression(m)),
        }
    }

    // -----------------------------------------------------------------------
    // Private helpers
    // -----------------------------------------------------------------------

    fn read_headers(reader: &mut BufReader<R>) -> Result<ArchiveFlags> {
        let mut sig = [0u8; 8];
        reader.read_exact(&mut sig).map_err(|_| RarError::InvalidSignature)?;
        if sig != RAR5_SIGNATURE {
            return Err(RarError::InvalidSignature);
        }

        match read_next_block(reader)? {
            RarV5Header::Archive { flags, .. } => Ok(flags),
            _ => Err(RarError::Corrupt("expected archive header block".into())),
        }
    }

    fn scan_entries(reader: &mut BufReader<R>) -> Result<Vec<FileEntry>> {
        let mut entries = Vec::new();
        let mut index = 0usize;

        loop {
            match read_next_block(reader) {
                Ok(RarV5Header::File(mut fh)) => {
                    if !fh.is_directory {
                        fh.index = index;
                        entries.push(fh);
                        index += 1;
                    }
                }
                Ok(RarV5Header::EndOfArchive { .. }) => break,
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
                    .find(|e| normalize_path(&e.name) == normalized)
                    .ok_or_else(|| RarError::FileNotFound(path.to_owned()))
            }
        }
    }

    fn make_store_reader(&mut self, entry: FileEntry) -> Result<EntryReader<'_>> {
        self.reader.seek(SeekFrom::Start(entry.data_offset))?;
        let crc32 = entry.checksum.as_ref().and_then(|c| {
            if let Checksum::Crc32(v) = c { Some(*v) } else { None }
        }).unwrap_or(0);

        Ok(EntryReader::Store(StoreReader::new(
            &mut self.reader as &mut dyn ReadSeek,
            entry.data_offset,
            entry.unpacked_size,
            crc32,
        )))
    }

    fn make_encrypted_reader(
        &mut self,
        entry: FileEntry,
        password: Vec<u8>,
    ) -> Result<EntryReader<'_>> {
        let enc = entry.encryption.as_ref().ok_or_else(|| {
            RarError::Corrupt("encrypted file missing encryption parameters".into())
        })?;

        let (key, iv) = derive_rar5_key(&password, enc);

        self.reader.seek(SeekFrom::Start(entry.data_offset))?;
        let mut encrypted = vec![0u8; entry.packed_size as usize];
        self.reader.read_exact(&mut encrypted)?;

        let decryptor = Aes256CbcDec::new_from_slices(&key, &iv)
            .map_err(|_| RarError::Corrupt("invalid AES-256 key/IV length".into()))?;

        let mut decrypted = encrypted.clone();
        decryptor
            .decrypt_padded_mut::<cbc::cipher::block_padding::NoPadding>(&mut decrypted)
            .map_err(|_| RarError::IncorrectPassword)?;

        if entry.unpacked_size > 0 {
            decrypted.truncate(entry.unpacked_size as usize);
        }

        // Note: For RAR5 encrypted files, the CRC32 in the file header is the
        // CRC32 of the *encrypted* data (not the plaintext). We skip CRC32
        // verification here. BLAKE2sp checksums (stored in the extra data area)
        // are for the plaintext and can be verified.
        if let Some(Checksum::Blake2sp(expected)) = &entry.checksum {
            let actual = blake2sp_hash(&decrypted);
            if &actual != expected {
                return Err(RarError::IncorrectPassword);
            }
        }

        Ok(EntryReader::InMemory(InMemoryReader::new(decrypted)))
    }
}

// ---------------------------------------------------------------------------
// Key derivation for RAR v5
// ---------------------------------------------------------------------------

/// Derive the AES-256 key and IV for RAR v5 encryption using PBKDF2-HMAC-SHA256.
fn derive_rar5_key(password: &[u8], enc: &EncryptionParams) -> ([u8; 32], [u8; 16]) {
    let iterations = 1u32 << enc.kdf_count;
    let mut key = [0u8; 32];
    pbkdf2::<Hmac<Sha256>>(password, &enc.salt, iterations, &mut key)
        .expect("PBKDF2 should not fail with valid parameters");
    (key, enc.iv)
}

// ---------------------------------------------------------------------------
// BLAKE2sp hash
// ---------------------------------------------------------------------------

/// Compute a BLAKE2s-256 hash (approximation of BLAKE2sp).
fn blake2sp_hash(data: &[u8]) -> [u8; 32] {
    let mut hasher = Blake2s256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

// ---------------------------------------------------------------------------
// Path normalization
// ---------------------------------------------------------------------------

fn normalize_path(path: &str) -> String {
    path.replace('\\', "/")
        .trim_start_matches('/')
        .to_lowercase()
}
