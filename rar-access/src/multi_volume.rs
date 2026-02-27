//! Multi-volume RAR archive support.
//!
//! RAR supports splitting archives across multiple files (volumes).
//! There are two naming conventions:
//!
//! **Old style** (RAR v4 default):
//! - First volume: `archive.rar`
//! - Subsequent volumes: `archive.r00`, `archive.r01`, ..., `archive.r99`
//!
//! **New style** (RAR v4 with `NEW_VOLUME_NAME` flag, and RAR v5):
//! - `archive.part1.rar`, `archive.part2.rar`, ...

use std::fs::File;
use std::io::{self, BufReader, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use crate::error::Result;

/// Resolve the list of volume paths for a multi-volume archive.
///
/// Given the path to the first volume, returns an ordered list of all
/// volume paths that exist on disk.
pub fn resolve_volumes(first_volume: &Path) -> Result<Vec<PathBuf>> {
    let mut volumes = Vec::new();
    volumes.push(first_volume.to_path_buf());

    let ext = first_volume
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_lowercase();

    if ext == "rar" {
        let stem = first_volume
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("");

        if let Some(part_num) = parse_part_number(stem) {
            // New-style: archive.part1.rar, archive.part2.rar, ...
            let base_stem = &stem[..stem.rfind('.').unwrap_or(stem.len())];
            let dir = first_volume.parent().unwrap_or(Path::new("."));
            let mut n = part_num + 1;
            loop {
                let next = dir.join(format!("{}.part{}.rar", base_stem, n));
                if next.exists() {
                    volumes.push(next);
                    n += 1;
                } else {
                    break;
                }
            }
        } else {
            // Old-style: archive.rar, archive.r00, archive.r01, ...
            let dir = first_volume.parent().unwrap_or(Path::new("."));
            let stem_str = first_volume
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or("");

            let letters = b"rstuvwxyz";
            'outer: for &letter in letters.iter() {
                for i in 0u32..100 {
                    let next = dir.join(format!("{}.{}{:02}", stem_str, letter as char, i));
                    if next.exists() {
                        volumes.push(next);
                    } else if i == 0 {
                        break 'outer;
                    } else {
                        break;
                    }
                }
            }
        }
    }

    Ok(volumes)
}

/// Parse a part number from a stem like "archive.part1" → Some(1).
fn parse_part_number(stem: &str) -> Option<u32> {
    let dot_pos = stem.rfind('.')?;
    let suffix = &stem[dot_pos + 1..];
    if suffix.starts_with("part") {
        suffix[4..].parse::<u32>().ok()
    } else {
        None
    }
}

/// A reader that spans multiple archive volumes, presenting them as a
/// single contiguous byte stream.
///
/// This is used to read file data that is split across volume boundaries.
pub struct MultiVolumeReader {
    segments: Vec<VolumeSegment>,
    total_len: u64,
    pos: u64,
    current_volume: Option<(usize, BufReader<File>)>,
}

struct VolumeSegment {
    path: PathBuf,
    /// Offset within the volume file where this segment's data starts.
    file_offset: u64,
    /// Length of this segment.
    len: u64,
    /// Start offset of this segment in the combined stream.
    stream_start: u64,
}

impl MultiVolumeReader {
    /// Create a new `MultiVolumeReader` from a list of `(path, file_offset, len)` segments.
    pub fn new(segments: Vec<(PathBuf, u64, u64)>) -> Self {
        let mut stream_start = 0u64;
        let segs: Vec<VolumeSegment> = segments
            .into_iter()
            .map(|(path, file_offset, len)| {
                let seg = VolumeSegment {
                    path,
                    file_offset,
                    len,
                    stream_start,
                };
                stream_start += len;
                seg
            })
            .collect();

        let total_len = stream_start;

        MultiVolumeReader {
            segments: segs,
            total_len,
            pos: 0,
            current_volume: None,
        }
    }

    fn find_segment(&self, stream_pos: u64) -> Option<usize> {
        self.segments.iter().position(|seg| {
            stream_pos >= seg.stream_start && stream_pos < seg.stream_start + seg.len
        })
    }

    fn open_volume(&mut self, seg_idx: usize) -> io::Result<()> {
        if let Some((idx, _)) = &self.current_volume {
            if *idx == seg_idx {
                return Ok(());
            }
        }
        let path = &self.segments[seg_idx].path;
        let file = File::open(path).map_err(|e| {
            io::Error::new(
                e.kind(),
                format!("failed to open volume {}: {}", path.display(), e),
            )
        })?;
        self.current_volume = Some((seg_idx, BufReader::new(file)));
        Ok(())
    }
}

impl Read for MultiVolumeReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.pos >= self.total_len {
            return Ok(0);
        }

        let seg_idx = self.find_segment(self.pos).ok_or_else(|| {
            io::Error::new(io::ErrorKind::UnexpectedEof, "position outside all segments")
        })?;

        self.open_volume(seg_idx)?;

        let seg = &self.segments[seg_idx];
        let offset_in_seg = self.pos - seg.stream_start;
        let remaining_in_seg = seg.len - offset_in_seg;
        let to_read = buf.len().min(remaining_in_seg as usize);

        let file_pos = seg.file_offset + offset_in_seg;
        let (_, reader) = self.current_volume.as_mut().unwrap();
        reader.seek(SeekFrom::Start(file_pos))?;
        let n = reader.read(&mut buf[..to_read])?;
        self.pos += n as u64;
        Ok(n)
    }
}

impl Seek for MultiVolumeReader {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let new_pos = match pos {
            SeekFrom::Start(n) => n,
            SeekFrom::End(n) => {
                if n >= 0 {
                    self.total_len.saturating_add(n as u64)
                } else {
                    self.total_len.checked_sub((-n) as u64).ok_or_else(|| {
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
        if new_pos > self.total_len {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "seek past end of multi-volume stream",
            ));
        }
        self.pos = new_pos;
        Ok(self.pos)
    }
}
