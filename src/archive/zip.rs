use std::collections::BTreeSet;
use std::fs::{self, OpenOptions};
use std::io::{Cursor, Read, Write};
use std::path::{Path, PathBuf};

use zip::read::ZipFile;
use zip::CompressionMethod;
use zip::ZipArchive;

#[cfg(feature = "crx")]
use crate::crx::crx_zip_payload_range;
use crate::security::{
    check_entry_limits, compression_ratio, deflate_input_bytes_used, enforce_entry_count_limit,
    entry_meta, reject_duplicate_entry_name, reject_special_file_entry, validate_entry_name,
};
use crate::types::{ArchiveEntry, ArchiveFormat, OpenPack, OpenPackError};

/// Creates a directory and all parent directories, aborting if any path
/// component is a symlink to prevent symlink race attacks during extraction.
fn create_dir_all_no_symlink(path: &Path) -> Result<(), OpenPackError> {
    if let Ok(meta) = std::fs::symlink_metadata(path) {
        if meta.file_type().is_symlink() {
            return Err(OpenPackError::InvalidArchive(format!(
                "symlink detected at extraction path: {}",
                path.display()
            )));
        }
        if meta.is_dir() {
            return Ok(());
        }
        return Err(OpenPackError::InvalidArchive(format!(
            "path exists and is not a directory: {}",
            path.display()
        )));
    }

    if let Some(parent) = path.parent() {
        create_dir_all_no_symlink(parent)?;
    }

    match std::fs::create_dir(path) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => Ok(()),
        Err(err) => Err(OpenPackError::Io(err)),
    }
}

impl OpenPack {
    fn zip_data(&self) -> Result<&[u8], OpenPackError> {
        let range = match self.format {
            ArchiveFormat::Zip | ArchiveFormat::Jar | ArchiveFormat::Apk | ArchiveFormat::Ipa => {
                0..self.mmap.len()
            }
            #[cfg(feature = "crx")]
            ArchiveFormat::Crx => crx_zip_payload_range(&self.mmap)?,
            #[cfg(not(feature = "crx"))]
            ArchiveFormat::Crx => return Err(OpenPackError::Unsupported),
        };
        Ok(&self.mmap[range])
    }

    fn open_zip_reader(&self) -> Result<ZipArchive<Cursor<&[u8]>>, OpenPackError> {
        let data = self.zip_data()?;
        Ok(ZipArchive::new(Cursor::new(data))?)
    }

    /// Lists all entries in the archive, enforcing limits and security checks.
    pub fn entries(&self) -> Result<Vec<ArchiveEntry>, OpenPackError> {
        let mut archive = self.open_zip_reader()?;
        let entry_count = archive.len();
        enforce_entry_count_limit(entry_count, &self.limits)?;

        let mut names = BTreeSet::new();
        let mut entries = Vec::with_capacity(entry_count);
        let mut total_uncompressed = 0u64;

        for i in 0..entry_count {
            let mut file = archive.by_index(i)?;
            let entry = entry_meta(&mut file)?;
            validate_entry_name(&entry.name)?;
            reject_duplicate_entry_name(&mut names, &entry.name)?;
            check_entry_limits(&self.limits, &entry, &mut total_uncompressed)?;
            entries.push(entry);
        }

        Ok(entries)
    }

    /// Returns `true` if the archive contains an entry with the given name.
    pub fn contains(&self, name: &str) -> Result<bool, OpenPackError> {
        validate_entry_name(name)?;
        let mut archive = self.open_zip_reader()?;
        enforce_entry_count_limit(archive.len(), &self.limits)?;

        let result = match archive.by_name(name) {
            Ok(file) => {
                reject_special_file_entry(&file)?;
                Ok(true)
            }
            Err(zip::result::ZipError::FileNotFound) => Ok(false),
            Err(err) => Err(OpenPackError::from(err)),
        };

        result
    }

    /// Reads the raw bytes of a single entry after its metadata has already
    /// been validated. This is the shared implementation used by both
    /// `read_entry` and `extract_all_to` so extraction does not re-parse the
    /// central directory for every file.
    fn read_zip_file(
        &self,
        entry: &ArchiveEntry,
        file: &mut ZipFile<'_, Cursor<&[u8]>>,
    ) -> Result<Vec<u8>, OpenPackError> {
        let name = &entry.name;

        // Bound the actual decompression so a malicious local header cannot
        // cause unbounded allocation before the post-read size check.
        let max = self.limits.max_entry_uncompressed_size.saturating_add(1);
        let mut data = if let Ok(cap) = usize::try_from(entry.uncompressed_size.min(max)) {
            Vec::with_capacity(cap)
        } else {
            Vec::new()
        };
        (&mut *file).take(max).read_to_end(&mut data)?;

        if data.len() as u64 > self.limits.max_entry_uncompressed_size {
            return Err(OpenPackError::LimitExceeded(format!(
                "entry '{}' decompressed bytes exceed size limit",
                name
            )));
        }

        // Defense in depth: enforce the compression ratio against the actual
        // deflate input bytes, not forged local-header compressed_size fields.
        // Stored entries cannot expand, so their metadata size is sufficient.
        let compressed_for_ratio = if file.compression() == CompressionMethod::Stored {
            entry.compressed_size
        } else if let Some(start) = file.data_start() {
            let zip_data = self.zip_data()?;
            let start = usize::try_from(start).unwrap_or(zip_data.len());
            deflate_input_bytes_used(&zip_data[start..]).ok_or_else(|| {
                OpenPackError::InvalidArchive(format!(
                    "entry '{}' failed deflate validation; compressed data may be malformed or truncated",
                    name
                ))
            })?
        } else {
            entry.compressed_size
        };
        let actual_ratio = compression_ratio(data.len() as u64, compressed_for_ratio);
        if actual_ratio > self.limits.max_compression_ratio {
            return Err(OpenPackError::LimitExceeded(format!(
                "entry '{}' exceeds compression ratio limit",
                name
            )));
        }

        if crc32fast::hash(&data) != entry.crc {
            return Err(OpenPackError::InvalidArchive(format!(
                "entry '{}' failed CRC32 validation",
                name
            )));
        }

        Ok(data)
    }

    /// Reads the uncompressed contents of a single entry.
    pub fn read_entry(&self, name: &str) -> Result<Vec<u8>, OpenPackError> {
        validate_entry_name(name)?;

        // Validate the full archive metadata first so that per-entry limits,
        // total limits, duplicates, and suspicious names are all enforced.
        let entries = self.entries()?;
        let entry = entries
            .into_iter()
            .find(|e| e.name == name)
            .ok_or_else(|| OpenPackError::MissingEntry(name.to_string()))?;

        let mut archive = self.open_zip_reader()?;
        let mut file = archive.by_name(name)?;
        self.read_zip_file(&entry, &mut file)
    }

    /// Extracts every entry in the archive to a destination directory.
    ///
    /// Uses `create_new` for files and validates directories are not symlinks
    /// in order to prevent symlink race attacks.
    pub fn extract_all_to(&self, destination: &Path) -> Result<Vec<PathBuf>, OpenPackError> {
        fs::create_dir_all(destination)?;
        let abs_dest = std::fs::canonicalize(destination)?;
        let entries = self.entries()?;
        let mut written_paths = Vec::with_capacity(entries.len());

        let mut archive = self.open_zip_reader()?;
        for entry in entries {
            validate_entry_name(&entry.name)?;
            let output_path = abs_dest.join(&entry.name);

            // Defense in depth: ensure the resolved path stays inside the
            // extraction root even if destination contains symlinks.
            if !output_path.starts_with(&abs_dest) {
                return Err(OpenPackError::ZipSlip(entry.name));
            }

            if entry.is_dir {
                create_dir_all_no_symlink(&output_path)?;
                continue;
            }

            if let Some(parent) = output_path.parent() {
                create_dir_all_no_symlink(parent)?;
            }

            let mut file = archive.by_name(&entry.name)?;
            let data = self.read_zip_file(&entry, &mut file)?;

            // Use create_new to prevent symlink race attacks: if an attacker
            // has placed a symlink at output_path, this will fail rather than
            // follow the symlink and write to an arbitrary location.
            let mut out_file = OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(&output_path)
                .map_err(OpenPackError::Io)?;
            out_file.write_all(&data).map_err(OpenPackError::Io)?;
            out_file.flush().map_err(OpenPackError::Io)?;
            written_paths.push(output_path);
        }

        written_paths.sort();
        Ok(written_paths)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::archive::test_helpers::*;
    use crate::types::Limits;
    use std::fs::File;
    use std::io::Write;
    use zip::write::SimpleFileOptions;
    use zip::CompressionMethod;

    #[test]
    fn extracts_all_entries_to_destination() {
        let temp = tempfile::tempdir().expect("tempdir");
        let zip_path = temp.path().join("fixture.zip");
        sample_zip(&zip_path).expect("sample zip");

        let pack = OpenPack::open_default(&zip_path).expect("open pack");
        let out_dir = temp.path().join("out");
        let extracted = pack.extract_all_to(&out_dir).expect("extract all");

        assert_eq!(extracted.len(), 2);
        assert!(out_dir.join("manifest.json").exists());
        assert!(out_dir.join("nested/script.js").exists());
    }

    #[test]
    fn lists_entries_and_sizes() {
        let archive = Scratch::new("list.zip");
        write_zip(
            &archive.path,
            &[
                ("a", b"one", CompressionMethod::Stored),
                ("b", b"two", CompressionMethod::Stored),
            ],
        );
        let pack = OpenPack::open_default(&archive.path).expect("open");
        let entries = pack.entries().expect("entries");
        assert_eq!(entries.len(), 2);
        assert!(entries.iter().any(|entry| entry.name == "a"));
        assert!(entries.iter().any(|entry| entry.name == "b"));
        assert!(entries.iter().all(|entry| !entry.is_dir));
    }

    #[test]
    fn reads_entry_bytes() {
        let archive = Scratch::new("read.zip");
        write_zip(
            &archive.path,
            &[("read.txt", b"hello-world", CompressionMethod::Stored)],
        );
        let pack = OpenPack::open_default(&archive.path).expect("open");
        let data = pack.read_entry("read.txt").expect("read");
        assert_eq!(data, b"hello-world");
    }

    #[test]
    fn missing_entry_returns_file_not_found() {
        let archive = Scratch::new("missing-entry.zip");
        write_zip(
            &archive.path,
            &[("present.txt", b"hello", CompressionMethod::Stored)],
        );
        let pack = OpenPack::open_default(&archive.path).expect("open");
        assert!(matches!(
            pack.read_entry("absent.txt"),
            Err(OpenPackError::MissingEntry(_))
        ));
    }

    #[test]
    fn contains_true_and_false() {
        let archive = Scratch::new("contains.zip");
        write_zip(&archive.path, &[("x", b"1", CompressionMethod::Stored)]);
        let pack = OpenPack::open_default(&archive.path).expect("open");
        assert!(pack.contains("x").expect("contains x"));
        assert!(!pack.contains("missing").expect("contains missing"));
    }

    #[test]
    fn contains_on_empty_archive_is_false() {
        let archive = Scratch::new("contains-empty.zip");
        write_empty_zip(&archive.path);
        let pack = OpenPack::open_default(&archive.path).expect("open");
        assert!(!pack.contains("missing").unwrap());
    }

    #[test]
    fn contains_blocks_traversal() {
        let archive = Scratch::new("contains.zip");
        write_zip(&archive.path, &[("x", b"1", CompressionMethod::Stored)]);
        let pack = OpenPack::open_default(&archive.path).expect("open");
        assert!(matches!(
            pack.contains("../x"),
            Err(OpenPackError::ZipSlip(_))
        ));
    }

    #[test]
    fn read_entry_blocks_traversal() {
        let archive = Scratch::new("readbad.zip");
        write_zip(&archive.path, &[("x", b"1", CompressionMethod::Stored)]);
        let pack = OpenPack::open_default(&archive.path).expect("open");
        assert!(matches!(
            pack.read_entry("../../x"),
            Err(OpenPackError::ZipSlip(_))
        ));
    }

    #[test]
    fn rejects_zip_slip_entry_names() {
        let archive = Scratch::new("zip-slip.zip");
        write_zip(
            &archive.path,
            &[
                ("good.txt", b"ok", CompressionMethod::Stored),
                ("../bad.txt", b"bad", CompressionMethod::Stored),
            ],
        );
        let pack = OpenPack::open_default(&archive.path).expect("open");
        assert!(pack.entries().is_err());
    }

    #[test]
    fn zip_writer_rejects_duplicate_entry_names() {
        let archive = Scratch::new("dupe.zip");
        let file = File::create(&archive.path).expect("create");
        let mut zip = zip::ZipWriter::new(file);
        let options = SimpleFileOptions::default().compression_method(CompressionMethod::Stored);
        zip.start_file("dup.txt", options).expect("start first");
        zip.write_all(b"one").expect("write first");
        assert!(zip.start_file("dup.txt", options).is_err());
    }

    #[test]
    fn rejects_zip_slip_absolute_path_entries() {
        let archive = Scratch::new("zip-slip-abs.zip");
        write_zip(
            &archive.path,
            &[("/etc/passwd", b"bad", CompressionMethod::Stored)],
        );
        let pack = OpenPack::open_default(&archive.path).expect("open");
        assert!(matches!(pack.entries(), Err(OpenPackError::ZipSlip(_))));
    }

    #[test]
    fn rejects_zip_slip_backslash_paths() {
        let archive = Scratch::new("zip-slip-win.zip");
        write_zip(
            &archive.path,
            &[("..\\windows\\system.ini", b"bad", CompressionMethod::Stored)],
        );
        let pack = OpenPack::open_default(&archive.path).expect("open");
        assert!(matches!(
            pack.entries(),
            Err(OpenPackError::InvalidArchive(_))
        ));
    }

    #[test]
    fn rejects_zip_slip_terminal_parent_component() {
        let archive = Scratch::new("zip-slip-parent.zip");
        write_zip(
            &archive.path,
            &[("safe/..", b"x", CompressionMethod::Stored)],
        );
        let pack = OpenPack::open_default(&archive.path).expect("open");
        assert!(matches!(pack.entries(), Err(OpenPackError::ZipSlip(_))));
    }

    #[test]
    fn read_entry_size_limit_is_enforced() {
        let archive = Scratch::new("limit.zip");
        let payload = vec![b'a'; 64];
        write_zip(
            &archive.path,
            &[("big", payload.as_slice(), CompressionMethod::Stored)],
        );
        let strict = Limits {
            max_entry_uncompressed_size: 4,
            ..Limits::default()
        };
        let pack = OpenPack::open(&archive.path, strict).expect("open");
        assert!(matches!(
            pack.read_entry("big"),
            Err(OpenPackError::LimitExceeded(_))
        ));
    }

    #[test]
    fn total_uncompressed_size_limit_is_enforced() {
        let archive = Scratch::new("total.zip");
        let mut entries = vec![];
        for i in 0..10 {
            entries.push((
                format!("file{i}"),
                vec![b'a'; 1024].into_boxed_slice(),
                CompressionMethod::Stored,
            ));
        }

        let file = File::create(&archive.path).expect("create");
        let mut zip = zip::ZipWriter::new(file);
        for (name, payload, method) in &entries {
            let options = SimpleFileOptions::default().compression_method(*method);
            zip.start_file(name.as_str(), options).expect("start file");
            zip.write_all(payload.as_ref()).expect("write payload");
        }
        zip.finish().expect("finish");

        let strict = Limits {
            max_total_uncompressed_size: 1024,
            max_entry_uncompressed_size: 1024,
            ..Limits::default()
        };
        let pack = OpenPack::open(&archive.path, strict).expect("open");
        assert!(matches!(
            pack.entries(),
            Err(OpenPackError::LimitExceeded(_))
        ));
    }

    #[test]
    fn compression_ratio_limit_is_enforced() {
        let archive = Scratch::new("ratio.zip");
        let payload = vec![b'a'; 4 * 1024];
        write_zip(
            &archive.path,
            &[("payload", payload.as_slice(), CompressionMethod::Deflated)],
        );
        let strict = Limits {
            max_compression_ratio: 0.5,
            ..Limits::default()
        };
        let pack = OpenPack::open(&archive.path, strict).expect("open");
        assert!(pack.entries().is_err());
    }

    #[test]
    fn create_dir_all_no_symlink_rejects_existing_regular_file() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let file_path = tmp.path().join("nested");
        std::fs::write(&file_path, b"not a directory").expect("write file");

        // BUG: should reject an existing regular file, but returns Ok(())
        let result = create_dir_all_no_symlink(&file_path);
        assert!(
            result.is_err(),
            "Expected error for existing file at directory path, got {result:?}"
        );
    }

    #[test]
    fn starts_with_is_vulnerable_without_canonicalization() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let abs_dest = tmp.path().join("dest");
        std::fs::create_dir_all(&abs_dest).expect("create dest");
        let output_path = abs_dest.join("..");
        // Naive starts_with matches parent paths when `..` is not normalized.
        assert!(
            output_path.starts_with(&abs_dest),
            "document naive starts_with traversal hazard before canonicalize"
        );
        let canonical = output_path.canonicalize().expect("canonicalize");
        assert!(
            !canonical.starts_with(abs_dest.canonicalize().expect("dest canonicalize")),
            "canonicalized paths must not escape the destination root"
        );
    }

    #[test]
    fn zip_bomb_detection_rejects_high_ratio_payload() {
        let archive = Scratch::new("bomb.zip");
        let payload = vec![b'z'; 256 * 1024];
        write_zip(
            &archive.path,
            &[(
                "payload.bin",
                payload.as_slice(),
                CompressionMethod::Deflated,
            )],
        );
        let strict = Limits {
            max_compression_ratio: 2.0,
            ..Limits::default()
        };
        let pack = OpenPack::open(&archive.path, strict).expect("open");
        assert!(matches!(
            pack.entries(),
            Err(OpenPackError::LimitExceeded(_))
        ));
    }

    #[test]
    fn read_entry_large_deflated_succeeds_after_streamend_fix() {
        let archive = Scratch::new("large-deflated.zip");
        // Repeating data compresses well and expands beyond the 16 KiB internal
        // deflate buffer, exercising the empty-input progress path.
        let payload = vec![b'a'; 64 * 1024];
        write_zip(
            &archive.path,
            &[("large.bin", payload.as_slice(), CompressionMethod::Deflated)],
        );
        let loose = Limits {
            max_compression_ratio: 1000.0,
            ..Limits::default()
        };
        let pack = OpenPack::open(&archive.path, loose).expect("open");
        let data = pack
            .read_entry("large.bin")
            .expect("read large deflated entry");
        assert_eq!(data, payload);
    }

    #[test]
    fn extract_all_to_reuses_entries_no_quadratic_reparsing() {
        let archive = Scratch::new("many.zip");
        let mut entries = Vec::new();
        for i in 0..100 {
            entries.push((
                format!("file{i}.txt"),
                vec![b'x'; i].into_boxed_slice(),
                CompressionMethod::Stored,
            ));
        }

        let file = File::create(&archive.path).expect("create");
        let mut zip = zip::ZipWriter::new(file);
        for (name, payload, method) in &entries {
            let options = SimpleFileOptions::default().compression_method(*method);
            zip.start_file(name.as_str(), options).expect("start file");
            zip.write_all(payload.as_ref()).expect("write payload");
        }
        zip.finish().expect("finish");

        let pack = OpenPack::open_default(&archive.path).expect("open");
        let tmp = tempfile::tempdir().expect("tempdir");
        let out = pack.extract_all_to(tmp.path()).expect("extract all");
        assert_eq!(out.len(), 100);
        for i in 0..100 {
            assert_eq!(
                std::fs::read(tmp.path().join(format!("file{i}.txt"))).expect("read extracted"),
                vec![b'x'; i]
            );
        }
    }
}
