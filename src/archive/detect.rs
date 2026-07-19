use std::fs::File;
use std::path::Path;

use crate::format::{detect_format, read_archive_bytes};
use crate::types::{ArchiveFormat, Limits, OpenPack, OpenPackError};

impl OpenPack {
    /// Opens an archive with custom safety [`Limits`].
    pub fn open<P: AsRef<Path>>(path: P, limits: Limits) -> Result<Self, OpenPackError> {
        limits.validate()?;
        let path = path.as_ref().to_path_buf();
        let file = File::open(&path)?;
        let metadata = file.metadata()?;

        if metadata.len() > limits.max_archive_size {
            return Err(OpenPackError::LimitExceeded("archive too large".into()));
        }

        let mmap = read_archive_bytes(file, metadata.len())?;
        let format = detect_format(&path, &mmap)?;

        Ok(Self {
            path,
            mmap,
            format,
            limits,
        })
    }

    /// Opens an archive using the default safety [`Limits`].
    pub fn open_default<P: AsRef<Path>>(path: P) -> Result<Self, OpenPackError> {
        Self::open(path, Limits::default())
    }

    /// Returns the path the archive was opened from.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Returns the detected [`ArchiveFormat`].
    pub fn format(&self) -> ArchiveFormat {
        self.format
    }

    #[doc(hidden)]
    pub fn mmap(&self) -> &[u8] {
        &self.mmap[..]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::archive::test_helpers::*;
    use crate::types::{Limits, OpenPackError};
    use zip::CompressionMethod;

    #[test]
    fn detects_zip_and_other_extensions() {
        for (name, expected) in [
            ("archive.zip", ArchiveFormat::Zip),
            ("archive.jar", ArchiveFormat::Jar),
            ("archive.apk", ArchiveFormat::Apk),
            ("archive.ipa", ArchiveFormat::Ipa),
        ] {
            let fixture = Scratch::new("detect");
            let path = fixture.path.with_file_name(name);
            write_file(&path, b"PK\x03\x04");
            let pack = OpenPack::open_default(&path).expect("open with extension");
            assert_eq!(pack.format(), expected);
        }
    }

    #[test]
    fn detects_crx_signature_when_enabled() {
        let payload = Scratch::new("format");
        let zip_payload = payload.path.with_extension("zip");
        write_zip(
            &zip_payload,
            &[("a.txt", b"hello", CompressionMethod::Stored)],
        );
        let bytes = std::fs::read(&zip_payload).unwrap();
        let crx_path = payload.path.with_extension("crx");

        #[cfg(feature = "crx")]
        {
            write_file(&crx_path, &crx_payload(&bytes));
            let pack = OpenPack::open_default(&crx_path).expect("open crx");
            assert_eq!(pack.format(), ArchiveFormat::Crx);
            assert!(pack.entries().is_ok());
        }

        #[cfg(not(feature = "crx"))]
        {
            write_file(&crx_path, &crx_payload(&bytes));
            assert!(matches!(
                OpenPack::open_default(&crx_path),
                Err(OpenPackError::Unsupported)
            ));
        }
    }

    #[test]
    fn crx_magic_without_extension_is_detected_or_blocked() {
        let payload = Scratch::new("raw-payload.zip");
        write_zip(
            &payload.path,
            &[("a.txt", b"hello", CompressionMethod::Stored)],
        );
        let bytes = std::fs::read(&payload.path).expect("payload bytes");
        let raw = Scratch::new("unknown.bin");
        write_file(&raw.path, &crx_payload(&bytes));

        #[cfg(feature = "crx")]
        {
            let pack = OpenPack::open_default(&raw.path).expect("open crx magic");
            assert_eq!(pack.format(), ArchiveFormat::Crx);
        }
        #[cfg(not(feature = "crx"))]
        {
            assert!(matches!(
                OpenPack::open_default(&raw.path),
                Err(OpenPackError::Unsupported)
            ));
        }
    }

    #[test]
    fn unknown_extensions_default_to_zip_format() {
        let archive = Scratch::new("mystery.dat");
        write_file(archive.path.as_path(), b"PK\x03\x04");
        let pack = OpenPack::open_default(&archive.path).expect("open");
        assert_eq!(pack.format(), ArchiveFormat::Zip);
    }

    #[test]
    fn opening_missing_file_fails() {
        let scratch = Scratch::new("missing.zip");
        assert!(OpenPack::open_default(scratch.path).is_err());
    }

    #[test]
    fn open_enforces_archive_size_limit() {
        let path = Scratch::new("big.zip");
        write_file(path.path.as_path(), &vec![0u8; 256]);
        let limits = Limits {
            max_archive_size: 1,
            ..Limits::default()
        };
        assert!(matches!(
            OpenPack::open(path.path, limits),
            Err(OpenPackError::LimitExceeded(_))
        ));
    }

    #[test]
    fn path_api_returns_original_path() {
        let archive = Scratch::new("path.zip");
        write_zip(&archive.path, &[("a", b"1", CompressionMethod::Stored)]);
        let pack = OpenPack::open_default(&archive.path).expect("open");
        assert_eq!(pack.path(), archive.path);
    }

    #[test]
    fn memory_map_is_exposed() {
        let archive = Scratch::new("mmap.zip");
        write_zip(&archive.path, &[("x", b"1", CompressionMethod::Stored)]);
        let pack = OpenPack::open_default(&archive.path).expect("open");
        assert_eq!(
            pack.mmap().len(),
            usize::try_from(std::fs::metadata(&archive.path).unwrap().len()).unwrap()
        );
    }

    #[test]
    fn format_display_uses_lowercase_tokens() {
        assert_eq!(ArchiveFormat::Zip.to_string(), "zip");
        assert_eq!(ArchiveFormat::Jar.to_string(), "jar");
        assert_eq!(ArchiveFormat::Apk.to_string(), "apk");
        assert_eq!(ArchiveFormat::Ipa.to_string(), "ipa");
        assert_eq!(ArchiveFormat::Crx.to_string(), "crx");
    }

    #[test]
    fn empty_file_fails_parsing_gracefully() {
        let archive = Scratch::new("empty-bytes.zip");
        write_file(&archive.path, b"");
        let pack = OpenPack::open_default(&archive.path).expect("open file path");
        assert!(matches!(pack.entries(), Err(OpenPackError::Zip(_))));
    }

    #[test]
    fn builtin_limits_match_positive_defaults() {
        let limits = Limits::builtin();
        assert!(limits.max_archive_size > 0);
        assert!(limits.max_total_uncompressed_size >= limits.max_entry_uncompressed_size);
        assert!(limits.max_compression_ratio >= 1.0);
    }

    #[test]
    fn open_default_uses_standard_limits() {
        let archive = Scratch::new("default-limits.zip");
        write_zip(
            &archive.path,
            &[("hello.txt", b"hello", CompressionMethod::Stored)],
        );
        let pack = OpenPack::open_default(&archive.path).expect("open");
        assert_eq!(pack.entries().unwrap().len(), 1);
        assert_eq!(pack.format(), ArchiveFormat::Zip);
    }

    #[test]
    fn from_toml_file_missing_path_returns_io_error() {
        let missing = Scratch::new("missing-config.toml");
        assert!(matches!(
            Limits::from_toml_file(missing.path.as_path()),
            Err(OpenPackError::Io(_))
        ));
    }

    #[test]
    fn from_toml_file_invalid_data_returns_config_error() {
        let file = Scratch::new("bad-config.toml");
        write_file(file.path.as_path(), b"max_entries = \"many\"");
        assert!(matches!(
            Limits::from_toml_file(file.path.as_path()),
            Err(OpenPackError::InvalidConfig(_))
        ));
    }

    #[test]
    fn limits_can_roundtrip_through_toml() {
        let original = Limits::strict();
        let raw = toml::to_string(&original).expect("serialize");
        let parsed = Limits::from_toml(&raw).expect("parse");
        assert_eq!(parsed.max_archive_size, original.max_archive_size);
        assert_eq!(
            parsed.max_entry_uncompressed_size,
            original.max_entry_uncompressed_size
        );
        assert_eq!(
            parsed.max_total_uncompressed_size,
            original.max_total_uncompressed_size
        );
        assert_eq!(parsed.max_entries, original.max_entries);
    }
}
