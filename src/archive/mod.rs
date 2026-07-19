pub mod apk;
pub mod crx;
pub mod detect;
pub mod jar;
pub mod zip;

#[cfg(test)]
pub(crate) mod test_helpers {
    use std::fs::File;
    use std::io::Write;
    use std::path::{Path, PathBuf};
    use zip::write::SimpleFileOptions;
    use zip::CompressionMethod;

    pub struct Scratch {
        pub _tmp: tempfile::TempDir,
        pub path: PathBuf,
    }

    impl Scratch {
        pub fn new(suffix: &str) -> Self {
            let tmp = tempfile::tempdir().expect("tempdir");
            let path = tmp.path().join(format!("archive.{suffix}"));
            Self { _tmp: tmp, path }
        }
    }

    pub fn write_zip(path: &Path, entries: &[(&str, &[u8], CompressionMethod)]) {
        let file = File::create(path).expect("create archive");
        let mut zip = zip::ZipWriter::new(file);
        for (name, data, method) in entries {
            let options = SimpleFileOptions::default().compression_method(*method);
            zip.start_file(*name, options).expect("start file");
            zip.write_all(data).expect("write entry");
        }
        zip.finish().expect("finish zip");
    }

    pub fn write_file(path: &Path, data: &[u8]) {
        std::fs::write(path, data).expect("write file");
    }

    pub fn write_empty_zip(path: &Path) {
        let file = File::create(path).expect("create archive");
        let zip = zip::ZipWriter::new(file);
        zip.finish().expect("finish zip");
    }

    pub fn crx_payload(payload: &[u8]) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"Cr24");
        bytes.extend_from_slice(&2u32.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(payload);
        bytes
    }

    #[cfg(feature = "crx")]
    pub fn crx3_payload(header: &[u8], payload: &[u8]) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"Cr24");
        bytes.extend_from_slice(&3u32.to_le_bytes());
        bytes.extend_from_slice(&u32::try_from(header.len()).unwrap().to_le_bytes());
        bytes.extend_from_slice(header);
        bytes.extend_from_slice(payload);
        bytes
    }

    pub fn sample_zip(path: &Path) -> Result<(), Box<dyn std::error::Error>> {
        let file = File::create(path)?;
        let mut zip = zip::ZipWriter::new(file);
        let options = zip::write::SimpleFileOptions::default();
        zip.add_directory("nested/", options)?;
        zip.start_file("manifest.json", options)?;
        zip.write_all(br#"{"name":"fixture"}"#)?;
        zip.start_file("nested/script.js", options)?;
        zip.write_all(b"console.log('hello');")?;
        zip.finish()?;
        Ok(())
    }
}

#[cfg(test)]
mod zip_tests {
    use super::test_helpers::*;
    use crate::types::{Limits, OpenPack, OpenPackError};
    use std::fs::File;
    use std::io::Write;
    use std::sync::Arc;
    use zip::write::SimpleFileOptions;
    use zip::CompressionMethod;

    #[test]
    fn entry_limit_is_enforced() {
        let archive = Scratch::new("entries.zip");
        let file = File::create(&archive.path).expect("create");
        let mut zip = zip::ZipWriter::new(file);
        for i in 0..50 {
            let options =
                SimpleFileOptions::default().compression_method(CompressionMethod::Stored);
            zip.start_file(format!("item{i}"), options).expect("start");
            zip.write_all(b"x").expect("write");
        }
        zip.finish().expect("finish");

        let strict = Limits {
            max_entries: 10,
            ..Limits::default()
        };
        let pack = OpenPack::open(&archive.path, strict).expect("open");
        assert!(matches!(
            pack.entries(),
            Err(OpenPackError::LimitExceeded(_))
        ));
    }

    #[test]
    fn list_is_stable_over_multiple_calls() {
        let archive = Scratch::new("stable.zip");
        write_zip(&archive.path, &[("a", b"1", CompressionMethod::Stored)]);
        let pack = OpenPack::open_default(&archive.path).expect("open");
        assert_eq!(pack.entries().unwrap().len(), 1);
        assert_eq!(pack.entries().unwrap().len(), 1);
    }

    #[test]
    fn reads_entries_multiple_times() {
        let archive = Scratch::new("twice.zip");
        write_zip(&archive.path, &[("a", b"v", CompressionMethod::Stored)]);
        let pack = OpenPack::open_default(&archive.path).expect("open");
        let first = pack.read_entry("a").expect("first");
        let second = pack.read_entry("a").expect("second");
        assert_eq!(first, second);
    }

    #[test]
    fn supports_junit_entry_names() {
        let archive = Scratch::new("names.zip");
        write_zip(
            &archive.path,
            &[
                ("dir/file.txt", b"a", CompressionMethod::Stored),
                ("dir2/file2.txt", b"b", CompressionMethod::Stored),
            ],
        );
        let pack = OpenPack::open_default(&archive.path).expect("open");
        let entries = pack.entries().expect("entries");
        assert_eq!(entries.len(), 2);
    }

    #[test]
    fn detects_path_component_parents_with_dotdot() {
        let archive = Scratch::new("dotzip.zip");
        write_zip(
            &archive.path,
            &[("a/../b.txt", b"x", CompressionMethod::Stored)],
        );
        let pack = OpenPack::open_default(&archive.path).expect("open");
        assert!(pack.entries().is_err());
    }

    #[test]
    fn reads_entry_after_listing() {
        let archive = Scratch::new("after-list.zip");
        write_zip(
            &archive.path,
            &[("readme", b"abc", CompressionMethod::Stored)],
        );
        let pack = OpenPack::open_default(&archive.path).expect("open");
        assert_eq!(pack.entries().unwrap().len(), 1);
        assert_eq!(pack.read_entry("readme").unwrap(), b"abc");
    }

    #[test]
    fn directory_entries_are_reported_as_directories() {
        let archive = Scratch::new("dirs.zip");
        let file = File::create(&archive.path).expect("create");
        let mut zip = zip::ZipWriter::new(file);
        let options = SimpleFileOptions::default().compression_method(CompressionMethod::Stored);
        zip.add_directory("nested/", options).expect("dir");
        zip.start_file("nested/file.txt", options).expect("file");
        zip.write_all(b"content").expect("write");
        zip.finish().expect("finish");

        let pack = OpenPack::open_default(&archive.path).expect("open");
        let entries = pack.entries().unwrap();
        assert!(entries
            .iter()
            .any(|entry| entry.name == "nested/" && entry.is_dir));
        assert!(entries
            .iter()
            .any(|entry| entry.name == "nested/file.txt" && !entry.is_dir));
    }

    #[test]
    fn empty_archives_are_supported() {
        let archive = Scratch::new("empty.zip");
        write_empty_zip(&archive.path);
        let pack = OpenPack::open_default(&archive.path).expect("open");
        let entries = pack.entries().expect("entries");
        assert!(entries.is_empty());
    }

    #[test]
    fn empty_archives_report_missing_entries() {
        let archive = Scratch::new("empty-read.zip");
        write_empty_zip(&archive.path);
        let pack = OpenPack::open_default(&archive.path).expect("open");
        assert!(matches!(
            pack.read_entry("missing.txt"),
            Err(OpenPackError::MissingEntry(_))
        ));
    }

    #[test]
    fn corrupted_zip_is_rejected() {
        let archive = Scratch::new("corrupted.zip");
        write_file(
            &archive.path,
            b"PK\x03\x04this-is-not-a-valid-central-directory",
        );
        assert!(matches!(
            OpenPack::open_default(&archive.path).and_then(|pack| pack.entries()),
            Err(OpenPackError::Zip(_))
        ));
    }

    #[test]
    fn non_archive_bytes_fail_zip_parsing() {
        let archive = Scratch::new("plain.zip");
        write_file(&archive.path, b"not-a-zip");
        // Without PK magic, format detection rejects before ZIP parsing.
        assert!(matches!(
            OpenPack::open_default(&archive.path),
            Err(OpenPackError::Unsupported)
        ));
    }

    #[test]
    fn contains_rejects_empty_entry_name() {
        let archive = Scratch::new("contains-empty-name.zip");
        write_zip(
            &archive.path,
            &[("present.txt", b"value", CompressionMethod::Stored)],
        );
        let pack = OpenPack::open_default(&archive.path).expect("open");
        assert!(matches!(
            pack.contains(""),
            Err(OpenPackError::InvalidArchive(_))
        ));
    }

    #[test]
    fn read_entry_rejects_empty_entry_name() {
        let archive = Scratch::new("read-empty-name.zip");
        write_zip(
            &archive.path,
            &[("present.txt", b"value", CompressionMethod::Stored)],
        );
        let pack = OpenPack::open_default(&archive.path).expect("open");
        assert!(matches!(
            pack.read_entry(""),
            Err(OpenPackError::InvalidArchive(_))
        ));
    }

    #[test]
    fn supports_unicode_entry_names_and_contents() {
        let archive = Scratch::new("unicode.zip");
        let name = "unicodé/こんにちは.txt";
        let payload = "Grüße 🌍".as_bytes();
        write_zip(&archive.path, &[(name, payload, CompressionMethod::Stored)]);
        let pack = OpenPack::open_default(&archive.path).expect("open");
        assert!(pack.contains(name).expect("contains unicode name"));
        assert_eq!(
            pack.read_entry(name).expect("read unicode payload"),
            payload
        );
    }

    #[test]
    fn supports_null_bytes_in_payload() {
        let archive = Scratch::new("null-bytes.zip");
        let payload = b"\0\0abc\0def\0";
        write_zip(
            &archive.path,
            &[("bin.dat", payload, CompressionMethod::Stored)],
        );
        let pack = OpenPack::open_default(&archive.path).expect("open");
        assert_eq!(pack.read_entry("bin.dat").expect("read payload"), payload);
    }

    #[test]
    fn handles_large_entry_payload_within_limits() {
        let archive = Scratch::new("huge-entry.zip");
        let payload = vec![b'x'; 2 * 1024 * 1024];
        write_zip(
            &archive.path,
            &[("huge.bin", payload.as_slice(), CompressionMethod::Stored)],
        );
        let limits = Limits {
            max_entry_uncompressed_size: 3 * 1024 * 1024,
            max_total_uncompressed_size: 3 * 1024 * 1024,
            ..Limits::default()
        };
        let pack = OpenPack::open(&archive.path, limits).expect("open");
        let data = pack.read_entry("huge.bin").expect("read large entry");
        assert_eq!(data.len(), payload.len());
        assert_eq!(data[0], b'x');
        assert_eq!(data[data.len() - 1], b'x');
    }

    #[test]
    fn encoded_traversal_names_are_rejected() {
        let archive = Scratch::new("encoded-traversal.zip");
        write_zip(
            &archive.path,
            &[("%2e%2e/evil.txt", b"bad", CompressionMethod::Stored)],
        );
        let pack = OpenPack::open_default(&archive.path).expect("open");
        assert!(matches!(pack.entries(), Err(OpenPackError::ZipSlip(_))));
    }

    #[test]
    fn doubly_encoded_traversal_names_are_rejected() {
        let archive = Scratch::new("double-encoded-traversal.zip");
        write_zip(
            &archive.path,
            &[("%252e%252e/evil.txt", b"bad", CompressionMethod::Stored)],
        );
        let pack = OpenPack::open_default(&archive.path).expect("open");
        assert!(matches!(pack.entries(), Err(OpenPackError::ZipSlip(_))));
    }

    #[test]
    fn concurrent_reads_are_consistent() {
        let archive = Scratch::new("concurrent-read.zip");
        write_zip(
            &archive.path,
            &[("shared.txt", b"concurrent-value", CompressionMethod::Stored)],
        );
        let pack = Arc::new(OpenPack::open_default(&archive.path).expect("open"));
        let mut handles = Vec::new();
        for _ in 0..8 {
            let pack = Arc::clone(&pack);
            handles.push(std::thread::spawn(move || {
                let data = pack.read_entry("shared.txt").expect("read entry");
                let contains = pack.contains("shared.txt").expect("contains entry");
                let listed = pack.entries().expect("entries");
                (data, contains, listed.len())
            }));
        }
        for handle in handles {
            let (data, contains, len) = handle.join().expect("thread join");
            assert_eq!(data, b"concurrent-value");
            assert!(contains);
            assert_eq!(len, 1);
        }
    }

    #[test]
    fn concurrent_missing_entry_checks_return_false() {
        let archive = Scratch::new("concurrent-miss.zip");
        write_zip(
            &archive.path,
            &[("present.txt", b"v", CompressionMethod::Stored)],
        );
        let pack = Arc::new(OpenPack::open_default(&archive.path).expect("open"));
        let mut handles = Vec::new();
        for _ in 0..6 {
            let pack = Arc::clone(&pack);
            handles.push(std::thread::spawn(move || {
                pack.contains("absent.txt").expect("contains missing")
            }));
        }
        for handle in handles {
            assert!(!handle.join().expect("thread join"));
        }
    }

    #[test]
    fn open_and_read_from_unicode_path() {
        let archive = Scratch::new("unicodé-路径.zip");
        write_zip(
            &archive.path,
            &[("file.txt", b"ok", CompressionMethod::Stored)],
        );
        let pack = OpenPack::open_default(&archive.path).expect("open");
        assert_eq!(pack.path(), archive.path);
        assert_eq!(pack.read_entry("file.txt").unwrap(), b"ok");
    }

    #[test]
    fn map_and_entries_work_repeatedly_after_large_read() {
        let archive = Scratch::new("repeat-large.zip");
        let payload = vec![b'r'; 1024 * 1024];
        write_zip(
            &archive.path,
            &[("repeat.bin", payload.as_slice(), CompressionMethod::Stored)],
        );
        let pack = OpenPack::open_default(&archive.path).expect("open");
        let data = pack.read_entry("repeat.bin").expect("read");
        assert_eq!(data.len(), payload.len());
        assert!(!pack.mmap().is_empty());
        assert_eq!(pack.entries().expect("entries").len(), 1);
        assert_eq!(pack.entries().expect("entries again").len(), 1);
    }

    #[test]
    fn unicode_missing_entry_returns_false() {
        let archive = Scratch::new("unicode-missing.zip");
        write_zip(&archive.path, &[("a.txt", b"a", CompressionMethod::Stored)]);
        let pack = OpenPack::open_default(&archive.path).expect("open");
        assert!(!pack
            .contains("不存在.txt")
            .expect("contains missing unicode"));
    }

    #[test]
    fn nested_archives_can_be_read_via_inner_entry() {
        let inner = Scratch::new("inner.zip");
        write_zip(
            &inner.path,
            &[("inner.txt", b"nested-data", CompressionMethod::Stored)],
        );
        let inner_bytes = std::fs::read(&inner.path).expect("read inner");

        let outer = Scratch::new("outer.zip");
        write_zip(
            &outer.path,
            &[(
                "nested/inner.zip",
                inner_bytes.as_slice(),
                CompressionMethod::Stored,
            )],
        );

        let outer_pack = OpenPack::open_default(&outer.path).expect("open outer");
        let nested_bytes = outer_pack
            .read_entry("nested/inner.zip")
            .expect("inner bytes");
        let extracted = outer.path.with_file_name("extracted-inner.zip");
        write_file(&extracted, &nested_bytes);

        let inner_pack = OpenPack::open_default(&extracted).expect("open nested archive");
        assert_eq!(inner_pack.read_entry("inner.txt").unwrap(), b"nested-data");
    }
}
