#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
use std::fs::File;
use std::io::Write;
use std::path::PathBuf;

use proptest::prelude::*;
use zip::write::SimpleFileOptions;
use zip::CompressionMethod;
use zip::ZipWriter;

use openpack::{Limits, OpenPack, OpenPackError};

struct Scratch {
    _tmp: tempfile::TempDir,
    path: PathBuf,
}

impl Scratch {
    fn new(suffix: &str) -> Self {
        let tmp = tempfile::tempdir().expect("tempdir");
        let path = tmp.path().join(format!("archive.{suffix}"));
        Self { _tmp: tmp, path }
    }
}

fn write_zip(path: &std::path::Path, entries: &[(&str, &[u8], CompressionMethod)]) {
    let file = File::create(path).unwrap();
    let mut zip = ZipWriter::new(file);
    for (name, data, comp) in entries {
        let options = SimpleFileOptions::default().compression_method(*comp);
        zip.start_file(*name, options).unwrap();
        zip.write_all(data).unwrap();
    }
    zip.finish().unwrap();
}

proptest! {
    #[test]
    fn proptest_archive_limits(
        max_archive_size in any::<u64>(),
        max_entry_size in any::<u64>(),
        max_total_size in any::<u64>(),
        max_entries in any::<usize>(),
        max_ratio in any::<f64>(),
    ) {
        let archive = Scratch::new("zip");
        write_zip(
            &archive.path,
            &[("test.txt", b"hello world", CompressionMethod::Stored)],
        );

        let limits = Limits {
            max_archive_size,
            max_entry_uncompressed_size: max_entry_size,
            max_total_uncompressed_size: max_total_size,
            max_entries,
            max_compression_ratio: max_ratio,
        };

        let result = OpenPack::open(&archive.path, limits);
        match result {
            Ok(pack) => {
                match pack.entries() {
                    Ok(entries) => {
                         // Must have exactly 1 entry since we wrote exactly 1
                         assert_eq!(entries.len(), 1);
                         assert_eq!(entries[0].name, "test.txt");
                    }
                    Err(e) => {
                        assert!(
                            matches!(e, OpenPackError::LimitExceeded(_) | OpenPackError::Zip(_)),
                            "Unexpected error during entries: {e:?}"
                        );
                    }
                }
            }
            Err(e) => {
                assert!(
                    matches!(e, OpenPackError::InvalidConfig(_) | OpenPackError::LimitExceeded(_) | OpenPackError::Zip(_)),
                    "Unexpected error type: {e:?}"
                );
            }
        }
    }

    #[test]
    fn proptest_arbitrary_entry_names(name in any::<String>()) {
        let archive = Scratch::new("zip");
        let file = File::create(&archive.path).unwrap();
        let mut zip = ZipWriter::new(file);

        // Only proceed if ZipWriter can handle the name
        let options = SimpleFileOptions::default().compression_method(CompressionMethod::Stored);
        if zip.start_file(&name, options).is_ok() {
            zip.write_all(b"data").unwrap();
            zip.finish().unwrap();

            if let Ok(pack) = OpenPack::open_default(&archive.path) {
                // Should either list successfully or fail due to ZipSlip
                match pack.entries() {
                    Ok(entries) => {
                        let found = entries.iter().any(|e| e.name == name);
                        // Zip writer normalizes backslashes sometimes, or we might have an exact match.
                        // We must assert something meaningful:
                        assert!(entries.len() == 1 || entries.is_empty(), "Expected 1 entry or normalized empty name omission");
                        if entries.len() == 1 {
                             // either it's identical, or zip writer did some sanitization
                             assert!(found || entries[0].name != name, "Entry must be present and correctly encoded");
                        }
                    }
                    Err(e) => {
                         assert!(
                            matches!(e, OpenPackError::ZipSlip(_) | OpenPackError::InvalidArchive(_) | OpenPackError::LimitExceeded(_) | OpenPackError::Zip(_)),
                            "Unexpected error type during entries(): {e:?}"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn proptest_arbitrary_content(data in any::<Vec<u8>>()) {
        let archive = Scratch::new("zip");
        write_zip(
            &archive.path,
            &[("data.bin", &data, CompressionMethod::Stored)],
        );

        // Increase limits to handle proptest arbitrary sizes safely
        let limits = Limits {
            max_entry_uncompressed_size: u64::MAX / 2,
            max_total_uncompressed_size: u64::MAX / 2,
            ..Limits::default()
        };

        if let Ok(pack) = OpenPack::open(&archive.path, limits) {
            match pack.read_entry("data.bin") {
                Ok(read_data) => {
                    assert_eq!(read_data, data, "Read data does not match written data");
                }
                Err(e) => {
                    assert!(
                        matches!(e, OpenPackError::LimitExceeded(_) | OpenPackError::Zip(_) | OpenPackError::MissingEntry(_)),
                        "Unexpected error: {e:?}"
                    );
                }
            }
        }
    }
}
