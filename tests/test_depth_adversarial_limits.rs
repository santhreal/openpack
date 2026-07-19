#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
use std::fs::File;
use std::io::Write;
use std::path::PathBuf;

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

#[test]
fn test_adversarial_limits_max_u64() {
    let archive = Scratch::new("zip");
    write_zip(
        &archive.path,
        &[("test.txt", b"hello", CompressionMethod::Stored)],
    );

    let limits = Limits {
        max_archive_size: u64::MAX,
        max_entry_uncompressed_size: u64::MAX,
        max_total_uncompressed_size: u64::MAX,
        ..Limits::default()
    };

    let result = OpenPack::open(&archive.path, limits);
    assert!(
        result.is_ok(),
        "Engine should support u64::MAX limits without overflowing: {result:?}"
    );

    let pack = result.unwrap();
    let entries = pack.entries().expect("Should be able to read entries");
    assert_eq!(entries.len(), 1);
}

#[test]
fn test_adversarial_limits_max_u32_entries() {
    let archive = Scratch::new("zip");
    write_zip(
        &archive.path,
        &[("test.txt", b"hello", CompressionMethod::Stored)],
    );

    let limits = Limits {
        max_entries: u32::MAX as usize, // Might truncate if usize is 32-bit, but u32::MAX is huge
        ..Limits::default()
    };

    let result = OpenPack::open(&archive.path, limits);
    assert!(
        result.is_ok(),
        "Engine should support huge max_entries limits: {result:?}"
    );
}

#[test]
fn test_adversarial_limits_zero() {
    let archive = Scratch::new("zip");
    write_zip(
        &archive.path,
        &[("test.txt", b"hello", CompressionMethod::Stored)],
    );

    let limits = Limits {
        max_entries: 0,
        ..Limits::default()
    };

    let result = OpenPack::open(&archive.path, limits);
    match result {
        Ok(pack) => {
            // Engine might open it, but reading entries should fail
            let entries_result = pack.entries();
            assert!(
                matches!(entries_result, Err(OpenPackError::LimitExceeded(_))),
                "Expected LimitExceeded when max_entries is 0, got {entries_result:?}"
            );
        }
        Err(e) => {
            assert!(
                matches!(
                    e,
                    OpenPackError::LimitExceeded(_) | OpenPackError::InvalidConfig(_)
                ),
                "Expected LimitExceeded or InvalidConfig for 0 limits, got {e:?}"
            );
        }
    }
}

#[test]
fn test_adversarial_limits_zero_sizes() {
    let archive = Scratch::new("zip");
    write_zip(
        &archive.path,
        &[("test.txt", b"hello", CompressionMethod::Stored)],
    );

    let limits = Limits {
        max_archive_size: 0,
        ..Limits::default()
    };

    let result = OpenPack::open(&archive.path, limits);
    assert!(
        matches!(
            result,
            Err(OpenPackError::LimitExceeded(_) | OpenPackError::InvalidConfig(_))
        ),
        "Expected failure when max_archive_size is 0, got {result:?}"
    );

    let limits = Limits {
        max_archive_size: 10000,
        max_entry_uncompressed_size: 0,
        ..Limits::default()
    };

    // Some engines only check entry size during extraction
    if let Ok(pack) = OpenPack::open(&archive.path, limits) {
        let entries_result = pack.entries();
        if let Ok(entries) = entries_result {
            let read_result = pack.read_entry(&entries[0].name);
            assert!(
                matches!(read_result, Err(OpenPackError::LimitExceeded(_))),
                "Expected LimitExceeded for read_entry when limit is 0, got {read_result:?}"
            );
        } else {
            assert!(
                matches!(entries_result, Err(OpenPackError::LimitExceeded(_))),
                "Expected LimitExceeded for entries when limit is 0, got {entries_result:?}"
            );
        }
    }
}
