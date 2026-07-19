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
fn test_adversarial_null_byte_path() {
    let archive = Scratch::new("zip");
    let payload = b"content";

    write_zip(
        &archive.path,
        &[("malicious\0name.txt", payload, CompressionMethod::Stored)],
    );

    let pack = OpenPack::open_default(&archive.path).unwrap();

    // Check entries explicitly instead of `if let Ok`
    match pack.entries() {
        Ok(entries) => {
            let found = entries.iter().find(|e| e.name == "malicious\0name.txt");
            assert!(found.is_some(), "Entry must be found if OK");
            let content = pack.read_entry(&found.unwrap().name).unwrap();
            assert_eq!(content, payload);
        }
        Err(e) => {
            assert!(
                matches!(
                    e,
                    OpenPackError::InvalidArchive(_)
                        | OpenPackError::ZipSlip(_)
                        | OpenPackError::Zip(_)
                ),
                "Expected structured error, got: {e:?}"
            );
        }
    }
}

#[test]
fn test_adversarial_zero_byte_archive() {
    let archive = Scratch::new("zip");
    File::create(&archive.path).unwrap(); // Empty file

    let pack = OpenPack::open_default(&archive.path).unwrap();
    let err = pack.entries().unwrap_err();
    assert!(
        matches!(
            err,
            OpenPackError::Zip(zip::result::ZipError::InvalidArchive(_))
        ),
        "Expected InvalidArchive for zero byte file, got: {err:?}"
    );
}

#[test]
fn test_adversarial_huge_name() {
    let archive = Scratch::new("zip");

    // Near 64KB name limit
    let huge_name = "a".repeat(65500);
    let payload = b"small";

    write_zip(
        &archive.path,
        &[(&huge_name, payload, CompressionMethod::Stored)],
    );

    let pack = OpenPack::open_default(&archive.path).unwrap();
    let entries = pack.entries().unwrap();
    assert!(entries.iter().any(|e| e.name == huge_name));

    let content = pack.read_entry(&huge_name).unwrap();
    assert_eq!(content, payload);
}

#[test]
fn test_adversarial_integer_overflow() {
    let archive = Scratch::new("zip");
    write_zip(
        &archive.path,
        &[("test", b"abc", CompressionMethod::Stored)],
    );

    let limits = Limits {
        max_archive_size: u64::MAX,
        max_total_uncompressed_size: u64::MAX,
        max_entry_uncompressed_size: u64::MAX,
        ..Limits::default()
    };

    let pack = OpenPack::open(&archive.path, limits).unwrap();
    let entries = pack.entries().unwrap();
    assert_eq!(entries.len(), 1);
}

#[test]
fn test_adversarial_0xff_bytes() {
    let archive = Scratch::new("zip");
    let name_bytes = b"bad_bytes_\xff\xff\xff";
    let name = String::from_utf8_lossy(name_bytes).into_owned();
    let payload = b"\xff\xff\xff\xff";

    write_zip(
        &archive.path,
        &[(&name, payload, CompressionMethod::Stored)],
    );

    let pack = OpenPack::open_default(&archive.path).unwrap();

    match pack.entries() {
        Ok(entries) => {
            let found = entries.iter().find(|e| e.name == name);
            assert!(found.is_some(), "Should find the 0xff entry");
            let content = pack.read_entry(&found.unwrap().name).unwrap();
            assert_eq!(content, payload);
        }
        Err(e) => {
            assert!(
                matches!(e, OpenPackError::InvalidArchive(_) | OpenPackError::Zip(_)),
                "Expected invalid archive err, got {e:?}"
            );
        }
    }
}
