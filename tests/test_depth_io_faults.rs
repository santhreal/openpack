#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::PathBuf;

use zip::write::SimpleFileOptions;
use zip::CompressionMethod;
use zip::ZipWriter;

use openpack::{OpenPack, OpenPackError};

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
fn test_io_fault_partial_write_truncate() {
    let archive = Scratch::new("zip");
    write_zip(
        &archive.path,
        &[("test.txt", b"hello", CompressionMethod::Stored)],
    );

    // Corrupt the zip file by truncating the last few bytes (central directory)
    let file = OpenOptions::new().write(true).open(&archive.path).unwrap();
    let len = file.metadata().unwrap().len();
    file.set_len(len - 10).unwrap();

    // OpenPack doesn't parse on open(), it maps it. Parsing happens in `entries()`
    let pack = OpenPack::open_default(&archive.path).expect("Mmap should succeed");
    let result = pack.entries();
    assert!(
        matches!(
            result,
            Err(OpenPackError::Zip(_) | OpenPackError::InvalidArchive(_))
        ),
        "Expected ZIP parsing error for truncated archive, got {result:?}"
    );
}

#[test]
#[cfg(unix)]
fn test_io_fault_missing_permissions() {
    use std::os::unix::fs::PermissionsExt;

    let archive = Scratch::new("zip");
    write_zip(
        &archive.path,
        &[("test.txt", b"hello", CompressionMethod::Stored)],
    );

    let mut perms = std::fs::metadata(&archive.path).unwrap().permissions();
    perms.set_mode(0o000); // Remove all read/write permissions
    std::fs::set_permissions(&archive.path, perms).unwrap();

    let result = OpenPack::open_default(&archive.path);
    assert!(
        matches!(result, Err(OpenPackError::Io(_))),
        "Expected IO error for missing permissions, got {result:?}"
    );
}

#[test]
fn test_io_fault_empty_file() {
    let archive = Scratch::new("zip");
    File::create(&archive.path).unwrap(); // 0 bytes

    // OpenPack might successfully map a 0-byte file, but parsing entries will fail
    let pack = OpenPack::open_default(&archive.path).expect("Mmap of empty file could succeed");
    let result = pack.entries();
    assert!(
        matches!(
            result,
            Err(OpenPackError::Zip(_) | OpenPackError::InvalidArchive(_))
        ),
        "Expected ZIP parsing error for empty file, got {result:?}"
    );
}
