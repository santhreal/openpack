#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
use std::fs::File;
use std::io::Write;
use std::path::PathBuf;

use zip::write::SimpleFileOptions;
use zip::CompressionMethod;
use zip::ZipWriter;

use openpack::{ArchiveFormat, Limits, OpenPack, OpenPackError};

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
fn zip_bomb_ratio_check_in_read_entry() {
    let archive = Scratch::new("zip");

    // Highly compressible payload
    let payload = vec![0u8; 1024 * 1024 * 10]; // 10MB of zeros

    write_zip(
        &archive.path,
        &[("bomb.txt", &payload, CompressionMethod::Deflated)],
    );

    let limits = Limits {
        max_compression_ratio: 5.0, // Strictly allow only 5x compression
        max_entry_uncompressed_size: 20 * 1024 * 1024,
        max_total_uncompressed_size: 20 * 1024 * 1024,
        ..Limits::default()
    };

    let pack = OpenPack::open(&archive.path, limits).unwrap();

    let err = pack.read_entry("bomb.txt").unwrap_err();
    assert!(
        matches!(err, OpenPackError::LimitExceeded(ref msg) if msg.contains("compression ratio limit")),
        "Expected compression ratio limit error, got {err:?}"
    );
}

#[test]
fn path_traversal_in_read_entry() {
    let archive = Scratch::new("zip");

    // Create an archive with a malicious entry name
    write_zip(
        &archive.path,
        &[("../../etc/passwd", b"secret", CompressionMethod::Stored)],
    );

    let pack = OpenPack::open_default(&archive.path).unwrap();

    let err = pack.read_entry("../../etc/passwd").unwrap_err();
    assert!(
        matches!(err, OpenPackError::ZipSlip(_)),
        "Expected ZipSlip error on read_entry"
    );

    let contains_err = pack.contains("../../etc/passwd").unwrap_err();
    assert!(
        matches!(contains_err, OpenPackError::ZipSlip(_)),
        "Expected ZipSlip error on contains"
    );
}

#[test]
fn path_traversal_in_extract_all_to() {
    let archive = Scratch::new("zip");

    write_zip(
        &archive.path,
        &[("../../etc/passwd", b"secret", CompressionMethod::Stored)],
    );

    let pack = OpenPack::open_default(&archive.path).unwrap();

    let extract_dir = tempfile::tempdir().unwrap();

    let err = pack.extract_all_to(extract_dir.path()).unwrap_err();
    assert!(
        matches!(err, OpenPackError::ZipSlip(_)),
        "Expected ZipSlip error on extract_all_to"
    );
}

#[test]
fn null_byte_in_entry_name_is_rejected() {
    let archive = Scratch::new("zip");

    // ZipWriter accepts arbitrary bytes in entry names, including null bytes.
    let file = File::create(&archive.path).unwrap();
    let mut zip = ZipWriter::new(file);
    let options = SimpleFileOptions::default().compression_method(CompressionMethod::Stored);
    zip.start_file("safe\0evil.txt", options).unwrap();
    zip.write_all(b"payload").unwrap();
    zip.finish().unwrap();

    let pack = OpenPack::open_default(&archive.path).unwrap();
    let err = pack.entries().unwrap_err();
    assert!(
        matches!(err, OpenPackError::InvalidArchive(ref msg) if msg.contains("null byte")),
        "Expected InvalidArchive for null byte in entry name, got {err:?}"
    );
}

#[test]
#[cfg(unix)]
fn extract_all_to_rejects_symlink_directory_race() {
    use std::os::unix::fs::symlink;

    let archive = Scratch::new("zip");
    write_zip(
        &archive.path,
        &[("nested/file.txt", b"secret", CompressionMethod::Stored)],
    );

    let pack = OpenPack::open_default(&archive.path).unwrap();
    let extract_dir = tempfile::tempdir().unwrap();

    // Create a symlink at the expected parent directory path pointing elsewhere.
    let nested = extract_dir.path().join("nested");
    let elsewhere = tempfile::tempdir().unwrap();
    symlink(elsewhere.path(), &nested).unwrap();

    let err = pack.extract_all_to(extract_dir.path()).unwrap_err();
    assert!(
        matches!(err, OpenPackError::InvalidArchive(ref msg) if msg.contains("symlink")),
        "Expected InvalidArchive for symlink race, got {err:?}"
    );
}

#[test]
fn contains_bypasses_entry_count_limit() {
    let archive = Scratch::new("zip");
    let file = File::create(&archive.path).unwrap();
    let mut zip = ZipWriter::new(file);
    let options = SimpleFileOptions::default().compression_method(CompressionMethod::Stored);
    for i in 0..50 {
        zip.start_file(format!("file{i}"), options).unwrap();
        zip.write_all(b"x").unwrap();
    }
    zip.finish().unwrap();

    let limits = Limits {
        max_entries: 10,
        ..Limits::default()
    };
    let pack = OpenPack::open(&archive.path, limits).unwrap();

    // entries() correctly rejects the archive
    assert!(
        matches!(pack.entries(), Err(OpenPackError::LimitExceeded(_))),
        "entries() should reject archive exceeding max_entries"
    );

    // BUG: contains() bypasses the limit check and returns true
    let contains_result = pack.contains("file0");
    assert!(
        contains_result.is_err(),
        "contains() should also reject limit violations, got {contains_result:?}"
    );
}

#[test]
fn format_confusion_apk_extension_without_zip_magic() {
    let archive = Scratch::new("apk");
    // Write gzip magic, not ZIP magic
    std::fs::write(&archive.path, b"\x1f\x8b\x08\x00").unwrap();

    // Extension-only APK detection is rejected: gzip magic must not open as Apk.
    assert!(
        matches!(
            OpenPack::open_default(&archive.path),
            Err(OpenPackError::Unsupported)
        ),
        "non-ZIP payload with .apk extension must not open"
    );
}

#[test]
fn zip_bomb_bypass_via_forged_local_header_compressed_size() {
    // Crafted ZIP: actual compressed data is 6 bytes, but local header claims 256 bytes.
    // The real compression ratio is 256/6 ≈ 42.7, which exceeds max_compression_ratio=2.0.
    // BUG: read_entry trusts file.compressed_size() from the local header, computing
    // ratio = 256/256 = 1.0, so the zip bomb passes the defense-in-depth ratio check.
    const FORGED_ZIP: &[u8] = &[
    0x50, 0x4b, 0x03, 0x04, 0x14, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x58, 0x85, 0x96, 0x0d, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01,
    0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x61, 0x63, 0x60, 0x18, 0xd9, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x50,
    0x4b, 0x01, 0x02, 0x14, 0x00, 0x14, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x58, 0x85, 0x96, 0x0d, 0x00, 0x01, 0x00, 0x00, 0x00,
    0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x61, 0x50, 0x4b,
    0x05, 0x06, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x2f, 0x00,
    0x00, 0x00, 0x1f, 0x01, 0x00, 0x00, 0x00, 0x00,
];

    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("forged.zip");
    std::fs::write(&path, FORGED_ZIP).unwrap();

    let limits = Limits {
        max_compression_ratio: 2.0,
        max_entry_uncompressed_size: 512,
        max_total_uncompressed_size: 512,
        ..Limits::default()
    };
    let pack = OpenPack::open(&path, limits).unwrap();

    // entries() uses central-directory sizes: 256 compressed / 256 uncompressed -> ratio 1.0, passes
    let entries = pack.entries().unwrap();
    assert_eq!(entries[0].compressed_size, 256);
    assert_eq!(entries[0].uncompressed_size, 256);

    // BUG: read_entry should reject the zip bomb because actual compressed bytes are ~6,
    // giving a real ratio of ~42.7, but it trusts the local header's compressed_size.
    let result = pack.read_entry("a");
    assert!(
        result.is_err(),
        "read_entry must reject zip bomb with forged local header compressed_size, got {result:?}"
    );
}
