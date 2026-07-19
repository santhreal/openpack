#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
use std::fs::File;
use std::io::Write;
use std::path::PathBuf;

use zip::write::SimpleFileOptions;
use zip::CompressionMethod;
use zip::ZipWriter;

use openpack::{Limits, OpenPack};

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
fn test_adversarial_payload_all_zeros() {
    let archive = Scratch::new("zip");
    let payload = vec![0u8; 1024 * 1024]; // 1MB of null bytes
    write_zip(
        &archive.path,
        &[("zeros.bin", &payload, CompressionMethod::Stored)],
    );

    let pack = OpenPack::open_default(&archive.path).expect("Should open archive");
    let entries = pack.entries().expect("Should list entries");
    assert_eq!(entries.len(), 1, "Should find the zeros entry");

    let content = pack
        .read_entry("zeros.bin")
        .expect("Should read zeros entry");
    assert_eq!(content.len(), payload.len(), "Content length mismatch");
    assert!(
        content.iter().all(|&b| b == 0),
        "Content should be all zeros"
    );
}

#[test]
fn test_adversarial_payload_all_0xff() {
    let archive = Scratch::new("zip");
    let payload = vec![0xffu8; 1024 * 1024]; // 1MB of 0xFF bytes
    write_zip(
        &archive.path,
        &[("ones.bin", &payload, CompressionMethod::Stored)],
    );

    let pack = OpenPack::open_default(&archive.path).expect("Should open archive");
    let content = pack.read_entry("ones.bin").expect("Should read ones entry");
    assert_eq!(content.len(), payload.len(), "Content length mismatch");
    assert!(
        content.iter().all(|&b| b == 0xff),
        "Content should be all 0xFF"
    );
}

#[test]
fn test_adversarial_payload_alternating_patterns() {
    let archive = Scratch::new("zip");
    let mut payload = Vec::with_capacity(1024 * 1024);
    for i in 0..1024 * 1024 {
        payload.push(if i % 2 == 0 { 0xaa } else { 0x55 });
    }
    write_zip(
        &archive.path,
        &[("alternating.bin", &payload, CompressionMethod::Deflated)],
    );

    let limits = Limits {
        max_compression_ratio: f64::MAX, // Alternating 0xaa/0x55 compresses incredibly well, avoid zip bomb check
        ..Limits::default()
    };

    let pack = OpenPack::open(&archive.path, limits).expect("Should open archive");
    let content = pack
        .read_entry("alternating.bin")
        .expect("Should read alternating entry");
    assert_eq!(content, payload, "Alternating pattern data corrupted");
}

#[test]
fn test_adversarial_hash_collisions() {
    // Generate inputs to test CRC collisions in internal hash maps or lookup routines.
    // CRC32 collisions: "plumless" and "buckeroo" have the same CRC32 (0x4ddb0c25)
    // "twister" and "pummel" (0x... etc)
    let archive = Scratch::new("zip");

    write_zip(
        &archive.path,
        &[
            ("plumless", b"first", CompressionMethod::Stored),
            ("buckeroo", b"second", CompressionMethod::Stored),
        ],
    );

    let pack = OpenPack::open_default(&archive.path).expect("Should open archive");

    // Ensure both can be independently read
    let content_first = pack
        .read_entry("plumless")
        .expect("Should read first collision entry");
    assert_eq!(content_first, b"first");

    let content_second = pack
        .read_entry("buckeroo")
        .expect("Should read second collision entry");
    assert_eq!(content_second, b"second");
}
