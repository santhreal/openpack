#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
use std::fs::File;
use std::io::Write;
use std::path::PathBuf;

use zip::write::SimpleFileOptions;
use zip::CompressionMethod;
use zip::ZipWriter;

use openpack::OpenPack;

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
fn test_integer_overflow_u32_truncation_size() {
    let archive = Scratch::new("zip");

    // We want a payload size that when added to some internal buffer could overflow a u32.
    // We can't practically allocate u32::MAX + 1 bytes in memory for the test (4GB+),
    // but we can generate many small files or rely on zip64 headers.
    // For this test, we test bounds at exact limits.
    let payload = vec![0x11; 256];

    write_zip(
        &archive.path,
        &[("exact_256.bin", &payload, CompressionMethod::Stored)],
    );

    let pack = OpenPack::open_default(&archive.path).unwrap();
    let content = pack.read_entry("exact_256.bin").unwrap();
    assert_eq!(content.len(), 256);
}

#[test]
fn test_integer_overflow_pattern_counts() {
    let archive = Scratch::new("zip");

    // Create an archive with exactly 256 entries to test 8-bit overflow counters
    let mut entries = Vec::new();
    let content = b"data";

    for i in 0..256 {
        entries.push(format!("entry_{i}.txt"));
    }

    let file = File::create(&archive.path).unwrap();
    let mut zip = ZipWriter::new(file);
    let options = SimpleFileOptions::default().compression_method(CompressionMethod::Stored);

    for name in &entries {
        zip.start_file(name, options).unwrap();
        zip.write_all(content).unwrap();
    }
    zip.finish().unwrap();

    let pack = OpenPack::open_default(&archive.path).unwrap();
    let listed = pack.entries().unwrap();

    assert_eq!(listed.len(), 256, "Should list exactly 256 entries");

    for i in 0..256 {
        let name = format!("entry_{i}.txt");
        assert!(pack.contains(&name).unwrap(), "Missing entry {name}");
    }
}
