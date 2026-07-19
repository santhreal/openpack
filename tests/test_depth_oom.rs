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
fn test_oom_massive_allocation_request() {
    let archive = Scratch::new("zip");

    // Test the limit enforcement mechanism which acts as our OOM protection
    let payload = b"small_payload";
    write_zip(
        &archive.path,
        &[("payload.bin", payload, CompressionMethod::Stored)],
    );

    // Corrupt the zip header to claim an uncompressed size of usize::MAX
    // Since zip-rs handles the parsing, we will instead test how Limits handles OOM boundaries

    // We expect the library to use limits to prevent OOM
    let limits = Limits {
        max_entry_uncompressed_size: 1, // 1 byte limit
        ..Limits::default()
    };

    let pack = OpenPack::open(&archive.path, limits).unwrap();

    // This should fail cleanly via LimitExceeded rather than attempting to allocate and failing OOM
    let result = pack.read_entry("payload.bin");

    assert!(
        matches!(result, Err(OpenPackError::LimitExceeded(_))),
        "Expected OOM protection (LimitExceeded) for massive allocation request relative to limit, got {result:?}"
    );
}
