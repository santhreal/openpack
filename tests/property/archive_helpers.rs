#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::fs::File;
use std::io::Write;
use std::path::PathBuf;

use zip::write::SimpleFileOptions;
use zip::CompressionMethod;
use zip::ZipWriter;

use openpack::Limits;

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

pub fn write_zip(path: &std::path::Path, entries: &[(&str, &[u8], CompressionMethod)]) {
    let file = File::create(path).unwrap();
    let mut zip = ZipWriter::new(file);
    for (name, data, comp) in entries {
        let options = SimpleFileOptions::default().compression_method(*comp);
        zip.start_file(*name, options).unwrap();
        zip.write_all(data).unwrap();
    }
    zip.finish().unwrap();
}

pub fn permissive_limits() -> Limits {
    Limits {
        max_entry_uncompressed_size: u64::MAX / 4,
        max_total_uncompressed_size: u64::MAX / 4,
        max_archive_size: u64::MAX / 4,
        ..Limits::default()
    }
}
