#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
use std::fs::File;
use std::io::Write;
use std::path::PathBuf;
use std::sync::Arc;
use std::thread;

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

#[test]
fn test_concurrent_stress_32_threads() {
    let archive = Scratch::new("zip");

    let file = File::create(&archive.path).unwrap();
    let mut zip = ZipWriter::new(file);
    let options = SimpleFileOptions::default().compression_method(CompressionMethod::Stored);

    for i in 0..100 {
        let name = format!("file_{i}.txt");
        let data = format!("content_{i}");
        zip.start_file(&name, options).unwrap();
        zip.write_all(data.as_bytes()).unwrap();
    }
    zip.finish().unwrap();

    let pack = Arc::new(OpenPack::open_default(&archive.path).unwrap());

    let mut handles = Vec::new();

    for thread_id in 0..32 {
        let pack_clone = Arc::clone(&pack);
        let handle = thread::spawn(move || {
            for iter in 0..50 {
                // Read entries list
                let entries = match pack_clone.entries() {
                    Ok(e) => e,
                    Err(err) => panic!("Thread {thread_id} failed to get entries: {err:?}"),
                };
                assert_eq!(
                    entries.len(),
                    100,
                    "Thread {thread_id} found incorrect entry count"
                );

                // Read a random entry based on thread_id and iter
                let target_idx = (thread_id + iter) % 100;
                let target_name = format!("file_{target_idx}.txt");
                let target_content = format!("content_{target_idx}");

                let contains = match pack_clone.contains(&target_name) {
                    Ok(c) => c,
                    Err(err) => panic!("Thread {thread_id} failed contains check: {err:?}"),
                };
                assert!(contains, "Thread {thread_id} reported missing entry");

                let content = match pack_clone.read_entry(&target_name) {
                    Ok(c) => c,
                    Err(err) => panic!("Thread {thread_id} failed to read entry: {err:?}"),
                };
                assert_eq!(
                    content,
                    target_content.as_bytes(),
                    "Thread {thread_id} read incorrect content"
                );

                // Read a non-existent entry
                let missing_name = format!("missing_{target_idx}.txt");
                let contains_missing = match pack_clone.contains(&missing_name) {
                    Ok(c) => c,
                    Err(err) => panic!("Thread {thread_id} failed missing contains check: {err:?}"),
                };
                assert!(
                    !contains_missing,
                    "Thread {thread_id} reported missing entry exists"
                );

                let read_missing = pack_clone.read_entry(&missing_name);
                assert!(
                    matches!(
                        read_missing,
                        Err(OpenPackError::MissingEntry(_) |
OpenPackError::Zip(zip::result::ZipError::FileNotFound))
                    ),
                    "Thread {thread_id} failed to return MissingEntry or FileNotFound: {read_missing:?}"
                );
            }
        });
        handles.push(handle);
    }

    for handle in handles {
        handle.join().unwrap();
    }
}
