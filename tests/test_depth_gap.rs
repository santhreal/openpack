#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
use std::fs::File;
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
fn test_gap_absolute_path_obfuscation() {
    let archive = Scratch::new("zip");

    // Obfuscated absolute paths might trick the zip slip checks if not normalized correctly
    write_zip(
        &archive.path,
        &[
            ("//etc/passwd", b"bad", CompressionMethod::Stored),
            (
                "C:\\Windows\\System32\\cmd.exe",
                b"bad",
                CompressionMethod::Stored,
            ),
        ],
    );

    let pack = OpenPack::open_default(&archive.path).unwrap();

    match pack.entries() {
        Ok(entries) => {
            for entry in entries {
                // If it allowed it, it better have sanitized the path!
                assert!(!entry.name.starts_with("//"), "Absolute path leaked!");
                assert!(
                    !entry.name.contains("C:\\"),
                    "Windows absolute path leaked!"
                );
            }
        }
        Err(err) => {
            assert!(
                matches!(
                    err,
                    OpenPackError::ZipSlip(_) | OpenPackError::InvalidArchive(_)
                ),
                "Expected ZipSlip or InvalidArchive error, got: {err:?}"
            );
        }
    }
}

#[test]
fn test_gap_dot_dot_slash_in_middle() {
    let archive = Scratch::new("zip");

    // Resolves internally, doesn't escape root, but uses traversal syntax
    write_zip(
        &archive.path,
        &[("a/../../b/c.txt", b"content", CompressionMethod::Stored)],
    );

    let pack = OpenPack::open_default(&archive.path).unwrap();

    match pack.entries() {
        Ok(entries) => {
            let found = entries
                .iter()
                .any(|e| e.name == "a/../../b/c.txt" || e.name == "../b/c.txt");
            assert!(found, "If successful, should find the entry");
        }
        Err(err) => {
            assert!(
                matches!(
                    err,
                    OpenPackError::ZipSlip(_) | OpenPackError::InvalidArchive(_)
                ),
                "Expected ZipSlip error for escaping root, got: {err:?}"
            );
        }
    }
}

#[test]
fn test_gap_extract_all_to_symlink() {
    let archive = Scratch::new("zip");

    let file = File::create(&archive.path).unwrap();
    let mut zip = ZipWriter::new(file);
    let mut options = SimpleFileOptions::default().compression_method(CompressionMethod::Stored);
    // 0xA000 is the unix mode for symlink
    options = options.unix_permissions(0o120_000 | 0o777);

    zip.start_file("link", options).unwrap();
    zip.write_all(b"/etc/passwd").unwrap(); // symlink target
    zip.finish().unwrap();

    let pack = OpenPack::open_default(&archive.path).unwrap();
    let dest = tempfile::tempdir().unwrap();

    // GAP finding: Does extract_all_to handle symlinks safely or ignore them?
    let res = pack.extract_all_to(dest.path());
    match res {
        Ok(_) => {
            // If it succeeds, ensure it didn't create a symlink to outside
            let link_path = dest.path().join("link");
            if link_path.exists() {
                if let Ok(meta) = std::fs::symlink_metadata(&link_path) {
                    if meta.file_type().is_symlink() {
                        let target = std::fs::read_link(&link_path).unwrap();
                        assert!(
                            target.is_relative(),
                            "extract_all_to created an absolute symlink!"
                        );
                    }
                }
            }
        }
        Err(e) => {
            // It might reject unsupported features like symlinks
            assert!(
                matches!(
                    e,
                    OpenPackError::Unsupported
                        | OpenPackError::Zip(_)
                        | OpenPackError::Io(_)
                        | OpenPackError::InvalidArchive(_)
                ),
                "Expected valid extraction rejection error, got: {e:?}"
            );
        }
    }
}
