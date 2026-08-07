use openpack::{ArchiveFormat, Limits, OpenPack, OpenPackError};
use std::fs::File;
use std::io::Write;
use std::path::Path;

fn sample_zip(path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let file = File::create(path)?;
    let mut zip = zip::ZipWriter::new(file);
    let options = zip::write::SimpleFileOptions::default();
    zip.add_directory("nested/", options)?;
    zip.start_file("manifest.json", options)?;
    zip.write_all(br#"{"name":"fixture"}"#)?;
    zip.start_file("nested/script.js", options)?;
    zip.write_all(b"console.log('hello');")?;
    zip.finish()?;
    Ok(())
}

#[test]
fn extracts_all_entries_to_destination() {
    let temp = tempfile::tempdir().expect("tempdir");
    let zip_path = temp.path().join("fixture.zip");
    sample_zip(&zip_path).expect("sample zip");

    let pack = OpenPack::open_default(&zip_path).expect("open pack");
    let out_dir = temp.path().join("out");
    let extracted = pack.extract_all_to(&out_dir).expect("extract all");

    assert_eq!(extracted.len(), 2);
    assert!(out_dir.join("manifest.json").exists());
    assert!(out_dir.join("nested/script.js").exists());
}

#[test]
fn reads_json_entry_when_present() {
    let temp = tempfile::tempdir().expect("tempdir");
    let zip_path = temp.path().join("fixture.zip");
    sample_zip(&zip_path).expect("sample zip");

    let pack = OpenPack::open_default(&zip_path).expect("open pack");
    let value = pack
        .read_json_entry::<serde_json::Value>("manifest.json")
        .expect("json read")
        .expect("json present");

    assert_eq!(value["name"], "fixture");
}

#[test]
fn reads_text_entry_when_present() {
    let temp = tempfile::tempdir().expect("tempdir");
    let zip_path = temp.path().join("fixture.zip");
    sample_zip(&zip_path).expect("sample zip");

    let pack = OpenPack::open_default(&zip_path).expect("open pack");
    let text = pack
        .read_text_entry("nested/script.js")
        .expect("text read")
        .expect("text present");

    assert!(text.contains("console.log"));
}

#[test]
fn summarizes_package_json() {
    let temp = tempfile::tempdir().expect("tempdir");
    let zip_path = temp.path().join("fixture.zip");
    let file = File::create(&zip_path).expect("create zip");
    let mut zip = zip::ZipWriter::new(file);
    let options = zip::write::SimpleFileOptions::default();
    zip.start_file("package.json", options)
        .expect("start package");
    zip.write_all(
            br#"{"name":"fixture","version":"1.2.3","main":"index.js","dependencies":{"react":"18.0.0"}}"#,
        )
        .expect("write package");
    zip.finish().expect("finish zip");

    let pack = OpenPack::open_default(&zip_path).expect("open pack");
    let summary = pack
        .read_package_json_summary()
        .expect("package summary")
        .expect("package present");

    assert_eq!(summary.name.as_deref(), Some("fixture"));
    assert_eq!(summary.version.as_deref(), Some("1.2.3"));
    assert_eq!(summary.dependencies, vec!["react".to_string()]);
}

#[cfg(feature = "crx")]
#[test]
fn summarizes_extension_manifest() {
    let temp = tempfile::tempdir().expect("tempdir");
    let zip_path = temp.path().join("fixture.crx");
    let file = File::create(&zip_path).expect("create zip");
    let mut zip = zip::ZipWriter::new(file);
    let options = zip::write::SimpleFileOptions::default();
    zip.start_file("manifest.json", options)
        .expect("start manifest");
    zip.write_all(
        br#"{
                "name":"fixture",
                "version":"1.0.0",
                "manifest_version":3,
                "permissions":["tabs"],
                "host_permissions":["<all_urls>"],
                "background":{"service_worker":"background.js"},
                "content_scripts":[{"matches":["<all_urls>"],"js":["content.js"]}]
            }"#,
    )
    .expect("write manifest");
    zip.finish().expect("finish zip");

    let pack = OpenPack::open_default(&zip_path).expect("open pack");
    let summary = pack
        .read_extension_manifest_summary()
        .expect("manifest summary")
        .expect("manifest present");

    assert_eq!(summary.name.as_deref(), Some("fixture"));
    assert_eq!(summary.manifest_version, Some(3));
    assert_eq!(
        summary.background_scripts,
        vec!["background.js".to_string()]
    );
    assert_eq!(summary.content_scripts, vec!["content.js".to_string()]);
}

use std::path::PathBuf;
use std::sync::Arc;
use zip::write::SimpleFileOptions;
use zip::CompressionMethod;

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

fn write_zip(path: &Path, entries: &[(&str, &[u8], CompressionMethod)]) {
    let file = File::create(path).expect("create archive");
    let mut zip = zip::ZipWriter::new(file);
    for (name, data, method) in entries {
        let options = SimpleFileOptions::default().compression_method(*method);
        zip.start_file(name, options).expect("start file");
        zip.write_all(data).expect("write entry");
    }
    zip.finish().expect("finish zip");
}

fn write_file(path: &Path, data: &[u8]) {
    std::fs::write(path, data).expect("write file");
}

fn write_empty_zip(path: &Path) {
    let file = File::create(path).expect("create archive");
    let zip = zip::ZipWriter::new(file);
    zip.finish().expect("finish zip");
}

fn crx_payload(payload: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"Cr24");
    bytes.extend_from_slice(&2u32.to_le_bytes());
    bytes.extend_from_slice(&0u32.to_le_bytes());
    bytes.extend_from_slice(&0u32.to_le_bytes());
    bytes.extend_from_slice(payload);
    bytes
}

#[cfg(feature = "crx")]
fn crx3_payload(header: &[u8], payload: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"Cr24");
    bytes.extend_from_slice(&3u32.to_le_bytes());
    bytes.extend_from_slice(&u32::try_from(header.len()).unwrap().to_le_bytes());
    bytes.extend_from_slice(header);
    bytes.extend_from_slice(payload);
    bytes
}

#[test]
fn detects_zip_and_other_extensions() {
    for (name, expected) in [
        ("archive.zip", ArchiveFormat::Zip),
        ("archive.jar", ArchiveFormat::Jar),
        ("archive.apk", ArchiveFormat::Apk),
        ("archive.ipa", ArchiveFormat::Ipa),
    ] {
        let fixture = Scratch::new("detect");
        let path = fixture.path.with_file_name(name);
        write_file(&path, b"PK\x03\x04");
        let pack = OpenPack::open_default(&path).expect("open with extension");
        assert_eq!(pack.format(), expected);
    }
}

#[test]
fn detects_crx_signature_when_enabled() {
    let payload = Scratch::new("format");
    let zip_payload = payload.path.with_extension("zip");
    write_zip(
        &zip_payload,
        &[("a.txt", b"hello", CompressionMethod::Stored)],
    );
    let bytes = std::fs::read(&zip_payload).unwrap();
    let crx_path = payload.path.with_extension("crx");

    #[cfg(feature = "crx")]
    {
        write_file(&crx_path, &crx_payload(&bytes));
        let pack = OpenPack::open_default(&crx_path).expect("open crx");
        assert_eq!(pack.format(), ArchiveFormat::Crx);
        assert!(pack.entries().is_ok());
    }

    #[cfg(not(feature = "crx"))]
    {
        write_file(&crx_path, &crx_payload(&bytes));
        assert!(matches!(
            OpenPack::open_default(&crx_path),
            Err(OpenPackError::Unsupported)
        ));
    }
}

#[test]
fn unknown_extensions_default_to_zip_format() {
    let archive = Scratch::new("mystery.dat");
    write_file(archive.path.as_path(), b"PK\x03\x04");
    let pack = OpenPack::open_default(&archive.path).expect("open");
    assert_eq!(pack.format(), ArchiveFormat::Zip);
}

#[test]
fn opening_missing_file_fails() {
    let scratch = Scratch::new("missing.zip");
    assert!(OpenPack::open_default(scratch.path).is_err());
}

#[test]
fn open_enforces_archive_size_limit() {
    let path = Scratch::new("big.zip");
    write_file(path.path.as_path(), &vec![0u8; 256]);
    let limits = Limits {
        max_archive_size: 1,
        ..Limits::default()
    };
    assert!(matches!(
        OpenPack::open(path.path, limits),
        Err(OpenPackError::LimitExceeded(_))
    ));
}

#[test]
fn lists_entries_and_sizes() {
    let archive = Scratch::new("list.zip");
    write_zip(
        &archive.path,
        &[
            ("a", b"one", CompressionMethod::Stored),
            ("b", b"two", CompressionMethod::Stored),
        ],
    );
    let pack = OpenPack::open_default(&archive.path).expect("open");
    let entries = pack.entries().expect("entries");
    assert_eq!(entries.len(), 2);
    assert!(entries.iter().any(|entry| entry.name == "a"));
    assert!(entries.iter().any(|entry| entry.name == "b"));
    assert!(entries.iter().all(|entry| !entry.is_dir));
}

#[test]
fn reads_entry_bytes() {
    let archive = Scratch::new("read.zip");
    write_zip(
        &archive.path,
        &[("read.txt", b"hello-world", CompressionMethod::Stored)],
    );
    let pack = OpenPack::open_default(&archive.path).expect("open");
    let data = pack.read_entry("read.txt").expect("read");
    assert_eq!(data, b"hello-world");
}

#[test]
fn missing_entry_returns_file_not_found() {
    let archive = Scratch::new("missing-entry.zip");
    write_zip(
        &archive.path,
        &[("present.txt", b"hello", CompressionMethod::Stored)],
    );
    let pack = OpenPack::open_default(&archive.path).expect("open");
    assert!(matches!(
        pack.read_entry("absent.txt"),
        Err(OpenPackError::MissingEntry(_))
    ));
}

#[test]
fn contains_true_and_false() {
    let archive = Scratch::new("contains.zip");
    write_zip(&archive.path, &[("x", b"1", CompressionMethod::Stored)]);
    let pack = OpenPack::open_default(&archive.path).expect("open");
    assert!(pack.contains("x").expect("contains x"));
    assert!(!pack.contains("missing").expect("contains missing"));
}

#[test]
fn contains_on_empty_archive_is_false() {
    let archive = Scratch::new("contains-empty.zip");
    write_empty_zip(&archive.path);
    let pack = OpenPack::open_default(&archive.path).expect("open");
    assert!(!pack.contains("missing").unwrap());
}

#[test]
fn contains_blocks_traversal() {
    let archive = Scratch::new("contains.zip");
    write_zip(&archive.path, &[("x", b"1", CompressionMethod::Stored)]);
    let pack = OpenPack::open_default(&archive.path).expect("open");
    assert!(matches!(
        pack.contains("../x"),
        Err(OpenPackError::ZipSlip(_))
    ));
}

#[test]
fn read_entry_blocks_traversal() {
    let archive = Scratch::new("readbad.zip");
    write_zip(&archive.path, &[("x", b"1", CompressionMethod::Stored)]);
    let pack = OpenPack::open_default(&archive.path).expect("open");
    assert!(matches!(
        pack.read_entry("../../x"),
        Err(OpenPackError::ZipSlip(_))
    ));
}

#[test]
fn rejects_zip_slip_entry_names() {
    let archive = Scratch::new("zip-slip.zip");
    write_zip(
        &archive.path,
        &[
            ("good.txt", b"ok", CompressionMethod::Stored),
            ("../bad.txt", b"bad", CompressionMethod::Stored),
        ],
    );
    let pack = OpenPack::open_default(&archive.path).expect("open");
    assert!(pack.entries().is_err());
}

#[test]
fn zip_writer_rejects_duplicate_entry_names() {
    let archive = Scratch::new("dupe.zip");
    let file = File::create(&archive.path).expect("create");
    let mut zip = zip::ZipWriter::new(file);
    let options = SimpleFileOptions::default().compression_method(CompressionMethod::Stored);
    zip.start_file("dup.txt", options).expect("start first");
    zip.write_all(b"one").expect("write first");
    assert!(zip.start_file("dup.txt", options).is_err());
}

#[test]
fn rejects_zip_slip_absolute_path_entries() {
    let archive = Scratch::new("zip-slip-abs.zip");
    write_zip(
        &archive.path,
        &[("/etc/passwd", b"bad", CompressionMethod::Stored)],
    );
    let pack = OpenPack::open_default(&archive.path).expect("open");
    assert!(matches!(pack.entries(), Err(OpenPackError::ZipSlip(_))));
}

#[test]
fn rejects_zip_slip_backslash_paths() {
    let archive = Scratch::new("zip-slip-win.zip");
    write_zip(
        &archive.path,
        &[("..\\windows\\system.ini", b"bad", CompressionMethod::Stored)],
    );
    let pack = OpenPack::open_default(&archive.path).expect("open");
    assert!(matches!(
        pack.entries(),
        Err(OpenPackError::InvalidArchive(_))
    ));
}

#[test]
fn rejects_zip_slip_terminal_parent_component() {
    let archive = Scratch::new("zip-slip-parent.zip");
    write_zip(
        &archive.path,
        &[("safe/..", b"x", CompressionMethod::Stored)],
    );
    let pack = OpenPack::open_default(&archive.path).expect("open");
    assert!(matches!(pack.entries(), Err(OpenPackError::ZipSlip(_))));
}

#[test]
fn memory_map_is_exposed() {
    let archive = Scratch::new("mmap.zip");
    write_zip(&archive.path, &[("x", b"1", CompressionMethod::Stored)]);
    let pack = OpenPack::open_default(&archive.path).expect("open");
    assert_eq!(
        pack.mmap().len(),
        usize::try_from(std::fs::metadata(&archive.path).unwrap().len()).unwrap()
    );
}

#[test]
fn read_entry_size_limit_is_enforced() {
    let archive = Scratch::new("limit.zip");
    let payload = vec![b'a'; 64];
    write_zip(
        &archive.path,
        &[("big", payload.as_slice(), CompressionMethod::Stored)],
    );
    let strict = Limits {
        max_entry_uncompressed_size: 4,
        ..Limits::default()
    };
    let pack = OpenPack::open(&archive.path, strict).expect("open");
    assert!(matches!(
        pack.read_entry("big"),
        Err(OpenPackError::LimitExceeded(_))
    ));
}

#[test]
fn total_uncompressed_size_limit_is_enforced() {
    let archive = Scratch::new("total.zip");
    let mut entries = vec![];
    for i in 0..10 {
        entries.push((
            format!("file{i}"),
            vec![b'a'; 1024].into_boxed_slice(),
            CompressionMethod::Stored,
        ));
    }

    let file = File::create(&archive.path).expect("create");
    let mut zip = zip::ZipWriter::new(file);
    for (name, payload, method) in &entries {
        let options = SimpleFileOptions::default().compression_method(*method);
        zip.start_file(name.as_str(), options).expect("start file");
        zip.write_all(payload.as_ref()).expect("write payload");
    }
    zip.finish().expect("finish");

    let strict = Limits {
        max_total_uncompressed_size: 1024,
        max_entry_uncompressed_size: 1024,
        ..Limits::default()
    };
    let pack = OpenPack::open(&archive.path, strict).expect("open");
    assert!(matches!(
        pack.entries(),
        Err(OpenPackError::LimitExceeded(_))
    ));
}

#[test]
fn compression_ratio_limit_is_enforced() {
    let archive = Scratch::new("ratio.zip");
    let payload = vec![b'a'; 4 * 1024];
    write_zip(
        &archive.path,
        &[("payload", payload.as_slice(), CompressionMethod::Deflated)],
    );
    let strict = Limits {
        max_compression_ratio: 0.5,
        ..Limits::default()
    };
    let pack = OpenPack::open(&archive.path, strict).expect("open");
    assert!(pack.entries().is_err());
}

#[test]
fn zip_bomb_detection_rejects_high_ratio_payload() {
    let archive = Scratch::new("bomb.zip");
    let payload = vec![b'z'; 256 * 1024];
    write_zip(
        &archive.path,
        &[(
            "payload.bin",
            payload.as_slice(),
            CompressionMethod::Deflated,
        )],
    );
    let strict = Limits {
        max_compression_ratio: 2.0,
        ..Limits::default()
    };
    let pack = OpenPack::open(&archive.path, strict).expect("open");
    assert!(matches!(
        pack.entries(),
        Err(OpenPackError::LimitExceeded(_))
    ));
}

#[test]
fn entry_limit_is_enforced() {
    let archive = Scratch::new("entries.zip");
    let file = File::create(&archive.path).expect("create");
    let mut zip = zip::ZipWriter::new(file);
    for i in 0..50 {
        let options = SimpleFileOptions::default().compression_method(CompressionMethod::Stored);
        zip.start_file(format!("item{i}"), options).expect("start");
        zip.write_all(b"x").expect("write");
    }
    zip.finish().expect("finish");

    let strict = Limits {
        max_entries: 10,
        ..Limits::default()
    };
    let pack = OpenPack::open(&archive.path, strict).expect("open");
    assert!(matches!(
        pack.entries(),
        Err(OpenPackError::LimitExceeded(_))
    ));
}

#[test]
fn list_is_stable_over_multiple_calls() {
    let archive = Scratch::new("stable.zip");
    write_zip(&archive.path, &[("a", b"1", CompressionMethod::Stored)]);
    let pack = OpenPack::open_default(&archive.path).expect("open");
    assert_eq!(pack.entries().unwrap().len(), 1);
    assert_eq!(pack.entries().unwrap().len(), 1);
}

#[test]
fn reads_entries_multiple_times() {
    let archive = Scratch::new("twice.zip");
    write_zip(&archive.path, &[("a", b"v", CompressionMethod::Stored)]);
    let pack = OpenPack::open_default(&archive.path).expect("open");
    let first = pack.read_entry("a").expect("first");
    let second = pack.read_entry("a").expect("second");
    assert_eq!(first, second);
}

#[test]
fn supports_junit_entry_names() {
    let archive = Scratch::new("names.zip");
    write_zip(
        &archive.path,
        &[
            ("dir/file.txt", b"a", CompressionMethod::Stored),
            ("dir2/file2.txt", b"b", CompressionMethod::Stored),
        ],
    );
    let pack = OpenPack::open_default(&archive.path).expect("open");
    let entries = pack.entries().expect("entries");
    assert_eq!(entries.len(), 2);
}

#[test]
fn detects_path_component_parents_with_dotdot() {
    let archive = Scratch::new("dotzip.zip");
    write_zip(
        &archive.path,
        &[("a/../b.txt", b"x", CompressionMethod::Stored)],
    );
    let pack = OpenPack::open_default(&archive.path).expect("open");
    assert!(pack.entries().is_err());
}

#[test]
fn path_api_returns_original_path() {
    let archive = Scratch::new("path.zip");
    write_zip(&archive.path, &[("a", b"1", CompressionMethod::Stored)]);
    let pack = OpenPack::open_default(&archive.path).expect("open");
    assert_eq!(pack.path(), archive.path);
}

#[test]
fn reads_entry_after_listing() {
    let archive = Scratch::new("after-list.zip");
    write_zip(
        &archive.path,
        &[("readme", b"abc", CompressionMethod::Stored)],
    );
    let pack = OpenPack::open_default(&archive.path).expect("open");
    assert_eq!(pack.entries().unwrap().len(), 1);
    assert_eq!(pack.read_entry("readme").unwrap(), b"abc");
}

#[test]
fn directory_entries_are_reported_as_directories() {
    let archive = Scratch::new("dirs.zip");
    let file = File::create(&archive.path).expect("create");
    let mut zip = zip::ZipWriter::new(file);
    let options = SimpleFileOptions::default().compression_method(CompressionMethod::Stored);
    zip.add_directory("nested/", options).expect("dir");
    zip.start_file("nested/file.txt", options).expect("file");
    zip.write_all(b"content").expect("write");
    zip.finish().expect("finish");

    let pack = OpenPack::open_default(&archive.path).expect("open");
    let entries = pack.entries().unwrap();
    assert!(entries
        .iter()
        .any(|entry| entry.name == "nested/" && entry.is_dir));
    assert!(entries
        .iter()
        .any(|entry| entry.name == "nested/file.txt" && !entry.is_dir));
}

#[test]
fn empty_archives_are_supported() {
    let archive = Scratch::new("empty.zip");
    write_empty_zip(&archive.path);
    let pack = OpenPack::open_default(&archive.path).expect("open");
    let entries = pack.entries().expect("entries");
    assert!(entries.is_empty());
}

#[test]
fn empty_archives_report_missing_entries() {
    let archive = Scratch::new("empty-read.zip");
    write_empty_zip(&archive.path);
    let pack = OpenPack::open_default(&archive.path).expect("open");
    assert!(matches!(
        pack.read_entry("missing.txt"),
        Err(OpenPackError::MissingEntry(_))
    ));
}

#[test]
fn builtin_limits_match_positive_defaults() {
    let limits = Limits::builtin();
    assert!(limits.max_archive_size > 0);
    assert!(limits.max_total_uncompressed_size >= limits.max_entry_uncompressed_size);
    assert!(limits.max_compression_ratio >= 1.0);
}

#[test]
fn open_default_uses_standard_limits() {
    let archive = Scratch::new("default-limits.zip");
    write_zip(
        &archive.path,
        &[("hello.txt", b"hello", CompressionMethod::Stored)],
    );
    let pack = OpenPack::open_default(&archive.path).expect("open");
    assert_eq!(pack.entries().unwrap().len(), 1);
    assert_eq!(pack.format(), ArchiveFormat::Zip);
}

#[test]
fn corrupted_zip_is_rejected() {
    let archive = Scratch::new("corrupted.zip");
    write_file(
        &archive.path,
        b"PK\x03\x04this-is-not-a-valid-central-directory",
    );
    assert!(matches!(
        OpenPack::open_default(&archive.path).and_then(|pack| pack.entries()),
        Err(OpenPackError::Zip(_))
    ));
}

#[test]
fn non_archive_bytes_fail_zip_parsing() {
    let archive = Scratch::new("plain.zip");
    write_file(&archive.path, b"not-a-zip");
    assert!(matches!(
        OpenPack::open_default(&archive.path),
        Err(OpenPackError::Unsupported)
    ));
}

#[test]
fn from_toml_file_missing_path_returns_io_error() {
    let missing = Scratch::new("missing-config.toml");
    assert!(matches!(
        Limits::from_toml_file(missing.path.as_path()),
        Err(OpenPackError::Io(_))
    ));
}

#[test]
fn from_toml_file_invalid_data_returns_config_error() {
    let file = Scratch::new("bad-config.toml");
    write_file(file.path.as_path(), b"max_entries = \"many\"");
    assert!(matches!(
        Limits::from_toml_file(file.path.as_path()),
        Err(OpenPackError::InvalidConfig(_))
    ));
}

#[test]
fn format_display_uses_lowercase_tokens() {
    assert_eq!(ArchiveFormat::Zip.to_string(), "zip");
    assert_eq!(ArchiveFormat::Jar.to_string(), "jar");
    assert_eq!(ArchiveFormat::Apk.to_string(), "apk");
    assert_eq!(ArchiveFormat::Ipa.to_string(), "ipa");
    assert_eq!(ArchiveFormat::Crx.to_string(), "crx");
}

#[test]
fn contains_rejects_empty_entry_name() {
    let archive = Scratch::new("contains-empty-name.zip");
    write_zip(
        &archive.path,
        &[("present.txt", b"value", CompressionMethod::Stored)],
    );
    let pack = OpenPack::open_default(&archive.path).expect("open");
    assert!(matches!(
        pack.contains(""),
        Err(OpenPackError::InvalidArchive(_))
    ));
}

#[test]
fn read_entry_rejects_empty_entry_name() {
    let archive = Scratch::new("read-empty-name.zip");
    write_zip(
        &archive.path,
        &[("present.txt", b"value", CompressionMethod::Stored)],
    );
    let pack = OpenPack::open_default(&archive.path).expect("open");
    assert!(matches!(
        pack.read_entry(""),
        Err(OpenPackError::InvalidArchive(_))
    ));
}

#[test]
fn supports_unicode_entry_names_and_contents() {
    let archive = Scratch::new("unicode.zip");
    let name = "unicodé/こんにちは.txt";
    let payload = "Grüße 🌍".as_bytes();
    write_zip(&archive.path, &[(name, payload, CompressionMethod::Stored)]);
    let pack = OpenPack::open_default(&archive.path).expect("open");
    assert!(pack.contains(name).expect("contains unicode name"));
    assert_eq!(
        pack.read_entry(name).expect("read unicode payload"),
        payload
    );
}

#[test]
fn supports_null_bytes_in_payload() {
    let archive = Scratch::new("null-bytes.zip");
    let payload = b"\0\0abc\0def\0";
    write_zip(
        &archive.path,
        &[("bin.dat", payload, CompressionMethod::Stored)],
    );
    let pack = OpenPack::open_default(&archive.path).expect("open");
    assert_eq!(pack.read_entry("bin.dat").expect("read payload"), payload);
}

#[test]
fn handles_large_entry_payload_within_limits() {
    let archive = Scratch::new("huge-entry.zip");
    let payload = vec![b'x'; 2 * 1024 * 1024];
    write_zip(
        &archive.path,
        &[("huge.bin", payload.as_slice(), CompressionMethod::Stored)],
    );
    let limits = Limits {
        max_entry_uncompressed_size: 3 * 1024 * 1024,
        max_total_uncompressed_size: 3 * 1024 * 1024,
        ..Limits::default()
    };
    let pack = OpenPack::open(&archive.path, limits).expect("open");
    let data = pack.read_entry("huge.bin").expect("read large entry");
    assert_eq!(data.len(), payload.len());
    assert_eq!(data[0], b'x');
    assert_eq!(data[data.len() - 1], b'x');
}

#[test]
fn encoded_traversal_names_are_rejected() {
    let archive = Scratch::new("encoded-traversal.zip");
    write_zip(
        &archive.path,
        &[("%2e%2e/evil.txt", b"bad", CompressionMethod::Stored)],
    );
    let pack = OpenPack::open_default(&archive.path).expect("open");
    assert!(matches!(pack.entries(), Err(OpenPackError::ZipSlip(_))));
}

#[test]
fn doubly_encoded_traversal_names_are_rejected() {
    let archive = Scratch::new("double-encoded-traversal.zip");
    write_zip(
        &archive.path,
        &[("%252e%252e/evil.txt", b"bad", CompressionMethod::Stored)],
    );
    let pack = OpenPack::open_default(&archive.path).expect("open");
    assert!(matches!(pack.entries(), Err(OpenPackError::ZipSlip(_))));
}

#[test]
fn concurrent_reads_are_consistent() {
    let archive = Scratch::new("concurrent-read.zip");
    write_zip(
        &archive.path,
        &[("shared.txt", b"concurrent-value", CompressionMethod::Stored)],
    );
    let pack = Arc::new(OpenPack::open_default(&archive.path).expect("open"));
    let mut handles = Vec::new();
    for _ in 0..8 {
        let pack = Arc::clone(&pack);
        handles.push(std::thread::spawn(move || {
            let data = pack.read_entry("shared.txt").expect("read entry");
            let contains = pack.contains("shared.txt").expect("contains entry");
            let listed = pack.entries().expect("entries");
            (data, contains, listed.len())
        }));
    }
    for handle in handles {
        let (data, contains, len) = handle.join().expect("thread join");
        assert_eq!(data, b"concurrent-value");
        assert!(contains);
        assert_eq!(len, 1);
    }
}

#[test]
fn concurrent_missing_entry_checks_return_false() {
    let archive = Scratch::new("concurrent-miss.zip");
    write_zip(
        &archive.path,
        &[("present.txt", b"v", CompressionMethod::Stored)],
    );
    let pack = Arc::new(OpenPack::open_default(&archive.path).expect("open"));
    let mut handles = Vec::new();
    for _ in 0..6 {
        let pack = Arc::clone(&pack);
        handles.push(std::thread::spawn(move || {
            pack.contains("absent.txt").expect("contains missing")
        }));
    }
    for handle in handles {
        assert!(!handle.join().expect("thread join"));
    }
}

#[test]
fn open_and_read_from_unicode_path() {
    let archive = Scratch::new("unicodé-路径.zip");
    write_zip(
        &archive.path,
        &[("file.txt", b"ok", CompressionMethod::Stored)],
    );
    let pack = OpenPack::open_default(&archive.path).expect("open");
    assert_eq!(pack.path(), archive.path);
    assert_eq!(pack.read_entry("file.txt").unwrap(), b"ok");
}

#[test]
fn map_and_entries_work_repeatedly_after_large_read() {
    let archive = Scratch::new("repeat-large.zip");
    let payload = vec![b'r'; 1024 * 1024];
    write_zip(
        &archive.path,
        &[("repeat.bin", payload.as_slice(), CompressionMethod::Stored)],
    );
    let pack = OpenPack::open_default(&archive.path).expect("open");
    let data = pack.read_entry("repeat.bin").expect("read");
    assert_eq!(data.len(), payload.len());
    assert!(!pack.mmap().is_empty());
    assert_eq!(pack.entries().expect("entries").len(), 1);
    assert_eq!(pack.entries().expect("entries again").len(), 1);
}

#[test]
fn empty_file_fails_parsing_gracefully() {
    let archive = Scratch::new("empty-bytes.zip");
    write_file(&archive.path, b"");
    let pack = OpenPack::open_default(&archive.path).expect("open file path");
    assert!(matches!(pack.entries(), Err(OpenPackError::Zip(_))));
}

#[test]
fn unicode_missing_entry_returns_false() {
    let archive = Scratch::new("unicode-missing.zip");
    write_zip(&archive.path, &[("a.txt", b"a", CompressionMethod::Stored)]);
    let pack = OpenPack::open_default(&archive.path).expect("open");
    assert!(!pack
        .contains("不存在.txt")
        .expect("contains missing unicode"));
}

#[test]
fn crx_magic_without_extension_is_detected_or_blocked() {
    let payload = Scratch::new("raw-payload.zip");
    write_zip(
        &payload.path,
        &[("a.txt", b"hello", CompressionMethod::Stored)],
    );
    let bytes = std::fs::read(&payload.path).expect("payload bytes");
    let raw = Scratch::new("unknown.bin");
    write_file(&raw.path, &crx_payload(&bytes));

    #[cfg(feature = "crx")]
    {
        let pack = OpenPack::open_default(&raw.path).expect("open crx magic");
        assert_eq!(pack.format(), ArchiveFormat::Crx);
    }
    #[cfg(not(feature = "crx"))]
    {
        assert!(matches!(
            OpenPack::open_default(&raw.path),
            Err(OpenPackError::Unsupported)
        ));
    }
}

#[test]
fn limits_can_roundtrip_through_toml() {
    let original = Limits::strict();
    let raw = toml::to_string(&original).expect("serialize");
    let parsed = Limits::from_toml(&raw).expect("parse");
    assert_eq!(parsed.max_archive_size, original.max_archive_size);
    assert_eq!(
        parsed.max_entry_uncompressed_size,
        original.max_entry_uncompressed_size
    );
    assert_eq!(
        parsed.max_total_uncompressed_size,
        original.max_total_uncompressed_size
    );
    assert_eq!(parsed.max_entries, original.max_entries);
}

#[test]
fn nested_archives_can_be_read_via_inner_entry() {
    let inner = Scratch::new("inner.zip");
    write_zip(
        &inner.path,
        &[("inner.txt", b"nested-data", CompressionMethod::Stored)],
    );
    let inner_bytes = std::fs::read(&inner.path).expect("read inner");

    let outer = Scratch::new("outer.zip");
    write_zip(
        &outer.path,
        &[(
            "nested/inner.zip",
            inner_bytes.as_slice(),
            CompressionMethod::Stored,
        )],
    );

    let outer_pack = OpenPack::open_default(&outer.path).expect("open outer");
    let nested_bytes = outer_pack
        .read_entry("nested/inner.zip")
        .expect("inner bytes");
    let extracted = outer.path.with_file_name("extracted-inner.zip");
    write_file(&extracted, &nested_bytes);

    let inner_pack = OpenPack::open_default(&extracted).expect("open nested archive");
    assert_eq!(inner_pack.read_entry("inner.txt").unwrap(), b"nested-data");
}

#[cfg(feature = "crx")]
#[test]
fn crx_header_too_short_is_rejected() {
    let archive = Scratch::new("short.crx");
    write_file(&archive.path, b"Cr24\x02\x00");
    assert!(matches!(
        OpenPack::open_default(&archive.path).and_then(|pack| pack.entries()),
        Err(OpenPackError::InvalidArchive(_))
    ));
}

#[cfg(feature = "crx")]
#[test]
fn crx_invalid_magic_is_rejected() {
    let archive = Scratch::new("badmagic.crx");
    let mut bytes = crx_payload(b"PK\x03\x04");
    bytes[0..4].copy_from_slice(b"Bad!");
    write_file(&archive.path, &bytes);
    assert!(matches!(
        OpenPack::open_default(&archive.path).and_then(|pack| pack.entries()),
        Err(OpenPackError::InvalidArchive(_))
    ));
}

#[cfg(feature = "crx")]
#[test]
fn crx_unsupported_version_is_rejected() {
    let archive = Scratch::new("badversion.crx");
    let mut bytes = crx_payload(b"PK\x03\x04");
    bytes[4..8].copy_from_slice(&4u32.to_le_bytes());
    write_file(&archive.path, &bytes);
    assert!(matches!(
        OpenPack::open_default(&archive.path).and_then(|pack| pack.entries()),
        Err(OpenPackError::InvalidArchive(_))
    ));
}

#[cfg(feature = "crx")]
#[test]
fn crx_invalid_header_lengths_are_rejected() {
    let archive = Scratch::new("badlengths.crx");
    let mut bytes = crx_payload(b"PK\x03\x04");
    bytes[8..12].copy_from_slice(&100u32.to_le_bytes());
    bytes[12..16].copy_from_slice(&100u32.to_le_bytes());
    write_file(&archive.path, &bytes);
    assert!(matches!(
        OpenPack::open_default(&archive.path).and_then(|pack| pack.entries()),
        Err(OpenPackError::InvalidArchive(_))
    ));
}

#[cfg(feature = "crx")]
#[test]
fn crx_header_overflow_is_rejected_without_panicking() {
    let archive = Scratch::new("overflow.crx");
    let mut bytes = crx_payload(b"PK\x03\x04");
    bytes[8..12].copy_from_slice(&u32::MAX.to_le_bytes());
    bytes[12..16].copy_from_slice(&u32::MAX.to_le_bytes());
    write_file(&archive.path, &bytes);
    assert!(matches!(
        OpenPack::open_default(&archive.path).and_then(|pack| pack.entries()),
        Err(OpenPackError::InvalidArchive(_))
    ));
}

#[cfg(feature = "crx")]
#[test]
fn crx3_payloads_are_supported() {
    let archive = Scratch::new("crx3.zip");
    write_zip(&archive.path, &[("x", b"hello", CompressionMethod::Stored)]);
    let payload = std::fs::read(&archive.path).expect("read payload");
    let crx = Scratch::new("crx3.crx");
    write_file(&crx.path, &crx3_payload(&[1, 2, 3], &payload));

    let pack = OpenPack::open_default(&crx.path).expect("open crx3");
    assert_eq!(pack.format(), ArchiveFormat::Crx);
    assert_eq!(pack.read_entry("x").expect("entry"), b"hello");
}

#[cfg(feature = "apk")]
#[test]
fn parse_android_manifest() {
    let archive = Scratch::new("app.apk");
    let manifest = r#"<manifest package="com.example.app" versionName="1.2.3" versionCode="5"><uses-sdk android:minSdkVersion="21"/></manifest>"#;
    write_zip(
        &archive.path,
        &[(
            "AndroidManifest.xml",
            manifest.as_bytes(),
            CompressionMethod::Stored,
        )],
    );
    let pack = OpenPack::open_default(&archive.path).expect("open");
    let parsed = pack.read_android_manifest().expect("manifest");
    assert_eq!(parsed.package, "com.example.app");
    assert_eq!(parsed.version_name.as_deref(), Some("1.2.3"));
}

#[cfg(feature = "ipa")]
#[test]
fn parse_ipa_info_plist() {
    let archive = Scratch::new("app.ipa");
    let plist = r"
        <plist>
          <dict>
            <key>CFBundleIdentifier</key><string>com.example.bundle</string>
            <key>CFBundleExecutable</key><string>Binary</string>
            <key>CFBundleShortVersionString</key><string>4.2.1</string>
          </dict>
        </plist>
        ";
    write_zip(
        &archive.path,
        &[(
            "Payload/App.app/Info.plist",
            plist.as_bytes(),
            CompressionMethod::Stored,
        )],
    );
    let pack = OpenPack::open_default(&archive.path).expect("open");
    let parsed = pack.read_info_plist().expect("plist");
    assert_eq!(
        parsed.bundle_identifier.as_deref(),
        Some("com.example.bundle")
    );
}

#[cfg(feature = "crx")]
#[test]
fn handles_crx_with_nested_zip() {
    let archive = Scratch::new("crx.zip");
    write_zip(&archive.path, &[("x", b"hello", CompressionMethod::Stored)]);
    let payload = std::fs::read(&archive.path).expect("read payload");
    let crx = Scratch::new("crx");
    let crx_path = crx.path;
    write_file(&crx_path, &crx_payload(&payload));
    let pack = OpenPack::open_default(&crx_path).expect("open crx");
    assert!(pack.entries().is_ok());
}

#[test]
fn deep_percent_encoding_beyond_limit_is_rejected() {
    // 11 layers of percent-encoding around "../"  -  more than the 10-round
    // decoder limit, so it must be rejected rather than partially decoded.
    let name = "%25252525252525252525252e%25252525252525252525252fetc/passwd";
    let archive = Scratch::new("deep-encoded.zip");
    write_zip(&archive.path, &[(name, b"bad", CompressionMethod::Stored)]);
    let pack = OpenPack::open_default(&archive.path).expect("open");
    assert!(matches!(pack.entries(), Err(OpenPackError::ZipSlip(_))));
}

#[test]
fn directory_marked_files_still_enforce_size_limits() {
    let archive = Scratch::new("dir-bypass.zip");
    let file = File::create(&archive.path).expect("create");
    let mut zip = zip::ZipWriter::new(file);
    let options = SimpleFileOptions::default().compression_method(CompressionMethod::Stored);
    // Names ending in "/" are treated as directories, but we can still store data.
    zip.start_file("huge_dir/", options).expect("start");
    zip.write_all(&vec![b'x'; 10 * 1024 * 1024]).expect("write");
    zip.finish().expect("finish");

    let strict = Limits {
        max_entry_uncompressed_size: 1024,
        max_total_uncompressed_size: 1024,
        ..Limits::default()
    };
    let pack = OpenPack::open(&archive.path, strict).expect("open");
    // entries() should reject it despite is_dir=true
    assert!(matches!(
        pack.entries(),
        Err(OpenPackError::LimitExceeded(_))
    ));
}

#[test]
fn limits_reject_nan_compression_ratio() {
    let toml = r"
max_archive_size = 104857600
max_entry_uncompressed_size = 10485760
max_total_uncompressed_size = 52428800
max_entries = 1000
max_compression_ratio = nan
";
    assert!(matches!(
        Limits::from_toml(toml),
        Err(OpenPackError::InvalidConfig(_))
    ));
}

#[test]
fn limits_reject_infinite_compression_ratio() {
    let toml = r"
max_archive_size = 104857600
max_entry_uncompressed_size = 10485760
max_total_uncompressed_size = 52428800
max_entries = 1000
max_compression_ratio = inf
";
    assert!(matches!(
        Limits::from_toml(toml),
        Err(OpenPackError::InvalidConfig(_))
    ));
}

#[test]
fn windows_absolute_paths_are_rejected() {
    let archive = Scratch::new("win-abs.zip");
    write_zip(
        &archive.path,
        &[("C:/Windows/System.ini", b"bad", CompressionMethod::Stored)],
    );
    let pack = OpenPack::open_default(&archive.path).expect("open");
    assert!(matches!(pack.entries(), Err(OpenPackError::ZipSlip(_))));
}
#[test]
fn entry_name_validation_rejects_windows_drive_letter_and_percent_traversal() {
    let archive = Scratch::new("drive-percent.zip");
    write_zip(
        &archive.path,
        &[
            ("D:evil", b"bad", CompressionMethod::Stored),
            ("%2e%2e/etc/passwd", b"bad", CompressionMethod::Stored),
        ],
    );
    let pack = OpenPack::open_default(&archive.path).expect("open");
    assert!(matches!(pack.entries(), Err(OpenPackError::ZipSlip(_))));
}

#[test]
fn contains_enforces_full_archive_validation() {
    let archive = Scratch::new("contains-zipslip.zip");
    write_zip(
        &archive.path,
        &[
            ("valid.txt", b"ok", CompressionMethod::Stored),
            ("../evil.txt", b"bad", CompressionMethod::Stored),
        ],
    );
    let pack = OpenPack::open_default(&archive.path).expect("open");
    assert!(matches!(
        pack.contains("valid.txt"),
        Err(OpenPackError::ZipSlip(_))
    ));
}
