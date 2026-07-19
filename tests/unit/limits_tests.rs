use openpack::Limits;

struct Scratch {
    path: std::path::PathBuf,
}

impl Scratch {
    fn new(suffix: &str) -> Self {
        let id = std::sync::atomic::AtomicUsize::new(0);
        let n = id.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let name = format!("openpack-limits-scratch-{}-{}", n, suffix);
        let path = std::env::temp_dir().join(name);
        Self { path }
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

fn write_file(path: &std::path::Path, data: &[u8]) {
    std::fs::write(path, data).unwrap();
}

#[test]
fn loads_limits_from_embedded_toml() {
    let cfg = include_str!("../../config/limits.toml");
    let parsed = Limits::from_toml(cfg).expect("valid config");
    assert!(parsed.max_entries > 0);
    assert!(parsed.max_archive_size > 0);
}

#[test]
fn limits_roundtrip_from_file() {
    let fixture = Scratch::new("toml");
    write_file(
        fixture.path.as_path(),
        include_bytes!("../../config/limits.toml"),
    );
    let parsed = Limits::from_toml_file(&fixture.path).expect("loaded from file");
    let defaults = Limits::builtin();
    assert_eq!(parsed.max_entries, defaults.max_entries);
    assert_eq!(parsed.max_compression_ratio, defaults.max_compression_ratio);
}

#[test]
fn invalid_limits_are_rejected() {
    let raw = "max_archive_size = \"big\"";
    assert!(Limits::from_toml(raw).is_err());
}

#[test]
fn builtin_limits_match_embedded_toml() {
    let cfg = include_str!("../../config/limits.toml");
    let from_toml = Limits::from_toml(cfg).expect("embedded config is valid");
    let builtin = Limits::builtin();
    assert_eq!(builtin.max_archive_size, from_toml.max_archive_size);
    assert_eq!(
        builtin.max_entry_uncompressed_size,
        from_toml.max_entry_uncompressed_size
    );
    assert_eq!(
        builtin.max_total_uncompressed_size,
        from_toml.max_total_uncompressed_size
    );
    assert_eq!(builtin.max_entries, from_toml.max_entries);
    assert!((builtin.max_compression_ratio - from_toml.max_compression_ratio).abs() < f64::EPSILON);
}

#[test]
fn strict_limits_are_tighter_than_default() {
    let strict = Limits::strict();
    let default = Limits::default();
    assert!(strict.max_archive_size < default.max_archive_size);
    assert!(strict.max_entry_uncompressed_size < default.max_entry_uncompressed_size);
    assert!(strict.max_total_uncompressed_size < default.max_total_uncompressed_size);
    assert!(strict.max_entries < default.max_entries);
    assert!(strict.max_compression_ratio < default.max_compression_ratio);
}

#[test]
fn permissive_limits_are_looser_than_default() {
    let permissive = Limits::permissive();
    let default = Limits::default();
    assert!(permissive.max_archive_size > default.max_archive_size);
    assert!(permissive.max_entry_uncompressed_size > default.max_entry_uncompressed_size);
    assert!(permissive.max_total_uncompressed_size > default.max_total_uncompressed_size);
    assert!(permissive.max_entries > default.max_entries);
    assert!(permissive.max_compression_ratio > default.max_compression_ratio);
}
