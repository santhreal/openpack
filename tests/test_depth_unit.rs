#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
use openpack::{
    ArchiveEntry, ArchiveFormat, ExtensionManifestSummary, Limits, OpenPackError,
    PackageJsonSummary,
};

#[test]
fn test_unit_limits_default() {
    let default_limits = Limits::default();
    assert!(default_limits.max_archive_size > 0);
    assert!(default_limits.max_entry_uncompressed_size > 0);
    assert!(
        default_limits.max_total_uncompressed_size >= default_limits.max_entry_uncompressed_size
    );
    assert!(default_limits.max_entries > 0);
    assert!(default_limits.max_compression_ratio > 1.0);
}

#[test]
fn test_unit_archive_format_display() {
    assert_eq!(ArchiveFormat::Zip.to_string(), "zip");
    assert_eq!(ArchiveFormat::Jar.to_string(), "jar");
    assert_eq!(ArchiveFormat::Apk.to_string(), "apk");
    assert_eq!(ArchiveFormat::Ipa.to_string(), "ipa");
    assert_eq!(ArchiveFormat::Crx.to_string(), "crx");
}

#[test]
fn test_unit_openpack_error_formatting() {
    // According to standard Santh rules, errors must contain actionable steps prefixed with "Fix: "
    let err = OpenPackError::InvalidConfig("test".into());
    let err_str = err.to_string();
    assert!(
        err_str.contains("Fix: "),
        "Error missing 'Fix: ': {err_str}"
    );

    let err = OpenPackError::InvalidArchive("test".into());
    let err_str = err.to_string();
    assert!(
        err_str.contains("Fix: "),
        "Error missing 'Fix: ': {err_str}"
    );

    let err = OpenPackError::ZipSlip("test".into());
    let err_str = err.to_string();
    assert!(
        err_str.contains("Fix: "),
        "Error missing 'Fix: ': {err_str}"
    );

    let err = OpenPackError::MissingEntry("test".into());
    let err_str = err.to_string();
    assert!(
        err_str.contains("Fix: "),
        "Error missing 'Fix: ': {err_str}"
    );

    let err = OpenPackError::LimitExceeded("test".into());
    let err_str = err.to_string();
    assert!(
        err_str.contains("Fix: "),
        "Error missing 'Fix: ': {err_str}"
    );

    let err = OpenPackError::Unsupported;
    let err_str = err.to_string();
    assert!(
        err_str.contains("Fix: "),
        "Error missing 'Fix: ': {err_str}"
    );
}

#[test]
fn test_unit_archive_entry_default() {
    let entry = ArchiveEntry::default();
    assert_eq!(entry.name, "");
    assert_eq!(entry.compressed_size, 0);
    assert_eq!(entry.uncompressed_size, 0);
    assert_eq!(entry.crc, 0);
    assert!(!entry.is_dir);
}

#[test]
fn test_unit_extension_manifest_summary() {
    let mut manifest = ExtensionManifestSummary {
        name: Some("test".into()),
        version: Some("1.0".into()),
        manifest_version: Some(3),
        permissions: vec!["storage".into()],
        host_permissions: vec!["*://*/*".into()],
        background_scripts: vec!["bg.js".into()],
        content_scripts: vec!["content.js".into()],
    };

    // Testing serialization / struct accessibility
    assert_eq!(manifest.name.as_deref(), Some("test"));
    assert_eq!(manifest.manifest_version, Some(3));

    // It should implement clone and equality
    let manifest_clone = manifest.clone();
    assert_eq!(manifest, manifest_clone);

    manifest.manifest_version = Some(2);
    assert_ne!(manifest, manifest_clone);
}

#[test]
fn test_unit_package_json_summary() {
    let mut pkg = PackageJsonSummary {
        name: Some("test-pkg".into()),
        version: Some("1.0.0".into()),
        description: Some("desc".into()),
        main: Some("index.js".into()),
        module: None,
        browser: None,
        dependencies: vec!["lodash".into()],
    };

    // Testing serialization / struct accessibility
    assert_eq!(pkg.name.as_deref(), Some("test-pkg"));
    assert_eq!(pkg.dependencies.len(), 1);

    // It should implement clone and equality
    let pkg_clone = pkg.clone();
    assert_eq!(pkg, pkg_clone);

    pkg.main = None;
    assert_ne!(pkg, pkg_clone);
}
