#![allow(unused_imports)]
#[cfg(feature = "crx")]
use crate::manifest::summarize_extension_manifest;
#[cfg(feature = "crx")]
use crate::types::ExtensionManifestSummary;
use crate::types::{OpenPack, OpenPackError};

impl OpenPack {
    /// Reads and summarizes a browser extension `manifest.json`.
    #[cfg(feature = "crx")]
    pub fn read_extension_manifest_summary(
        &self,
    ) -> Result<Option<ExtensionManifestSummary>, OpenPackError> {
        let manifest = self.read_manifest_json::<serde_json::Value>()?;
        Ok(manifest.map(summarize_extension_manifest))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::archive::test_helpers::*;
    use crate::types::{ArchiveFormat, OpenPackError};
    use std::fs::File;
    use std::io::Write;
    use zip::CompressionMethod;

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
}
