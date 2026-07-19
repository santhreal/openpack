#![allow(unused_imports)]
#[cfg(feature = "apk")]
use crate::manifest::parse_android_manifest;
#[cfg(feature = "ipa")]
use crate::manifest::parse_info_plist;
use crate::types::{OpenPack, OpenPackError};

impl OpenPack {
    /// Reads and parses `AndroidManifest.xml` from an APK.
    #[cfg(feature = "apk")]
    pub fn read_android_manifest(&self) -> Result<crate::AndroidManifest, OpenPackError> {
        let bytes = self.read_entry("AndroidManifest.xml")?;
        match parse_android_manifest(&bytes) {
            Some(manifest) => Ok(manifest),
            None => {
                // If the manifest is not valid UTF-8 it is likely AXML (binary Android XML).
                if std::str::from_utf8(&bytes).is_err() {
                    Err(OpenPackError::InvalidArchive(
                        "failed parsing AndroidManifest.xml: binary AXML not supported. Fix: enable an AXML parser or add support via a feature like 'apk-axml'.".into(),
                    ))
                } else {
                    Err(OpenPackError::InvalidArchive(
                        "failed parsing AndroidManifest.xml".into(),
                    ))
                }
            }
        }
    }

    /// Reads and parses `Info.plist` from an IPA.
    #[cfg(feature = "ipa")]
    pub fn read_info_plist(&self) -> Result<crate::IpaInfoPlist, OpenPackError> {
        let entry_name = self
            .entries()?
            .into_iter()
            .find_map(|entry| {
                entry
                    .name
                    .strip_prefix("Payload/")
                    .filter(|inner| {
                        // Require Payload/<Name>.app/Info.plist with no extra
                        // path components, so an embedded extension/app's plist
                        // cannot be mistaken for the root bundle's plist.
                        let parts: Vec<&str> = inner.split('/').collect();
                        parts.len() == 2
                            && parts[0].ends_with(".app")
                            && parts[1] == "Info.plist"
                    })
                    .map(|_| entry.name.clone())
            })
            .ok_or_else(|| OpenPackError::MissingEntry("Info.plist".into()))?;

        let bytes = self.read_entry(&entry_name)?;
        // Binary property lists start with the magic "bplist00".
        if bytes.starts_with(b"bplist00") {
            return Err(OpenPackError::InvalidArchive(
                "Info.plist appears to be a binary plist (bplist00); binary plists are not supported. Fix: enable plist parsing (e.g., add the 'plist' crate behind an 'ipa-plist' feature).".into(),
            ));
        }

        let text = String::from_utf8_lossy(&bytes);
        parse_info_plist(&text)
            .ok_or_else(|| OpenPackError::InvalidArchive("failed parsing Info.plist".into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::archive::test_helpers::*;
    use zip::CompressionMethod;

    #[cfg(feature = "apk")]
    #[test]
    fn apk_manifest_duplicate_attribute_is_first_match() {
        let archive = Scratch::new("app.apk");
        let manifest = r#"<manifest package="com.evil.app" package="com.real.app" versionName="1.0"></manifest>"#;
        use crate::archive::test_helpers::write_zip;
        use zip::CompressionMethod;
        write_zip(
            &archive.path,
            &[("AndroidManifest.xml", manifest.as_bytes(), CompressionMethod::Stored)],
        );
        let pack = OpenPack::open_default(&archive.path).expect("open");
        let parsed = pack.read_android_manifest().expect("manifest");
        // BUG: naive string matching extracts the FIRST (malicious) package attribute
        assert_eq!(
            parsed.package, "com.real.app",
            "Should extract the real package name, not the first duplicate"
        );
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

    #[cfg(feature = "ipa")]
    #[test]
    fn read_info_plist_rejects_embedded_extension_plist() {
        let archive = Scratch::new("app-extension.ipa");
        let root_plist = r"
        <plist><dict>
            <key>CFBundleIdentifier</key><string>com.example.app</string>
        </dict></plist>";
        let ext_plist = r"
        <plist><dict>
            <key>CFBundleIdentifier</key><string>com.evil.extension</string>
        </dict></plist>";
        write_zip(
            &archive.path,
            &[
                (
                    "Payload/App.app/Info.plist",
                    root_plist.as_bytes(),
                    CompressionMethod::Stored,
                ),
                (
                    "Payload/App.app/PlugIns/Ext.appex/Info.plist",
                    ext_plist.as_bytes(),
                    CompressionMethod::Stored,
                ),
            ],
        );
        let pack = OpenPack::open_default(&archive.path).expect("open");
        let parsed = pack.read_info_plist().expect("plist");
        assert_eq!(
            parsed.bundle_identifier.as_deref(),
            Some("com.example.app"),
            "must return the root app bundle plist, not an embedded extension's"
        );
    }
}
