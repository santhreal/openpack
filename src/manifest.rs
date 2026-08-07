#[cfg(feature = "apk")]
use std::str::from_utf8;

#[cfg(feature = "crx")]
use crate::types::ExtensionManifestSummary;
use crate::types::PackageJsonSummary;

/// Summarizes a browser extension `manifest.json` into a structured summary.
#[cfg(feature = "crx")]
pub fn summarize_extension_manifest(value: serde_json::Value) -> ExtensionManifestSummary {
    let permissions = value
        .get("permissions")
        .and_then(|value| value.as_array())
        .into_iter()
        .flatten()
        .filter_map(|value| value.as_str().map(ToOwned::to_owned))
        .collect::<Vec<_>>();
    let host_permissions = value
        .get("host_permissions")
        .and_then(|value| value.as_array())
        .into_iter()
        .flatten()
        .filter_map(|value| value.as_str().map(ToOwned::to_owned))
        .collect::<Vec<_>>();
    let background_scripts = value
        .get("background")
        .map(background_scripts_from_manifest)
        .unwrap_or_default();
    let content_scripts = value
        .get("content_scripts")
        .and_then(|value| value.as_array())
        .into_iter()
        .flatten()
        .flat_map(|group| {
            group
                .get("js")
                .and_then(|value| value.as_array())
                .into_iter()
                .flatten()
                .filter_map(|value| value.as_str().map(ToOwned::to_owned))
        })
        .collect::<Vec<_>>();

    ExtensionManifestSummary {
        name: value
            .get("name")
            .and_then(|value| value.as_str())
            .map(ToOwned::to_owned),
        version: value
            .get("version")
            .and_then(|value| value.as_str())
            .map(ToOwned::to_owned),
        manifest_version: value
            .get("manifest_version")
            .and_then(|value| value.as_u64()),
        permissions,
        host_permissions,
        background_scripts,
        content_scripts,
    }
}

#[cfg(feature = "crx")]
fn background_scripts_from_manifest(value: &serde_json::Value) -> Vec<String> {
    let mut scripts = value
        .get("scripts")
        .and_then(|value| value.as_array())
        .into_iter()
        .flatten()
        .filter_map(|value| value.as_str().map(ToOwned::to_owned))
        .collect::<Vec<_>>();
    if let Some(worker) = value
        .get("service_worker")
        .and_then(|value| value.as_str())
        .map(ToOwned::to_owned)
    {
        scripts.push(worker);
    }
    scripts
}

/// Summarizes a Node.js `package.json` into a structured summary.
pub fn summarize_package_json(value: serde_json::Value) -> PackageJsonSummary {
    let dependencies = value
        .get("dependencies")
        .and_then(|value| value.as_object())
        .map(|deps| deps.keys().cloned().collect::<Vec<_>>())
        .unwrap_or_default();

    PackageJsonSummary {
        name: value
            .get("name")
            .and_then(|value| value.as_str())
            .map(ToOwned::to_owned),
        version: value
            .get("version")
            .and_then(|value| value.as_str())
            .map(ToOwned::to_owned),
        description: value
            .get("description")
            .and_then(|value| value.as_str())
            .map(ToOwned::to_owned),
        main: value
            .get("main")
            .and_then(|value| value.as_str())
            .map(ToOwned::to_owned),
        module: value
            .get("module")
            .and_then(|value| value.as_str())
            .map(ToOwned::to_owned),
        browser: value
            .get("browser")
            .and_then(|value| value.as_str())
            .map(ToOwned::to_owned),
        dependencies,
    }
}

#[cfg(feature = "apk")]
pub(crate) fn parse_android_manifest(bytes: &[u8]) -> Option<crate::AndroidManifest> {
    let clean_bytes = crate::security::strip_bom(bytes);
    let xml = from_utf8(clean_bytes).ok()?;
    let package = extract_xml_attr(xml, "package")?;
    Some(crate::AndroidManifest {
        package,
        version_name: extract_xml_attr(xml, "versionName"),
        version_code: extract_xml_attr(xml, "versionCode"),
        min_sdk: extract_block_attr(xml, "uses-sdk", "android:minSdkVersion")
            .or_else(|| extract_block_attr(xml, "uses-sdk", "android:targetSdkVersion")),
    })
}

/// Returns the byte range of the first real start tag, skipping XML
/// declarations, comments, DOCTYPEs, and processing instructions.
#[cfg(feature = "apk")]
fn first_start_tag_range(xml: &str) -> Option<(usize, usize)> {
    let mut pos = 0;
    while pos < xml.len() {
        let rest = &xml[pos..];
        let lt = rest.find('<')?;
        pos += lt;
        if xml[pos..].starts_with("<!--") {
            let end = xml[pos..].find("-->")? + 3;
            pos += end;
        } else if xml[pos..].starts_with("<?") {
            let end = xml[pos..].find("?>")? + 2;
            pos += end;
        } else if xml[pos..].starts_with("<!") {
            let end = xml[pos..].find('>')? + 1;
            pos += end;
        } else if xml[pos..].starts_with("</") {
            let end = xml[pos..].find('>')? + 1;
            pos += end;
        } else {
            let end = xml[pos..].find('>')? + 1;
            return Some((pos, pos + end));
        }
    }
    None
}

/// Extracts the value of an attribute from a tag string, taking the last
/// occurrence in that tag (well-formed XML forbids duplicate attributes).
#[cfg(feature = "apk")]
fn last_attr_value_in_tag(tag: &str, attr: &str) -> Option<String> {
    let prefix = format!(" {}=\"", attr);
    let mut last = None;
    let mut pos = 0;
    while let Some(start) = tag[pos..].find(&prefix) {
        let abs_start = pos + start;
        let value_start = abs_start + prefix.len();
        let end = tag[value_start..].find('"')?;
        let value = &tag[value_start..value_start + end];
        last = Some(value.to_string());
        pos = value_start + end + 1;
    }
    last
}

#[cfg(feature = "apk")]
fn extract_xml_attr(xml: &str, attr: &str) -> Option<String> {
    let (start, end) = first_start_tag_range(xml)?;
    let tag = &xml[start..end];
    last_attr_value_in_tag(tag, attr)
}

fn find_start_tag(xml: &str, tag_name: &str) -> Option<(usize, usize)> {
    let mut pos = 0;
    while pos < xml.len() {
        let rest = &xml[pos..];
        let lt = rest.find('<')?;
        pos += lt;
        if xml[pos..].starts_with("<!--") {
            let end = xml[pos..].find("-->")? + 3;
            pos += end;
        } else if xml[pos..].starts_with("<?") {
            let end = xml[pos..].find("?>")? + 2;
            pos += end;
        } else if xml[pos..].starts_with("<!") {
            let end = xml[pos..].find('>')? + 1;
            pos += end;
        } else if xml[pos..].starts_with("</") {
            let end = xml[pos..].find('>')? + 1;
            pos += end;
        } else {
            let end = xml[pos..].find('>')? + 1;
            let tag_content = &xml[pos + 1..pos + end];
            let name_end = tag_content
                .find(|c: char| c.is_whitespace() || c == '/' || c == '>')
                .unwrap_or(tag_content.len());
            let found_name = &tag_content[..name_end];
            if found_name == tag_name {
                return Some((pos, pos + end));
            }
            pos += end;
        }
    }
    None
}

#[cfg(feature = "apk")]
fn extract_block_attr(xml: &str, block: &str, attr: &str) -> Option<String> {
    let (start, end) = find_start_tag(xml, block)?;
    let tag = &xml[start..end];
    last_attr_value_in_tag(tag, attr)
}

#[cfg(feature = "ipa")]
fn strip_xml_comments(xml: &str) -> String {
    let mut result = String::with_capacity(xml.len());
    let mut pos = 0;
    while pos < xml.len() {
        if let Some(start) = xml[pos..].find("<!--") {
            result.push_str(&xml[pos..pos + start]);
            if let Some(end) = xml[pos + start..].find("-->") {
                pos += start + end + 3;
            } else {
                break;
            }
        } else {
            result.push_str(&xml[pos..]);
            break;
        }
    }
    result
}

#[cfg(feature = "ipa")]
pub(crate) fn parse_info_plist(xml: &str) -> Option<crate::IpaInfoPlist> {
    let clean_xml_str = crate::security::strip_bom_str(xml);
    let clean_xml = strip_xml_comments(clean_xml_str);
    Some(crate::IpaInfoPlist {
        bundle_identifier: parse_plist_key(&clean_xml, "CFBundleIdentifier"),
        bundle_version: parse_plist_key(&clean_xml, "CFBundleShortVersionString"),
        executable: parse_plist_key(&clean_xml, "CFBundleExecutable"),
    })
}

#[cfg(feature = "ipa")]
fn parse_plist_key(xml: &str, key: &str) -> Option<String> {
    let marker = format!("<key>{}</key>", key);
    let key_pos = xml.find(&marker)?;
    let after_key = key_pos + marker.len();
    let tail = &xml[after_key..];
    // Restrict the value search to the immediate sibling node: stop at the
    // next key or the end of the enclosing dict.
    let value_end = tail.find("<key>").or_else(|| tail.find("</dict>"))?;
    let value_scope = &tail[..value_end];
    let string_start = value_scope.find("<string>")? + "<string>".len();
    let value_tail = &value_scope[string_start..];
    let end = value_tail.find("</string>")?;
    Some(value_tail[..end].trim().to_string())
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "apk")]
    #[test]
    fn parse_android_manifest_skips_closing_tags_and_comments() {
        let xml = b"</manifest package=\"fake\"><manifest package=\"com.real.app\"><!-- <uses-sdk android:minSdkVersion=\"10\" /> --><uses-sdk android:minSdkVersion=\"21\" /></manifest>";
        let manifest = super::parse_android_manifest(xml).expect("parse manifest");
        assert_eq!(manifest.package, "com.real.app");
        assert_eq!(manifest.min_sdk.as_deref(), Some("21"));
    }

    #[cfg(feature = "ipa")]
    #[test]
    fn parse_info_plist_skips_commented_keys() {
        let xml = "<!-- <key>CFBundleIdentifier</key><string>com.fake.app</string> --><dict><key>CFBundleIdentifier</key><string>com.real.app</string></dict>";
        let plist = super::parse_info_plist(xml).expect("parse plist");
        assert_eq!(plist.bundle_identifier.as_deref(), Some("com.real.app"));
    }
    #[cfg(feature = "apk")]
    #[test]
    fn xml_attr_ignores_comments_and_takes_last_duplicate() {
        use super::extract_xml_attr;
        let xml = r#"<?xml version="1.0"?><!-- package="com.evil.app" --><manifest package="com.evil.app" package="com.real.app" versionName="1.0"></manifest>"#;
        assert_eq!(
            extract_xml_attr(xml, "package").as_deref(),
            Some("com.real.app")
        );
        assert_eq!(extract_xml_attr(xml, "versionName").as_deref(), Some("1.0"));
    }

    #[cfg(feature = "apk")]
    #[test]
    fn block_attr_scoped_to_tag_not_later_elements() {
        use super::extract_block_attr;
        let xml = r#"<manifest package="com.example.app"><uses-sdk android:targetSdkVersion="30"/><activity android:minSdkVersion="21"></activity></manifest>"#;
        assert_eq!(
            extract_block_attr(xml, "uses-sdk", "android:minSdkVersion").as_deref(),
            None
        );
        assert_eq!(
            extract_block_attr(xml, "uses-sdk", "android:targetSdkVersion").as_deref(),
            Some("30")
        );
    }

    #[cfg(feature = "ipa")]
    #[test]
    fn plist_key_value_scoped_to_immediate_sibling() {
        use super::parse_plist_key;
        let xml = "<plist><dict><key>CFBundleIdentifier</key><string>com.example.bundle</string><key>CFBundleExecutable</key><string>Binary</string></dict></plist>";
        assert_eq!(
            parse_plist_key(xml, "CFBundleIdentifier").as_deref(),
            Some("com.example.bundle")
        );
        assert_eq!(
            parse_plist_key(xml, "CFBundleExecutable").as_deref(),
            Some("Binary")
        );
    }

    #[cfg(feature = "ipa")]
    #[test]
    fn plist_key_missing_returns_none() {
        use super::parse_plist_key;
        let xml = "<plist><dict><key>CFBundleIdentifier</key><string>com.example.bundle</string></dict></plist>";
        assert_eq!(parse_plist_key(xml, "CFBundleExecutable"), None);
    }
}
