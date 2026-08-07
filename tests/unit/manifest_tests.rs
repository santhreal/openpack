#[cfg(feature = "crx")]
use openpack::summarize_extension_manifest;
use openpack::summarize_package_json;

mod tests {
    use super::*;

    #[test]
    fn summarizes_package_json() {
        let json = serde_json::json!({
            "name": "foo",
            "version": "1.0.0",
            "description": "A package",
            "main": "index.js",
            "dependencies": {
                "react": "^18.0.0"
            }
        });

        let summary = summarize_package_json(json);
        assert_eq!(summary.name.unwrap(), "foo");
        assert_eq!(summary.version.unwrap(), "1.0.0");
        assert_eq!(summary.description.unwrap(), "A package");
        assert_eq!(summary.main.unwrap(), "index.js");
        assert_eq!(summary.dependencies, vec!["react"]);
    }

    #[cfg(feature = "crx")]
    #[test]
    fn summarizes_extension_manifest() {
        let json = serde_json::json!({
            "name": "My Extension",
            "version": "1.0",
            "manifest_version": 3,
            "permissions": ["storage", "activeTab"],
            "host_permissions": ["*://*.example.com/*"],
            "background": {
                "service_worker": "bg.js"
            },
            "content_scripts": [
                {
                    "matches": ["<all_urls>"],
                    "js": ["content.js"]
                }
            ]
        });

        let summary = summarize_extension_manifest(json);
        assert_eq!(summary.name.unwrap(), "My Extension");
        assert_eq!(summary.version.unwrap(), "1.0");
        assert_eq!(summary.manifest_version.unwrap(), 3);
        assert_eq!(summary.permissions, vec!["storage", "activeTab"]);
        assert_eq!(summary.host_permissions, vec!["*://*.example.com/*"]);
        assert_eq!(summary.background_scripts, vec!["bg.js"]);
        assert_eq!(summary.content_scripts, vec!["content.js".to_string()]);
    }

}
