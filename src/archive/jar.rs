use crate::manifest::summarize_package_json;
use crate::types::{OpenPack, OpenPackError, PackageJsonSummary};

impl OpenPack {
    /// Reads and deserializes a JSON entry when it exists.
    pub fn read_json_entry<T>(&self, name: &str) -> Result<Option<T>, OpenPackError>
    where
        T: serde::de::DeserializeOwned,
    {
        if !self.contains(name)? {
            return Ok(None);
        }

        let bytes = self.read_entry(name)?;
        let value = serde_json::from_slice(&bytes).map_err(|err| {
            OpenPackError::InvalidArchive(format!("invalid JSON in '{name}': {err}"))
        })?;
        Ok(Some(value))
    }

    /// Reads a UTF-8 text entry when it exists.
    pub fn read_text_entry(&self, name: &str) -> Result<Option<String>, OpenPackError> {
        if !self.contains(name)? {
            return Ok(None);
        }

        let bytes = self.read_entry(name)?;
        let text = String::from_utf8(bytes).map_err(|err| {
            OpenPackError::InvalidArchive(format!("entry '{name}' is not valid UTF-8: {err}"))
        })?;
        Ok(Some(text))
    }

    /// Reads `manifest.json` when present.
    pub fn read_manifest_json<T>(&self) -> Result<Option<T>, OpenPackError>
    where
        T: serde::de::DeserializeOwned,
    {
        self.read_json_entry("manifest.json")
    }

    /// Reads `package.json` when present.
    pub fn read_package_json<T>(&self) -> Result<Option<T>, OpenPackError>
    where
        T: serde::de::DeserializeOwned,
    {
        self.read_json_entry("package.json")
    }

    /// Reads and summarizes a `package.json`.
    pub fn read_package_json_summary(&self) -> Result<Option<PackageJsonSummary>, OpenPackError> {
        let package = self.read_package_json::<serde_json::Value>()?;
        Ok(package.map(summarize_package_json))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::archive::test_helpers::*;
    use std::fs::File;
    use std::io::Write;

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
}
