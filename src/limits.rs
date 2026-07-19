use std::fs::File;
use std::io::Read;
use std::path::Path;

use crate::types::{Limits, OpenPackError};

impl Limits {
    /// Provides very restrictive limits for highly untrusted archives.
    ///
    /// # Examples
    ///
    /// ```
    /// use openpack::Limits;
    /// let limits = Limits::strict();
    /// ```
    pub fn strict() -> Self {
        Self {
            max_archive_size: 10 * 1024 * 1024,
            max_entry_uncompressed_size: 2 * 1024 * 1024,
            max_total_uncompressed_size: 20 * 1024 * 1024,
            max_entries: 100,
            max_compression_ratio: 20.0,
        }
    }

    /// Provides extremely loose limits for trusted archives only.
    ///
    /// # Examples
    ///
    /// ```
    /// use openpack::Limits;
    /// let limits = Limits::permissive();
    /// ```
    pub fn permissive() -> Self {
        Self {
            max_archive_size: 2 * 1024 * 1024 * 1024,
            max_entry_uncompressed_size: 1024 * 1024 * 1024,
            max_total_uncompressed_size: 4 * 1024 * 1024 * 1024,
            max_entries: 100000,
            max_compression_ratio: 1000.0,
        }
    }

    /// Parses limits from a TOML string.
    ///
    /// # Examples
    ///
    /// ```
    /// use openpack::Limits;
    /// let toml_str = r#"
    /// max_archive_size = 104857600
    /// max_entry_uncompressed_size = 10485760
    /// max_total_uncompressed_size = 52428800
    /// max_entries = 1000
    /// max_compression_ratio = 50.0
    /// "#;
    /// let limits = Limits::from_toml(toml_str).unwrap();
    /// ```
    pub fn from_toml(raw: &str) -> Result<Self, OpenPackError> {
        let limits: Self =
            toml::from_str(raw).map_err(|err| OpenPackError::InvalidConfig(err.to_string()))?;
        limits.validate()?;
        Ok(limits)
    }

    pub(crate) fn validate(&self) -> Result<(), OpenPackError> {
        if self.max_archive_size == 0 {
            return Err(OpenPackError::InvalidConfig(
                "max_archive_size must be greater than 0".into(),
            ));
        }
        if self.max_entry_uncompressed_size == 0 {
            return Err(OpenPackError::InvalidConfig(
                "max_entry_uncompressed_size must be greater than 0".into(),
            ));
        }
        if self.max_total_uncompressed_size == 0 {
            return Err(OpenPackError::InvalidConfig(
                "max_total_uncompressed_size must be greater than 0".into(),
            ));
        }
        if self.max_entries == 0 {
            return Err(OpenPackError::InvalidConfig(
                "max_entries must be greater than 0".into(),
            ));
        }
        if self.max_total_uncompressed_size < self.max_entry_uncompressed_size {
            return Err(OpenPackError::InvalidConfig(
                "max_total_uncompressed_size must be >= max_entry_uncompressed_size".into(),
            ));
        }
        if self.max_compression_ratio.is_nan()
            || self.max_compression_ratio.is_infinite()
            || self.max_compression_ratio <= 0.0
        {
            return Err(OpenPackError::InvalidConfig(
                "max_compression_ratio must be a positive finite number".into(),
            ));
        }
        Ok(())
    }

    /// Parses limits from a TOML file.
    pub fn from_toml_file(path: &Path) -> Result<Self, OpenPackError> {
        let mut file = File::open(path)?;
        let mut raw = String::new();
        file.read_to_string(&mut raw)?;
        Self::from_toml(&raw)
    }

    /// Loads the builtin limits compiled into the binary.
    ///
    /// # Examples
    ///
    /// ```
    /// use openpack::Limits;
    /// let limits = Limits::builtin();
    /// ```
    pub fn builtin() -> Self {
        // The bundled config is trusted and must be valid; if it is corrupted,
        // fail loudly so the packaging error is caught immediately rather than
        // silently degrading to defaults.
        Self::from_toml(include_str!("../config/limits.toml")).expect(
            "builtin config/limits.toml is invalid; fix the bundled configuration",
        )
    }
}
