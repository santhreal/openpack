use std::collections::BTreeSet;
use std::path::{Component, Path};

use flate2::Decompress;
use flate2::FlushDecompress;
use flate2::Status;
use percent_encoding::percent_decode_str;
use zip::read::ZipFile;

use crate::types::{ArchiveEntry, Limits, OpenPackError};

pub(crate) fn check_entry_limits(
    limits: &Limits,
    entry: &ArchiveEntry,
    total_uncompressed: &mut u64,
) -> Result<(), OpenPackError> {
    // Do not skip checks for directory entries. An attacker may mark a file
    // as a directory to bypass size and ratio limits.
    if entry.uncompressed_size > limits.max_entry_uncompressed_size {
        return Err(OpenPackError::LimitExceeded(format!(
            "entry '{}' exceeds uncompressed size limit",
            entry.name
        )));
    }

    let ratio = compression_ratio(entry.uncompressed_size, entry.compressed_size);

    if ratio > limits.max_compression_ratio {
        return Err(OpenPackError::LimitExceeded(format!(
            "entry '{}' exceeds compression ratio limit",
            entry.name
        )));
    }

    *total_uncompressed = total_uncompressed.saturating_add(entry.uncompressed_size);
    if *total_uncompressed > limits.max_total_uncompressed_size {
        return Err(OpenPackError::LimitExceeded(
            "total uncompressed size exceeds limit".into(),
        ));
    }
    Ok(())
}

/// Computes the compression ratio from metadata sizes.
///
/// This is used for a fast metadata-level check; `read_entry` enforces the
/// ratio against the actual decompressed bytes for defense in depth.
#[allow(clippy::cast_precision_loss)]
/// Returns deflate input bytes consumed before `StreamEnd`, if the payload is valid.
pub(crate) fn deflate_input_bytes_used(compressed: &[u8]) -> Option<u64> {
    let mut decompress = Decompress::new(false);
    let mut input = compressed;
    let mut output = [0u8; 16 * 1024];
    let mut prev_total_in: u64 = 0;
    let mut prev_total_out: u64 = 0;

    loop {
        let status = decompress
            .decompress(input, &mut output, FlushDecompress::None)
            .ok()?;
        let total_in = decompress.total_in();
        let total_out = decompress.total_out();
        input = &compressed[usize::try_from(total_in).ok()?..];
        match status {
            Status::StreamEnd => return Some(total_in),
            Status::Ok | Status::BufError => {
                if total_in == prev_total_in && total_out == prev_total_out {
                    // No progress was made; the stream is stuck or truncated.
                    return None;
                }
                prev_total_in = total_in;
                prev_total_out = total_out;
            }
        }
    }
}

pub(crate) fn compression_ratio(uncompressed: u64, compressed: u64) -> f64 {
    if compressed == 0 {
        if uncompressed == 0 {
            0.0
        } else {
            f64::INFINITY
        }
    } else {
        uncompressed as f64 / compressed as f64
    }
}

pub(crate) fn enforce_entry_count_limit(
    entry_count: usize,
    limits: &Limits,
) -> Result<(), OpenPackError> {
    if entry_count > limits.max_entries {
        Err(OpenPackError::LimitExceeded(
            "entry count exceeds limit".into(),
        ))
    } else {
        Ok(())
    }
}

/// Strips UTF-8 Byte Order Mark (BOM) `0xEF 0xBB 0xBF` from raw bytes if present.
pub(crate) fn strip_bom(mut bytes: &[u8]) -> &[u8] {
    while bytes.starts_with(b"\xEF\xBB\xBF") {
        bytes = &bytes[3..];
    }
    bytes
}

/// Strips UTF-8 Byte Order Mark (BOM) `\u{FEFF}` from string slice if present.
pub(crate) fn strip_bom_str(mut s: &str) -> &str {
    while let Some(stripped) = s.strip_prefix('\u{FEFF}') {
        s = stripped;
    }
    s
}

pub(crate) fn validate_entry_name(name: &str) -> Result<(), OpenPackError> {
    if name.is_empty() {
        return Err(OpenPackError::InvalidArchive("empty entry name".into()));
    }

    if name.contains('\0') {
        return Err(OpenPackError::InvalidArchive(
            "null byte in entry name".into(),
        ));
    }

    let clean_name = strip_bom_str(name);
    if clean_name.is_empty() {
        return Err(OpenPackError::InvalidArchive("empty entry name".into()));
    }

    let decoded = fully_percent_decode(clean_name)?;
    let clean_decoded = strip_bom_str(&decoded);

    if clean_name.contains('\\') || clean_decoded.contains('\\') {
        return Err(OpenPackError::InvalidArchive(
            "backslash in entry name".into(),
        ));
    }

    if contains_parent_traversal(clean_name) || contains_parent_traversal(clean_decoded) {
        return Err(OpenPackError::ZipSlip(name.to_string()));
    }

    if Path::new(clean_decoded).components().any(|component| {
        matches!(
            component,
            Component::Prefix(_) | Component::RootDir | Component::ParentDir
        )
    }) {
        return Err(OpenPackError::ZipSlip(name.to_string()));
    }

    if is_windows_absolute(clean_decoded) {
        return Err(OpenPackError::ZipSlip(name.to_string()));
    }

    Ok(())
}

/// Validates the raw byte representation of an entry name.
///
/// This is encoding-agnostic protection against traversal attacks that might
/// be obfuscated via non-UTF-8 or non-CP437 encodings.
pub(crate) fn validate_entry_name_raw(name: &[u8]) -> Result<(), OpenPackError> {
    if name.is_empty() {
        return Err(OpenPackError::InvalidArchive("empty entry name".into()));
    }

    if name.contains(&b'\0') {
        return Err(OpenPackError::InvalidArchive(
            "null byte in entry name".into(),
        ));
    }

    let clean = strip_bom(name);
    if clean.is_empty() {
        return Err(OpenPackError::InvalidArchive("empty entry name".into()));
    }

    if clean.contains(&b'\\') {
        return Err(OpenPackError::InvalidArchive(
            "backslash in entry name".into(),
        ));
    }

    if clean.starts_with(b"/") {
        let name_str = String::from_utf8_lossy(clean);
        return Err(OpenPackError::ZipSlip(name_str.into_owned()));
    }

    if clean.len() >= 2 && clean[0].is_ascii_alphabetic() && clean[1] == b':' {
        let name_str = String::from_utf8_lossy(clean);
        return Err(OpenPackError::ZipSlip(name_str.into_owned()));
    }

    let name_str = String::from_utf8_lossy(clean);
    validate_entry_name(&name_str)?;

    Ok(())
}

pub(crate) fn reject_duplicate_entry_name(
    names: &mut BTreeSet<String>,
    name: &str,
) -> Result<(), OpenPackError> {
    if names.insert(name.to_string()) {
        Ok(())
    } else {
        Err(OpenPackError::InvalidArchive("duplicate entry name".into()))
    }
}

pub(crate) fn entry_meta<R: std::io::Read + ?Sized>(
    file: &mut ZipFile<'_, R>,
) -> Result<ArchiveEntry, OpenPackError> {
    reject_special_file_entry(file)?;
    validate_entry_name_raw(file.name_raw())?;
    Ok(ArchiveEntry {
        name: file.name().to_string(),
        compressed_size: file.compressed_size(),
        uncompressed_size: file.size(),
        crc: file.crc32(),
        is_dir: file.is_dir(),
    })
}

pub(crate) fn reject_special_file_entry<R: std::io::Read + ?Sized>(
    file: &ZipFile<'_, R>,
) -> Result<(), OpenPackError> {
    const S_IFMT: u32 = 0o170000;
    const S_IFLNK: u32 = 0o120000;
    const S_IFBLK: u32 = 0o060000;
    const S_IFCHR: u32 = 0o020000;
    const S_IFIFO: u32 = 0o010000;
    const S_IFSOCK: u32 = 0o140000;

    if file.is_symlink() {
        return Err(OpenPackError::InvalidArchive(format!(
            "symlink entry `{}` is not supported",
            file.name()
        )));
    }

    if let Some(mode) = file.unix_mode() {
        let file_type = mode & S_IFMT;
        if file_type == S_IFLNK {
            return Err(OpenPackError::InvalidArchive(format!(
                "symlink entry `{}` is not supported",
                file.name()
            )));
        }
        if matches!(file_type, S_IFBLK | S_IFCHR | S_IFIFO | S_IFSOCK) {
            return Err(OpenPackError::InvalidArchive(format!(
                "special file entry `{}` is not supported",
                file.name()
            )));
        }
    }

    Ok(())
}

fn fully_percent_decode(value: &str) -> Result<String, OpenPackError> {
    // Repeated percent-decoding is applied iteratively until the value stabilizes.
    // Limit the number of iterations to avoid pathological or adversarially-encoded inputs.
    const MAX_DECODE_ITER: usize = 10;
    let mut current = value.to_string();
    for _ in 0..MAX_DECODE_ITER {
        let decoded = percent_decode_str(&current)
            .decode_utf8_lossy()
            .into_owned();
        if decoded == current {
            return Ok(current);
        }
        current = decoded;
    }
    Err(OpenPackError::ZipSlip(
        "path contains excessively encoded percent sequences".into(),
    ))
}

fn contains_parent_traversal(value: &str) -> bool {
    value.contains("../") || value.ends_with("/..") || value == ".."
}

fn is_windows_absolute(value: &str) -> bool {
    value.len() >= 2 && value.as_bytes()[0].is_ascii_alphabetic() && value.as_bytes()[1] == b':'
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::write::DeflateEncoder;
    use flate2::Compression;
    use std::io::Write;

    #[test]
    fn deflate_input_bytes_used_handles_large_output_with_empty_input() {
        // Produce a deflate payload whose decompressed output exceeds the
        // 16 KiB internal buffer so the decompressor must be called again with
        // a fresh buffer even when the input slice has been fully consumed.
        let uncompressed = vec![b'a'; 64 * 1024];
        let mut encoder = DeflateEncoder::new(Vec::new(), Compression::default());
        encoder
            .write_all(&uncompressed)
            .expect("write uncompressed");
        let compressed = encoder.finish().expect("finish compression");

        let used =
            deflate_input_bytes_used(&compressed).expect("deflate_input_bytes_used must succeed");
        assert_eq!(used, compressed.len() as u64);
    }
}
#[cfg(test)]
mod security_tests {
    use super::*;

    #[test]
    fn validate_entry_name_raw_rejects_windows_drive_letter_and_percent_traversal() {
        assert!(matches!(
            validate_entry_name_raw(b"C:/Windows/System.ini"),
            Err(OpenPackError::ZipSlip(_))
        ));
        assert!(matches!(
            validate_entry_name_raw(b"D:evil"),
            Err(OpenPackError::ZipSlip(_))
        ));
        assert!(matches!(
            validate_entry_name_raw(b"%2e%2e/etc/passwd"),
            Err(OpenPackError::ZipSlip(_))
        ));
        assert!(matches!(
            validate_entry_name_raw(b"\xEF\xBB\xBF\xEF\xBB\xBF../etc/passwd"),
            Err(OpenPackError::ZipSlip(_))
        ));

        assert_eq!(strip_bom(b"\xEF\xBB\xBF\xEF\xBB\xBFhello"), b"hello");
        assert_eq!(strip_bom_str("\u{FEFF}\u{FEFF}hello"), "hello");
    }
}
