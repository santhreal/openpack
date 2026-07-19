use std::ffi::OsStr;
use std::fs::File;
use std::path::Path;

use memmap2::Mmap;

use crate::types::{ArchiveFormat, OpenPackError};

pub(crate) fn detect_format(path: &Path, bytes: &[u8]) -> Result<ArchiveFormat, OpenPackError> {
    let ext = path
        .extension()
        .and_then(OsStr::to_str)
        .map(|value| value.to_ascii_lowercase());

    // ZIP-derived extensions require PK magic so extension-only detection cannot
    // be fooled by gzip or other non-ZIP payloads (e.g. .apk with gzip header).
    if let Some(ext_str) = ext.as_deref() {
        match ext_str {
            "jar" if bytes.starts_with(b"PK") => return Ok(ArchiveFormat::Jar),
            "apk" if bytes.starts_with(b"PK") => return Ok(ArchiveFormat::Apk),
            "ipa" if bytes.starts_with(b"PK") => return Ok(ArchiveFormat::Ipa),
            "zip" if bytes.is_empty() || bytes.starts_with(b"PK") => {
                return Ok(ArchiveFormat::Zip);
            }
            "crx" => {
                if bytes.starts_with(b"PK\x03\x04") {
                    return Ok(ArchiveFormat::Zip);
                }
                #[cfg(feature = "crx")]
                {
                    return Ok(ArchiveFormat::Crx);
                }
                #[cfg(not(feature = "crx"))]
                {
                    return Err(OpenPackError::Unsupported);
                }
            }
            _ => {}
        }
    }

    // Extension did not identify the format; fall back to magic bytes.
    if bytes.starts_with(b"Cr24") {
        #[cfg(feature = "crx")]
        {
            return Ok(ArchiveFormat::Crx);
        }
        #[cfg(not(feature = "crx"))]
        {
            return Err(OpenPackError::Unsupported);
        }
    }

    if bytes.starts_with(b"PK") {
        return Ok(ArchiveFormat::Zip);
    }

    if bytes.len() >= 2 && &bytes[0..2] == b"\x1F\x8B" {
        // GZIP / tar.gz detected  -  not supported by this crate by default.
        return Err(OpenPackError::Unsupported);
    }

    // Unknown format / extension without recognizable magic
    Err(OpenPackError::Unsupported)
}

#[allow(unsafe_code)]
pub(crate) fn read_archive_bytes(file: File, file_len: u64) -> Result<Mmap, OpenPackError> {
    // Ensure archive fits into platform memory indexing
    let _capacity = usize::try_from(file_len)
        .map_err(|_| OpenPackError::LimitExceeded("archive too large for platform".into()))?;
    // Safety: memory-map the file for zero-copy access.
    let mmap = unsafe {
        memmap2::MmapOptions::new()
            .map(&file)
            .map_err(OpenPackError::Io)?
    };
    Ok(mmap)
}
