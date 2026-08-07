# Changelog

## [0.2.7] - 2026-08-07

### Security & Safety
- Stripped stacked multi-BOM prefixes (`0xEF 0xBB 0xBF` / `\u{FEFF}`) in `strip_bom` and `strip_bom_str` to prevent multi-BOM obfuscation attacks.
- Hardened `validate_entry_name_raw` to enforce raw byte checks against Windows drive letters (`C:`), leading slashes, backslashes, null bytes, and percent-encoded parent traversals.
- Updated `OpenPack::contains` to validate the complete archive metadata via `entries()`, ensuring limit violations, ZipSlip entries, duplicate filenames, and special files are detected rather than bypassed.
- Handled out-of-bounds `data_start` offsets safely with `zip_data.get(start..)` to prevent slice index panics in deflate validation.
- Hardened XML manifest and plist parsing (`parse_android_manifest`, `parse_info_plist`, `extract_block_attr`) to skip XML comments, ignore closing tags, and perform exact start-tag name matching.

## [0.2.6] - 2026-08-07

### Changed
- BOM-aware path validation and text/JSON/TOML entry reads.
- Authors set to `Santh <64453045+santhreal@users.noreply.github.com>`.


## [0.2.5] - 2026-08-07

### Security & Safety
- Stripped UTF-8 Byte Order Mark (`0xEF 0xBB 0xBF` / `\u{FEFF}`) in path validation routines (`validate_entry_name` and `validate_entry_name_raw`) to prevent BOM-prefixed obfuscation of root directories, Windows drive letters, or parent directory traversals.
- Added BOM-safe decoding for container metadata (`read_json_entry`, `read_text_entry`, `Limits::from_toml`, `parse_android_manifest`, and `parse_info_plist`) so UTF-8 files saved with a BOM by Windows tools parse cleanly without JSON/XML/TOML errors or leftover zero-width space characters.
- Standardized `Cargo.toml` metadata, updated authors to `Santh <64453045+santhreal@users.noreply.github.com>`, and declared `package.metadata.santh.status = "beta"`.

### Fixed
- `read_entry`/`extract_all_to` rejected valid archives compressed with bzip2 (and any other non-deflate method) with `InvalidArchive("failed deflate validation")`: the deflate-stream validator used for the compression-ratio check ran on every non-Stored entry. It now only runs on deflated entries; other methods use the central-directory compressed size while the decompressed byte count stays hard-capped.
## [0.2.2] - 2026-04-12

### Added
- Initial release of openpack.
