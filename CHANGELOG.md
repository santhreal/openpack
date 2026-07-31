# Changelog

## [0.2.5] - 2026-07-30

### Fixed
- `read_entry`/`extract_all_to` rejected valid archives compressed with bzip2 (and any other non-deflate method) with `InvalidArchive("failed deflate validation")`: the deflate-stream validator used for the compression-ratio check ran on every non-Stored entry. It now only runs on deflated entries; other methods use the central-directory compressed size while the decompressed byte count stays hard-capped.

## [0.2.2] - 2026-04-12

### Added
- Initial release of openpack.
