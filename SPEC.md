# openpack  -  Technical Spec

## Overview

Archive reader for ZIP-derived container formats with safe-by-default extraction checks.

## Architecture

The crate is organized into the following public modules:

- (see source for module layout)

## Guarantees

- `#![forbid(unsafe_code)]` where applicable; see `src/lib.rs` for the exact lint preamble.
- All public types have doc comments.
- Error messages are actionable where applicable.

## Public API Summary

Key entry points are exported from `src/lib.rs` via `pub mod` and `pub use` re-exports.
Consult the module-level documentation in each source file for function signatures and usage examples.

## Error Handling

- Standard `Result` / error types.
