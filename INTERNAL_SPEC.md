# openpack  -  Internal Spec

> This file is gitignored. It exists for agents and internal development. Never committed to public repos.

## Identity
Safe archive-reader for ZIP-derived container formats (ZIP, CRX, JAR, APK, IPA) with BOM-safe checks.

## Purpose
Parses and extracts complex container formats safely. Without it, scanners would be vulnerable to zip bombs, path traversal, and malicious archives.

## North Star
An unexploitable, zero-copy archive parser that can handle untrusted inputs up to gigabytes in size without memory exhaustion or CPU pinning.

## Role in Ecosystem
- **Depends on:** none (internal)
- **Depended on by:** warpscan, rule engines
- **Relationship to warpscan:** Used to unpack and analyze mobile apps, browser extensions, and compressed artifacts before scanning.
- **Standalone value:** YES. Valuable for any system ingesting user-uploaded ZIP/APK/CRX files.

## Invariants
Never allows path traversal out of the extraction directory. Never exceeds memory limits on decompression.

## Boundaries
Does not analyze the extracted code. Does not create or compress archives (read-only).

## Quality State
- Tests: Extensive (adversarial, concurrent, property, integration)
- Lint preamble: yes
- #![forbid(unsafe_code)]: yes
- Doc coverage: ~90%
- Known issues: None