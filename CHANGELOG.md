# Change Log

All notable changes to this project will be documented in this file.
This project adheres to [Semantic Versioning](http://semver.org/).
This file follows the convention described at
[Keep a Changelog](http://keepachangelog.com/en/1.0.0/).

## [3.0.0] - 2026-06-19
### Security
- Prevent symlink-based path traversal during extraction. A malicious archive
  could plant a symbolic link entry and then write files "through" it to
  locations outside the destination directory; extraction now refuses to
  traverse or overwrite symbolic links.
- Bound Zstandard decompression by the size declared in the manifest to guard
  against decompression bombs.
- Reject a declared content/block size larger than the bytes remaining in the
  archive before allocating, so a tiny crafted file cannot force a
  multi-gigabyte allocation.
- Clamp the Argon2 key-derivation parameters (memory, time, parallelism, and
  tag length) read from the archive header before deriving the key, preventing
  a memory/CPU exhaustion denial-of-service when opening an encrypted archive.
- Validate the AES-256-GCM key and nonce lengths, returning an error instead of
  panicking on a malformed encryption header.
- Avoid panics when parsing malformed archive headers containing empty, short,
  or odd-length values.
### Changed
- **BREAKING:** The public `Error` enum is now annotated `#[non_exhaustive]`, so
  downstream `match` expressions must include a wildcard arm. This is a breaking
  change under Rust semver and requires a major version bump, but it allows
  future error variants to be added without further breakage.
- Added the `Error::UnsafePath`, `Error::DecompressionBomb`, and
  `Error::InvalidKdfParams` variants.

## [2.0.0] - 2026-04-10
### Changed
- **BREAKING:** `Entry` methods `user()` and `group()` return values changed
  from `Option<&String>` to `Option<&str>` to be more idiomatic.
- Updated `rand_core` dependency to latest release.

## [1.2.0] - 2025-05-01
### Changed
- Updated `rand_core` and `thiserror` dependencies to latest release.

## [1.1.1] - 2024-05-11
### Fixed
- File slices were missing the `LN` header row if the file offset was non-zero.
  In the case of file slices, they are treated as regular files.
- Added `Clone` and `Debug` to public enums and structs.

## [1.1.0] - 2024-05-11
### Added
- `content_size()` to return content block size limit.
- `bytes_written()` on `Writer` that is updated for each content block as it is written.
- `LN` header for for files and links whose value is their length in bytes.
### Changed
- Format is now version **1.1** with the addition of `LN` header row.

## [1.0.0] - 2024-05-09
### Changed
- Initial release
