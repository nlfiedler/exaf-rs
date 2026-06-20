# Change Log

All notable changes to this project will be documented in this file.
This project adheres to [Semantic Versioning](http://semver.org/).
This file follows the convention described at
[Keep a Changelog](http://keepachangelog.com/en/1.0.0/).

## [Unreleased]
### Added
- Optional **XZ** (LZMA2) content compression as an alternative to Zstandard,
  selectable via `Options::compression`. Gated behind the `xz` crate feature
  (off by default) so the liblzma dependency is only pulled in when needed. The
  archive format records this as compression algorithm (`CA`) value `2`.
- The `Compression` enum is now part of the public API, and `Compression::None`
  is selectable to store content uncompressed (the `CA` row is elided, and the
  reader defaults an absent `CA` row to _none_).
- Optional **scrypt** key derivation as an alternative to Argon2id, selectable
  via `KeyDerivation::Scrypt` in `Writer::enable_encryption`. Gated behind the
  `scrypt` crate feature (off by default). The archive format records this as
  key derivation algorithm (`KD`) value `2`. For scrypt the shared cost rows are
  reinterpreted as `log2(N)`, block size `r`, and parallelism `p`, with their
  own bounds enforced to guard against resource-exhaustion when reading an
  untrusted archive.

## [3.0.0] - 2026-06-19
### Added
- Support for the **ChaCha20-Poly1305** AEAD cipher as an alternative to
  AES256-GCM, selectable via `Writer::enable_encryption` or the new
  `--cipher` option of the `create` CLI subcommand. The archive format records
  this as encryption algorithm (`EA`) value `2`.
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
- **BREAKING:** The public `Error`, `Encryption`, and `KeyDerivation` enums are
  now annotated `#[non_exhaustive]`, so downstream `match` expressions must
  include a wildcard arm. This is a breaking change under Rust semver and
  requires a major version bump, but it allows future error variants, ciphers,
  and key-derivation functions to be added without further breakage.
- Added the `Error::UnsafePath`, `Error::DecompressionBomb`, and
  `Error::InvalidKdfParams` variants, and the `Encryption::ChaCha20Poly1305`
  variant.

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
