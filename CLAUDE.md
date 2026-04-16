# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**exaf-rs** is a Rust library and CLI implementing the EXtensible Archiver Format (EXAF) — an alternative to ZIP/7-zip with optional Zstandard compression and AES-256-GCM encryption. The format spec is in `FORMAT.md`.

## Commands

```bash
# Build
cargo build

# Run all tests
cargo test

# Run a single test
cargo test test_name

# Run tests for one module
cargo test --lib reader::tests

# Lint (zero warnings enforced)
cargo clippy -- -D warnings

# Run the CLI
cargo run -- create archive.exa <path>
cargo run -- list archive.exa
cargo run -- extract archive.exa
```

## Architecture

Single crate with four source files:

- **`src/lib.rs`** — Public types (`Entry`, `Kind`, `Encryption`, `KeyDerivation`, `KeyDerivationParams`, `Error`), constants (`BUNDLE_SIZE` = 16 MB in prod, 2 KB in tests via `cfg(test)`), and shared helper functions for I/O, encryption, and key derivation.
- **`src/writer.rs`** — `Writer` struct with `Options`. Accumulates file content in 16 MB bundles; when a bundle fills, it writes a manifest/content pair (compressed, optionally encrypted) and starts a new one. Large files may be split across multiple pairs.
- **`src/reader.rs`** — `from_file()` for full extraction; `Entries` iterator for listing without extraction. Reconstructs directory structure via `PathBuilder`.
- **`src/main.rs`** — CLI using `clap` with three subcommands: `create`, `list`, `extract`.

### File Format Structure

```
Archive Header (magic + version + optional encryption params)
  └─ Manifest/Content Pair (repeatable)
     ├─ Manifest Header (entry count, compression algo, block size)
     ├─ Directory/File/Symlink Entry records (with directory IDs for nesting)
     └─ Content Block (Zstandard-compressed; AES-256-GCM encrypted if requested)
```

Encryption wraps the entire manifest + content pair. KDF is Argon2id (salt stored in archive header, nonce stored per manifest).

### Key Constants and Tags

Tag identifiers (two-byte ASCII) for the binary format are defined as constants in `lib.rs` (e.g., `TAG_NE`, `TAG_CA`, `TAG_BS`). These map directly to the field names in `FORMAT.md`.

## Testing

Tests use `tempfile` for scratch directories and `blake3` for content verification. The `BUNDLE_SIZE` constant is reduced to 2 KB in `cfg(test)` to exercise bundle-splitting logic without large files. Test fixtures (a small directory tree with files, symlinks, and empty dirs) live in `test/fixtures/version1/tiny_tree/`.
