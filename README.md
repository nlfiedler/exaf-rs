# Exaf

The EXtensible Archiver Format describes an [archive file](https://en.wikipedia.org/wiki/Archive_file) format for compressing and archiving files. It offers an alternative to the well-known zip and 7-zip formats, with extensibility in mind. The running time of this reference implementation is similar to that of GNU tar with Zstandard compression, and the resulting file size is very similar. Encryption of both metadata and file content is available using strong encryption algorithms -- see the specification for details.

## Specification

See the [FORMAT.md](./FORMAT.md) document for the details on the current format, which specifies the supported algorithms for data compression, key derivation, and encryption. In short, the file consists of a short header which may include encryption details, followed by a manifest of directories, files, and symbolic links which are followed by a block of compressed file content. If using encryption, the manifest and compressed content block will be encrypted with the derived key and a unique nonce. Additional pairs of manifests and content blocks are added as needed to contain everything that will be written to the archive.

## Supported Rust Versions

The Rust edition is set to `2024` and hence version `1.85.0` is the minimum supported version.

## Features

When using this crate in your own Rust application, the following optional features are available.

### Optional Features

* `scrypt`: Enable the scrypt key derivation function as an alternative to the default Argon2id.
* `xz`: Enable support for Xz/LZMA2 compression, in addition to the default Zstandard. Requires the `liblzma` library.

## Build and Test

Unit tests exist that exercise all of the functionality.

```shell
cargo test --all-features
```

## Command-line Usage

### Creating, listing, extracting archives

Start by creating an archive using the `create` command. The example below assumes that you have downloaded something interesting into your `~/Downloads` directory.

```shell
$ cargo run -- create archive.exa ~/Downloads/httpd-2.4.59
...
Added 3138 files to archive.exa
```

Now that the `archive.exa` file exists, you can list the contents like so:

```shell
$ cargo run -- list archive.exa | head -20
...
httpd-2.4.59/.deps
httpd-2.4.59/.gdbinit
httpd-2.4.59/.gitignore
httpd-2.4.59/ABOUT_APACHE
httpd-2.4.59/Apache-apr2.dsw
httpd-2.4.59/Apache.dsw
httpd-2.4.59/BuildAll.dsp
httpd-2.4.59/BuildBin.dsp
...
```

Finally, run `extract` to unpack the contents of the archive into the current directory:

```shell
$ cargo run -- extract archive.exa
...
Extracted 3138 files from archive.exa
```

### Encryption

With the `--password <PASSWD>` option to the commands listed above, the archive can be encrypted using a passphrase. A secret key will be derived using the [Argon2id](https://en.wikipedia.org/wiki/Argon2) algorithm and a random salt (which is then stored in the archive header), and each run of content in the archive will be encrypted with that secret key and a unique nonce (stored in the header of each manifest) using the AES256-GCM [Authenticated Encryption with Associated Data](https://en.wikipedia.org/wiki/Authenticated_encryption) cipher. The encryption includes both the entry metadata as well as the compressed file content.

If using the crate in your own application, additional algorithms are available.

## Code Coverage

Using [grcov](https://github.com/mozilla/grcov) seems to be the easiest at this time.

```shell
export RUSTFLAGS="-Cinstrument-coverage"
export LLVM_PROFILE_FILE="exaf_rs-%p-%m.profraw"
cargo clean
cargo build
cargo test
grcov . -s . --binary-path ./target/debug/ -t html --branch --ignore-not-existing -o ./target/debug/coverage/
open target/debug/coverage/index.html
```

## Prior Art

There are [many existing](https://en.wikipedia.org/wiki/List_of_archive_formats) archive formats, many of which have long since fallen out of common use. Those that remain are not without their shortcomings, such as poorly implemented encryption features, or vulnerability to compression factor exploits (*zip bomb*).

The original motivation to start this project began when [O](https://github.com/OttoCoddo) announced the [Pack](https://pack.ac) file format. They introduced a novel approach to the problem of archiving and compressing files while lamenting the general lack of progress in this area. A Rust version of that program can be found [here](https://github.com/nlfiedler/pack-rs) -- it's speed and output size are similar to that of this project.
