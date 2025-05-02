# Exaf

The EXtensible Archiver Format describes an [archive file](https://en.wikipedia.org/wiki/Archive_file) format for compressing and archiving files. It offers an alternative to the well-known zip and 7-zip formats, with extensibility in mind. The running time of this reference implementation is similar to that of GNU tar with Zstandard compression, and the resulting file size is very similar. Encryption of both metadata and file content is implemented using Argon2id and AES256-GCM which ensures both data confidentiality and authenticity. See the [Encryption](#encryption) section below for more information.

## Specification

See the [FORMAT.md](./FORMAT.md) document for the details on the current format, which specifies Zstandard for compression, and the Argon2id key-derivation function, along with the AES256-GCM cipher, for encryption. Future versions may add support for other algorithms as appropriate.

In short, the file consists of a short header which may include encryption details, followed by a manifest of directories, files, and symbolic links which are contained in the following compressed block of content. These content blocks may contain many files, up to a predefined total size, which are then compressed using Zstandard. If using encryption, the manifest and compressed content block will be encrypted with the derived key and a unique nonce. The manifest/content pair can be followed by as many additional pairs as are needed to contain everything that will be written to the archive.

## Objectives

First and foremost, the purpose of this project is to satisfy my own needs, and this reference implementation is written in [Rust](https://www.rust-lang.org) so that I can use it within my own Rust-based applications. If it happens to be useful to others, fantastic, and I would be more than happy to continue developing the format and/or this crate toward that end.

## Build and Run

### Prerequisites

* [Rust](https://www.rust-lang.org) 2021 edition

### Running the tests

Unit tests exist that exercise most of the functionality.

```shell
cargo test
```

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

### Code Coverage

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

## Encryption

With the `--password <PASSWD>` option to the commands listed above, the archive can be encrypted using a passphrase. A secret key will be derived using the [Argon2id](https://en.wikipedia.org/wiki/Argon2) algorithm and a random salt (which is then stored in the archive header), and each run of content in the archive will be encrypted with that secret key and a unique nonce (stored in the header of each manifest) using the AES256-GCM [Authenticated Encryption with Associated Data](https://en.wikipedia.org/wiki/Authenticated_encryption) cipher. The encryption includes both the entry metadata as well as the compressed file content.

## Prior Art

There are [many existing](https://en.wikipedia.org/wiki/List_of_archive_formats) archive formats, many of which have long since fallen out of common use. Those that remain are not without their shortcomings, such as poorly implemented encryption features, or vulnerability to compression factor exploits (*zip bomb*).

The original motivation to start this project began when [O](https://github.com/OttoCoddo) announced the [Pack](https://pack.ac) file format. They introduced a novel approach to the problem of archiving and compressing files while lamenting the general lack of progress in this area. A Rust version of that program can be found [here](https://github.com/nlfiedler/pack-rs) -- it's speed and output size are nearly identical to that of this project.
