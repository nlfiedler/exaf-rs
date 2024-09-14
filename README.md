# Exaf

The EXtensible Archiver Format describes an [archive file](https://en.wikipedia.org/wiki/Archive_file) format for compressing and archiving files. It offers an alternative to the well-known zip and 7-zip formats, with extensibility in mind. The running time of this reference implementation is similar to that of GNU tar with Zstandard compression, and the resulting file size is very similar. It is much faster and the file size is considerably smaller than Info-Zip. While the file size is larger than that of 7-zip, the run time is much less. Encryption of both metadata and file content is implemented using the Argon2id key derivation function and an AEAD cipher that ensures the data confidentiality and authenticity. See the [Encryption](#encryption) section below for more information.

## Specification

See the [FORMAT.md](./FORMAT.md) file for the gory details.

In short, it is like tar when compressed with Zstandard, but with less overhead, and sets of files are combined into compressed content blocks, rather than compressing the entire file. It takes inspiration from both [XAR](https://en.wikipedia.org/wiki/Xar_(archiver)) and [Exif](https://en.wikipedia.org/wiki/Exif) in that there is a basic header at the start of the file which identifies the format and version, followed by zero or more optional tag/size/value tuples akin to Exif or the zip format's "extra fields" as described [here](https://en.wikipedia.org/wiki/ZIP_(file_format)). The directory and file entries within the archive consist entirely of tag/size/value tuples.

What distinguishes this format from that of tar with Zstandard is that the table of contents is not compressed and thus the entries can be quickly perused. Rather than compressing the entire file in one pass, the file content is grouped into large chunks and then compressed. Each set of compressed data is prefixed by the corresponding directory/file/link metadata. In this way, the format is similar to XAR with multiple occurrences of the TOC and heap, as needed. An advantage to this format is that new content can simply be appended to the end of the existing file.

## Objectives

First and foremost, the purpose of this project is to satisfy my own needs, and it is written in [Rust](https://www.rust-lang.org) so that I can use it within my own Rust-based applications. If it happens to be useful to others, fantastic, and I would be more than happy to continue developing toward that end.

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

The original motivation to start this project began when [O](https://github.com/OttoCoddo) announced the [Pack](https://pack.ac) file format. They introduced a novel approach to the problem of archiving and compressing files while lamenting the general lack of progress in this area. A Rust version of this can be found [here](https://github.com/nlfiedler/pack-rs) -- it's speed and output size are nearly identical to that of this project.
