# Exaf

The EXtensible Archiver Format is intended to be used in compressing and archiving files. It offers an alternative to the well-known zip and 7-zip formats, with extensibility in mind.

**This is a work in progress.** There is a basic working prototype and the format is, for the most part, settled and will be documented soon.

## Specification

A proper one is coming soon. If you can read an emacs [org-mode](https://orgmode.org) file, check out the `TODO.org` file for the file format as it exists currently.

In short, it takes inspiration from both [xar](https://en.wikipedia.org/wiki/Xar_(archiver)) and [Exif](https://en.wikipedia.org/wiki/Exif) in that there is a basic header at the start of the file which identifies the format and version, followed by zero or more optional tag/value pairs akin to Exif or the zip format's "extra fields" as described [here](https://en.wikipedia.org/wiki/ZIP_(file_format)). The directory and file entries within the archive also consist entirely of tag/size/value tuples.

## Objectives

For now, the first objective was to complete the proof of concept by building an `exaf` binary that can create, list, and extract archives, offering a modest amount of functionality -- that has basically been achieved as of now. The next task will be to provide a full-featured binary as well as a [Rust](https://www.rust-lang.org) library with an interface similar to that of the [tar crate](https://docs.rs/tar/latest/tar/).

## Build and Run

### Prerequisites

* [Rust](https://www.rust-lang.org) 2021 edition

### Running the tests

For the time being there are very few unit tests.

```shell
cargo test
```

### Creating, listing, extracting archives

Start by creating an archive using the `create` subcommand. The example below assumes that you have downloaded something interesting into your `~/Downloads` directory.

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

## Prior Art

There are [many existing](https://en.wikipedia.org/wiki/List_of_archive_formats) archive formats, many of which have long since fallen out of common use. Those that remain are not without their shortcomings, such as poorly implemented encryption features, or vulnerability to compression factor exploits (*zip bomb*).

The original motivation to start this project began when [O](https://github.com/OttoCoddo) announced the [pack](https://pack.ac) file format. They introduced a novel approach to the problem of archiving and compressing files while lamenting the general lack of progress in this area.
