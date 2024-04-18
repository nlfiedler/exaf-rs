# Exaf

The EXtensible Archiver Format is intended to be used in compressing and archiving files. It offers an alternative to the well-known zip and 7-zip formats, with extensibility in mind.

**This is a work in progress.**

## Specification

A proper one is coming soon, once the proof of concept is finished. If you can read an emacs [org-mode](https://orgmode.org) file, check out the `TODO.org` file for the file format as it exists currently.

In short, it takes inspiration from both [xar](https://en.wikipedia.org/wiki/Xar_(archiver)) and [Exif](https://en.wikipedia.org/wiki/Exif) in that there is a basic header at the start of the file which identifies the format and version, followed by zero or more optional tag/value pairs akin to Exif or the zip format's "extra fields" as described [here](https://en.wikipedia.org/wiki/ZIP_(file_format)). The directory and file entries within the archive will consist entirely of tag/size/value tuples.

## Objectives

For now, the first objective is to complete the proof of concept by building an `exaf` binary that can create, list, and extract archives, offering a modest amount of functionality. Eventually the purpose of this project will be to provide a full-featured binary as well as a [Rust](https://www.rust-lang.org) library with an interface similar to that of the [tar crate](https://docs.rs/tar/latest/tar/).

## Build and Run

### Prerequisites

* [Rust](https://www.rust-lang.org) 2021 edition

### Instructions

For the time being there are no unit tests, so simply build and run like so:

```shell
cargo run
```

## Prior Art

There are [many existing](https://en.wikipedia.org/wiki/List_of_archive_formats) archive formats, many of which have long since fallen out of common use. Those that remain are not without their shortcomings, such as poorly implemented encryption features, or vulnerability to compression factor exploits (*zip bomb*).

The original motivation to start this project began when [O](https://github.com/OttoCoddo) announced the [pack](https://pack.ac) file format. They introduced a novel approach to the problem of archiving and compressing files while lamenting the general lack of progress in this area.
