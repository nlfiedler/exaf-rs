# Exaf File Format

## Overview

The basic file structure starts with a header that describes the file, followed by a table-of-contents (hereafter called _manifest_), followed by the (compressed) file data (_content_). The manifest describes the directories, files, and symbolic links that are recorded in the content. The file and link entries have additional fields that indicate where their content is stored within the content block. At a minimum there will be a header followed by one manifest and content block, but it is possible to have multiple manifest/content pairs, one following immediately after the other.

| Section | Description |
| ------- | ----------- |
| Archive header | Magic number, version, optional attributes |
| Manifest | Information on directories, files, and symbolic links in the following block of content |
| Content | A large compressed blob of file data |
| ... | Manifest and Content may repeat as many times as needed |

The details of each portion of the archive are described in the sections below.

### Prior Art

There is nothing at all novel about the format described here, as it borrows heavily from other file formats and simply tries to make an appropriate set of tradeoffs. The primary sources of influence for this format are named below (in alphabetical order).

* [Pack](https://pack.ac): the manner in which it packs files into a content blob.
* [tar](https://en.wikipedia.org/wiki/Tar_(computing)): how it can easily append new content at the end of an existing file.
* [XAR](https://en.wikipedia.org/wiki/Xar_(archiver)): the basic overall structure and flexible metadata format.
* [ZIP](https://en.wikipedia.org/wiki/ZIP_(file_format)): the tag/size/value _extra fields_ which are described herein as _header rows_. This basic structure is also known as [Type-length-value](https://en.wikipedia.org/wiki/Type–length–value).

### Objectives

The high-level objectives are as follows:

* It should be flexible, extensible, and support fields of various lengths.
* It should be easy to add content by simply appending to the end of the file.
* It should support recording metadata for files and directories.
* It should support the best available compression algorithms.
* It should support encryption using the best available algorithms and standards.
* It should have as few limits as is reasonable (see [Limitations](#limitations) below).

Concerning the potential choices for the format of metadata within the archive, several formats come to mind. Looking at something like [XAR](https://en.wikipedia.org/wiki/Xar_(archiver)), it is clear that XML is flexible, humanly readable, and supports complex data types. Alternatively, JSON is smaller than XML and almost as expressive. Even more concise is something like the EXIF format that uses _tag_, _type_, and _count_ to record all sorts of values. A binary format that is very concise, [CBOR](https://cbor.io), is also a strong contender.

At a higher level, the overall container format found in Pack is very interesting. It places a hard dependency on a third party (SQLite), and involves some very complex SQL queries, but it is fast and produces a pretty small archive. As we will soon see with CBOR, relying on SQLite means you **must** have access to a good library that provides everything you need from SQLite, and that can be a challenge.

Ultimately, the format of metadata described below most closely resembles that of the _extra fields_ found in the [ZIP file format](https://en.wikipedia.org/wiki/ZIP_(file_format)). Why not XML? It's not compact, not even close. Why not JSON? It is smaller than XML but still not very compact. Why not CBOR? It is difficult to find a compliant implementation (in Rust), especially with respect to storing a byte array (referred to as a _byte string_ in the CBOR specification).

### Headers

Nearly all metadata is represented with a _header_ that consists of rows of **tag**, **size**, and **value**. A header starts with 2 bytes that indicate the number of rows. Each row has a 2-byte tag, a 2-byte size, and an N-byte value, where N may any integer from 0 to 65,535. An empty header is represented as two zero bytes, meaning there are zero rows in the header. A textual value **must** be UTF-8 encoded. An integer value _should_ be serialized to the smallest number of bytes. Tags and sizes will **always** be two bytes each, so the shortest possible row will be 4 bytes in length (2 + 2 + 0). Likewise, the longest possible row will be 2 + 2 + 65,535 bytes. Tags, sizes, and numeric values are stored in network byte order (Big Endian).

The order of rows in the header is **not** significant. A header should be treated as a dictionary of keys and values.

Why does _every_ row have a 2-byte tag and 2-byte size? Because different implementations are free to write out tags that are understood by that implementation, but not necessarily other implementations. As such, a reader might be given a file that contains unrecognized tags, and as such _should_ ignore anything it does not understand. With this basic structure in place, any reader can parse the bytes into a simple map of **tags** to **values** (in which the values are simply raw bytes), processing those tags the reader knows about and ignoring the rest.

A simple example follows, which contains 2 rows, one textual value and one numeric value. Offsets 0 and 1 indicate the number of rows, while row 1 starts at offset 2 and ends at offset 14, and row 2 starts at offset 15 and ends at offset 19. This header describes a file whose name is `README.md` and it belongs in a directory whose unique identifier is `101`.

| Offset | Value  | Description |
| ------ | ------ | ----------- |
|      0 | `0x00` | High byte of 16-bit **number of rows** in header |
|      1 | `0x02` | Low byte of 16-bit **number of rows** in header |
|      2 | `N`    | High byte of 16-bit **tag** (letter _N_) |
|      3 | `M`    | Low byte of 16-bit **tag** (letter _M_) |
|      4 | `0x00` | High byte of 16-bit **size** of value in bytes |
|      5 | `0x09` | Low byte of 16-bit **size** of value in bytes |
|      6 | `R`    | First byte of the value |
|      7 | `E`    | Second byte of the value |
|      8 | `A`    | ... |
|      9 | `D`    | ... |
|     10 | `M`    | ... |
|     11 | `E`    | ... |
|     12 | `.`    | ... |
|     13 | `m`    | ... |
|     14 | `d`    | Last byte for the value of row 1 |
|     15 | `P`    | High byte of 16-bit tag (letter _P_) |
|     16 | `A`    | Low byte of 16-bit tag (letter _A_) |
|     17 | `0x00` | High byte of 16-bit size of value in bytes |
|     18 | `0x01` | Low byte of 16-bit size of value in bytes |
|     19 | `0x65` | The value, decimal number _101_ |

Throughout this document, any _value_ that is shown as text can be assumed to be UTF-8 encoded. In the example above, the `N` and `M` tags are the hexadecimal values `0x4e` and `0x4d`, respectively.

In the tables that detail the format in subsequent sections, the **Max Size** values indicate the maximum size of the row value. The purpose of this is to indicate the numeric precision for values that may be squashed to their smallest possible size. That is, what might normally be a 4-byte value can be written as a single byte if its value is less than 256. As such, the **size** of the value would be `0x0001` in the file but when parsed into memory it _should_ be a 32-bit number. The `PA` row in the example above is an example of this squashing: the directory identifier would normally be a 32-bit number, but since this value was `101` it was serialized as a single byte.

In the tables in subsequent sections, the **Type** labels are basically Rust types. A `u8` is an unsigned 8-bit integer and a `u32` is an unsigned 32-bit integer, while a `[u8]` is an array of unsigned 8-bit integers. A `str` is a UTF-8 encoded string.

## Archive header

Every Exaf archive starts with a magic number, version, and number of optional header rows.

| Offset | Value |
| ------ | ----- |
|      0 |  `E`  |
|      1 |  `X`  |
|      2 |  `A`  |
|      3 |  `F`  |
|      4 | `0x01` |
|      5 | `0x01` |
|      6 | vary  |
|      7 | vary  |

* The first four bytes are the UTF-8 encoded characters `EXAF` which act as the _magic number_ value.
* Offsets 4 and 5 represent the **major** and **minor** version of the file format, currently **1.1**.
* Offsets 6 and 7 indicate the number of rows of tag/size/value tuples that follow.
    - If the archive header is empty, the bytes at offsets 6 and 7 will be `0`.

### Optional archive header rows

If the bytes at offsets 6 and 7 in the archive header are non-zero, then the rows after that may be as described in the table below.

| Tag  | Description                              | Max Size | Type   |
| ---- | ---------------------------------------- | -------- | ------ |
| `EA` | encryption algorithm (e.g. AES256-GCM)   |        1 | `u8`   |
| `KD` | key derivation algorithm (e.g. Argon2id) |        1 | `u8`   |
| `SA` | random salt used to derive the key       |     vary | `[u8]` |
| `TC` | optional number of iterations for KDF (_time cost_) | 4 | `u32` |
| `MC` | optional number of 1kb memory blocks for KDF (_memory cost_) | 4 | `u32` |
| `PC` | optional degree of parallelism for KDF (_parallelism cost_) | 4 | `u32` |
| `TL` | optional number of bytes of output for KDF (_tag length_) | 4 | `u32` |

The encryption related rows are described in detail in the [Encryption](#encryption) section.

## Manifest and Content

The manifest and content start immediately after the archive header. The manifest describes the directories, files, and symbolic links that are contained in whole or in part in the content block that follows. The main objective of having a content block is to combine as much file content as it takes to fill a large buffer and then compress it. Compression is typically more effective with larger blocks of data. As such, the implementation contained in this repository combines files until it fills an in-memory buffer that is **16 megabytes** in size. Larger sizes can also work, but the results are often less than 1 percent smaller.

Files that cannot fit within the remainder of a content block will be split into the next manifest/content pair. This is also true for very large files that exceed the size of the content block. The manifest entries will indicate what portion of a file is contained in the paired content block.

| Section | Description |
| ------- | ----------- |
| Manifest header | Small header of about 3 rows that describes the rest of the manifest |
| Directory entry | Optional directory entries that serve to contain other entries |
| File/link entry | Entry that describes a file or symbolic link, probably belonging to a directory above |
| Content | After possibly many directory/file/link entries, the content follows |

The number of directory, file, and symlink entries in the manifest is indicated by a value in the manifest header, as described below. The manifest header also indicates what compression algorithm was used to compress the content, as well as the size in bytes of the content block.

There may be more than one of these manifest/content pairs existing in the archive. The only indication is when the reader reaches the end of the file. This allows for easy appending of new manifest/content pairs without modifying the existing archive data.

When creating multiple manifest/content pairs, only the file entries that appear in that content need to be listed in the associated manifest. Similarly, parent directories that have already been recorded in a previous manifest do not need to be repeated in subsequent manifests. If a file is split across two or more content blocks, then its entry will appear in each associated manifest. Why? Because each entry will indicate which part of the file is stored in the associated content, and where within the content (as described below). It is sufficient to store the metadata only in the first manifest, rather than repeat that lengthy set of rows each time. The metadata only needs to be applied when the file is first created, and that will happen when the first content block containing a piece of that file is processed.

### Header

Each manifest starts with a small header that describes the rest of the manifest and the content. Following that short header will be one or more directory, file, or symlink entries, then finally the content.

| Tag  | Description                        | Max Size | Type  |
| ---- | ---------------------------------- | -------- | ----- |
| `NE` | number of entries in this manifest |        4 | `u32` |
| `CA` | compression algorithm (e.g. zstd)  |        1 | `u8`  |
| `BS` | size of content in bytes           |        4 | `u32` |

The values for `CA` at this time are `0` for _none_ and `1` for [Zstandard](http://facebook.github.io/zstd/). Zstandard makes for a good choice for the initial version since it is both fast and produces fairly small compressed content. When creating an archive, rather than have a `CA` row whose value is `0` it is better to simply elide that row entirely as _none_ will be the default.

### Entries

Following the short manifest header are one or more _entry_ headers. The number of entries is specified in the `NE` row of the manifest header and will never exceed 4,294,967,295, which should be enough for most use cases. Keep in mind that the `NE` limit is **per manifest**, not the archive overall. In theory, the archive could be extremely large, with as many manifest/content pairs as necessary. The only limiting factor to the archive size is that unique identifiers for directories are limited to 32 bits, so at most an archive could have 4,294,967,295 directories (`0` is not a valid identifier).

* Directory entries are optional, but should appear before any entries that refer to them.
* Each directory entry is assigned a numeric identifier that is unique within the archive.
* All textual values are UTF-8 encoded, including directory, file, and symlink names.
* Full file paths are _not_ recorded to avoid the slash/backslash translation problem.
* References to parent directories are made using a unique identifier.
* If an entry has any date/time fields (e.g. _modified time_) then it is encoded using either a signed 32-bit integer or a signed 64-bit integer as seconds since the epoch, also known as [Unix time](https://en.wikipedia.org/wiki/Unix_time).
* Directory entries have a row with the tag `ID` that is their unique identifier.
* Symbolic links have a row with the tag `SL` that is the name of the link.
* Any entry that does not have an `ID` or an `SL` row is a normal file.

#### Directories

For the sake of compactness, and to avoid the slash/backslash path separator issue, directories in the archive are given unique numeric identifiers. That is, every full path appearing in the archive will have a unique identifier. Each entry _may_ have a `PA` header row that refers to the parent directory to which that the entry belongs. As such, it is helpful, if not practically required, that parent directories appear before those entries that refer to them. As such, a breadth-first traversal is the best approach when creating an archive from a directory tree.

However, parents are not required: an entry can simply exist at the top of the archive, which may be useful for collecting parts of files into an archive, without regard to any existing directory structure. In this case, the entry would _not_ have a `PA` row.

| Tag  | Max Size | Description                         | Required? | Type  |
| ---- | -------- | ----------------------------------- | --------- | ----- |
| `ID` |        4 | Unique identifier                   | yes       | `u32` |
| `NM` |   65,535 | name of directory                   | yes       | `str` |
| `PA` |        4 | identifier of parent directory      |           | `u32` |
| `MO` |        4 | Unix mode                           |           | `u32` |
| `FA` |        4 | Windows file attributes             |           | `u32` |
| `MT` |        8 | modification date/time as Unix time |           | `i64` |
| `CT` |        8 | creation date/time as Unix time     |           | `i64` |
| `AT` |        8 | access date/time as Unix time       |           | `i64` |
| `UN` |   65,535 | name of FS owner                    |           | `str` |
| `UI` |        4 | user identifier                     |           | `u32` |
| `GN` |   65,535 | name of FS group                    |           | `str` |
| `GI` |        4 | group identifier                    |           | `u32` |

Note that it is extremely unlikely that the `NM`, `UN`, and `GN` rows will have a length that is anywhere near the maximum of `65,535` -- this is merely the result of the row **size** being a 16-bit number.

#### Files

File entries will have this format:

| Tag  | Max Size | Description                         | Required? | Type  |
| ---- | -------- | ----------------------------------- | --------- | ----- |
| `NM` |   65,535 | name of file                        | yes       | `str` |
| `PA` |        4 | identifier of parent directory      |           | `u32` |
| `LN` |        8 | total length of file in bytes       |           | `u64` |
| `MO` |        4 | Unix mode                           |           | `u32` |
| `FA` |        4 | Windows file attributes             |           | `u32` |
| `MT` |        8 | modification date/time as Unix time |           | `i64` |
| `CT` |        8 | creation date/time as Unix time     |           | `i64` |
| `AT` |        8 | access date/time as Unix time       |           | `i64` |
| `UN` |   65,535 | name of FS owner                    |           | `str` |
| `UI` |        4 | user identifier                     |           | `u32` |
| `GN` |   65,535 | name of FS group                    |           | `str` |
| `GI` |        4 | group identifier                    |           | `u32` |

As with directories, the `NM`, `UN`, and `GN` rows will almost certainly be much shorter than 64kb.

As mentioned above, the `LN` and other metadata rows will likely only be present the first time the file appears in the archive, and should not be repeated in subsequent manifests if the file content spills over into another block.

#### Symbolic Links

Typically symbolic links do not have any metadata as it depends on the operating system, with FreeBSD being one such exception. If a link does have its own metadata, those values will be represented in the header in an identical manner to other directory and file entries.

| Tag  | Max Size | Description                    | Required? | Type  |
| ---- | -------- | ------------------------------ | --------- | ----- |
| `SL` |   65,535 | name of symbolic link          | yes       | `str` |
| `PA` |        4 | identifier of parent directory |           | `u32` |
| `LN` |        8 | length of link content         |           | `u64` |

Similar to files and directories, the `SL` row will almost certainly be much shorter than 64kb.

### Content

The entry headers above are enough to describe a file on disk but not where the content of the file can be found within the content block. As such, additional header rows are added to each symbolic link and file entry in the manifest that describe where the file content can be found in the content block that follows the manifest header.

| Tag  | Description                                   | Max Size | Type  |
| ---- | --------------------------------------------- | -------- | ----- |
| `IP` | item position: offset within file             |        8 | `u64` |
| `CP` | content position: offset within content block |        4 | `u32` |
| `SZ` | size in bytes of this piece of the file       |        4 | `u32` |

Typically an entire file will fit within a block, in which case its `IP` value will be `0` and its `SZ` value will equal the length of the file. The `CP` is the offset within the **uncompressed** content block where the file content can be found.

With these three values, files of any size can be recorded in the archive. Additionally, the content blocks can be filled to their maximum size by splitting files across blocks, ensuring the best results for compression of the content (hence, no need for bin packing files into content blocks).

There are no data encoders involved in this archive format. As such, file data is simply copied in to and out of the content block, without any translation. When the block is full, then it is compressed.

Symbolic link content is simply stored in the content block like any other file, however it should not be split across content blocks (the implementation in this repository assumes this to be the case). Storing the entire link content in a single block may result in a content block being slightly larger than its ideal _maximum_ but that is not in any way a limitation: the content block size can be very large if that is helpful. The 16 megabyte target size is just a target, not a rule.

Zero-length files will have a `SZ` of `0` and thus no data within the block.

A simple example of a file entry in the manifest that describes where the content is stored in the content block follows, which contains 5 rows of values. First is the name (`NM`), then its parent directory (`PA`), then the offset within the file where the content came from (`IP`), followed by the position within the (uncompressed) content block where the data resides (`CP`), and finally the size in bytes of the file part (`SZ`).

| Offset | Value  | Description |
| ------ | ------ | ----------- |
|      0 | `0x00` | Number of rows (high byte) |
|      1 | `0x05` | Number of rows (low byte) |
|      2 | `N`    | Tag (high byte) |
|      3 | `M`    | Tag (low byte) |
|      4 | `0x00` | Size (high byte) |
|      5 | `0x09` | Size (low byte) |
|      6 | `R`    | Value |
|      7 | `E`    | . |
|      8 | `A`    | . |
|      9 | `D`    | . |
|     10 | `M`    | . |
|     11 | `E`    | . |
|     12 | `.`    | . |
|     13 | `m`    | . |
|     14 | `d`    | . |
|     15 | `P`    | Tag (high byte) |
|     16 | `A`    | Tag (low byte) |
|     17 | `0x00` | Size (high byte) |
|     18 | `0x01` | Size (low byte) |
|     19 | `0x65` | value |
|     20 | `I`    | Tag (high byte) |
|     21 | `P`    | Tag (low byte) |
|     22 | `0x00` | Size (high byte) |
|     23 | `0x01` | Size (low byte) |
|     24 | `0x00` | value |
|     25 | `C`    | Tag (high byte) |
|     26 | `P`    | Tag (low byte) |
|     27 | `0x00` | Size (high byte) |
|     28 | `0x02` | Size (low byte) |
|     29 | `0x01` | Value |
|     30 | `0x0f` | . |
|     31 | `S`    | Tag (high byte) |
|     32 | `Z`    | Tag (low byte) |
|     33 | `0x00` | Size (high byte) |
|     34 | `0x02` | Size (low byte) |
|     35 | `0x10` | Value |
|     36 | `0xab` | . |

Note that an `IP` row _could_ have a 64-bit value, but here it's recorded as a single zero, saving several bytes. Same for the `CP` and `SZ` row values. The number squashing may look confusing but it helps in the long run.

## Encryption

Encryption in the archive is applied on a per manifest/content pair basis. That is, the initial archive header remains the same, with the addition of header rows that describe the encryption. After the archive header, the encrypted content will follow, preceded by a short header. It is allowable to have more than one manifest/content pair with some of them encrypted and some of them not encrypted.

An encrypted manifest is distinguished by the presence of a header row with the tag `ES` (_encrypted size_). Otherwise, it is safe to assume that the manifest and content are not encrypted.

As a reminder, the archive header rows related to encryption are as follows:

| Tag  | Description                              | Max Size | Type   |
| ---- | ---------------------------------------- | -------- | ------ |
| `EA` | encryption algorithm (e.g. AES256-GCM)   |        1 | `u8`   |
| `KD` | key derivation algorithm (e.g. Argon2id) |        1 | `u8`   |
| `SA` | random salt used to derive the key       |     vary | `[u8]` |
| `TC` | optional number of iterations for KDF (_time cost_) | 4 | `u32` |
| `MC` | optional number of 1kb memory blocks for KDF (_memory cost_) | 4 | `u32` |
| `PC` | optional degree of parallelism for KDF (_parallelism cost_) | 4 | `u32` |
| `TL` | optional number of bytes of output for KDF (_tag length_) | 4 | `u32` |

The values for `EA` at this time are `0` for _none_ and `1` for the **AES256-GCM AEAD** cipher. Similarly, the `KD` can be `0` for _none_ and `1` for the **Argon2id** key derivation function (KDF). When creating an archive, rather than have `EA` or `KD` rows whose values are `0` it is better to simply elide the rows entirely as _none_ will be the default.

The `SA` value length may vary but it will likely be around 16 bytes. The salt is stored as raw bytes, so if your library generates an encoded form (such as base64), you must decode it before storing in the `SA` header row.

The three optional _cost_ rows are given as parameters to the key-derivation function. The `TC` value indicates the number of iterations, the `MC` value indicates the number of 1 kilobyte memory blocks to be used, and the `PC` value indicates the degree of parallelism. The **default** value for `TC` is `2`, the **default** for `MC` is `19,456`, and the **default** for `PC` is `1`. These defaults are recommended in OWASP's [password storage cheat sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html) and are the defaults in the [argon2](https://docs.rs/argon2/latest/argon2/) Rust crate.

The `TL` row is a value that may be referred to as either the _output length_ or _tag length_, which indicates the number of bytes of desired output from the key derivation function. The **default** in the Argon2 Rust create is `32` and as such is the default for this format. In fact, for AES-256 encryption you **need** a key of 32 bytes.

The basic flow of encryption works like so:

1. A password is used to derive a secret key using a KDF, typically with a random salt.
1. The derived key is used to perform symmetric-key encryption on the entire manifest/content pair.
1. Each manifest/content pair will be encrypted with the secret key and a unique nonce.
1. The nonce and size of the cipher text (encrypted data) is stored in a small header that precedes the encrypted data.

Similarly, decryption works in this manner:

1. Use the provided password and the salt read from the archive header to derive the secret key.
1. Read the nonce from the encryption header (the `IV` row in the header described below).
1. Read the encrypted data (the number of bytes is indicated in the `ES` header row).
1. Use the secret key and nonce to decrypt the cipher text.
1. The decrypted data is the original manifest and content pair.

All of this can easily be done in memory since the content block is typically less than 16mb and the manifest _should_ be much smaller than the content. Even a 64mb block is still very small compared to the memory found in modern computers. Note that it will help _significantly_ to allocate a large memory buffer and reuse it during the entire process.

### Header

As alluded to above, an encrypted archive will have both the manifest and its content encrypted as a single _message_, typically **much** smaller than the limits imposed by the encryption algorithm. The cipher text will be preceded by a header that provides the nonce described above and the number of bytes to read after the header to get the entire encrypted block of data.

| Tag  | Description                   | Max Size | Type   |
| ---- | ----------------------------- | -------- | ------ |
| `IV` | initialization vector (nonce) |     vary | `[u8]` |
| `ES` | byte size of the cipher text  |        4 | `u32`  |

The `IV` data will typically be 12 to 16 bytes in length.

As alluded to above, the `ES` value will typically be smaller than 16mb due to compression.

## Limitations

From the details above, we can infer several limits on the archive format:

* The number of rows in a header is encoded as 16-bits, so a header can have at most 65,535 rows.
* Header row sizes are encoded as 16-bits, so a row value can have at most 65,535 bytes.
* Algorithms are all encoded as 8-bits, limiting us to 255 compression algorithms, 255 encryption algorithms, and 255 key derivation functions.
* File _item position_ (`IP`) values are encoding using 64-bits, limiting file sizes to around 18,446,744,073,709,551,615 bytes.
* The number of iterations for the KDF is encoded using 32-bits, limiting us to 4,294,967,295 iterations.
* Directory identifiers are encoded using 32-bits, so at most 4,294,967,295 directories can appear in a single archive.

The content blocks have a size limit, but that is not relevant since the archive may have an unlimited number of content blocks, and as such the blocks can be sized to any reasonable length.

## Revision History

### Version 1.1

* Added `LN` header row for files and links whose value is the total size of the file or link.

### Version 1.0

Initial release with directories, files, and symbolic links, basic metadata, compression using Zstandard, Argon2id KDF, AES256-GCM AEAD.
