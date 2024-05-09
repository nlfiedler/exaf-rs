//
// Copyright (c) 2024 Nathan Fiedler
//
use super::*;
use std::collections::HashMap;
use std::fs;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

//
// Represents the content of a file (item) and its position within a content
// bundle when building an archive. It is possible that a portion of the file is
// being added and thus the itempos might be non-zero; similarly the size may be
// less than the actual file length.
//
struct IncomingContent {
    // path of the file being packed
    path: PathBuf,
    // kind of item: file or symlink
    kind: Kind,
    // corresponding file entry identifier
    file_id: u32,
    // offset within the file from which to start, usually zero
    itempos: u64,
    // offset within the content bundle where the data will go
    contentpos: u64,
    // size of the item content
    size: u64,
}

///
/// Creates or updates an archive.
///
pub struct PackBuilder<W: Write + Seek> {
    // output to which archive will be written
    output: W,
    // identifier of the most recent directory entry
    prev_dir_id: u32,
    // directories to be written in the pending manifest
    directories: Vec<Entry>,
    // identifier of the most recent file entry
    prev_file_id: u32,
    // files to be written, at least partially, in the pending manifest; the key is
    // a numeric identifier that is unique to this archive
    files: HashMap<u32, Entry>,
    // byte offset within a bundle to which new content is added
    current_pos: u64,
    // item content that will reside in the bundle under construction
    contents: Vec<IncomingContent>,
    // buffer for compressing content bundle in memory (to get final size)
    buffer: Option<Vec<u8>>,
    // buffer for building up the manifest + content in memory
    manifest: Option<Vec<u8>>,
    // chosen encryption algorithm, possibly none
    encryption: Encryption,
    // secret key for encrypting files, if encryption is enabled
    secret_key: Option<Vec<u8>>,
}

impl<W: Write + Seek> PackBuilder<W> {
    ///
    /// Construct a new `PackBuilder` that will operate entirely in memory.
    ///
    pub fn new(mut output: W) -> Result<Self, Error> {
        write_archive_header(&mut output, None)?;
        Ok(Self {
            output,
            prev_dir_id: 0,
            directories: vec![],
            prev_file_id: 0,
            files: HashMap::new(),
            current_pos: 0,
            contents: vec![],
            buffer: None,
            manifest: None,
            encryption: Encryption::None,
            secret_key: None,
        })
    }

    ///
    /// Enable encryption when building this archive, using the given passphrase.
    ///
    pub fn enable_encryption(
        &mut self,
        kd: KeyDerivation,
        ea: Encryption,
        password: &str,
    ) -> Result<(), Error> {
        if self.prev_dir_id > 0 || self.prev_file_id > 0 {
            return Err(Error::InternalError("pack must be empty".into()));
        }
        self.encryption = ea.clone();
        let salt = generate_salt(&kd)?;
        let params: KeyDerivationParams = Default::default();
        self.secret_key = Some(derive_key(&kd, password, &salt, &params)?);
        // reset the output position and write out a new archive header that
        // includes the encryption information provided
        self.output.seek(SeekFrom::Start(0))?;
        let mut header = HeaderBuilder::new();
        header.add_u8(TAG_ENC_ALGO, ea.into())?;
        header.add_u8(TAG_KEY_DERIV, kd.into())?;
        header.add_bytes(TAG_SALT, &salt)?;
        write_archive_header(&mut self.output, Some(header))?;
        Ok(())
    }

    ///
    /// Visit all of the files and directories within the specified path, adding
    /// them to the archive.
    ///
    /// **Note:** Remember to call `finish()` when done adding content.
    ///
    pub fn add_dir_all<P: AsRef<Path>>(&mut self, basepath: P) -> Result<u64, Error> {
        let mut file_count: u64 = 0;
        let mut subdirs: Vec<(u32, PathBuf)> = Vec::new();
        subdirs.push((0, basepath.as_ref().to_path_buf()));
        while let Some((parent, currdir)) = subdirs.pop() {
            let dir_id = self.add_directory(&currdir, parent)?;
            let readdir = fs::read_dir(currdir)?;
            for entry_result in readdir {
                let entry = entry_result?;
                let path = entry.path();
                // DirEntry.metadata() does not follow symlinks and that is good
                let metadata = entry.metadata()?;
                if metadata.is_dir() {
                    subdirs.push((dir_id, path));
                } else if metadata.is_file() {
                    self.add_file(&path, Some(dir_id))?;
                    file_count += 1;
                } else if metadata.is_symlink() {
                    self.add_symlink(&path, Some(dir_id))?;
                }
            }
        }
        Ok(file_count)
    }

    ///
    /// Call `finish()` when all file content has been added to the builder.
    ///
    pub fn finish(&mut self) -> Result<(), Error> {
        if !self.contents.is_empty() {
            self.process_contents()?;
        }
        Ok(())
    }

    ///
    /// Process the current bundle of item content, clearing the collection and
    /// resetting the current content position.
    ///
    fn process_contents(&mut self) -> Result<(), Error> {
        self.insert_content()?;
        self.contents.clear();
        self.directories.clear();
        self.current_pos = 0;
        Ok(())
    }

    ///
    /// Add directory entry to the manifest, returning the new directory identifier.
    ///
    fn add_directory<P: AsRef<Path>>(&mut self, path: P, parent: u32) -> Result<u32, Error> {
        self.prev_dir_id += 1;
        let mut dir_entry = Entry::new(path);
        dir_entry.dir_id = Some(self.prev_dir_id);
        // parent might be zero when buildin
        if parent > 0 {
            dir_entry.parent = Some(parent);
        }
        self.directories.push(dir_entry);
        Ok(self.prev_dir_id)
    }

    ///
    /// Adds a single file to the archive.
    ///
    /// Depending on the size of the file and the content bundle so far, this
    /// may result in writing one or more manifest/content pairs to the output.
    ///
    /// **Note:** Remember to call `finish()` when done adding content.
    ///
    pub fn add_file<P: AsRef<Path>>(&mut self, path: P, parent: Option<u32>) -> Result<(), Error> {
        self.prev_file_id += 1;
        let mut file_entry = Entry::new(path.as_ref());
        file_entry.parent = parent;
        self.files.insert(self.prev_file_id, file_entry);

        let md = fs::metadata(path.as_ref());
        let file_len = match md.as_ref() {
            Ok(attr) => attr.len(),
            Err(_) => 0,
        };
        // empty files will result in a manifest entry whose size is zero,
        // allowing for the extraction process to know to create an empty file
        // (otherwise it is difficult to tell from the available data)
        let mut itempos: u64 = 0;
        let mut size: u64 = file_len;
        loop {
            if self.current_pos + size > BUNDLE_SIZE {
                let remainder = BUNDLE_SIZE - self.current_pos;
                // add a portion of the file to fill the bundle
                let content = IncomingContent {
                    path: path.as_ref().to_path_buf(),
                    kind: Kind::File,
                    file_id: self.prev_file_id,
                    itempos,
                    contentpos: self.current_pos,
                    size: remainder,
                };
                self.contents.push(content);
                // insert the content and itemcontent rows and start a new
                // bundle, then continue with the current file
                self.process_contents()?;
                size -= remainder;
                itempos += remainder;
            } else {
                // the remainder of the file fits within this content bundle
                let content = IncomingContent {
                    path: path.as_ref().to_path_buf(),
                    kind: Kind::File,
                    file_id: self.prev_file_id,
                    itempos,
                    contentpos: self.current_pos,
                    size,
                };
                self.contents.push(content);
                self.current_pos += size;
                break;
            }
        }
        Ok(())
    }

    ///
    /// Adds a symbolic link to the archive.
    ///
    /// **Note:** Remember to call `finish()` when done adding content.
    ///
    pub fn add_symlink<P: AsRef<Path>>(
        &mut self,
        path: P,
        parent: Option<u32>,
    ) -> Result<(), Error> {
        self.prev_file_id += 1;
        let mut file_entry = Entry::new(path.as_ref());
        file_entry.parent = parent;
        self.files.insert(self.prev_file_id, file_entry);

        let md = fs::symlink_metadata(path.as_ref());
        let link_len = match md.as_ref() {
            Ok(attr) => attr.len(),
            Err(_) => 0,
        };
        // assume that the link value is relatively small and simply add it into
        // the current content bundle in whole
        let content = IncomingContent {
            path: path.as_ref().to_path_buf(),
            kind: Kind::Link,
            file_id: self.prev_file_id,
            itempos: 0,
            contentpos: self.current_pos,
            size: link_len,
        };
        self.contents.push(content);
        self.current_pos += link_len;
        Ok(())
    }

    ///
    /// Adds a slice of a file to the archive, using the given name.
    ///
    /// Depending on the size of the slice and the content bundle so far, this
    /// may result in writing one or more manifest/content pairs to the output.
    ///
    /// **Note:** Remember to call `finish()` when done adding content.
    ///
    pub fn add_file_slice<P: AsRef<Path>, S: Into<String>>(
        &mut self,
        path: P,
        name: S,
        parent: Option<u32>,
        offset: u64,
        length: u32,
    ) -> Result<(), Error> {
        self.prev_file_id += 1;
        let mut file_entry = Entry::with_name(name);
        file_entry.parent = parent;
        self.files.insert(self.prev_file_id, file_entry);

        let mut itempos: u64 = offset;
        let mut size: u64 = length as u64;
        loop {
            if self.current_pos + size > BUNDLE_SIZE {
                let remainder = BUNDLE_SIZE - self.current_pos;
                // add a portion of the file to fill the bundle
                let content = IncomingContent {
                    path: path.as_ref().to_path_buf(),
                    kind: Kind::Slice(offset),
                    file_id: self.prev_file_id,
                    itempos,
                    contentpos: self.current_pos,
                    size: remainder,
                };
                self.contents.push(content);
                // insert the content and itemcontent rows and start a new
                // bundle, then continue with the current file
                self.process_contents()?;
                size -= remainder;
                itempos += remainder;
            } else {
                // the remainder of the file fits within this content bundle
                let content = IncomingContent {
                    path: path.as_ref().to_path_buf(),
                    kind: Kind::Slice(offset),
                    file_id: self.prev_file_id,
                    itempos,
                    contentpos: self.current_pos,
                    size,
                };
                self.contents.push(content);
                self.current_pos += size;
                break;
            }
        }
        Ok(())
    }

    //
    // Creates a content bundle based on the data collected so far, then
    // compresses it, produces a manifest to describe the entries in this
    // bundle, optionally encrypts everything, and finally writes to the output.
    //
    fn insert_content(&mut self) -> Result<(), Error> {
        // Allocate a buffer for the compressed data, reusing it each time. For
        // small data sets this makes no observable difference, but for large
        // data sets (e.g. Linux kernel), it makes a huge difference.
        let mut content: Vec<u8> = if let Some(mut buf) = self.buffer.take() {
            buf.clear();
            buf
        } else {
            Vec::with_capacity(BUNDLE_SIZE as usize)
        };

        // iterate through the file contents, compressing to the buffer
        let mut encoder = zstd::stream::write::Encoder::new(content, 0)?;
        for item in self.contents.iter() {
            match item.kind {
                Kind::Link => {
                    let value = read_link(&item.path)?;
                    encoder.write_all(&value)?;
                }
                _ => {
                    // files and slices of files are handled the same
                    let mut input = fs::File::open(&item.path)?;
                    input.seek(SeekFrom::Start(item.itempos))?;
                    let mut chunk = input.take(item.size);
                    io::copy(&mut chunk, &mut encoder)?;
                }
            }
        }
        content = encoder.finish()?;

        // serialize everything to an in-memory buffer to allow for easier
        // encryption, in which we need to know the block size before writing
        // the encryption header to the file _before_ the encrypted block
        // (reader must know how many bytes to read)
        let mut output: Vec<u8> = if let Some(mut buf) = self.manifest.take() {
            buf.clear();
            buf
        } else {
            // add some capacity for the manifest entries
            Vec::with_capacity(content.len() / 2 * 3)
        };

        // create the manifest header
        let num_entries = (self.directories.len() + self.contents.len()) as u32;
        let header = make_manifest_header(num_entries, content.len())?;
        header.write_header(&mut output)?;

        // write all of the directory entries to the output
        for dir_entry in self.directories.iter() {
            let mut header = HeaderBuilder::new();
            add_directory_rows(&dir_entry, &mut header)?;
            // add_metadata_rows(&dir_entry, &mut header)?;
            header.write_header(&mut output)?;
        }

        // serialize item contents, and their corresponding file entries, as a
        // single unit (files and symbolic links are handled the same)
        for content in self.contents.iter() {
            let file_entry = self
                .files
                .get(&content.file_id)
                .expect("internal error, missing file entry for item content");
            let mut header = HeaderBuilder::new();
            add_file_rows(&file_entry, &mut header)?;
            // add_metadata_rows(&file_entry, &mut header)?;
            add_content_rows(&content, &mut header)?;
            header.write_header(&mut output)?;
        }

        // write the compressed buffer to the output
        output.write_all(&mut content)?;

        // if encryption is enabled, write an additional header and then the
        // encrypted block of manifest + content; the result of this will likely
        // be a larger (new) buffer, which will take the place of the working
        // buffer named `output`
        if let Some(ref secret) = self.secret_key {
            let (cipher, nonce) = encrypt_data(&self.encryption, secret, output.as_slice())?;
            let mut header = HeaderBuilder::new();
            header.add_bytes(TAG_INIT_VECTOR, &nonce)?;
            header.add_u32(TAG_ENCRYPTED_SIZE, cipher.len() as u32)?;
            header.write_header(&mut self.output)?;
            output = cipher;
        }
        let mut cursor = std::io::Cursor::new(&output);
        io::copy(&mut cursor, &mut self.output)?;

        self.buffer = Some(content);
        self.manifest = Some(output);
        Ok(())
    }
}

fn write_archive_header<W: Write>(mut output: W, rows: Option<HeaderBuilder>) -> Result<(), Error> {
    let version = [b'E', b'X', b'A', b'F', 1, 0];
    output.write_all(&version)?;
    if let Some(header) = rows {
        header.write_header(output)?;
    } else {
        // an empty header is a header with zero entries
        output.write_all(&[0, 0])?;
    }
    Ok(())
}

///
/// Builds a header consisting of 3-tuples, one value at a time.
///
struct HeaderBuilder {
    buffer: Vec<u8>,
    row_count: u16,
}

impl HeaderBuilder {
    /// Create an empty header builder.
    fn new() -> Self {
        Self {
            buffer: vec![],
            row_count: 0,
        }
    }

    /// Add a single u8 value to the header.
    fn add_u8(&mut self, tag: u16, value: u8) -> Result<(), Error> {
        let tag_bytes = u16::to_be_bytes(tag);
        self.buffer.write_all(&tag_bytes)?;
        self.buffer.write_all(&[0, 1, value])?;
        self.row_count += 1;
        Ok(())
    }

    /// Add a single u16 value to the header.
    fn add_u16(&mut self, tag: u16, value: u16) -> Result<(), Error> {
        if value < 256 {
            self.add_u8(tag, value as u8)
        } else {
            let tag_bytes = u16::to_be_bytes(tag);
            self.buffer.write_all(&tag_bytes)?;
            self.buffer.write_all(&[0, 2])?;
            let value_bytes = u16::to_be_bytes(value);
            self.buffer.write_all(&value_bytes)?;
            self.row_count += 1;
            Ok(())
        }
    }

    /// Add a single u32 value to the header.
    fn add_u32(&mut self, tag: u16, value: u32) -> Result<(), Error> {
        if value < 65_536 {
            self.add_u16(tag, value as u16)
        } else {
            let tag_bytes = u16::to_be_bytes(tag);
            self.buffer.write_all(&tag_bytes)?;
            self.buffer.write_all(&[0, 4])?;
            let value_bytes = u32::to_be_bytes(value);
            self.buffer.write_all(&value_bytes)?;
            self.row_count += 1;
            Ok(())
        }
    }

    /// Add a single u64 value to the header.
    fn add_u64(&mut self, tag: u16, value: u64) -> Result<(), Error> {
        if value < 4_294_967_296 {
            self.add_u32(tag, value as u32)
        } else {
            let tag_bytes = u16::to_be_bytes(tag);
            self.buffer.write_all(&tag_bytes)?;
            self.buffer.write_all(&[0, 8])?;
            let value_bytes = u64::to_be_bytes(value);
            self.buffer.write_all(&value_bytes)?;
            self.row_count += 1;
            Ok(())
        }
    }

    /// Add a single i32 value to the header.
    fn add_i32(&mut self, tag: u16, value: i32) -> Result<(), Error> {
        let tag_bytes = u16::to_be_bytes(tag);
        self.buffer.write_all(&tag_bytes)?;
        self.buffer.write_all(&[0, 4])?;
        let value_bytes = i32::to_be_bytes(value);
        self.buffer.write_all(&value_bytes)?;
        self.row_count += 1;
        Ok(())
    }

    /// Add a single i64 value to the header.
    fn add_i64(&mut self, tag: u16, value: i64) -> Result<(), Error> {
        if value <= 2_147_483_647 || value >= -2_147_483_648 {
            self.add_i32(tag, value as i32)
        } else {
            let tag_bytes = u16::to_be_bytes(tag);
            self.buffer.write_all(&tag_bytes)?;
            self.buffer.write_all(&[0, 8])?;
            let value_bytes = i64::to_be_bytes(value);
            self.buffer.write_all(&value_bytes)?;
            self.row_count += 1;
            Ok(())
        }
    }

    /// Add a variable length string to the header.
    fn add_str(&mut self, tag: u16, value: &str) -> Result<(), Error> {
        // the value is almost certainly not going to be this long
        if value.len() > 65535 {
            return Err(Error::InternalError("add_str value too long".into()));
        }
        let tag_bytes = u16::to_be_bytes(tag);
        self.buffer.write_all(&tag_bytes)?;
        let value_bytes = value.as_bytes();
        let value_len = u16::to_be_bytes(value_bytes.len() as u16);
        self.buffer.write_all(&value_len)?;
        self.buffer.write_all(value_bytes)?;
        self.row_count += 1;
        Ok(())
    }

    /// Add a variable length slice of bytes to the header.
    fn add_bytes(&mut self, tag: u16, value: &[u8]) -> Result<(), Error> {
        // the value is almost certainly not going to be this long
        if value.len() > 65535 {
            return Err(Error::InternalError("add_bytes value too long".into()));
        }
        let tag_bytes = u16::to_be_bytes(tag);
        self.buffer.write_all(&tag_bytes)?;
        let value_len = u16::to_be_bytes(value.len() as u16);
        self.buffer.write_all(&value_len)?;
        self.buffer.write_all(value)?;
        self.row_count += 1;
        Ok(())
    }

    /// Write the header to the given output.
    fn write_header<W: Write>(&self, mut output: W) -> Result<(), Error> {
        let row_count = u16::to_be_bytes(self.row_count);
        output.write_all(&row_count)?;
        output.write_all(&self.buffer)?;
        Ok(())
    }
}

// Build the manifest header and write the bytes to the output.
fn make_manifest_header(num_entries: u32, block_size: usize) -> Result<HeaderBuilder, Error> {
    let mut header = HeaderBuilder::new();
    header.add_u32(TAG_NUM_ENTRIES, num_entries)?;
    // compression algorithm is always Zstandard, for now
    header.add_u8(TAG_COMP_ALGO, Compression::ZStandard.into())?;
    // block size will never larger than 2^32 bytes
    header.add_u32(TAG_BLOCK_SIZE, block_size as u32)?;
    Ok(header)
}

// Inject the metadata rows into the header.
#[allow(dead_code)]
fn add_metadata_rows(entry: &Entry, header: &mut HeaderBuilder) -> Result<(), Error> {
    if let Some(mode) = entry.mode {
        header.add_u32(TAG_UNIX_MODE, mode)?;
    }
    if let Some(attrs) = entry.attrs {
        header.add_u32(TAG_FILE_ATTRS, attrs)?;
    }
    if let Some(mt) = entry.mtime {
        header.add_i64(TAG_MODIFY_TIME, mt.timestamp())?;
    }
    if let Some(ct) = entry.ctime {
        header.add_i64(TAG_CREATE_TIME, ct.timestamp())?;
    }
    if let Some(at) = entry.atime {
        header.add_i64(TAG_ACCESS_TIME, at.timestamp())?;
    }
    if let Some(ref username) = entry.user {
        header.add_str(TAG_USER_NAME, username)?;
    }
    if let Some(ref groupname) = entry.group {
        header.add_str(TAG_GROUP_NAME, groupname)?;
    }
    if let Some(uid) = entry.uid {
        header.add_u32(TAG_USER_ID, uid)?;
    }
    if let Some(gid) = entry.gid {
        header.add_u32(TAG_GROUP_ID, gid)?;
    }
    Ok(())
}

// Build the directory entry header and write the bytes to the output.
fn add_directory_rows(entry: &Entry, header: &mut HeaderBuilder) -> Result<(), Error> {
    if let Some(dir_id) = entry.dir_id {
        header.add_u32(TAG_DIRECTORY_ID, dir_id)?;
    } else {
        return Err(Error::InternalError("dir_id was missing".into()));
    }
    header.add_str(TAG_NAME, &entry.name)?;
    if let Some(parent) = entry.parent {
        header.add_u32(TAG_PARENT, parent)?;
    }
    Ok(())
}

// Add the header rows for the file/link entry to the header builder.
fn add_file_rows(entry: &Entry, header: &mut HeaderBuilder) -> Result<(), Error> {
    if entry.is_link {
        // symbolic links have the SL tag instead of the NM tag
        header.add_str(TAG_SYM_LINK, &entry.name)?;
    } else {
        header.add_str(TAG_NAME, &entry.name)?;
    }
    if let Some(parent) = entry.parent {
        header.add_u32(TAG_PARENT, parent)?;
    }
    Ok(())
}

// Add the header rows for the item content to the header builder.
fn add_content_rows(
    item_content: &IncomingContent,
    header: &mut HeaderBuilder,
) -> Result<(), Error> {
    match item_content.kind {
        Kind::Slice(offset) => {
            // slices will be extracted as their own file, so the recorded item
            // position must be adjusted based on the starting offset
            header.add_u64(TAG_ITEM_POS, item_content.itempos - offset)?;
        }
        _ => {
            header.add_u64(TAG_ITEM_POS, item_content.itempos)?;
        }
    }
    // content position will never more than 2^32 bytes
    header.add_u32(TAG_CONTENT_POS, item_content.contentpos as u32)?;
    // size of content will never more than 2^32 bytes
    header.add_u32(TAG_ITEM_SIZE, item_content.size as u32)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_header_builder_empty() -> Result<(), Error> {
        let builder = HeaderBuilder::new();
        let mut output: Vec<u8> = vec![];
        builder.write_header(&mut output)?;
        assert_eq!(output.len(), 2);
        assert_eq!(output[..], [0, 0]);
        Ok(())
    }

    #[test]
    fn test_header_builder_down_i64() -> Result<(), Error> {
        let mut builder = HeaderBuilder::new();
        builder.add_i64(0x1234, 101)?;
        let mut output: Vec<u8> = vec![];
        builder.write_header(&mut output)?;
        assert_eq!(output.len(), 10);
        assert_eq!(output[..], [0, 1, 0x12, 0x34, 0, 4, 0, 0, 0, 101]);
        Ok(())
    }

    #[test]
    fn test_header_builder_down_u64() -> Result<(), Error> {
        let mut builder = HeaderBuilder::new();
        builder.add_u64(0x1234, 101)?;
        let mut output: Vec<u8> = vec![];
        builder.write_header(&mut output)?;
        assert_eq!(output.len(), 7);
        assert_eq!(output[..], [0, 1, 0x12, 0x34, 0, 1, 101]);
        Ok(())
    }

    #[test]
    fn test_header_builder_down_i32() -> Result<(), Error> {
        let mut builder = HeaderBuilder::new();
        builder.add_i32(0x1234, 101)?;
        let mut output: Vec<u8> = vec![];
        builder.write_header(&mut output)?;
        assert_eq!(output.len(), 10);
        assert_eq!(output[..], [0, 1, 0x12, 0x34, 0, 4, 0, 0, 0, 101]);
        Ok(())
    }

    #[test]
    fn test_header_builder_u8() -> Result<(), Error> {
        let mut builder = HeaderBuilder::new();
        builder.add_u8(0x1234, 255)?;
        let mut output: Vec<u8> = vec![];
        builder.write_header(&mut output)?;
        assert_eq!(output.len(), 7);
        assert_eq!(output[..], [0, 1, 0x12, 0x34, 0, 1, 255]);
        Ok(())
    }

    #[test]
    fn test_header_builder_u16() -> Result<(), Error> {
        let mut builder = HeaderBuilder::new();
        builder.add_u16(0x1234, 65_535)?;
        let mut output: Vec<u8> = vec![];
        builder.write_header(&mut output)?;
        assert_eq!(output.len(), 8);
        assert_eq!(output[..], [0, 1, 0x12, 0x34, 0, 2, 255, 255]);
        Ok(())
    }

    #[test]
    fn test_header_builder_u32() -> Result<(), Error> {
        let mut builder = HeaderBuilder::new();
        builder.add_u32(0x1234, 4_294_967_295)?;
        let mut output: Vec<u8> = vec![];
        builder.write_header(&mut output)?;
        assert_eq!(output.len(), 10);
        assert_eq!(output[..], [0, 1, 0x12, 0x34, 0, 4, 255, 255, 255, 255]);
        Ok(())
    }

    #[test]
    fn test_header_builder_u64() -> Result<(), Error> {
        let mut builder = HeaderBuilder::new();
        builder.add_u64(0x1234, 4_294_967_297)?;
        let mut output: Vec<u8> = vec![];
        builder.write_header(&mut output)?;
        assert_eq!(output.len(), 14);
        assert_eq!(output[..], [0, 1, 0x12, 0x34, 0, 8, 0, 0, 0, 1, 0, 0, 0, 1]);
        Ok(())
    }

    #[test]
    fn test_header_builder_str() -> Result<(), Error> {
        let mut builder = HeaderBuilder::new();
        builder.add_str(0x1234, "foobar")?;
        let mut output: Vec<u8> = vec![];
        builder.write_header(&mut output)?;
        assert_eq!(output.len(), 12);
        assert_eq!(
            output[..],
            [0, 1, 0x12, 0x34, 0, 6, b'f', b'o', b'o', b'b', b'a', b'r']
        );
        Ok(())
    }

    #[test]
    fn test_header_builder_bytes() -> Result<(), Error> {
        let mut builder = HeaderBuilder::new();
        builder.add_bytes(0x1234, "foobar".as_bytes())?;
        let mut output: Vec<u8> = vec![];
        builder.write_header(&mut output)?;
        assert_eq!(output.len(), 12);
        assert_eq!(
            output[..],
            [0, 1, 0x12, 0x34, 0, 6, b'f', b'o', b'o', b'b', b'a', b'r']
        );
        Ok(())
    }

    fn sha1_from_file(infile: &Path) -> io::Result<String> {
        use sha1::{Digest, Sha1};
        let mut file = fs::File::open(infile)?;
        let mut hasher = Sha1::new();
        io::copy(&mut file, &mut hasher)?;
        let digest = hasher.finalize();
        Ok(format!("{:x}", digest))
    }

    #[test]
    fn test_create_archive_file_slice() -> Result<(), Error> {
        // create the archive
        let outdir = tempdir()?;
        let archive = outdir.path().join("archive.exa");
        let output = std::fs::File::create(&archive)?;
        let mut builder = super::writer::PackBuilder::new(output)?;
        builder.add_file_slice(
            "test/fixtures/IMG_0385.JPG",
            "5ba33678260abc495b6c77003ddab5cc613b9ba7",
            None,
            4096,
            8192,
        )?;
        builder.finish()?;

        // extract the archive and verify everything
        let mut reader = super::reader::from_file(&archive)?;
        reader.extract_all(outdir.path())?;
        let actual = sha1_from_file(
            outdir
                .path()
                .join("5ba33678260abc495b6c77003ddab5cc613b9ba7")
                .as_path(),
        )?;
        assert_eq!(actual, "5ba33678260abc495b6c77003ddab5cc613b9ba7");

        Ok(())
    }
}
