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
}

impl<W: Write + Seek> PackBuilder<W> {
    ///
    /// Construct a new `PackBuilder` that will operate entirely in memory.
    ///
    pub fn new(mut output: W) -> Result<Self, Error> {
        write_archive_header(&mut output)?;
        Ok(Self {
            output,
            prev_dir_id: 0,
            directories: vec![],
            prev_file_id: 0,
            files: HashMap::new(),
            current_pos: 0,
            contents: vec![],
            buffer: None,
        })
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
        self.contents = vec![];
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
    /// Adds a single file to the archive, returning the item identifier.
    ///
    /// Depending on the size of the file and the content bundle so far, this
    /// may result in writing one or more rows to the content and itemcontent
    /// tables.
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
    /// Adds a symbolic link to the archive, returning the item identifier.
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

    //
    // Creates a content bundle based on the data collected so far, then
    // compresses it, writing the blob to a new row in the `content` table. Then
    // creates the necessary rows in the `itemcontent` table to map the file
    // data to the content bundle.
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

        // iterate through the file contents, compressing to the output
        let mut encoder = zstd::stream::write::Encoder::new(content, 0)?;
        for item in self.contents.iter() {
            if item.kind == Kind::File {
                let mut input = fs::File::open(&item.path)?;
                input.seek(SeekFrom::Start(item.itempos))?;
                let mut chunk = input.take(item.size);
                io::copy(&mut chunk, &mut encoder)?;
            } else if item.kind == Kind::Link {
                let value = read_link(&item.path)?;
                encoder.write_all(&value)?;
            }
        }
        content = encoder.finish()?;

        // serialize the manifest header to the output
        let num_entries = (self.directories.len() + self.files.len()) as u16;
        write_manifest_header(num_entries, content.len(), &mut self.output)?;

        // write all of the directory entries to the output
        for dir_entry in self.directories.iter() {
            let mut header = HeaderBuilder::new();
            add_directory_rows(&dir_entry, &mut header)?;
            // add_metadata_rows(&dir_entry, &mut header)?;
            header.write_header(&mut self.output)?;
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
            header.write_header(&mut self.output)?;
        }

        // write the compressed buffer to the output
        self.output.write_all(&mut content)?;

        self.buffer = Some(content);
        Ok(())
    }
}

fn write_archive_header<W: Write>(mut output: W) -> io::Result<()> {
    // Any optional header rows would be serialized to a buffer here, and that
    // length would be written as the last two bytes of this `version` row, then
    // the buffer would be written to the output.
    let version = [b'E', b'X', b'A', b'F', 1, 0, 0, 0];
    output.write_all(&version)?;
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
        let tag_bytes = u16::to_be_bytes(tag);
        self.buffer.write_all(&tag_bytes)?;
        self.buffer.write_all(&[0, 2])?;
        let value_bytes = u16::to_be_bytes(value);
        self.buffer.write_all(&value_bytes)?;
        self.row_count += 1;
        Ok(())
    }

    /// Add a single u32 value to the header.
    fn add_u32(&mut self, tag: u16, value: u32) -> Result<(), Error> {
        let tag_bytes = u16::to_be_bytes(tag);
        self.buffer.write_all(&tag_bytes)?;
        self.buffer.write_all(&[0, 4])?;
        let value_bytes = u32::to_be_bytes(value);
        self.buffer.write_all(&value_bytes)?;
        self.row_count += 1;
        Ok(())
    }

    /// Add a single u64 value to the header.
    fn add_u64(&mut self, tag: u16, value: u64) -> Result<(), Error> {
        let tag_bytes = u16::to_be_bytes(tag);
        self.buffer.write_all(&tag_bytes)?;
        self.buffer.write_all(&[0, 8])?;
        let value_bytes = u64::to_be_bytes(value);
        self.buffer.write_all(&value_bytes)?;
        self.row_count += 1;
        Ok(())
    }

    /// Add a single i64 value to the header.
    fn add_i64(&mut self, tag: u16, value: i64) -> Result<(), Error> {
        let tag_bytes = u16::to_be_bytes(tag);
        self.buffer.write_all(&tag_bytes)?;
        self.buffer.write_all(&[0, 8])?;
        let value_bytes = i64::to_be_bytes(value);
        self.buffer.write_all(&value_bytes)?;
        self.row_count += 1;
        Ok(())
    }

    /// Add a variable length string to the header.
    fn add_str(&mut self, tag: u16, value: &str) -> Result<(), Error> {
        // the value is almost certainly not going to be this long
        assert!(value.len() < 65536);
        let tag_bytes = u16::to_be_bytes(tag);
        self.buffer.write_all(&tag_bytes)?;
        let value_bytes = value.as_bytes();
        let value_len = u16::to_be_bytes(value_bytes.len() as u16);
        self.buffer.write_all(&value_len)?;
        self.buffer.write_all(value_bytes)?;
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
fn write_manifest_header<W: Write>(
    num_entries: u16,
    block_size: usize,
    output: W,
) -> Result<(), Error> {
    let mut header = HeaderBuilder::new();
    header.add_u16(TAG_NUM_ENTRIES, num_entries)?;
    // compression algorithm is always Zstandard, for now
    header.add_u8(TAG_COMP_ALGO, 1)?;
    // block size will never larger than 2^32 bytes
    header.add_u32(TAG_BLOCK_SIZE, block_size as u32)?;
    header.write_header(output)?;
    Ok(())
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
    header.add_u64(TAG_ITEM_POS, item_content.itempos)?;
    // content position will never more than 2^32 bytes
    header.add_u32(TAG_CONTENT_POS, item_content.contentpos as u32)?;
    // size of content will never more than 2^32 bytes
    header.add_u32(TAG_ITEM_SIZE, item_content.size as u32)?;
    Ok(())
}
