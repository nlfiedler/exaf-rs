//
// Copyright (c) 2024 Nathan Fiedler
//
use chrono::prelude::*;
use clap::{arg, Command};
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{self, BufRead, ErrorKind, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::time::SystemTime;

/// This type represents all possible errors that can occur within this crate.
#[derive(thiserror::Error, Debug)]
pub enum Error {
    /// Error occurred during IO related operation.
    #[error("I/O error: {0}")]
    IOError(#[from] std::io::Error),
    /// Error occurred decoding a UTF-8 string from bytes.
    #[error("UTF-8 error: {0}")]
    FromUtf8Error(#[from] std::string::FromUtf8Error),
    /// Error occurred attempting to manipulate a slice.
    #[error("Slice error: {0}")]
    SliceError(#[from] std::array::TryFromSliceError),
    /// File header lacks the initial `E,X,A,F` bytes.
    #[error("missing magic 'EXAF' number")]
    MissingMagic,
    /// Reached the end of file before reading all of the content.
    #[error("unexpectedly reached end of file")]
    UnexpectedEof,
    /// Version of EXAF not currently supported by this crate.
    #[error("unsupported EXAF version")]
    UnsupportedVersion,
    /// Encountered and entry header that was not recognized.
    #[error("unsupported header format")]
    UnsupportedHeader,
    /// Compression algorithm in archive is not supported.
    #[error("unsupported compression algorithm {0}")]
    UnsupportedCompAlgo(String),
    /// TODO: this will go away
    #[error("unsupported header size")]
    TempUnsupportedHdrSize,
    /// A header was missing a required tag row.
    #[error("missing required tag from header: {0}")]
    MissingTag(String),
}

///
/// Return the last part of the path, converting to a String.
///
fn get_file_name<P: AsRef<Path>>(path: P) -> String {
    // ignore any paths that end in '..'
    if let Some(p) = path.as_ref().file_name() {
        // ignore any paths that failed UTF-8 translation
        if let Some(pp) = p.to_str() {
            return pp.to_owned();
        }
    }
    // normal conversion failed, return whatever garbage is there
    path.as_ref().to_string_lossy().into_owned()
}

///
/// Read the symbolic link value and convert to raw bytes.
///
fn read_link(path: &Path) -> Result<Vec<u8>, Error> {
    // convert whatever value returned by the OS into raw bytes without string conversion
    use os_str_bytes::OsStringBytes;
    let value = fs::read_link(path)?;
    Ok(value.into_os_string().into_raw_vec())
}

///
/// Return the Unix file mode for the given path.
///
#[cfg(target_family = "unix")]
pub fn unix_mode<P: AsRef<Path>>(path: P) -> Option<u32> {
    use std::os::unix::fs::MetadataExt;
    if let Ok(meta) = fs::symlink_metadata(path) {
        Some(meta.mode())
    } else {
        None
    }
}

#[cfg(target_family = "windows")]
pub fn unix_mode<P: AsRef<Path>>(_path: P) -> Option<u32> {
    None
}

///
/// Return the Windows file attributes for the given path.
///
#[cfg(target_family = "unix")]
pub fn file_attrs<P: AsRef<Path>>(_path: P) -> Option<u32> {
    None
}

#[cfg(target_family = "windows")]
pub fn file_attrs<P: AsRef<Path>>(path: P) -> Option<u32> {
    use std::os::windows::prelude::*;
    if let Ok(meta) = fs::symlink_metadata(path) {
        Some(meta.file_attributes())
    } else {
        None
    }
}

fn get_header_str(rows: &HashMap<u16, Vec<u8>>, key: &u16) -> Result<Option<String>, Error> {
    if let Some(row) = rows.get(key) {
        let s = String::from_utf8(row.to_owned())?;
        Ok(Some(s))
    } else {
        Ok(None)
    }
}

#[allow(dead_code)]
fn get_header_u16(rows: &HashMap<u16, Vec<u8>>, key: &u16) -> Result<Option<u16>, Error> {
    if let Some(row) = rows.get(key) {
        let raw: [u8; 2] = row[0..2].try_into()?;
        let v = u16::from_be_bytes(raw);
        Ok(Some(v))
    } else {
        Ok(None)
    }
}

fn get_header_u32(rows: &HashMap<u16, Vec<u8>>, key: &u16) -> Result<Option<u32>, Error> {
    if let Some(row) = rows.get(key) {
        let raw: [u8; 4] = row[0..4].try_into()?;
        let v = u32::from_be_bytes(raw);
        Ok(Some(v))
    } else {
        Ok(None)
    }
}

fn get_header_u64(rows: &HashMap<u16, Vec<u8>>, key: &u16) -> Result<Option<u64>, Error> {
    if let Some(row) = rows.get(key) {
        let raw: [u8; 8] = row[0..8].try_into()?;
        let v = u64::from_be_bytes(raw);
        Ok(Some(v))
    } else {
        Ok(None)
    }
}

fn get_header_time(
    rows: &HashMap<u16, Vec<u8>>,
    key: &u16,
) -> Result<Option<DateTime<Utc>>, Error> {
    if let Some(row) = rows.get(key) {
        let raw: [u8; 8] = row[0..8].try_into()?;
        let secs = i64::from_be_bytes(raw);
        Ok(DateTime::from_timestamp(secs, 0))
    } else {
        Ok(None)
    }
}

fn get_header_bytes(rows: &HashMap<u16, Vec<u8>>, key: &u16) -> Result<Option<Vec<u8>>, Error> {
    if let Some(row) = rows.get(key) {
        Ok(Some(row.to_owned()))
    } else {
        Ok(None)
    }
}

/// A file, directory, or symbolic link within a tree.
#[derive(Clone, Debug)]
pub struct EntryMetadata {
    /// Name of the file, directory, or symbolic link.
    pub name: String,
    /// Unix file mode of the entry.
    pub mode: Option<u32>,
    /// Windows file attributes of the entry.
    pub attrs: Option<u32>,
    /// Unix user identifier
    pub uid: Option<u32>,
    /// Name of the owning user.
    pub user: Option<String>,
    /// Unix group identifier
    pub gid: Option<u32>,
    /// Name of the owning group.
    pub group: Option<String>,
    /// Created time of the entry.
    pub ctime: Option<DateTime<Utc>>,
    /// Modification time of the entry.
    pub mtime: Option<DateTime<Utc>>,
    /// Accessed time of the entry.
    pub atime: Option<DateTime<Utc>>,
    // Set of extended file attributes, if any. The key is the name of the
    // extended attribute, and the value is the raw data from the file system.
    pub xattrs: Option<HashMap<String, Vec<u8>>>,
}

impl EntryMetadata {
    ///
    /// Create an instance of `EntryMetadata` based on the given path.
    ///
    pub fn new<P: AsRef<Path>>(path: P) -> Self {
        let name = get_file_name(path.as_ref());
        let metadata = fs::symlink_metadata(path.as_ref());
        let mtime = match metadata.as_ref() {
            Ok(attr) => {
                let mt = attr.modified().unwrap_or(SystemTime::UNIX_EPOCH);
                Some(DateTime::<Utc>::from(mt))
            }
            Err(_) => None,
        };
        let ctime = match metadata.as_ref() {
            Ok(attr) => {
                let ct = attr.created().unwrap_or(SystemTime::UNIX_EPOCH);
                Some(DateTime::<Utc>::from(ct))
            }
            Err(_) => None,
        };
        let atime = match metadata.as_ref() {
            Ok(attr) => {
                let at = attr.accessed().unwrap_or(SystemTime::UNIX_EPOCH);
                Some(DateTime::<Utc>::from(at))
            }
            Err(_) => None,
        };
        let mode = unix_mode(path.as_ref());
        let attrs = file_attrs(path.as_ref());
        let em = Self {
            name,
            mode,
            attrs,
            uid: None,
            gid: None,
            user: None,
            group: None,
            ctime,
            mtime,
            atime,
            xattrs: None,
        };
        em.owners(path.as_ref())
    }

    ///
    /// Construct metadata from the map of tags and values.
    ///
    pub fn from_map(rows: &HashMap<u16, Vec<u8>>) -> Result<Self, Error> {
        let name = get_header_str(rows, &0x4e4d)?.ok_or_else(|| Error::MissingTag("NM".into()))?;
        let mode = get_header_u32(rows, &0x4d4f)?;
        let attrs = get_header_u32(rows, &0x4641)?;
        let uid = get_header_u32(rows, &0x5549)?;
        let gid = get_header_u32(rows, &0x4749)?;
        let user = get_header_str(rows, &0x554e)?;
        let group = get_header_str(rows, &0x474e)?;
        let ctime = get_header_time(rows, &0x4354)?;
        let mtime = get_header_time(rows, &0x4d54)?;
        let atime = get_header_time(rows, &0x4154)?;
        // TODO: extract the extended attributes map
        Ok(Self {
            name,
            mode,
            attrs,
            uid,
            gid,
            user,
            group,
            ctime,
            mtime,
            atime,
            xattrs: None,
        })
    }

    ///
    /// Set the user and group ownership of the given path.
    ///
    #[cfg(target_family = "unix")]
    pub fn owners<P: AsRef<Path>>(mut self, path: P) -> Self {
        use std::ffi::CStr;
        use std::os::unix::fs::MetadataExt;
        if let Ok(meta) = fs::symlink_metadata(path) {
            self.uid = Some(meta.uid());
            self.gid = Some(meta.gid());
            // get the user name
            let username: String = unsafe {
                let passwd = libc::getpwuid(meta.uid());
                if passwd.is_null() {
                    String::new()
                } else {
                    let c_buf = (*passwd).pw_name;
                    if c_buf.is_null() {
                        String::new()
                    } else {
                        CStr::from_ptr(c_buf).to_string_lossy().into_owned()
                    }
                }
            };
            self.user = Some(username);
            // get the group name
            let groupname = unsafe {
                let group = libc::getgrgid(meta.gid());
                if group.is_null() {
                    String::new()
                } else {
                    let c_buf = (*group).gr_name;
                    if c_buf.is_null() {
                        String::new()
                    } else {
                        CStr::from_ptr(c_buf).to_string_lossy().into_owned()
                    }
                }
            };
            self.group = Some(groupname);
        }
        self
    }

    #[cfg(target_family = "windows")]
    pub fn owners(self, _path: &Path) -> Self {
        self
    }
}

///
/// A `FileEntry` represents a file in the archive.
///
#[allow(dead_code)]
#[derive(Clone, Debug)]
pub struct FileEntry {
    /// Metadata originally gathered from the file system.
    metadata: EntryMetadata,
    /// Identifier of directory in which this file resides.
    directory: Option<u32>,
    /// Original byte size of the file.
    original_len: u64,
    /// Compressed byte size of the file data in the archive.
    compressed_len: Option<u64>,
    /// The compression algorithm that was used (e.g. 'LZMA').
    comp_algo: Option<String>,
    /// The hash digest algorithm used to compute the `checksum` (e.g. 'SHA1').
    hash_algo: Option<String>,
    /// The hash digest of the original file contents.
    checksum: Option<Vec<u8>>,
}

impl FileEntry {
    ///
    /// Create an instance of `FileEntry` based on the given path.
    ///
    pub fn new<P: AsRef<Path>>(path: P, directory: Option<u32>) -> Self {
        let metadata = EntryMetadata::new(path.as_ref());
        let md = fs::symlink_metadata(path.as_ref());
        let original_len = match md.as_ref() {
            Ok(attr) => attr.len(),
            Err(_) => 0,
        };
        Self {
            metadata,
            directory,
            original_len,
            compressed_len: None,
            comp_algo: None,
            hash_algo: None,
            checksum: None,
        }
    }

    ///
    /// Construct a file entry from the map of tags and values.
    ///
    pub fn from_map(rows: &HashMap<u16, Vec<u8>>) -> Result<Self, Error> {
        let metadata = EntryMetadata::from_map(&rows)?;
        let original_len =
            get_header_u64(rows, &0x535a)?.ok_or_else(|| Error::MissingTag("SZ".into()))?;
        let directory = get_header_u32(rows, &0x4449)?;
        let compressed_len = get_header_u64(rows, &0x4c4e)?;
        let comp_algo = get_header_str(rows, &0x4341)?;
        let hash_algo = get_header_str(rows, &0x4841)?;
        let checksum = get_header_bytes(rows, &0x4353)?;
        Ok(Self {
            metadata,
            directory,
            original_len,
            compressed_len,
            comp_algo,
            hash_algo,
            checksum,
        })
    }

    ///
    /// Compute the SHA1 hash digest of the given path and set the `hash_algo`
    /// and `checksum` properties.
    ///
    pub fn compute_sha1<P: AsRef<Path>>(mut self, path: P) -> io::Result<Self> {
        use sha1::{Digest, Sha1};
        let mut file = fs::File::open(path)?;
        let mut hasher = Sha1::new();
        io::copy(&mut file, &mut hasher)?;
        let digest = hasher.finalize();
        self.checksum = Some(digest.as_slice().to_owned());
        self.hash_algo = Some("SHA1".into());
        Ok(self)
    }
}

///
/// A `DirectoryEntry` represents a directory within the archive.
///
#[derive(Clone, Debug)]
pub struct DirectoryEntry {
    /// Metadata originally gathered from the file system.
    metadata: EntryMetadata,
    /// Unique identifier that may be assigned to files in the archive.
    identifier: u32,
    /// Leading path to this directory.
    parent_path: Option<String>,
}

impl DirectoryEntry {
    ///
    /// Create an instance of `DirectoryEntry` based on the given path.
    ///
    pub fn new<P: AsRef<Path>>(path: P, identifier: u32) -> Self {
        let metadata = EntryMetadata::new(path.as_ref());
        let parent_path = path
            .as_ref()
            .parent()
            .map(|p| p.to_string_lossy().into_owned());
        Self {
            metadata,
            identifier,
            parent_path,
        }
    }

    ///
    /// Construct a directory entry from the map of tags and values.
    ///
    pub fn from_map(rows: &HashMap<u16, Vec<u8>>) -> Result<Self, Error> {
        let metadata = EntryMetadata::from_map(&rows)?;
        let identifier =
            get_header_u32(rows, &0x4944)?.ok_or_else(|| Error::MissingTag("ID".into()))?;
        let parent_path = get_header_str(rows, &0x5041)?;
        Ok(Self {
            metadata,
            identifier,
            parent_path,
        })
    }
}

#[derive(PartialEq)]
enum Kind {
    File,
    Link,
}

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

// Desired size of the compressed bundle of file data.
const BUNDLE_SIZE: u64 = 16777216;

///
/// Creates or updates an archive.
///
struct PackBuilder<W: Write + Seek> {
    // output to which archive will be written
    output: W,
    // identifier of the most recent directory entry
    prev_dir_id: u32,
    // directories to be written in the pending manifest
    directories: Vec<DirectoryEntry>,
    // identifier of the most recent file entry
    prev_file_id: u32,
    // files to be written, at least partially, in the pending manifest; the key is
    // a numeric identifier that is unique to this archive
    files: HashMap<u32, FileEntry>,
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
    fn new(mut output: W) -> Result<Self, Error> {
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
    fn add_dir_all<P: AsRef<Path>>(&mut self, basepath: P) -> Result<u64, Error> {
        let mut file_count: u64 = 0;
        let mut subdirs: Vec<(u32, PathBuf)> = Vec::new();
        subdirs.push((self.prev_dir_id, basepath.as_ref().to_path_buf()));
        while let Some((mut dir_id, currdir)) = subdirs.pop() {
            dir_id = self.add_directory(&currdir)?;
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
    fn finish(&mut self) -> Result<(), Error> {
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
    fn add_directory<P: AsRef<Path>>(&mut self, path: P) -> Result<u32, Error> {
        self.prev_dir_id += 1;
        let dir_entry = DirectoryEntry::new(path, self.prev_dir_id);
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
    fn add_file<P: AsRef<Path>>(&mut self, path: P, parent: Option<u32>) -> Result<(), Error> {
        self.prev_file_id += 1;
        let file_entry = FileEntry::new(path.as_ref(), parent);
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
    fn add_symlink<P: AsRef<Path>>(&mut self, _path: P, _parent: Option<u32>) -> Result<(), Error> {
        // let name = get_file_name(path.as_ref());
        // self.conn.execute(
        //     "INSERT INTO item (parent, kind, name) VALUES (?1, ?2, ?3)",
        //     (&parent, KIND_SYMLINK, &name),
        // )?;
        // let item_id = self.conn.last_insert_rowid();
        // let md = fs::symlink_metadata(path.as_ref());
        // let link_len = match md.as_ref() {
        //     Ok(attr) => attr.len(),
        //     Err(_) => 0,
        // };
        // // assume that the link value is relatively small and simply add it into
        // // the current content bundle in whole
        // let content = IncomingContent {
        //     path: path.as_ref().to_path_buf(),
        //     kind: KIND_SYMLINK,
        //     item: item_id,
        //     itempos: 0,
        //     contentpos: self.current_pos,
        //     size: link_len,
        // };
        // self.contents.push(content);
        // self.current_pos += link_len;
        // Ok(item_id)
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
        // small data sets this makes no observable difference, but for any
        // large data set (e.g. Linux kernel), it makes a huge difference.
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
        let header = make_manifest_header(num_entries, content.len())?;
        write_entry_header(&header, &mut self.output)?;

        // write all of the directory entries to the output
        for dir_entry in self.directories.iter() {
            let header = make_dir_header(&dir_entry)?;
            write_entry_header(&header, &mut self.output)?;
        }

        // serialize item contents, and their corresponding file entries, as a
        // single unit
        for content in self.contents.iter() {
            let file_entry = self
                .files
                .get(&content.file_id)
                .expect("internal error, missing file entry for item content");
            let mut fheader = make_file_header(&file_entry)?;
            let mut cheader = make_content_header(&content)?;
            fheader.append(&mut cheader);
            write_entry_header(&fheader, &mut self.output)?;
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

fn make_manifest_header(num_entries: u16, block_size: usize) -> Result<Vec<u8>, Error> {
    let mut header: Vec<u8> = Vec::new();

    // NE: number (of) entries
    header.write_all(&[b'N', b'E', 0, 2])?;
    let num_entries_raw = u16::to_be_bytes(num_entries);
    header.write_all(&num_entries_raw)?;

    // CA: compression algorithm (0 for copy, 1 for zstd)
    header.write_all(&[b'C', b'A', 0, 1, 1])?;

    // BS: block size (never larger than 2^32 bytes)
    header.write_all(&[b'B', b'S', 0, 4])?;
    let block_size_raw = u32::to_be_bytes(block_size as u32);
    header.write_all(&block_size_raw)?;

    Ok(header)
}

fn make_dir_header(dir_entry: &DirectoryEntry) -> io::Result<Vec<u8>> {
    let mut header: Vec<u8> = Vec::new();

    // ID: unique identifier
    header.write_all(&[b'I', b'D', 0, 4])?;
    let dir_id = u32::to_be_bytes(dir_entry.identifier);
    header.write_all(&dir_id)?;

    // NM: file name
    header.write_all(&[b'N', b'M'])?;
    let name = dir_entry.metadata.name.as_bytes();
    let name_len = u16::to_be_bytes(name.len() as u16);
    header.write_all(&name_len)?;
    header.write_all(name)?;

    // PA: parent path, if available
    if let Some(ref parent) = dir_entry.parent_path {
        let path = PathBuf::from(parent).to_string_lossy().into_owned();
        let path_bytes = path.as_bytes();
        header.write_all(&[b'P', b'A'])?;
        let path_len = u16::to_be_bytes(path_bytes.len() as u16);
        header.write_all(&path_len)?;
        header.write_all(path_bytes)?;
    }

    // MO: Unix file mode, if available
    if let Some(mode) = dir_entry.metadata.mode {
        header.write_all(&[b'M', b'O', 0, 4])?;
        let unix_mode = u32::to_be_bytes(mode);
        header.write_all(&unix_mode)?;
    }

    // FA: Windows file attributes, if available
    if let Some(attrs) = dir_entry.metadata.attrs {
        header.write_all(&[b'F', b'A', 0, 4])?;
        let file_attrs = u32::to_be_bytes(attrs);
        header.write_all(&file_attrs)?;
    }

    // MT: modified time, if available
    if let Some(mt) = dir_entry.metadata.mtime {
        header.write_all(&[b'M', b'T', 0, 8])?;
        let unix_time = i64::to_be_bytes(mt.timestamp());
        header.write_all(&unix_time)?;
    }

    // CT: creation time, if available
    if let Some(ct) = dir_entry.metadata.ctime {
        header.write_all(&[b'C', b'T', 0, 8])?;
        let unix_time = i64::to_be_bytes(ct.timestamp());
        header.write_all(&unix_time)?;
    }

    // AT: last accessed time, if available
    if let Some(at) = dir_entry.metadata.atime {
        header.write_all(&[b'A', b'T', 0, 8])?;
        let unix_time = i64::to_be_bytes(at.timestamp());
        header.write_all(&unix_time)?;
    }

    // TODO: write XA

    // UN: user name, if available
    if let Some(ref username) = dir_entry.metadata.user {
        header.write_all(&[b'U', b'N'])?;
        let name_len = u16::to_be_bytes(username.len() as u16);
        header.write_all(&name_len)?;
        header.write_all(username.as_bytes())?;
    }

    // GN: group name, if available
    if let Some(ref groupname) = dir_entry.metadata.group {
        header.write_all(&[b'G', b'N'])?;
        let name_len = u16::to_be_bytes(groupname.len() as u16);
        header.write_all(&name_len)?;
        header.write_all(groupname.as_bytes())?;
    }

    // UI: user identifier, if available
    if let Some(uid) = dir_entry.metadata.uid {
        header.write_all(&[b'U', b'I', 0, 4])?;
        let uid_be = u32::to_be_bytes(uid);
        header.write_all(&uid_be)?;
    }

    // GI: group identifier, if available
    if let Some(gid) = dir_entry.metadata.gid {
        header.write_all(&[b'G', b'I', 0, 4])?;
        let gid_be = u32::to_be_bytes(gid);
        header.write_all(&gid_be)?;
    }
    Ok(header)
}

fn make_file_header(file_entry: &FileEntry) -> io::Result<Vec<u8>> {
    // build out the header data piece by piece
    let mut header: Vec<u8> = Vec::new();

    // NM: file name
    header.write_all(&[b'N', b'M'])?;
    let name = file_entry.metadata.name.as_bytes();
    let name_len = u16::to_be_bytes(name.len() as u16);
    header.write_all(&name_len)?;
    header.write_all(name)?;

    // SZ: original file size
    header.write_all(&[b'S', b'Z', 0, 8])?;
    let orig_len = u64::to_be_bytes(file_entry.original_len);
    header.write_all(&orig_len)?;

    // MO: Unix file mode, if available
    if let Some(mode) = file_entry.metadata.mode {
        header.write_all(&[b'M', b'O', 0, 4])?;
        let unix_mode = u32::to_be_bytes(mode);
        header.write_all(&unix_mode)?;
    }

    // FA: Windows file attributes, if available
    if let Some(attrs) = file_entry.metadata.attrs {
        header.write_all(&[b'F', b'A', 0, 4])?;
        let file_attrs = u32::to_be_bytes(attrs);
        header.write_all(&file_attrs)?;
    }

    // HA: hash digest algorithm
    if let Some(algo) = file_entry.hash_algo.as_ref() {
        header.write_all(&[b'H', b'A', 0, 4])?;
        let algo_bytes = algo.as_bytes();
        header.write_all(&algo_bytes)?;
    }

    // CS: hash digest value
    if let Some(checksum) = file_entry.checksum.as_ref() {
        header.write_all(&[b'C', b'S'])?;
        let cs_len = u16::to_be_bytes(checksum.len() as u16);
        header.write_all(&cs_len)?;
        header.write_all(checksum.as_slice())?;
    }

    // DI: directory identifier, if available
    if let Some(di) = file_entry.directory {
        header.write_all(&[b'D', b'I', 0, 4])?;
        let dir_id = u32::to_be_bytes(di);
        header.write_all(&dir_id)?;
    }

    // MT: modified time, if available
    if let Some(mt) = file_entry.metadata.mtime {
        header.write_all(&[b'M', b'T', 0, 8])?;
        let unix_time = i64::to_be_bytes(mt.timestamp());
        header.write_all(&unix_time)?;
    }

    // CT: creation time, if available
    if let Some(ct) = file_entry.metadata.ctime {
        header.write_all(&[b'C', b'T', 0, 8])?;
        let unix_time = i64::to_be_bytes(ct.timestamp());
        header.write_all(&unix_time)?;
    }

    // AT: last accessed time, if available
    if let Some(at) = file_entry.metadata.atime {
        header.write_all(&[b'A', b'T', 0, 8])?;
        let unix_time = i64::to_be_bytes(at.timestamp());
        header.write_all(&unix_time)?;
    }

    // TODO: write XA

    // UN: user name, if available
    if let Some(ref username) = file_entry.metadata.user {
        header.write_all(&[b'U', b'N'])?;
        let name_len = u16::to_be_bytes(username.len() as u16);
        header.write_all(&name_len)?;
        header.write_all(username.as_bytes())?;
    }

    // GN: group name, if available
    if let Some(ref groupname) = file_entry.metadata.group {
        header.write_all(&[b'G', b'N'])?;
        let name_len = u16::to_be_bytes(groupname.len() as u16);
        header.write_all(&name_len)?;
        header.write_all(groupname.as_bytes())?;
    }

    // UI: user identifier, if available
    if let Some(uid) = file_entry.metadata.uid {
        header.write_all(&[b'U', b'I', 0, 4])?;
        let uid_be = u32::to_be_bytes(uid);
        header.write_all(&uid_be)?;
    }

    // GI: group identifier, if available
    if let Some(gid) = file_entry.metadata.gid {
        header.write_all(&[b'G', b'I', 0, 4])?;
        let gid_be = u32::to_be_bytes(gid);
        header.write_all(&gid_be)?;
    }
    Ok(header)
}

fn make_content_header(item_content: &IncomingContent) -> io::Result<Vec<u8>> {
    // build out the header data piece by piece
    let mut header: Vec<u8> = Vec::new();

    // IP: item position (up to 64 bits)
    header.write_all(&[b'I', b'P', 0, 8])?;
    let itempos = u64::to_be_bytes(item_content.itempos);
    header.write_all(&itempos)?;

    // CP: content position (never more than 32 bits)
    header.write_all(&[b'C', b'P', 0, 4])?;
    let content_pos = u32::to_be_bytes(item_content.contentpos as u32);
    header.write_all(&content_pos)?;
    // size: u64,

    // SZ: size of content (never more than 32 bits)
    header.write_all(&[b'S', b'Z', 0, 4])?;
    let size = u32::to_be_bytes(item_content.size as u32);
    header.write_all(&size)?;

    Ok(header)
}

fn write_entry_header<W: Write>(header: &[u8], mut output: W) -> io::Result<()> {
    // write the fully realized header to the output
    let header_len = u16::to_be_bytes(header.len() as u16);
    output.write_all(&header_len)?;
    output.write_all(&header)?;
    Ok(())
}

// TODO: turn this into a factory method that will construct a pack reader
// TODO: version 1 pack reader will then read the optional header fields into a map
// TODO: pack reader will take ownership of the input File
#[allow(dead_code)]
fn read_archive_header<P: AsRef<Path>>(infile: P) -> Result<File, Error> {
    let mut input = File::open(infile)?;
    let mut archive_start = [0; 8];
    input.read_exact(&mut archive_start)?;
    if archive_start[0..4] != [b'E', b'X', b'A', b'F'] {
        return Err(Error::MissingMagic);
    }
    if archive_start[4..6] != [1, 0] {
        return Err(Error::UnsupportedVersion);
    }
    // TODO: read the remaining header size, then skip that many bytes
    if archive_start[6..8] != [0, 0] {
        return Err(Error::TempUnsupportedHdrSize);
    }
    Ok(input)
}

#[allow(dead_code)]
fn list_entries<R: BufRead + Seek>(mut input: R) -> Result<(), Error> {
    // loop until the end of the file is reached
    loop {
        // read next 2 bytes as header size
        let mut header_size = [0; 2];
        match input.read_exact(&mut header_size) {
            Ok(()) => {
                let size = u16::from_be_bytes(header_size);
                // read those number of bytes as a header
                let mut header: Vec<u8> = Vec::new();
                let mut chunk = input.take(size as u64);
                let n = chunk.read_to_end(&mut header)?;
                if n != size as usize {
                    return Err(Error::UnexpectedEof);
                }
                // parse header rows into a HashMap
                let mut rows: HashMap<u16, Vec<u8>> = HashMap::new();
                let mut index: usize = 0;
                while index < header.len() {
                    let tag = u16::from_be_bytes([header[index], header[index + 1]]);
                    let len = u16::from_be_bytes([header[index + 2], header[index + 3]]) as usize;
                    let value: Vec<u8> = Vec::from(&header[index + 4..index + 4 + len]);
                    rows.insert(tag, value);
                    index += 4 + len;
                }
                input = chunk.into_inner();
                if rows.contains_key(&0x4944) {
                    // create a DirectoryEntry from the supported tags in the HashMap
                    let entry = DirectoryEntry::from_map(&rows)?;
                    println!("directory: {:?}", entry.metadata.name);
                } else if rows.contains_key(&0x535a) {
                    // create a FileEntry from the supported tags in the HashMap
                    let entry = FileEntry::from_map(&rows)?;
                    println!("file: {:?}", entry.metadata.name);

                    // TODO: skip over file content temporarily
                    let pos: i64 = if let Some(clen) = entry.compressed_len {
                        clen
                    } else {
                        entry.original_len
                    } as i64;
                    input.seek(SeekFrom::Current(pos))?;

                    // read the file data, decompressing as needed, print to stdout
                    // let mut chunk = if let Some(clen) = entry.compressed_len {
                    //     input.take(clen)
                    // } else {
                    //     input.take(entry.original_len)
                    // };
                    // if let Some(algo) = entry.comp_algo {
                    //     if algo == "zstd" {
                    //         if dict.is_empty() {
                    //             zstd::stream::copy_decode(&mut chunk, io::stdout())?;
                    //         } else {
                    //             let mut decoder =
                    //                 zstd::stream::read::Decoder::with_dictionary(&mut chunk, dict)?;
                    //             let mut out = io::stdout();
                    //             io::copy(&mut decoder, &mut out)?;
                    //         }
                    //     } else {
                    //         return Err(Error::UnsupportedCompAlgo(algo));
                    //     }
                    // } else {
                    //     let mut out = io::stdout();
                    //     io::copy(&mut chunk, &mut out)?;
                    // }
                    // input = chunk.into_inner();
                } else {
                    return Err(Error::UnsupportedHeader);
                }
            }
            Err(err) => {
                if err.kind() == ErrorKind::UnexpectedEof {
                    return Ok(());
                }
                return Err(Error::from(err));
            }
        }
    }
}

///
/// Create a pack file at the given location and add all of the named inputs.
///
/// Returns the total number of files added to the archive.
///
fn create_archive<P: AsRef<Path>>(archive: P, inputs: Vec<&PathBuf>) -> Result<u64, Error> {
    let path_ref = archive.as_ref();
    let path = match path_ref.extension() {
        Some(_) => path_ref.to_path_buf(),
        None => path_ref.with_extension("exa"),
    };
    let output = File::create(path)?;
    let mut builder = PackBuilder::new(output)?;
    let mut file_count: u64 = 0;
    for input in inputs {
        let metadata = input.metadata()?;
        if metadata.is_dir() {
            file_count += builder.add_dir_all(input)?;
        } else if metadata.is_file() {
            builder.add_file(input, None)?;
            file_count += 1;
        }
    }
    builder.finish()?;
    Ok(file_count)
}

///
/// List all file entries in the archive in breadth-first order.
///
fn list_contents(_archive: &str) -> Result<(), Error> {
    // if !pack_rs::is_pack_file(archive)? {
    //     return Err(Error::NotPackFile);
    // }
    // let reader = PackReader::new(archive)?;
    // let entries = reader.entries()?;
    // for result in entries {
    //     let entry = result?;
    //     if entry.kind != KIND_DIRECTORY {
    //         println!("{}", entry.name)
    //     }
    // }
    Ok(())
}

///
/// Extract all of the files from the archive.
///
fn extract_contents(_archive: &str) -> Result<u64, Error> {
    // if !pack_rs::is_pack_file(archive)? {
    //     return Err(Error::NotPackFile);
    // }
    // let reader = PackReader::new(archive)?;
    // let file_count = reader.extract_all()?;
    // Ok(file_count)
    Ok(0)
}

fn cli() -> Command {
    Command::new("exaf-rs")
        .about("Archiver/compressor")
        .subcommand_required(true)
        .arg_required_else_help(true)
        .subcommand(
            Command::new("create")
                .about("Creates an archive from a set of files.")
                .short_flag('c')
                .arg(arg!(archive: <ARCHIVE> "File path to which the archive will be written."))
                .arg(
                    arg!(<INPUTS> ... "Files to add to archive")
                        .value_parser(clap::value_parser!(PathBuf)),
                )
                .arg_required_else_help(true),
        )
        .subcommand(
            Command::new("list")
                .about("Lists the contents of an archive.")
                .short_flag('l')
                .arg(arg!(archive: <ARCHIVE> "File path specifying the archive to read from."))
                .arg_required_else_help(true),
        )
        .subcommand(
            Command::new("extract")
                .about("Extracts one or more files from an archive.")
                .short_flag('x')
                .arg(arg!(archive: <ARCHIVE> "File path specifying the archive to read from."))
                .arg_required_else_help(true),
        )
}

fn main() -> Result<(), Error> {
    let matches = cli().get_matches();
    match matches.subcommand() {
        Some(("create", sub_matches)) => {
            let archive = sub_matches
                .get_one::<String>("archive")
                .map(|s| s.as_str())
                .unwrap_or("archive.exa");
            let inputs = sub_matches
                .get_many::<PathBuf>("INPUTS")
                .into_iter()
                .flatten()
                .collect::<Vec<_>>();
            let file_count = create_archive(archive, inputs)?;
            println!("Added {} files to {}", file_count, archive);
        }
        Some(("list", sub_matches)) => {
            let archive = sub_matches
                .get_one::<String>("archive")
                .map(|s| s.as_str())
                .unwrap_or("archive.exa");
            list_contents(archive)?;
        }
        Some(("extract", sub_matches)) => {
            let archive = sub_matches
                .get_one::<String>("archive")
                .map(|s| s.as_str())
                .unwrap_or("archive.exa");
            let file_count = extract_contents(archive)?;
            println!("Extracted {} files from {}", file_count, archive)
        }
        _ => unreachable!(),
    }
    Ok(())
}
