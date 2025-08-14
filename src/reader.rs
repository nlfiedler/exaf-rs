//
// Copyright (c) 2024 Nathan Fiedler
//

//!
//! Read an archive, decrypting and decompressing as needed.
//!
//! The `reader` module provides the functions needed to read an archive which
//! may have optional encryption enabled. The `Entries` iterator provides a
//! simple means of examining all of the entries contained in the archive.
//!
//! To extract the contents of the archive, use the `extract_all()` function of
//! the `Reader` implementation.
//!

use super::*;
use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::fs::File;
use std::io::{self, ErrorKind, Read, Seek, SeekFrom};
use std::path::Path;

//
// Concerning the versioned reader API, it seems like a good idea but it has not
// been fleshed out yet, so it looks incomplete at the moment.
//

///
/// A reader of the EXAF format for one version or another.
///
trait VersionedReader {
    // Read the header starting at the current position.
    fn read_next_header(&mut self) -> Result<HeaderMap, Error>;

    // Skip some content in the input stream (such as compressed content).
    #[allow(dead_code)]
    fn skip_n_bytes(&mut self, skip: u32) -> Result<(), Error>;

    // Read the given number of bytes into a new vector.
    fn read_n_bytes(&mut self, count: u64) -> Result<Vec<u8>, Error>;
}

//
// Helper for building up the full path for entries in the archive.
//
struct PathBuilder {
    // directories encountered so far; key is ID, value is (PA, NM)
    // (if PA is zero, the entry is at the root of the tree)
    parents: HashMap<u32, (u32, String)>,
    // full paths of the directory with the given identifier; built lazily when
    // get_full_path() is called
    full_paths: HashMap<u32, PathBuf>,
}

impl PathBuilder {
    fn new() -> Self {
        Self {
            parents: HashMap::new(),
            full_paths: HashMap::new(),
        }
    }

    // insert a mapping for the given directory to its parent
    fn insert<S: Into<String>>(&mut self, dir_id: u32, parent: u32, name: S) {
        self.parents.insert(dir_id, (parent, name.into()));
    }

    // follow the parent chain to build up a path
    fn get_full_path(&mut self, mut parent: u32) -> Result<PathBuf, Error> {
        let fullpath = if let Some(cached_path) = self.full_paths.get(&parent) {
            cached_path.to_owned()
        } else {
            let mut paths: Vec<String> = vec![];
            let entry_parent = parent;
            while parent != 0 {
                if let Some(pair) = self.parents.get(&parent) {
                    parent = pair.0;
                    paths.push(pair.1.clone());
                } else {
                    return Err(Error::MissingParent(parent));
                }
            }
            let mut fullpath: PathBuf = PathBuf::new();
            while let Some(path) = paths.pop() {
                fullpath = fullpath.join(path);
            }
            self.full_paths.insert(entry_parent, fullpath.clone());
            fullpath
        };
        Ok(fullpath)
    }
}

// describes a file/link that will be extracted from the content block
#[derive(Debug)]
struct OutboundContent {
    // offset within the content for this chunk of file
    contentpos: u64,
    // offset within the file where this chunk belongs
    itempos: u64,
    // size of the file chunk
    size: u64,
    // content is either for a file or symbolic link
    kind: Kind,
}

impl TryFrom<HeaderMap> for OutboundContent {
    type Error = super::Error;

    fn try_from(value: HeaderMap) -> Result<Self, Self::Error> {
        let kind: Kind = if get_header_str(&value, &TAG_NAME)?.is_some() {
            Kind::File
        } else if get_header_str(&value, &TAG_SYM_LINK)?.is_some() {
            Kind::Link
        } else {
            return Err(Error::MissingTag("NM or SL".into()));
        };
        let contentpos = get_header_u32(&value, &TAG_CONTENT_POS)?
            .ok_or_else(|| Error::MissingTag("CP".into()))?;
        let itempos =
            get_header_u64(&value, &TAG_ITEM_POS)?.ok_or_else(|| Error::MissingTag("IP".into()))?;
        let size = get_header_u32(&value, &TAG_ITEM_SIZE)?
            .ok_or_else(|| Error::MissingTag("SZ".into()))?;
        Ok(Self {
            contentpos: contentpos as u64,
            itempos,
            size: size as u64,
            kind,
        })
    }
}

/// Raw header rows consisting of the tags and values without interpretation.
type HeaderMap = HashMap<u16, Vec<u8>>;

// Read a complete header from the stream.
fn read_header<R: Read>(mut input: R) -> Result<HeaderMap, Error> {
    let mut rows: HeaderMap = HashMap::new();
    // read in the number of rows in this header
    let mut row_count_bytes = [0; 2];
    input.read_exact(&mut row_count_bytes)?;
    let row_count = u16::from_be_bytes(row_count_bytes);
    // read that many tag/size/value tuples into the map
    for _ in 0..row_count {
        // read tag bytes, convert to u16
        let mut tag_bytes = [0; 2];
        input.read_exact(&mut tag_bytes)?;
        let tag = u16::from_be_bytes(tag_bytes);
        // read size bytes, convert to u16
        let mut size_bytes = [0; 2];
        input.read_exact(&mut size_bytes)?;
        let size = u16::from_be_bytes(size_bytes);
        // read N bytes into a Vec<u8>
        let mut chunk = input.take(size as u64);
        let mut value: Vec<u8> = vec![];
        chunk.read_to_end(&mut value)?;
        input = chunk.into_inner();
        rows.insert(tag, value);
    }
    Ok(rows)
}

fn get_header_str(rows: &HeaderMap, key: &u16) -> Result<Option<String>, Error> {
    if let Some(row) = rows.get(key) {
        let s = String::from_utf8(row.to_owned())?;
        Ok(Some(s))
    } else {
        Ok(None)
    }
}

fn get_header_u8(rows: &HeaderMap, key: &u16) -> Result<Option<u8>, Error> {
    if let Some(row) = rows.get(key) {
        Ok(Some(row[0]))
    } else {
        Ok(None)
    }
}

#[allow(dead_code)]
fn pad_to_u16(row: &[u8]) -> [u8; 2] {
    if row.len() == 1 {
        [0, row[0]]
    } else {
        [row[0], row[1]]
    }
}

#[allow(dead_code)]
fn get_header_u16(rows: &HeaderMap, key: &u16) -> Result<Option<u16>, Error> {
    if let Some(row) = rows.get(key) {
        let raw: [u8; 2] = pad_to_u16(row);
        let v = u16::from_be_bytes(raw);
        Ok(Some(v))
    } else {
        Ok(None)
    }
}

fn pad_to_u32(row: &[u8]) -> [u8; 4] {
    if row.len() == 1 {
        [0, 0, 0, row[0]]
    } else if row.len() == 2 {
        [0, 0, row[0], row[1]]
    } else {
        [row[0], row[1], row[2], row[3]]
    }
}

fn get_header_u32(rows: &HeaderMap, key: &u16) -> Result<Option<u32>, Error> {
    if let Some(row) = rows.get(key) {
        let raw: [u8; 4] = pad_to_u32(row);
        let v = u32::from_be_bytes(raw);
        Ok(Some(v))
    } else {
        Ok(None)
    }
}

fn pad_to_u64(row: &[u8]) -> [u8; 8] {
    if row.len() == 1 {
        [0, 0, 0, 0, 0, 0, 0, row[0]]
    } else if row.len() == 2 {
        [0, 0, 0, 0, 0, 0, row[0], row[1]]
    } else if row.len() == 4 {
        [0, 0, 0, 0, row[0], row[1], row[2], row[3]]
    } else {
        [
            row[0], row[1], row[2], row[3], row[4], row[5], row[6], row[7],
        ]
    }
}

fn get_header_u64(rows: &HeaderMap, key: &u16) -> Result<Option<u64>, Error> {
    if let Some(row) = rows.get(key) {
        let raw: [u8; 8] = pad_to_u64(row);
        let v = u64::from_be_bytes(raw);
        Ok(Some(v))
    } else {
        Ok(None)
    }
}

fn get_header_time(rows: &HeaderMap, key: &u16) -> Result<Option<DateTime<Utc>>, Error> {
    if let Some(row) = rows.get(key) {
        if row.len() == 4 {
            let raw: [u8; 4] = row[0..4].try_into()?;
            let secs = i32::from_be_bytes(raw);
            Ok(DateTime::from_timestamp(secs as i64, 0))
        } else {
            let raw: [u8; 8] = row[0..8].try_into()?;
            let secs = i64::from_be_bytes(raw);
            Ok(DateTime::from_timestamp(secs, 0))
        }
    } else {
        Ok(None)
    }
}

fn get_header_bytes(rows: &HeaderMap, key: &u16) -> Result<Option<Vec<u8>>, Error> {
    if let Some(row) = rows.get(key) {
        Ok(Some(row.to_owned()))
    } else {
        Ok(None)
    }
}

///
/// Optional values read from the archive header.
///
struct ArchiveHeader {
    /// Encryption algorithm
    enc_algo: Encryption,
    /// Key derivation algorithm
    key_algo: KeyDerivation,
    /// Salt for deriving the key from a passphrase
    salt: Option<Vec<u8>>,
    /// Number of iterations for key derivation function
    time_cost: Option<u32>,
    /// Number of 1 kb memory blocks for key derivation function
    mem_cost: Option<u32>,
    /// Degree of parallelism for key derivation function
    para_cost: Option<u32>,
    /// Output length for key derivation function
    tag_length: Option<u32>,
}

impl TryFrom<HeaderMap> for ArchiveHeader {
    type Error = super::Error;

    fn try_from(value: HeaderMap) -> Result<Self, Self::Error> {
        let enc_algo = get_header_u8(&value, &TAG_ENC_ALGO)?
            .map_or(Ok(Encryption::None), Encryption::try_from)?;
        let key_algo = get_header_u8(&value, &TAG_KEY_DERIV)?
            .map_or(Ok(KeyDerivation::None), KeyDerivation::try_from)?;
        let salt = get_header_bytes(&value, &TAG_SALT)?;
        let time_cost = get_header_u32(&value, &TAG_TIME_COST)?;
        let mem_cost = get_header_u32(&value, &TAG_MEM_COST)?;
        let para_cost = get_header_u32(&value, &TAG_PARA_COST)?;
        let tag_length = get_header_u32(&value, &TAG_TAG_LENGTH)?;
        Ok(Self {
            enc_algo,
            key_algo,
            salt,
            time_cost,
            mem_cost,
            para_cost,
            tag_length,
        })
    }
}

impl TryFrom<HeaderMap> for Entry {
    type Error = super::Error;

    fn try_from(value: HeaderMap) -> Result<Self, Self::Error> {
        let (is_link, name): (bool, String) = if let Some(nm) = get_header_str(&value, &TAG_NAME)? {
            (false, nm)
        } else if let Some(sl) = get_header_str(&value, &TAG_SYM_LINK)? {
            (true, sl)
        } else {
            return Err(Error::MissingTag("NM or SL".into()));
        };
        let dir_id = get_header_u32(&value, &TAG_DIRECTORY_ID)?;
        let parent = get_header_u32(&value, &TAG_PARENT)?;
        let size = get_header_u64(&value, &TAG_FILE_SIZE)?;
        let mode = get_header_u32(&value, &TAG_UNIX_MODE)?;
        let attrs = get_header_u32(&value, &TAG_FILE_ATTRS)?;
        let uid = get_header_u32(&value, &TAG_USER_ID)?;
        let gid = get_header_u32(&value, &TAG_GROUP_ID)?;
        let user = get_header_str(&value, &TAG_USER_NAME)?;
        let group = get_header_str(&value, &TAG_GROUP_NAME)?;
        let ctime = get_header_time(&value, &TAG_CREATE_TIME)?;
        let mtime = get_header_time(&value, &TAG_MODIFY_TIME)?;
        let atime = get_header_time(&value, &TAG_ACCESS_TIME)?;
        Ok(Self {
            name,
            is_link,
            dir_id,
            parent,
            size,
            mode,
            attrs,
            uid,
            gid,
            user,
            group,
            ctime,
            mtime,
            atime,
        })
    }
}

///
/// Represents the properties related to a content block that holds one or more
/// files (or parts of files).
///
#[derive(Debug)]
struct Manifest {
    /// Number of directory, file, or symbolic links in the content block.
    num_entries: u32,
    /// Compression algorithm for this content block.
    comp_algo: Compression,
    /// Size in bytes of the (compressed) content block.
    block_size: u32,
}

impl fmt::Display for Manifest {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "num_entries: {}, comp_algo: {}, block_size: {}",
            self.num_entries, self.comp_algo, self.block_size
        )
    }
}

impl TryFrom<HeaderMap> for Manifest {
    type Error = super::Error;

    fn try_from(value: HeaderMap) -> Result<Self, Self::Error> {
        let num_entries = get_header_u32(&value, &TAG_NUM_ENTRIES)?
            .ok_or_else(|| Error::MissingTag("NE".into()))?;
        let comp_num =
            get_header_u8(&value, &TAG_COMP_ALGO)?.ok_or_else(|| Error::MissingTag("CA".into()))?;
        let block_size = get_header_u32(&value, &TAG_BLOCK_SIZE)?
            .ok_or_else(|| Error::MissingTag("BS".into()))?;
        let comp_algo = Compression::try_from(comp_num)?;
        Ok(Self {
            num_entries,
            comp_algo,
            block_size,
        })
    }
}

///
/// Parameters related to the subsequent encrypted data.
///
struct Encrypted {
    // nonce, or initialization vector, depending on who you ask
    init_vector: Vec<u8>,
    // size in bytes of the encrypted data following the header
    block_size: u32,
}

impl TryFrom<HeaderMap> for Encrypted {
    type Error = super::Error;

    fn try_from(value: HeaderMap) -> Result<Self, Self::Error> {
        let block_size = get_header_u32(&value, &TAG_ENCRYPTED_SIZE)?
            .ok_or_else(|| Error::MissingTag("ES".into()))?;
        let init_vector = get_header_bytes(&value, &TAG_INIT_VECTOR)?
            .ok_or_else(|| Error::MissingTag("IV".into()))?;
        Ok(Self {
            init_vector,
            block_size,
        })
    }
}

//
// The use of a versioned reader seemed like a good idea but it has not been
// fully realized as yet; for now it's just convenient to use the code in this
// way (that is, the ref cells and boxes and helpful).
//
struct ReaderV1<R: ?Sized> {
    input: RefCell<R>,
}

impl<R: Read> ReaderV1<R> {
    fn new(input: R) -> Self {
        Self {
            input: RefCell::new(input),
        }
    }
}

impl<R: Read + Seek> VersionedReader for ReaderV1<R> {
    fn read_next_header(&mut self) -> Result<HeaderMap, Error> {
        let input = self.input.get_mut();
        read_header(input)
    }

    #[allow(dead_code)]
    fn skip_n_bytes(&mut self, skip: u32) -> Result<(), Error> {
        let input = self.input.get_mut();
        input.seek(SeekFrom::Current(skip as i64))?;
        Ok(())
    }

    fn read_n_bytes(&mut self, count: u64) -> Result<Vec<u8>, Error> {
        let input = self.input.get_mut();
        let mut taker = input.take(count);
        let mut content: Vec<u8> = vec![];
        let bytes_read = taker.read_to_end(&mut content)? as u64;
        if bytes_read != count {
            return Err(Error::UnexpectedEof);
        }
        Ok(content)
    }
}

///
/// Generic archive reader that returns manifest headers, entry headers, and
/// compressed output.
///
/// The caller should check if the archive is encrypted by calling the
/// `is_encrypted()` function, and if it returns `true`, then call
/// `enable_encryption()` with a password provided by the user.
///
pub struct Reader {
    // underlying reader for a specific file format
    reader: Box<dyn VersionedReader>,
    // archive header read from the input data
    header: ArchiveHeader,
    // secret key for encrypting files, if encryption is enabled
    secret_key: Option<Vec<u8>>,
    // number of bytes to read for the block after the manifest (if none, the
    // manifest has not yet been read, or the block has already been read)
    block_size: Option<u32>,
    // buffered content, if any (this includes entries and file content)
    // content: Option<Vec<u8>>,
    content: Option<std::io::Cursor<Vec<u8>>>,
}

impl Reader {
    ///
    /// Create a new Reader with the given versioned reader.
    ///
    fn new(mut input: Box<dyn VersionedReader>) -> Result<Self, Error> {
        let rows = input.read_next_header()?;
        let header = ArchiveHeader::try_from(rows)?;
        Ok(Self {
            reader: input,
            header,
            secret_key: None,
            block_size: None,
            content: None,
        })
    }

    ///
    /// Return `true` if the archive appears to have encrypted content.
    ///
    pub fn is_encrypted(&self) -> bool {
        self.header.key_algo != KeyDerivation::None
    }

    ///
    /// Enable encryption when reading the archive, using the given passphrase.
    ///
    pub fn enable_encryption(&mut self, password: &str) -> Result<(), Error> {
        let kd = self.header.key_algo.clone();
        if let Some(ref salt) = self.header.salt {
            let mut params: KeyDerivationParams = Default::default();
            params = params.time_cost(self.header.time_cost);
            params = params.mem_cost(self.header.mem_cost);
            params = params.para_cost(self.header.para_cost);
            params = params.tag_length(self.header.tag_length);
            self.secret_key = Some(derive_key(&kd, password, salt, &params)?);
            Ok(())
        } else {
            Err(Error::InternalError(
                "called enable_encryption() on plain archive".into(),
            ))
        }
    }

    ///
    /// Extracts all of the entries in the archive to the current directory.
    ///
    pub fn extract_all(&mut self, output_dir: &Path) -> Result<u64, Error> {
        // allocate a large buffer for decompressing content to save time
        let mut buffer: Vec<u8> = Vec::with_capacity(BUNDLE_SIZE as usize);
        let mut path_builder = PathBuilder::new();
        let mut file_count: u64 = 0;
        // loop until the end of the file is reached
        loop {
            // try to read the next manifest header, if any
            match self.read_next_manifest()? {
                Some(manifest) => {
                    // collect all files/links into a list to process them a bit later
                    let mut files: Vec<(OutboundContent, PathBuf)> = vec![];
                    for _ in 0..manifest.num_entries {
                        let entry_rows = self.read_next_entry()?;
                        let entry = Entry::try_from(entry_rows.clone())?;
                        if let Some(dir_id) = entry.dir_id {
                            let entry_parent = entry.parent.unwrap_or(0);
                            path_builder.insert(dir_id, entry_parent, entry.name.clone());
                        }
                        let path = if let Some(parent) = entry.parent {
                            path_builder.get_full_path(parent)?.join(entry.name)
                        } else {
                            PathBuf::from(entry.name)
                        };
                        if entry.dir_id.is_some() {
                            // ensure directories exist, even the empty ones
                            let safe_path = super::sanitize_path(path)?;
                            let fpath = output_dir.to_path_buf().join(safe_path);
                            fs::create_dir_all(&fpath)?;
                        } else {
                            let oc = OutboundContent::try_from(entry_rows.clone())?;
                            files.push((oc, path));
                        }
                    }

                    let mut content = self.read_content()?;
                    if manifest.comp_algo == Compression::ZStandard {
                        zstd::stream::copy_decode(content.as_slice(), &mut buffer)?;
                    } else {
                        // the only remaining option is copy (keep the larger buffer
                        // to optimize memory management)
                        if buffer.len() > content.len() {
                            buffer.append(&mut content);
                        } else {
                            buffer = content;
                        }
                    }

                    // process each of the outbound content elements
                    for (entry, path) in files.iter() {
                        // perform basic sanitization of the path to prevent abuse
                        let safe_path = super::sanitize_path(path)?;
                        let fpath = output_dir.to_path_buf().join(safe_path);
                        if entry.kind == Kind::File {
                            // make sure the file exists and is writable
                            let mut output = fs::OpenOptions::new()
                                .create(true)
                                .append(true)
                                .open(&fpath)?;
                            let file_len = fs::metadata(fpath)?.len();
                            if file_len == 0 {
                                // just created a new file, count it
                                file_count += 1;
                            }
                            // if the file was an empty file, then we are already done
                            if entry.size > 0 {
                                // ensure the file has the appropriate length for writing this
                                // content chunk into the file, extending it if necessary
                                if file_len < entry.itempos {
                                    output.set_len(entry.itempos)?;
                                }
                                // seek to the correct position within the file for this chunk
                                if entry.itempos > 0 {
                                    output.seek(SeekFrom::Start(entry.itempos))?;
                                }
                                let mut cursor = std::io::Cursor::new(&buffer);
                                cursor.seek(SeekFrom::Start(entry.contentpos))?;
                                let mut chunk = cursor.take(entry.size);
                                io::copy(&mut chunk, &mut output)?;
                            }
                        } else if entry.kind == Kind::Link {
                            // links are always captured in whole, never chunks
                            let mut cursor = std::io::Cursor::new(&buffer);
                            cursor.seek(SeekFrom::Start(entry.contentpos))?;
                            let mut chunk = cursor.take(entry.size);
                            let mut raw_bytes: Vec<u8> = vec![];
                            chunk.read_to_end(&mut raw_bytes)?;
                            write_link(&raw_bytes, &fpath)?;
                        }
                    }
                    buffer.clear();
                }
                None => return Ok(file_count),
            }
        }
    }

    ///
    /// Attempt to read the next manifest header from the archive.
    ///
    /// Returns `None` if the end of the file has been reached.
    ///
    /// If the archive is encrypted and `enable_encryption()` has been called,
    /// then the encrypted block of entries and file content will be decrypted.
    ///
    /// Call `read_next_entry()` to get the next entry in the manifest, doing so
    /// `manifest.num_entries` times. Then call `read_content()` to get the
    /// compressed file data. Failing to do so will result in strange errors.
    ///
    fn read_next_manifest(&mut self) -> Result<Option<Manifest>, Error> {
        if self.content.is_some() || self.block_size.is_some() {
            return Err(Error::InternalError(
                "you forgot to call read_content()".into(),
            ));
        }
        match self.reader.read_next_header() {
            Ok(rows) => {
                if rows.contains_key(&TAG_ENCRYPTED_SIZE) {
                    // an encrypted block of entries and file data, must be
                    // decrypted and the plain text content cached for later
                    let encrypted = Encrypted::try_from(rows)?;
                    let cipher = self.reader.read_n_bytes(encrypted.block_size as u64)?;
                    if let Some(ref secret) = self.secret_key {
                        let plain = decrypt_data(
                            &self.header.enc_algo,
                            secret,
                            &cipher,
                            &encrypted.init_vector,
                        )?;
                        let mut cursor = std::io::Cursor::new(&plain);
                        let rows = read_header(&mut cursor)?;
                        let manifest = Manifest::try_from(rows)?;
                        let mut buffer: Vec<u8> = vec![];
                        cursor.read_to_end(&mut buffer)?;
                        self.content = Some(std::io::Cursor::new(buffer));
                        self.block_size = None;
                        Ok(Some(manifest))
                    } else {
                        Err(Error::InternalError(
                            "encrypted archive, call enable_encryption()".into(),
                        ))
                    }
                } else {
                    let manifest = Manifest::try_from(rows)?;
                    // discard any previously cached content and set the next
                    // block size so that we know how to read the content
                    self.block_size = Some(manifest.block_size);
                    self.content = None;
                    Ok(Some(manifest))
                }
            }
            Err(err) => match err {
                Error::UnexpectedEof => Ok(None),
                Error::IOError(ioerr) => {
                    if ioerr.kind() == ErrorKind::UnexpectedEof {
                        Ok(None)
                    } else {
                        Err(Error::from(ioerr))
                    }
                }
                _ => Err(err),
            },
        }
    }

    ///
    /// Read the next set of header rows from the archive.
    ///
    /// This can be called at most `num_entries` times before it starts to
    /// return garbage, or an error.
    ///
    fn read_next_entry(&mut self) -> Result<HeaderMap, Error> {
        if let Some(reader) = self.content.as_mut() {
            read_header(reader)
        } else {
            self.reader.read_next_header()
        }
    }

    ///
    /// Read the upcoming block of compressed file content from the archive.
    ///
    /// This only yields expected results if `read_next_entry()` has been called
    /// the appropriate number of times.
    ///
    fn read_content(&mut self) -> Result<Vec<u8>, Error> {
        if let Some(mut reader) = self.content.take() {
            let pos = reader.stream_position()? as usize;
            let mut buffer = reader.into_inner();
            buffer.drain(..pos);
            Ok(buffer)
        } else if let Some(count) = self.block_size.take() {
            self.reader.read_n_bytes(count as u64)
        } else {
            Err(Error::InternalError(
                "should call read_next_manifest() first".into(),
            ))
        }
    }
}

// Calculate the hash value for a given string.
fn calculate_hash(name: &str) -> u64 {
    use std::hash::{DefaultHasher, Hash, Hasher};
    let mut s = DefaultHasher::new();
    name.hash(&mut s);
    s.finish()
}

///
/// An iterator over the entries within an archive.
///
/// The caller should check if the archive is encrypted by calling the
/// `is_encrypted()` function, and if it returns `true`, then call
/// `enable_encryption()` with a password provided by the user.
///
pub struct Entries {
    reader: Reader,
    path_builder: PathBuilder,
    entries_remaining: Option<u32>,
    visited: HashSet<u64>,
}

impl Entries {
    ///
    /// Create an `Entries` iterator for the given file.
    ///
    pub fn new<P: AsRef<Path>>(infile: P) -> Result<Entries, Error> {
        let reader = from_file(infile)?;
        let path_builder = PathBuilder::new();
        Ok(Self {
            reader,
            path_builder,
            entries_remaining: None,
            visited: HashSet::new(),
        })
    }

    ///
    /// Return `true` if the archive appears to have encrypted content.
    ///
    pub fn is_encrypted(&self) -> bool {
        self.reader.is_encrypted()
    }

    ///
    /// Enable encryption when reading the archive, using the given passphrase.
    ///
    pub fn enable_encryption(&mut self, password: &str) -> Result<(), Error> {
        self.reader.enable_encryption(password)
    }

    // Retrieve the next entry from the manifest, reading the next manifest if
    // needed, and skipping content once the end of the manifest is reached.
    // Once the end of the input is reached, returns `Ok(None)` indefinitely.
    fn get_next_entry(&mut self) -> Result<Option<Entry>, Error> {
        loop {
            match self.entries_remaining.take() {
                Some(0) => {
                    // throw away the compressed content since we are only listing
                    self.reader.read_content()?;
                }
                Some(remaining) => {
                    // get the next entry from the manifest
                    let entry_rows = self.reader.read_next_entry()?;
                    let mut entry = Entry::try_from(entry_rows)?;
                    if let Some(dir_id) = entry.dir_id {
                        let entry_parent = entry.parent.unwrap_or(0);
                        self.path_builder
                            .insert(dir_id, entry_parent, entry.name.clone());
                    }
                    if let Some(parent) = entry.parent {
                        let mut fullpath = self.path_builder.get_full_path(parent)?;
                        fullpath = fullpath.join(entry.name);
                        entry.name = fullpath.to_string_lossy().to_string();
                    }
                    self.entries_remaining = Some(remaining - 1);

                    // return unique paths, since a file may be split across
                    // more than one content, we will see its entry again
                    let hash = calculate_hash(&entry.name);
                    if !self.visited.contains(&hash) {
                        self.visited.insert(hash);
                        return Ok(Some(entry));
                    }
                }
                None => {
                    // try to read the next manifest
                    if let Some(manifest) = self.reader.read_next_manifest()? {
                        self.entries_remaining = Some(manifest.num_entries);
                    } else {
                        // reached the end of the file
                        return Ok(None);
                    }
                }
            }
        }
    }
}

impl Iterator for Entries {
    type Item = Result<Entry, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        match self.get_next_entry() {
            Ok(None) => None,
            Ok(some) => some.map(Ok),
            Err(err) => Some(Err(err)),
        }
    }
}

///
/// Create a `Reader` from the given file.
///
/// ```no_run
/// # let passwd: Option<&str> = None;
/// let mut reader = exaf_rs::reader::from_file("archive.exa").expect("from file");
/// if reader.is_encrypted() && passwd.is_none() {
///     println!("Archive is encrypted, please provide a password.");
/// } else {
///     if let Some(password) = passwd {
///         reader.enable_encryption(password).expect("enable crypto");
///     }
///     let path = std::env::current_dir().expect("no env?");
///     reader.extract_all(&path).expect("extract all");
/// }
/// ```
///
pub fn from_file<P: AsRef<Path>>(infile: P) -> Result<Reader, Error> {
    let mut input = File::open(infile)?;
    let mut archive_start = [0; 6];
    input.read_exact(&mut archive_start)?;
    if archive_start[0..4] != [b'E', b'X', b'A', b'F'] {
        return Err(Error::MissingMagic);
    }
    // for now, only know how to build version 1 readers
    if archive_start[4] != 1 {
        return Err(Error::UnsupportedVersion);
    }
    Reader::new(Box::new(ReaderV1::new(input)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_header_u16() -> Result<(), Error> {
        let input: Vec<u8> = vec![0, 1, 0x12, 0x34, 0, 2, 255, 255];
        let rows = read_header(input.as_slice())?;
        assert_eq!(rows.len(), 1);
        let maybe_value = get_header_u16(&rows, &0x1234)?;
        let value = maybe_value.unwrap();
        assert_eq!(value, 65_535);
        Ok(())
    }

    #[test]
    fn test_get_header_u32_up() -> Result<(), Error> {
        let input: Vec<u8> = vec![0, 1, 0x12, 0x34, 0, 2, 255, 255];
        let rows = read_header(input.as_slice())?;
        assert_eq!(rows.len(), 1);
        let maybe_value = get_header_u32(&rows, &0x1234)?;
        let value = maybe_value.unwrap();
        assert_eq!(value, 65_535);
        Ok(())
    }

    #[test]
    fn test_get_header_u64_up() -> Result<(), Error> {
        let input: Vec<u8> = vec![0, 1, 0x12, 0x34, 0, 4, 255, 255, 255, 255];
        let rows = read_header(input.as_slice())?;
        assert_eq!(rows.len(), 1);
        let maybe_value = get_header_u64(&rows, &0x1234)?;
        let value = maybe_value.unwrap();
        assert_eq!(value, 4_294_967_295);
        Ok(())
    }

    #[test]
    fn test_get_header_time_i32() -> Result<(), Error> {
        let input: Vec<u8> = vec![0, 1, 0x12, 0x34, 0, 4, 0x66, 0x38, 0x17, 0x80];
        let rows = read_header(input.as_slice())?;
        assert_eq!(rows.len(), 1);
        let maybe_value = get_header_time(&rows, &0x1234)?;
        let value = maybe_value.unwrap();
        assert_eq!(value.year(), 2024);
        assert_eq!(value.month(), 5);
        assert_eq!(value.day(), 5);
        Ok(())
    }

    #[test]
    fn test_get_header_time_i64() -> Result<(), Error> {
        // the value may fit in 4 bytes but its signed value is outside of the
        // range supported by an i32 so we must use i64
        let input: Vec<u8> = vec![0, 1, 0x12, 0x34, 0, 8, 0, 0, 0, 0, 0x93, 0xf7, 0x14, 0x00];
        let rows = read_header(input.as_slice())?;
        assert_eq!(rows.len(), 1);
        let maybe_value = get_header_time(&rows, &0x1234)?;
        let value = maybe_value.unwrap();
        assert_eq!(value.year(), 2048);
        assert_eq!(value.month(), 8);
        assert_eq!(value.day(), 30);
        Ok(())
    }

    #[test]
    fn test_get_header_str() -> Result<(), Error> {
        let input: Vec<u8> = vec![0, 1, 0x12, 0x34, 0, 6, b'f', b'o', b'o', b'b', b'a', b'r'];
        let rows = read_header(input.as_slice())?;
        assert_eq!(rows.len(), 1);
        let maybe_value = get_header_str(&rows, &0x1234)?;
        let value = maybe_value.unwrap();
        assert_eq!(value, "foobar");
        Ok(())
    }

    #[test]
    fn test_get_header_bytes() -> Result<(), Error> {
        let input: Vec<u8> = vec![0, 1, 0x12, 0x34, 0, 6, b'f', b'o', b'o', b'b', b'a', b'r'];
        let rows = read_header(input.as_slice())?;
        assert_eq!(rows.len(), 1);
        let maybe_value = get_header_bytes(&rows, &0x1234)?;
        let value = maybe_value.unwrap();
        assert_eq!(value, "foobar".as_bytes());
        Ok(())
    }

    #[test]
    fn test_version1_reader_one_tiny_file() -> Result<(), Error> {
        let input_path = "test/fixtures/version1/one_tiny_file.exa";
        let mut reader = from_file(input_path)?;
        let maybe_manifest = reader.read_next_manifest()?;
        let manifest = maybe_manifest.unwrap();
        assert_eq!(manifest.num_entries, 1);
        assert_eq!(manifest.comp_algo, Compression::ZStandard);
        assert_eq!(manifest.block_size, 32);
        Ok(())
    }

    #[test]
    fn test_read_header() -> Result<(), Error> {
        let raw_bytes: Vec<u8> = vec![
            0x00, 0x0a, 0x49, 0x44, 0x00, 0x04, 0x00, 0x00, 0x00, 0x01, 0x4e, 0x4d, 0x00, 0x03,
            0x74, 0x6d, 0x70, 0x4d, 0x4f, 0x00, 0x04, 0x00, 0x00, 0x41, 0xed, 0x4d, 0x54, 0x00,
            0x08, 0x00, 0x00, 0x00, 0x00, 0x66, 0x26, 0xef, 0xd3, 0x43, 0x54, 0x00, 0x08, 0x00,
            0x00, 0x00, 0x00, 0x66, 0x11, 0xb6, 0xb8, 0x41, 0x54, 0x00, 0x08, 0x00, 0x00, 0x00,
            0x00, 0x66, 0x26, 0xef, 0xd4, 0x55, 0x4e, 0x00, 0x08, 0x6e, 0x66, 0x69, 0x65, 0x64,
            0x6c, 0x65, 0x72, 0x47, 0x4e, 0x00, 0x05, 0x73, 0x74, 0x61, 0x66, 0x66, 0x55, 0x49,
            0x00, 0x04, 0x00, 0x00, 0x01, 0xf5, 0x47, 0x49, 0x00, 0x04, 0x00, 0x00, 0x00, 0x14,
            0x00, 0x0b,
        ];
        let rows = read_header(raw_bytes.as_slice())?;
        assert_eq!(rows.len(), 10);
        // no use trying to check all of the values as some of them are timestamps
        assert_eq!(rows.get(&TAG_DIRECTORY_ID), Some(vec![0, 0, 0, 1].as_ref()));
        assert_eq!(rows.get(&TAG_NAME), Some(vec![b't', b'm', b'p'].as_ref()));
        Ok(())
    }
}
