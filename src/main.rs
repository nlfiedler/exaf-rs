//
// Copyright (c) 2024 Nathan Fiedler
//
use chrono::prelude::*;
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{self, Read, Seek, SeekFrom, Write};
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
    Utf8Error(#[from] std::str::Utf8Error),
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
    // extended attribute, and the value raw data from the file system.
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
            },
            Err(_) => None,
        };
        let ctime = match metadata.as_ref() {
            Ok(attr) => {
                let ct = attr.created().unwrap_or(SystemTime::UNIX_EPOCH);
                Some(DateTime::<Utc>::from(ct))
            },
            Err(_) => None,
        };
        let atime = match metadata.as_ref() {
            Ok(attr) => {
                let at = attr.accessed().unwrap_or(SystemTime::UNIX_EPOCH);
                Some(DateTime::<Utc>::from(at))
            },
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
        if rows.contains_key(&0x4e4d) {
            let raw = &rows[&0x4e4d];
            let name = std::str::from_utf8(raw)?;
            // TODO: extract the rest of the values
            Ok(Self {
                name: name.to_string(),
                mode: None,
                attrs: None,
                uid: None,
                gid: None,
                user: None,
                group: None,
                ctime: None,
                mtime: None,
                atime: None,
                xattrs: None,
            })
        } else {
            return Err(Error::MissingTag("NM".into()));
        }
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
    pub fn new<P: AsRef<Path>>(path: P) -> Self {
        let metadata = EntryMetadata::new(path.as_ref());
        let md = fs::symlink_metadata(path.as_ref());
        let original_len = match md.as_ref() {
            Ok(attr) => attr.len(),
            Err(_) => 0,
        };
        Self {
            metadata,
            directory: None,
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
        if rows.contains_key(&0x535a) {
            let raw = &rows[&0x535a];
            let len: [u8; 8] = raw[0..8].try_into()?;
            let original_len = u64::from_be_bytes(len);
            // TODO: extract the rest of the values
            Ok(Self {
                metadata,
                directory: None,
                original_len,
                compressed_len: None,
                comp_algo: None,
                hash_algo: None,
                checksum: None,
            })
        } else {
            Err(Error::MissingTag("SZ".into()))
        }
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

fn write_archive_header<W: Write>(mut output: W) -> io::Result<()> {
    // TODO: write the version and remaining header size using BE
    let version = [b'E', b'X', b'A', b'F', 1, 0, 0, 0];
    output.write_all(&version)?;
    Ok(())
}

fn make_file_header(file_entry: &FileEntry) -> io::Result<Vec<u8>> {
    // build out the header data piece by piece
    let mut header: Vec<u8> = Vec::new();

    // NM: file name
    header.write_all(&[b'N', b'M'])?;
    let meta = &file_entry.metadata;
    let name = meta.name.as_bytes();
    let name_len = u16::to_be_bytes(name.len() as u16);
    header.write_all(&name_len)?;
    header.write_all(name)?;

    // SZ: original file size
    header.write_all(&[b'S', b'Z', 0, 8])?;
    let orig_len = u64::to_be_bytes(file_entry.original_len);
    header.write_all(&orig_len)?;

    // MO: Unix file mode, if available
    if let Some(mode) = file_entry.metadata.mode {
        header.write_all(&[b'M', b'O', 0, 2])?;
        let unix_mode = u32::to_be_bytes(mode);
        header.write_all(&unix_mode[2..])?;
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

    // TODO: write DI

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
    // TODO: write UN
    // TODO: write UI
    // TODO: write GN
    // TODO: write GI
    Ok(header)
}

fn write_file_header<W: Write>(header: &[u8], mut output: W) -> io::Result<()> {
    // write the fully realized header to the output
    let header_len = u16::to_be_bytes(header.len() as u16);
    output.write_all(&header_len)?;
    output.write_all(&header)?;
    Ok(())
}

fn add_file<P: AsRef<Path>, W: Write + Seek>(infile: P, mut output: W) -> io::Result<()> {
    let mut file_entry = FileEntry::new(infile.as_ref());
    file_entry = file_entry.compute_sha1(infile.as_ref())?;
    let mut header = make_file_header(&file_entry)?;
    //
    // when compressing the file...
    //
    // 1. add CA row to header
    // 2. get the current position in the output as p1
    // 3. write (2 + header.len() + 12) of zeros
    // 4. get the current position in the output as p15
    // 5. write the compressed file data
    // 6. remember this current position as p2
    // 7. seek back to p1
    // 8. add the LN field to the header with length equal to p2 - p15
    // 9. write the completed header data starting at p1
    // 10. seek back to p2 for the next invocation
    //
    header.write_all(&[b'C', b'A', 0, 4, b'z', b's', b't', b'd'])?;
    let p1 = output.stream_position()?;
    // header-size field (2 bytes) + header length + upcoming LN row
    let header_len = 2 + header.len() + 12;
    let mut zeros: Vec<u8> = Vec::with_capacity(header_len);
    zeros.resize(header_len, 0);
    output.write_all(&zeros)?;
    let p15 = output.stream_position()?;
    let input = File::open(infile)?;
    zstd::stream::copy_encode(input, &mut output, 0)?;
    let p2 = output.stream_position()?;
    output.seek(SeekFrom::Start(p1))?;
    header.write_all(&[b'L', b'N', 0, 8])?;
    let data_len = u64::to_be_bytes(p2 - p15);
    header.write_all(&data_len)?;
    write_file_header(&header, &mut output)?;
    output.seek(SeekFrom::Start(p2))?;

    //
    // TODO: if not compressing, then write file header and copy file
    //
    // write_file_header(&header, &mut output)?;
    // let mut input = File::open(infile)?;
    // io::copy(&mut input, &mut output)?;
    Ok(())
}

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

fn list_files<R: Read + Seek>(mut input: R) -> Result<(), Error> {
    // read next 2 bytes as header size
    let mut header_size = [0; 2];
    input.read_exact(&mut header_size)?;
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
    // create a FileEntry from the supported tags in the HashMap
    let entry = FileEntry::from_map(&rows)?;
    println!("entry: {:?}", entry);
    // TODO: read the file data, decompress, print
    Ok(())
}

fn main() {
    let infile = PathBuf::from("LICENSE");
    let mut outfile = File::create("output.exaf").expect("could not create file");
    write_archive_header(&mut outfile).expect("could not write header");
    add_file(infile, &mut outfile).expect("could not add file");
    println!("Archive created");
    let infile = PathBuf::from("output.exaf");
    let input = read_archive_header(&infile).expect("could not write header");
    list_files(input).expect("could not add file");
    println!("Archive examined");
}
