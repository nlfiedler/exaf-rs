//
// Copyright (c) 2024 Nathan Fiedler
//
use chrono::prelude::*;
use std::fmt;
use std::fs;
use std::path::{Component, Path, PathBuf};
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
    /// The symbolic link bytes were not decipherable.
    #[error("symbolic link encoding was not recognized")]
    LinkTextEncoding,
    /// File header lacks the initial `E,X,A,F` bytes.
    #[error("missing magic 'EXAF' number")]
    MissingMagic,
    /// File/link entry referred to an unknown parent.
    #[error("unknown parent identifier {0}")]
    MissingParent(u32),
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
    UnsupportedCompAlgo(u8),
    /// Encryption algorithm in archive is not supported.
    #[error("unsupported encryption algorithm {0}")]
    UnsupportedEncAlgo(u8),
    /// Key derivation function in archive is not supported.
    #[error("unsupported key derivation function {0}")]
    UnsupportedKeyAlgo(u8),
    /// A header was missing a required tag row.
    #[error("missing required tag from header: {0}")]
    MissingTag(String),
    /// An unexpected error occurred that would otherwise have been a panic.
    #[error("something bad happened: {0}")]
    InternalError(String),
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
/// Create a symbolic link using the given raw bytes.
///
fn write_link(contents: &[u8], filepath: &Path) -> Result<(), Error> {
    use os_str_bytes::OsStringBytes;
    // this may panic if the bytes are not valid for this platform
    let target = std::ffi::OsString::from_io_vec(contents.to_owned())
        .ok_or_else(|| Error::LinkTextEncoding)?;
    // cfg! macro will not work in this OS-specific import case
    {
        #[cfg(target_family = "unix")]
        use std::os::unix::fs;
        #[cfg(target_family = "windows")]
        use std::os::windows::fs;
        #[cfg(target_family = "unix")]
        fs::symlink(target, filepath)?;
        #[cfg(target_family = "windows")]
        fs::symlink_file(target, filepath)?;
    }
    return Ok(());
}

///
/// Return the Unix file mode for the given path.
///
#[cfg(target_family = "unix")]
fn unix_mode<P: AsRef<Path>>(path: P) -> Option<u32> {
    use std::os::unix::fs::MetadataExt;
    if let Ok(meta) = fs::symlink_metadata(path) {
        Some(meta.mode())
    } else {
        None
    }
}

#[cfg(target_family = "windows")]
fn unix_mode<P: AsRef<Path>>(_path: P) -> Option<u32> {
    None
}

///
/// Return the Windows file attributes for the given path.
///
#[cfg(target_family = "unix")]
fn file_attrs<P: AsRef<Path>>(_path: P) -> Option<u32> {
    None
}

#[cfg(target_family = "windows")]
fn file_attrs<P: AsRef<Path>>(path: P) -> Option<u32> {
    use std::os::windows::prelude::*;
    if let Ok(meta) = fs::symlink_metadata(path) {
        Some(meta.file_attributes())
    } else {
        None
    }
}

///
/// Return a sanitized version of the path, with any non-normal components
/// removed. Roots and prefixes are especially problematic for extracting an
/// archive, so those are always removed. Note also that path components which
/// refer to the parent directory will be stripped ("foo/../bar" will become
/// "foo/bar").
///
fn sanitize_path<P: AsRef<Path>>(dirty: P) -> Result<PathBuf, Error> {
    let components = dirty.as_ref().components();
    let allowed = components.filter(|c| matches!(c, Component::Normal(_)));
    let mut path = PathBuf::new();
    for component in allowed {
        path = path.join(component);
    }
    Ok(path)
}

///
/// Type of compression used on a specific content block.
///
#[derive(Clone, Debug, PartialEq)]
enum Compression {
    Copy,
    ZStandard,
}

impl fmt::Display for Compression {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Compression::Copy => write!(f, "copy"),
            Compression::ZStandard => write!(f, "zstd"),
        }
    }
}

impl TryFrom<u8> for Compression {
    type Error = self::Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Compression::Copy),
            1 => Ok(Compression::ZStandard),
            v => Err(self::Error::UnsupportedCompAlgo(v)),
        }
    }
}

///
/// Algorithm for encrypting the archive data.
///
#[derive(Clone, Debug, PartialEq)]
enum Encryption {
    None,
    Blowfish,
}

impl fmt::Display for Encryption {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Encryption::None => write!(f, "none"),
            Encryption::Blowfish => write!(f, "Blowfish"),
        }
    }
}

impl TryFrom<u8> for Encryption {
    type Error = self::Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Encryption::None),
            1 => Ok(Encryption::Blowfish),
            v => Err(self::Error::UnsupportedEncAlgo(v)),
        }
    }
}

///
/// Algorithm for deriving a key from a passphrase.
///
#[derive(Clone, Debug, PartialEq)]
enum KeyDerivation {
    None,
    Argon2id,
}

impl fmt::Display for KeyDerivation {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            KeyDerivation::None => write!(f, "none"),
            KeyDerivation::Argon2id => write!(f, "Argon2id"),
        }
    }
}

impl TryFrom<u8> for KeyDerivation {
    type Error = self::Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(KeyDerivation::None),
            1 => Ok(KeyDerivation::Argon2id),
            v => Err(self::Error::UnsupportedKeyAlgo(v)),
        }
    }
}

///
/// Represents a file, directory, or symbolic link within an archive.
///
pub struct Entry {
    // name of the file, directory, or symbolic link
    name: String,
    // true if this entry is a symbolic link
    is_link: bool,
    // identifier for directory entries
    dir_id: Option<u32>,
    // identifier of the parent directory
    parent: Option<u32>,
    // Unix file mode
    mode: Option<u32>,
    // Windows file attributes
    attrs: Option<u32>,
    // Unix user identifier
    uid: Option<u32>,
    // name of the owning user
    user: Option<String>,
    // Unix group identifier
    gid: Option<u32>,
    // name of the owning group
    group: Option<String>,
    // created time
    ctime: Option<DateTime<Utc>>,
    // modification time
    mtime: Option<DateTime<Utc>>,
    // last accessed time
    atime: Option<DateTime<Utc>>,
}

impl Entry {
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
        let is_link = match metadata.as_ref() {
            Ok(attr) => attr.is_symlink(),
            Err(_) => false,
        };
        let mode = unix_mode(path.as_ref());
        let attrs = file_attrs(path.as_ref());
        let em = Self {
            name,
            is_link,
            dir_id: None,
            parent: None,
            mode,
            attrs,
            uid: None,
            gid: None,
            user: None,
            group: None,
            ctime,
            mtime,
            atime,
        };
        em.owners(path.as_ref())
    }

    ///
    /// Set the user and group ownership of the given path.
    ///
    #[cfg(target_family = "unix")]
    fn owners<P: AsRef<Path>>(mut self, path: P) -> Self {
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
    fn owners(self, _path: &Path) -> Self {
        self
    }
}

#[derive(Debug, PartialEq)]
pub enum Kind {
    File,
    Link,
}

// tags for archive header rows
const TAG_ENC_ALGO: u16 = 0x4541;
const TAG_KEY_DERIV: u16 = 0x4b44;
const TAG_SALT: u16 = 0x5341;
const TAG_KEY_ITER: u16 = 0x4b49;

// tags for manifest header rows
const TAG_NUM_ENTRIES: u16 = 0x4e45;
const TAG_COMP_ALGO: u16 = 0x4341;
const TAG_BLOCK_SIZE: u16 = 0x4253;

// tags for entry header rows
const TAG_NAME: u16 = 0x4e4d;
const TAG_PARENT: u16 = 0x5041;
const TAG_DIRECTORY_ID: u16 = 0x4944;
const TAG_UNIX_MODE: u16 = 0x4d4f;
const TAG_FILE_ATTRS: u16 = 0x4641;
const TAG_MODIFY_TIME: u16 = 0x4d54;
const TAG_CREATE_TIME: u16 = 0x4354;
const TAG_ACCESS_TIME: u16 = 0x4154;
const TAG_USER_NAME: u16 = 0x554e;
const TAG_GROUP_NAME: u16 = 0x474e;
const TAG_USER_ID: u16 = 0x5549;
const TAG_GROUP_ID: u16 = 0x4749;
const TAG_ITEM_POS: u16 = 0x4950;
const TAG_CONTENT_POS: u16 = 0x4350;
const TAG_ITEM_SIZE: u16 = 0x535a;
const TAG_SYM_LINK: u16 = 0x534c;

// Desired size of the compressed bundle of file data.
const BUNDLE_SIZE: u64 = 16777216;

pub mod reader;
pub mod writer;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_file_name() -> Result<(), Error> {
        assert_eq!(get_file_name(PathBuf::from("")), "");
        assert_eq!(get_file_name(PathBuf::from("path/to/file")), "file");
        assert_eq!(get_file_name(PathBuf::from("path/to/..")), "path/to/..");
        Ok(())
    }

    #[test]
    fn test_sanitize_path() -> Result<(), Error> {
        // need to use real paths for the canonicalize() call
        #[cfg(target_family = "windows")]
        {
            let result = sanitize_path(Path::new("C:\\Windows"))?;
            assert_eq!(result, PathBuf::from("Windows"));
        }
        #[cfg(target_family = "unix")]
        {
            let result = sanitize_path(Path::new("/etc"))?;
            assert_eq!(result, PathBuf::from("etc"));
        }
        let result = sanitize_path(Path::new("src/lib.rs"))?;
        assert_eq!(result, PathBuf::from("src/lib.rs"));

        let result = sanitize_path(Path::new("/usr/../src/./lib.rs"))?;
        assert_eq!(result, PathBuf::from("usr/src/lib.rs"));
        Ok(())
    }
}
