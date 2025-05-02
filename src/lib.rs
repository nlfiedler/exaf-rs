//
// Copyright (c) 2024 Nathan Fiedler
//

//!
//! The `exaf_rs` crate implements the EXtensible Archiver Format and is
//! intended to be used in compressing and archiving files. It offers an
//! alternative to the well-known zip and 7-zip formats, with extensibility in
//! mind. The running time of this reference implementation is similar to that
//! of GNU tar with Zstandard compression, and the resulting file size is very
//! similar.
//!
//! ## Examples
//!
//! To create an archive, use the `Writer` to add files, directories, and
//! symbolic links. It also can add an entire directory tree in one call.
//!
//! ```no_run
//! # use std::fs::File;
//! use exaf_rs::writer::Writer;
//!
//! let output = File::create("archive.exa").expect("create file");
//! let mut writer = Writer::new(output).expect("new writer");
//! writer.add_dir_all("important-docs").expect("add dir all");
//!
//! // You must call finish() in order to flush everything to the output.
//! writer.finish().expect("finish");
//! ```
//!
//! The code to list the entries of an archive might look like this (this
//! example assumes that the archive is not encrypted):
//!
//! ```no_run
//! let mut reader = exaf_rs::reader::Entries::new("archive.exa").expect("new entries");
//! for result in reader {
//!     match result {
//!         Ok(entry) => println!("{}", entry.name()),
//!         Err(err) => println!("error: {}", err),
//!     }
//! }
//! ```
//!
//! To extract everything within the archive, which may be encrypted, use the
//! `Reader` like so:
//!
//! ```no_run
//! # let passwd: Option<&str> = None;
//! let mut reader = exaf_rs::reader::from_file("archive.exa").expect("from file");
//! if reader.is_encrypted() && passwd.is_none() {
//!     println!("Archive is encrypted, please provide a password.");
//! } else {
//!     if let Some(password) = passwd {
//!         reader.enable_encryption(password).expect("enable crypto");
//!     }
//!     let path = std::env::current_dir().expect("no env?");
//!     reader.extract_all(&path).expect("extract all");
//! }
//! ```
//!
//! A more complete example of creating and extracting archives can be found in
//! the `src/main.rs` file in the source repository.
//!

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
    /// A usage error
    #[error("error: {0}")]
    Usage(String),
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
/// Generate a salt appropriate for the given key derivation function.
///
fn generate_salt(kd: &KeyDerivation) -> Result<Vec<u8>, Error> {
    if *kd == KeyDerivation::Argon2id {
        use argon2::password_hash::{rand_core::OsRng, SaltString};
        let salt = SaltString::generate(&mut OsRng);
        let mut buf: Vec<u8> = vec![0; salt.len()];
        let bytes = salt
            .decode_b64(&mut buf)
            .map_err(|e| Error::InternalError(format!("argon2 failed: {}", e)))?;
        Ok(bytes.to_vec())
    } else {
        // something went terribly wrong
        Err(Error::UnsupportedKeyAlgo(255))
    }
}

///
/// Produce a secret key from a passphrase and random salt.
///
fn derive_key(
    kd: &KeyDerivation,
    password: &str,
    salt: &[u8],
    params: &KeyDerivationParams,
) -> Result<Vec<u8>, Error> {
    if *kd == KeyDerivation::Argon2id {
        use argon2::{Algorithm, ParamsBuilder, Version};
        let mut output: Vec<u8> = vec![0; params.tag_length as usize];
        let mut builder: ParamsBuilder = ParamsBuilder::new();
        builder.t_cost(params.time_cost);
        builder.m_cost(params.mem_cost);
        builder.p_cost(params.para_cost);
        builder.output_len(params.tag_length as usize);
        let kdf = builder
            .context(Algorithm::Argon2id, Version::V0x13)
            .map_err(|e| Error::InternalError(format!("argon2 failed: {}", e)))?;
        kdf.hash_password_into(password.as_bytes(), salt, &mut output.as_mut_slice())
            .map_err(|e| Error::InternalError(format!("argon2 failed: {}", e)))?;
        Ok(output)
    } else {
        // something went terribly wrong
        Err(Error::UnsupportedKeyAlgo(255))
    }
}

///
/// Encrypt the given data, returning a newly allocated vector of bytes
/// containing the cipher text, and the nonce that was generated.
///
fn encrypt_data(ea: &Encryption, key: &[u8], data: &[u8]) -> Result<(Vec<u8>, Vec<u8>), Error> {
    if *ea == Encryption::AES256GCM {
        use aes_gcm::{
            aead::{Aead, AeadCore, KeyInit, OsRng},
            Aes256Gcm, Key,
        };
        let key: &Key<Aes256Gcm> = key.into();
        let cipher = Aes256Gcm::new(&key);
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        let ciphertext = cipher
            .encrypt(&nonce, data)
            .map_err(|e| Error::InternalError(format!("aes_gcm failed: {}", e)))?;
        Ok((ciphertext, nonce.to_vec()))
    } else {
        // something went terribly wrong
        Err(Error::UnsupportedEncAlgo(255))
    }
}

///
/// Decrypt the given data, returning a newly allocated vector of bytes
/// containing the plain text.
///
fn decrypt_data(ea: &Encryption, key: &[u8], data: &[u8], nonce: &[u8]) -> Result<Vec<u8>, Error> {
    if *ea == Encryption::AES256GCM {
        use aes_gcm::{
            aead::{generic_array::GenericArray, Aead, AeadCore, KeyInit},
            Aes256Gcm, Key,
        };
        let key: &Key<Aes256Gcm> = key.into();
        let cipher = Aes256Gcm::new(&key);
        let nonce: &GenericArray<u8, <Aes256Gcm as AeadCore>::NonceSize> = nonce.into();
        let plaintext = cipher
            .decrypt(&nonce, data)
            .map_err(|e| Error::InternalError(format!("aes_gcm failed: {}", e)))?;
        Ok(plaintext)
    } else {
        // something went terribly wrong
        Err(Error::UnsupportedEncAlgo(255))
    }
}

///
/// Type of compression used on a specific content block.
///
#[derive(Clone, Debug, PartialEq)]
enum Compression {
    None,
    ZStandard,
}

impl fmt::Display for Compression {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Compression::None => write!(f, "none"),
            Compression::ZStandard => write!(f, "zstd"),
        }
    }
}

impl Into<u8> for Compression {
    fn into(self) -> u8 {
        match self {
            Compression::None => 0,
            Compression::ZStandard => 1,
        }
    }
}

impl TryFrom<u8> for Compression {
    type Error = self::Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Compression::None),
            1 => Ok(Compression::ZStandard),
            v => Err(self::Error::UnsupportedCompAlgo(v)),
        }
    }
}

///
/// Algorithm for encrypting the archive data.
///
#[derive(Clone, Debug, PartialEq)]
pub enum Encryption {
    /// No encryption; _default_
    None,
    /// Use the AES 256 bit GCM AEAD cipher.
    AES256GCM,
}

impl fmt::Display for Encryption {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Encryption::None => write!(f, "none"),
            Encryption::AES256GCM => write!(f, "AES256GCM"),
        }
    }
}

impl Into<u8> for Encryption {
    fn into(self) -> u8 {
        match self {
            Encryption::None => 0,
            Encryption::AES256GCM => 1,
        }
    }
}

impl TryFrom<u8> for Encryption {
    type Error = self::Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Encryption::None),
            1 => Ok(Encryption::AES256GCM),
            v => Err(self::Error::UnsupportedEncAlgo(v)),
        }
    }
}

///
/// Algorithm for deriving a key from a passphrase.
///
#[derive(Clone, Debug, PartialEq)]
pub enum KeyDerivation {
    /// No derivation function, _default_
    None,
    /// Use the Argon2id KDF
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

impl Into<u8> for KeyDerivation {
    fn into(self) -> u8 {
        match self {
            KeyDerivation::None => 0,
            KeyDerivation::Argon2id => 1,
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
/// Parameters to be provided to the key derivation function. These are fairly
/// common to most such functions.
///
#[derive(Clone, Debug)]
pub struct KeyDerivationParams {
    /// Number of iterations for key derivation function
    time_cost: u32,
    /// Number of 1 kb memory blocks for key derivation function
    mem_cost: u32,
    /// Degree of parallelism for key derivation function
    para_cost: u32,
    /// Output length for key derivation function
    tag_length: u32,
}

impl KeyDerivationParams {
    ///
    /// Set the time cost from the optional value found in the archive.
    ///
    pub fn time_cost(mut self, time_cost: Option<u32>) -> Self {
        if let Some(tc) = time_cost {
            self.time_cost = tc;
        }
        self
    }

    ///
    /// Set the memory cost from the optional value found in the archive.
    ///
    pub fn mem_cost(mut self, mem_cost: Option<u32>) -> Self {
        if let Some(tc) = mem_cost {
            self.mem_cost = tc;
        }
        self
    }

    ///
    /// Set the degree of parallelism from the optional value found in the
    /// archive.
    ///
    pub fn para_cost(mut self, para_cost: Option<u32>) -> Self {
        if let Some(tc) = para_cost {
            self.para_cost = tc;
        }
        self
    }

    ///
    /// Set the output length from the optional value found in the archive.
    ///
    pub fn tag_length(mut self, tag_length: Option<u32>) -> Self {
        if let Some(tc) = tag_length {
            self.tag_length = tc;
        }
        self
    }
}

impl Default for KeyDerivationParams {
    fn default() -> Self {
        Self {
            time_cost: 2,
            mem_cost: 19_456,
            para_cost: 1,
            tag_length: 32,
        }
    }
}

///
/// Represents a file, directory, or symbolic link within an archive.
///
#[derive(Clone, Debug)]
pub struct Entry {
    // name of the file, directory, or symbolic link
    name: String,
    // true if this entry is a symbolic link
    is_link: bool,
    // identifier for directory entries
    dir_id: Option<u32>,
    // identifier of the parent directory
    parent: Option<u32>,
    // size of the content for files and links
    size: Option<u64>,
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
    /// Create an instance of `Entry` based on the given path.
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
            size: None,
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
    /// Create an instance of `Entry` with just the given name.
    ///
    pub fn with_name<S: Into<String>>(name: S) -> Self {
        Self {
            name: name.into(),
            is_link: false,
            dir_id: None,
            parent: None,
            size: None,
            mode: None,
            attrs: None,
            uid: None,
            gid: None,
            user: None,
            group: None,
            ctime: None,
            mtime: None,
            atime: None,
        }
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

    /// Name of the entry, will be the full path when returned from `Entries`.
    pub fn name(&self) -> &str {
        self.name.as_str()
    }

    pub fn size(&self) -> Option<u64> {
        self.size
    }

    /// Unix file mode
    pub fn mode(&self) -> Option<u32> {
        self.mode
    }

    /// Windows file attributes
    pub fn attrs(&self) -> Option<u32> {
        self.attrs
    }

    /// Unix user identifier
    pub fn uid(&self) -> Option<u32> {
        self.uid
    }

    /// Name of the owning user
    pub fn user(&self) -> Option<&String> {
        self.user.as_ref()
    }

    /// Unix group identifier
    pub fn gid(&self) -> Option<u32> {
        self.gid
    }

    /// Name of the owning group
    pub fn group(&self) -> Option<&String> {
        self.group.as_ref()
    }

    /// Created time
    pub fn ctime(&self) -> Option<DateTime<Utc>> {
        self.ctime
    }

    /// Modification time
    pub fn mtime(&self) -> Option<DateTime<Utc>> {
        self.mtime
    }

    /// Last accessed time
    pub fn atime(&self) -> Option<DateTime<Utc>> {
        self.atime
    }
}

///
/// The type of an entry that has content, such as a file or symbolic link.
///
#[derive(Clone, Debug, PartialEq)]
pub enum Kind {
    /// Item represents a file an its entirety.
    File,
    /// Item represents a symbolic link.
    Link,
    /// Item represents a portion of a file at the given offset.
    Slice(u64),
}

impl Kind {
    /// Return `true` if this kind represents a file slice.
    pub fn is_slice(&self) -> bool {
        matches!(*self, Kind::Slice(_))
    }
}

// tags for archive header rows
const TAG_ENC_ALGO: u16 = 0x4541;
const TAG_KEY_DERIV: u16 = 0x4b44;
const TAG_SALT: u16 = 0x5341;
const TAG_TIME_COST: u16 = 0x5443;
const TAG_MEM_COST: u16 = 0x4d43;
const TAG_PARA_COST: u16 = 0x5043;
const TAG_TAG_LENGTH: u16 = 0x544c;

// tags for manifest header rows
const TAG_NUM_ENTRIES: u16 = 0x4e45;
const TAG_COMP_ALGO: u16 = 0x4341;
const TAG_BLOCK_SIZE: u16 = 0x4253;

// tags for entry header rows
const TAG_NAME: u16 = 0x4e4d;
const TAG_PARENT: u16 = 0x5041;
const TAG_FILE_SIZE: u16 = 0x4c4e;
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

// tags for encryption header rows
const TAG_INIT_VECTOR: u16 = 0x4956;
const TAG_ENCRYPTED_SIZE: u16 = 0x4553;

// Desired size of the compressed bundle of file data.
//
// For the unit tests, which all use fairly small files, make the bundle size
// very small so that we can easily exercise the case of adding a file that
// pushes into another manifest/content pair.
#[cfg(test)]
const BUNDLE_SIZE: u64 = 2048;
#[cfg(not(test))]
const BUNDLE_SIZE: u64 = 16777216;

///
/// Return the size in bytes of the content block at which point a `Writer` will
/// create a new manifest and content pair.
///
pub fn content_size() -> u64 {
    BUNDLE_SIZE
}

pub mod reader;
pub mod writer;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::writer::Options;
    use tempfile::tempdir;

    #[test]
    fn test_content_size() {
        assert_eq!(content_size(), 2048);
    }

    #[test]
    fn test_kind_is_slide() {
        assert_eq!(Kind::File.is_slice(), false);
        assert_eq!(Kind::Link.is_slice(), false);
        assert_eq!(Kind::Slice(0).is_slice(), true);
    }

    #[test]
    fn test_get_file_name() -> Result<(), Error> {
        assert_eq!(get_file_name(PathBuf::from("")), "");
        assert_eq!(get_file_name(PathBuf::from("path/to/file")), "file");
        assert_eq!(get_file_name(PathBuf::from("path/to/..")), "path/to/..");
        Ok(())
    }

    #[cfg(target_family = "unix")]
    #[test]
    fn test_write_link_read_link() -> Result<(), Error> {
        let outdir = tempdir()?;
        let link = outdir.path().join("mylink");
        let target = "link_target_is_meaningless";
        write_link(target.as_bytes(), &link)?;
        let actual = read_link(&link)?;
        assert_eq!(actual, target.as_bytes());
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

    #[test]
    fn test_compression_try_from() {
        let result = Compression::try_from(0);
        assert!(result.is_ok());
        let value = result.unwrap();
        assert_eq!(value, Compression::None);

        let result = Compression::try_from(1);
        assert!(result.is_ok());
        let value = result.unwrap();
        assert_eq!(value, Compression::ZStandard);

        let result = Compression::try_from(2);
        assert!(result.is_err());
        let err_string = result.err().unwrap().to_string();
        assert_eq!(err_string, "unsupported compression algorithm 2");
    }

    #[test]
    fn test_compression_into_u8() {
        let value: u8 = Compression::None.into();
        assert_eq!(value, 0);

        let value: u8 = Compression::ZStandard.into();
        assert_eq!(value, 1);
    }

    #[test]
    fn test_encryption_try_from() {
        let result = Encryption::try_from(0);
        assert!(result.is_ok());
        let value = result.unwrap();
        assert_eq!(value, Encryption::None);

        let result = Encryption::try_from(1);
        assert!(result.is_ok());
        let value = result.unwrap();
        assert_eq!(value, Encryption::AES256GCM);

        let result = Encryption::try_from(2);
        assert!(result.is_err());
        let err_string = result.err().unwrap().to_string();
        assert_eq!(err_string, "unsupported encryption algorithm 2");
    }

    #[test]
    fn test_encryption_into_u8() {
        let value: u8 = Encryption::None.into();
        assert_eq!(value, 0);

        let value: u8 = Encryption::AES256GCM.into();
        assert_eq!(value, 1);
    }

    #[test]
    fn test_key_derivation_try_from() {
        let result = KeyDerivation::try_from(0);
        assert!(result.is_ok());
        let value = result.unwrap();
        assert_eq!(value, KeyDerivation::None);

        let result = KeyDerivation::try_from(1);
        assert!(result.is_ok());
        let value = result.unwrap();
        assert_eq!(value, KeyDerivation::Argon2id);

        let result = KeyDerivation::try_from(2);
        assert!(result.is_err());
        let err_string = result.err().unwrap().to_string();
        assert_eq!(err_string, "unsupported key derivation function 2");
    }

    #[test]
    fn test_key_derivation_into_u8() {
        let value: u8 = KeyDerivation::None.into();
        assert_eq!(value, 0);

        let value: u8 = KeyDerivation::Argon2id.into();
        assert_eq!(value, 1);
    }

    #[test]
    fn test_generate_salt() -> Result<(), Error> {
        use argon2::password_hash::{rand_core::OsRng, SaltString};
        let salt = SaltString::generate(&mut OsRng);
        let mut buf: Vec<u8> = vec![0; salt.len()];
        let result = salt.decode_b64(&mut buf);
        assert!(result.is_ok());
        let bytes = result.unwrap();
        assert_eq!(bytes.len(), 16);
        Ok(())
    }

    #[test]
    fn test_derive_key_argon2() -> Result<(), Error> {
        let password = "keyboard cat";
        let salt = generate_salt(&KeyDerivation::Argon2id)?;
        let params: KeyDerivationParams = Default::default();
        let secret = derive_key(&KeyDerivation::Argon2id, password, &salt, &params)?;
        assert_eq!(secret.len(), 32);
        assert_ne!(password.as_bytes(), secret.as_slice());
        Ok(())
    }

    #[test]
    fn test_encrypt_decrypt() -> Result<(), Error> {
        let password = "keyboard cat";
        let salt = generate_salt(&KeyDerivation::Argon2id)?;
        let params: KeyDerivationParams = Default::default();
        let secret = derive_key(&KeyDerivation::Argon2id, password, &salt, &params)?;
        let input = "mary had a little lamb whose fleece was white as snow";
        assert_eq!(input.len(), 53);
        let (cipher, nonce) = encrypt_data(&Encryption::AES256GCM, &secret, input.as_bytes())?;
        // the cipher text will be larger than the input due to the
        // authentication tag, and possibly the encryption algorithm
        assert_eq!(cipher.len(), 69);
        // the nonce is usually around 12 bytes, not really important
        assert_eq!(nonce.len(), 12);
        let plain = decrypt_data(&Encryption::AES256GCM, &secret, &cipher, &nonce)?;
        // the part that matters -- the data can make the roundtrip
        assert_eq!(plain, input.as_bytes());
        Ok(())
    }

    #[test]
    fn test_create_list_extract() -> Result<(), Error> {
        // git does not track empty directories
        std::fs::create_dir_all("test/fixtures/version1/tiny_tree/sub/empty-dir")?;
        // create the archive
        let outdir = tempdir()?;
        let archive = outdir.path().join("archive.exa");
        let output = std::fs::File::create(&archive)?;
        let mut builder = super::writer::Writer::new(output)?;
        builder.add_dir_all("test/fixtures/version1/tiny_tree")?;
        builder.finish()?;

        // verify the entries appear as expected
        let reader = super::reader::Entries::new(&archive)?;
        assert!(!reader.is_encrypted());
        let mut entries: Vec<String> = reader
            .filter_map(|e| e.ok())
            .map(|e| e.name().to_owned())
            .collect();
        entries.sort();
        assert_eq!(entries.len(), 9);
        #[cfg(target_family = "unix")]
        let expected: Vec<String> = vec![
            "tiny_tree".into(),
            "tiny_tree/file-a.txt".into(),
            "tiny_tree/file-b.txt".into(),
            "tiny_tree/file-c.txt".into(),
            "tiny_tree/link-to-c".into(),
            "tiny_tree/sub".into(),
            "tiny_tree/sub/empty-dir".into(),
            "tiny_tree/sub/empty-file".into(),
            "tiny_tree/sub/file-1.txt".into(),
        ];
        #[cfg(target_family = "windows")]
        let expected: Vec<String> = vec![
            "tiny_tree".into(),
            "tiny_tree\\file-a.txt".into(),
            "tiny_tree\\file-b.txt".into(),
            "tiny_tree\\file-c.txt".into(),
            "tiny_tree\\link-to-c".into(),
            "tiny_tree\\sub".into(),
            "tiny_tree\\sub\\empty-dir".into(),
            "tiny_tree\\sub\\empty-file".into(),
            "tiny_tree\\sub\\file-1.txt".into(),
        ];
        for (a, b) in entries.iter().zip(expected.iter()) {
            assert_eq!(a, b);
        }

        // extract the archive and verify everything
        let mut reader = super::reader::from_file(&archive)?;
        assert!(!reader.is_encrypted());
        reader.extract_all(outdir.path())?;

        // the symbolic link (has expected bytes)
        if cfg!(target_family = "unix") {
            // links do not work properly on windows, there are several issues
            // both in reading and writing symbolic links
            let link = outdir.path().join("tiny_tree").join("link-to-c");
            let link_bytes = read_link(&link)?;
            let expected_link: Vec<u8> = "file-c.txt".as_bytes().to_vec();
            assert_eq!(link_bytes, expected_link);
        }

        // the empty directory (should exist)
        let empty_dir = outdir
            .path()
            .join("tiny_tree")
            .join("sub")
            .join("empty-dir");
        let metadata = std::fs::metadata(&empty_dir)?;
        assert!(metadata.is_dir());

        // the empty file (is empty)
        let empty_file = outdir
            .path()
            .join("tiny_tree")
            .join("sub")
            .join("empty-file");
        let metadata = std::fs::metadata(&empty_file)?;
        assert_eq!(metadata.len(), 0);

        // the other files (have expected content)
        let actual = std::fs::read_to_string(outdir.path().join("tiny_tree").join("file-a.txt"))?;
        #[cfg(target_family = "unix")]
        assert_eq!(actual, "mary had a little lamb\n");
        #[cfg(target_family = "windows")]
        assert_eq!(actual, "mary had a little lamb\r\n");
        let actual = std::fs::read_to_string(outdir.path().join("tiny_tree").join("file-b.txt"))?;
        #[cfg(target_family = "unix")]
        assert_eq!(actual, "whose fleece was white as snow\n");
        #[cfg(target_family = "windows")]
        assert_eq!(actual, "whose fleece was white as snow\r\n");
        let actual = std::fs::read_to_string(outdir.path().join("tiny_tree").join("file-c.txt"))?;
        #[cfg(target_family = "unix")]
        assert_eq!(actual, "and everywhere that Mary went\n");
        #[cfg(target_family = "windows")]
        assert_eq!(actual, "and everywhere that Mary went\r\n");
        let actual = std::fs::read_to_string(
            outdir
                .path()
                .join("tiny_tree")
                .join("sub")
                .join("file-1.txt"),
        )?;
        #[cfg(target_family = "unix")]
        assert_eq!(actual, "the lamb was sure to go.\n");
        #[cfg(target_family = "windows")]
        assert_eq!(actual, "the lamb was sure to go.\r\n");
        Ok(())
    }

    #[test]
    fn test_create_list_file_size() -> Result<(), Error> {
        // git does not track empty directories
        std::fs::create_dir_all("test/fixtures/version1/tiny_tree/sub/empty-dir")?;
        // create the archive
        let outdir = tempdir()?;
        let archive = outdir.path().join("archive.exa");
        let output = std::fs::File::create(&archive)?;
        let options = Options::new().file_size(true);
        let mut builder = super::writer::Writer::with_options(output, options)?;
        builder.add_dir_all("test/fixtures/version1/tiny_tree")?;
        builder.finish()?;

        // verify the entries appear with file/link sizes
        let reader = super::reader::Entries::new(&archive)?;
        assert!(!reader.is_encrypted());
        let mut entries: Vec<(String, Option<u64>)> = reader
            .filter_map(|e| e.ok())
            .map(|e| (e.name().to_owned(), e.size()))
            .collect();
        entries.sort();
        assert_eq!(entries.len(), 9);
        #[cfg(target_family = "unix")]
        let expected: Vec<(String, Option<u64>)> = vec![
            ("tiny_tree".into(), None),
            ("tiny_tree/file-a.txt".into(), Some(23 as u64)),
            ("tiny_tree/file-b.txt".into(), Some(31 as u64)),
            ("tiny_tree/file-c.txt".into(), Some(30 as u64)),
            ("tiny_tree/link-to-c".into(), Some(10 as u64)),
            ("tiny_tree/sub".into(), None),
            ("tiny_tree/sub/empty-dir".into(), None),
            ("tiny_tree/sub/empty-file".into(), Some(0 as u64)),
            ("tiny_tree/sub/file-1.txt".into(), Some(25 as u64)),
        ];
        #[cfg(target_family = "windows")]
        let expected: Vec<(String, Option<u64>)> = vec![
            ("tiny_tree".into(), None),
            ("tiny_tree\\file-a.txt".into(), Some(24 as u64)),
            ("tiny_tree\\file-b.txt".into(), Some(32 as u64)),
            ("tiny_tree\\file-c.txt".into(), Some(31 as u64)),
            ("tiny_tree\\link-to-c".into(), Some(10 as u64)),
            ("tiny_tree\\sub".into(), None),
            ("tiny_tree\\sub\\empty-dir".into(), None),
            ("tiny_tree\\sub\\empty-file".into(), Some(0 as u64)),
            ("tiny_tree\\sub\\file-1.txt".into(), Some(26 as u64)),
        ];
        for (a, b) in entries.iter().zip(expected.iter()) {
            assert_eq!(a, b);
        }

        Ok(())
    }

    #[test]
    fn test_create_list_metadata() -> Result<(), Error> {
        // create the archive
        let outdir = tempdir()?;
        let archive = outdir.path().join("archive.exa");
        let output = std::fs::File::create(&archive)?;
        let options = Options::new().metadata(true);
        let mut builder = super::writer::Writer::with_options(output, options)?;
        builder.add_file("test/fixtures/version1/tiny_tree/file-a.txt", None)?;
        builder.finish()?;

        // verify the entries appear with metadata
        let reader = super::reader::Entries::new(&archive)?;
        assert!(!reader.is_encrypted());
        for result in reader {
            let entry = result?;
            // probably only mtime is reliable across platforms
            assert!(entry.mtime().is_some());
        }

        Ok(())
    }

    #[test]
    fn test_create_list_extract_encryption() -> Result<(), Error> {
        // git does not track empty directories
        std::fs::create_dir_all("test/fixtures/version1/tiny_tree/sub/empty-dir")?;
        // create the archive
        let outdir = tempdir()?;
        let archive = outdir.path().join("archive.exa");
        let output = std::fs::File::create(&archive)?;
        let mut builder = super::writer::Writer::new(output)?;
        builder.enable_encryption(
            super::KeyDerivation::Argon2id,
            super::Encryption::AES256GCM,
            "Passw0rd!",
        )?;
        builder.add_dir_all("test/fixtures/version1/tiny_tree")?;
        builder.finish()?;

        // verify the entries appear as expected
        let mut reader = super::reader::Entries::new(&archive)?;
        assert!(reader.is_encrypted());
        reader.enable_encryption("Passw0rd!")?;
        let mut entries: Vec<String> = reader
            .filter_map(|e| e.ok())
            .map(|e| e.name().to_owned())
            .collect();
        entries.sort();
        assert_eq!(entries.len(), 9);
        #[cfg(target_family = "unix")]
        let expected: Vec<String> = vec![
            "tiny_tree".into(),
            "tiny_tree/file-a.txt".into(),
            "tiny_tree/file-b.txt".into(),
            "tiny_tree/file-c.txt".into(),
            "tiny_tree/link-to-c".into(),
            "tiny_tree/sub".into(),
            "tiny_tree/sub/empty-dir".into(),
            "tiny_tree/sub/empty-file".into(),
            "tiny_tree/sub/file-1.txt".into(),
        ];
        #[cfg(target_family = "windows")]
        let expected: Vec<String> = vec![
            "tiny_tree".into(),
            "tiny_tree\\file-a.txt".into(),
            "tiny_tree\\file-b.txt".into(),
            "tiny_tree\\file-c.txt".into(),
            "tiny_tree\\link-to-c".into(),
            "tiny_tree\\sub".into(),
            "tiny_tree\\sub\\empty-dir".into(),
            "tiny_tree\\sub\\empty-file".into(),
            "tiny_tree\\sub\\file-1.txt".into(),
        ];
        for (a, b) in entries.iter().zip(expected.iter()) {
            assert_eq!(a, b);
        }

        // extract the archive and verify everything
        let mut reader = super::reader::from_file(&archive)?;
        assert!(reader.is_encrypted());
        reader.enable_encryption("Passw0rd!")?;
        reader.extract_all(outdir.path())?;

        // the symbolic link (has expected bytes)
        if cfg!(target_family = "unix") {
            // links do not work properly on windows, there are several issues
            // both in reading and writing symbolic links
            let link = outdir.path().join("tiny_tree").join("link-to-c");
            let link_bytes = read_link(&link)?;
            let expected_link: Vec<u8> = "file-c.txt".as_bytes().to_vec();
            assert_eq!(link_bytes, expected_link);
        }

        // the empty directory (should exist)
        let empty_dir = outdir
            .path()
            .join("tiny_tree")
            .join("sub")
            .join("empty-dir");
        let metadata = std::fs::metadata(&empty_dir)?;
        assert!(metadata.is_dir());

        // the empty file (is empty)
        let empty_file = outdir
            .path()
            .join("tiny_tree")
            .join("sub")
            .join("empty-file");
        let metadata = std::fs::metadata(&empty_file)?;
        assert_eq!(metadata.len(), 0);

        // the other files (have expected content)
        let actual = std::fs::read_to_string(outdir.path().join("tiny_tree").join("file-a.txt"))?;
        #[cfg(target_family = "unix")]
        assert_eq!(actual, "mary had a little lamb\n");
        #[cfg(target_family = "windows")]
        assert_eq!(actual, "mary had a little lamb\r\n");
        let actual = std::fs::read_to_string(outdir.path().join("tiny_tree").join("file-b.txt"))?;
        #[cfg(target_family = "unix")]
        assert_eq!(actual, "whose fleece was white as snow\n");
        #[cfg(target_family = "windows")]
        assert_eq!(actual, "whose fleece was white as snow\r\n");
        let actual = std::fs::read_to_string(outdir.path().join("tiny_tree").join("file-c.txt"))?;
        #[cfg(target_family = "unix")]
        assert_eq!(actual, "and everywhere that Mary went\n");
        #[cfg(target_family = "windows")]
        assert_eq!(actual, "and everywhere that Mary went\r\n");
        let actual = std::fs::read_to_string(
            outdir
                .path()
                .join("tiny_tree")
                .join("sub")
                .join("file-1.txt"),
        )?;
        #[cfg(target_family = "unix")]
        assert_eq!(actual, "the lamb was sure to go.\n");
        #[cfg(target_family = "windows")]
        assert_eq!(actual, "the lamb was sure to go.\r\n");
        Ok(())
    }
}
