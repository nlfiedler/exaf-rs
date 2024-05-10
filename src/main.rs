//
// Copyright (c) 2024 Nathan Fiedler
//
use clap::{arg, Command};
use exaf_rs::{writer::*, *};
use std::fs::File;
use std::path::{Path, PathBuf};

///
/// Create a pack file at the given location and add all of the named inputs.
///
/// Returns the total number of files added to the archive.
///
fn create_archive<P: AsRef<Path>>(
    archive: P,
    inputs: Vec<&PathBuf>,
    passwd: Option<&str>,
) -> Result<u64, Error> {
    let path_ref = archive.as_ref();
    let path = match path_ref.extension() {
        Some(_) => path_ref.to_path_buf(),
        None => path_ref.with_extension("exa"),
    };
    let output = File::create(path)?;
    let mut builder = Writer::new(output)?;
    if let Some(password) = passwd {
        builder.enable_encryption(
            exaf_rs::KeyDerivation::Argon2id,
            exaf_rs::Encryption::AES256GCM,
            password,
        )?;
    }
    let mut file_count: u64 = 0;
    for input in inputs {
        let metadata = input.metadata()?;
        if metadata.is_dir() {
            file_count += builder.add_dir_all(input)?;
        } else if metadata.is_file() {
            builder.add_file(input, None)?;
            file_count += 1;
        } else if metadata.is_symlink() {
            builder.add_symlink(input, None)?;
        }
    }
    builder.finish()?;
    Ok(file_count)
}

///
/// List all file entries in the archive.
///
fn list_contents<P: AsRef<Path>>(archive: P, passwd: Option<&str>) -> Result<(), Error> {
    let mut reader = exaf_rs::reader::Entries::new(archive)?;
    if reader.is_encrypted() && passwd.is_none() {
        Err(Error::Usage(
            "Archive is encrypted, use --password to provide one.".into(),
        ))
    } else {
        if let Some(password) = passwd {
            reader.enable_encryption(password)?;
        }
        for result in reader {
            match result {
                Ok(entry) => println!("{}", entry.name()),
                Err(err) => println!("error: {}", err),
            }
        }
        Ok(())
    }
}

///
/// Extract all of the files from the archive.
///
fn extract_contents<P: AsRef<Path>>(archive: P, passwd: Option<&str>) -> Result<u64, Error> {
    let mut reader = exaf_rs::reader::from_file(archive)?;
    if reader.is_encrypted() && passwd.is_none() {
        Err(Error::Usage(
            "Archive is encrypted, use --password to provide one.".into(),
        ))
    } else {
        if let Some(password) = passwd {
            reader.enable_encryption(password)?;
        }
        let path = std::env::current_dir()?;
        reader.extract_all(&path)
    }
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
                .arg_required_else_help(true)
                .arg(arg!(--password <PASSWD> "Password for encrypting the archive.")),
        )
        .subcommand(
            Command::new("list")
                .about("Lists the contents of an archive.")
                .short_flag('l')
                .arg(
                    arg!(archive: <ARCHIVE> "File path specifying the archive to read from.")
                        .value_parser(clap::value_parser!(PathBuf)),
                )
                .arg_required_else_help(true)
                .arg(arg!(--password <PASSWD> "Password for decrypting the archive.")),
        )
        .subcommand(
            Command::new("extract")
                .about("Extracts one or more files from an archive.")
                .short_flag('x')
                .arg(
                    arg!(archive: <ARCHIVE> "File path specifying the archive to read from.")
                        .value_parser(clap::value_parser!(PathBuf)),
                )
                .arg_required_else_help(true)
                .arg(arg!(--password <PASSWD> "Password for decrypting the archive.")),
        )
}

fn main() -> Result<(), Error> {
    let default_archive_path = PathBuf::from("archive.exa");
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
            let passwd = sub_matches
                .get_one::<String>("password")
                .map(|s| s.as_str());
            let file_count = create_archive(archive, inputs, passwd)?;
            println!("Added {} files to {}", file_count, archive);
        }
        Some(("list", sub_matches)) => {
            let archive = sub_matches
                .get_one::<PathBuf>("archive")
                .unwrap_or(&default_archive_path);
            let passwd = sub_matches
                .get_one::<String>("password")
                .map(|s| s.as_str());
            list_contents(archive, passwd)?;
        }
        Some(("extract", sub_matches)) => {
            let archive = sub_matches
                .get_one::<PathBuf>("archive")
                .unwrap_or(&default_archive_path);
            let passwd = sub_matches
                .get_one::<String>("password")
                .map(|s| s.as_str());
            let file_count = extract_contents(archive, passwd)?;
            println!("Extracted {} files", file_count)
        }
        _ => unreachable!(),
    }
    Ok(())
}
