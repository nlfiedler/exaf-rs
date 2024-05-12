# Change Log

All notable changes to this project will be documented in this file.
This project adheres to [Semantic Versioning](http://semver.org/).
This file follows the convention described at
[Keep a Changelog](http://keepachangelog.com/en/1.0.0/).

## [1.1.1] - 2024-05-11
### Fixed
- File slices were missing the `LN` header row if the file offset was non-zero.
  In the case of file slices, they are treated as regular files.
- Added `Clone` and `Debug` to public enums and structs.

## [1.1.0] - 2024-05-11
### Added
- `content_size()` to return content block size limit.
- `bytes_written()` on `Writer` that is updated for each content block as it is written.
- `LN` header for for files and links whose value is their length in bytes.
### Changed
- Format is now version **1.1** with the addition of `LN` header row.

## [1.0.0] - 2024-05-09
### Changed
- Initial release
