# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.4.1] - 2020-11-25
### Changed
- Fixed typo in 1.4.0 (Thanks @cham423!)

## [1.4.0] - 2020-11-22
### Changed
- Added some error state checks and retry logic to pastebin scraping (#116)
- Refactored paste inputs to use a base class

### Added
- Support for ix.io (#95)
- Additional unit tests (pytest still has some issues with import paths on travis)


## [1.3.2] - 2020-02-15
### Changed
Minor patch fixing error in email yara regexp

## [1.3.1] - 2020-02-15
### Changed
- Tweaked base64.yar to ignore data uris that contain numbers
- Improved error handling around missing pastes (404s)
- Fixed slexy timeout/rapid requests
- Began ignoring CSS (.css), SASS (.scss), and Unreal asset (.uasset) files by default for GitHub
- Fixed github filename blacklist being ignored
- GitHub now uses file blob hashes instead of commit ids for paste_id. This is to prevent collision for commits with multiple matching files
- Reduced false positives returned from password_list rule
- Removed email_list rule (superseded) by email_filter

### Added
- HTTP Output (#104)

## [1.2.1] - 2019-12-29
### Changed
- move config file to ~/.config
- move custom yara rules
- refactor yara rules location

## [1.2.0] - 2019-12-28
### Added
- Changelog
- travis CI
- PyPi Installation

### Changed
- FilePaths to enable pip
