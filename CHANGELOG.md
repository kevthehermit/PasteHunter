# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]
### Changed
- Tweaked base64.yar to ignore data uris that contain numbers
- Improved error handling around missing pastes (404s)
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
