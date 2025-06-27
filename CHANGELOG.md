# Changelog

All notable changes to this project will be documented in this file.

## Unreleased

### Added

### Changed

### Fixed

## [0.2.0](https://github.com/flowerysong/pam_okta_auth/releases/tag/v0.2.0) - 2025-06-27

### Added
- SELinux support
- Additional visible indicators of authentication progress
- HTTP proxy support
- autopush flag

### Changed
- OOB polling terminates early if the server indicates that the request was
  rejected by the user.
- Attempting to use a world-accessible config file will fail loudly.

### Fixed
- RPM build issues on RHEL 10

## [0.1.0](https://github.com/flowerysong/pam_okta_auth/releases/tag/v0.1.0) - 2025-06-26

### Added
- .deb package build using [nfpm](https://nfpm.goreleaser.com/)

### Fixed
- RPM building on EL8

## [0.0.1](https://github.com/flowerysong/pam_okta_auth/releases/tag/v0.0.1) - 2025-06-26

Initial release.
