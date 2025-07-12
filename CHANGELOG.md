# Changelog

All notable changes to this project will be documented in this file.

## Unreleased

### Added

### Changed

### Fixed
- Password authentication with second factor.

## [0.3.2](https://github.com/flowerysong/pam_okta_auth/releases/tag/v0.3.2) - 2025-07-10

### Changed
- Smaller dependency tree from version bump to toml 0.9.

## [0.3.1](https://github.com/flowerysong/pam_okta_auth/releases/tag/v0.3.1) - 2025-07-07

### Fixed
- The custom User-Agent correctly reflects the name of the software in use.

## [0.3.0](https://github.com/flowerysong/pam_okta_auth/releases/tag/v0.3.0) - 2025-07-07

### Added
- `debug` config flag
- Number Challenge handling

### Changed
- Primary authentication is less hacky.
- HTTP requests send a custom User-Agent header instead of the library's default.

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
