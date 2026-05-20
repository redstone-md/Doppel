# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Local certificate authority with on-demand, cached leaf-certificate minting.
- Identity profiles with built-in iPhone, Android, Windows and macOS
  fingerprints, plus support for user-supplied profiles.
- uTLS-based upstream dialer that produces a per-profile JA3/JA4 fingerprint.
- HTTP/1.1 round tripper and a profile-controlled HTTP/2 client with per-host
  connection pooling.
- Transparent decoding of gzip, brotli, zstd and deflate responses.
- Single-port SOCKS5 and HTTP CONNECT proxy with protocol auto-detection and a
  client-negotiation deadline.
- TLS interception that re-originates requests through the chosen profile.
- `doppel` command-line interface: `init`, `run`, `launch`, `profiles`,
  `ca`, `verify`.
- First-run setup wizard covering both OS and language-runtime trust stores.
- Application launcher mode for running HTTPS clients and Electron apps through
  Doppel without proxychains.
- Upstream SOCKS5 proxy support for `run`, `launch`, and `verify`.
- Profile-controlled HTTP/2 SETTINGS, initial WINDOW_UPDATE and header ordering.

### Known limitations

- The host kernel's TCP/IP fingerprint is not altered.

[Unreleased]: https://github.com/redstone-md/Doppel/commits/main
