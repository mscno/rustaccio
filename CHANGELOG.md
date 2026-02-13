# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.3.0] - 2026-02-14

### Added

- Graceful shutdown handling for standalone runtime on `SIGTERM`/`Ctrl+C`.
- Additional runtime/config test coverage for timeout parsing, `audit.enabled` route gating, `web.enable` route gating, and invalid `RUSTACCIO_CONFIG` handling.
- Explicit compatibility policy and documented Verdaccio behavior differences/limits in `README.md`.

### Changed

- CI Rust job timeout increased from 30 to 60 minutes.
- `Config::from_env()` now returns `Result` and fails fast when `RUSTACCIO_CONFIG` is set but invalid/unreadable.
- Security audit endpoints now return `404` when audit middleware is disabled.
- Search endpoint now caps `size` to `250`.
- Store persistence and sidecar syncing were refactored to reduce unnecessary state cloning and filter uplink-cached package snapshots during serialization.
- Docker publish workflow now builds with `CARGO_BUILD_JOBS=1` for lower-memory builds.
- Docker runtime image hardening updated user creation with `useradd --no-log-init`.
- Dependency surface cleanup:
  - removed unused direct deps `bytes`, `futures-util`, and `http`
  - removed unused `reqwest` `stream` feature
  - moved `flate2` and `tar` to `dev-dependencies`
  - removed unused `chrono` `serde` feature
- Repo hygiene updates for local artifacts (`.gitignore`, `.dockerignore`).

### Removed

- Deprecated file-length gate test (`tests/file_length.rs`).

## [0.2.0] - 2026-02-14

### Added

- GitHub Actions CI for formatting, check, clippy, feature-matrix tests, and docs with warnings denied.
- Multi-stage Docker build with non-root runtime defaults.
- GitHub Actions workflow to build and publish multi-arch container images to GHCR on version tags.
- GitHub Actions release job for version tags that publishes a GitHub Release using the matching version section from `CHANGELOG.md`.
- README deployment and embedding examples for standalone, library-owned `main`, and Axum sidecar integration with a custom `AuthHook`.
- S3 TLS CA bundle controls and richer S3 error reporting.

## [0.1.0] - 2026-02-13

### Added

- Verdaccio-compatible npm registry proxy core API surface.
- Config loading from defaults, YAML config, CLI `--config`, and environment variables.
- Local and S3 tarball storage backends.
- Pluggable auth backends (local, HTTP plugin, embedded `AuthHook`).
- Built-in web UI routes and parity test suite.
