# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- Breaking: removed snapshot-based package metadata persistence and shared S3 `__rustaccio_meta/state.json` package snapshots. Package metadata is now always sidecar-authoritative (`package.json`), and local `state.json` persists auth/session/token records only.

## [0.9.0] - 2026-02-14

### Added

- CI: MinIO integration test job that spins up MinIO and runs S3 backend tests on every push and PR.

## [0.8.0] - 2026-02-14

### Fixed

- Package manifest `versions` object now preserves insertion (publish) order instead of sorting lexicographically, matching Verdaccio behavior.

## [0.7.0] - 2026-02-14

### Changed

- CI: increased Docker publish workflow timeout from 45 to 120 minutes.

## [0.6.0] - 2026-02-14

### Fixed

- Docker build: pass `CARGO_BUILD_JOBS` as env var to `cargo-chef cook` instead of unsupported `-j` flag.

## [0.5.0] - 2026-02-14

### Fixed

- Web UI: content area no longer overflows viewport width (added `min-width: 0` to cards/grids and `overflow: hidden` to content container).

### Changed

- Docker build: `cargo chef cook` now respects `CARGO_PROFILE` build arg, using the `dist` profile when specified instead of always using `release`.
- Switched Docker runtime base image to distroless (`gcr.io/distroless/cc-debian12:nonroot`).
- Improved config loading and runtime setup.
- CI: made sccache optional when GHA cache is unavailable.

## [0.4.0] - 2026-02-14

### Added

- `RUSTACCIO_CONFIG_BASE64` support for loading base64-encoded Verdaccio-style YAML configuration from environment variables.
- Validation and test coverage for `RUSTACCIO_CONFIG_BASE64` success/failure paths and conflicts with `RUSTACCIO_CONFIG`.
- New `justfile` with common local development and build commands.
- Project logo asset and updated README branding.
- Tagged-release binary artifact publishing in CI (`rustaccio-linux-amd64` attached to GitHub releases).

### Changed

- Config loading flow refactor to unify YAML/env parsing paths while preserving precedence (`defaults < env config source < --config file < env overrides`).
- Built-in web UI redesign across package listing, package details, login, and settings views, including improved responsive layout and accessibility polish.
- CI and container build pipeline updates for faster, more reliable release builds (cache/sccache and dist-profile build path improvements).
- Docker and release documentation updated to reflect the revised build/release workflow.

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
