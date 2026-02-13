# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- GitHub Actions CI for formatting, clippy, full-feature tests, no-default-feature tests, and file-length gate.
- Multi-stage Docker build with non-root runtime defaults.
- GitHub Actions workflow to build and publish multi-arch container images to GHCR on version tags.
- S3 TLS CA bundle controls and richer S3 error reporting.

## [0.1.0] - 2026-02-13

### Added

- Verdaccio-compatible npm registry proxy core API surface.
- Config loading from defaults, YAML config, CLI `--config`, and environment variables.
- Local and S3 tarball storage backends.
- Pluggable auth backends (local, HTTP plugin, embedded `AuthHook`).
- Built-in web UI routes and parity test suite.
