# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
