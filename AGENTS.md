# AGENTS.md

Guidance for coding agents working in `rustaccio`.

## Non-Negotiable Rules

1. Run validation after every unit of work. A unit of work is any coherent code or config edit before starting the next edit.
2. Never bypass git hooks. Do not use `--no-verify` for commits or pushes.
3. Keep CI parity locally. If a CI job would fail, your work is not done.
4. Do not introduce `unsafe` code. This repo already enforces `#![forbid(unsafe_code)]`.
5. Do not ignore warnings. Treat warnings as defects and fix them.

## Required Validation Loop

Run these after every unit of work:

```bash
just check
cargo test --workspace --all-targets --locked
```

Run this full gate before finalizing a task, opening a PR, or asking for review:

```bash
cargo fmt --all -- --check
cargo check --workspace --all-targets --all-features --locked
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features --all-targets --locked
cargo test --workspace --no-default-features --all-targets --locked
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --all-features --no-deps --locked
```

If your changes touch S3/tarball backend behavior, also run integration coverage:

```bash
just minio-up
just test-s3-it
just minio-down
```

## Git Hooks

Install hooks once per clone:

```bash
lefthook install
```

Run hooks manually before commit when needed:

```bash
lefthook run pre-commit
```

If a hook fails, fix the underlying issue. Do not bypass hooks.

## Rust Engineering Standards

1. Prefer explicit error propagation with `Result` and typed errors (`thiserror`) over panics.
2. Avoid `unwrap()` and `expect()` in production paths. If unavoidable, document why at the call site.
3. Keep async code non-blocking. Avoid blocking I/O or long CPU work on async executor threads without offloading.
4. Use structured logging/tracing fields (for example `tracing::info!(key = %value, ...)`) for operational visibility.
5. Keep modules focused and cohesive; prefer small, composable functions.
6. Add or update tests for every behavior change:
   - Unit tests for isolated logic.
   - Integration tests in `tests/` for API/runtime behavior.
7. Preserve feature-flag compatibility (`default`, `all-features`, and `no-default-features` paths).
8. Keep formatting canonical via `rustfmt`; keep lint clean under clippy with `-D warnings`.

## Runtime Modes Contract

Rustaccio has two valid operating modes. Agents must preserve both.

1. `self-hosted / self-managed` mode:
   - Must run with local/simple defaults only.
   - No external infra required (no Redis, no Postgres, no OTel collector, no external policy service).
   - Memory/local backends must remain first-class:
     - `RUSTACCIO_RATE_LIMIT_BACKEND=none|memory`
     - `RUSTACCIO_QUOTA_BACKEND=none|memory`
     - `RUSTACCIO_POLICY_BACKEND=local`
     - `RUSTACCIO_MANAGED_MODE=false`
   - Do not force strict guardrails in this mode.

2. `managed` mode:
   - Enabled via `RUSTACCIO_MANAGED_MODE=true`.
   - Stricter guardrails are expected and enforced.
   - External backends (Redis/Postgres/OTel/policy service) are opt-in, not implicit defaults.

### Mode-Safety Requirements for Changes

1. Any change touching auth/admin/policy/governance/storage must not regress simple mode behavior.
2. Managed-mode safeguards must be additive and explicitly gated behind config/env/feature flags.
3. Never make Redis/Postgres/OTel/policy dependencies mandatory for core startup.
4. Document mode impacts in `README.md` when behavior/config changes.
5. Add/update tests to cover both:
   - simple local path
   - managed/strict path when relevant

## Change Discipline

1. Make the smallest safe change that solves the task.
2. Validate immediately after each unit of work.
3. If validation fails, stop and fix before doing more edits.
4. Update docs (`README.md`, config examples) when public behavior or configuration changes.
5. Update `CHANGELOG.md` for user-visible changes.

## Definition of Done

A task is done only when:

1. Code, tests, and docs are updated as needed.
2. Required validation commands pass locally.
3. Pre-commit hooks pass without bypassing.
4. No new warnings are introduced.
