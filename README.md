# rustaccio

![Rustaccio logo](docs/logo.png)

A Rust/Tokio/Axum npm registry proxy inspired by Verdaccio core behavior.

## Compatibility Policy

Rustaccio prioritizes npm client compatibility for common Verdaccio workflows (install, publish, dist-tags, auth, and uplink proxying). It does not guarantee byte-for-byte parity with Verdaccio internals or edge-case behavior; known differences and current limits are documented in [Verdaccio Differences and Limits](#verdaccio-differences-and-limits).

## Quick Start

1. Copy the example config:

```bash
cp config.example.yml config.yml
```

2. Start the server with that config:

```bash
cargo run -- --config ./config.yml
```

3. Point npm to Rustaccio:

```bash
npm config set registry http://127.0.0.1:4873/
```

## Deployment

Standalone with defaults (no config file):

```bash
cargo run
```

Standalone with explicit config file:

```bash
cargo run -- --config ./config.yml
```

Standalone help:

```bash
cargo run -- --help
```

Release binary:

```bash
cargo build --release
./target/release/rustaccio --config ./config.yml
```

Maximum-optimization distribution build:

```bash
cargo build --profile dist
./target/dist/rustaccio --config ./config.yml
```

Container (local build + run):

```bash
docker build -t rustaccio:local .
# Lower memory pressure on constrained builders (slower compile):
docker build --build-arg CARGO_BUILD_JOBS=1 -t rustaccio:local .
docker run --rm -p 4873:4873 \
  -v "$(pwd)/.rustaccio-data:/var/lib/rustaccio/data" \
  -v "$(pwd)/config.yml:/etc/rustaccio/config.yml:ro" \
  -e RUSTACCIO_CONFIG=/etc/rustaccio/config.yml \
  rustaccio:local
```

The Docker image compiles `rustaccio` with `--features s3` by default.
The image does not include `config.example.yml`; mount your own config and set `RUSTACCIO_CONFIG`.

`--config` loads the given YAML file and fails fast if the file cannot be read or parsed.
`RUSTACCIO_CONFIG` and `RUSTACCIO_CONFIG_BASE64` remain available as environment-variable alternatives.
Unified merge precedence is:

`defaults < RUSTACCIO_CONFIG or RUSTACCIO_CONFIG_BASE64 < --config file < environment variables`.

`main` delegates to library runtime (`rustaccio::runtime::run_from_env()`), so standalone and embedded usage share the same config/runtime path.
The full `RUSTACCIO_*` environment variable list is generated into `.env.example` via `cargo run --bin sync_examples`.

Environment variables:

- `RUSTACCIO_BIND` (default `127.0.0.1:4873`)
- `PORT` (optional platform-assigned port; when set, rustaccio binds to `0.0.0.0:$PORT` and this takes precedence over `RUSTACCIO_BIND`)
- `RUSTACCIO_DATA_DIR` (default `.rustaccio-data`)
- `RUSTACCIO_CONFIG` (optional Verdaccio-style YAML; loads `packages` ACL rules + `uplinks`)
- `RUSTACCIO_CONFIG_BASE64` (optional base64-encoded Verdaccio-style YAML; mutually exclusive with `RUSTACCIO_CONFIG`)
- `RUSTACCIO_UPSTREAM` (optional, eg `https://registry.npmjs.org`)
- `RUSTACCIO_WEB_LOGIN` (default `false`; enables `/-/v1/login*` endpoints)
- `RUSTACCIO_WEB_ENABLE` (default `true`)
- `RUSTACCIO_WEB_TITLE` (default `Rustaccio`; used by built-in web UI title)
- `RUSTACCIO_PUBLISH_CHECK_OWNERS` (default `false`; enforces owner-only package mutations)
- `RUSTACCIO_PASSWORD_MIN` (default `3`)
- `RUSTACCIO_LOGIN_SESSION_TTL_SECONDS` (default `120`)
- `RUSTACCIO_MAX_BODY_SIZE` (default `50mb`, accepts `kb|mb|gb` suffixes)
- `RUSTACCIO_AUDIT_ENABLED` (default `true`)
- `RUSTACCIO_URL_PREFIX` (default `/`)
- `RUSTACCIO_TRUST_PROXY` (default `false`)
- `RUSTACCIO_KEEP_ALIVE_TIMEOUT` (seconds, optional; applied as HTTP/1 keep-alive/header-read timeout)
- `RUSTACCIO_REQUEST_TIMEOUT_SECS` (default `30`, clamps `1..=300`)
- `RUSTACCIO_LOG_LEVEL` (default `info`)
- `RUSTACCIO_LOG_FORMAT` (`pretty`, `compact`, or `json`, default `pretty`)
- `RUSTACCIO_VERBOSE_DEP_LOGS` (default `false`; set `true`/`1` to keep noisy dependency targets at your chosen `RUST_LOG` level)
- `RUST_LOG` (optional full tracing filter; overrides default `rustaccio=<level>,tower_http=info`)
- `RUSTACCIO_TOKIO_WORKER_THREADS` (default `min(max(available_parallelism, 2), 8)`)
- `RUSTACCIO_TOKIO_MAX_BLOCKING_THREADS` (default `64`)
- `RUSTACCIO_TOKIO_THREAD_STACK_SIZE` (bytes, default `1048576`)
- `RUSTACCIO_UPSTREAM_CONNECT_TIMEOUT_SECS` (default `3`)
- `RUSTACCIO_UPSTREAM_TIMEOUT_SECS` (default `20`)
- `RUSTACCIO_UPSTREAM_POOL_IDLE_TIMEOUT_SECS` (default `30`)
- `RUSTACCIO_UPSTREAM_POOL_MAX_IDLE_PER_HOST` (default `4`)
- `RUSTACCIO_UPSTREAM_TCP_KEEPALIVE_SECS` (default `30`)
- `RUSTACCIO_AUTH_BACKEND` (`local` or `http`, default `local`)
- `RUSTACCIO_AUTH_HTTP_BASE_URL` (required for `http` auth backend)
- `RUSTACCIO_AUTH_HTTP_ADDUSER_ENDPOINT` (default `/adduser`)
- `RUSTACCIO_AUTH_HTTP_LOGIN_ENDPOINT` (default `/authenticate`)
- `RUSTACCIO_AUTH_HTTP_CHANGE_PASSWORD_ENDPOINT` (default `/change-password`)
- `RUSTACCIO_AUTH_HTTP_REQUEST_AUTH_ENDPOINT` (optional token->identity hook for custom auth middleware parity)
- `RUSTACCIO_AUTH_HTTP_ALLOW_ACCESS_ENDPOINT` (optional ACL override hook endpoint)
- `RUSTACCIO_AUTH_HTTP_ALLOW_PUBLISH_ENDPOINT` (optional ACL override hook endpoint)
- `RUSTACCIO_AUTH_HTTP_ALLOW_UNPUBLISH_ENDPOINT` (optional ACL override hook endpoint)
- `RUSTACCIO_AUTH_EXTERNAL_MODE` (default `false`; disables local user/token/web-login endpoints)
- `RUSTACCIO_AUTH_HTTP_TIMEOUT_MS` (default `5000`)
- `RUSTACCIO_TARBALL_BACKEND` (`local` or `s3`, default `local`)
- `RUSTACCIO_S3_BUCKET` (required for `s3` backend)
- `RUSTACCIO_S3_REGION` (default `us-east-1`)
- `RUSTACCIO_S3_ENDPOINT` (optional, eg MinIO/LocalStack endpoint)
- `RUSTACCIO_S3_ACCESS_KEY_ID` / `RUSTACCIO_S3_SECRET_ACCESS_KEY` (optional static credentials)
- `RUSTACCIO_S3_PREFIX` (optional key prefix)
- `RUSTACCIO_S3_FORCE_PATH_STYLE` (default `true`)
- `RUSTACCIO_S3_CA_BUNDLE` (optional PEM bundle path for S3 TLS trust; falls back to common system bundle paths when present)

Build features:

- `s3` feature enables native S3 tarball backend support (disabled by default for a leaner production binary).
- Enable with `--features s3` when you need S3 tarball storage.

## CI and Releases

- Rust CI is in `.github/workflows/ci.yml` and runs `fmt`, `check`, `clippy -D warnings`, tests (`all-features` and `no-default-features`), and docs with `-D warnings`.
- Container publish is in `.github/workflows/docker-publish.yml` and pushes multi-arch images to `ghcr.io/<owner>/<repo>` on version tags (`vX.Y.Z`).
- Keep a Changelog format changelog lives in `CHANGELOG.md`.

## Test

```bash
cargo test
```

## Just Commands

```bash
just          # default: check + test
just check
just test
just build    # fast local release profile
just dist     # fully optimized distribution profile
just serve
just serve ./config.yml
```

## Git Hooks (lefthook)

Install and enable local pre-commit hooks:

```bash
brew install lefthook
lefthook install
```

Run hooks manually:

```bash
lefthook run pre-commit
```

Configured pre-commit checks:

- `cargo fmt --all -- --check`
- `cargo check --workspace --all-targets --locked`
- `cargo clippy --workspace --all-targets --all-features -- -D warnings`
- `cargo test --workspace --all-targets --locked --quiet`

Quality gate:

```bash
cargo clippy --workspace --all-targets --all-features -- -D warnings
```

## Library Embedding

### User-Owned `main` with `--config`

If you want your own binary entrypoint but keep rustaccio runtime/config behavior:

```rust
use rustaccio::{config::Config, runtime};
use std::{error::Error, path::PathBuf};

fn parse_config_arg() -> Option<PathBuf> {
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        if arg == "--config" || arg == "-c" {
            return args.next().map(PathBuf::from);
        }
        if let Some(value) = arg.strip_prefix("--config=") {
            return Some(PathBuf::from(value));
        }
    }
    None
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let cfg = if let Some(path) = parse_config_arg() {
        Config::from_env_with_config_file(path)
            .map_err(|msg| std::io::Error::new(std::io::ErrorKind::InvalidInput, msg))?
    } else {
        Config::from_env()
    };

    runtime::run_standalone(cfg).await?;
    Ok(())
}
```

### Custom `AuthHook` Implementation

```rust
use async_trait::async_trait;
use rustaccio::{auth::AuthHook, error::RegistryError, models::AuthIdentity};

#[derive(Default)]
struct CompanyAuthHook;

#[async_trait]
impl AuthHook for CompanyAuthHook {
    async fn authenticate_request(
        &self,
        token: &str,
        _method: &str,
        _path: &str,
    ) -> Result<Option<AuthIdentity>, RegistryError> {
        if token == "internal-token" {
            return Ok(Some(AuthIdentity {
                username: Some("ci-bot".to_string()),
                groups: vec!["publishers".to_string()],
            }));
        }
        Ok(None)
    }

    async fn allow_publish(
        &self,
        identity: Option<AuthIdentity>,
        _package_name: &str,
    ) -> Result<Option<bool>, RegistryError> {
        let can_publish = identity
            .as_ref()
            .map(|id| id.groups.iter().any(|g| g == "publishers"))
            .unwrap_or(false);
        Ok(Some(can_publish))
    }
}
```

### Integrate into an Existing Axum Server

```rust
use axum::{Router, routing::get};
use rustaccio::{app::build_router, runtime};
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut cfg = rustaccio::config::Config::from_env();

    // Router::nest("/registry", ...) strips the prefix before dispatch.
    // Keep url_prefix as "/" in this mode.
    cfg.url_prefix = "/".to_string();

    let state = runtime::build_state(&cfg, Some(Arc::new(CompanyAuthHook::default()))).await?;
    let registry_router = build_router(state);

    let app = Router::new()
        .route("/healthz", get(|| async { "ok" }))
        .nest("/registry", registry_router);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await?;
    axum::serve(listener, app).await?;
    Ok(())
}
```

If you instead run rustaccio at the root path (not nested) behind a reverse proxy prefix, set `RUSTACCIO_URL_PREFIX` (for example `/registry`) so generated URLs include that prefix.

Key APIs:
- `rustaccio::auth::AuthHook`
- `rustaccio::storage::Store::open_with_options`
- `rustaccio::runtime::{build_state, run, run_from_env}`

## Implemented Core API Surface

- `/-/ping`
- `/-/whoami`
- `/-/user/*` (add user/login/logout)
- `/-/v1/search`
- `/-/all` and `/-/all/since` (deprecated response)
- `/-/admin/reindex` and `/-/admin/storage-health` (authenticated admin/ops endpoints)
- `/-/_view/starredByUser`
- `/-/package/:package/dist-tags` (+ `:tag`)
- `/-/npm/v1/user`
- `/-/npm/v1/tokens` (+ token delete)
- `/-/npm/v1/security/advisories/bulk`
- `/-/npm/v1/security/audits/quick`
- `/-/npm/v1/security/audits`
- `/-/v1/login`, `/-/v1/login_cli/:sessionId`, `/-/v1/done/:sessionId`
- Built-in web UI routes: `/`, `/-/web`, `/-/web/login`, `/-/web/settings`, `/-/web/detail/:package`, and static assets under `/-/web/static/*`
- Package/tarball/publish routes (including scoped packages):
  - `GET|HEAD /:package/:version?`
  - `GET|HEAD /:package/-/:filename`
  - `PUT /:package`
  - `PUT /:package/-rev/:revision`
  - `DELETE /:package/-rev/:revision`
  - `DELETE /:package/-/:filename/-rev/:revision`
  - legacy dist-tag `PUT /:package/:tag`

## Parity Coverage

The integration suite in `tests/parity.rs` currently validates:

- user creation/login/conflict/mismatch/logout/whoami
- package publish/get/tarball (including scoped and encoded scoped names)
- package version and dist-tag lookups (`/:package/:versionOrTag`)
- `?write=true` package reads for unpublish-style flows
- dist-tags add/remove/read + invalid body handling
- owner/star update flows
- deprecate + undeprecate package versions via metadata updates
- unpublish-version flow via `PUT /:package/-rev/:revision` metadata mutation
- `publish.check_owners` parity for write routes (`GET ?write=true`, publish/unpublish, dist-tags)
- external HTTP auth plugin backend (`add user`, `authenticate`, `change password`)
- HTTP request-auth hook contract (`token + method + path -> identity/groups`)
- pluggable tarball backend (`local` filesystem or `s3`)
- `tarball backend startup reindexing` to discover versions from existing backend tarballs before serving requests
- npm token APIs (list/create/delete + validation errors)
- profile APIs (get + password change validation)
- security audit endpoints (uplink proxy + local fallback response shape)
- search v1 with pagination semantics
- login session APIs (`/-/v1/login`, `/-/v1/login_cli/:sessionId`, `/-/v1/done/:sessionId`)
- `flags.webLogin` parity behavior (login routes disabled unless enabled)
- deprecated search endpoint (`/-/all`)
- uplink behavior for package metadata, dist-tags, search, and tarballs
- package ACL parity subset (`access`/`publish`/`unpublish`) with pattern matching and proxy uplink selection
- `url_prefix` path handling + `max_body_size` request enforcement
- built-in web UI serving, SPA fallback behavior, and `web.enable` route gating

## Verdaccio Differences and Limits

Rustaccio targets Verdaccio-compatible npm client behavior for core flows, but it is not a byte-for-byte Verdaccio clone. Current known differences/limits:

- ACL matching is a parity subset: rule matching supports common wildcard patterns, but not full Verdaccio/micromatch pattern semantics.
- Authorization parsing currently accepts `Bearer <token>` only.
- `:revision` route segments are accepted for Verdaccio-compatible route shapes, but revision values are not currently used for optimistic-concurrency checks.
- `/-/npm/v1/user` currently does not support 2FA updates (`tfa` payload returns `503`).
- Search (`/-/v1/search`) currently uses `text`, `size`, and `from`; score tuning params are ignored, and `total` reflects returned page size.
- YAML `listen` can be configured as a list for config compatibility, but the server currently binds a single effective socket address.
- `server.keepAliveTimeout` is currently mapped to an HTTP/1 header-read timeout for keep-alive connections (not a byte-for-byte Node.js socket timeout implementation).
- Built-in web UI is a lightweight Verdaccio-style SPA shell and static assets, not the full upstream Verdaccio frontend/runtime surface.
- Rustaccio-specific admin endpoints are exposed at `/-/admin/reindex` and `/-/admin/storage-health`.

## Architecture

- `src/api.rs`: HTTP routing + Verdaccio-compatible endpoint behavior
- `src/acl.rs`: package rule matching + access/publish/unpublish permission checks
- `src/config.rs`: env + Verdaccio-style YAML parsing (`packages`, `uplinks`)
- `src/storage.rs`: local state, persistence, auth/token/package operations + backend integration
- `src/auth_plugin.rs`: HTTP auth backend plugin client
- `src/tarball_backend.rs`: tarball backend abstraction (`local`, `s3`)
- `src/upstream.rs`: npm uplink proxy client for package/search/tarball
- `src/app.rs`: app state + router construction
- `src/web_ui.rs`: built-in Verdaccio-style web UI shell/assets and SPA route handling

## Plugin Config (YAML)

```yaml
auth:
  backend: http
  external: false
  http:
    baseUrl: http://auth.local:9000
    addUserEndpoint: /adduser
    loginEndpoint: /authenticate
    changePasswordEndpoint: /change-password
    requestAuthEndpoint: /request-auth
    allowAccessEndpoint: /allow-access
    allowPublishEndpoint: /allow-publish
    allowUnpublishEndpoint: /allow-unpublish
    timeoutMs: 5000

store:
  aws-s3-storage:
    bucket: npm-cache
    region: us-east-1
    endpoint: http://127.0.0.1:9001
    accessKeyId: minio
    secretAccessKey: miniopass
    prefix: tarballs/
    s3ForcePathStyle: true
```

## HTTP Auth Plugin Contract

The HTTP auth backend is called by core user endpoints and keeps the same external npm/Verdaccio API contract.

- `POST {baseUrl}{addUserEndpoint}` with `{ "username", "password" }`
- `POST {baseUrl}{loginEndpoint}` with `{ "username", "password" }`
- `POST {baseUrl}{changePasswordEndpoint}` with `{ "username", "old_password", "new_password" }`
- `POST {baseUrl}{requestAuthEndpoint}` with `{ "token", "method", "path" }` and response including:
  - `authenticated` (`true|false`, optional)
  - user identity: `username` or `user` or `name` (optional)
  - groups: `groups`/`roles` array or `group` scalar (optional)
- Optional ACL override callbacks:
  - `POST {baseUrl}{allowAccessEndpoint}`
  - `POST {baseUrl}{allowPublishEndpoint}`
  - `POST {baseUrl}{allowUnpublishEndpoint}`
  - request body includes `{ "package", "username", "groups", "identity" }`, response supports `{ "allowed": true|false }` or raw boolean

Behavior:

- `2xx` means success.
- Non-`2xx` propagates status and `error`/`message` from plugin JSON body when present.

## License

Licensed under either of:

- MIT (`LICENSE-MIT`)
- Apache-2.0 (`LICENSE-APACHE`)

## Embedded Auth Hook Contract

When embedding, implement `AuthHook`:
- `authenticate_request(token, method, path)` for token-to-identity mapping
- `allow_access(identity, package)` optional override for read permission
- `allow_publish(identity, package)` optional override for publish permission
- `allow_unpublish(identity, package)` optional override for unpublish permission
- optional: `add_user`, `authenticate`, `change_password` for user/profile/token flows

Returned identity (`AuthIdentity`) is used directly by package ACL rules (`access`, `publish`, `unpublish`) via `username` and `groups`.
If `allow_*` returns `Some(true|false)`, that decision overrides ACL; `None` falls back to ACL rules.
