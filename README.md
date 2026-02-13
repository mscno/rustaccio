# rustaccio

A Rust/Tokio/Axum npm registry proxy inspired by Verdaccio core behavior.

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

## Run

Run with defaults (no config file):

```bash
cargo run
```

Run with YAML config:

```bash
cargo run -- --config ./config.yml
```

Run with help:

```bash
cargo run -- --help
```

`--config` loads the given YAML file and fails fast if the file cannot be read or parsed.
`RUSTACCIO_CONFIG` remains available as an environment-variable alternative.
Merge precedence is: defaults < `RUSTACCIO_CONFIG` file < `--config` file < environment variables.

`main` now delegates to library runtime (`rustaccio::runtime::run_from_env()`), so the same code path is used for standalone and embedded usage.

Environment variables:

- `RUSTACCIO_BIND` (default `127.0.0.1:4873`)
- `RUSTACCIO_DATA_DIR` (default `.rustaccio-data`)
- `RUSTACCIO_CONFIG` (optional Verdaccio-style YAML; loads `packages` ACL rules + `uplinks`)
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
- `RUSTACCIO_KEEP_ALIVE_TIMEOUT` (seconds, optional)
- `RUSTACCIO_LOG_LEVEL` (default `info`)
- `RUSTACCIO_LOG_FORMAT` (`pretty`, `compact`, or `json`, default `pretty`)
- `RUST_LOG` (optional full tracing filter; overrides default `rustaccio=<level>,tower_http=info`)
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

- `s3` feature enables native S3 tarball backend support (enabled by default).
- Disable with `--no-default-features` if you want local-only tarball storage.

## Test

```bash
cargo test
```

Quality gate:

```bash
cargo clippy --all-targets --all-features -- -D warnings
```

File-size gate (enforced by `tests/file_length.rs`): every Rust source file in `src/` and `tests/` must be `<= 400` lines.
The gate is currently disabled by default; enable it explicitly with:

```bash
RUSTACCIO_ENFORCE_FILE_LENGTH=1 cargo test --test file_length
```

## Library Embedding

You can use `rustaccio` as a library and inject your own in-process auth implementation:

```rust
use rustaccio::{auth::AuthHook, config::Config, runtime};
use std::sync::Arc;

// implement AuthHook in your crate
let cfg = Config::from_env();
let custom_hook: Arc<dyn AuthHook> = Arc::new(MyHook::default());
runtime::run(cfg, Some(custom_hook)).await?;
```

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
