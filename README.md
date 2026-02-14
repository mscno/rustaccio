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
# Build image with managed-platform backends enabled at compile-time:
docker build \
  --build-arg CARGO_FEATURES="s3,redis,postgres,otel" \
  -t rustaccio:saas .

docker run --rm -p 4873:4873 \
  -v "$(pwd)/.rustaccio-data:/var/lib/rustaccio/data" \
  -v "$(pwd)/config.yml:/etc/rustaccio/config.yml:ro" \
  -e RUSTACCIO_CONFIG=/etc/rustaccio/config.yml \
  rustaccio:local
```

The Docker image compiles `rustaccio` with `--features s3` by default.
Override compile-time features with `--build-arg CARGO_FEATURES=...` when you need optional backends:

- `redis` for distributed rate limiting (`RUSTACCIO_RATE_LIMIT_BACKEND=redis`)
- `postgres` for persistent quota backend (`RUSTACCIO_QUOTA_BACKEND=postgres`)
- `otel` for OTLP tracing export (`RUSTACCIO_OTEL_ENABLED=true`)

If a backend is configured at runtime without its compile-time feature, startup fails fast.
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
- `RUSTACCIO_PACKAGE_METADATA_AUTHORITY` (`sidecar`, default `sidecar`)
- `RUSTACCIO_STATE_COORDINATION_BACKEND` (`none`, `redis`, or `s3`, default `none`)
- `RUSTACCIO_STATE_COORDINATION_REDIS_URL` (required for `redis` state coordination backend)
- `RUSTACCIO_STATE_COORDINATION_LOCK_KEY` (default `rustaccio:state:lock`)
- `RUSTACCIO_STATE_COORDINATION_LEASE_MS` (default `5000`)
- `RUSTACCIO_STATE_COORDINATION_ACQUIRE_TIMEOUT_MS` (default `15000`)
- `RUSTACCIO_STATE_COORDINATION_POLL_INTERVAL_MS` (default `100`)
- `RUSTACCIO_STATE_COORDINATION_FAIL_OPEN` (default `false`)
- `RUSTACCIO_STATE_COORDINATION_S3_BUCKET` (required for `s3` state coordination backend)
- `RUSTACCIO_STATE_COORDINATION_S3_REGION` (default `us-east-1`)
- `RUSTACCIO_STATE_COORDINATION_S3_ENDPOINT` (optional, eg MinIO/LocalStack endpoint)
- `RUSTACCIO_STATE_COORDINATION_S3_ACCESS_KEY_ID` / `RUSTACCIO_STATE_COORDINATION_S3_SECRET_ACCESS_KEY` (optional static credentials)
- `RUSTACCIO_STATE_COORDINATION_S3_PREFIX` (default `rustaccio/state-locks/`)
- `RUSTACCIO_STATE_COORDINATION_S3_FORCE_PATH_STYLE` (default `false`)

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
cargo test --features s3
```

Run real S3-backend integration tests against local MinIO:

```bash
just minio-up
just test-s3-it
just minio-down
```

Run Redis/Postgres governance integration tests:

```bash
just governance-up
just test-governance-it
just governance-down
```

Defaults:

- MinIO API: `http://127.0.0.1:9002`
- MinIO console: `http://127.0.0.1:9003`
- Access key / secret: `minioadmin` / `minioadmin`
- Test bucket: `rustaccio-it`

Override integration test connection settings with:

- `RUSTACCIO_S3_IT_ENDPOINT`
- `RUSTACCIO_S3_IT_REGION`
- `RUSTACCIO_S3_IT_BUCKET`
- `RUSTACCIO_S3_IT_ACCESS_KEY`
- `RUSTACCIO_S3_IT_SECRET_KEY`

Governance integration test connection settings:

- `RUSTACCIO_REDIS_IT_URL` (default `redis://127.0.0.1:56379/`)
- `RUSTACCIO_POSTGRES_IT_URL` (default `postgres://postgres:postgres@127.0.0.1:55432/rustaccio`)

## Just Commands

```bash
just          # default: check + test
just check
just test
just build    # fast local release profile
just dist     # fully optimized distribution profile
just serve
just serve ./config.yml
just minio-up
just minio-down
just test-s3-it
just governance-up
just governance-down
just test-governance-it
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
- `/-/admin/reindex`, `/-/admin/storage-health`, and `/-/admin/policy-cache/invalidate` (admin/ops endpoints)
- `/-/_view/starredByUser`
- `/-/package/:package/dist-tags` (+ `:tag`)
- `/-/npm/v1/user`
- `/-/npm/v1/tokens` (+ token delete)
- `/-/npm/v1/security/advisories/bulk`
- `/-/npm/v1/security/audits/quick`
- `/-/npm/v1/security/audits`
- `/-/metrics` (optional, when `RUSTACCIO_METRICS_BACKEND=prometheus`)
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
- Rustaccio-specific admin endpoints are exposed at `/-/admin/reindex`, `/-/admin/storage-health`, and `/-/admin/policy-cache/invalidate`.

## Architecture

- `src/api.rs`: HTTP routing + Verdaccio-compatible endpoint behavior
- `src/acl.rs`: package rule matching + access/publish/unpublish permission checks
- `src/config.rs`: env + Verdaccio-style YAML parsing (`packages`, `uplinks`)
- `src/storage.rs`: local state, persistence, auth/token/package operations + backend integration
- `src/policy.rs`: policy engine abstraction (`external policy backend -> auth hook/plugin decisions -> ACL fallback`)
- `src/governance.rs`: opt-in governance controls (`rate limiting`, `quota`, `metrics`) via trait-based guards/backends
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
    endpoint: http://127.0.0.1:9002
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

## External Policy Backend (HTTP, via Env)

Policy decisions can be sourced from a dedicated HTTP backend and will run before auth-hook/plugin/ACL fallback.

Environment variables:

- `RUSTACCIO_POLICY_BACKEND=local|http` (default `local`)
- `RUSTACCIO_POLICY_HTTP_BASE_URL` (required when backend=`http`)
- `RUSTACCIO_POLICY_HTTP_DECISION_ENDPOINT` (default `/authorize`)
- `RUSTACCIO_POLICY_HTTP_TIMEOUT_MS` (default `3000`)
- `RUSTACCIO_POLICY_HTTP_CACHE_TTL_MS` (default `5000`, set `0` to disable cache)
- `RUSTACCIO_POLICY_HTTP_FAIL_OPEN` (default `false`)

Decision request payload includes:

- `action` (`access|publish|unpublish`)
- `package`
- `method`
- `path`
- identity context: `username`, `groups`, `identity`
- tenant context: `tenant`, `org_id`, `project_id` (from request headers when present)

Decision response:

- `{ "allowed": true|false }` or raw JSON boolean
- `401/403` is treated as an explicit deny
- Other non-`2xx`:
  - with `RUSTACCIO_POLICY_HTTP_FAIL_OPEN=true`: fall back to local policy chain
  - with `RUSTACCIO_POLICY_HTTP_FAIL_OPEN=false`: request fails with `502`

Cache control:

- `POST /-/admin/policy-cache/invalidate` clears in-memory external policy decision cache for the running instance.

## Governance Controls (Opt-In)

Rustaccio defaults to simple mode. Governance controls are disabled unless explicitly enabled via env.

Rate limiting:

- `RUSTACCIO_RATE_LIMIT_BACKEND=none|memory|redis` (default `none`)
- `RUSTACCIO_RATE_LIMIT_REQUESTS_PER_WINDOW` (default `0`, disabled)
- `RUSTACCIO_RATE_LIMIT_WINDOW_SECS` (default `60`)
- `RUSTACCIO_RATE_LIMIT_REDIS_URL` (required when backend=`redis`)
- `RUSTACCIO_RATE_LIMIT_FAIL_OPEN` (default `true`)

Quota enforcement:

- `RUSTACCIO_QUOTA_BACKEND=none|memory|postgres` (default `none`)
- `RUSTACCIO_QUOTA_REQUESTS_PER_DAY` (default `0`, disabled)
- `RUSTACCIO_QUOTA_DOWNLOADS_PER_DAY` (default `0`, disabled)
- `RUSTACCIO_QUOTA_PUBLISHES_PER_DAY` (default `0`, disabled)
- `RUSTACCIO_QUOTA_POSTGRES_URL` (required when backend=`postgres`)
- `RUSTACCIO_QUOTA_FAIL_OPEN` (default `true`)

Postgres quota migrations:

- Rustaccio applies quota schema migrations automatically on startup when `RUSTACCIO_QUOTA_BACKEND=postgres`.
- Migration files live under `migrations/` (current: `migrations/0001_quota_usage_table.sql`).

State write coordination (opt-in):

- `RUSTACCIO_STATE_COORDINATION_BACKEND=none|redis|s3` (default `none`)
- `RUSTACCIO_STATE_COORDINATION_REDIS_URL` (required when backend=`redis`)
- `RUSTACCIO_STATE_COORDINATION_LOCK_KEY` (default `rustaccio:state:lock`)
- `RUSTACCIO_STATE_COORDINATION_LEASE_MS` (default `5000`)
- `RUSTACCIO_STATE_COORDINATION_ACQUIRE_TIMEOUT_MS` (default `15000`)
- `RUSTACCIO_STATE_COORDINATION_POLL_INTERVAL_MS` (default `100`)
- `RUSTACCIO_STATE_COORDINATION_FAIL_OPEN` (default `false`)
- `RUSTACCIO_STATE_COORDINATION_S3_BUCKET` (required when backend=`s3`)
- `RUSTACCIO_STATE_COORDINATION_S3_REGION` (default `us-east-1`)
- `RUSTACCIO_STATE_COORDINATION_S3_ENDPOINT` (optional)
- `RUSTACCIO_STATE_COORDINATION_S3_ACCESS_KEY_ID`, `RUSTACCIO_STATE_COORDINATION_S3_SECRET_ACCESS_KEY` (optional)
- `RUSTACCIO_STATE_COORDINATION_S3_PREFIX` (default `rustaccio/state-locks/`)
- `RUSTACCIO_STATE_COORDINATION_S3_FORCE_PATH_STYLE` (default `false`)

Semantics:

- Coordinates write sections with scoped lease locks (`state` scope for auth/session persistence and `package:<name>` scope for package mutations).
- Prevents overlapping multi-instance write sections when all instances use the same coordination backend.
- This is a write-coordination primitive, not full multi-writer state conflict resolution.

Metrics endpoint:

- `RUSTACCIO_METRICS_BACKEND=none|prometheus` (default `none`)
- `RUSTACCIO_METRICS_PATH` (default `/-/metrics`)
- `RUSTACCIO_METRICS_REQUIRE_ADMIN` (default `true`)

Build features for external backends:

- `cargo build --features redis` for Redis rate limiter
- `cargo build --features postgres` for Postgres quota backend
- `cargo build --features otel` for OTLP span export

OpenTelemetry (opt-in):

- `RUSTACCIO_OTEL_ENABLED=false|true` (default `false`)
- `RUSTACCIO_OTEL_EXPORTER_OTLP_ENDPOINT` (for example `http://otel-collector:4318/v1/traces`)
- `RUSTACCIO_OTEL_SERVICE_NAME` (default `rustaccio`)

## Admin Endpoint Authorization

Admin endpoints are controlled by environment variables:

- `RUSTACCIO_MANAGED_MODE=false|true` (default `false`)
- `RUSTACCIO_ADMIN_ALLOW_ANY_AUTHENTICATED` (default `true`)
- `RUSTACCIO_ADMIN_USERS` (comma/space-separated usernames)
- `RUSTACCIO_ADMIN_GROUPS` (comma/space-separated groups/roles)

Behavior:

- If `RUSTACCIO_ADMIN_ALLOW_ANY_AUTHENTICATED=true`, any authenticated identity can call `/-/admin/*`.
- If `RUSTACCIO_ADMIN_ALLOW_ANY_AUTHENTICATED=false`, only identities whose username is in `RUSTACCIO_ADMIN_USERS` or whose group/role is in `RUSTACCIO_ADMIN_GROUPS` are allowed.
- Unauthenticated requests receive `401`; authenticated non-admin requests receive `403`.
- If `RUSTACCIO_MANAGED_MODE=true`, startup enforces stricter guardrails:
  - `RUSTACCIO_ADMIN_ALLOW_ANY_AUTHENTICATED=false`
  - at least one explicit admin principal in `RUSTACCIO_ADMIN_USERS` or `RUSTACCIO_ADMIN_GROUPS`
  - `auth.plugin.externalMode=true` (external identity provider mode)

Recommended managed-mode posture:

- Set `RUSTACCIO_MANAGED_MODE=true`.
- Set `RUSTACCIO_ADMIN_ALLOW_ANY_AUTHENTICATED=false`.
- Define a dedicated admin group from your control-plane identity provider, and set it in `RUSTACCIO_ADMIN_GROUPS`.

## Run Modes

Rustaccio now runs sidecar-authoritative package metadata in all modes.

| Mode | Tarball Backend | Metadata Authority | Governance Backends | Typical Use |
|---|---|---|---|---|
| Simple local | `local` | package sidecars (`package.json`) | none/memory | single-node, low ops |
| Shared object store | `s3` | package sidecars (`package.json`) | none/memory | multi-node with shared blob storage |
| Managed governance | `local` or `s3` | package sidecars (`package.json`) | Redis/Postgres/Prometheus/OTel | managed platform with limits/observability |
| External control-plane auth/policy | `local` or `s3` | package sidecars (`package.json`) | same as above | centralized identity/policy decisions |

Simple local mode defaults:

- `RUSTACCIO_TARBALL_BACKEND=local`
- `RUSTACCIO_PACKAGE_METADATA_AUTHORITY=sidecar`
- `RUSTACCIO_RATE_LIMIT_BACKEND=none`
- `RUSTACCIO_QUOTA_BACKEND=none`
- `RUSTACCIO_POLICY_BACKEND=local`
- `RUSTACCIO_MANAGED_MODE=false`

Managed hardening mode:

- `RUSTACCIO_MANAGED_MODE=true` enforces:
  - `RUSTACCIO_ADMIN_ALLOW_ANY_AUTHENTICATED=false`
  - explicit admin principals (`RUSTACCIO_ADMIN_USERS` or `RUSTACCIO_ADMIN_GROUPS`)
  - `auth.plugin.externalMode=true` (env: `RUSTACCIO_AUTH_EXTERNAL_MODE=true`)

## Deploying with Redis/Postgres Backends

### 1) Build image with required compile-time features

```bash
docker build \
  --build-arg CARGO_FEATURES="s3,redis,postgres,otel" \
  -t rustaccio:saas .
```

### 2) Runtime env for managed governance

Required for Redis rate limiter:

- `RUSTACCIO_RATE_LIMIT_BACKEND=redis`
- `RUSTACCIO_RATE_LIMIT_REDIS_URL=redis://redis:6379/`

Required for Postgres quotas:

- `RUSTACCIO_QUOTA_BACKEND=postgres`
- `RUSTACCIO_QUOTA_POSTGRES_URL=postgres://postgres:postgres@postgres:5432/rustaccio`

Recommended managed security baseline:

- `RUSTACCIO_MANAGED_MODE=true`
- `RUSTACCIO_AUTH_EXTERNAL_MODE=true`
- `RUSTACCIO_ADMIN_ALLOW_ANY_AUTHENTICATED=false`
- `RUSTACCIO_ADMIN_GROUPS=<control-plane-admin-group>`
- `RUSTACCIO_PACKAGE_METADATA_AUTHORITY=sidecar`
- `RUSTACCIO_STATE_COORDINATION_BACKEND=redis`
- `RUSTACCIO_STATE_COORDINATION_REDIS_URL=redis://redis:6379/`

Alternative coordination backend (if you prefer object-storage-native locking):

- `RUSTACCIO_STATE_COORDINATION_BACKEND=s3`
- `RUSTACCIO_STATE_COORDINATION_S3_BUCKET=<lock-bucket>`
- `RUSTACCIO_STATE_COORDINATION_S3_PREFIX=rustaccio/state-locks/`

Example container run:

```bash
docker run --rm -p 4873:4873 \
  -v "$(pwd)/.rustaccio-data:/var/lib/rustaccio/data" \
  -v "$(pwd)/config.yml:/etc/rustaccio/config.yml:ro" \
  -e RUSTACCIO_CONFIG=/etc/rustaccio/config.yml \
  -e RUSTACCIO_MANAGED_MODE=true \
  -e RUSTACCIO_AUTH_EXTERNAL_MODE=true \
  -e RUSTACCIO_ADMIN_ALLOW_ANY_AUTHENTICATED=false \
  -e RUSTACCIO_ADMIN_GROUPS=platform-admins \
  -e RUSTACCIO_PACKAGE_METADATA_AUTHORITY=sidecar \
  -e RUSTACCIO_RATE_LIMIT_BACKEND=redis \
  -e RUSTACCIO_RATE_LIMIT_REDIS_URL=redis://redis:6379/ \
  -e RUSTACCIO_STATE_COORDINATION_BACKEND=redis \
  -e RUSTACCIO_STATE_COORDINATION_REDIS_URL=redis://redis:6379/ \
  -e RUSTACCIO_QUOTA_BACKEND=postgres \
  -e RUSTACCIO_QUOTA_POSTGRES_URL=postgres://postgres:postgres@postgres:5432/rustaccio \
  -e RUSTACCIO_METRICS_BACKEND=prometheus \
  rustaccio:saas
```

Notes:

- `RUSTACCIO_RATE_LIMIT_FAIL_OPEN=true|false` controls availability vs strictness on Redis failures.
- `RUSTACCIO_QUOTA_FAIL_OPEN=true|false` controls availability vs strictness on Postgres failures.
- Postgres migrations for quotas run automatically at startup.

## Storage and Data Model

### Core persisted model

The local persisted state file (`<data_dir>/state.json`) stores only auth/session state:

- `users`
- `auth_tokens`
- `npm_tokens`
- `login_sessions`

`packages` is intentionally persisted as an empty map. Package metadata authority is sidecar-only.

Package runtime state (`PackageRecord`) contains:

- `manifest` (full package manifest JSON)
- `upstream_tarballs` (filename -> original upstream URL cache)
- `updated_at`
- `cached_from_uplink`

### Metadata sidecars

Package metadata is stored in backend sidecars:

- Local: `<data_dir>/tarballs/<package-with-slashes-replaced>/package.json`
- S3: `<prefix><package>/package.json` (Verdaccio-compatible layout)

Rustaccio writes sidecars after manifest mutations (`publish`, metadata-only update, dist-tag/owner/star changes, tarball removals).

At startup and reindex:

- Rustaccio loads tarball references from backend listing.
- It loads sidecars when available.
- It merges legacy Verdaccio package index hints (`verdaccio-s3-db.json`) when present.
- It rebuilds missing manifest structures from tarball filenames and sidecar metadata.

## Data Inconsistency and Failure Modes

Known failure windows:

1. Tarball written, sidecar write fails:
- blob may exist without updated manifest reference.

2. Sidecar updated, tarball delete fails:
- manifest may stop referencing a blob that still exists (or vice versa, depending on operation ordering).

3. Sidecar authority multi-writer races:
- if coordination backend is `none`, concurrent writers can still race.
- with `redis`/`s3` coordination enabled, rustaccio serializes package mutations by `package:<name>` scope, which removes overlapping write sections but is still not a full transactional metadata system.

4. Backend outages (Redis/Postgres/S3 lock backend):
- behavior depends on `*_FAIL_OPEN` settings (`allow` vs reject with backend-unavailable errors).

Operational diagnostics:

- `GET /-/admin/storage-health` reports drift signals:
  - `tarballsWithoutSidecar`
  - `sidecarsWithoutTarballs`
  - `tarballsMissingFromManifest`
  - `manifestAttachmentsMissingBlob`
  - `staleStatePackages`

## Rebuild and Recovery

### Online reindex from storage backend

Use admin endpoint:

```bash
curl -X POST \
  -H "Authorization: Bearer <admin-token>" \
  http://<host>:4873/-/admin/reindex
```

Response includes:

- `changed`
- `packagesBefore`
- `packagesAfter`
- `sidecarsSynced`

This rebuilds package metadata from backend tarballs/sidecars and can repair many drift cases.

### What cannot be reconstructed from tarballs alone

- `users`, `auth_tokens`, `npm_tokens`, and `login_sessions` are local auth/session state.
- If local `state.json` is lost and no backup exists, those records are not recoverable from tarball blobs.

### Recommended backup strategy

- Back up local `state.json` for auth/session records.
- Back up all tarball objects and package sidecars.
- For governance:
  - back up Postgres quota tables
  - persist Redis if you require durable counters across restarts (optional by policy)

## Scalability Characteristics

What scales today:

- Object-store tarballs (`s3`) and sidecars.
- Horizontal read/write nodes with shared object storage.
- Distributed rate limiting (Redis) and quota accounting (Postgres).

Current bottlenecks/limits:

- Metadata writes are still not transactional across tarball + sidecar artifacts.
- Sidecar conflict resolution remains optimistic at application level.

Recommended evolution for high-scale managed deployments:

- Move package/user/token metadata to a transactional DB-backed metadata store.
- Keep object storage for immutable tarballs/blobs.
- Add distributed compare-and-swap/evented invalidation for metadata cache coherence.

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
