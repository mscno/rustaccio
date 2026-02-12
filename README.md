# rustaccio

A Rust/Tokio/Axum npm registry proxy inspired by Verdaccio core behavior.

## Run

```bash
cargo run
```

Environment variables:

- `RUSTACCIO_BIND` (default `127.0.0.1:4873`)
- `RUSTACCIO_DATA_DIR` (default `.rustaccio-data`)
- `RUSTACCIO_CONFIG` (optional Verdaccio-style YAML; loads `packages` ACL rules + `uplinks`)
- `RUSTACCIO_UPSTREAM` (optional, eg `https://registry.npmjs.org`)
- `RUSTACCIO_WEB_LOGIN` (default `false`; enables `/-/v1/login*` endpoints)
- `RUSTACCIO_PUBLISH_CHECK_OWNERS` (default `false`; enforces owner-only package mutations)
- `RUSTACCIO_PASSWORD_MIN` (default `3`)
- `RUSTACCIO_LOGIN_SESSION_TTL_SECONDS` (default `120`)
- `RUSTACCIO_AUTH_BACKEND` (`local` or `http`, default `local`)
- `RUSTACCIO_AUTH_HTTP_BASE_URL` (required for `http` auth backend)
- `RUSTACCIO_AUTH_HTTP_ADDUSER_ENDPOINT` (default `/adduser`)
- `RUSTACCIO_AUTH_HTTP_LOGIN_ENDPOINT` (default `/authenticate`)
- `RUSTACCIO_AUTH_HTTP_CHANGE_PASSWORD_ENDPOINT` (default `/change-password`)
- `RUSTACCIO_AUTH_HTTP_TIMEOUT_MS` (default `5000`)
- `RUSTACCIO_TARBALL_BACKEND` (`local` or `s3`, default `local`)
- `RUSTACCIO_S3_BUCKET` (required for `s3` backend)
- `RUSTACCIO_S3_REGION` (default `us-east-1`)
- `RUSTACCIO_S3_ENDPOINT` (optional, eg MinIO/LocalStack endpoint)
- `RUSTACCIO_S3_ACCESS_KEY_ID` / `RUSTACCIO_S3_SECRET_ACCESS_KEY` (optional static credentials)
- `RUSTACCIO_S3_PREFIX` (optional key prefix)
- `RUSTACCIO_S3_FORCE_PATH_STYLE` (default `true`)

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
- `/-/npm/v1/security/audits`
- `/-/v1/login`, `/-/v1/login_cli/:sessionId`, `/-/v1/done/:sessionId`
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
- pluggable tarball backend (`local` filesystem or `s3`)
- npm token APIs (list/create/delete + validation errors)
- profile APIs (get + password change validation)
- security audit endpoints (uplink proxy + local fallback response shape)
- search v1 with pagination semantics
- login session APIs (`/-/v1/login`, `/-/v1/login_cli/:sessionId`, `/-/v1/done/:sessionId`)
- `flags.webLogin` parity behavior (login routes disabled unless enabled)
- deprecated search endpoint (`/-/all`)
- uplink behavior for package metadata, dist-tags, search, and tarballs
- package ACL parity subset (`access`/`publish`/`unpublish`) with pattern matching and proxy uplink selection

## Architecture

- `src/api.rs`: HTTP routing + Verdaccio-compatible endpoint behavior
- `src/acl.rs`: package rule matching + access/publish/unpublish permission checks
- `src/config.rs`: env + Verdaccio-style YAML parsing (`packages`, `uplinks`)
- `src/storage.rs`: local state, persistence, auth/token/package operations + backend integration
- `src/auth_plugin.rs`: HTTP auth backend plugin client
- `src/tarball_backend.rs`: tarball backend abstraction (`local`, `s3`)
- `src/upstream.rs`: npm uplink proxy client for package/search/tarball
- `src/app.rs`: app state + router construction

## Plugin Config (YAML)

```yaml
auth:
  backend: http
  http:
    baseUrl: http://auth.local:9000
    addUserEndpoint: /adduser
    loginEndpoint: /authenticate
    changePasswordEndpoint: /change-password
    timeoutMs: 5000

storage:
  backend: s3
  s3:
    bucket: npm-cache
    region: us-east-1
    endpoint: http://127.0.0.1:9001
    accessKeyId: minio
    secretAccessKey: miniopass
    prefix: tarballs/
    forcePathStyle: true
```

## HTTP Auth Plugin Contract

The HTTP auth backend is called by core user endpoints and keeps the same external npm/Verdaccio API contract.

- `POST {baseUrl}{addUserEndpoint}` with `{ "username", "password" }`
- `POST {baseUrl}{loginEndpoint}` with `{ "username", "password" }`
- `POST {baseUrl}{changePasswordEndpoint}` with `{ "username", "old_password", "new_password" }`

Behavior:

- `2xx` means success.
- Non-`2xx` propagates status and `error`/`message` from plugin JSON body when present.
