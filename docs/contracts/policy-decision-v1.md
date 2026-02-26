# Policy Decision Contract v1

Status: Active  
Version: `v1`

## Endpoint

`POST {baseUrl}{decisionEndpoint}`

## Request Body

```json
{
  "action": "access|publish|unpublish",
  "package": "<package-name>",
  "method": "GET|PUT|POST|DELETE|HEAD",
  "path": "/requested/path",
  "request_id": "<x-request-id-or-null>",
  "username": "alice",
  "groups": ["admins"],
  "identity": {
    "username": "alice",
    "groups": ["admins"]
  },
  "tenant": {
    "org_id": "org_123",
    "project_id": "proj_456"
  },
  "org_id": "org_123",
  "project_id": "proj_456"
}
```

## Request Headers

1. `Content-Type: application/json`
2. `x-request-id: <request-id>` when available

## Decision Response

Accepted response shapes:

1. `{"allowed": true}`
2. `{"allowed": false}`
3. `true`
4. `false`

## Status Handling

1. `2xx` => parse decision payload.
2. `401/403` => explicit deny (`allowed=false`).
3. Other non-`2xx`:
   - If `RUSTACCIO_POLICY_HTTP_FAIL_OPEN=true`, fallback to local policy chain.
   - Else fail request with `502` and `POLICY_BACKEND_UNAVAILABLE`.

## Cache Semantics

1. Decisions may be cached for `RUSTACCIO_POLICY_HTTP_CACHE_TTL_MS`.
2. Cache invalidation endpoint: `POST /-/admin/policy-cache/invalidate`.
