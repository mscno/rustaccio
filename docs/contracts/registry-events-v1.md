# Registry Events Contract v1

Status: Active  
Version: `v1`

## Event Shape

```json
{
  "event_type": "package.published",
  "occurred_at": "2026-02-26T10:00:00Z",
  "actor": "alice",
  "package": "@scope/demo",
  "request_id": "req_123",
  "tenant": {
    "org_id": "org_123",
    "project_id": "proj_456"
  },
  "attributes": {}
}
```

## Delivery

When `RUSTACCIO_EVENT_SINK=http`:

1. Rustaccio POSTs events to `{RUSTACCIO_EVENT_HTTP_BASE_URL}{RUSTACCIO_EVENT_HTTP_ENDPOINT}`.
2. `x-request-id` is forwarded when present.
3. Delivery is best-effort and does not block npm operations.

## Event Types (current)

1. `admin.reindex`
2. `admin.storage_health.read`
3. `admin.policy_cache.invalidate`
4. `admin.package_cache.invalidate`
5. `package.published`
6. `package.metadata_updated`
7. `package.dist_tag.updated`
8. `package.dist_tag.removed`
9. `package.removed`
10. `package.tarball.removed`
