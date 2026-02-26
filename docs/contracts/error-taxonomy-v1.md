# Error Taxonomy v1

Status: Active  
Version: `v1`

Registry errors include both message and machine-readable code:

```json
{
  "error": "human-readable message",
  "code": "MACHINE_CODE"
}
```

## Code Families

### Auth

1. `AUTH_UNAUTHORIZED`
2. `AUTH_FORBIDDEN`

### Policy

1. `POLICY_DENIED`
2. `POLICY_BACKEND_UNAVAILABLE`

### Storage

1. `STORAGE_BAD_REQUEST`
2. `STORAGE_CONFLICT`
3. `STORAGE_NOT_FOUND`
4. `STORAGE_UNPROCESSABLE`

### Upstream

1. `UPSTREAM_BAD_GATEWAY`
2. `UPSTREAM_UNAVAILABLE`
3. `UPSTREAM_TIMEOUT`

### Internal

1. `INTERNAL_ERROR`

## Compatibility

1. Existing `error` message field remains stable.
2. `code` is additive and intended for automation and support tooling.
