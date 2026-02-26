# Auth Request Contract v1

Status: Active  
Version: `v1`

## Endpoint

`POST {baseUrl}{requestAuthEndpoint}`

## Request Body

```json
{
  "token": "<token>",
  "method": "GET|PUT|POST|DELETE|HEAD",
  "path": "/requested/path",
  "request_id": "<x-request-id-or-null>"
}
```

## Request Headers

1. `Content-Type: application/json`
2. `x-request-id: <request-id>` when available

## Success Response (`2xx`)

Any of:

1. `{"authenticated":false}` (treated as unauthenticated)
2. `{"authenticated":true,"username":"alice","groups":["admins"]}`
3. `{"username":"alice","groups":["admins"]}`
4. `{"user":"alice","roles":["admins"]}`
5. `{"name":"alice","group":"admins"}`

Notes:

1. Username fields accepted in this order: `username`, `user`, `name`.
2. Group fields accepted from `groups`, `roles`, or `group`.
3. Empty identity (`no username and no groups`) is treated as unauthenticated.

## Deny Response

1. `401` or `403` => explicit deny (no identity).

## Error Response

Non-`2xx` (except `401/403`) is treated as backend failure and translated to data-plane `502`.

## Operational Expectations

1. Provider should echo request IDs in logs using `x-request-id`.
2. Provider should keep latency low (single-digit milliseconds target in-cluster).
