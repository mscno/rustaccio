# npm Bootstrap Contract v1

Status: Active  
Version: `v1`

## Endpoint

`GET /-/npm/v1/bootstrap`

Optional query params:

1. `scope=<scope-name-or-@scope>`

## Response

```json
{
  "registry": "https://registry.example.com/",
  "scope": "@acme",
  "authTokenKey": "//registry.example.com/:_authToken",
  "userHint": "Authenticated as `alice`.",
  "snippets": {
    "npmrc": "registry=...\n...",
    "npm": "npm config set registry ...",
    "pnpm": "pnpm config set registry ...",
    "yarn": "yarn config set npmRegistryServer ...",
    "bun": "bun pm config set registry ..."
  },
  "notes": [
    "Export token before install/publish: export RUSTACCIO_NPM_TOKEN=<token>",
    "For CI, prefer project-scoped tokens and rotate periodically."
  ]
}
```

## Behavior

1. Registry URL is computed from request host/proxy headers and `url_prefix`.
2. If `scope` is provided without `@`, the response normalizes it to `@scope`.
