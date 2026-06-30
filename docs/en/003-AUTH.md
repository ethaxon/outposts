# Authentication

Outposts has one current protected application path: `outposts-web` accessing
the Confluence API. It uses standard OpenID Connect with Authorization Code +
PKCE in the browser and Securitydept resource-server validation in the backend.
Authentik is the reference provider, but the contract is standard OIDC.

## Modes

| `AUTH_TYPE` | Intended use                                   | Behaviour                                                                                                                 |
| ----------- | ---------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------- |
| `OIDC`      | Normal local, CI, and deployment configuration | The browser authenticates with the configured provider; Confluence validates Bearer access tokens.                        |
| `DEV`       | Local development only                         | The Angular development build skips OIDC and the Rust debug build accepts requests as `AUTH_DEV_USER_ID` (default `dev`). |

`DEV` is rejected by a production Angular build and by a Rust release build. It
must never be used as a deployment authentication mode.

## OIDC Flow

1. `outposts-web-host` requests the unauthenticated public projection at
   `GET /api/auth/config?redirect_uri=<web-callback-url>` from Confluence.
2. The host sidecar injects that projection into the HTML served by nginx. It
   contains public provider metadata, client ID, scopes, PKCE settings, and the
   callback URL—never a client secret or user data.
3. The Angular Securitydept registry resolves configuration in this order:
   injected Realm projection, persisted projection cache, then the canonical
   Confluence endpoint.
4. A protected `/confluence` route uses a
   `TokenSetClientRegistryAuthRequirement`. If authentication is needed, the
   SDK starts the OIDC redirect.
5. `/auth/callback` hosts `TokenSetFrontendCallbackComponent`; the application
   then navigates to the returned post-auth URL through Angular Router.
6. The Angular authorization interceptor adds a Bearer token only to the
   configured Confluence API origin and path. `/api/auth/config` is explicitly
   excluded to avoid recursive client initialization.

Confluence performs provider discovery and JWKS-backed access-token validation.
It enforces configured scopes and enforces an audience only when
`CONFLUENCE_OIDC_AUDIENCE` is set.

## Configuration

Start from the checked-in template:

```sh
cp .env.example .env
```

### Shared Web Configuration

| Variable                  | Required | Purpose                                                                           |
| ------------------------- | -------: | --------------------------------------------------------------------------------- |
| `AUTH_TYPE`               |      Yes | `OIDC` for normal operation; `DEV` only for local debug development.              |
| `CONFLUENCE_API_ENDPOINT` |      Yes | Public Confluence API base URL, for example `https://confluence.example.com/api`. |
| `OUTPOSTS_WEB_HOST`       |      Yes | Public web hostname used by the projection host's built-in Confluence topology.   |

### OIDC Configuration

These are required when `AUTH_TYPE=OIDC`.

| Variable                      | Purpose                                                                       |
| ----------------------------- | ----------------------------------------------------------------------------- |
| `OIDC_ISSUER`                 | OIDC issuer URL.                                                              |
| `OUTPOSTS_WEB_OIDC_CLIENT_ID` | Public browser OIDC client ID; Confluence serves it in the config projection. |
| `CONFLUENCE_OIDC_SCOPES`      | Space- or comma-separated requested and required scopes.                      |
| `CONFLUENCE_OIDC_AUDIENCE`    | Optional expected token audience. Omit it to skip audience validation.        |
| `CONFLUENCE_OIDC_USER_CLAIM`  | Optional principal claim; defaults to `sub`.                                  |

The frontend build validates `AUTH_TYPE`, `CONFLUENCE_API_ENDPOINT`, and
`OUTPOSTS_WEB_HOST`. In OIDC mode it also validates `OIDC_ISSUER`,
`OUTPOSTS_WEB_OIDC_CLIENT_ID`, and `CONFLUENCE_OIDC_SCOPES`. The backend also
requires its normal database and listener settings from `.env`.

## Development

For OIDC development, use the values appropriate to the local web and API
origins, then run:

```sh
docker compose -f docker-compose.dev-deps.yml up -d
just dev-confluence
just dev-webui
```

For a no-auth local loop, set `AUTH_TYPE=DEV` and optionally `AUTH_DEV_USER_ID`.
Run the frontend through `just dev-webui` and the backend through
`just dev-confluence`; both are development commands and therefore satisfy the
mode restriction.

## CI and Deployment

The `build-web` job in `.github/workflows/ci.yaml` runs in the `BUILD` GitHub
Actions environment. Repository or environment variables must be exposed to its
dotenv-generation step. In particular, `AUTH_TYPE` must be mapped along with
the OIDC and URL variables; otherwise the web build intentionally fails before
producing a bundle.

For deployment, use `PROJECTION_SOURCES` to describe one or more projection
endpoints. If it is absent, `outposts-web-host` falls back to one Confluence
source using `OUTPOSTS_WEB_HOST`. The projection host refreshes its injected
HTML periodically; browser token persistence remains owned by Securitydept.

## Security Boundaries

- The public config projection exposes only data needed to initiate OIDC.
- The backend is a resource server; it does not hold a browser client secret.
- Browser tokens are never attached to requests outside the configured API
  boundary.
- Authentication mode is explicit and validated at build/startup time rather
  than inferred from missing values.

---

[English](003-AUTH.md) | [中文](../zh/003-AUTH.md)
