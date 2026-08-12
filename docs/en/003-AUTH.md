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
3. The Angular Securitydept registry registers the client lazily. The first
   route, callback, or authorized request that needs it resolves configuration
   in this order: injected Realm projection, persisted projection cache, then
   the canonical Confluence endpoint.
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

## Client Error Messages

Outposts keeps `AppOverlayService` as the single owner of application toast
presentation. The root-scoped `AuthService` owns Outposts-specific auth
orchestration that does not belong in the Securitydept SDK. It currently
connects the Token Set lifecycle to that presentation owner:

```text
Token Set client operation or materialization failure
  -> registry.errors (non-replay aggregate)
  -> AuthService
  -> AppOverlayService.showClientError()
  -> Sonner toast
```

The registry owns the dynamic client subscriptions. Its `errors` stream merges
operation errors from every ready client with configuration, projection, and
other factory/materialization failures. `AuthService` subscribes only to this
aggregate; it does not select clients, flatten per-client resources, start,
refresh, restore, or otherwise operate a client.

Angular's application initializer calls the idempotent `AuthService.start()`
once to install all root-scoped auth bridges before lazy client initialization.
Client initialization itself remains demand-driven and owned by the registry,
route coordination, callback component, and authorization interceptor.

`AppOverlayService` uses `readErrorPresentationDescriptor()` as the only
`ClientError` presentation projection. Its title can include the client and
operation captured by the error span, while tracing-only attributes, runtime
messages, tokens, authorization headers, and provider payloads are not shown.
Lifecycle events are deliberately non-replay: current authentication state is
read from the SDK Resource/Signal APIs, and historical diagnostics belong to
explicit tracing or logs.

This default bridge does not handle ordinary Confluence API errors, Angular
`HttpErrorResponse`, query/mutation failures, router boundaries, form
validation, or caller-owned Promise rejections. Those errors remain owned by
their application call sites.

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

The Confluence Rust build uses the pinned stable toolchain declared in the
repository root `rust-toolchain.toml`. Local mise and the Linux amd64/arm64
GitHub jobs read that same file; CI does not install a separate moving toolchain.

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

## Revoked Sessions and SDK Installation

The Confluence client explicitly uses `refreshErrorPolicy: "revokeAsUnauthenticated"`. Confirmed revocation during startup, manual refresh, timer refresh, or page resume clears credentials and resolves to unauthenticated state. The next protected navigation starts login and preserves the attempted URL without requiring a browser reload. Ordinary network or protocol failures remain errors.

The application root owns the themed Toast host, so SDK errors are visible on public pages and callback routes as well as the protected layout. The auth coordinator forwards the SDK registry error stream directly to `AppOverlayService`.

The frontend installs the four published Securitydept SDK packages at `0.3.0-beta.11` with `mise exec -- pnpm install`. No sibling Securitydept checkout or upstream SDK build is required. Angular adapters use their published package entry points.

[English](003-AUTH.md) | [中文](../zh/003-AUTH.md)
