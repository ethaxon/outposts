# Changelog

## 0.3.5

- **Frontend/Workspace: Monaco editor UX was hardened for constrained screens and dialogs** — unified Monaco shell handling in workspace and dialog flows, removed `fixedOverflowWidgets` after position regressions, relaxed dialog/content overflow via a Monaco-specific dialog class to prevent suggestion clipping, and set default Monaco indentation to `tabSize: 2` with spaces for better mobile/tablet editing density.
- **Frontend/Auth: persistent key naming and diagnostics gating were corrected** — fixed auth persistent state key duplication (`outposts.web.auth.outposts.web.auth.confluence` -> `outposts.web.auth.confluence`) by using a non-prefixed `persistentStateKey`, and changed auth diagnostics behavior so development is enabled by default while production remains disabled unless `OUTPOSTS_WEB_ENABLE_AUTH_DIAGNOSTICS=true`.
- **Release: patch version bumped to `0.3.5`** — synchronized version metadata across root workspace (`package.json`), `apps/outposts-web/package.json`, and `apps/confluence/Cargo.toml`.

## 0.3.4

- **Frontend/Auth: guard-triggered login redirects now preserve the attempted URL** — route protection switched to `createFrontendOidcLoginRedirectHandler`, and `AuthService.redirectToLogin()` now accepts an explicit `postAuthRedirectUri` so redirects can use the guard's attempted route instead of the previously committed `Router.url`; auth service specs were updated to lock down that contract.
- **Frontend/Dev: Angular dev-server projection injection is now package-exported and Nx-compatible** — `outposts-web` now exports `./dev-inject-middleware`, the Nx `serve` target resolves middleware through that export path, and the middleware no longer uses top-level await so Nx can `require()` it while still fetching and injecting `window.__OUTPOSTS_CONFIG__` into dev HTML responses.
- **Web host: projection injector now runs on Bun or Node.js** — `apps/outposts-web-host/inject.ts` now detects the runtime explicitly, keeps Bun as the production path, adds a Node.js host adapter with lazy `node:fs/promises` loading for local development, and documents a localhost `PROJECTION_SOURCES` example in `.env.example`.
- **Securitydept dependencies: frontend and backend advanced to `0.2.0-beta.3`** — bumped the published `@securitydept/*` npm packages, aligned the Rust workspace `securitydept-core` dependency and lockfile crates to `0.2.0-beta.3`, and refreshed package/crate version metadata for the `0.3.4` release.
- **Tooling: local commands aligned on current workspace conventions** — `just dev-proxy` now runs through `pnpm --filter dev-proxy run start`, `oxfmt` was updated to `^0.46.0`, and the old `.cursorignore` override file was removed from the workspace.

## 0.3.3

- **Frontend: published `securitydept` SDK adoption** — replaced local `link:` dependencies with published `0.2.0-beta.2` packages for `@securitydept/client`, `@securitydept/client-angular`, `@securitydept/token-set-context-client`, and `@securitydept/token-set-context-client-angular`; removed the pnpm override that forced a local Angular client build.
- **Frontend: bearer injection hardening** — `provideTokenSetBearerInterceptor` now runs with `strictUrlMatch: true`, so bearer tokens are only attached to requests matching registered `urlPatterns` and no longer fall back onto unrelated third-party URLs.
- **Frontend: auth regression coverage** — added focused Vitest specs for auth definitions, callback route ordering, bearer-token injection boundaries, and `AuthService.redirectToLogin()` preserving the current route as `postAuthRedirectUri`.
- **Backend: published crate alignment** — switched `securitydept-core` from git/path overrides to published `=0.2.0-beta.2`, removed the `openidconnect` patch override, and refreshed Rust dependencies including `fancy-regex` `0.18`.
- **Docs: auth integration guidance refreshed** — updated `docs/en/003-AUTH.md` and `docs/zh/003-AUTH.md` to describe the SDK-based auth runtime, strict bearer matching, completed Stage 1/2 status, and the new default of published dependencies with local overrides only for temporary integration loops.

## 0.3.2

- **Fix: Auth sign-in reverted to redirect flow** — `canActivate` default sign-in type changed back from `popup` to `redirect` for better UX and broader IdP compatibility.
- **Backend: Clash DNS features** — Added support for parsing `proxy-server-nameserver` and related DNS template fields.
- **Backend: Nameserver policy muxing** — Added `proxy_server_nameserver_policy_source` to `SubscribeSource`. Muxing now automatically merges and deduplicates per-source proxy server TLDs into the output `proxy-server-nameserver-policy`.
- **Frontend: Subscribe Source UI** — Added a dropdown in the workspace to configure the DNS nameserver policy source.

## 0.3.1

- **Fix: OIDC silent renew — auth state stays stale after renewal** — `AuthService` now subscribes to `PublicEventsService#NewAuthenticationResult`; on every successful token refresh it calls `refresh()` so the `userInfo$` / `isAuthenticated$` observables (previously frozen by `shareReplay`) are kept up to date.
- **Fix: OIDC silent renew failure leaves app in broken state** — `AuthService` now listens for `SilentRenewFailed`, `TokenExpired`, and `IdTokenExpired`; any renewal failure triggers an immediate redirect to the IdP so the user is re-authenticated rather than left with silently failing API calls.
- **Fix: `p-panel-content-wrapper` cannot shrink inside a flex container** — added `::ng-deep` override in `workspace.component.scss` to set `min-width: 0` on PrimeNG's internal content wrapper, restoring normal flex-shrink behaviour.

## 0.3.0

- **Auth: Authentik-first OIDC hardening** — removed RFC 8707 `resource` indicator parameters from frontend OIDC requests (Authentik does not support Resource Indicators); driver no longer filters tokens by target resource URL.
- **Auth: optional audience validation** — `CONFLUENCE_OIDC_AUDIENCE` is now optional; when absent the resource-server verifier skips audience checks entirely, enabling Authentik deployments that omit the `aud` claim.
- **Auth: tolerant token parsing** — `client_id` and `aud` in RFC 9068 JWT claims are now `Option`, accepting tokens from providers that omit these fields.
- **Backend: `securitydept-core` pinned to git ref** — workspace dependency switched from local `path` to `git + rev`; local iteration uses `[patch]` override (commented for CI).
- **Backend: `CONFLUENCE_OIDC_AUDIENCE_REQUIRED` removed** — replaced by the simpler convention of leaving `CONFLUENCE_OIDC_AUDIENCE` unset.
- **Backend: expanded auth test coverage** — new cases for tokens without `client_id`, disabled audience validation, and optional audience behavior.
- **Frontend: OIDC config simplified** — `resolveTargetResource` and `customParams*Request.resource` blocks removed from `createOidcAuthConfig`.
- **Tooling: pnpm bumped to 10.33.0** — updated in `mise.toml`, CI workflow, and `Dockerfile.dev`.
- **Tooling: `just dev-deps` now passes `--remove-orphans`**; added `just dev-deps-down` target.
- **Docs: `003-AUTH.md` updated** (en + zh) — documents optional audience, RFC 8707 removal, and git-ref + patch dependency pattern.

## 0.2.0

- Refined the Outposts Web UI, routing, and documentation experience.
- Hardened the Confluence backend auth flow and expanded backend test coverage.
- Moved frontend lint/format onto the ESLint/Ox toolchain and simplified editor/CI integration.
- Improved Rust container delivery by shifting release builds toward CI-produced binaries.
