# Changelog

## 0.3.3

- **Frontend: OIDC** — `triggerAuthorizationResultEvent` and app-controlled return; stable callback `redirectUrl` (`origin + /auth/callback`), `StsConfigLoader` + `WINDOW`, `isAuthenticated$` from token session, localStorage for `AbstractSecurityStorage` after `_provideAuth`.
- **Tests** — Vitest/TestBed setup and `provide-oidc-auth` coverage for callback `redirectUrl`.

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
