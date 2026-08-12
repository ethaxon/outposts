# Roadmap

## Implemented

| Component                             | Status                      |
| ------------------------------------- | --------------------------- |
| Confluence                            | Core functionality complete |
| SSO (standard OIDC / Authentik-first) | Integrated                  |
| Outposts-web                          | Angular portal working      |

## Cross-cutting: Authentication E2E

- [ ] Add a reproducible local OIDC provider, such as Dex or a browser-hosted
      test provider, with deterministic users, clients, and token lifecycles
- [ ] Exercise the complete frontend and backend OIDC flow, including login
      callbacks, protected-route return URLs, refresh, confirmed revocation,
      reauthentication, and non-revocation failures
- [ ] Run the suite in CI once provider startup, browser installation, and test
      isolation are reliable and fast enough for routine development

## Phase 1: Confluence Enhancements

- [ ] Subscription health monitoring
- [ ] Config preview / diff before mux
- [ ] Bulk source import/export
- [ ] Usage statistics dashboard

## Phase 2: Securitydept

Securitydept is the integrated security and authentication infrastructure
toolkit. Its current OIDC capabilities are used by Outposts; planned L4 MFA
gateway capabilities target services such as RDP and SSH:

- [ ] Basic auth zone mode
- [ ] MFA challenge integration
- [ ] IP allowlist / blocklist
- [ ] Audit logging

## Phase 3: CelestialGates

Service web portal / teleportation:

- [ ] Unified service entry point
- [ ] SSO-aware routing
- [ ] Service health aggregation
- [ ] Quick-access bookmarks

## Phase 4: Yü-shih

System monitor client & center:

- [ ] Metrics collection agents
- [ ] Time-series data storage
- [ ] Alert rules engine
- [ ] Dashboard visualization

---

[English](100-ROADMAP.md) | [中文](../zh/100-ROADMAP.md)
