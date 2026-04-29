# Changelog

## 0.3.6

- **Workspace UI** — added traffic metadata, reset policy, next reset, and usage progress to subscribe source cards; added workspace summary metadata and a rename affordance; switched card lists to responsive grid layouts.
- **Subscribe source reset policy** — added persisted traffic reset policy and cached next-reset timestamps, with calendar-aware backend calculation and DTO/TypeScript bindings.
- **Forms and i18n** — added reset policy controls to subscribe source create/edit dialogs and aligned translated select option rendering.
- **Release** — bumped package/crate version metadata to `0.3.6`.

## 0.3.5

- **Workspace editor** — hardened Monaco editor sizing, dialog overflow, and indentation defaults.
- **Auth** — fixed persistent auth key naming and tightened diagnostics defaults.
- **Release** — bumped package/crate version metadata to `0.3.5`.

## 0.3.4

- **Auth** — preserved attempted URLs through guard-triggered login redirects.
- **Dev server** — made projection injection package-exported and Nx-compatible.
- **Web host** — added Bun/Node runtime support for projection injection.
- **Dependencies** — advanced Securitydept packages/crates to `0.2.0-beta.3`.
- **Tooling** — aligned dev-proxy and formatting commands with workspace conventions.

## 0.3.3

- **Securitydept SDK** — moved frontend and backend dependencies to published `0.2.0-beta.2` packages/crates.
- **Auth hardening** — restricted bearer injection to strict URL matches and expanded regression coverage.
- **Docs** — refreshed English and Chinese auth integration guidance.

## 0.3.2

- **Auth** — reverted guarded sign-in to redirect flow.
- **Clash DNS** — added proxy server nameserver parsing and mux policy generation.
- **Subscribe source UI** — added DNS nameserver policy configuration.

## 0.3.1

- **Auth** — kept OIDC state fresh after silent renew and redirected on renewal failures.
- **Workspace layout** — fixed PrimeNG panel content shrinking inside flex containers.

## 0.3.0

- **Auth** — simplified Authentik-first OIDC handling, optional audience validation, and tolerant JWT claim parsing.
- **Backend** — moved `securitydept-core` to a pinned git ref and expanded auth coverage.
- **Tooling** — bumped pnpm, refined dev-deps commands, and updated auth docs.

## 0.2.0

- Refined the Outposts Web UI, routing, and documentation experience.
- Hardened the Confluence backend auth flow and expanded backend test coverage.
- Moved frontend lint/format onto the ESLint/Ox toolchain and simplified editor/CI integration.
- Improved Rust container delivery by shifting release builds toward CI-produced binaries.
