# Changelog

## 0.4.0

- **Breaking UI** — replaced PrimeNG/PrimeUI with Spartan NG, Helm primitives, Lucide icons, Tailwind v4 theming, and the application `.dark` theme state; removed the PrimeUI license path while retaining existing business layouts and workflows.
- **Authentication and development** — aligned the Angular adapter integration with Securitydept `0.3.0-beta.6`, added development auth mode, and removed the unused redirect service.
- **UX and i18n** — restored loading, dialog, action, QR code, document, and accessibility copy behavior; added matching English and Chinese translation coverage.
- **Performance and tooling** — upgraded the Angular/Nx toolchain, moved Prism assets to document-level on-demand loading, and raised the initial bundle budget to 2 MB.
- **Release** — bumped the root package, web application, host sidecar, dev proxy, and Confluence crate to `0.4.0`.

## 0.3.10

- **Securitydept** — upgraded the Rust crate and four frontend SDK packages to `0.3.0-beta.6`; migrated auth composition to `FoundationEnvironment`, Resource-backed `TokenSetClientRegistry`, the new frontend callback and secure-route adapters, and the registry authorization interceptor. External IdP navigation now uses the Angular adapter's built-in native-web routing support.
- **Frontend** — migrated the web application to Angular 22, Nx 23, PrimeNG 22, and the corresponding ngx-markdown/ngx-monaco-editor integrations; updated auth configuration and callback flows for the current SDK APIs.
- **Tooling** — upgraded the safe patch-level tooling and Markdown dependencies, removed unused build integrations, and aligned the Angular application build target with the esbuild-based builder.
- **Development server** — restored the Angular dev-server compatibility dependency and fixed ESM loading for the development projection-injection middleware.
- **Release** — bumped package and crate version metadata to `0.3.10`.

## 0.3.9

- **Clash DNS** — added direct `proxy-server-nameserver-policy` / `nameserver-policy` source merge modes and tightened `auto` precedence to prefer non-empty policy maps before generated nameserver rules.
- **Subscribe source UI** — exposed the new DNS policy source options for subscribe source create/edit flows.
- **Release** — bumped package and crate version metadata to `0.3.9`.

## 0.3.8

- **Securitydept** — upgraded all four frontend SDK packages (`@securitydept/client`, `@securitydept/client-angular`, `@securitydept/token-set-context-client`, `@securitydept/token-set-context-client-angular`) from local `link:` references to published `0.3.0-beta.3`; adopted `ClientEnvironmentService` + `createFrontendOidcModeWebClientEnvironment(...)` composition root, `providePageClientEnvironment()`, and `provideAuthPlannerHost()` from the new SDK surface.
- **Docs** — refreshed English and Chinese auth integration guidance to reflect the `0.3.0-beta.3` API surface and updated dependency version examples.
- **Release** — bumped package and crate version metadata to `0.3.8`; upgraded `securitydept-core` backend crate to `0.3.0-beta.3`.

## 0.3.7

- **Securitydept** — upgraded frontend packages and backend crate to `0.3.0-beta.2`.
- **Tooling** — migrated to pnpm v11 across CI, mise, Dockerfiles, and lockfile; moved pnpm overrides and build allowlist from `package.json` into `pnpm-workspace.yaml`; streamlined `just setup` by replacing `prek install` with `mise install`; added `zellij-dev.kdl` layout and `just dev` command for portable one-shot zellij dev environment; registered `watchexec` and `zellij` in mise tools; set `terminal.integrated.macOptionIsMeta` in VS Code settings.
- **Release** — bumped package/crate version metadata to `0.3.7`.

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
