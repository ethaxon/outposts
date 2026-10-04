# Changelog

## 0.4.7

- **WireGuard tunnels** — client configurations and their peers now belong to the tunnel. You can save or import configurations before assigning them to VLAN members. Revoking an assignment keeps the configuration on the tunnel.
- **Profile age encryption** — added multiple age recipients per Profile. Ordinary subscriptions are encrypted to the selected recipients. VLAN requests on an encrypted Profile also require the requesting supplicant to be a Profile recipient, and the response is encrypted to that supplicant alone.
- **Client compatibility** — added an opt-in Profile setting for clients that cannot load age-encrypted subscriptions. A matching supplicant private key in the User-Agent returns uncached YAML after the usual Profile and VLAN authorization checks.
- **Workspace UI** — added encryption indicators on Profile cards and recipient selection with load-error recovery in the Profile editor. Updated the VLAN member and WireGuard configuration controls.
- **Subscription refresh** — require valid Clash YAML with a non-empty `proxies` list. Failed refreshes keep the last successful content and traffic metadata available for muxing and record the latest failure in `last_sync_error`. A successful refresh clears the error.
- **Subscription source cards** — update sync status without a page reload. On failure, the status indicator turns red and a separate action shows the error type, timestamp, HTTP status, response headers, and up to 64 KiB of response body when available. Cards stay ordered by creation time, oldest first.
- **Database upgrade** — moved existing WireGuard configs and peers to their tunnels while preserving member assignments. Added Profile recipient links and the compatibility setting, which defaults to off.
- **Release** — bumped the root package, web application, host sidecar, dev proxy, and Confluence crate to `0.4.7`.

## 0.4.6

- **VLAN tunnels** — replaced VLAN-level EasyTier gateways with named tunnels. Each VLAN keeps destination CIDRs and a member list, and each tunnel grants a subset of those members. EasyTier Portal tunnels keep the IPv4 /24 pool, server key, and per-grant slot ranges. WireGuard tunnels store one client configuration per grant, including an imported Interface and its Peers.
- **Subscriptions** — a request without a slot selects authorized WireGuard tunnels, and a slot also selects EasyTier tunnels whose grants allow it. Each tunnel is one Mihomo proxy, VLAN routes share one selection group, and an authorized VLAN with no matching tunnel still returns its rules with REJECT ahead of DIRECT.
- **Database upgrade** — the tunnel migration preserves VLAN memberships, workspace links, and EasyTier gateway identities, copies existing slot grants onto each EasyTier tunnel, and writes implicit Portal subnet routes. Stop Confluence and take a restorable backup before upgrading; roll back by restoring that backup with the previous application version.
- **Release** — bumped the root package, web application, host sidecar, dev proxy, and Confluence crate to `0.4.6`.

## 0.4.5

- **VLAN editor** — replaced the destination CIDR textarea with a tag-style list that validates and canonicalizes IPv4/IPv6 networks as they are added, and rejects forms the backend would not accept. Gateway subnets are constrained to IPv4 /24 and rewritten to network form on blur.
- **Release** — bumped the root package, web application, host sidecar, dev proxy, and Confluence crate to `0.4.5`.

## 0.4.4

- **EasyTier VLAN subscriptions** — added a dedicated Confluence sidebar page for shared VLANs, gateways, routes, and supplicant grants. Workspaces can link multiple VLANs, and each grant controls its allowed slots. Clients can select VLANs in the subscription URL or User-Agent and receive an age-encrypted configuration.
- **Database upgrade** — Confluence now requires PostgreSQL 18. The UUIDv7 migration replaces integer management IDs while preserving workspace relationships, timestamps, and existing UUIDv4 subscription tokens. Update saved workspace links and take a restorable backup before upgrading.
- **Authentication and workspace UI** — show sign-in progress through redirects and callback processing, initialize the Securitydept client when the browser is idle, and simplify the workspace card layout.
- **Tooling** — updated backend dependencies and development images, and split the Just recipes into smaller files with platform-specific execution where needed.

## 0.4.3

- **Dialogs** — kept CDK overlays out of the browser top layer so toasts stay above workspace edit and preview dialogs, while dialogs still cover the top bar and loading veil.
- **Tooling** — added `mise.ci.toml` so CI installs only node, pnpm, and rust, leaving watchexec and zellij for local development.
- **Release** — bumped the root package, web application, host sidecar, dev proxy, and Confluence crate to `0.4.3`.

## 0.4.2

- **Authentication** — adopted Securitydept `0.3.0-beta.11` with explicit recovery of confirmed token revocation across initialization and runtime refresh, allowing protected routes to restart login without reloading the page.
- **Error presentation** — moved the themed Toast host to the application root so SDK errors forwarded through the existing auth coordinator are visible even when a protected layout cannot load.
- **SDK installation** — installed all four published Securitydept TypeScript packages at `0.3.0-beta.11`, removing the sibling checkout requirement and local-link runtime resolution configuration.
- **Release** — bumped the root package, web application, host sidecar, dev proxy, and Confluence crate to `0.4.2`.

## 0.4.1

- **Breaking UI** — replaced PrimeNG/PrimeUI with Spartan NG, Helm primitives, Lucide icons, Tailwind v4 theming, and the application `.dark` theme state; removed the PrimeUI license path while retaining existing business layouts and workflows.
- **Authentication and development** — aligned the Angular adapter and backend integration with published Securitydept `0.3.0-beta.10`, added development auth mode, and removed the unused redirect service. The Outposts-owned `AuthService` connects Token Set lifecycle and registry materialization failures to the existing `AppOverlayService`, using span-backed `ClientError` presentation without creating a replay error store.
- **UX and i18n** — restored loading, dialog, action, QR code, document, and accessibility copy behavior; added matching English and Chinese translation coverage.
- **Performance and tooling** — upgraded the Angular/Nx toolchain, moved Prism assets to document-level on-demand loading, and raised the initial bundle budget to 2 MB. Rust is pinned by `rust-toolchain.toml`, while local mise and the multi-architecture GitHub build consume that single version authority.
- **Release** — bumped the root package, web application, host sidecar, dev proxy, and Confluence crate to `0.4.1`.

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
