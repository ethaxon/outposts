# Features

## Confluence

Confluence is a Clash subscription manager and configuration muxer.

- Manage confluences, profiles, subscription sources, and profile transforms.
- Refresh sources on configurable Cron schedules and display subscription usage
  metadata where it is available.
- Merge selected sources into Clash-compatible output profiles.
- Edit YAML and transform scripts with Monaco.
- Preview rendered documentation with Markdown, Mermaid diagrams, KaTeX, and
  Prism syntax highlighting.

The API is served below `/api`; the web client uses `/api/auth/config` only to
obtain public OIDC client configuration. It is excluded from Bearer-token
interception.

## VLAN subscriptions

Open **Apps → Confluence → VLAN**. A workspace can link multiple VLANs. Each VLAN defines destination CIDRs and an allowed supplicant list. Each tunnel grants access to a subset of that list. Removing a VLAN member also removes that member's tunnel grants and credentials.

- **EasyTier Portal** uses an IPv4 /24 pool, the Portal server key and pre-registered subscription-slot-N clients. Slot ranges belong to each tunnel grant. The client export can fill the endpoint, suggested pool and AllowedIPs. Enter the server key separately.
- **WireGuard** assigns a client configuration to each tunnel grant. Import one [Interface] and one or more [Peer] sections. Supported fields are Address, PrivateKey, MTU, Endpoint, PublicKey, PresharedKey, AllowedIPs and PersistentKeepalive. All peers use the same keepalive. Devices using the same supplicant share one client credential for the tunnel.

Each tunnel's AllowedIPs must fit within the VLAN CIDRs. **Recompute VLAN CIDRs from tunnels** replaces the route draft with the normalized union of the configured AllowedIPs and EasyTier Portal subnets. Each tunnel appears as one selectable Mihomo proxy. WireGuard chooses among its own peers. All VLAN routes point to the same selection group, and a selected tunnel may reach only part of the VLAN. Management responses show whether secrets are set and omit their values.

Use `?supplicant=example-user&vlans=office,lab:10` in the subscription URL, or append `confluence/supplicant=example-user&vlans=office,lab:10` to the User-Agent. Both sources must agree when present. Requests without a slot select authorized WireGuard tunnels. Providing a slot also selects EasyTier tunnels whose grants permit it. VLAN membership is required. An authorized VLAN with no matching tunnel still returns its rules and a group with REJECT first and DIRECT available. The subscription is encrypted to the supplicant's age recipient after profile transforms and bypasses shared caches.

### Database migration

PostgreSQL 18+ is required. Business primary keys use native `uuid` columns with database-generated `uuidv7()` defaults. Existing records and foreign keys are migrated together while preserving timestamps and subscription `resource_token` values. Management API IDs and routes use UUID strings. ts-rs exports these Rust `Uuid` fields through the named TypeScript scalar `UUIDV7 = string`; the alias provides a visible semantic name with structural string compatibility. Subscription credentials use independent random UUIDv4 tokens, exported as the TypeScript scalar `UUIDV4 = string`.

Stop Confluence and take a restorable backup before applying the migrations. The tunnel migration preserves VLAN memberships, workspace links and EasyTier gateway identities. It copies existing slot grants to each EasyTier tunnel and materializes implicit Portal subnet routes. Start matching backend and frontend versions after migration. Roll back by restoring the backup and the previous application version.

## Authentication

- `AUTH_TYPE=OIDC` uses Authorization Code with PKCE in the browser and
  Securitydept resource-server validation in Confluence.
- Route protection is declared with Securitydept token-set requirements rather
  than an application-owned login wrapper.
- The Angular authorization interceptor attaches a Bearer token only to the
  configured Confluence API origin and path.
- `AUTH_TYPE=DEV` is a local-development bypass; it is unavailable in
  production frontend builds and release backend builds.

See [Authentication](003-AUTH.md) for required configuration.

## Outposts-web

- Angular 22 SPA with an Nx 23 workspace.
- Spartan NG / Helm primitives, Tailwind CSS v4, and Lucide icons.
- English and Simplified Chinese UI text via Transloco.
- Responsive application shell, workspace forms, dialogs, toast feedback, and
  loading states.
- Feature-level loading for documentation assets so Prism, Mermaid, and KaTeX
  do not inflate the initial page.

---

[English](002-FEATURES.md) | [中文](../zh/002-FEATURES.md)
