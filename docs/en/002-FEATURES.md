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

## EasyTier VLAN subscriptions

In the left sidebar, open **Apps → Confluence → EasyTier VLAN** to manage VLANs and supplicants. Each VLAN has its own gateways, routes and supplicant grants, with slot ranges such as `2,4,10-100`. In a workspace, select existing VLAN cards and save the references. A VLAN can serve multiple workspaces with the same creator. Changes to a shared VLAN take effect in all linked workspaces. Deleting a workspace removes its references. Deleting a VLAN removes its references from all workspaces. Remove the grants before deleting a supplicant.

Use `confluence/supplicant=example-user&vlans=example-network:10,another-network:20` in the subscription UA, or `?supplicant=example-user&vlans=example-network:10,another-network:20` in its URL. Both sources must describe the same request when present. Duplicate networks, missing identities, disabled networks and unauthorized slots reject the entire request. Rust injects the selected nodes and routes after custom transforms, then encrypts the complete configuration to the shared supplicant's age X25519 recipient. Configure the matching age private key in the client. Responses bypass shared caches.

Portals use canonical IPv4 `/24` pools and pre-registered `subscription-slot-N` clients. Keys follow EasyTier's native HKDF-SHA256 derivation. Concurrent devices within one Portal need distinct slots. Distribution permissions apply to subscription credentials; Portal network and ACL settings control network reachability. Gateway private keys reside in the database, are hidden in management responses, and are retained by blank edits matching existing VLAN and gateway identities.

### Database migration

PostgreSQL 18+ is required. Business primary keys use native `uuid` columns with database-generated `uuidv7()` defaults. Existing records and foreign keys are migrated together while preserving timestamps and subscription `resource_token` values. Management API IDs and routes use UUID strings. ts-rs exports these Rust `Uuid` fields through the named TypeScript scalar `UUIDV7 = string`; the alias provides a visible semantic name with structural string compatibility. Subscription credentials use independent random UUIDv4 tokens, exported as the TypeScript scalar `UUIDV4 = string`.

For rollout, stop Confluence, retain a restorable database backup, apply the primary-key migration followed by the VLAN tables migration, then start the matching backend and frontend. Old integer management URLs expire. Restore the backup together with the old application version to reverse the primary-key migration. Register Portal slots, configure VLANs and supplicant grants, link the VLANs to the relevant workspaces, remove legacy VLAN injection from scripts, and update client UA/URL and age settings. Browser script previews cover custom transforms; fetch a subscription to validate native VLAN processing.

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
