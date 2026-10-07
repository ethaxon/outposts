# Features

## Confluence

Confluence is a Clash subscription manager and configuration muxer.

- Manage Confluences, profiles, subscription sources, and profile transforms.
- Browse pages under **Apps → Confluence**: **Confluences** (`/confluence/confluences`),
  each Confluence (`/confluence/confluence/{id}`), **VLAN** (`/confluence/vlans`) and
  **Supplicants** (`/confluence/supplicants`). The former `/confluence/dashboard` and
  `/confluence/workspace/{id}` paths redirect to the new ones.
- Refresh sources on configurable Cron schedules and display subscription usage
  metadata where it is available.
- Merge selected sources into Clash-compatible output profiles.
- Edit YAML and transform scripts with Monaco.
- Preview rendered documentation with Markdown, Mermaid diagrams, KaTeX, and
  Prism syntax highlighting.

The API is served below `/api`; the web client uses `/api/auth/config` only to
obtain public OIDC client configuration. It is excluded from Bearer-token
interception.

### API routes

Management routes require sign-in and only return the caller's own records.
Collections are plural, kebab-case nouns. Per-item actions are sub-routes such
as `POST /{id}/sync`.

| Resource             | Routes                                                                                                                                           |
| -------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------ |
| Confluences          | `GET, POST /api/confluences`; `GET, PUT, DELETE /api/confluences/{id}`; `PUT /{id}/cron`, `PUT /{id}/vlans`, `POST /{id}/sync`, `POST /{id}/mux` |
| Subscription sources | `POST /api/subscribe_sources`; `PUT, DELETE /api/subscribe_sources/{id}`; `POST /{id}/sync`                                                      |
| Profiles             | `POST /api/profiles`; `PUT, DELETE /api/profiles/{id}`; `POST /{id}/preview`                                                                     |
| VLANs                | `GET, POST /api/vlans` (the list includes referenceable supplicants); `PUT, DELETE /api/vlans/{id}`; `POST /api/vlans/routes/aggregate`          |
| Supplicants          | `GET, POST /api/supplicants`; `PUT, DELETE /api/supplicants/{id}`                                                                                |

Public routes: `GET /api/profile_token/{token}` (the subscription URL that
clients store), `GET /api/health` and `GET /api/auth/config`.

### Subscription source refresh

A refresh requires a successful HTTP response containing Clash YAML with a non-empty `proxies` list. If a refresh fails, Confluence keeps the last successfully saved content and traffic metadata so the source can still be used for muxing. Muxing requires saved content for every source.

Source cards are ordered by creation time, oldest first. A failed refresh turns the status indicator red and adds a button to the card's actions for viewing the error. The details include the HTTP status, response headers, and up to 64 KiB of the response body when available. The next successful refresh clears the error.

### Profile age encryption

Open **Apps → Confluence → Supplicants** to add or edit the age public keys used by Profiles and VLANs. The page shows both reference counts. Clear those references before deleting a supplicant.

Edit a Profile and select one or more **age encryption recipients** from the Confluence supplicant catalog. A request without selectors uses all selected recipients. It returns a single age ciphertext each recipient can decrypt with their own key. An empty Profile recipient list serves YAML without injecting VLAN tunnels. Remove a supplicant from each Profile that references it before deleting it.

For clients that cannot load age-encrypted subscriptions, enable **Allow unsafe age private-key compatibility** on the Profile. The option is off by default. Add the following marker to the HTTPS request's `User-Agent`, replacing `PRIVATE_KEY` with the named supplicant's X25519 age private key.

```text
Client/1 confluence/supplicants=example-user&_unsafe_supplicant_private=PRIVATE_KEY
Client/1 confluence/supplicants=example-user&vlans=office&_unsafe_supplicant_private=PRIVATE_KEY
```

The request must resolve to exactly one supplicant. Confluence checks the key against that supplicant's stored public key and applies the usual Profile and VLAN permissions before returning plaintext YAML. It rejects this parameter in URL queries and excludes it from Profile transforms. Client and reverse-proxy logs may capture User-Agent headers. Use a dedicated key for this mode.

### Testing a Profile

**Test Profile Transform** on a Profile card renders the saved Profile on the server through the same pipeline as its subscription URL. Edit the request URL (including any `vlans`/`supplicants` selectors) and headers such as `User-Agent`, then select **Refresh**. The result shows the YAML before encryption and the body actually served, with the selected supplicants, included VLANs and age recipients. Only the Confluence creator can use it. The preview uses the Profile ID and requires sign-in.

## VLAN subscriptions

Open **Apps → Confluence → VLAN**. A Confluence can link multiple VLANs. Each VLAN defines destination CIDRs and an allowed supplicant list. Each tunnel grants access to a subset of that list. Removing a VLAN member revokes their tunnel grants.

Each **WireGuard** tunnel has one client configuration. Enter or import it, then select zero or more VLAN members who can use it. All selected members receive the same WireGuard configuration in their own subscriptions. Revoking access preserves the configuration. Import one [Interface] and one or more [Peer] sections. Supported fields are Address, PrivateKey, MTU, Endpoint, PublicKey, PresharedKey, AllowedIPs and PersistentKeepalive. All peers use the same keepalive.

Each tunnel's AllowedIPs must fit within the VLAN CIDRs. **Recompute VLAN CIDRs from tunnels** replaces the route draft with the normalized union of the peers' AllowedIPs. Each tunnel appears as one selectable Mihomo proxy. WireGuard chooses among its own peers. All VLAN routes point to the same selection group, and a selected tunnel may reach only part of the VLAN. Management responses show whether secrets are set.

The default selectors are both wildcards. `vlans=*` uses the enabled VLANs linked to the Confluence. `supplicants=*` uses all supplicants linked to the Profile. To restrict either set, supply a comma-separated list. For example, use `?vlans=office,lab&supplicants=alice,bob` or append `confluence/vlans=office,lab&supplicants=alice,bob` to the User-Agent. A selector present in both locations must agree.

Every selected supplicant must have access to a VLAN and to each included tunnel. Wildcard VLAN selection skips ineligible VLANs. Explicitly requesting one fails the request. A jointly accessible VLAN without any shared tunnels still produces its route rules and a selection group with REJECT first and DIRECT available. Confluence applies Profile transforms before VLAN injection and encrypts the result to all selected supplicants. Encrypted and unsafe-compatible subscriptions bypass shared caches.

### Database migration

PostgreSQL 18+ is required. Business primary keys use native `uuid` columns with database-generated `uuidv7()` defaults. Existing records and foreign keys are migrated together while preserving timestamps and subscription `resource_token` values. Management API IDs and routes use UUID strings. ts-rs exports these Rust `Uuid` fields through the named TypeScript scalar `UUIDV7 = string`; the alias provides a visible semantic name with structural string compatibility. Subscription credentials use independent random UUIDv4 tokens, exported as the TypeScript scalar `UUIDV4 = string`.

Stop Confluence and take a restorable backup before upgrading. Confluence 0.5 creates the final WireGuard and Profile schema directly on databases at or before the UUIDv7 migration. If your database applied the original seven migrations, replace their records in `seaql_migrations` with `m20261121_000001_confluence_vlan_and_profile` before starting 0.5. Keep the timestamp of the final original migration. If a database is partway through the original sequence, finish it with the previous build before updating the records. Use VLAN names without slot suffixes in subscription URLs and User-Agents. Start matching backend and frontend versions after migration.

Rolling back the combined migration returns to the UUIDv7 schema and removes VLAN and WireGuard data, Profile recipient links and the age compatibility setting, and saved subscription sync errors. Rolling back the UUIDv7 migration allocates new integer IDs while preserving relationships, timestamps, and subscription tokens. To recover discarded data or the original IDs, restore the corresponding database backup with its application build.

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
- Responsive application shell, Confluence forms, dialogs, toast feedback, and
  loading states.
- Feature-level loading for documentation assets so Prism, Mermaid, and KaTeX
  do not inflate the initial page.

---

[English](002-FEATURES.md) | [中文](../zh/002-FEATURES.md)
