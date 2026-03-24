# Features

## Confluence (Clash Subscription Manager)

**Purpose**: Manage and mux multiple Clash subscription sources into unified configs.

### Core Features

- **Subscription Sources**: Add/remove/update subscription URLs with name and tags
- **Passive Sync**: Auto-refresh subscriptions on configurable cron schedule
- **Profile Management**: Create profiles (configs) linked to a confluence
- **Config Muxing**: Merge multiple subscription sources into single Clash config
- **Userinfo Extraction**: Parse Clash subscription userinfo from HTTP headers (upload/total/download/expiry)
- **JWT Auth**: Validate tokens via biscuit JWT/JWK with JWKS caching
- **OIDC SSO**: Integrate with Logto for authentication

### API Endpoints

- `POST /api/confluences` — Create confluence
- `GET /api/confluences` — List user's confluences
- `GET /api/confluences/:id` — Get confluence with profiles & sources
- `PUT /api/confluences/:id` — Update confluence
- `DELETE /api/confluences/:id` — Delete confluence
- `POST /api/confluences/:id/sources` — Add subscription source
- `PUT /api/sources/:id` — Update source
- `DELETE /api/sources/:id` — Remove source
- `GET /api/confluences/:id/mux` — Get muxed Clash config
- `POST /api/confluences/:id/profiles` — Create profile
- `PUT /api/profiles/:id` — Update profile
- `DELETE /api/profiles/:id` — Delete profile

## SSO (OIDC via Logto)

- Integration with self-hosted Logto instance
- JWT token validation
- JWKS key rotation support

## Outposts-web (Frontend Portal)

- Angular 20 SPA
- PrimeNG UI components
- i18n via Transloco
- Angular SSR for SEO

---

[English](002-FEATURES.md) | [中文](../zh/002-FEATURES.md)
