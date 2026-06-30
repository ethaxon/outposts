# Architecture

## Technology Stack

| Layer          | Current implementation                                                               |
| -------------- | ------------------------------------------------------------------------------------ |
| Frontend       | Angular 22, Nx 23, Spartan NG (Helm/Brain), Tailwind CSS v4, Lucide icons, Transloco |
| Backend        | Rust, Axum, Sea-ORM, PostgreSQL, Tokio                                               |
| Authentication | Securitydept resource-server validation and frontend OIDC client registry            |
| Delivery       | Docker Compose, nginx static host, Bun/Node projection host                          |
| Tooling        | pnpm 11, TypeScript 6, mise, cargo, just                                             |

`outposts-web` is a browser-only SPA. It does not implement SSR.

## Project Structure

```text
outposts/
├── apps/
│   ├── confluence/         # Rust API and subscription-mux service
│   ├── outposts-web/       # Angular application
│   ├── outposts-web-host/  # Runtime OIDC projection injector
│   └── dev-proxy/          # Development reverse proxy
├── assets/                 # Shared static assets
├── docs/                   # English and Chinese product documentation
└── docker-compose*.yml     # Local and deployment orchestration
```

## Confluence

Confluence manages subscription sources, profiles, and merged Clash-compatible
configuration.

- Axum exposes the HTTP API and Sea-ORM persists its data in PostgreSQL.
- Tokio Cron Scheduler refreshes subscription sources according to configured schedules.
- In OIDC mode, Securitydept verifies access tokens through provider discovery,
  JWKS, optional audience validation, and required scopes.
- `AUTH_TYPE=DEV` accepts requests without credentials only in Rust debug builds;
  it is deliberately rejected by release builds.

## Web Application and Runtime Configuration

The Angular application is built once and served by nginx. Its OIDC settings are
not compiled into the application bundle:

1. `outposts-web-host` fetches each backend's public `/api/auth/config`
   projection.
2. It writes an HTML bootstrap script into the shared served `index.html`.
3. The Angular Securitydept client registry resolves that injected projection,
   then its persisted cache, then the backend endpoint as a fallback.

The application shell uses Spartan NG primitives and locally generated Helm
component libraries. Business layouts and feature styling remain application
code. Transloco provides English and Simplified Chinese UI text. Monaco,
Chart.js, Mermaid, KaTeX, and Prism remain feature-specific integrations;
Prism, Mermaid, and KaTeX load only when documentation content needs them.

## Development

```sh
docker compose -f docker-compose.dev-deps.yml up -d
just dev-confluence
just dev-webui
just dev-proxy
```

Copy `.env.example` to `.env` before starting services. See
[Authentication](003-AUTH.md) for the environment-variable contract.

---

[English](001-ARCHITECTURE.md) | [中文](../zh/001-ARCHITECTURE.md)
