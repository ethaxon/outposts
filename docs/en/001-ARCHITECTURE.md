# Architecture

## Tech Stack

| Layer | Stack |
|-------|-------|
| Frontend | Angular 20, Nx, PrimeNG, TailwindCSS, `@jsverse/transloco` |
| Backend | Rust, Axum, Sea-ORM, PostgreSQL, tokio |
| Auth | OIDC via Logto, biscuit (JWT/JWK) |
| Container | Docker Compose |
| Tools | mise, pnpm, cargo, just |

## Project Structure

```
outposts/
├── apps/
│   ├── confluence/      # Rust backend server
│   │   └── src/
│   │       ├── auth/       # OIDC authentication
│   │       ├── clash/      # Clash config parsing
│   │       ├── models/     # Sea-ORM entities
│   │       ├── migrations/ # DB migrations
│   │       ├── services.rs # Business logic
│   │       ├── tasks/      # Cron scheduled jobs
│   │       └── mux/        # Config muxing
│   ├── outposts-web/   # Angular frontend
│   └── dev-proxy/      # Dev reverse proxy
├── assets/             # Static assets
└── docker-compose*.yml # Container orchestration
```

## Confluence Backend

Confluence is the core backend service managing Clash subscription sources:

- **HTTP Layer**: Axum with tower-http (CORS, tracing, static files)
- **Database**: PostgreSQL via Sea-ORM
- **Auth**: OIDC via openidconnect + biscuit for JWT/JWK
- **Scheduling**: tokio-cron-scheduler for subscription sync
- **State**: Shared `AppState` with DB connection, config, JWKS cache, OIDC provider cache

### Key Modules

- `clash/` — Parse Clash subscription userinfo headers
- `services.rs` — CRUD for confluences, profiles, subscribe sources
- `mux/` — Merge multiple subscription configs
- `auth/` — JWT validation, OIDC provider config

## Frontend

Angular 20 SPA with:

- Nx monorepo workspace
- PrimeNG components
- TailwindCSS styling
- Transloco i18n
- Angular SSR for initial load

---

[English](001-ARCHITECTURE.md) | [中文](../zh/001-ARCHITECTURE.md)
