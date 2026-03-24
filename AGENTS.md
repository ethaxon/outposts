# AGENTS.md

_Single source of truth. `CLAUDE.md` and `GEMINI.md` symlink here. Only edit this `AGENTS.md`._

## Identity

- **Role**: Expert coding assistant
- **Chat**: User's language (Chinese if user uses Chinese)
- **Code/Comments**: English ONLY
- **Style**: Concise, technical, action-oriented

## Code Standards

- Comments explain _why_, not _what_; update docs when logic changes
- Use mature community libraries over custom implementations
- Do NOT auto-commit — ask before staging/committing
- YAML: 2-space indent; Bash: `set -e`, `[[ ]]`, quote variables
- Docs reflect current/future state only; history → CHANGELOG.md

## Project Structure

```
apps/
  confluence/     # Rust backend: Axum + Sea-ORM + PostgreSQL
  outposts-web/   # Angular 20 frontend: Nx + PrimeNG + TailwindCSS
  dev-proxy/      # Development proxy
assets/           # Static assets
docker-compose*.yml  # Container orchestration
```

## Tech Stack

| Layer | Stack |
|-------|-------|
| Frontend | Angular 20, Nx, PrimeNG, TailwindCSS, `@jsverse/transloco` |
| Backend | Rust, Axum, Sea-ORM, PostgreSQL, tokio |
| Tools | `mise`, `pnpm`, `cargo`, `just` |

## Backend Rules (`apps/confluence/`)

- Error handling: `anyhow` + `thiserror`
- Bindings: `ts-rs` for TypeScript generation
- Structure: `models/` (entities), `services.rs` (logic), `tasks/` (cron), `migrations/` (DB)

## Frontend Rules (`apps/outposts-web/`)

- Use standalone components, signals where appropriate
- i18n via `transloco`; keys in `transloco.config.js`

## Task Runner (`justfile`)

- `just dev-confluence` / `just dev-webui` / `just dev-proxy`
- `just container-build` / `just container-deploy`
- `docker compose -f docker-compose.dev-deps.yml up -d` for dev deps
- Verify build/lint/tests pass after each iteration

## Multi-language Docs

- Structure: `docs/{lang}/00x-TITLE.md` (en, zh)
- Translate user-facing docs only (not AGENTS.md, CLAUDE.md, etc.)
- Add bidirectional links at bottom: `[English](../en/xxx.md) | [中文](xxx.md)`
