# Outposts Overview

Outposts is a personal **Digital Outpost** for managing side projects and homelab services.

## Components

| Code               | Description                                                   | Status      |
| ------------------ | ------------------------------------------------------------- | ----------- |
| **Confluence**     | Clash subscription mux and manager                            | Implemented |
| **SSO**            | OIDC SSO baseline for Authentik or any standard OIDC provider | Implemented |
| **Outposts-web**   | Angular 22 portal using Spartan NG                            | Implemented |
| **Securitydept**   | Security and authentication infrastructure toolkit            | Integrated  |
| **CelestialGates** | Service web portal / teleportation                            | Planned     |
| **Yü-shih**        | System monitor client & center                                | Planned     |

## Quick Start

```sh
cp .env.example .env
# Review .env, then:
docker compose up
```

The compose stack starts PostgreSQL, Confluence, the static web host, and the
web-host sidecar that injects public OIDC configuration into the served HTML.

## Dev Setup

```sh
# Dev dependencies
docker compose -f docker-compose.dev-deps.yml up -d

# Backend
just dev-confluence

# Frontend
just dev-webui

# Proxy
just dev-proxy
```

## Document Index

- [001-ARCHITECTURE.md](001-ARCHITECTURE.md)
- [002-FEATURES.md](002-FEATURES.md)
- [003-AUTH.md](003-AUTH.md)
- [100-ROADMAP.md](100-ROADMAP.md)

---

[English](000-OVERVIEW.md) | [中文](../zh/000-OVERVIEW.md)
