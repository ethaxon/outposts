# Outposts Overview

Outposts is a personal **Digital Outpost** for managing side projects and homelab services.

## Components

| Code | Description | Status |
|------|-------------|--------|
| **Confluence** | Clash subscription mux and manager | Implemented |
| **SSO** | OIDC SSO baseline for Authentik or any standard OIDC provider | Implemented |
| **Outposts-web** | Angular 20 portal | Implemented |
| **SecurityDept** | MFA checkpoint for L4 services | Planned |
| **CelestialGates** | Service web portal / teleportation | Planned |
| **Yü-shih** | System monitor client & center | Planned |

## Quick Start

```sh
# Edit .env, then:
docker compose up
```

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
- [100-ROADMAP.md](100-ROADMAP.md)
