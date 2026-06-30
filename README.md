<h1 align="center">
  <img src="./assets/icons/logo-512.png" height="150" alt="OUTPOSTS">
  <div style="color: #232848; font-weight: 700;">OUTPOSTS</div>
  <div align="center">
    <img src="https://img.shields.io/badge/status-work--in--progress-blue" alt="status-badge" />
  </div>
</h1>

<p align="center">Build My Personal <b>Digital Outpost</b> for Side Projects and Homelabs</p>

## Quick Start

Create and review the local configuration, then start the stack:

```sh
cp .env.example .env
# Edit .env for your database and OIDC provider.
docker compose up
```

The frontend, backend, and production projection host share this configuration. See the
[English documentation](docs/en/000-OVERVIEW.md) or [中文文档](docs/zh/000-OVERVIEW.md)
for development and authentication details.

## Roadmap

- [x] Confluence: A clash subscriber source muxer and manage service.
- [x] SSO: A standard OIDC SSO baseline for Authentik or any compatible provider.
- [x] [Securitydept](https://github.com/ethaxon/securitydept): a security and authentication infrastructure toolkit; Outposts currently uses its OIDC capabilities.
- [ ] CelestialGates: Web portal or teleportation for services.
- [ ] Yü-shih / Yü-shih T’ai: System monitor client and center service.
