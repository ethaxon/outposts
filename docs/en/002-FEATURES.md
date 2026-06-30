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
