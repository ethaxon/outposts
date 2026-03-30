# Auth Plan

This document describes the current auth baseline and next steps for `outposts`. The current single-`confluence` path has already been narrowed to a **standard OIDC / Authentik-first** runtime surface. The next step is to continue validating multi-backend and multi-OIDC-client scenarios on top of that baseline instead of preserving any Logto-era transition assumptions.

The current project scope already includes at least:

- `outposts-web`
- `confluence`
- future `app1`
- future `app2`

## Current Reading

### 1. Frontend problem

`outposts-web` already has a standard OIDC driver and focused evidence for the single-`confluence` flow, but two real constraints remain:

- route guards, callback handling, token access, and user state are still mostly concentrated in one `AuthService`
- the current runtime still looks close to “single app, single OIDC client, single resource happy path”

That may still work when only `confluence` is integrated. Once the same frontend host must support `confluence`, `app1`, and `app2`, the more realistic problems appear:

- different apps may use different OIDC clients
- different apps may require different audiences / scopes
- one frontend route area may require credentials for more than one app

### 2. Backend problem

The `confluence` backend still selects its OIDC branch via `AUTH_TYPE=OIDC`, but its Bearer validation is now directly narrowed to `securitydept-oauth-resource-server`:

- OIDC discovery
- provider metadata / JWKS fetch and refresh
- issuer validation
- audience validation
- required-scope validation

So the real near-term refactor focus should be:

- a provider-neutral frontend auth boundary
- route-level orchestration for multiple requirements
- a clearer and configurable issuer / audience / scope contract across services

not rewriting every backend into a new auth framework first.

## Target Architecture

### Frontend: provider-neutral auth boundary

`outposts-web` should move toward these boundaries:

1. **Keep the auth core interface provider-neutral**
   - sign in
   - sign out
   - callback handling
   - access-token retrieval
   - user/auth-state observation

2. **Treat the OIDC provider SDK as a replaceable driver**
   - the current single-`confluence` flow already uses a standard OIDC client as the only runtime path
   - the practical near-term target is Authentik or any standard OIDC provider
   - the frontend should stay on a standard OIDC client behind a provider-neutral boundary instead of re-binding to another provider SDK

3. **Do not let route guards hard-code one IdP calling style**
   - guards should express “which requirements this route needs”
   - orchestration should live in a separate layer

### Backend: keep a provider-neutral OIDC contract

Each backend service should continue to follow:

- standard OIDC discovery / JWT resource-server verification for Bearer tokens
- issuer / audience / scope controlled by config
- no reverse dependency on frontend SDK-specific behavior

For `confluence`, the current single-path OIDC contract should be read as:

- `OIDC_ISSUER`: the standard OIDC issuer
- `OUTPOSTS_WEB_OIDC_CLIENT_ID`: the frontend OIDC client id
- `CONFLUENCE_API_ENDPOINT`: the frontend API base URL for `confluence`, also used as the current single-resource request-targeting parameter
- `CONFLUENCE_OIDC_AUDIENCE`: the backend Bearer-token audience expectation
- `CONFLUENCE_OIDC_SCOPES`: the shared frontend/backend scope contract for the current single path, with default value `openid profile email confluence offline_access`

In practice:

- `outposts-web` uses that scope set to build the OIDC authorize / code / refresh request scope
- `confluence` uses the same scope set as the required-scope policy inside `securitydept-oauth-resource-server`

In the current deployment, `CONFLUENCE_API_ENDPOINT` and `CONFLUENCE_OIDC_AUDIENCE` may use the same value, but their meanings are now explicitly separated so that the browser request URL and JWT audience are no longer conflated.

## Multi-Backend / Multi-OIDC-Client Scenario

This is the most important new constraint.

`outposts-web` is not just “one frontend talking to one protected backend”, but:

- one frontend host
- multiple backend services
- different services potentially using different OIDC clients / audiences / scope sets

That means the frontend can no longer model only “am I signed in now?”. It needs to express:

- which app requirements are active
- whether each requirement is already satisfied
- which requirement can be acquired silently
- which requirement requires interactive redirect

## How to Schedule Authorization When One Route Needs Multiple Credentials

For example, one route area may require:

- `app1`
- `app2`

It is not a good idea to hard-code this into “automatically do two redirects in sequence”, because in real product flows:

- the user may not understand why two redirects happen
- some requirements may be silent and some interactive
- failure of one requirement may not need to block the entire page
- some scenarios are better served by showing a chooser first

The recommended boundary is:

1. **The app keeps full freedom**
   - whether to show a chooser first
   - whether to authorize sequentially
   - how to degrade when one step fails
   - whether some functionality may load before the full requirement set is satisfied

2. **The lower-level orchestration should stay headless**
   - input: current route requirements, token state, pending callback state
   - output: the next action to take

A recommended action model can look like:

- `satisfied`
- `acquire_silently(requirement)`
- `redirect(requirement)`
- `prompt_user(choices, remaining)`
- `blocked(reason)`

Recommended default policy:

1. check which requirements are already satisfied
2. satisfy silent requirements first when possible
3. if only one interactive requirement remains, allow a direct redirect by default
4. if multiple interactive requirements remain, default to `prompt_user`
5. after callback, resume the pending plan and continue the remaining requirements

## SDK vs App Ownership Boundary

Given the current `securitydept` direction, the boundary should be:

### App-owned

- chooser UI
- router policy
- page-level auth UX
- business-specific fallback / degradation when one requirement fails

### Possibly SDK-owned later

- requirement model
- headless scheduler / orchestrator
- pending callback recovery primitive
- the thinnest possible `web` / `angular` / `react` adapters

In other words:

- `outposts` should validate this orchestration model at the app layer first
- only the stable parts should later move back into `securitydept`

## Near-Term Delivery Stages

The near-term work should proceed in this order instead of one large migration.

### Stage 1: standard OIDC / Authentik-first baseline

Goal:

- the current single-`confluence` flow is already on the standard OIDC driver
- frontend config naming is narrowed to `OIDC_ISSUER` / `OUTPOSTS_WEB_OIDC_CLIENT_ID`
- focused tests lock callback / redirect / target-resource contract

### Stage 2: align backend issuer / audience / scope

Goal:

- let `confluence` align with Authentik claims first
- let `securitydept-oauth-resource-server` carry the single-path Bearer-token verification
- make each service explicit about:
  - issuer
  - audience
  - required scopes

### Stage 3: route-level requirement orchestration prototype

Goal:

- build the first prototype in `outposts-web` itself
- do not rush it into the SDK
- validate whether the combination of headless scheduler + chooser UI is actually workable

### Stage 4: feed stable parts back into `securitydept`

Goal:

- promote only the stable requirement model / scheduler abstractions into `securitydept`
- keep chooser UI and router glue in `outposts`

## Local Workspace Dependency Rules

During this refactor, do not optimize around published package versions first.

### Rust

Keep using workspace `path` dependencies, for example:

```toml
[workspace.dependencies]
securitydept-core = { path = "../securitydept/packages/core" }
```

If `confluence` needs more local crates later, keep using the same `path` approach.

### Node / pnpm

Prefer local `link:` references, for example:

```json
{
  "dependencies": {
    "@securitydept/token-set-context-client": "link:../securitydept/sdks/ts/packages/token-set-context-client",
    "@securitydept/session-context-client": "link:../securitydept/sdks/ts/packages/session-context-client"
  }
}
```

Rules:

- declare dependencies at the package root only, not per subpath
- during active refactor, do not first integrate a published version and later switch back to a local link
- the whole point of local links is to let `outposts` validate the latest `securitydept` boundaries directly

## Current Conclusion

`outposts` should not be read as a project that is still in a Logto-transition intermediate state.  
The more accurate target is:

- stabilize the current single-`confluence` flow on a standard OIDC / Authentik-first baseline
- keep the current single-`confluence` backend Bearer path on `oauth-resource-server`
- keep evolving the frontend from a single-provider happy path into a provider-neutral auth boundary
- keep the backend on a provider-neutral OIDC validation model
- use real multi-backend, multi-requirement route scenarios to validate future scheduler abstractions
- feed only the stable pieces back into `securitydept`

---

[English](003-AUTH.md) | [中文](../zh/003-AUTH.md)
