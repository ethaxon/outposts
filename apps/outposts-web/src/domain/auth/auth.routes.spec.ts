import { describe, expect, it } from "vitest";
import { AuthCallbackRouteSegment, AuthClientKey } from "./auth.defs";

// Iteration 150 (outposts adopter calibration):
//
// These tests pin down the route-shape contract between outposts and the
// securitydept Angular adapter:
//   1. /auth/callback is the canonical callback route.
//   2. The secured "confluence" route subtree expresses provider-neutral
//      requirement metadata (kind: "frontend_oidc"), NOT a provider-specific
//      identity ("authentik" / "oidc" / etc.).
//   3. The callback route is registered BEFORE the secured route subtree so
//      it cannot be intercepted by the route-aggregation guard.
//
// We import `routes` lazily so the heavier Angular module graph is only
// touched when the test is actually executed; this keeps the spec's failure
// mode focused on routing intent rather than DI bootstrap problems.

async function loadRoutes() {
  const mod = await import("@/app/app.routes");
  return mod.routes;
}

describe("outposts app routes — provider-neutral wiring", () => {
  it("registers the SDK callback route at the AuthCallbackRouteSegment path", async () => {
    const routes = await loadRoutes();
    const callback = routes.find((r) => r.path === AuthCallbackRouteSegment);
    expect(callback).toBeDefined();
    expect(callback?.component?.name).toBe("TokenSetCallbackComponent");
    // No guard on the callback route itself — it MUST be reachable when
    // unauthenticated, otherwise the OIDC redirect-back can never complete.
    expect(callback?.canActivate).toBeUndefined();
    expect(callback?.canActivateChild).toBeUndefined();
  });

  it("declares /auth/callback BEFORE any secured route subtree", async () => {
    const routes = await loadRoutes();
    const callbackIndex = routes.findIndex((r) => r.path === AuthCallbackRouteSegment);
    expect(callbackIndex).toBeGreaterThanOrEqual(0);

    // The secured "confluence" subtree lives nested under a "" parent; locate
    // it by walking children for a node with canActivate (secureRouteRoot
    // adds the aggregation guard).
    const securedParentIndex = routes.findIndex((r) =>
      (r.children ?? []).some(
        (c) =>
          (Array.isArray(c.canActivate) && c.canActivate.length > 0) ||
          (Array.isArray(c.canActivateChild) && c.canActivateChild.length > 0),
      ),
    );
    expect(securedParentIndex).toBeGreaterThanOrEqual(0);
    expect(callbackIndex).toBeLessThan(securedParentIndex);
  });

  it("secured confluence route declares provider-neutral requirement metadata", async () => {
    const routes = await loadRoutes();
    let confluenceRoute: { data?: Record<string, unknown> } | undefined;
    for (const r of routes) {
      for (const c of r.children ?? []) {
        if (c.path === AuthClientKey.Confluence) {
          confluenceRoute = c;
        }
      }
    }
    expect(confluenceRoute).toBeDefined();
    const data = confluenceRoute?.data ?? {};

    // Find the requirements array regardless of which key the SDK helper
    // serialised it under (withRouteRequirements uses an internal key).
    let requirements: Array<Record<string, unknown>> | undefined;
    for (const value of Object.values(data)) {
      if (Array.isArray(value) && value.length > 0 && typeof value[0] === "object") {
        const candidate = value as Array<Record<string, unknown>>;
        if (candidate.every((v) => "kind" in v)) {
          requirements = candidate;
          break;
        }
      }
    }
    expect(requirements).toBeDefined();
    expect(requirements?.[0]?.["kind"]).toBe("frontend_oidc");
    // Provider-neutral assertion: NO requirement kind / id / label leaks the
    // provider name. "authentik" is purely a config-projection input and
    // must NEVER appear in route metadata.
    const serialized = JSON.stringify(requirements);
    expect(serialized).not.toMatch(/authentik/i);
    expect(serialized).not.toMatch(/logto/i);
  });

  it("secured confluence route has both canActivate and canActivateChild guards", async () => {
    const routes = await loadRoutes();
    let confluenceRoute: { canActivate?: unknown[]; canActivateChild?: unknown[] } | undefined;
    for (const r of routes) {
      for (const c of r.children ?? []) {
        if (c.path === AuthClientKey.Confluence) {
          confluenceRoute = c;
        }
      }
    }
    expect(confluenceRoute).toBeDefined();
    expect(Array.isArray(confluenceRoute?.canActivate)).toBe(true);
    expect((confluenceRoute?.canActivate ?? []).length).toBeGreaterThan(0);
    expect(Array.isArray(confluenceRoute?.canActivateChild)).toBe(true);
    expect((confluenceRoute?.canActivateChild ?? []).length).toBeGreaterThan(0);
  });
});
