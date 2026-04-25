import { describe, expect, it } from "vitest";
import { AuthCallbackPath, AuthCallbackRouteSegment, AuthClientKey } from "./auth.defs";

// Iteration 150 (outposts adopter calibration):
//
// These are pure consistency tests for the provider-neutral auth boundary
// surface. They lock in the contract between the Angular Router segment used
// in `app.routes.ts` and the absolute path used as both OIDC redirect_uri and
// SDK callbackPath in `auth.providers.ts`.
//
// If anyone changes one without the other, this fails immediately and forces
// the boundary to remain a single source of truth.
describe("auth.defs — provider-neutral boundary", () => {
  it("AuthCallbackPath is the absolute /-prefixed form of AuthCallbackRouteSegment", () => {
    expect(AuthCallbackPath).toBe(`/${AuthCallbackRouteSegment}`);
    expect(AuthCallbackPath.startsWith("/")).toBe(true);
    expect(AuthCallbackRouteSegment.startsWith("/")).toBe(false);
  });

  it("AuthCallbackPath is /auth/callback (locked by SDK callback semantics)", () => {
    // The SDK callback discrimination uses the absolute pathname; a drift
    // here would silently break TokenSetCallbackComponent route routing.
    expect(AuthCallbackPath).toBe("/auth/callback");
  });

  it("AuthClientKey values are requirement keys, NOT provider identities", () => {
    // confluence is the requirement / app key; "authentik" lives ONLY in the
    // providerFamily field of provideTokenSetAuth() and never in this enum.
    const values = Object.values(AuthClientKey);
    expect(values).toContain("confluence");
    expect(values).not.toContain("authentik");
    expect(values).not.toContain("oidc");
    expect(values).not.toContain("logto");
    expect(values).not.toContain("angular-auth-oidc-client");
  });

  it("AuthClientKey is frozen-shape const enum (TS string-literal domain)", () => {
    // Lock the as-const projection: keys and values must coincide with the
    // string-literal domain so guards / interceptor URL-prefix routing keep
    // working when more apps are added.
    expect(AuthClientKey.Confluence).toBe("confluence");
  });
});
