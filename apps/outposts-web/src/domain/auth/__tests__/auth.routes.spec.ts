import { readSecuritydeptRouteMetadata } from "@securitydept/client";
import { describe, expect, it } from "vitest";
import { AuthCallbackRouteSegment, AuthClientKey } from "../auth.defs";

async function loadRoutes() {
  return (await import("../../../app/app.routes")).routes;
}

describe("outposts auth routes", () => {
  it("exposes the callback component without authentication guards", async () => {
    const routes = await loadRoutes();
    const callback = routes.find((route) => route.path === AuthCallbackRouteSegment);

    expect(callback?.component?.name).toBe("AuthCallbackComponent");
    expect(callback?.canActivate).toBeUndefined();
    expect(callback?.canActivateChild).toBeUndefined();
  });

  it("binds the secured Confluence subtree to its registry client", async () => {
    const routes = await loadRoutes();
    const confluenceRoute = routes
      .flatMap((route) => route.children ?? [])
      .find((route) => route.path === AuthClientKey.Confluence);
    const requirements = readSecuritydeptRouteMetadata(confluenceRoute?.data)?.requirements;

    expect(requirements).toEqual([
      expect.objectContaining({
        id: "confluence-oidc",
        label: "Confluence OIDC",
        attributes: { query: { clientKey: AuthClientKey.Confluence } },
      }),
    ]);
  });
});
