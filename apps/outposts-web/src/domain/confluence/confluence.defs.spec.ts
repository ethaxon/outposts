import { afterEach, describe, expect, it, vi } from "vitest";

async function loadDefsModule(scopes = "openid profile email confluence offline_access") {
  vi.resetModules();
  vi.doMock("@/environments/environment", () => ({
    environment: {
      CONFLUENCE_API_ENDPOINT: "https://confluence.example/api",
      CONFLUENCE_OIDC_SCOPES: scopes,
    },
  }));

  return import("./confluence.defs");
}

afterEach(() => {
  vi.resetModules();
  vi.clearAllMocks();
});

describe("AUTH_CONFLUENCE_CONFIG", () => {
  it("parses configured confluence scopes from the shared env contract", async () => {
    const { AUTH_CONFLUENCE_CONFIG } = await loadDefsModule(
      "openid,profile email confluence offline_access confluence",
    );

    expect(AUTH_CONFLUENCE_CONFIG).toEqual({
      resource: "https://confluence.example/api",
      scopes: ["openid", "profile", "email", "confluence", "offline_access"],
    });
  });
});
