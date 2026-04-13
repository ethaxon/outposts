import { afterEach, describe, expect, it, vi } from "vitest";

async function loadDefsModule(confluenceApiEndpoint = "https://confluence.example/api") {
  vi.resetModules();
  vi.doMock("@/environments/environment", () => ({
    environment: {
      CONFLUENCE_API_ENDPOINT: confluenceApiEndpoint,
    },
  }));

  return import("./confluence.defs");
}

afterEach(() => {
  vi.resetModules();
  vi.clearAllMocks();
});

describe("AUTH_CONFLUENCE_CONFIG", () => {
  it("reads the resource endpoint from the environment", async () => {
    const { AUTH_CONFLUENCE_CONFIG } = await loadDefsModule("https://confluence.example/api");

    expect(AUTH_CONFLUENCE_CONFIG).toEqual({
      resource: "https://confluence.example/api",
    });
  });
});
