import { afterEach, describe, expect, it, vi } from "vitest";
import { fetchOidcConfigProjection } from "./auth-config-projection";

const VALID_PROJECTION = {
  wellKnownUrl: "https://auth.example.com/.well-known/openid-configuration",
  issuerUrl: "https://auth.example.com",
  clientId: "outposts-web",
  scopes: ["openid", "profile", "email", "confluence", "offline_access"],
  requiredScopes: ["openid", "profile", "email", "confluence", "offline_access"],
  redirectUrl: "https://app.example.com/auth/callback",
  pkceEnabled: true,
};

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("fetchOidcConfigProjection", () => {
  it("parses a valid config projection from the backend", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue({
        ok: true,
        json: () => Promise.resolve(VALID_PROJECTION),
      }),
    );

    const config = await fetchOidcConfigProjection({
      apiEndpoint: "https://confluence.example.com/api",
      redirectUri: "https://app.example.com/auth/callback",
      defaultPostAuthRedirectUri: "/",
    });

    expect(config.issuer).toBe("https://auth.example.com");
    expect(config.clientId).toBe("outposts-web");
    // redirectUri override always wins over projection's redirect_url
    expect(config.redirectUri).toBe("https://app.example.com/auth/callback");
    expect(config.scopes).toContain("confluence");
    expect(config.pkceEnabled).toBe(true);
    expect(config.defaultPostAuthRedirectUri).toBe("/");
  });

  it("makes the request to /api/auth/config with redirect_uri query param", async () => {
    const mockFetch = vi.fn().mockResolvedValue({
      ok: true,
      json: () => Promise.resolve(VALID_PROJECTION),
    });
    vi.stubGlobal("fetch", mockFetch);

    await fetchOidcConfigProjection({
      apiEndpoint: "https://confluence.example.com/api",
      redirectUri: "https://app.example.com/auth/callback",
    });

    const calledUrl = mockFetch.mock.calls[0][0] as string;
    expect(calledUrl).toContain("/api/auth/config");
    expect(calledUrl).toContain(
      `redirect_uri=${encodeURIComponent("https://app.example.com/auth/callback")}`,
    );
  });

  it("throws when backend returns an error status", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue({
        ok: false,
        status: 400,
        statusText: "Bad Request",
      }),
    );

    await expect(
      fetchOidcConfigProjection({
        apiEndpoint: "https://confluence.example.com/api",
        redirectUri: "https://app.example.com/auth/callback",
      }),
    ).rejects.toThrow("All config projection sources exhausted");
  });

  it("throws when projection body is missing required clientId", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue({
        ok: true,
        // Missing clientId — projection validation should fail.
        json: () =>
          Promise.resolve({
            ...VALID_PROJECTION,
            clientId: undefined,
          }),
      }),
    );

    await expect(
      fetchOidcConfigProjection({
        apiEndpoint: "https://confluence.example.com/api",
        redirectUri: "https://app.example.com/auth/callback",
      }),
    ).rejects.toThrow("All config projection sources exhausted");
  });

  it("defaults defaultPostAuthRedirectUri to / when not provided", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue({
        ok: true,
        json: () => Promise.resolve(VALID_PROJECTION),
      }),
    );

    const config = await fetchOidcConfigProjection({
      apiEndpoint: "https://confluence.example.com/api",
      redirectUri: "https://app.example.com/auth/callback",
    });

    expect(config.defaultPostAuthRedirectUri).toBe("/");
  });
});
