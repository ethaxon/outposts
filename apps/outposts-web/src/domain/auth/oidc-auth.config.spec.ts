import { afterEach, describe, expect, it, vi } from "vitest";

async function loadConfigModule(options?: {
  appHost?: string;
  oidcIssuer?: string;
  oidcClientId?: string;
  callbackPath?: string;
  resourceConfigs?: Array<{ resource: string; scopes: string[] }>;
}): Promise<typeof import("./oidc-auth.config")> {
  vi.resetModules();
  vi.doMock("@/environments/environment", () => ({
    environment: {
      APP_HOST: options?.appHost ?? "host.outposts.example",
      OIDC_ISSUER: options?.oidcIssuer ?? "https://issuer.example/oidc",
      OIDC_CLIENT_ID: options?.oidcClientId ?? "client-id",
    },
  }));
  vi.doMock("./auth.defs", () => ({
    AUTH_CALLBACK_PATH: options?.callbackPath ?? "/auth/callback",
    AUTH_RESOURCE_CONFIGS: options?.resourceConfigs ?? [],
  }));

  return import("./oidc-auth.config");
}

function setWindowOrigin(origin?: string): void {
  if (origin) {
    Object.defineProperty(globalThis, "window", {
      value: {
        location: {
          origin,
        },
      },
      configurable: true,
      writable: true,
    });
    return;
  }

  Reflect.deleteProperty(globalThis, "window");
}

afterEach(() => {
  setWindowOrigin();
  vi.resetModules();
  vi.clearAllMocks();
});

describe("createOidcAuthConfig", () => {
  it("builds the Authentik-first single confluence OIDC contract with configured scopes and target resource params", async () => {
    setWindowOrigin("https://browser.outposts.example");
    const { createOidcAuthConfig } = await loadConfigModule({
      appHost: "ignored.example",
      oidcIssuer: "https://issuer.example/application/o/outposts/",
      oidcClientId: "outposts-web",
      resourceConfigs: [
        {
          resource: "https://confluence.example/api",
          scopes: ["openid", "profile", "email", "confluence", "offline_access", "confluence"],
        },
      ],
    });

    const oidcConfig = createOidcAuthConfig().config;

    if (!oidcConfig || Array.isArray(oidcConfig)) {
      throw new Error("expected a single OIDC config");
    }

    expect(oidcConfig.authority).toBe("https://issuer.example/application/o/outposts/");
    expect(oidcConfig.clientId).toBe("outposts-web");
    expect(oidcConfig.redirectUrl).toBe("https://browser.outposts.example/auth/callback");
    expect(oidcConfig.postLogoutRedirectUri).toBe("https://browser.outposts.example/");
    expect(oidcConfig.scope.split(" ")).toEqual([
      "openid",
      "profile",
      "email",
      "confluence",
      "offline_access",
    ]);
    expect(oidcConfig.customParamsAuthRequest).toEqual({
      resource: "https://confluence.example/api",
    });
    expect(oidcConfig.customParamsCodeRequest).toEqual({
      resource: "https://confluence.example/api",
    });
    expect(oidcConfig.customParamsRefreshTokenRequest).toEqual({
      resource: "https://confluence.example/api",
    });
  });

  it("falls back to APP_HOST and omits resource params when no target resource exists", async () => {
    const { createOidcAuthConfig } = await loadConfigModule({
      appHost: "app.outposts.example",
      resourceConfigs: [],
    });

    const oidcConfig = createOidcAuthConfig().config;

    if (!oidcConfig || Array.isArray(oidcConfig)) {
      throw new Error("expected a single OIDC config");
    }

    expect(oidcConfig.redirectUrl).toBe("https://app.outposts.example/auth/callback");
    expect(oidcConfig.postLogoutRedirectUri).toBe("https://app.outposts.example/");
    expect(oidcConfig.scope).toBe("");
    expect(oidcConfig.customParamsAuthRequest).toBeUndefined();
    expect(oidcConfig.customParamsCodeRequest).toBeUndefined();
    expect(oidcConfig.customParamsRefreshTokenRequest).toBeUndefined();
  });
});
