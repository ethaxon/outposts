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

function mockBrowserWindow(origin: string): Window {
  const protocol = origin.startsWith("https") ? "https:" : "http:";
  return { location: { origin, protocol } } as Window;
}

afterEach(() => {
  vi.resetModules();
  vi.clearAllMocks();
});

describe("createOidcAuthConfig", () => {
  it("builds the single confluence OIDC config with configured scopes (no resource params sent to provider)", async () => {
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

    const oidcConfig = createOidcAuthConfig(
      mockBrowserWindow("https://browser.outposts.example"),
    ).config;

    if (!oidcConfig || Array.isArray(oidcConfig)) {
      throw new Error("expected a single OIDC config");
    }

    expect(oidcConfig.authority).toBe("https://issuer.example/application/o/outposts/");
    expect(oidcConfig.clientId).toBe("outposts-web");
    expect(oidcConfig.redirectUrl).toBe("https://browser.outposts.example/auth/callback");
    expect(oidcConfig.postLogoutRedirectUri).toBe("https://browser.outposts.example/");
    expect(oidcConfig.scope?.split(" ")).toEqual([
      "openid",
      "profile",
      "email",
      "confluence",
      "offline_access",
    ]);
    // RFC 8707 resource params are NOT sent — Authentik does not support resource indicators
    expect(oidcConfig.customParamsAuthRequest).toBeUndefined();
    expect(oidcConfig.customParamsCodeRequest).toBeUndefined();
    expect(oidcConfig.customParamsRefreshTokenRequest).toBeUndefined();

    // Silent renew tuning
    expect(oidcConfig.renewTimeBeforeTokenExpiresInSeconds).toBe(75);
    expect(oidcConfig.triggerRefreshWhenIdTokenExpired).toBe(false);
  });

  it("falls back to APP_HOST when no browser Window is available", async () => {
    const { createOidcAuthConfig } = await loadConfigModule({
      appHost: "app.outposts.example",
      resourceConfigs: [],
    });

    const oidcConfig = createOidcAuthConfig(null).config;

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

describe("resolveAppOriginFromWindow (sign-in redirect_uri vs localStorage origin)", () => {
  /**
   * Return path is stored under the *current page* origin. If authorize() used a
   * redirect_uri on a different host than window.location.origin (e.g. env
   * APP_HOST=localhost while the user opened 127.0.0.1), the IdP sends the
   * browser to the wrong origin and localStorage does not contain the key —
   * post-login navigation falls back to "/".
   */
  it("uses window.location.origin even when APP_HOST names a different host", async () => {
    const { resolveAppOriginFromWindow, createOidcAuthConfig } = await loadConfigModule({
      appHost: "localhost:4200",
      resourceConfigs: [],
    });

    const win = mockBrowserWindow("http://127.0.0.1:4200");

    expect(resolveAppOriginFromWindow(win)).toBe("http://127.0.0.1:4200");

    const oidcConfig = createOidcAuthConfig(win).config;
    if (!oidcConfig || Array.isArray(oidcConfig)) {
      throw new Error("expected a single OIDC config");
    }
    expect(oidcConfig.redirectUrl).toBe("http://127.0.0.1:4200/auth/callback");
  });

  it("rejects the legacy redirect_uri formula that mixed protocol + APP_HOST", async () => {
    const { resolveAppOriginFromWindow } = await loadConfigModule({
      appHost: "localhost:4200",
      callbackPath: "/auth/callback",
      resourceConfigs: [],
    });

    const win = mockBrowserWindow("http://127.0.0.1:4200");
    const callbackPath = "/auth/callback";
    const legacyAuthorizeRedirect = `${win.location.protocol}//localhost:4200${callbackPath}`;
    const fromSharedResolver = `${resolveAppOriginFromWindow(win)}${callbackPath}`;

    expect(legacyAuthorizeRedirect).toBe("http://localhost:4200/auth/callback");
    expect(fromSharedResolver).toBe("http://127.0.0.1:4200/auth/callback");
    expect(legacyAuthorizeRedirect).not.toBe(fromSharedResolver);
  });
});
