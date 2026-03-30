import type { OidcSecurityService } from "angular-auth-oidc-client";
import { of } from "rxjs";
import { describe, expect, it, vi } from "vitest";
import { createOidcAuthDriver } from "./oidc-auth.driver";

function createOidcSecurityServiceStub() {
  return {
    authorize: vi.fn(),
    checkAuth: vi.fn(() => of({ isAuthenticated: true })),
    getAccessToken: vi.fn(() => of("access-token")),
    getPayloadFromAccessToken: vi.fn(() => of({ scope: "confluence:read confluence:write" })),
    getUserData: vi.fn(() => of(null)),
    logoff: vi.fn(() => of(undefined)),
  } as unknown as OidcSecurityService & {
    authorize: ReturnType<typeof vi.fn>;
    checkAuth: ReturnType<typeof vi.fn>;
    getAccessToken: ReturnType<typeof vi.fn>;
    getPayloadFromAccessToken: ReturnType<typeof vi.fn>;
    getUserData: ReturnType<typeof vi.fn>;
    logoff: ReturnType<typeof vi.fn>;
  };
}

function createDriver(oidcSecurityService = createOidcSecurityServiceStub()) {
  return {
    driver: createOidcAuthDriver(oidcSecurityService, {
      redirectUrl: "https://outposts.example/auth/callback",
      postLogoutRedirectUri: "https://outposts.example/",
    }),
    oidcSecurityService,
  };
}

describe("createOidcAuthDriver", () => {
  it("recognizes callback URLs that match the configured redirect route", async () => {
    const { driver } = createDriver();

    await expect(
      driver.isRedirectCallback(
        "https://outposts.example/auth/callback?code=auth-code&state=return-here",
      ),
    ).resolves.toBe(true);
  });

  it("does not treat non-callback URLs as redirect callbacks", async () => {
    const { driver } = createDriver();

    await expect(
      driver.isRedirectCallback("https://outposts.example/auth/callback?state=return-here"),
    ).resolves.toBe(false);
    await expect(
      driver.isRedirectCallback("https://outposts.example/elsewhere?code=auth-code"),
    ).resolves.toBe(false);
  });

  it("returns an access token for any resource string", async () => {
    const { driver, oidcSecurityService } = createDriver();

    // Without RFC 8707, a single token covers all resources in the scope
    await expect(driver.getAccessToken("https://other.example/api")).resolves.toBe("access-token");
    await expect(driver.getAccessToken("https://confluence.example/api")).resolves.toBe(
      "access-token",
    );

    expect(oidcSecurityService.checkAuth).toHaveBeenCalledTimes(1);
    expect(oidcSecurityService.getAccessToken).toHaveBeenCalledTimes(2);
  });

  it("returns access token claims for any resource string", async () => {
    const { driver, oidcSecurityService } = createDriver();

    await expect(driver.getAccessTokenClaims("https://other.example/api")).resolves.toEqual({
      scope: "confluence:read confluence:write",
    });
    await expect(driver.getAccessTokenClaims("https://confluence.example/api")).resolves.toEqual({
      scope: "confluence:read confluence:write",
    });

    expect(oidcSecurityService.checkAuth).toHaveBeenCalledTimes(1);
    expect(oidcSecurityService.getPayloadFromAccessToken).toHaveBeenCalledWith(false);
  });

  it("uses the existing redirect contract for sign-in and callback handling", async () => {
    const oidcSecurityService = createOidcSecurityServiceStub();
    oidcSecurityService.checkAuth.mockReturnValueOnce(
      of({
        isAuthenticated: true,
        errorMessage: "",
      }),
    );

    const { driver } = createDriver(oidcSecurityService);

    await driver.signInRedirect("https://outposts.example/workspace");
    await driver.handleRedirectCallback(
      "https://outposts.example/auth/callback?code=auth-code&state=return-here",
    );

    expect(oidcSecurityService.authorize).toHaveBeenCalledWith(undefined, {
      redirectUrl: "https://outposts.example/workspace",
    });
    expect(oidcSecurityService.checkAuth).toHaveBeenCalledWith(
      "https://outposts.example/auth/callback?code=auth-code&state=return-here",
    );
  });
});
