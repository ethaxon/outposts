import { Injector, runInInjectionContext } from "@angular/core";
import { Router } from "@angular/router";
import { TokenSetAuthRegistry } from "@securitydept/token-set-context-client-angular";
import { FrontendOidcModeClient } from "@securitydept/token-set-context-client/frontend-oidc-mode";
import { describe, expect, it, vi } from "vitest";
import { AuthClientKey } from "./auth.defs";
import { AuthService } from "./auth.service";

// Iteration 150 review-1 fix (Finding 2):
//
// Locks down the contract that AuthService.redirectToLogin() forwards the
// CURRENT router URL as `postAuthRedirectUri` so the IdP round-trip resumes
// users on the route that triggered the auth challenge — instead of always
// dropping them on the app root. Source-reading is not enough; this test
// exercises the actual call path with a stub Router and a stub client.
//
// Vitest runs in `node` environment (no DOM) so we deliberately avoid
// `TestBed` (which pulls in the platform-browser DocumentToken) and instead
// instantiate AuthService inside an isolated `Injector.create()` injection
// context — the same primitive standalone Angular relies on internally.

function makeAuthService(providers: { provide: unknown; useValue: unknown }[]): AuthService {
  const injector = Injector.create({
    providers: providers as Parameters<typeof Injector.create>[0]["providers"],
  });
  return runInInjectionContext(injector, () => new AuthService());
}

describe("AuthService.redirectToLogin", () => {
  it("passes the current router URL as postAuthRedirectUri", async () => {
    const currentUrl = "/spaces/abc?tab=pages";

    const loginWithRedirect = vi.fn().mockResolvedValue(undefined);

    // Minimal FrontendOidcModeClient stub: only the surface AuthService
    // touches inside redirectToLogin. We use Object.create() so the stub
    // satisfies `instanceof FrontendOidcModeClient` without instantiating
    // the real (network-touching) client.
    const stubClient = Object.create(FrontendOidcModeClient.prototype) as {
      loginWithRedirect: typeof loginWithRedirect;
    };
    stubClient.loginWithRedirect = loginWithRedirect;

    const registryStub = {
      whenReady: vi.fn().mockResolvedValue({ client: stubClient }),
    } as unknown as TokenSetAuthRegistry;

    const service = makeAuthService([
      { provide: TokenSetAuthRegistry, useValue: registryStub },
      { provide: Router, useValue: { url: currentUrl } },
    ]);

    await new Promise<void>((resolve, reject) => {
      service.redirectToLogin(AuthClientKey.Confluence).subscribe({
        complete: () => resolve(),
        error: (err) => reject(err),
      });
    });

    expect(loginWithRedirect).toHaveBeenCalledTimes(1);
    expect(loginWithRedirect).toHaveBeenCalledWith({
      postAuthRedirectUri: currentUrl,
    });
  });

  it("completes without invoking IdP when the registered client is not OIDC", async () => {
    const nonOidcClient = { foo: "bar" } as unknown as object;
    const registryStub = {
      whenReady: vi.fn().mockResolvedValue({ client: nonOidcClient }),
    } as unknown as TokenSetAuthRegistry;

    const service = makeAuthService([
      { provide: TokenSetAuthRegistry, useValue: registryStub },
      { provide: Router, useValue: { url: "/should-not-matter" } },
    ]);

    let completed = false;
    await new Promise<void>((resolve) => {
      service.redirectToLogin(AuthClientKey.Confluence).subscribe({
        complete: () => {
          completed = true;
          resolve();
        },
      });
    });
    expect(completed).toBe(true);
  });
});
