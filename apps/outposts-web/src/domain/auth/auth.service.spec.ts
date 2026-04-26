import { Injector, runInInjectionContext } from "@angular/core";
import { Router } from "@angular/router";
import { TokenSetAuthRegistry } from "@securitydept/token-set-context-client-angular";
import { FrontendOidcModeClient } from "@securitydept/token-set-context-client/frontend-oidc-mode";
import { describe, expect, it, vi } from "vitest";
import { AuthClientKey } from "./auth.defs";
import { AuthService } from "./auth.service";

// Iteration 150 review-1 fix (Finding 2):
//
// Locks down the contract that AuthService.redirectToLogin() can forward an
// explicit attempted URL as `postAuthRedirectUri`. Guard-triggered redirects
// must use Angular RouterStateSnapshot.url, not Router.url, because Router.url
// still points at the previously committed route while a guard is running.
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
  it("passes the explicit attempted URL as postAuthRedirectUri", async () => {
    const currentUrl = "/previous";
    const attemptedUrl = "/spaces/abc?tab=pages";

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
      service.redirectToLogin(AuthClientKey.Confluence, attemptedUrl).subscribe({
        complete: () => resolve(),
        error: (err) => reject(err),
      });
    });

    expect(loginWithRedirect).toHaveBeenCalledTimes(1);
    expect(loginWithRedirect).toHaveBeenCalledWith({
      postAuthRedirectUri: attemptedUrl,
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
