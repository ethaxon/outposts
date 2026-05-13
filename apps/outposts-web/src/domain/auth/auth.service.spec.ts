import "@angular/compiler";
import { Injector, runInInjectionContext } from "@angular/core";
import { Router } from "@angular/router";
import { providePageClientEnvironment } from "@securitydept/client-angular";
import {
  createBrowserPageClientEnvironment,
  createWebClientEnvironment,
  deriveClientEnvironment,
} from "@securitydept/client/web";
import { TokenSetAuthRegistry } from "@securitydept/token-set-context-client-angular";
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

function makeAuthService(
  providers: Parameters<typeof Injector.create>[0]["providers"],
): AuthService {
  const injector = Injector.create({
    providers,
  });
  return runInInjectionContext(injector, () => new AuthService());
}

function createTestPageEnvironment() {
  const webEnvironment = createWebClientEnvironment({
    transport: {
      execute: vi.fn(async () => ({
        status: 200,
        headers: {},
        body: null,
      })),
    },
    scheduler: {
      setTimeout() {
        return { cancel() {} };
      },
    },
    clock: { now: () => Date.now() },
  });

  return createBrowserPageClientEnvironment({
    ...deriveClientEnvironment(webEnvironment),
    pageCapability: {
      location: {
        href: "https://outposts.example.test/current",
        hash: "",
        pathname: "/current",
        search: "",
      },
      history: {
        replaceState() {},
      },
    },
  });
}

describe("AuthService.redirectToLogin", () => {
  it("passes the explicit attempted URL as postAuthRedirectUri", async () => {
    const currentUrl = "/previous";
    const attemptedUrl = "/spaces/abc?tab=pages";
    const pageEnvironment = createTestPageEnvironment();

    const loginWithRedirect = vi.fn().mockResolvedValue(undefined);
    const stubClient = {
      loginWithRedirect,
    };

    const registryStub = {
      whenReady: vi.fn().mockResolvedValue({ client: stubClient }),
    } as unknown as TokenSetAuthRegistry;

    const service = makeAuthService([
      { provide: TokenSetAuthRegistry, useValue: registryStub },
      { provide: Router, useValue: { url: currentUrl } },
      providePageClientEnvironment({ environment: pageEnvironment }),
    ]);

    await new Promise<void>((resolve, reject) => {
      service.redirectToLogin(AuthClientKey.Confluence, attemptedUrl).subscribe({
        complete: () => resolve(),
        error: (err) => reject(err),
      });
    });

    expect(loginWithRedirect).toHaveBeenCalledTimes(1);
    expect(loginWithRedirect).toHaveBeenCalledWith({
      environment: pageEnvironment,
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

  it("fails fast when redirectToLogin is used without a registered page environment", async () => {
    const registryStub = {
      whenReady: vi.fn().mockResolvedValue({
        client: { loginWithRedirect: vi.fn().mockResolvedValue(undefined) },
      }),
    } as unknown as TokenSetAuthRegistry;

    const service = makeAuthService([
      { provide: TokenSetAuthRegistry, useValue: registryStub },
      { provide: Router, useValue: { url: "/spaces" } },
    ]);

    await expect(
      new Promise<void>((resolve, reject) => {
        service.redirectToLogin(AuthClientKey.Confluence).subscribe({
          complete: () => resolve(),
          error: (err) => reject(err),
        });
      }),
    ).rejects.toThrow(/providePageClientEnvironment/);
  });
});
