import "@angular/compiler";
import { Injector, runInInjectionContext } from "@angular/core";
import { Router } from "@angular/router";
import { TOKEN_SET_CLIENT_REGISTRY } from "@securitydept/token-set-context-client-angular";
import { describe, expect, it, vi } from "vitest";
import { AuthClientKey } from "../auth.defs";
import { AuthService } from "../auth.service";

function makeAuthService(
  providers: Parameters<typeof Injector.create>[0]["providers"],
): AuthService {
  const injector = Injector.create({ providers });
  return runInInjectionContext(injector, () => new AuthService());
}

function createRegistryStub(client: { loginWithRedirect: (options: unknown) => Promise<void> }) {
  return {
    clientResourceFor: vi.fn(() => ({
      whenValue: vi.fn().mockResolvedValue(client),
    })),
  };
}

function waitForCompletion(service: AuthService, attemptedUrl?: string): Promise<void> {
  return new Promise<void>((resolve, reject) => {
    service.redirectToLogin(AuthClientKey.Confluence, attemptedUrl).subscribe({
      complete: resolve,
      error: reject,
    });
  });
}

describe("AuthService.redirectToLogin", () => {
  it("passes the explicit attempted URL as postAuthRedirectUri", async () => {
    const loginWithRedirect = vi.fn().mockResolvedValue(undefined);
    const registry = createRegistryStub({ loginWithRedirect });
    const service = makeAuthService([
      { provide: TOKEN_SET_CLIENT_REGISTRY, useValue: registry },
      { provide: Router, useValue: { url: "/previous" } },
    ]);

    await waitForCompletion(service, "/spaces/abc?tab=pages");

    expect(registry.clientResourceFor).toHaveBeenCalledWith(AuthClientKey.Confluence);
    expect(loginWithRedirect).toHaveBeenCalledWith({
      postAuthRedirectUri: "/spaces/abc?tab=pages",
    });
  });

  it("uses the current Angular route when no attempted URL is supplied", async () => {
    const loginWithRedirect = vi.fn().mockResolvedValue(undefined);
    const service = makeAuthService([
      {
        provide: TOKEN_SET_CLIENT_REGISTRY,
        useValue: createRegistryStub({ loginWithRedirect }),
      },
      { provide: Router, useValue: { url: "/current" } },
    ]);

    await waitForCompletion(service);

    expect(loginWithRedirect).toHaveBeenCalledWith({ postAuthRedirectUri: "/current" });
  });

  it("propagates client materialization failures", async () => {
    const service = makeAuthService([
      {
        provide: TOKEN_SET_CLIENT_REGISTRY,
        useValue: {
          clientResourceFor: () => ({
            whenValue: () => Promise.reject(new Error("client initialization failed")),
          }),
        },
      },
      { provide: Router, useValue: { url: "/current" } },
    ]);

    await expect(waitForCompletion(service)).rejects.toThrow("client initialization failed");
  });
});
