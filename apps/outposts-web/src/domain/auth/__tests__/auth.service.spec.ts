import { createEnvironmentInjector, type EnvironmentInjector, Injector } from "@angular/core";
import { ClientError, ClientErrorKind } from "@securitydept/client";
import { createEnvironmentForTest } from "@securitydept/client/test";
import {
  TokenSetClientInitializationMode,
  TokenSetClientRegistry,
} from "@securitydept/token-set-context-client/registry";
import { TOKEN_SET_CLIENT_REGISTRY } from "@securitydept/token-set-context-client-angular";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { AppOverlayService } from "@/core/servces/app-overlay.service";
import { AuthService } from "../auth.service";

function createHarness() {
  const registry = TokenSetClientRegistry.fromEnvironmentConfig({
    environment: createEnvironmentForTest(),
  });
  const overlay = { showClientError: vi.fn() };
  const injector = createEnvironmentInjector(
    [
      AuthService,
      { provide: TOKEN_SET_CLIENT_REGISTRY, useValue: registry },
      { provide: AppOverlayService, useValue: overlay },
    ],
    Injector.create({ providers: [] }) as EnvironmentInjector,
  );

  return { injector, overlay, registry };
}

function createError(message: string): ClientError {
  return new ClientError({ kind: ClientErrorKind.Server, message });
}

async function emitRegistryError(
  registry: TokenSetClientRegistry,
  clientKey: string,
  error: ClientError,
): Promise<void> {
  registry.register({
    clientFactory: async () => {
      throw error;
    },
    meta: {
      clientKey,
      initialization: TokenSetClientInitializationMode.Lazy,
      urlPatterns: [],
    },
  });

  await expect(registry.clientRecordFor(clientKey, { initialize: true })).rejects.toBe(error);
}

describe("AuthService", () => {
  const injectors: EnvironmentInjector[] = [];
  const registries: TokenSetClientRegistry[] = [];

  beforeEach(() => vi.clearAllMocks());

  afterEach(() => {
    for (const injector of injectors.splice(0)) {
      injector.destroy();
    }
    for (const registry of registries.splice(0)) {
      registry.dispose();
    }
  });

  it("does not install orchestration before start", async () => {
    const harness = createHarness();
    injectors.push(harness.injector);
    registries.push(harness.registry);
    harness.injector.get(AuthService);

    await emitRegistryError(harness.registry, "before-start", createError("Failure before start"));
    await Promise.resolve();

    expect(harness.overlay.showClientError).not.toHaveBeenCalled();
  });

  it("starts orchestration exactly once", async () => {
    const harness = createHarness();
    injectors.push(harness.injector);
    registries.push(harness.registry);
    const service = harness.injector.get(AuthService);

    service.start();
    service.start();
    const error = createError("Single observer failure");
    await emitRegistryError(harness.registry, "single-observer", error);

    await vi.waitFor(() => {
      expect(harness.overlay.showClientError).toHaveBeenCalledOnce();
    });
    expect(harness.overlay.showClientError).toHaveBeenCalledWith(error);
  });

  it("forwards every registry client error", async () => {
    const harness = createHarness();
    injectors.push(harness.injector);
    registries.push(harness.registry);
    harness.injector.get(AuthService).start();
    const firstError = createError("First client failure");
    const secondError = createError("Second client failure");

    await emitRegistryError(harness.registry, "first-error", firstError);
    await emitRegistryError(harness.registry, "second-error", secondError);

    await vi.waitFor(() => {
      expect(harness.overlay.showClientError).toHaveBeenCalledTimes(2);
    });
    expect(harness.overlay.showClientError).toHaveBeenCalledWith(firstError);
    expect(harness.overlay.showClientError).toHaveBeenCalledWith(secondError);
  });

  it("stops observing after the Angular root injector is destroyed", async () => {
    const harness = createHarness();
    registries.push(harness.registry);
    harness.injector.get(AuthService).start();
    harness.injector.destroy();

    await emitRegistryError(
      harness.registry,
      "after-destroy",
      createError("Failure after destroy"),
    );
    await Promise.resolve();

    expect(harness.overlay.showClientError).not.toHaveBeenCalled();
  });
});
