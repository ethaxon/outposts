import {
  createEnvironmentInjector,
  type EnvironmentInjector,
  Injector,
  runInInjectionContext,
} from "@angular/core";
import { TranslocoService } from "@jsverse/transloco";
import { ClientError, ClientErrorKind, ErrorPresentationTone } from "@securitydept/client";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { AppOverlayService } from "../app-overlay.service";

const sdkSpies = vi.hoisted(() => ({
  readErrorPresentationDescriptor: vi.fn(),
}));
const toastSpies = vi.hoisted(() => ({
  error: vi.fn(),
  info: vi.fn(),
  warning: vi.fn(),
}));

vi.mock("@securitydept/client", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@securitydept/client")>()),
  readErrorPresentationDescriptor: sdkSpies.readErrorPresentationDescriptor,
}));

vi.mock("@spartan-ng/brain/sonner", () => ({
  toast: toastSpies,
}));

describe("AppOverlayService.showClientError", () => {
  const injectors: EnvironmentInjector[] = [];

  beforeEach(() => {
    vi.clearAllMocks();
  });

  afterEach(() => {
    for (const injector of injectors.splice(0)) {
      injector.destroy();
    }
  });

  function createService(): AppOverlayService {
    const injector = createEnvironmentInjector(
      [
        AppOverlayService,
        {
          provide: TranslocoService,
          useValue: { translate: vi.fn((key: string) => key) },
        },
      ],
      Injector.create({ providers: [] }) as EnvironmentInjector,
    );
    injectors.push(injector);
    return runInInjectionContext(injector, () => new AppOverlayService());
  }

  it.each([
    [ErrorPresentationTone.Neutral, "info"],
    [ErrorPresentationTone.Warning, "warning"],
    [ErrorPresentationTone.Danger, "error"],
  ] as const)("maps %s presentation to toast.%s", (tone, toastMethod) => {
    const error = new ClientError({
      kind: ClientErrorKind.Internal,
      message: "Runtime diagnostic",
    });
    sdkSpies.readErrorPresentationDescriptor.mockReturnValue({
      title: "Projected title",
      description: "Projected description",
      tone,
    });

    createService().showClientError(error);

    expect(sdkSpies.readErrorPresentationDescriptor).toHaveBeenCalledWith(error);
    expect(toastSpies[toastMethod]).toHaveBeenCalledWith("Projected title", {
      description: "Projected description",
      duration: 5000,
    });
  });
});
