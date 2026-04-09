import { DOCUMENT } from "@angular/common";
import { provideHttpClient } from "@angular/common/http";
import { TestBed } from "@angular/core/testing";
import { describe, expect, it, vi } from "vitest";
import { ConfigurationService } from "angular-auth-oidc-client";
import { firstValueFrom } from "rxjs";
import { WINDOW, windowProvider } from "@/core/providers/window";
import {
  createMockBrowserWindow,
  createMockDocumentWithDefaultView,
} from "@/core/providers/window.testing";
import { provideOidcAuthFromInjectedWindow } from "./provide-oidc-auth";

vi.mock("@/environments/environment", () => ({
  environment: {
    APP_HOST: "host.outposts.example",
    OIDC_ISSUER: "https://issuer.example/oidc/",
    OIDC_CLIENT_ID: "test-client",
    APP_VERSION: "0.0.0-test",
    CONFLUENCE_API_ENDPOINT: "https://confluence.example/api",
    CONFLUENCE_OIDC_SCOPES: "openid profile email",
    production: true,
    ssr: false,
  },
}));

describe("provideOidcAuthFromInjectedWindow", () => {
  it("builds OIDC redirectUrl from DI WINDOW (mock DOCUMENT.defaultView), not global document/window", async () => {
    const mockWin = createMockBrowserWindow("http://127.0.0.1:4200");
    const mockDoc = createMockDocumentWithDefaultView(mockWin);

    TestBed.configureTestingModule({
      providers: [
        provideHttpClient(),
        { provide: DOCUMENT, useValue: mockDoc },
        { provide: WINDOW, useFactory: windowProvider, deps: [DOCUMENT] },
        provideOidcAuthFromInjectedWindow(),
      ],
    });

    expect(TestBed.inject(WINDOW)).toBe(mockWin);

    const configurationService = TestBed.inject(ConfigurationService);
    const cfg = await firstValueFrom(configurationService.getOpenIDConfiguration());
    expect(cfg?.redirectUrl).toBe("http://127.0.0.1:4200/auth/callback");
  });
});
