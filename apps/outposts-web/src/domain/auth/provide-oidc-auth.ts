import { EnvironmentProviders, makeEnvironmentProviders } from "@angular/core";
import {
  AbstractSecurityStorage,
  _provideAuth,
  DefaultLocalStorageService,
  StsConfigLoader,
  StsConfigStaticLoader,
} from "angular-auth-oidc-client";
import { WINDOW } from "@/core/providers/window";
import { createOidcAuthConfig } from "./oidc-auth.config";

/**
 * OIDC registration using `WINDOW` from DI (`windowProvider` + `DOCUMENT`), no
 * `inject()` at provider-expand time (so TestBed and NgModule both work).
 */
export function provideOidcAuthFromInjectedWindow(): EnvironmentProviders {
  return makeEnvironmentProviders([
    ..._provideAuth({
      loader: {
        provide: StsConfigLoader,
        useFactory: (browserWindow: Window | null) => {
          const passed = createOidcAuthConfig(browserWindow);
          const cfg = passed.config;
          if (!cfg || Array.isArray(cfg)) {
            throw new Error("expected a single OIDC configuration");
          }
          return new StsConfigStaticLoader(cfg);
        },
        deps: [WINDOW],
      },
    }),
    // `_provideAuth` always adds `DefaultSessionStorageService` for this token; list
    // `DefaultLocalStorageService` after so it wins and tokens persist in localStorage.
    { provide: AbstractSecurityStorage, useClass: DefaultLocalStorageService },
  ]);
}
