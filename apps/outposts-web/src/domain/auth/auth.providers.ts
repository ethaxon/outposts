import { APP_INITIALIZER, type Provider } from "@angular/core";
import { OidcSecurityService } from "angular-auth-oidc-client";
import { take } from "rxjs";
import { WINDOW } from "@/core/providers/window";
import { AUTH_RESOURCE_CONFIGS } from "./auth.defs";
import { AUTH_DRIVER } from "./auth.driver";
import { authInterceptor } from "./auth.interceptor";
import { createOidcAuthConfig } from "./oidc-auth.config";
import { createOidcAuthDriver } from "./oidc-auth.driver";
import { AuthService } from "./auth.service";

export const AUTH_PROVIDERS: Provider[] = [
  {
    provide: AUTH_DRIVER,
    useFactory: (oidcSecurityService: OidcSecurityService, window: Window) => {
      const oidcConfig = createOidcAuthConfig().config;
      const singleOidcConfig = Array.isArray(oidcConfig) ? undefined : oidcConfig;

      return createOidcAuthDriver(oidcSecurityService, {
        redirectUrl: singleOidcConfig?.redirectUrl || `${window.location.origin}/`,
        postLogoutRedirectUri:
          singleOidcConfig?.postLogoutRedirectUri || `${window.location.origin}/`,
        targetResource: AUTH_RESOURCE_CONFIGS[0]?.resource,
      });
    },
    deps: [OidcSecurityService, WINDOW],
  },
  authInterceptor,
  {
    provide: APP_INITIALIZER,
    multi: true,
    useFactory: (authService: AuthService) => {
      return () => authService.isAuthenticated$.pipe(take(1));
    },
    deps: [AuthService],
  },
];
