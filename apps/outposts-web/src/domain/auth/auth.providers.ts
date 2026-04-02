import { APP_INITIALIZER, type Provider } from "@angular/core";
import { OidcSecurityService, PublicEventsService } from "angular-auth-oidc-client";
import { take } from "rxjs";
import { WINDOW } from "@/core/providers/window";
import { AUTH_DRIVER } from "./auth.driver";
import { authInterceptor } from "./auth.interceptor";
import { createOidcAuthConfig } from "./oidc-auth.config";
import { createOidcAuthDriver } from "./oidc-auth.driver";
import { AuthService } from "./auth.service";

export const AUTH_PROVIDERS: Provider[] = [
  {
    provide: AUTH_DRIVER,
    useFactory: (
      oidcSecurityService: OidcSecurityService,
      publicEventsService: PublicEventsService,
      window: Window,
    ) => {
      const oidcConfig = createOidcAuthConfig().config;
      const singleOidcConfig = Array.isArray(oidcConfig) ? undefined : oidcConfig;

      return createOidcAuthDriver(oidcSecurityService, {
        redirectUrl: singleOidcConfig?.redirectUrl || `${window.location.origin}/`,
        postLogoutRedirectUri:
          singleOidcConfig?.postLogoutRedirectUri || `${window.location.origin}/`,
        publicEventsService,
      });
    },
    deps: [OidcSecurityService, PublicEventsService, WINDOW],
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
