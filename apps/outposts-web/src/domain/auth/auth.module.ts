import { CommonModule } from "@angular/common";
import { inject, NgModule, provideAppInitializer } from "@angular/core";
import { AuthModule as OidcAuthModule, OidcSecurityService } from "angular-auth-oidc-client";
import { firstValueFrom } from "rxjs";
import { WINDOW } from "@/core/providers/window";
import { AUTH_DRIVER } from "./auth.driver";
import { authInterceptor } from "./auth.interceptor";
import { createOidcAuthDriver } from "./oidc-auth.driver";
import { AuthService } from "./auth.service";
import { AuthRoutingModule } from "./auth-routing.module";
import { AUTH_CALLBACK_PATH } from "./auth.defs";

@NgModule({
  declarations: [],
  imports: [CommonModule, OidcAuthModule, AuthRoutingModule],
  providers: [
    {
      provide: AUTH_DRIVER,
      useFactory: (oidcSecurityService: OidcSecurityService, window: Window) => {
        return createOidcAuthDriver(oidcSecurityService, {
          // Must match OIDC `redirectUrl` (including path) so `isRedirectCallback` detects
          // `/auth/callback`; a bare `origin + '/'` breaks `shouldHandleCallback` and skips
          // `handleSignInCallback` (return-URL navigation never runs).
          redirectUrl: `${window.location.origin}${AUTH_CALLBACK_PATH}`,
          postLogoutRedirectUri: `${window.location.origin}/`,
        });
      },
      deps: [OidcSecurityService, WINDOW],
    },
    authInterceptor,
    provideAppInitializer(() => {
      const authService = inject(AuthService);
      return firstValueFrom(authService.isAuthenticated$);
    }),
  ],
})
export class AuthModule {}
