import { CommonModule } from "@angular/common";
import { inject, NgModule, provideAppInitializer } from "@angular/core";
import {
  AbstractSecurityStorage,
  AuthModule as OidcAuthModule,
  DefaultLocalStorageService,
  OidcSecurityService,
} from "angular-auth-oidc-client";
import { firstValueFrom } from "rxjs";
import { WINDOW } from "@/core/providers/window";
import { AUTH_DRIVER } from "./auth.driver";
import { authInterceptor } from "./auth.interceptor";
import { createOidcAuthConfig } from "./oidc-auth.config";
import { createOidcAuthDriver } from "./oidc-auth.driver";
import { AuthService } from "./auth.service";
import { AuthRoutingModule } from "./auth-routing.module";

@NgModule({
  declarations: [],
  imports: [CommonModule, OidcAuthModule.forRoot(createOidcAuthConfig()), AuthRoutingModule],
  providers: [
    { provide: AbstractSecurityStorage, useClass: DefaultLocalStorageService },
    {
      provide: AUTH_DRIVER,
      useFactory: (oidcSecurityService: OidcSecurityService, window: Window) => {
        const oidcConfigs = oidcSecurityService.getConfigurations();
        const singleOidcConfig = oidcConfigs.length === 1 ? oidcConfigs[0] : undefined;

        return createOidcAuthDriver(oidcSecurityService, {
          redirectUrl: singleOidcConfig?.redirectUrl || `${window.location.origin}/`,
          postLogoutRedirectUri:
            singleOidcConfig?.postLogoutRedirectUri || `${window.location.origin}/`,
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
