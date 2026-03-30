import type { OidcSecurityService } from "angular-auth-oidc-client";
import { firstValueFrom } from "rxjs";
import type { AuthAccessTokenClaims, AuthDriver } from "./auth.driver";
import type { AuthUserState } from "./auth.defs";

export interface OidcAuthDriverConfig {
  redirectUrl: string;
  postLogoutRedirectUri: string;
  targetResource?: string;
}

function isOidcCallbackUrl(currentUrl: string, redirectUrl: string): boolean {
  const url = new URL(currentUrl);
  const callbackUrl = new URL(redirectUrl);

  return (
    url.origin === callbackUrl.origin &&
    url.pathname === callbackUrl.pathname &&
    (url.searchParams.has("code") || url.searchParams.has("error"))
  );
}

export function createOidcAuthDriver(
  oidcSecurityService: OidcSecurityService,
  config: OidcAuthDriverConfig,
): AuthDriver {
  let authCheck: Promise<boolean> | null = null;

  const ensureChecked = async (): Promise<boolean> => {
    if (!authCheck) {
      authCheck = firstValueFrom(oidcSecurityService.checkAuth()).then(
        (loginResponse) => loginResponse.isAuthenticated,
      );
    }

    return authCheck;
  };

  const matchesTargetResource = (resource: string): boolean =>
    !config.targetResource || resource === config.targetResource;

  return {
    signInRedirect(redirectUrl: string): Promise<void> {
      authCheck = null;
      oidcSecurityService.authorize(undefined, { redirectUrl });
      return Promise.resolve();
    },
    async signOutRedirect(redirectUrl: string): Promise<void> {
      authCheck = null;
      await firstValueFrom(
        oidcSecurityService.logoff(undefined, {
          customParams: {
            post_logout_redirect_uri: redirectUrl || config.postLogoutRedirectUri,
          },
        }),
      );
    },
    async handleRedirectCallback(callbackUrl: string): Promise<void> {
      authCheck = firstValueFrom(oidcSecurityService.checkAuth(callbackUrl)).then(
        (loginResponse) => {
          if (loginResponse.errorMessage) {
            throw new Error(loginResponse.errorMessage);
          }

          return loginResponse.isAuthenticated;
        },
      );

      await authCheck;
    },
    isRedirectCallback(callbackUrl: string): Promise<boolean> {
      return Promise.resolve(isOidcCallbackUrl(callbackUrl, config.redirectUrl));
    },
    async isAuthenticated(): Promise<boolean> {
      return ensureChecked();
    },
    async getUserInfo(): Promise<AuthUserState | null> {
      await ensureChecked();
      return (await firstValueFrom(oidcSecurityService.getUserData())) as AuthUserState | null;
    },
    async getAccessToken(_resource: string): Promise<string | null> {
      if (!matchesTargetResource(_resource)) {
        return null;
      }
      await ensureChecked();
      return (await firstValueFrom(oidcSecurityService.getAccessToken())) || null;
    },
    async getAccessTokenClaims(_resource: string): Promise<AuthAccessTokenClaims | null> {
      if (!matchesTargetResource(_resource)) {
        return null;
      }
      await ensureChecked();
      return (await firstValueFrom(
        oidcSecurityService.getPayloadFromAccessToken(false),
      )) as AuthAccessTokenClaims | null;
    },
  };
}
