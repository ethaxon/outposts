import type { OidcSecurityService, PublicEventsService } from "angular-auth-oidc-client";
import { filter, firstValueFrom } from "rxjs";
import type { AuthAccessTokenClaims, AuthDriver } from "./auth.driver";
import type { AuthUserState } from "./auth.defs";

// EventTypes.NewAuthenticationResult = 9. Using the raw number avoids a runtime
// import of angular-auth-oidc-client which has side-effects that require the
// Angular JIT compiler (breaks vitest in node mode).
const EVENT_NEW_AUTH_RESULT = 9;

export interface OidcAuthDriverConfig {
  redirectUrl: string;
  postLogoutRedirectUri: string;
  /** Inject PublicEventsService to enable automatic token-refresh cache invalidation. */
  publicEventsService?: PublicEventsService;
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
  // Cached promise for the initial checkAuth call. Reset on sign-in, sign-out,
  // and — critically — whenever the library completes a silent token renewal so
  // that getAccessToken always returns the current, non-expired token.
  let authCheck: Promise<boolean> | null = null;

  const ensureChecked = async (): Promise<boolean> => {
    if (!authCheck) {
      authCheck = firstValueFrom(oidcSecurityService.checkAuth()).then(
        (loginResponse) => loginResponse.isAuthenticated,
      );
    }

    return authCheck;
  };

  // Invalidate the cached auth check whenever the OIDC library publishes a new
  // authentication result (covers both the initial code exchange and every
  // subsequent silent renew / refresh-token grant).
  if (config.publicEventsService) {
    config.publicEventsService
      .registerForEvents()
      .pipe(filter((e) => e.type === EVENT_NEW_AUTH_RESULT))
      .subscribe(() => {
        authCheck = null;
      });
  }

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
      await ensureChecked();
      return (await firstValueFrom(oidcSecurityService.getAccessToken())) || null;
    },
    async getAccessTokenClaims(_resource: string): Promise<AuthAccessTokenClaims | null> {
      await ensureChecked();
      return (await firstValueFrom(
        oidcSecurityService.getPayloadFromAccessToken(false),
      )) as AuthAccessTokenClaims | null;
    },
  };
}
