import type { PassedInitialConfig } from "angular-auth-oidc-client";
import { environment } from "@/environments/environment";
import { AUTH_CALLBACK_PATH, AUTH_RESOURCE_CONFIGS } from "./auth.defs";

// Mirror of angular-auth-oidc-client's LogLevel enum as a plain const to avoid
// runtime imports that trigger Angular JIT compilation in vitest.
// See auth-oidc-events.ts for the same pattern used with EventTypes.
const LogLevel = {
  None: 0,
  Debug: 1,
  Warn: 2,
  Error: 3,
} satisfies typeof import("angular-auth-oidc-client").LogLevel;

/**
 * Resolves the app origin for redirect URIs from an explicit browser `Window`
 * (e.g. `inject(WINDOW)`), never
 * from the global `window` object.
 */
export function resolveAppOriginFromWindow(browserWindow: Window | null | undefined): string {
  const origin = browserWindow?.location?.origin;
  if (typeof origin === "string" && origin.length > 0) {
    return origin;
  }

  return `https://${environment.APP_HOST}`;
}

function resolveScope(): string {
  return AUTH_RESOURCE_CONFIGS.flatMap((resourceConfig) => resourceConfig.scopes)
    .filter((scope, index, allScopes) => allScopes.indexOf(scope) === index)
    .join(" ");
}

export function createOidcAuthConfig(
  browserWindow: Window | null | undefined,
): PassedInitialConfig {
  const appOrigin = resolveAppOriginFromWindow(browserWindow);

  return {
    config: {
      authority: environment.OIDC_ISSUER,
      clientId: environment.OIDC_CLIENT_ID,
      redirectUrl: `${appOrigin}${AUTH_CALLBACK_PATH}`,
      postLogoutRedirectUri: `${appOrigin}/`,
      scope: resolveScope(),
      responseType: "code",
      silentRenew: true,
      useRefreshToken: true,
      autoUserInfo: true,
      renewUserInfoAfterTokenRenew: true,
      // Trigger renewal 75 seconds before the access token expires so the
      // refresh has enough headroom to complete even on slow connections.
      renewTimeBeforeTokenExpiresInSeconds: 75,
      // Some OIDC providers (e.g. Authentik) do not return an id_token on
      // refresh-token grants. Without this flag the library treats the
      // missing id_token as an error and aborts the silent renew cycle.
      triggerRefreshWhenIdTokenExpired: false,
      /**
       * When false (library default), `CodeFlowCallbackService` calls
       * `router.navigateByUrl(postLoginRoute || '/')` after a successful code
       * callback — that overrides any app-controlled return URL. Setting this
       * to true skips that navigation so AuthService can send the user to the
       * stored path (e.g. `AUTH_CALLBACK_ORIGIN_URI_KEY`) after login.
       */
      triggerAuthorizationResultEvent: true,
      logLevel: environment.production ? LogLevel.Warn : LogLevel.Debug,
    },
  };
}
