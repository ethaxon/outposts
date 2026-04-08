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

function resolveAppOrigin(): string {
  if (typeof window !== "undefined" && window.location?.origin) {
    return window.location.origin;
  }

  return `https://${environment.APP_HOST}`;
}

function resolveScope(): string {
  return AUTH_RESOURCE_CONFIGS.flatMap((resourceConfig) => resourceConfig.scopes)
    .filter((scope, index, allScopes) => allScopes.indexOf(scope) === index)
    .join(" ");
}

export function createOidcAuthConfig(): PassedInitialConfig {
  const appOrigin = resolveAppOrigin();

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
      logLevel: environment.production ? LogLevel.Warn : LogLevel.Debug,
    },
  };
}
