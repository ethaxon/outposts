import type { PassedInitialConfig } from "angular-auth-oidc-client";
import { environment } from "@/environments/environment";
import { AUTH_CALLBACK_PATH, AUTH_RESOURCE_CONFIGS } from "./auth.defs";

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
    },
  };
}
