export const AuthCallbackRouteSegment = "auth/callback";

// Absolute URL path used for OIDC redirectUri and callbackPath configuration.
export const AuthCallbackPath = `/${AuthCallbackRouteSegment}` as const;

export const AuthClientKey = {
  Confluence: "confluence",
} as const;

export type AuthClientKey = (typeof AuthClientKey)[keyof typeof AuthClientKey];
