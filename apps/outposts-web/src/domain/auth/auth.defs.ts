// Absolute URL path used for OIDC redirectUri and callbackPath configuration.
export const AuthCallbackPath = "/auth/callback";

// Angular Router route segment (no leading slash) for the callback route declaration.
// Must be kept in sync with the path portion of AuthCallbackPath.
export const AuthCallbackRouteSegment = "auth/callback";

export const AuthClientKey = {
  Confluence: "confluence",
} as const;

export type AuthClientKey = (typeof AuthClientKey)[keyof typeof AuthClientKey];
