/**
 * Backend-driven OIDC config projection loader.
 *
 * This module is now a thin convenience wrapper around the SDK's canonical
 * `resolveConfigProjection` + `networkConfigSource` from
 * `@securitydept/token-set-context-client/frontend-oidc-mode`.
 *
 * For new code, prefer importing from the SDK directly:
 *
 * ```ts
 * import { resolveConfigProjection, networkConfigSource }
 *   from "@securitydept/token-set-context-client/frontend-oidc-mode";
 * ```
 *
 * This file is retained for the application-level test suite which validates
 * the network fetch path end-to-end with mocked fetch.
 */

import {
  resolveConfigProjection,
  networkConfigSource,
  type FrontendOidcModeClientConfig,
} from "@securitydept/token-set-context-client/frontend-oidc-mode";

export interface FetchOidcConfigOptions {
  /** Base URL of the Confluence API (e.g. `https://confluence.example.com/api`). */
  apiEndpoint: string;
  /**
   * The redirect URI this browser client will use for the OIDC callback.
   */
  redirectUri: string;
  /**
   * Default app-level URI to redirect the user to after authentication.
   * Defaults to `"/"`.
   */
  defaultPostAuthRedirectUri?: string;
}

/**
 * Fetch and validate the OIDC client config projection from the backend.
 *
 * Delegates entirely to the SDK's `resolveConfigProjection([networkConfigSource(...)])`.
 *
 * @throws when the HTTP request fails, or when the projection body is
 * structurally invalid (missing required fields or wrong types).
 */
export async function fetchOidcConfigProjection(
  options: FetchOidcConfigOptions,
): Promise<FrontendOidcModeClientConfig> {
  const { apiEndpoint, redirectUri, defaultPostAuthRedirectUri = "/" } = options;

  const resolved = await resolveConfigProjection([
    networkConfigSource({
      apiEndpoint,
      redirectUri,
      defaultPostAuthRedirectUri,
    }),
  ]);

  return resolved.config;
}
