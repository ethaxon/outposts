import type { CancellationTokenTrait, FoundationEnvironment } from "@securitydept/client";
import {
  type FrontendOidcModeClientConfig,
  FrontendOidcModeConfigProjectionSourceKind,
  resolveFrontendOidcModeConfigProjection,
} from "@securitydept/token-set-context-client/frontend-oidc-mode";

export interface ResolveConfluenceOidcConfigProjectionOptions {
  /** Angular-adapted environment shared by the client registry. */
  environment: FoundationEnvironment;
  clientKey: string;
  /** Base URL of the Confluence API (e.g. `https://confluence.example.com/api`). */
  apiEndpoint: string;
  /** The redirect URI this browser client will use for the OIDC callback. */
  redirectUri: string;
  /** Default app-level URI after authentication. Defaults to `/`. */
  defaultPostAuthRedirectUri?: string;
  /** Persistent projection cache key. */
  storageKey?: string;
  cancellationToken?: CancellationTokenTrait;
}

export function createOidcConfigProjectionEndpoint(
  apiEndpoint: string,
  redirectUri: string,
): string {
  const url = new URL(`${apiEndpoint.replace(/\/+$/, "")}/auth/config`);
  url.searchParams.set("redirect_uri", redirectUri);
  return url.toString();
}

/** Resolve and validate the Confluence OIDC projection using the shared environment. */
export async function resolveConfluenceOidcConfigProjection(
  options: ResolveConfluenceOidcConfigProjectionOptions,
): Promise<FrontendOidcModeClientConfig> {
  const {
    environment,
    clientKey,
    apiEndpoint,
    redirectUri,
    defaultPostAuthRedirectUri = "/",
    storageKey,
    cancellationToken,
  } = options;
  const resolved = await resolveFrontendOidcModeConfigProjection({
    clientKey,
    environment,
    cancellationToken,
    sources: [
      {
        kind: FrontendOidcModeConfigProjectionSourceKind.Realm,
      },
      {
        kind: FrontendOidcModeConfigProjectionSourceKind.Persisted,
        storageKey,
      },
      {
        kind: FrontendOidcModeConfigProjectionSourceKind.Network,
        endpoint: createOidcConfigProjectionEndpoint(apiEndpoint, redirectUri),
      },
    ],
    overrides: { redirectUri, defaultPostAuthRedirectUri },
  });

  return resolved.config;
}
