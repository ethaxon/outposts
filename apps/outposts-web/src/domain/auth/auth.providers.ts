import { type EnvironmentProviders, type Provider } from "@angular/core";
import { provideEnvironment } from "@securitydept/client-angular";
import { createEnvironmentForNativeWeb } from "@securitydept/client/web";
import { createFrontendOidcModeClientFactory } from "@securitydept/token-set-context-client/frontend-oidc-mode";
import {
  TokenSetClientInitializationMode,
  TokenSetRequirementKind,
} from "@securitydept/token-set-context-client/registry";
import {
  provideTokenSetClientRegistry,
  provideTokenSetClientRegistryAuthorizationInterceptor,
} from "@securitydept/token-set-context-client-angular";
import { environment } from "@/environments/environment";
import { resolveConfluenceOidcConfigProjection } from "./auth-config-projection";
import { AuthCallbackPath, AuthClientKey } from "./auth.defs";

/** Storage key for caching the OIDC config projection in localStorage. */
const PROJECTION_CACHE_KEY = "config.projection";

const STORAGE_PREFIX = "outposts.web.auth.";

/** No-op auth providers for local DEV mode (backend accepts unauthenticated requests). */
export function provideDevAuth(): (Provider | EnvironmentProviders)[] {
  return [];
}

/**
 * Create Angular providers for SDK-backed auth with backend-driven OIDC config.
 *
 * Config source precedence is the server-injected realm projection, the
 * persisted projection cache, then the canonical Confluence endpoint.
 */
export function provideAuth(browserWindow: Window): (Provider | EnvironmentProviders)[] {
  const apiEndpoint = environment.CONFLUENCE_API_ENDPOINT;
  const appOrigin = browserWindow.location.origin;
  const redirectUri = `${appOrigin}${AuthCallbackPath}`;

  return [
    ...provideEnvironment({
      createBaseEnvironment: createEnvironmentForNativeWeb,
      routerForAngularCreateOptions: {
        location: browserWindow.location,
        history: browserWindow.history,
        navigation: browserWindow.navigation,
        window: browserWindow,
      },
      pageLifecycleForNativeWebCreateOptions: {
        document: browserWindow.document,
        window: browserWindow,
      },
      popupForNativeWebCreateOptions: { window: browserWindow },
      persistentStorageForNativeWebCreateOptions: {
        prefix: STORAGE_PREFIX,
      },
      sessionStorageForNativeWebCreateOptions: {
        prefix: STORAGE_PREFIX,
      },
    }),
    ...provideTokenSetClientRegistry({
      clients: [
        {
          clientFactory: createFrontendOidcModeClientFactory({
            config: async ({ cancellationToken, environment: clientEnvironment }) => {
              const config = await resolveConfluenceOidcConfigProjection({
                clientKey: AuthClientKey.Confluence,
                environment: clientEnvironment,
                cancellationToken,
                apiEndpoint,
                redirectUri,
                defaultPostAuthRedirectUri: "/",
                storageKey: PROJECTION_CACHE_KEY,
              });

              return {
                ...config,
                persistence: { key: AuthClientKey.Confluence },
              };
            },
          }),
          meta: {
            clientKey: AuthClientKey.Confluence,
            requirementKind: TokenSetRequirementKind.FrontendOidc,
            providerFamily: "authentik",
            initialization: TokenSetClientInitializationMode.Immediate,
            // Config acquisition uses the same HttpClient-backed environment.
            // Excluding that public endpoint avoids recursively initializing
            // this client from its own authorization interceptor.
            urlPatterns: [
              (requestUrl) => matchesConfluenceAuthorizedApiUrl(apiEndpoint, requestUrl),
            ],
            callbackUrl: redirectUri,
          },
        },
      ],
    }),
    ...provideTokenSetClientRegistryAuthorizationInterceptor(),
  ];
}

export function matchesConfluenceAuthorizedApiUrl(
  apiEndpoint: string,
  requestUrl: string,
): boolean {
  try {
    const apiUrl = new URL(apiEndpoint);
    const candidate = new URL(requestUrl, apiUrl);
    const apiPath = apiUrl.pathname.replace(/\/+$/, "");
    const configPath = `${apiPath}/auth/config`;

    return (
      candidate.origin === apiUrl.origin &&
      (candidate.pathname === apiPath || candidate.pathname.startsWith(`${apiPath}/`)) &&
      candidate.pathname !== configPath
    );
  } catch {
    return false;
  }
}
