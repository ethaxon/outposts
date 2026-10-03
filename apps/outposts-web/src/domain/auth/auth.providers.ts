import {
  type EnvironmentProviders,
  inject,
  type Provider,
  provideAppInitializer,
} from "@angular/core";
import type { IdleCallbackTrait } from "@securitydept/client";
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
import { AuthService } from "./auth.service";

/** Storage key for caching the OIDC config projection in localStorage. */
const PROJECTION_CACHE_KEY = "config.projection";

const STORAGE_PREFIX = "outposts.web.auth.";

/**
 * Adapts the browser idle scheduler for the SDK's `Idle` client initialization.
 *
 * Without this trait the SDK never fires idle initialization. Safari lacks
 * `requestIdleCallback`, so fall back to a macrotask after the current work.
 */
export function createIdleCallbackForWindow(browserWindow: Window): IdleCallbackTrait {
  if (typeof browserWindow.requestIdleCallback === "function") {
    return {
      requestIdleCallback: (callback) => browserWindow.requestIdleCallback(() => callback()),
      cancelIdleCallback: (handle) => browserWindow.cancelIdleCallback(handle as number),
    };
  }
  return {
    requestIdleCallback: (callback) => browserWindow.setTimeout(callback, 1),
    cancelIdleCallback: (handle) => browserWindow.clearTimeout(handle as number),
  };
}

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
      idleCallback: createIdleCallbackForWindow(browserWindow),
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
                refreshErrorPolicy: "revokeAsUnauthenticated",
                persistence: { key: AuthClientKey.Confluence },
              };
            },
          }),
          meta: {
            clientKey: AuthClientKey.Confluence,
            requirementKind: TokenSetRequirementKind.FrontendOidc,
            providerFamily: "authentik",
            initialization: TokenSetClientInitializationMode.Idle,
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
    AuthService,
    provideAppInitializer(() => {
      inject(AuthService).start();
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
