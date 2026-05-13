import {
  type EnvironmentProviders,
  inject,
  type Provider,
  provideEnvironmentInitializer,
} from "@angular/core";
import { provideAuthPlannerHost, providePageClientEnvironment } from "@securitydept/client-angular";
import {
  createLocalStorageStore,
  createSessionStorageStore,
} from "@securitydept/client/persistence/web";
import {
  ClientEnvironmentService,
  createBrowserPageClientEnvironment,
  deriveClientEnvironment,
} from "@securitydept/client/web";
import {
  createFrontendOidcModeClient,
  createFrontendOidcModeWebClientEnvironment,
  resolveConfigProjection,
} from "@securitydept/token-set-context-client/frontend-oidc-mode";
import {
  bootstrapScriptSource,
  networkConfigSource,
  persistConfigProjection,
  persistedConfigSource,
  scheduleIdleRevalidation,
} from "@securitydept/token-set-context-client/frontend-oidc-mode";
import {
  provideTokenSetAuth,
  provideTokenSetBearerInterceptor,
  TokenSetAuthRegistry,
} from "@securitydept/token-set-context-client-angular";
import { environment } from "@/environments/environment";
import { installOutpostsAuthEventDiagnostics } from "./auth.event-diagnostics";
import { AuthCallbackPath, AuthClientKey } from "./auth.defs";

/** Window global key used by the outposts server-side injection. */
const BOOTSTRAP_GLOBAL_KEY = "__OUTPOSTS_CONFIG__";

/** Storage key for caching the OIDC config projection in localStorage. */
const PROJECTION_CACHE_KEY = "config.projection";

/**
 * Create Angular providers for SDK-backed auth with backend-driven OIDC config.
 *
 * Source precedence (highest to lowest priority):
 *   1. bootstrap_script — server-injected via `window.__OUTPOSTS_CONFIG__`
 *   2. persisted — restored from localStorage (avoids cold-start network RTT)
 *   3. network — fetched from confluence `/api/auth/config` (canonical truth)
 *
 * After resolution:
 *   - Non-persisted sources are written back to localStorage for future boots
 *   - Non-network sources schedule idle revalidation when stale (freshness
 *     based on projection's authoritative `generatedAt`, NOT local time)
 */
export function provideAuth(browserWindow: Window): (Provider | EnvironmentProviders)[] {
  const apiEndpoint = environment.CONFLUENCE_API_ENDPOINT;
  const appOrigin = browserWindow?.location?.origin ?? `https://${environment.APP_HOST}`;
  const redirectUri = `${appOrigin}${AuthCallbackPath}`;
  const persistentStore = createLocalStorageStore("outposts.web.auth.");
  const sessionStore = createSessionStorageStore("outposts.web.auth.");
  const pageEnvironmentService = new ClientEnvironmentService({
    createClientEnvironment: () =>
      createFrontendOidcModeWebClientEnvironment({
        origin: appOrigin,
        fetch: resolveBrowserFetch(browserWindow),
        persistentStoragePrefix: "outposts.web.auth.",
        persistentStore,
        sessionStore,
      }),
    createPageEnvironment: async (webEnvironment) =>
      createBrowserPageClientEnvironment({
        ...deriveClientEnvironment(webEnvironment),
        pageCapability: requireBrowserPageCapability(browserWindow),
      }),
  });

  return [
    provideAuthPlannerHost(),
    providePageClientEnvironment({ environment: pageEnvironmentService }),
    ...provideTokenSetAuth({
      clients: [
        {
          key: AuthClientKey.Confluence,
          requirementKind: "frontend_oidc",
          providerFamily: "authentik",
          clientFactory: async () => {
            const netSource = networkConfigSource({
              apiEndpoint,
              redirectUri,
              defaultPostAuthRedirectUri: "/",
            });

            const resolved = await resolveConfigProjection([
              bootstrapScriptSource({
                globalKey: BOOTSTRAP_GLOBAL_KEY,
                projectionField: "confluence",
                redirectUri,
              }),
              persistedConfigSource({
                store: persistentStore,
                storageKey: PROJECTION_CACHE_KEY,
                redirectUri,
              }),
              netSource,
            ]);

            // Write back to persisted cache for future cold starts
            if (resolved.sourceKind !== "persisted") {
              void persistConfigProjection(persistentStore, PROJECTION_CACHE_KEY, resolved);
            }

            // Schedule idle revalidation when source is stale
            if (resolved.sourceKind !== "network") {
              scheduleIdleRevalidation({
                networkSource: netSource,
                store: persistentStore,
                storageKey: PROJECTION_CACHE_KEY,
                generatedAt: resolved.generatedAt,
              });
            }

            const frontendEnvironment = await pageEnvironmentService.resolveClientEnvironment();

            return createFrontendOidcModeClient(
              {
                ...resolved.config,
                persistentStateKey: "confluence",
              },
              deriveClientEnvironment(frontendEnvironment),
            );
          },
          urlPatterns: [apiEndpoint],
          callbackPath: AuthCallbackPath,
        },
      ],
    }),
    provideEnvironmentInitializer(() => {
      installOutpostsAuthEventDiagnostics(
        browserWindow,
        inject(TokenSetAuthRegistry),
        AuthClientKey.Confluence,
      );
    }),
    provideTokenSetBearerInterceptor({ strictUrlMatch: true }),
  ];
}

function resolveBrowserFetch(browserWindow: Window): typeof globalThis.fetch {
  if (typeof browserWindow?.fetch === "function") {
    return browserWindow.fetch.bind(browserWindow);
  }

  if (typeof globalThis.fetch === "function") {
    return globalThis.fetch.bind(globalThis);
  }

  throw new Error(
    "Outposts auth requires a fetch implementation to create the frontend OIDC web environment.",
  );
}

function requireBrowserPageCapability(browserWindow: Window): Pick<Window, "history" | "location"> {
  if (
    browserWindow?.location &&
    browserWindow?.history &&
    typeof browserWindow.history.replaceState === "function"
  ) {
    return {
      location: browserWindow.location,
      history: browserWindow.history,
    };
  }

  throw new Error(
    "Outposts auth redirect flows require a browser page environment with location and history.",
  );
}
