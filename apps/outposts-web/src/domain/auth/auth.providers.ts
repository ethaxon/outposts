import { type EnvironmentProviders, type Provider } from "@angular/core";
import { provideAuthPlannerHost } from "@securitydept/client-angular";
import { createWebRuntime } from "@securitydept/client/web";
import {
  createLocalStorageStore,
  createSessionStorageStore,
} from "@securitydept/client/persistence/web";
import {
  createFrontendOidcModeClient,
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
} from "@securitydept/token-set-context-client-angular";
import { environment } from "@/environments/environment";
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

  return [
    provideAuthPlannerHost(),
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

            return createFrontendOidcModeClient(
              {
                ...resolved.config,
                persistentStateKey: "outposts.web.auth.confluence",
              },
              createWebRuntime({
                persistentStore,
                sessionStore: createSessionStorageStore("outposts.web.auth."),
              }),
            );
          },
          urlPatterns: [apiEndpoint],
          callbackPath: AuthCallbackPath,
        },
      ],
    }),
    provideTokenSetBearerInterceptor({ strictUrlMatch: true }),
  ];
}
