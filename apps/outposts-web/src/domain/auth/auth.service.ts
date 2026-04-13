import { Injectable, inject } from "@angular/core";
import { Router } from "@angular/router";
import { TokenSetAuthRegistry } from "@securitydept/token-set-context-client-angular";
import { FrontendOidcModeClient } from "@securitydept/token-set-context-client/frontend-oidc-mode";
import {
  EMPTY,
  Observable,
  defer,
  distinctUntilChanged,
  from,
  map,
  shareReplay,
  switchMap,
} from "rxjs";
import { AuthPrincipal } from "@securitydept/token-set-context-client/orchestration";
import { AuthClientKey } from "./auth.defs";

@Injectable({
  providedIn: "root",
})
export class AuthService {
  private readonly registry = inject(TokenSetAuthRegistry);
  private readonly router = inject(Router);

  // Streams keyed by client — lazily resolved once whenReady() resolves.
  // Using defer() + from(whenReady()) means the Observable is not subscribed
  // until something subscribes to it, at which point the auth service awaits
  // client readiness naturally rather than assuming it is synchronously available.
  readonly isAuthenticated$: Map<AuthClientKey, Observable<boolean>> = new Map(
    (Object.values(AuthClientKey) as AuthClientKey[]).map((key) => [
      key,
      defer(() =>
        from(this.registry.whenReady(key)).pipe(
          switchMap((service) =>
            service.authState$.pipe(
              map((s) => s !== null),
              distinctUntilChanged(),
            ),
          ),
          shareReplay(1),
        ),
      ),
    ]),
  );

  readonly userInfo$: Map<AuthClientKey, Observable<AuthPrincipal | null>> = new Map(
    (Object.values(AuthClientKey) as AuthClientKey[]).map((key) => [
      key,
      defer(() =>
        from(this.registry.whenReady(key)).pipe(
          switchMap((service) =>
            service.authState$.pipe(map((s) => s?.metadata?.principal ?? null)),
          ),
          shareReplay(1),
        ),
      ),
    ]),
  );

  /**
   * Get the FrontendOidcModeClient for a key once it has materialized.
   *
   * Returns a Promise so callers can await client readiness rather than
   * assuming the client is synchronously available.
   */
  async getClient(key: AuthClientKey): Promise<FrontendOidcModeClient | null> {
    const service = await this.registry.whenReady(key);
    if (service.client instanceof FrontendOidcModeClient) {
      return service.client;
    }
    return null;
  }

  /**
   * Redirect to the IdP login page, recording the current route so it can
   * be resumed after successful authentication.
   *
   * Intended for use inside an `onUnauthenticated` handler passed to
   * `createTokenSetRouteAggregationGuard()`.
   */
  redirectToLogin(clientKey: AuthClientKey): Observable<never> {
    return defer(() =>
      from(this.getClient(clientKey)).pipe(
        switchMap((client) => {
          if (!client) return EMPTY;
          return from(client.loginWithRedirect({ postAuthRedirectUri: this.router.url })).pipe(
            switchMap(() => EMPTY),
          );
        }),
      ),
    );
  }
}
