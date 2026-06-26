import { Injectable, inject } from "@angular/core";
import { Router } from "@angular/router";
import type { IdentityPrincipal } from "@securitydept/client";
import type { BaseOidcModeClient } from "@securitydept/token-set-context-client/orchestration";
import type { TokenSetClientRegistry } from "@securitydept/token-set-context-client/registry";
import { TOKEN_SET_CLIENT_REGISTRY } from "@securitydept/token-set-context-client-angular";
import {
  EMPTY,
  type Observable,
  defer,
  distinctUntilChanged,
  from,
  map,
  shareReplay,
  switchMap,
} from "rxjs";
import { AuthClientKey } from "./auth.defs";

@Injectable({
  providedIn: "root",
})
export class AuthService {
  private readonly registry: TokenSetClientRegistry<BaseOidcModeClient> =
    inject(TOKEN_SET_CLIENT_REGISTRY);
  private readonly router = inject(Router);

  readonly isAuthenticated$: Map<AuthClientKey, Observable<boolean>> = new Map(
    (Object.values(AuthClientKey) as AuthClientKey[]).map((key) => [
      key,
      defer(() => from(this.registry.clientResourceFor(key).whenValue())).pipe(
        switchMap((client) => from(client.isAuthenticated.value)),
        distinctUntilChanged(),
        shareReplay({ bufferSize: 1, refCount: true }),
      ),
    ]),
  );

  readonly userInfo$: Map<AuthClientKey, Observable<IdentityPrincipal | null>> = new Map(
    (Object.values(AuthClientKey) as AuthClientKey[]).map((key) => [
      key,
      defer(() => from(this.registry.clientResourceFor(key).whenValue())).pipe(
        switchMap((client) => from(client.authResource.value)),
        map((snapshot) => snapshot?.metadata.principal ?? null),
        distinctUntilChanged(),
        shareReplay({ bufferSize: 1, refCount: true }),
      ),
    ]),
  );

  async getClient(key: AuthClientKey): Promise<BaseOidcModeClient> {
    return await this.registry.clientResourceFor(key).whenValue();
  }

  /** Redirect to the IdP and preserve the attempted application URL. */
  redirectToLogin(
    clientKey: AuthClientKey,
    postAuthRedirectUri: string = this.router.url,
  ): Observable<never> {
    return defer(() =>
      from(this.getClient(clientKey)).pipe(
        switchMap((client) =>
          from(client.loginWithRedirect({ postAuthRedirectUri })).pipe(switchMap(() => EMPTY)),
        ),
      ),
    );
  }
}
