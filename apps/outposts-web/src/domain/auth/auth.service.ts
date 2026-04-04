import { DestroyRef, Injectable, inject } from "@angular/core";
import { takeUntilDestroyed } from "@angular/core/rxjs-interop";
import { type ActivatedRouteSnapshot, Router, type RouterStateSnapshot } from "@angular/router";
import { PublicEventsService } from "angular-auth-oidc-client";
import { subscribeToOidcEvents } from "./auth-oidc-events";
import {
  catchError,
  distinctUntilChanged,
  EMPTY,
  forkJoin,
  from,
  map,
  merge,
  type Observable,
  type Observer,
  of,
  ReplaySubject,
  Subject,
  shareReplay,
  switchMap,
  take,
  tap,
  throwError,
} from "rxjs";
import { WINDOW } from "@/core/providers/window";
import { environment } from "../../environments/environment";
import { AUTH_DRIVER, type AuthAccessTokenClaims } from "./auth.driver";
import {
  AUTH_CALLBACK_ORIGIN_URI_KEY,
  AUTH_CALLBACK_PATH,
  type AuthResourceConfig,
  type AuthUserState,
  type SignInOptions,
  type SignOutOptions,
} from "./auth.defs";
import { parseScope } from "./auth.utils";

@Injectable({
  providedIn: "root",
})
export class AuthService {
  protected readonly authDriver = inject(AUTH_DRIVER);
  protected readonly destoryRef = inject(DestroyRef);
  protected readonly window = inject(WINDOW);
  protected readonly router = inject(Router);

  protected readonly initSubject$ = new Subject<void>();
  protected readonly refreshSubject$ = new Subject<void>();
  protected readonly errorSubject$ = new ReplaySubject<Error>(1);

  protected readonly authSyncTrigger$ = merge(this.initSubject$, this.refreshSubject$);

  public readonly error$ = this.errorSubject$.asObservable();
  public readonly isAuthenticated$: Observable<boolean>;
  public readonly userInfo$: Observable<AuthUserState | null>;

  constructor() {
    const publicEventsService = inject(PublicEventsService);

    const isAuthenticated$ = this.authSyncTrigger$.pipe(
      switchMap(() => this.authDriver.isAuthenticated()),
      catchError((error) => {
        this.error = error;
        return of(false);
      }),
    );

    this.userInfo$ = isAuthenticated$.pipe(
      switchMap((isAuthenticated) => (isAuthenticated ? this.authDriver.getUserInfo() : of(null))),
      catchError((error) => {
        this.error = error;
        return of(null);
      }),
      shareReplay(1),
    );

    this.isAuthenticated$ = this.userInfo$.pipe(
      map((userInfo) => !!userInfo),
      distinctUntilChanged(),
      shareReplay(1),
    );

    this.shouldHandleCallback()
      .pipe(
        switchMap((isCallback) =>
          isCallback
            ? (this.handleSignInCallback(this.window.location.href) as Observable<boolean>)
            : of(undefined),
        ),
        takeUntilDestroyed(this.destoryRef),
      )
      .subscribe(this.initSubject$ as Observer<undefined | boolean>);

    this.error$.pipe(takeUntilDestroyed(this.destoryRef)).subscribe((error) => {
      console.error("Auth error:", error);
    });

    // React to OIDC library lifecycle events (silent renew success / failure).
    // The heavy lifting lives in subscribeToOidcEvents() which is a pure
    // function tested independently.
    const oidcEvents$ = publicEventsService
      .registerForEvents()
      .pipe(takeUntilDestroyed(this.destoryRef));

    subscribeToOidcEvents(oidcEvents$, {
      onRenewSuccess: () => this.refresh(),
      onRenewFailure: () => {
        const redirectUrl = new URL(
          `${this.window.location.protocol}//${environment.APP_HOST}${AUTH_CALLBACK_PATH}`,
        );
        try {
          localStorage.setItem(AUTH_CALLBACK_ORIGIN_URI_KEY, this.router.url);
        } catch (e) {
          console.error("Failed to store origin URL in local storage.", e);
        }
        this.signIn({ signInType: "redirect", redirectUrl: redirectUrl.toString() }).subscribe();
      },
    });
  }

  public refresh(): void {
    this.refreshSubject$.next();
  }

  public set error(error: Error) {
    this.errorSubject$.next(error);
  }

  signIn(options: SignInOptions): Observable<void> {
    if (options.signInType === "redirect") {
      return from(this.authDriver.signInRedirect(options.redirectUrl));
    }
    // Popup: open the IdP in a popup, await completion, then refresh auth state
    // so isAuthenticated$ / userInfo$ reflect the new session.
    return from(this.authDriver.signInPopup()).pipe(
      tap(() => this.refresh()),
      map(() => undefined),
    );
  }

  signOut(options: SignOutOptions): Observable<void> {
    if (options.signOutType === "redirect") {
      return from(this.authDriver.signOutRedirect(options.redirectUrl));
    }
    /**
     * @TODO FIXME HERE
     */
    return throwError(() => new Error("not implemented"));
  }

  handleSignInCallback(callbackUrl: string): Observable<boolean> {
    return from(this.authDriver.handleRedirectCallback(callbackUrl)).pipe(
      switchMap(() => this.authDriver.isAuthenticated()),
      tap((signInCallbackResult) => {
        let authCallbackOriginUri = "/";
        try {
          if (signInCallbackResult) {
            authCallbackOriginUri = localStorage.getItem(AUTH_CALLBACK_ORIGIN_URI_KEY) || "/";
          }
          localStorage.removeItem(AUTH_CALLBACK_ORIGIN_URI_KEY);
        } catch (e: unknown) {
          this.error = e as Error;
          console.error("Failed to load origin URL in local storage.", e);
        }
        this.router.navigateByUrl(authCallbackOriginUri, { replaceUrl: true });
        return signInCallbackResult;
      }),
      catchError((error) => {
        this.router.navigateByUrl("/", { replaceUrl: true });
        this.error = error;
        return of(false);
      }),
    );
  }

  protected shouldHandleCallback(): Observable<boolean> {
    return from(this.authDriver.isRedirectCallback(this.window.location.href)).pipe(
      catchError((error) => {
        this.error = error;
        return of(false);
      }),
    );
  }

  getResourceToken(resource: string): Observable<string | null> {
    return from(this.authDriver.getAccessToken(resource)).pipe(
      catchError((error) => {
        this.error = error;
        return of(null);
      }),
    );
  }

  getResourcesClaims(resourcesConfigs: AuthResourceConfig[]): Observable<{
    configs: AuthResourceConfig[];
    resources: Array<AuthAccessTokenClaims | null>;
  } | null> {
    return this.isAuthenticated$.pipe(
      switchMap((isAuth) => {
        if (!isAuth) {
          return of(null);
        }
        return forkJoin(
          resourcesConfigs.map((r) =>
            from(this.authDriver.getAccessTokenClaims(r.resource)).pipe(
              catchError((error) => {
                this.error = error;
                return of(null);
              }),
            ),
          ),
        ).pipe(
          map((resourceClaims) => {
            return {
              configs: resourcesConfigs,
              resources: resourceClaims,
            };
          }),
        );
      }),
    );
  }

  canActivate(
    resourcesConfigs: AuthResourceConfig[],
    {
      originUrlToBase,
      signInType = "popup",
    }: {
      originUrlToBase?: string;
      signInType?: SignInOptions["signInType"];
    } = {},
  ): (route: ActivatedRouteSnapshot, state: RouterStateSnapshot) => Observable<boolean> {
    return (_route, state) => {
      const originUrl = originUrlToBase ?? state.url;
      return this.isAuthenticated$.pipe(
        take(1),
        switchMap((isAuth) => {
          if (isAuth) {
            return of(true);
          }

          if (signInType === "popup") {
            // Popup: stays on the same page. After signIn() resolves isAuthenticated$
            // is updated via refresh(), so we switchMap back into a fresh auth check.
            return this.signIn({ signInType: "popup" }).pipe(
              switchMap(() => this.isAuthenticated$),
              take(1),
              catchError(() => {
                // Popup blocked or failed — fall back to redirect flow
                return this._signInRedirectAndBlock(originUrl);
              }),
            );
          }

          return this._signInRedirectAndBlock(originUrl);
        }),
        switchMap((isAuth) => {
          if (!isAuth) {
            return of(false);
          }
          return this.getResourcesClaims(resourcesConfigs).pipe(
            map((clms) => {
              const expectedScopes = resourcesConfigs.flatMap((c) => c.scopes);
              const actualScopes = new Set(
                (clms?.resources || []).flatMap((c) => parseScope(c?.scope)),
              );
              return (
                expectedScopes.length === 0 || expectedScopes.every((e) => actualScopes.has(e))
              );
            }),
          );
        }),
      );
    };
  }

  /** Redirect to IdP for sign-in and block the route (emits EMPTY while navigating). */
  private _signInRedirectAndBlock(originUrl: string): Observable<never> {
    const redirectUrl = new URL(
      `${this.window.location.protocol}//${environment.APP_HOST}${AUTH_CALLBACK_PATH}`,
    );
    try {
      localStorage.setItem(AUTH_CALLBACK_ORIGIN_URI_KEY, originUrl);
    } catch (e) {
      console.error("Failed to store origin URL in local storage.", e);
    }
    return this.signIn({
      redirectUrl: redirectUrl.toString(),
      signInType: "redirect",
    }).pipe(switchMap(() => EMPTY));
  }
}
