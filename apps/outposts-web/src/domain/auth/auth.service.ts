import { Location } from "@angular/common";
import { DestroyRef, DOCUMENT, Injectable, inject } from "@angular/core";
import { takeUntilDestroyed } from "@angular/core/rxjs-interop";
import {
	type ActivatedRouteSnapshot,
	Router,
	type RouterStateSnapshot,
} from "@angular/router";
import LogtoClient from "@logto/browser";
import type { AccessTokenClaims } from "@logto/js";
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
	tap,
	throwError,
} from "rxjs";
import { WINDOW } from "@/core/providers/window";
import { environment } from "../../environments/environment";
import {
	AUTH_CALLBACK_ORIGIN_URI_KEY,
	AUTH_CALLBACK_PATH,
	AUTH_RESOURCE_CONFIGS,
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
	protected readonly logtoClient: LogtoClient = new LogtoClient({
		endpoint: environment.AUTH_ENDPOINT,
		appId: environment.AUTH_APPID,
		resources: AUTH_RESOURCE_CONFIGS.map((r) => r.resource),
		scopes: AUTH_RESOURCE_CONFIGS.flatMap((r) => r.scopes),
	});
	protected readonly destoryRef = inject(DestroyRef);
	protected readonly window = inject(WINDOW);
	protected readonly location = inject(Location);
	protected readonly document = inject(DOCUMENT);
	protected readonly router = inject(Router);

	protected readonly initSubject$ = new Subject<void>();
	protected readonly refreshSubject$ = new Subject<void>();
	protected readonly errorSubject$ = new ReplaySubject<Error>(1);

	protected readonly authSyncTrigger$ = merge(
		this.initSubject$,
		this.refreshSubject$,
	);

	public readonly error$ = this.errorSubject$.asObservable();
	public readonly isAuthenticated$: Observable<boolean>;
	public readonly userInfo$: Observable<AuthUserState | null>;

	constructor() {
		const isAuthenticated$ = this.authSyncTrigger$.pipe(
			switchMap(() => this.logtoClient.isAuthenticated()),
			catchError((error) => {
				this.error = error;
				return of(false);
			}),
		);

		this.userInfo$ = isAuthenticated$.pipe(
			switchMap((isAuthenticated) =>
				isAuthenticated ? this.logtoClient.fetchUserInfo() : of(null),
			),
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
						? (this.handleSignInCallback(
								this.window.location.href,
							) as Observable<boolean>)
						: of(undefined),
				),
				takeUntilDestroyed(this.destoryRef),
			)
			.subscribe(this.initSubject$ as Observer<undefined | boolean>);

		this.error$.pipe(takeUntilDestroyed(this.destoryRef)).subscribe((error) => {
			console.error("Auth error:", error);
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
			return from(this.logtoClient.signIn(options.redirectUrl));
		}
		/**
		 * @TODO FIXME HERE
		 */
		return throwError(() => new Error("not implemented"));
	}

	signOut(options: SignOutOptions): Observable<void> {
		if (options.signOutType === "redirect") {
			return from(this.logtoClient.signOut(options.redirectUrl));
		}
		/**
		 * @TODO FIXME HERE
		 */
		return throwError(() => new Error("not implemented"));
	}

	handleSignInCallback(callbackUrl: string): Observable<boolean> {
		return from(this.logtoClient.handleSignInCallback(callbackUrl)).pipe(
			switchMap(() => this.logtoClient.isAuthenticated()),
			tap((signInCallbackResult) => {
				let authCallbackOriginUri = "/";
				try {
					if (signInCallbackResult) {
						authCallbackOriginUri =
							localStorage.getItem(AUTH_CALLBACK_ORIGIN_URI_KEY) || "/";
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
		return from(
			this.logtoClient.isSignInRedirected(this.window.location.href),
		).pipe(
			catchError((error) => {
				this.error = error;
				return of(false);
			}),
		);
	}

	getResourceToken(resource: string): Observable<string | null> {
		return from(this.logtoClient.getAccessToken(resource)).pipe(
			catchError((error) => {
				this.error = error;
				return of(null);
			}),
		);
	}

	getResourcesClaims(resourcesConfigs: AuthResourceConfig[]): Observable<{
		configs: AuthResourceConfig[];
		resources: AccessTokenClaims[];
	} | null> {
		return this.isAuthenticated$.pipe(
			switchMap((isAuth) => {
				if (!isAuth) {
					return of(null);
				}
				return forkJoin(
					resourcesConfigs.map((r) =>
						from(this.logtoClient.getAccessTokenClaims(r.resource)).pipe(
							catchError((error) => {
								this.error = error;
								return of({} as AccessTokenClaims);
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
		}: {
			originUrlToBase?: string;
		} = {},
	): (
		route: ActivatedRouteSnapshot,
		state: RouterStateSnapshot,
	) => Observable<boolean> {
		return (_route, state) => {
			const originUrl = originUrlToBase ?? state.url;
			return this.isAuthenticated$.pipe(
				switchMap((isAuth) => {
					if (isAuth) {
						return of(true);
					}

					const redirectUrl = new URL(
						`${this.window.location.protocol}//${environment.APP_HOST}${AUTH_CALLBACK_PATH}`,
					);

					try {
						localStorage.setItem(AUTH_CALLBACK_ORIGIN_URI_KEY, originUrl);
					} catch (e) {
						console.error("Failed to store origin URL in local storage.", e);
					}

					return from(
						this.signIn({
							redirectUrl: redirectUrl.toString(),
							signInType: "redirect",
						}),
					).pipe(switchMap(() => EMPTY));
				}),
				switchMap((_isAuth) => {
					return this.getResourcesClaims(resourcesConfigs).pipe(
						map((clms) => {
							const expectedScopes = resourcesConfigs.flatMap((c) => c.scopes);
							const actualScopes = new Set(
								(clms?.resources || []).flatMap((c) => parseScope(c?.scope)),
							);
							return (
								expectedScopes.length === 0 ||
								expectedScopes.every((e) => actualScopes.has(e))
							);
						}),
					);
				}),
			);
		};
	}
}
