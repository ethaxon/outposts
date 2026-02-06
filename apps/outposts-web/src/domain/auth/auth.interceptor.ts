import {
	HTTP_INTERCEPTORS,
	type HttpEvent,
	type HttpHandler,
	type HttpInterceptor,
	type HttpRequest,
} from "@angular/common/http";
import { Injectable, inject } from "@angular/core";
import { type Observable, of, switchMap } from "rxjs";
import { AUTH_RESOURCE_CONFIGS } from "./auth.defs";
import { AuthService } from "./auth.service";

@Injectable()
export class AuthInterceptor implements HttpInterceptor {
	protected readonly authService = inject(AuthService);

	intercept(
		req: HttpRequest<unknown>,
		next: HttpHandler,
	): Observable<HttpEvent<unknown>> {
		return of(
			AUTH_RESOURCE_CONFIGS.find((r) => req.url.startsWith(r.resource)),
		).pipe(
			switchMap((matchResource) =>
				matchResource
					? this.authService.getResourceToken(matchResource.resource)
					: of(null),
			),
			switchMap((resourceAccessToken) => {
				let authReq = req;
				if (resourceAccessToken) {
					authReq = req.clone({
						setHeaders: { Authorization: `Bearer ${resourceAccessToken}` },
					});
				}
				return next.handle(authReq);
			}),
		);
	}
}

export const authInterceptor = {
	provide: HTTP_INTERCEPTORS,
	useClass: AuthInterceptor,
	multi: true,
};
