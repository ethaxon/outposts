import { APP_INITIALIZER, type Provider } from "@angular/core";
import { take } from "rxjs";
import { authInterceptor } from "./auth.interceptor";
import { AuthService } from "./auth.service";

export const AUTH_PROVIDERS: Provider[] = [
  authInterceptor,
  {
    provide: APP_INITIALIZER,
    multi: true,
    useFactory: (authService: AuthService) => {
      return () => authService.isAuthenticated$.pipe(take(1));
    },
    deps: [AuthService],
  },
];
