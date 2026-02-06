import { CommonModule } from "@angular/common";
import { APP_INITIALIZER, NgModule } from "@angular/core";
import { take } from "rxjs";
import { authInterceptor } from "./auth.interceptor";
import { AuthService } from "./auth.service";
import { AuthRoutingModule } from "./auth-routing.module";

@NgModule({
	declarations: [],
	providers: [
		AuthService,
		authInterceptor,
		{
			provide: APP_INITIALIZER,
			multi: true,
			useFactory: (authService: AuthService) => {
				return () => {
					return authService.isAuthenticated$.pipe(take(1));
				};
			},
			deps: [AuthService],
		},
	],
	imports: [CommonModule, AuthRoutingModule],
})
export class AuthModule {}
