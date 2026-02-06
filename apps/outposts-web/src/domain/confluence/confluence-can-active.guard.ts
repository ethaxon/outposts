import { inject } from "@angular/core";
import type { CanActivateFn } from "@angular/router";
import { AuthService } from "@/domain/auth/auth.service";
import { AUTH_CONFLUENCE_CONFIG } from "./confluence.defs";

export const canActiveConfluence: CanActivateFn = (...args) => {
	const authService = inject(AuthService);

	return authService.canActivate([AUTH_CONFLUENCE_CONFIG])(...args);
};
