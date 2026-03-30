import { InjectionToken } from "@angular/core";
import type { AuthUserState } from "./auth.defs";

export type AuthAccessTokenClaims = Record<string, unknown> & {
  scope?: string;
};

export interface AuthDriver {
  signInRedirect(redirectUrl: string): Promise<void>;
  signOutRedirect(redirectUrl: string): Promise<void>;
  handleRedirectCallback(callbackUrl: string): Promise<void>;
  isRedirectCallback(callbackUrl: string): Promise<boolean>;
  isAuthenticated(): Promise<boolean>;
  getUserInfo(): Promise<AuthUserState | null>;
  getAccessToken(resource: string): Promise<string | null>;
  getAccessTokenClaims(resource: string): Promise<AuthAccessTokenClaims | null>;
}

export const AUTH_DRIVER = new InjectionToken<AuthDriver>("AUTH_DRIVER");
