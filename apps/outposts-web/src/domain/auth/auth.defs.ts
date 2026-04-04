import { AUTH_CONFLUENCE_CONFIG } from "@/domain/confluence/confluence.defs";

export interface AuthResourceConfig {
  resource: string;
  scopes: string[];
}

export const AUTH_CALLBACK_PATH = "/auth/callback";
export const AUTH_CALLBACK_ORIGIN_URI_KEY = "auth_callback_origin_uri";
export const AUTH_RESOURCE_CONFIGS: AuthResourceConfig[] = [AUTH_CONFLUENCE_CONFIG];

export type AuthUserIdentity = {
  userId: string;
  details?: Record<string, unknown>;
};

export type AuthUserState = {
  sub: string;
  name?: string | null;
  username?: string | null;
  picture?: string | null;
  email?: string | null;
  email_verified?: boolean;
  phone_number?: string | null;
  phone_number_verified?: boolean;
  custom_data?: unknown;
  identities?: Record<string, AuthUserIdentity>;
};

export interface RedirectSignInOptions {
  signInType: "redirect";
  redirectUrl: string;
}

export interface PopupSignInOptions {
  signInType: "popup";
}

export type SignInOptions = RedirectSignInOptions | PopupSignInOptions;

export interface RedirectSignOutOptions {
  signOutType: "redirect";
  redirectUrl: string;
}

/**
 * @unimplemented
 */
export interface PopupSignOutOptions {
  signOutType: "popup";
}

export type SignOutOptions = RedirectSignOutOptions | PopupSignOutOptions;
