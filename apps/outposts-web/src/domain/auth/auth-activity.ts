import { signal } from "@angular/core";
import type { RouteBehaviourContextExtra } from "@securitydept/client";
import type { BaseOidcModeClient } from "@securitydept/token-set-context-client/orchestration";
import type { TokenSetOnClientUnauthenticated } from "@securitydept/token-set-context-client/registry";

/** What the auth flow is doing that the user has to wait for. */
export const AuthActivity = {
  Idle: "idle",
  /** A guard decided to leave the app for the IdP login page. */
  Redirecting: "redirecting",
  /** The IdP sent the user back and the callback is being exchanged. */
  Callback: "callback",
} as const;

export type AuthActivity = (typeof AuthActivity)[keyof typeof AuthActivity];

// Module-level because SDK route behaviour hooks run outside Angular DI;
// a root signal is the only state both the hook and components can reach.
const activity = signal<AuthActivity>(AuthActivity.Idle);

export const authActivity = activity.asReadonly();

export function setAuthActivity(next: AuthActivity): void {
  activity.set(next);
}

/** Resets only when the current activity matches, so a newer flow is never clobbered. */
export function clearAuthActivity(expected: AuthActivity): void {
  if (activity() === expected) activity.set(AuthActivity.Idle);
}

/**
 * Mirrors the SDK default (redirect to the IdP for the first unauthenticated
 * client) and marks the redirect, so the UI reflects the real decision instead
 * of guessing it from pending router navigations.
 */
export const redirectToLoginOnUnauthenticated: TokenSetOnClientUnauthenticated<
  BaseOidcModeClient,
  RouteBehaviourContextExtra
> = async (_requirement, context, clients) => {
  for await (const { client } of clients) {
    if ((await client.isAuthenticated.whenValue()) === true) continue;

    setAuthActivity(AuthActivity.Redirecting);
    try {
      await client.loginWithRedirect({ postAuthRedirectUri: context.planContext.routeState.url });
    } catch (error) {
      clearAuthActivity(AuthActivity.Redirecting);
      throw error;
    }
    // The page is unloading; keep the navigation pending like the SDK default.
    return await new Promise<never>(() => {});
  }
  return true;
};
