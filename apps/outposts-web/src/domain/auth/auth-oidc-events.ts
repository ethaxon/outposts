import { type Observable, type Subscription, filter } from "rxjs";

// Mirrors angular-auth-oidc-client's EventTypes enum as a plain const object.
//
// The `satisfies typeof import(...)` clause is used ONLY as a type — TypeScript
// erases it entirely at compile time, so no runtime import of
// angular-auth-oidc-client is generated (which would trigger the Angular JIT
// compiler and break vitest in node mode).
//
// Benefits over individual `const OIDC_EVENT_XYZ = N` constants:
//   • TypeScript validates every value against the real library literal type.
//   • TypeScript requires all enum members to be present — a library upgrade
//     that adds a new member will produce a compile error, not silent drift.

export const EventTypes = {
  ConfigLoaded: 0,
  CheckingAuth: 1,
  CheckingAuthFinished: 2,
  CheckingAuthFinishedWithError: 3,
  ConfigLoadingFailed: 4,
  CheckSessionReceived: 5,
  UserDataChanged: 6,
  NewAuthenticationResult: 7,
  TokenExpired: 8,
  IdTokenExpired: 9,
  SilentRenewStarted: 10,
  SilentRenewFailed: 11,
} satisfies typeof import("angular-auth-oidc-client").EventTypes;

export interface OidcEventHandlers {
  /** Called after every successful silent renew / refresh-token grant. */
  onRenewSuccess: () => void;
  /** Called when silent renew fails or a token expires without renewal. */
  onRenewFailure: () => void;
}

/**
 * Subscribe to OIDC library events and dispatch to the appropriate handler.
 *
 * This is a pure function with no Angular dependencies so it can be tested
 * in isolation under vitest's node environment.
 *
 * @param events$ - Observable of OIDC event notifications (from PublicEventsService)
 * @param handlers - Callbacks for renewal success and failure
 * @returns An array of subscriptions (caller is responsible for cleanup)
 */
export function subscribeToOidcEvents(
  events$: Observable<{ type: number }>,
  handlers: OidcEventHandlers,
): Subscription[] {
  const renewSuccessSub = events$
    .pipe(filter((e) => e.type === EventTypes.NewAuthenticationResult))
    .subscribe(() => handlers.onRenewSuccess());

  const renewFailureSub = events$
    .pipe(
      filter(
        (e) =>
          e.type === EventTypes.SilentRenewFailed ||
          e.type === EventTypes.TokenExpired ||
          e.type === EventTypes.IdTokenExpired,
      ),
    )
    .subscribe(() => handlers.onRenewFailure());

  return [renewSuccessSub, renewFailureSub];
}
