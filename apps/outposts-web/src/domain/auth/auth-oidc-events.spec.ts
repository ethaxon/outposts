import { Subject } from "rxjs";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { EventTypes, subscribeToOidcEvents } from "./auth-oidc-events";

describe("EventTypes const object", () => {
  // Reference values cross-checked against the library source (event-types.ts).
  // satisfies ensures TypeScript validates each value against the real enum literal
  // type — a wrong number here becomes a compile error, not a silent wrong test.
  const LIBRARY_VALUES = {
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

  it("contains an entry for every known library EventType", () => {
    for (const [key, value] of Object.entries(LIBRARY_VALUES)) {
      expect(EventTypes[key as keyof typeof EventTypes]).toBe(value);
    }
  });

  it("has the same number of entries as the library enum", () => {
    expect(Object.keys(EventTypes)).toHaveLength(Object.keys(LIBRARY_VALUES).length);
  });
});

describe("subscribeToOidcEvents", () => {
  let events$: Subject<{ type: number }>;
  let onRenewSuccess: ReturnType<typeof vi.fn>;
  let onRenewFailure: ReturnType<typeof vi.fn>;

  // Cast mocks to the () => void signature expected by OidcEventHandlers.
  const asVoidFn = (fn: ReturnType<typeof vi.fn>) => fn as unknown as () => void;

  const register = (
    src$: Subject<{ type: number }>,
    successFn = onRenewSuccess,
    failureFn = onRenewFailure,
  ) =>
    subscribeToOidcEvents(src$, {
      onRenewSuccess: asVoidFn(successFn),
      onRenewFailure: asVoidFn(failureFn),
    });

  beforeEach(() => {
    events$ = new Subject<{ type: number }>();
    onRenewSuccess = vi.fn();
    onRenewFailure = vi.fn();
    register(events$);
  });

  afterEach(() => {
    events$.complete();
  });

  // ── Renew success ─────────────────────────────────────────────────────────

  it("calls onRenewSuccess when NewAuthenticationResult fires", () => {
    events$.next({ type: EventTypes.NewAuthenticationResult });
    expect(onRenewSuccess).toHaveBeenCalledTimes(1);
    expect(onRenewFailure).not.toHaveBeenCalled();
  });

  it("calls onRenewSuccess on every subsequent renew", () => {
    events$.next({ type: EventTypes.NewAuthenticationResult });
    events$.next({ type: EventTypes.NewAuthenticationResult });
    events$.next({ type: EventTypes.NewAuthenticationResult });
    expect(onRenewSuccess).toHaveBeenCalledTimes(3);
  });

  // ── Renew failure ─────────────────────────────────────────────────────────

  it("calls onRenewFailure when SilentRenewFailed fires", () => {
    events$.next({ type: EventTypes.SilentRenewFailed });
    expect(onRenewFailure).toHaveBeenCalledTimes(1);
    expect(onRenewSuccess).not.toHaveBeenCalled();
  });

  it("ignores TokenExpired (informational, library will attempt silent renew)", () => {
    events$.next({ type: EventTypes.TokenExpired });
    expect(onRenewFailure).not.toHaveBeenCalled();
    expect(onRenewSuccess).not.toHaveBeenCalled();
  });

  it("ignores IdTokenExpired (informational, library will attempt silent renew)", () => {
    events$.next({ type: EventTypes.IdTokenExpired });
    expect(onRenewFailure).not.toHaveBeenCalled();
    expect(onRenewSuccess).not.toHaveBeenCalled();
  });

  // ── Unrelated events are silently ignored ─────────────────────────────────

  it("ignores ConfigLoaded events", () => {
    events$.next({ type: EventTypes.ConfigLoaded });
    expect(onRenewSuccess).not.toHaveBeenCalled();
    expect(onRenewFailure).not.toHaveBeenCalled();
  });

  it("ignores CheckingAuth and CheckingAuthFinished events", () => {
    events$.next({ type: EventTypes.CheckingAuth });
    events$.next({ type: EventTypes.CheckingAuthFinished });
    expect(onRenewSuccess).not.toHaveBeenCalled();
    expect(onRenewFailure).not.toHaveBeenCalled();
  });

  it("ignores SilentRenewStarted (only Started, not Failed)", () => {
    events$.next({ type: EventTypes.SilentRenewStarted });
    expect(onRenewSuccess).not.toHaveBeenCalled();
    expect(onRenewFailure).not.toHaveBeenCalled();
  });

  it("ignores UserDataChanged events", () => {
    events$.next({ type: EventTypes.UserDataChanged });
    expect(onRenewSuccess).not.toHaveBeenCalled();
    expect(onRenewFailure).not.toHaveBeenCalled();
  });

  // ── Mixed event sequences ─────────────────────────────────────────────────

  it("handles interleaved success and failure events independently", () => {
    events$.next({ type: EventTypes.NewAuthenticationResult });
    events$.next({ type: EventTypes.SilentRenewFailed });
    events$.next({ type: EventTypes.NewAuthenticationResult });
    events$.next({ type: EventTypes.TokenExpired }); // ignored

    expect(onRenewSuccess).toHaveBeenCalledTimes(2);
    expect(onRenewFailure).toHaveBeenCalledTimes(1);
  });

  // ── Subscription lifecycle ────────────────────────────────────────────────

  it("stops dispatching after returned subscriptions are unsubscribed", () => {
    // beforeEach has already registered one subscription; this call registers a second.
    // Both share the same mocks, so events fire twice while both are active.
    const subs = register(events$);

    events$.next({ type: EventTypes.NewAuthenticationResult });
    expect(onRenewSuccess).toHaveBeenCalledTimes(2); // beforeEach sub + this test's sub

    subs.forEach((s) => s.unsubscribe());
    onRenewSuccess.mockClear();
    onRenewFailure.mockClear();

    events$.next({ type: EventTypes.NewAuthenticationResult });
    events$.next({ type: EventTypes.SilentRenewFailed });

    // Only the beforeEach sub remains; each event fires exactly once.
    expect(onRenewSuccess).toHaveBeenCalledTimes(1);
    expect(onRenewFailure).toHaveBeenCalledTimes(1);
  });

  it("returns one subscription per event group (success and failure)", () => {
    const subs = register(events$);
    expect(subs).toHaveLength(2);
    subs.forEach((s) => s.unsubscribe());
  });
});
