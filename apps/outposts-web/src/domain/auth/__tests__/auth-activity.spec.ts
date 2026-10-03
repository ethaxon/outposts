import { beforeEach, describe, expect, it, vi } from "vitest";
import {
  AuthActivity,
  authActivity,
  clearAuthActivity,
  redirectToLoginOnUnauthenticated,
  setAuthActivity,
} from "../auth-activity";

type HookArgs = Parameters<typeof redirectToLoginOnUnauthenticated>;

function fakeClient(authenticated: boolean, loginWithRedirect = vi.fn(async () => undefined)) {
  return {
    client: {
      isAuthenticated: { whenValue: async () => authenticated },
      loginWithRedirect,
    },
  };
}

async function* clientsOf(...views: ReturnType<typeof fakeClient>[]) {
  yield* views;
}

function invoke(...views: ReturnType<typeof fakeClient>[]) {
  const context = { planContext: { routeState: { url: "/confluence/dashboard" } } };
  return redirectToLoginOnUnauthenticated(
    {} as HookArgs[0],
    context as unknown as HookArgs[1],
    clientsOf(...views) as unknown as HookArgs[2],
  );
}

describe("auth activity", () => {
  beforeEach(() => setAuthActivity(AuthActivity.Idle));

  it("only clears the activity it expects", () => {
    setAuthActivity(AuthActivity.Redirecting);
    clearAuthActivity(AuthActivity.Callback);
    expect(authActivity()).toBe(AuthActivity.Redirecting);

    clearAuthActivity(AuthActivity.Redirecting);
    expect(authActivity()).toBe(AuthActivity.Idle);
  });

  it("lets the route through without signalling when every client is authenticated", async () => {
    await expect(invoke(fakeClient(true), fakeClient(true))).resolves.toBe(true);
    expect(authActivity()).toBe(AuthActivity.Idle);
  });

  it("marks the redirect and logs in with the guarded route as post-auth target", async () => {
    const login = vi.fn(async () => undefined);
    const settled = vi.fn();
    void Promise.resolve(invoke(fakeClient(true), fakeClient(false, login))).then(settled);

    await vi.waitFor(() => expect(login).toHaveBeenCalledOnce());
    expect(login).toHaveBeenCalledWith({ postAuthRedirectUri: "/confluence/dashboard" });
    expect(authActivity()).toBe(AuthActivity.Redirecting);
    await Promise.resolve();
    // The navigation stays pending while the page unloads.
    expect(settled).not.toHaveBeenCalled();
  });

  it("clears the redirect when starting the login fails", async () => {
    const failure = new Error("authorize failed");
    const login = vi.fn(async () => {
      throw failure;
    });

    await expect(invoke(fakeClient(false, login))).rejects.toBe(failure);
    expect(authActivity()).toBe(AuthActivity.Idle);
  });
});
