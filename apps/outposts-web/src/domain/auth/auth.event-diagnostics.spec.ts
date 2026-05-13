import { describe, expect, it, vi } from "vitest";

function createMemoryStorage(initial: Record<string, string> = {}): Storage {
  const store = new Map(Object.entries(initial));

  return {
    get length() {
      return store.size;
    },
    clear() {
      store.clear();
    },
    getItem(key: string) {
      return store.get(key) ?? null;
    },
    key(index: number) {
      return [...store.keys()][index] ?? null;
    },
    removeItem(key: string) {
      store.delete(key);
    },
    setItem(key: string, value: string) {
      store.set(key, value);
    },
  };
}

describe("installOutpostsAuthEventDiagnostics", () => {
  it("exposes an inspect() snapshot with current client and persisted storage state", async () => {
    vi.resetModules();
    process.env["OUTPOSTS_WEB_ENABLE_AUTH_DIAGNOSTICS"] = "true";
    const { installOutpostsAuthEventDiagnostics, OUTPOSTS_AUTH_DIAGNOSTICS_WINDOW_KEY } =
      await import("./auth.event-diagnostics");

    const localStorage = createMemoryStorage({
      "outposts.web.auth.confluence": JSON.stringify({
        value: {
          tokens: {
            accessToken: "persisted-at",
            refreshMaterial: "persisted-rt",
            idToken: "persisted-id",
            accessTokenExpiresAt: "2030-01-01T00:00:00.000Z",
          },
        },
      }),
      "outposts.web.auth.invalid": "not-json",
    });
    const sessionStorage = createMemoryStorage();
    const authEvents = {
      subscribe: vi.fn(() => ({ unsubscribe() {} })),
    };
    const registry = {
      authEvents,
      get: vi.fn().mockReturnValue(undefined),
      whenReady: vi.fn().mockResolvedValue({
        client: {
          state: {
            get: () => ({
              tokens: {
                accessToken: "memory-at",
                refreshMaterial: "memory-rt",
                accessTokenExpiresAt: "2031-02-02T00:00:00.000Z",
              },
            }),
          },
        },
      }),
    };

    const browserWindow = {
      location: { search: "?sd-auth-events=1" },
      sessionStorage,
      localStorage,
    } as unknown as Window & {
      [OUTPOSTS_AUTH_DIAGNOSTICS_WINDOW_KEY]?: {
        inspect(): Promise<unknown>;
      };
    };

    installOutpostsAuthEventDiagnostics(browserWindow, registry as never, "confluence");
    await Promise.resolve();

    const diagnostics = browserWindow[OUTPOSTS_AUTH_DIAGNOSTICS_WINDOW_KEY];

    expect(diagnostics).toBeDefined();
    const snapshot = await diagnostics!.inspect();

    expect(snapshot.clientKey).toBe("confluence");
    expect(snapshot.ready).toBe(true);
    expect(snapshot.clientState).toEqual({
      hasAccessToken: true,
      hasRefreshMaterial: true,
      hasIdToken: false,
      accessTokenExpiresAt: "2031-02-02T00:00:00.000Z",
    });
    expect(snapshot.localStorageEntries).toEqual([
      {
        key: "outposts.web.auth.confluence",
        hasAccessToken: true,
        hasRefreshMaterial: true,
        hasIdToken: true,
        accessTokenExpiresAt: "2030-01-01T00:00:00.000Z",
      },
      {
        key: "outposts.web.auth.invalid",
        hasAccessToken: false,
        hasRefreshMaterial: false,
        hasIdToken: false,
        parseError: expect.any(String),
      },
    ]);

    delete process.env["OUTPOSTS_WEB_ENABLE_AUTH_DIAGNOSTICS"];
  });
});
