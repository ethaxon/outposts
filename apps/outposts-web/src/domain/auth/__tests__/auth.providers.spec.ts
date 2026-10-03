import { describe, expect, it, vi } from "vitest";
import { createIdleCallbackForWindow, matchesConfluenceAuthorizedApiUrl } from "../auth.providers";

const API_ENDPOINT = "https://confluence.example.com/api";

describe("matchesConfluenceAuthorizedApiUrl", () => {
  it("matches only the configured API origin and path boundary", () => {
    expect(matchesConfluenceAuthorizedApiUrl(API_ENDPOINT, API_ENDPOINT)).toBe(true);
    expect(matchesConfluenceAuthorizedApiUrl(API_ENDPOINT, `${API_ENDPOINT}/items`)).toBe(true);
    expect(matchesConfluenceAuthorizedApiUrl(API_ENDPOINT, "/api/items")).toBe(true);

    expect(
      matchesConfluenceAuthorizedApiUrl(API_ENDPOINT, "https://third-party.example.com/api/items"),
    ).toBe(false);
    expect(
      matchesConfluenceAuthorizedApiUrl(
        API_ENDPOINT,
        "https://confluence.example.com/api-evil/items",
      ),
    ).toBe(false);
  });

  it("excludes the public config projection endpoint", () => {
    expect(
      matchesConfluenceAuthorizedApiUrl(
        API_ENDPOINT,
        `${API_ENDPOINT}/auth/config?redirect_uri=https%3A%2F%2Fapp.example.com%2Fauth%2Fcallback`,
      ),
    ).toBe(false);
  });

  it("rejects malformed request URLs", () => {
    expect(matchesConfluenceAuthorizedApiUrl(API_ENDPOINT, "http://[invalid")).toBe(false);
  });
});

describe("createIdleCallbackForWindow", () => {
  it("delegates to the native idle scheduler when available", () => {
    const fakeWindow = {
      requestIdleCallback: vi.fn((callback: () => void) => {
        callback();
        return 7;
      }),
      cancelIdleCallback: vi.fn(),
    } as unknown as Window;
    const callback = vi.fn();
    const trait = createIdleCallbackForWindow(fakeWindow);

    const handle = trait.requestIdleCallback(callback);
    trait.cancelIdleCallback(handle);

    expect(callback).toHaveBeenCalledOnce();
    expect(fakeWindow.cancelIdleCallback).toHaveBeenCalledWith(7);
  });

  it("falls back to a timer where requestIdleCallback is missing", () => {
    vi.useFakeTimers();
    try {
      const fakeWindow = {
        setTimeout: (callback: () => void, ms: number) => setTimeout(callback, ms),
        clearTimeout: (handle: number) => clearTimeout(handle),
      } as unknown as Window;
      const trait = createIdleCallbackForWindow(fakeWindow);
      const fired = vi.fn();
      const cancelled = vi.fn();

      trait.requestIdleCallback(fired);
      trait.cancelIdleCallback(trait.requestIdleCallback(cancelled));
      vi.runAllTimers();

      expect(fired).toHaveBeenCalledOnce();
      expect(cancelled).not.toHaveBeenCalled();
    } finally {
      vi.useRealTimers();
    }
  });
});
