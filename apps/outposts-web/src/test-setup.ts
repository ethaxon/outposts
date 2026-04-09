import { getTestBed, TestBed } from "@angular/core/testing";
import {
  BrowserDynamicTestingModule,
  platformBrowserDynamicTesting,
} from "@angular/platform-browser-dynamic/testing";
import { afterEach, vi } from "vitest";
import "zone.js";

TestBed.initTestEnvironment(BrowserDynamicTestingModule, platformBrowserDynamicTesting());

/**
 * Browser storage stubs for node-based Vitest (OIDC default storage uses
 * session/local storage in some code paths).
 */
function createStorageMock(): Storage {
  const store = new Map<string, string>();
  return {
    get length() {
      return store.size;
    },
    clear: () => {
      store.clear();
    },
    getItem: (key: string) => (store.has(key) ? store.get(key)! : null),
    key: (index: number) => Array.from(store.keys())[index] ?? null,
    removeItem: (key: string) => {
      store.delete(key);
    },
    setItem: (key: string, value: string) => {
      store.set(key, value);
    },
  };
}

if (typeof globalThis.localStorage === "undefined") {
  vi.stubGlobal("localStorage", createStorageMock());
}
if (typeof globalThis.sessionStorage === "undefined") {
  vi.stubGlobal("sessionStorage", createStorageMock());
}

afterEach(() => {
  getTestBed().resetTestingModule();
});
