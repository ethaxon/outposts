import { TokenSetAuthRegistry } from "@securitydept/token-set-context-client-angular";
import {
  type AuthSnapshot,
  AuthSourceKind,
} from "@securitydept/token-set-context-client/orchestration";
import type { Observable } from "rxjs";
import { firstValueFrom, of } from "rxjs";
import { afterEach, describe, expect, it, vi } from "vitest";
import { AuthClientKey } from "./auth.defs";

// Iteration 150 (outposts adopter calibration):
//
// These tests prove that outposts's API requests are augmented with bearer
// tokens by the @securitydept/token-set-context-client-angular adapter
// (provideTokenSetBearerInterceptor) — and NOT by app-local code that hand-
// writes Authorization headers.
//
// We exercise the SDK interceptor directly with a mock registry shaped the
// same way provideAuth() shapes the real one: keyed by AuthClientKey.Confluence
// with urlPatterns = [CONFLUENCE_API_ENDPOINT]. This isolates the contract
// from the rest of the host bootstrap so the test stays a tight boundary.

const API_ENDPOINT = "https://confluence.example.com/api";

interface FakeReq {
  url: string;
  setHeaders?: Record<string, string>;
}

function makeReq(url: string): FakeReq {
  return {
    url,
    setHeaders: undefined,
  };
}

function makeReqClone(req: FakeReq): {
  url: string;
  clone(update: { setHeaders?: Record<string, string> }): FakeReq;
} {
  return {
    url: req.url,
    clone(update) {
      return { url: req.url, setHeaders: update.setHeaders };
    },
  };
}

function makeSnapshot(token: string): AuthSnapshot {
  return {
    tokens: {
      accessToken: token,
      idToken: "id-test",
      accessTokenExpiresAt: new Date(Date.now() + 3600_000).toISOString(),
    },
    metadata: { source: { kind: AuthSourceKind.OidcAuthorizationCode } },
  };
}

function createMockClient(initial: AuthSnapshot | null = null) {
  let value = initial;
  const listeners = new Set<() => void>();
  return {
    state: {
      get: () => value,
      subscribe(l: () => void) {
        listeners.add(l);
        return () => listeners.delete(l);
      },
    },
    dispose: vi.fn(),
    restorePersistedState: vi.fn().mockResolvedValue(null),
    handleCallback: vi.fn(),
    _set(snap: AuthSnapshot | null) {
      value = snap;
      for (const l of listeners) l();
    },
  };
}

function nextHandler(captured: FakeReq[]): (req: unknown) => Observable<unknown> {
  return (req) => {
    captured.push(req as FakeReq);
    return of({ kind: "response" });
  };
}

let registries: TokenSetAuthRegistry[] = [];

function newRegistry(): TokenSetAuthRegistry {
  const r = new TokenSetAuthRegistry();
  registries.push(r);
  return r;
}

afterEach(() => {
  for (const r of registries) {
    r.dispose();
  }
  registries = [];
});

async function loadInterceptor() {
  // Lazy-import so vitest's module loader does not pull Angular DI surface
  // into the eager test entry; this keeps the spec node-environment clean.
  const mod = await import("@securitydept/token-set-context-client-angular");
  return mod.createTokenSetBearerInterceptor;
}

describe("outposts bearer interceptor — provider-neutral injection", () => {
  it("injects Authorization: Bearer for URLs matching CONFLUENCE_API_ENDPOINT", async () => {
    const create = await loadInterceptor();
    const registry = newRegistry();
    const client = createMockClient(makeSnapshot("tok-confluence"));
    registry.register({
      key: AuthClientKey.Confluence,
      clientFactory: () => client,
      urlPatterns: [API_ENDPOINT],
    });

    const interceptor = create(registry, { strictUrlMatch: true });
    const captured: FakeReq[] = [];
    const req = makeReq(`${API_ENDPOINT}/items`);

    const obs = interceptor(makeReqClone(req), nextHandler(captured));
    await firstValueFrom(obs);

    expect(captured).toHaveLength(1);
    expect(captured[0]?.setHeaders).toEqual({
      Authorization: "Bearer tok-confluence",
    });
  });

  it("does NOT leak bearer to URLs outside CONFLUENCE_API_ENDPOINT prefix", async () => {
    const create = await loadInterceptor();
    const registry = newRegistry();
    const client = createMockClient(makeSnapshot("tok-confluence"));
    registry.register({
      key: AuthClientKey.Confluence,
      clientFactory: () => client,
      urlPatterns: [API_ENDPOINT],
    });

    // Outposts uses strictUrlMatch: true (see auth.providers.ts) precisely so
    // requests to anything other than CONFLUENCE_API_ENDPOINT cannot pick up
    // the registry's only token via the SDK's single-client convenience
    // fallback. This is the security-critical assertion of this spec.
    const interceptor = create(registry, { strictUrlMatch: true });
    const captured: FakeReq[] = [];
    const req = makeReq("https://third-party.example.com/v1/data");

    await firstValueFrom(interceptor(makeReqClone(req), nextHandler(captured)));

    expect(captured).toHaveLength(1);
    expect(captured[0]?.setHeaders).toBeUndefined();
  });

  it("makes NO Authorization header when no token is available", async () => {
    const create = await loadInterceptor();
    const registry = newRegistry();
    const client = createMockClient(null); // no snapshot → accessToken() === null
    registry.register({
      key: AuthClientKey.Confluence,
      clientFactory: () => client,
      urlPatterns: [API_ENDPOINT],
    });

    const interceptor = create(registry, { strictUrlMatch: true });
    const captured: FakeReq[] = [];
    const req = makeReq(`${API_ENDPOINT}/items`);

    await firstValueFrom(interceptor(makeReqClone(req), nextHandler(captured)));

    expect(captured).toHaveLength(1);
    expect(captured[0]?.setHeaders).toBeUndefined();
  });

  it("registry routes URL matching by AuthClientKey.Confluence", async () => {
    const registry = newRegistry();
    registry.register({
      key: AuthClientKey.Confluence,
      clientFactory: () => createMockClient(),
      urlPatterns: [API_ENDPOINT],
    });

    expect(registry.clientKeyForUrl(`${API_ENDPOINT}/items`)).toBe(AuthClientKey.Confluence);
    expect(registry.clientKeyForUrl("https://third-party.example.com/x")).toBeUndefined();
  });

  it("documents SDK default fallback behaviour for non-strict adopters", async () => {
    // Regression guard for the SDK's single-client convenience fallback.
    // When `strictUrlMatch` is omitted, an unmatched URL still receives the
    // first available token. Outposts opts out of this with strictUrlMatch:
    // true; this test documents the SDK behaviour future adopters will see
    // by default and ensures changing that default is a deliberate decision.
    const create = await loadInterceptor();
    const registry = newRegistry();
    const client = createMockClient(makeSnapshot("tok-confluence"));
    registry.register({
      key: AuthClientKey.Confluence,
      clientFactory: () => client,
      urlPatterns: [API_ENDPOINT],
    });

    const interceptor = create(registry); // no options → fallback enabled
    const captured: FakeReq[] = [];
    const req = makeReq("https://third-party.example.com/v1/data");

    await firstValueFrom(interceptor(makeReqClone(req), nextHandler(captured)));

    expect(captured).toHaveLength(1);
    expect(captured[0]?.setHeaders).toEqual({
      Authorization: "Bearer tok-confluence",
    });
  });
});
