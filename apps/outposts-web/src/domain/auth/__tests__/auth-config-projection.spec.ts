import { HttpHeaders, HttpResponse } from "@angular/common/http";
import { createFoundationEnvironment } from "@securitydept/client";
import {
  type AngularHttpClientLike,
  createEnvironmentForAngular,
} from "@securitydept/client-angular";
import { injectConfigProjectionIntoRealm } from "@securitydept/token-set-context-client/frontend-oidc-mode";
import { type Observable, of } from "rxjs";
import { describe, expect, it, vi } from "vitest";
import { resolveConfluenceOidcConfigProjection } from "../auth-config-projection";

const API_ENDPOINT = "https://confluence.example.com/api";
const REDIRECT_URI = "https://app.example.com/auth/callback";

const VALID_PROJECTION = {
  wellKnownUrl: "https://auth.example.com/.well-known/openid-configuration",
  issuerUrl: "https://auth.example.com",
  clientId: "outposts-web",
  scopes: ["openid", "profile", "email", "confluence", "offline_access"],
  requiredScopes: ["openid", "profile", "email", "confluence", "offline_access"],
  redirectUrl: REDIRECT_URI,
  pkceEnabled: true,
  generatedAt: Date.now(),
};

function createAngularProjectionEnvironment(body: unknown) {
  const headers = new HttpHeaders({ "content-type": "application/json" });
  const request = vi.fn(
    (): Observable<HttpResponse<string>> =>
      of(
        new HttpResponse({
          status: 200,
          headers,
          body: JSON.stringify(body),
        }),
      ),
  );
  const httpClient: AngularHttpClientLike = { request };
  const environment = createEnvironmentForAngular({
    createBaseEnvironment: createFoundationEnvironment,
    routerForAngularCreateOptions: {
      router: {
        url: "/",
        navigateByUrl: vi.fn(async () => true),
      },
    },
    transportForAngularCreateOptions: { httpClient },
  });

  return { environment, request };
}

describe("resolveConfluenceOidcConfigProjection", () => {
  it("requests the app endpoint through the supplied Angular environment", async () => {
    const { environment, request } = createAngularProjectionEnvironment(VALID_PROJECTION);
    const config = await resolveConfluenceOidcConfigProjection({
      environment,
      clientKey: "confluence",
      apiEndpoint: API_ENDPOINT,
      redirectUri: REDIRECT_URI,
    });

    expect(config).toMatchObject({
      issuer: "https://auth.example.com",
      clientId: "outposts-web",
      redirectUri: REDIRECT_URI,
      defaultPostAuthRedirectUri: "/",
    });
    expect(request).toHaveBeenCalledWith(
      "GET",
      `${API_ENDPOINT}/auth/config?redirect_uri=${encodeURIComponent(REDIRECT_URI)}`,
      {
        headers: { accept: "application/json" },
        observe: "response",
        responseType: "text",
      },
    );
  });

  it("prefers the server-injected realm over the network source", async () => {
    const { environment, request } = createAngularProjectionEnvironment(VALID_PROJECTION);
    const realmKey = Symbol.for("securitydept.frontend_oidc.config_projection:v1:confluence");
    injectConfigProjectionIntoRealm({
      clientKey: "confluence",
      projection: { ...VALID_PROJECTION, clientId: "realm-client" },
    });

    try {
      const config = await resolveConfluenceOidcConfigProjection({
        environment,
        clientKey: "confluence",
        apiEndpoint: API_ENDPOINT,
        redirectUri: REDIRECT_URI,
      });

      expect(config.clientId).toBe("realm-client");
      expect(request).not.toHaveBeenCalled();
    } finally {
      Reflect.deleteProperty(globalThis, realmKey);
    }
  });

  it("applies the app-owned post-auth redirect override", async () => {
    const { environment } = createAngularProjectionEnvironment(VALID_PROJECTION);
    const config = await resolveConfluenceOidcConfigProjection({
      environment,
      clientKey: "confluence",
      apiEndpoint: API_ENDPOINT,
      redirectUri: REDIRECT_URI,
      defaultPostAuthRedirectUri: "/workspace",
    });

    expect(config.defaultPostAuthRedirectUri).toBe("/workspace");
  });
});
