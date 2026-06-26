import { describe, expect, it } from "vitest";
import { matchesConfluenceAuthorizedApiUrl } from "../auth.providers";

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
