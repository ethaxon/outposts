import { describe, expect, it } from "vitest";
import { windowProvider } from "./window";
import { createMockBrowserWindow, createMockDocumentWithDefaultView } from "./window.testing";

describe("windowProvider", () => {
  it("returns the same reference as document.defaultView from injected DOCUMENT", () => {
    const win = createMockBrowserWindow("https://app.example");
    const doc = createMockDocumentWithDefaultView(win);
    expect(windowProvider(doc)).toBe(win);
  });

  it("returns null when the document has no defaultView", () => {
    const doc = createMockDocumentWithDefaultView(null);
    expect(windowProvider(doc)).toBeNull();
  });
});
