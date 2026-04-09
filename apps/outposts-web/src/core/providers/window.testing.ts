/**
 * Test doubles for {@link DOCUMENT} / {@link WINDOW} so specs never rely on
 * global `document` or `window`.
 */

/** Minimal `Window` with `location` used by `resolveAppOriginFromWindow`. */
export function createMockBrowserWindow(origin: string): Window {
  const protocol = origin.startsWith("https") ? "https:" : "http:";
  return { location: { origin, protocol } } as Window;
}

/** Minimal `Document` exposing only `defaultView` (matches `windowProvider`). */
export function createMockDocumentWithDefaultView(defaultView: Window | null): Document {
  return { defaultView } as Document;
}
