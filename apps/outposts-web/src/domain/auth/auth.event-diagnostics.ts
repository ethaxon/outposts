import type { EventStreamTrait } from "@securitydept/client";
import type { TokenSetAuthRegistry } from "@securitydept/token-set-context-client-angular";
import { environment } from "@/environments/environment";

export const OUTPOSTS_AUTH_DIAGNOSTICS_QUERY_PARAM = "sd-auth-events";
export const OUTPOSTS_AUTH_DIAGNOSTICS_SESSION_FLAG = "outposts.auth.debug.events";
export const OUTPOSTS_AUTH_DIAGNOSTICS_WINDOW_KEY = "__OUTPOSTS_AUTH_DIAGNOSTICS__";

const OUTPOSTS_AUTH_DIAGNOSTIC_EVENT_LIMIT = 200;

interface DiagnosticTokenSetAuthErrorSummary {
  message?: string;
  errorKind?: string;
  errorCode?: string;
  recovery?: string;
}

interface DiagnosticTokenSetAuthEvent {
  id: string;
  type: string;
  at: number;
  payload: {
    source?: string;
    clientKey?: string;
    requirementKind?: string;
    providerFamily?: string;
    freshness?: string;
    hasRefreshMaterial?: boolean;
    reason?: string;
    outcome?: string;
    refreshBarrierId?: string;
    errorSummary?: DiagnosticTokenSetAuthErrorSummary;
  };
}

export interface OutpostsAuthDiagnosticEvent {
  id: string;
  type: string;
  at: number;
  source?: string;
  clientKey?: string;
  requirementKind?: string;
  providerFamily?: string;
  freshness?: string;
  hasRefreshMaterial?: boolean;
  reason?: string;
  outcome?: string;
  refreshBarrierId?: string;
  errorSummary?: DiagnosticTokenSetAuthErrorSummary;
}

export interface OutpostsAuthDiagnosticsState {
  readonly enabled: true;
  readonly events: OutpostsAuthDiagnosticEvent[];
  attachAttempts: number;
  subscriptionSource: "registry" | "service" | null;
  lastAttachError?: string;
  clear(): void;
  inspect(): Promise<OutpostsAuthDiagnosticsSnapshot>;
}

export interface OutpostsAuthSnapshotSummary {
  hasAccessToken: boolean;
  hasRefreshMaterial: boolean;
  hasIdToken: boolean;
  accessTokenExpiresAt?: string;
}

export interface OutpostsAuthStorageEntrySummary extends OutpostsAuthSnapshotSummary {
  key: string;
  parseError?: string;
}

export interface OutpostsAuthDiagnosticsSnapshot {
  clientKey: string;
  ready: boolean;
  clientState: OutpostsAuthSnapshotSummary | null;
  localStorageEntries: OutpostsAuthStorageEntrySummary[];
  attachAttempts: number;
  subscriptionSource: "registry" | "service" | null;
  lastAttachError?: string;
}

type StorageLike = Pick<Storage, "length" | "key" | "getItem">;

type OutpostsDiagnosticsWindow = Window & {
  [OUTPOSTS_AUTH_DIAGNOSTICS_WINDOW_KEY]?: OutpostsAuthDiagnosticsState;
};

export function installOutpostsAuthEventDiagnostics(
  browserWindow: Window,
  registry: TokenSetAuthRegistry,
  clientKey: string,
): void {
  if (!shouldEnableOutpostsAuthDiagnostics(browserWindow)) {
    return;
  }

  const diagnosticsWindow = browserWindow as OutpostsDiagnosticsWindow;
  if (diagnosticsWindow[OUTPOSTS_AUTH_DIAGNOSTICS_WINDOW_KEY]) {
    return;
  }

  const events: OutpostsAuthDiagnosticEvent[] = [];
  const diagnosticsState: OutpostsAuthDiagnosticsState = {
    enabled: true,
    events,
    attachAttempts: 0,
    subscriptionSource: null,
    lastAttachError: undefined,
    clear() {
      events.length = 0;
    },
    async inspect() {
      return await inspectDiagnosticsState(browserWindow, registry, clientKey, diagnosticsState);
    },
  };
  diagnosticsWindow[OUTPOSTS_AUTH_DIAGNOSTICS_WINDOW_KEY] = diagnosticsState;

  queueMicrotask(() => {
    attachDiagnosticsStream(registry, clientKey, diagnosticsState);
  });
}

function sanitizeAuthEvent(event: DiagnosticTokenSetAuthEvent): OutpostsAuthDiagnosticEvent {
  return {
    id: event.id,
    type: event.type,
    at: event.at,
    source: event.payload.source,
    clientKey: event.payload.clientKey,
    requirementKind: event.payload.requirementKind,
    providerFamily: event.payload.providerFamily,
    freshness: event.payload.freshness,
    hasRefreshMaterial: event.payload.hasRefreshMaterial,
    reason: event.payload.reason,
    outcome: event.payload.outcome,
    refreshBarrierId: event.payload.refreshBarrierId,
    errorSummary: sanitizeErrorSummary(event.payload.errorSummary),
  };
}

function resolveRegistryAuthEvents(
  registry: TokenSetAuthRegistry,
): EventStreamTrait<DiagnosticTokenSetAuthEvent> | undefined {
  const maybeRegistry = registry as TokenSetAuthRegistry & {
    authEvents?: EventStreamTrait<DiagnosticTokenSetAuthEvent>;
    core?: { authEvents?: EventStreamTrait<DiagnosticTokenSetAuthEvent> };
  };

  return maybeRegistry.authEvents ?? maybeRegistry.core?.authEvents;
}

function subscribeToAuthEvents(
  stream: EventStreamTrait<DiagnosticTokenSetAuthEvent>,
  events: OutpostsAuthDiagnosticEvent[],
): void {
  stream.subscribe({
    next: (event: DiagnosticTokenSetAuthEvent) => {
      events.push(sanitizeAuthEvent(event));
      if (events.length > OUTPOSTS_AUTH_DIAGNOSTIC_EVENT_LIMIT) {
        events.splice(0, events.length - OUTPOSTS_AUTH_DIAGNOSTIC_EVENT_LIMIT);
      }
    },
  });
}

function attachDiagnosticsStream(
  registry: TokenSetAuthRegistry,
  clientKey: string,
  diagnosticsState: OutpostsAuthDiagnosticsState,
  remainingRetries = 10,
): void {
  if (diagnosticsState.subscriptionSource !== null) {
    return;
  }

  diagnosticsState.attachAttempts += 1;

  const authEvents = resolveRegistryAuthEvents(registry);
  if (authEvents) {
    diagnosticsState.subscriptionSource = "registry";
    diagnosticsState.lastAttachError = undefined;
    subscribeToAuthEvents(authEvents, diagnosticsState.events);
    return;
  }

  void registry
    .whenReady(clientKey)
    .then((service) => {
      const serviceRecord = service as {
        authEvents?: EventStreamTrait<DiagnosticTokenSetAuthEvent>;
        client?: { authEvents?: EventStreamTrait<DiagnosticTokenSetAuthEvent> };
      };
      const serviceEvents = serviceRecord.authEvents ?? serviceRecord.client?.authEvents;
      if (serviceEvents) {
        diagnosticsState.subscriptionSource = "service";
        diagnosticsState.lastAttachError = undefined;
        subscribeToAuthEvents(serviceEvents, diagnosticsState.events);
        return;
      }

      diagnosticsState.lastAttachError = `missing authEvents on service: ${Object.keys(
        service as object,
      ).join(",")}`;

      if (remainingRetries > 0) {
        setTimeout(() => {
          attachDiagnosticsStream(registry, clientKey, diagnosticsState, remainingRetries - 1);
        }, 0);
      }
    })
    .catch((error: unknown) => {
      diagnosticsState.lastAttachError = error instanceof Error ? error.message : String(error);
      if (remainingRetries > 0) {
        setTimeout(() => {
          attachDiagnosticsStream(registry, clientKey, diagnosticsState, remainingRetries - 1);
        }, 0);
      }
    });
}

function sanitizeErrorSummary(
  summary: DiagnosticTokenSetAuthErrorSummary | undefined,
): DiagnosticTokenSetAuthErrorSummary | undefined {
  if (!summary) {
    return undefined;
  }

  return {
    message: summary.message,
    errorKind: summary.errorKind,
    errorCode: summary.errorCode,
    recovery: summary.recovery,
  };
}

async function inspectDiagnosticsState(
  browserWindow: Window,
  registry: TokenSetAuthRegistry,
  clientKey: string,
  diagnosticsState: OutpostsAuthDiagnosticsState,
): Promise<OutpostsAuthDiagnosticsSnapshot> {
  const service = await resolveDiagnosticService(registry, clientKey);
  return {
    clientKey,
    ready: service !== null,
    clientState: summarizeSnapshot(readServiceSnapshot(service)),
    localStorageEntries: summarizeStorageEntries(browserWindow.localStorage, "outposts.web.auth."),
    attachAttempts: diagnosticsState.attachAttempts,
    subscriptionSource: diagnosticsState.subscriptionSource,
    lastAttachError: diagnosticsState.lastAttachError,
  };
}

async function resolveDiagnosticService(
  registry: TokenSetAuthRegistry,
  clientKey: string,
): Promise<unknown | null> {
  const registryRecord = registry as TokenSetAuthRegistry & {
    get?: (key: string) => unknown;
    whenReady?: (key: string) => Promise<unknown>;
  };

  const current = registryRecord.get?.(clientKey);
  if (current) {
    return current;
  }

  if (!registryRecord.whenReady) {
    return null;
  }

  try {
    return await registryRecord.whenReady(clientKey);
  } catch {
    return null;
  }
}

function readServiceSnapshot(service: unknown): unknown {
  if (!service || typeof service !== "object") {
    return null;
  }

  const serviceRecord = service as {
    client?: {
      state?: {
        get?: () => unknown;
      };
    };
    authState?: () => unknown;
  };

  if (typeof serviceRecord.client?.state?.get === "function") {
    return serviceRecord.client.state.get();
  }
  if (typeof serviceRecord.authState === "function") {
    return serviceRecord.authState();
  }
  return null;
}

function summarizeStorageEntries(
  storage: StorageLike | undefined,
  prefix: string,
): OutpostsAuthStorageEntrySummary[] {
  if (!storage) {
    return [];
  }

  const entries: OutpostsAuthStorageEntrySummary[] = [];
  for (let index = 0; index < storage.length; index += 1) {
    const key = storage.key(index);
    if (!key || !key.startsWith(prefix)) {
      continue;
    }

    const raw = storage.getItem(key);
    if (raw === null) {
      continue;
    }

    try {
      const parsed = JSON.parse(raw) as { value?: unknown; tokens?: unknown };
      const tokens = readSnapshotTokens(parsed.value ?? parsed);
      entries.push({
        key,
        ...summarizeTokens(tokens),
      });
    } catch (error) {
      entries.push({
        key,
        hasAccessToken: false,
        hasRefreshMaterial: false,
        hasIdToken: false,
        parseError: error instanceof Error ? error.message : String(error),
      });
    }
  }

  return entries.sort((left, right) => left.key.localeCompare(right.key));
}

function summarizeSnapshot(snapshot: unknown): OutpostsAuthSnapshotSummary | null {
  const tokens = readSnapshotTokens(snapshot);
  if (!tokens) {
    return null;
  }
  return summarizeTokens(tokens);
}

function readSnapshotTokens(snapshot: unknown): {
  accessToken?: unknown;
  refreshMaterial?: unknown;
  idToken?: unknown;
  accessTokenExpiresAt?: unknown;
} | null {
  if (!snapshot || typeof snapshot !== "object") {
    return null;
  }

  const record = snapshot as {
    tokens?: {
      accessToken?: unknown;
      refreshMaterial?: unknown;
      idToken?: unknown;
      accessTokenExpiresAt?: unknown;
    };
  };

  return record.tokens ?? null;
}

function summarizeTokens(
  tokens: {
    accessToken?: unknown;
    refreshMaterial?: unknown;
    idToken?: unknown;
    accessTokenExpiresAt?: unknown;
  } | null,
): OutpostsAuthSnapshotSummary {
  return {
    hasAccessToken: typeof tokens?.accessToken === "string" && tokens.accessToken.length > 0,
    hasRefreshMaterial:
      typeof tokens?.refreshMaterial === "string" && tokens.refreshMaterial.length > 0,
    hasIdToken: typeof tokens?.idToken === "string" && tokens.idToken.length > 0,
    accessTokenExpiresAt:
      typeof tokens?.accessTokenExpiresAt === "string" ? tokens.accessTokenExpiresAt : undefined,
  };
}

function shouldEnableOutpostsAuthDiagnostics(browserWindow: Window): boolean {
  if (!environment.production) {
    return true;
  }

  if (environment.production && !environment.ENABLE_AUTH_DIAGNOSTICS) {
    return false;
  }

  const search = browserWindow.location?.search ?? "";
  const queryEnabled =
    new URLSearchParams(search).get(OUTPOSTS_AUTH_DIAGNOSTICS_QUERY_PARAM) === "1";

  if (queryEnabled) {
    try {
      browserWindow.sessionStorage?.setItem(OUTPOSTS_AUTH_DIAGNOSTICS_SESSION_FLAG, "1");
    } catch {
      // Ignore storage failures; diagnostics stay enabled for this load.
    }
    return true;
  }

  try {
    return browserWindow.sessionStorage?.getItem(OUTPOSTS_AUTH_DIAGNOSTICS_SESSION_FLAG) === "1";
  } catch {
    return false;
  }
}
