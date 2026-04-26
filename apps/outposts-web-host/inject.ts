/**
 * Projection config injector for outposts-web production host.
 *
 * Periodically fetches OIDC config projections from one or more backend
 * services via HTTP, then injects them into the Angular index.html as a
 * bootstrap script. The injected HTML is written to a shared volume
 * that nginx serves to browsers.
 *
 * Architecture:
 *   bun-injector (this script) ←HTTP→ backend API servers
 *   bun-injector →writes→ /shared/index.html
 *   nginx ←reads→ /shared/index.html → browser
 *
 * Runtime isolation:
 *   All host-specific I/O (file read/write, env, timers, logging) goes
 *   through the HostPort interface. The startup code selects Bun or Node.js
 *   at runtime.
 *
 * Environment variables:
 *   PROJECTION_SOURCES       - JSON array of projection source descriptors (preferred)
 *                              Each entry: { "key": string, "endpoint": string, "redirectUri": string }
 *                              Example: [{"key":"confluence","endpoint":"http://confluence:8080/api","redirectUri":"https://app/callback"}]
 *                              When absent, outposts falls back to the built-in
 *                              single-source confluence topology.
 *   INJECT_INTERVAL_MS       - Refresh interval in ms (default: 300000 = 5min)
 *   MAX_FAILURES             - Max consecutive failures before clearing cache (default: 3)
 *   TEMPLATE_PATH            - Path to the original index.html (default: /app/index.html)
 *   OUTPUT_PATH              - Path to write injected index.html (default: /shared/index.html)
 */
// ---------------------------------------------------------------------------
// Host port — minimal interface for runtime-specific capabilities
// ---------------------------------------------------------------------------

interface HostPort {
  /** Read a text file. */
  readFile(path: string): Promise<string>;
  /** Write a text file. */
  writeFile(path: string, content: string): Promise<void>;
  /** Get environment variable value. */
  env(key: string): string | undefined;
  /** Fetch JSON from a URL. */
  fetchJson(url: string): Promise<unknown>;
  /** Schedule a repeating callback. Returns a cancel function. */
  setInterval(fn: () => void, ms: number): () => void;
  /** Log at info level. */
  logInfo(msg: string): void;
  /** Log at warn level. */
  logWarn(msg: string): void;
  /** Log at error level. */
  logError(msg: string): void;
  /** Exit process with code. */
  exit(code: number): never;
}

// ---------------------------------------------------------------------------
// Bun adapter
// ---------------------------------------------------------------------------

function createBunHostPort(): HostPort {
  const BunApi = (globalThis as Record<string, unknown>).Bun as {
    file(path: string): { text(): Promise<string> };
    write(path: string, content: string): Promise<void>;
  };

  return {
    readFile: (path) => BunApi.file(path).text(),
    writeFile: (path, content) => BunApi.write(path, content),
    env: (key) => process.env[key],
    fetchJson: async (url) => {
      const response = await fetch(url, {
        headers: { Accept: "application/json" },
      });
      if (!response.ok) {
        throw new Error(`Fetch failed: ${response.status} ${response.statusText}`);
      }
      return response.json();
    },
    setInterval: (fn, ms) => {
      const id = setInterval(fn, ms);
      return () => clearInterval(id);
    },
    logInfo: (msg) => console.log(msg),
    logWarn: (msg) => console.warn(msg),
    logError: (msg) => console.error(msg),
    exit: (code) => process.exit(code),
  };
}

// ---------------------------------------------------------------------------
// Node.js adapter
// ---------------------------------------------------------------------------

function createNodeHostPort(): HostPort {
  return {
    readFile: async (path) => {
      const fs = await import("node:fs/promises");
      return fs.readFile(path, "utf-8");
    },
    writeFile: async (path, content) => {
      const fs = await import("node:fs/promises");
      await fs.writeFile(path, content, "utf-8");
    },
    env: (key) => process.env[key],
    fetchJson: async (url) => {
      const response = await fetch(url, {
        headers: { Accept: "application/json" },
      });
      if (!response.ok) {
        throw new Error(`Fetch failed: ${response.status} ${response.statusText}`);
      }
      return response.json();
    },
    setInterval: (fn, ms) => {
      const id = setInterval(fn, ms);
      return () => clearInterval(id);
    },
    logInfo: (msg) => console.log(msg),
    logWarn: (msg) => console.warn(msg),
    logError: (msg) => console.error(msg),
    exit: (code) => process.exit(code),
  };
}

function createHostPort(): HostPort {
  if ("Bun" in globalThis) {
    return createBunHostPort();
  }
  if (typeof process !== "undefined" && process.versions?.node) {
    return createNodeHostPort();
  }
  throw new Error("[injector] Unsupported runtime: expected Bun or Node.js");
}

// ---------------------------------------------------------------------------
// Projection source descriptor
// ---------------------------------------------------------------------------

/** A single projection endpoint to fetch and inject. */
interface ProjectionSourceDescriptor {
  /** Key under which the projection is placed in the global payload (e.g. "confluence"). */
  key: string;
  /** Backend API base URL (e.g. "http://confluence:8080/api"). */
  endpoint: string;
  /** OIDC callback redirect URI (e.g. "https://app.example.com/auth/callback"). */
  redirectUri: string;
}

// ---------------------------------------------------------------------------
// Injector config
// ---------------------------------------------------------------------------

interface InjectorConfig {
  sources: ProjectionSourceDescriptor[];
  intervalMs: number;
  maxFailures: number;
  templatePath: string;
  outputPath: string;
}

function defaultSources(host: HostPort): ProjectionSourceDescriptor[] | null {
  const outpostsWebHost = host.env("OUTPOSTS_WEB_HOST");
  if (!outpostsWebHost) {
    return null;
  }

  return [
    {
      key: "confluence",
      endpoint: "http://confluence:4001/api",
      redirectUri: `https://${outpostsWebHost}/auth/callback`,
    },
  ];
}

function readConfig(host: HostPort): InjectorConfig {
  const sourcesJson = host.env("PROJECTION_SOURCES");

  let sources: ProjectionSourceDescriptor[];
  if (sourcesJson) {
    try {
      sources = JSON.parse(sourcesJson) as ProjectionSourceDescriptor[];
    } catch {
      host.logError("[injector] PROJECTION_SOURCES must be valid JSON");
      host.exit(1);
    }
  } else {
    const fallbackSources = defaultSources(host);
    if (!fallbackSources) {
      host.logError(
        "[injector] PROJECTION_SOURCES is required unless OUTPOSTS_WEB_HOST is set for the built-in confluence fallback",
      );
      host.exit(1);
    }
    sources = fallbackSources;
  }

  if (!Array.isArray(sources) || sources.length === 0) {
    host.logError("[injector] PROJECTION_SOURCES must be a non-empty array");
    host.exit(1);
  }

  for (const s of sources) {
    if (!s.key || !s.endpoint || !s.redirectUri) {
      host.logError(
        `[injector] Each PROJECTION_SOURCES entry must have key, endpoint, and redirectUri. Got: ${JSON.stringify(s)}`,
      );
      host.exit(1);
    }
  }

  return {
    sources,
    intervalMs: Number(host.env("INJECT_INTERVAL_MS") || "300000"),
    maxFailures: Number(host.env("MAX_FAILURES") || "3"),
    templatePath: host.env("TEMPLATE_PATH") || "/app/index.html",
    outputPath: host.env("OUTPUT_PATH") || "/shared/index.html",
  };
}

// ---------------------------------------------------------------------------
// Fetch projection from a single source
// ---------------------------------------------------------------------------

async function fetchProjection(
  host: HostPort,
  source: ProjectionSourceDescriptor,
): Promise<unknown> {
  const url = new URL(`${source.endpoint}/auth/config`);
  url.searchParams.set("redirect_uri", source.redirectUri);
  return host.fetchJson(url.toString());
}

/**
 * Extract the authoritative `generatedAt` from the projection payload.
 * Falls back to 0 if the field is missing (legacy backend).
 */
function extractGeneratedAt(projection: unknown): number {
  if (
    typeof projection === "object" &&
    projection !== null &&
    "generatedAt" in projection &&
    typeof (projection as Record<string, unknown>).generatedAt === "number"
  ) {
    return (projection as Record<string, unknown>).generatedAt as number;
  }
  return 0;
}

// ---------------------------------------------------------------------------
// Inject bootstrap script into HTML
// ---------------------------------------------------------------------------

/**
 * Build the injected payload from all successfully fetched projections.
 *
 * Payload shape:
 *   window.__OUTPOSTS_CONFIG__ = {
 *     confluence: { ...projectionA },
 *     otherService: { ...projectionB },
 *   };
 *
 * Each key corresponds to a `ProjectionSourceDescriptor.key`.
 * The `generatedAt` is embedded in each projection itself.
 */
function injectBootstrapScript(
  html: string,
  projections: Record<string, unknown>,
): string {
  if (Object.keys(projections).length === 0) return html;

  const payload = JSON.stringify(projections);
  const script = `<script>window.__OUTPOSTS_CONFIG__=${payload};</script>`;

  const headCloseIndex = html.indexOf("</head>");
  if (headCloseIndex === -1) {
    return script + html;
  }
  return html.slice(0, headCloseIndex) + script + html.slice(headCloseIndex);
}

// ---------------------------------------------------------------------------
// Write output
// ---------------------------------------------------------------------------

async function writeOutput(
  host: HostPort,
  config: InjectorConfig,
  projections: Record<string, unknown>,
): Promise<void> {
  const template = await host.readFile(config.templatePath);
  const output = Object.keys(projections).length > 0
    ? injectBootstrapScript(template, projections)
    : template;
  await host.writeFile(config.outputPath, output);
}

// ---------------------------------------------------------------------------
// Main refresh cycle
// ---------------------------------------------------------------------------

async function createRefreshCycle(
  host: HostPort,
  config: InjectorConfig,
): Promise<void> {
  /** Per-source failure counters. */
  const failureCounts = new Map<string, number>();
  /** Last successfully fetched projections. */
  const cachedProjections = new Map<string, unknown>();

  const refresh = async (): Promise<void> => {
    for (const source of config.sources) {
      try {
        const projection = await fetchProjection(host, source);
        cachedProjections.set(source.key, projection);
        failureCounts.set(source.key, 0);

        const generatedAt = extractGeneratedAt(projection);
        host.logInfo(
          `[injector] ${source.key}: refreshed (generatedAt: ${new Date(generatedAt).toISOString()})`,
        );
      } catch (error) {
        const count = (failureCounts.get(source.key) ?? 0) + 1;
        failureCounts.set(source.key, count);
        const msg = error instanceof Error ? error.message : String(error);

        if (count <= config.maxFailures) {
          host.logWarn(
            `[injector] ${source.key}: fetch failed (${count}/${config.maxFailures}), retaining cache: ${msg}`,
          );
        } else {
          host.logError(
            `[injector] ${source.key}: fetch failed (${count}/${config.maxFailures}), clearing cache: ${msg}`,
          );
          cachedProjections.delete(source.key);
        }
      }
    }

    // Build composite payload from all cached projections
    const payload: Record<string, unknown> = {};
    for (const [key, proj] of cachedProjections) {
      payload[key] = proj;
    }
    await writeOutput(host, config, payload);
  };

  // Initial fetch
  await refresh();

  // Periodic refresh
  host.setInterval(() => {
    void refresh();
  }, config.intervalMs);
}

// ---------------------------------------------------------------------------
// Startup
// ---------------------------------------------------------------------------

const host = createHostPort();
const config = readConfig(host);

host.logInfo(`[injector] Starting with ${config.sources.length} projection source(s):`);
for (const s of config.sources) {
  host.logInfo(`  ${s.key}: ${s.endpoint} (redirectUri: ${s.redirectUri})`);
}
host.logInfo(`  INJECT_INTERVAL_MS: ${config.intervalMs}`);
host.logInfo(`  MAX_FAILURES: ${config.maxFailures}`);
host.logInfo(`  TEMPLATE_PATH: ${config.templatePath}`);
host.logInfo(`  OUTPUT_PATH: ${config.outputPath}`);

await createRefreshCycle(host, config);

export type { HostPort, InjectorConfig, ProjectionSourceDescriptor };
