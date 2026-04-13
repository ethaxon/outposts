/**
 * Angular dev server middleware — multi-projection config injection.
 *
 * Equivalent to the production bun-injector, but for the dev server.
 * Fetches OIDC config projections from one or more backend services and
 * injects them into HTML responses as a bootstrap script.
 *
 * Usage in project.json:
 *   "serve": {
 *     "executor": "@nx/angular:dev-server",
 *     "options": {
 *       "esbuildMiddleware": ["apps/outposts-web/plugins/dev-inject-middleware.ts"]
 *     }
 *   }
 *
 * Environment variables:
 *   PROJECTION_SOURCES - JSON array of projection source descriptors (required)
 *     Each entry: { "key": string, "endpoint": string, "redirectUri": string }
 *     Example: [{"key":"confluence","endpoint":"http://localhost:8080/api","redirectUri":"http://localhost:4200/auth/callback"}]
 *   DEV_INJECT_INTERVAL_MS - Refresh interval in ms (default: 300000 = 5min)
 */

import type { IncomingMessage, ServerResponse } from "node:http";
import { Buffer } from "node:buffer";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface ProjectionSourceDescriptor {
  key: string;
  endpoint: string;
  redirectUri: string;
}

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

const cachedProjections = new Map<string, unknown>();

const REFRESH_INTERVAL_MS = Number(process.env["DEV_INJECT_INTERVAL_MS"] || "300000");

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

function readSources(): ProjectionSourceDescriptor[] {
  const raw = process.env["PROJECTION_SOURCES"];
  if (!raw) {
    console.warn("[dev-inject] PROJECTION_SOURCES not set, skipping injection");
    return [];
  }
  try {
    const parsed = JSON.parse(raw) as ProjectionSourceDescriptor[];
    if (!Array.isArray(parsed)) return [];
    return parsed.filter((s) => s.key && s.endpoint && s.redirectUri);
  } catch {
    console.warn("[dev-inject] PROJECTION_SOURCES is not valid JSON");
    return [];
  }
}

// ---------------------------------------------------------------------------
// Fetch
// ---------------------------------------------------------------------------

async function fetchProjection(source: ProjectionSourceDescriptor): Promise<unknown> {
  const url = new URL(`${source.endpoint}/auth/config`);
  url.searchParams.set("redirect_uri", source.redirectUri);

  const response = await fetch(url.toString(), {
    headers: { Accept: "application/json" },
  });

  if (!response.ok) {
    throw new Error(`Config projection fetch failed: ${response.status} ${response.statusText}`);
  }

  return response.json() as Promise<unknown>;
}

// ---------------------------------------------------------------------------
// Refresh all sources
// ---------------------------------------------------------------------------

const sources = readSources();

async function refreshAll(): Promise<void> {
  for (const source of sources) {
    try {
      const projection = await fetchProjection(source);
      cachedProjections.set(source.key, projection);
      console.log(`[dev-inject] ${source.key}: refreshed`);
    } catch (error) {
      console.warn(
        `[dev-inject] ${source.key}: failed to fetch: ${error instanceof Error ? error.message : String(error)}`,
      );
    }
  }
}

function buildBootstrapScript(): string {
  if (cachedProjections.size === 0) return "";
  const payload: Record<string, unknown> = {};
  for (const [key, proj] of cachedProjections) {
    payload[key] = proj;
  }
  return `<script>window.__OUTPOSTS_CONFIG__=${JSON.stringify(payload)};</script>`;
}

// Initial fetch on module load
if (sources.length > 0) {
  await refreshAll();
  // Periodic refresh
  setInterval(() => {
    void refreshAll();
  }, REFRESH_INTERVAL_MS);
}

// ---------------------------------------------------------------------------
// Middleware
// ---------------------------------------------------------------------------

/**
 * Connect-style middleware for Angular CLI esbuild dev server.
 *
 * Intercepts HTML responses and injects the bootstrap script before </head>.
 */
export default function devInjectMiddleware(
  req: IncomingMessage,
  res: ServerResponse,
  next: () => void,
): void {
  const accept = req.headers.accept || "";
  if (!accept.includes("text/html")) {
    next();
    return;
  }

  const originalWrite = res.write.bind(res) as ServerResponse["write"];
  const originalEnd = res.end.bind(res) as ServerResponse["end"];
  const chunks: Buffer[] = [];

  res.write = function (chunk: any, ..._args: any[]): boolean {
    if (typeof chunk === "string") {
      chunks.push(Buffer.from(chunk));
    } else if (Buffer.isBuffer(chunk)) {
      chunks.push(chunk);
    }
    return true;
  } as ServerResponse["write"];

  res.end = function (chunk?: any, ..._args: any[]): ServerResponse {
    if (chunk) {
      if (typeof chunk === "string") {
        chunks.push(Buffer.from(chunk));
      } else if (Buffer.isBuffer(chunk)) {
        chunks.push(chunk);
      }
    }

    let body = Buffer.concat(chunks).toString("utf-8");
    const contentType = res.getHeader("content-type");
    const isHtml = typeof contentType === "string" && contentType.includes("text/html");

    if (isHtml && cachedProjections.size > 0) {
      const script = buildBootstrapScript();
      const headCloseIdx = body.indexOf("</head>");
      if (headCloseIdx !== -1) {
        body = body.slice(0, headCloseIdx) + script + body.slice(headCloseIdx);
      }
    }

    res.setHeader("content-length", Buffer.byteLength(body));
    originalWrite(body);
    return originalEnd();
  } as ServerResponse["end"];

  next();
}
