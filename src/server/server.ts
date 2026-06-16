import {
  createServer as createHttpServer,
  type IncomingMessage,
  type Server,
  type ServerResponse,
} from "node:http";
import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { loadConfig } from "../config.js";
import type { AnalyserConfig, AnalyserRequest } from "../types.js";
import { buildProvider } from "../llm/factory.js";
import { DetectionAnalyser } from "../services/detection_analyser.js";
import { AuditLog } from "../services/audit_log.js";
import { AzureTokenProvider } from "../tools/azure_auth.js";
import { LogAnalyticsClient } from "../tools/log_analytics_client.js";
import { SentinelClient } from "../tools/sentinel_client.js";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface AnalyserSinks {
  onText: (text: string) => void;
  onThinking: (text: string) => void;
  onToolCall: (name: string, input: unknown) => void;
}

/** Builds the per-request analyser. Overridable for tests so no network/SDK is touched. */
export type AnalyserFactory = (config: AnalyserConfig, sinks: AnalyserSinks) => DetectionAnalyser;

export interface ServerOptions {
  host?: string;
  port?: number;
  /** Base config; defaults to loadConfig(process.env). Per-request overrides are layered on top. */
  baseConfig?: AnalyserConfig;
  analyserFactory?: AnalyserFactory;
  /** Static asset directory; defaults to the bundled public/ folder. */
  publicDir?: string;
  /** Environment used to detect which providers have credentials. Defaults to process.env. */
  env?: NodeJS.ProcessEnv;
}

interface AnalysePayload {
  request: AnalyserRequest;
  overrides?: { provider?: string; effort?: string };
}

const MAX_BODY_BYTES = 1_000_000;
const CONTENT_TYPES: Record<string, string> = {
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".svg": "image/svg+xml",
  ".ico": "image/x-icon",
};
const EFFORTS = new Set(["low", "medium", "high", "xhigh", "max"]);
const PROVIDERS = new Set(["anthropic", "openai", "azure"]);

// ---------------------------------------------------------------------------
// Default analyser wiring (mirrors the CLI)
// ---------------------------------------------------------------------------

function defaultAnalyserFactory(config: AnalyserConfig, sinks: AnalyserSinks): DetectionAnalyser {
  const tokenProvider = new AzureTokenProvider();
  return new DetectionAnalyser({
    provider: buildProvider(config),
    logAnalytics: new LogAnalyticsClient({ tokenProvider, endpoint: config.logAnalyticsEndpoint }),
    sentinel: new SentinelClient({ tokenProvider, armEndpoint: config.armEndpoint }),
    auditLog: new AuditLog(config.auditLogPath),
    config,
    onText: sinks.onText,
    onThinking: sinks.onThinking,
    onToolCall: sinks.onToolCall,
  });
}

/** Which providers have credentials configured (booleans only — never the keys). */
function providerAvailability(env: NodeJS.ProcessEnv): Record<string, boolean> {
  return {
    anthropic: Boolean(env.ANTHROPIC_API_KEY || env.ANTHROPIC_AUTH_TOKEN),
    openai: Boolean(env.OPENAI_API_KEY),
    azure: Boolean(env.AZURE_OPENAI_ENDPOINT),
  };
}

/** Non-secret subset of config, safe to expose to the browser. */
function publicConfig(config: AnalyserConfig, env: NodeJS.ProcessEnv): Record<string, unknown> {
  return {
    provider: config.provider,
    anthropicModel: config.anthropicModel,
    openaiModel: config.openaiModel,
    azureDeployment: config.azureDeployment ?? null,
    effort: config.effort,
    allowDeploy: config.allowDeploy,
    logAnalyticsEndpoint: config.logAnalyticsEndpoint,
    armEndpoint: config.armEndpoint,
    // booleans only — the keys themselves are never exposed.
    available: providerAvailability(env),
  };
}

function withOverrides(base: AnalyserConfig, overrides?: AnalysePayload["overrides"]): AnalyserConfig {
  const out: AnalyserConfig = { ...base };
  if (overrides?.provider && PROVIDERS.has(overrides.provider)) {
    out.provider = overrides.provider as AnalyserConfig["provider"];
  }
  if (overrides?.effort && EFFORTS.has(overrides.effort)) {
    out.effort = overrides.effort as AnalyserConfig["effort"];
  }
  // Deployment is never enabled via the web UI, regardless of base config.
  out.allowDeploy = false;
  return out;
}

// ---------------------------------------------------------------------------
// Server
// ---------------------------------------------------------------------------

export function createSentretServer(opts: ServerOptions = {}): Server {
  const env = opts.env ?? process.env;
  const baseConfig = opts.baseConfig ?? loadConfig(env);
  const factory = opts.analyserFactory ?? defaultAnalyserFactory;
  const publicDir = opts.publicDir ?? fileURLToPath(new URL("./public/", import.meta.url));

  return createHttpServer((req, res) => {
    handle(req, res, { baseConfig, factory, publicDir, env }).catch((error: unknown) => {
      if (!res.headersSent) {
        res.writeHead(500, { "Content-Type": "application/json" });
      }
      if (!res.writableEnded) {
        res.end(JSON.stringify({ error: error instanceof Error ? error.message : String(error) }));
      }
    });
  });
}

export function startServer(opts: ServerOptions = {}): Promise<Server> {
  const host = opts.host ?? process.env.SENTRET_WEB_HOST ?? "127.0.0.1";
  const port = Number(opts.port ?? process.env.SENTRET_WEB_PORT ?? 8787);
  const server = createSentretServer(opts);
  return new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(port, host, () => {
      server.off("error", reject);
      resolve(server);
    });
  });
}

interface HandlerCtx {
  baseConfig: AnalyserConfig;
  factory: AnalyserFactory;
  publicDir: string;
  env: NodeJS.ProcessEnv;
}

async function handle(req: IncomingMessage, res: ServerResponse, ctx: HandlerCtx): Promise<void> {
  const url = new URL(req.url ?? "/", "http://localhost");
  const pathname = url.pathname;

  if (req.method === "GET" && pathname === "/api/health") {
    return sendJson(res, 200, { status: "ok" });
  }
  if (req.method === "GET" && pathname === "/api/config") {
    return sendJson(res, 200, publicConfig(ctx.baseConfig, ctx.env));
  }
  if (req.method === "POST" && pathname === "/api/analyse") {
    return handleAnalyse(req, res, ctx);
  }
  if (req.method === "GET") {
    return serveStatic(pathname === "/" ? "/index.html" : pathname, res, ctx.publicDir);
  }
  return sendJson(res, 404, { error: "Not found" });
}

async function handleAnalyse(req: IncomingMessage, res: ServerResponse, ctx: HandlerCtx): Promise<void> {
  let payload: AnalysePayload;
  try {
    const raw = await readBody(req, MAX_BODY_BYTES);
    payload = JSON.parse(raw) as AnalysePayload;
  } catch (error) {
    return sendJson(res, 400, {
      error: `Invalid request body: ${error instanceof Error ? error.message : String(error)}`,
    });
  }
  if (!payload || typeof payload !== "object" || typeof payload.request !== "object") {
    return sendJson(res, 400, { error: "Body must be { request, overrides? }." });
  }

  res.writeHead(200, {
    "Content-Type": "text/event-stream; charset=utf-8",
    "Cache-Control": "no-cache, no-transform",
    Connection: "keep-alive",
    "X-Accel-Buffering": "no",
  });

  const send = (event: string, data: unknown): void => {
    if (res.writableEnded) return;
    res.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`);
  };

  const sinks: AnalyserSinks = {
    onText: (text) => send("text", { text }),
    onThinking: (text) => send("thinking", { text }),
    onToolCall: (name, input) => send("tool", { name, purpose: purposeOf(input) }),
  };

  try {
    const config = withOverrides(ctx.baseConfig, payload.overrides);
    send("start", { provider: config.provider, effort: config.effort });
    const analyser = ctx.factory(config, sinks);
    const outcome = await analyser.analyse(payload.request);
    if (outcome.report) send("report", outcome.report);
    send("done", {
      verdict: outcome.report?.verdict ?? null,
      overall_score: outcome.report?.overall_score ?? null,
      rating: outcome.report?.rating ?? null,
      markdown: outcome.markdown,
      modelUsed: outcome.modelUsed,
      refusal: outcome.refusal ?? null,
      aborted: outcome.aborted ?? null,
      savedFiles: outcome.savedFiles,
    });
  } catch (error) {
    send("error", { message: error instanceof Error ? error.message : String(error) });
  } finally {
    if (!res.writableEnded) res.end();
  }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function purposeOf(input: unknown): string | undefined {
  if (input && typeof input === "object" && "purpose" in input) {
    const p = (input as { purpose?: unknown }).purpose;
    return typeof p === "string" ? p : undefined;
  }
  return undefined;
}

function readBody(req: IncomingMessage, limit: number): Promise<string> {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks: Buffer[] = [];
    req.on("data", (chunk: Buffer) => {
      size += chunk.length;
      if (size > limit) {
        reject(new Error("Request body too large"));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
    req.on("error", reject);
  });
}

async function serveStatic(pathname: string, res: ServerResponse, publicDir: string): Promise<void> {
  // Resolve within publicDir and reject any traversal outside it.
  const safe = path.normalize(decodeURIComponent(pathname)).replace(/^(\.\.([/\\]|$))+/, "");
  const filePath = path.join(publicDir, safe);
  const resolved = path.resolve(filePath);
  if (resolved !== path.resolve(publicDir) && !resolved.startsWith(path.resolve(publicDir) + path.sep)) {
    return sendJson(res, 403, { error: "Forbidden" });
  }
  try {
    const data = await readFile(resolved);
    const type = CONTENT_TYPES[path.extname(resolved).toLowerCase()] ?? "application/octet-stream";
    res.writeHead(200, { "Content-Type": type });
    res.end(data);
  } catch {
    return sendJson(res, 404, { error: "Not found" });
  }
}

function sendJson(res: ServerResponse, status: number, body: unknown): void {
  res.writeHead(status, { "Content-Type": "application/json; charset=utf-8" });
  res.end(JSON.stringify(body));
}
