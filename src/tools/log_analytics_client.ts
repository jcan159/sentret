/**
 * Azure Monitor Logs Query API client (Log Analytics).
 *
 * Implements the two read-only operations the analyser needs:
 * - `runQuery`: POST /v1/workspaces/{id}/query — never throws for HTTP-level
 *   failures; everything is folded into a {@link LogQueryResult}.
 * - `getWorkspaceSchema`: GET /v1/workspaces/{id}/metadata?select=tables —
 *   throws {@link LogAnalyticsApiError} on failure (the caller converts it
 *   into a tool error; schema lookup is non-critical).
 */

import type {
  KustoColumn,
  KustoTable,
  LogQueryError,
  LogQueryResult,
  RunQueryOptions,
  TokenProvider,
  WorkspaceTableSchema,
} from "../types.js";

/**
 * Microsoft Entra scope for the public-cloud Log Analytics endpoint.
 *
 * Kept exported for compatibility; the client itself derives the scope from
 * its configured endpoint so sovereign clouds (e.g. api.loganalytics.us,
 * api.loganalytics.azure.cn) request a matching token audience.
 */
export const LOG_ANALYTICS_SCOPE = "https://api.loganalytics.azure.com/.default";

const DEFAULT_ENDPOINT = "https://api.loganalytics.azure.com";
const DEFAULT_WAIT_SECONDS = 300;

export interface LogAnalyticsClientOptions {
  tokenProvider: TokenProvider;
  /** API base URL; defaults to the public cloud endpoint. */
  endpoint?: string;
  /**
   * Explicit Microsoft Entra scope for token acquisition. Defaults to the
   * endpoint origin + "/.default" (public cloud yields
   * {@link LOG_ANALYTICS_SCOPE}). Escape hatch for clouds where the token
   * audience differs from the API endpoint.
   */
  scope?: string;
  /** Injectable fetch for tests; defaults to globalThis.fetch. */
  fetchImpl?: typeof fetch;
}

/** Error thrown by {@link LogAnalyticsClient.getWorkspaceSchema} on failure. */
export class LogAnalyticsApiError extends Error {
  readonly code: string;
  readonly status: number;

  constructor(code: string, message: string, status: number) {
    super(message);
    this.name = "LogAnalyticsApiError";
    this.code = code;
    this.status = status;
  }
}

// ---------------------------------------------------------------------------
// Defensive parsing helpers
// ---------------------------------------------------------------------------

function asRecord(value: unknown): Record<string, unknown> | undefined {
  return typeof value === "object" && value !== null && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : undefined;
}

function errorMessage(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

type ParsedJson = { ok: true; value: unknown } | { ok: false; value: undefined; reason: string };

function tryParseJson(text: string): ParsedJson {
  try {
    return { ok: true, value: JSON.parse(text) };
  } catch (err) {
    return { ok: false, value: undefined, reason: errorMessage(err) };
  }
}

function parseColumns(value: unknown): KustoColumn[] {
  if (!Array.isArray(value)) return [];
  const columns: KustoColumn[] = [];
  for (const entry of value) {
    const rec = asRecord(entry);
    if (rec === undefined) continue;
    columns.push({
      name: typeof rec["name"] === "string" ? rec["name"] : "",
      type: typeof rec["type"] === "string" ? rec["type"] : "",
    });
  }
  return columns;
}

function parseTables(value: unknown): KustoTable[] {
  if (!Array.isArray(value)) return [];
  const tables: KustoTable[] = [];
  for (const entry of value) {
    const rec = asRecord(entry);
    if (rec === undefined) continue;
    const rawRows = rec["rows"];
    tables.push({
      name: typeof rec["name"] === "string" ? rec["name"] : "",
      columns: parseColumns(rec["columns"]),
      rows: Array.isArray(rawRows)
        ? rawRows.filter((row): row is unknown[] => Array.isArray(row))
        : [],
    });
  }
  return tables;
}

/** Parses the `error` member of a response body ({ code, message, innererror? }). */
function parseErrorMember(value: unknown): LogQueryError | undefined {
  const rec = asRecord(value);
  if (rec === undefined) return undefined;
  const error: LogQueryError = {
    code: typeof rec["code"] === "string" ? rec["code"] : "UnknownError",
    message: typeof rec["message"] === "string" ? rec["message"] : "Unknown error",
  };
  const details = rec["innererror"] ?? rec["details"];
  if (details !== undefined) error.details = details;
  return error;
}

/** Maps a non-2xx response to a friendly LogQueryError for downstream handling. */
function mapHttpError(response: Response, body: unknown): LogQueryError {
  const envelope = parseErrorMember(asRecord(body)?.["error"]);
  const status = response.status;
  const statusLabel = `HTTP ${status}${response.statusText ? ` ${response.statusText}` : ""}`;

  if (status === 401 || status === 403) {
    return {
      code: "AuthError",
      message:
        envelope?.message ??
        `${statusLabel}: not authorised to query this workspace. Check Microsoft Entra ` +
          'sign-in (e.g. "az login") and workspace RBAC.',
      ...(envelope?.details !== undefined ? { details: envelope.details } : {}),
    };
  }
  if (status === 404) {
    return {
      code: "WorkspaceNotFound",
      message: envelope?.message ?? `${statusLabel}: workspace not found. Verify the workspace ID.`,
      ...(envelope?.details !== undefined ? { details: envelope.details } : {}),
    };
  }
  if (status === 429) {
    const retryAfter = response.headers.get("retry-after");
    const base = envelope?.message ?? `${statusLabel}: request was throttled.`;
    return {
      code: "Throttled",
      message: retryAfter === null ? base : `${base} Retry after ${retryAfter} seconds.`,
      ...(retryAfter !== null
        ? { details: { retryAfter } }
        : envelope?.details !== undefined
          ? { details: envelope.details }
          : {}),
    };
  }
  if (status === 504 || status === 408) {
    return {
      code: "QueryTimeout",
      message:
        envelope?.message ??
        `${statusLabel}: the query timed out. Narrow the timespan or simplify the query.`,
      ...(envelope?.details !== undefined ? { details: envelope.details } : {}),
    };
  }
  return {
    code: envelope?.code ?? `HTTP${status}`,
    message: envelope?.message ?? (response.statusText || `HTTP ${status}`),
    ...(envelope?.details !== undefined ? { details: envelope.details } : {}),
  };
}

/**
 * Builds the single combined Prefer header value from the query options.
 * Returns undefined when every part is disabled (no header should be sent).
 */
function buildPreferHeader(opts: RunQueryOptions): string | undefined {
  const parts: string[] = [];
  if (opts.includeStatistics ?? true) parts.push("include-statistics=true");
  if (opts.includeDataSources ?? false) parts.push("include-dataSources=true");
  const waitSeconds = opts.waitSeconds ?? DEFAULT_WAIT_SECONDS;
  if (Number.isFinite(waitSeconds) && waitSeconds > 0) {
    parts.push(`wait=${Math.floor(waitSeconds)}`);
  }
  return parts.length > 0 ? parts.join(", ") : undefined;
}

// ---------------------------------------------------------------------------
// Client
// ---------------------------------------------------------------------------

/**
 * Minimal client for the Azure Monitor Logs Query API
 * (`https://api.loganalytics.azure.com/v1`).
 */
export class LogAnalyticsClient {
  readonly #tokenProvider: TokenProvider;
  readonly #endpoint: string;
  readonly #scope: string;
  readonly #fetchImpl: typeof fetch;

  constructor(opts: LogAnalyticsClientOptions) {
    this.#tokenProvider = opts.tokenProvider;
    this.#endpoint = (opts.endpoint ?? DEFAULT_ENDPOINT).replace(/\/+$/, "");
    this.#scope = opts.scope ?? `${new URL(this.#endpoint).origin}/.default`;
    this.#fetchImpl = opts.fetchImpl ?? globalThis.fetch;
  }

  /**
   * Runs a KQL query against a workspace.
   *
   * Never throws for HTTP-level, transport, or credential failures: every
   * outcome is mapped into a {@link LogQueryResult}. A 200 response that also
   * carries an `error` object becomes `"PartialFailure"`; non-2xx responses
   * become `"Failed"` with a friendly error code (AuthError,
   * WorkspaceNotFound, Throttled, QueryTimeout, TransportError, ...).
   */
  async runQuery(opts: RunQueryOptions): Promise<LogQueryResult> {
    const started = Date.now();
    const fail = (error: LogQueryError): LogQueryResult => ({
      status: "Failed",
      tables: [],
      error,
      durationMs: Date.now() - started,
    });

    let token: string;
    try {
      token = await this.#tokenProvider.getToken(this.#scope);
    } catch (err) {
      return fail({ code: "AuthError", message: errorMessage(err) });
    }

    const url = `${this.#endpoint}/v1/workspaces/${encodeURIComponent(opts.workspaceId)}/query`;
    const requestBody: Record<string, unknown> = {
      query: opts.query,
      timespan: opts.timespan,
    };
    if (opts.additionalWorkspaces !== undefined && opts.additionalWorkspaces.length > 0) {
      requestBody["workspaces"] = opts.additionalWorkspaces;
    }

    const headers: Record<string, string> = {
      Authorization: `Bearer ${token}`,
      "Content-Type": "application/json",
    };
    const prefer = buildPreferHeader(opts);
    if (prefer !== undefined) headers["Prefer"] = prefer;

    let response: Response;
    let rawText: string;
    try {
      response = await this.#fetchImpl(url, {
        method: "POST",
        headers,
        body: JSON.stringify(requestBody),
      });
      rawText = await response.text();
    } catch (err) {
      return fail({ code: "TransportError", message: errorMessage(err) });
    }

    const durationMs = Date.now() - started;

    if (!response.ok) {
      return {
        status: "Failed",
        tables: [],
        error: mapHttpError(response, tryParseJson(rawText).value),
        durationMs,
      };
    }
    // 204 No Content (or an empty 2xx body) is a documented success: the
    // workspace simply has no data for the query.
    if (response.status === 204 || rawText.trim() === "") {
      return { status: "Succeeded", tables: [], durationMs };
    }

    const parsed = tryParseJson(rawText);
    if (!parsed.ok) {
      return {
        status: "Failed",
        tables: [],
        error: {
          code: "InvalidResponse",
          message: `Could not parse Log Analytics response body as JSON: ${parsed.reason}`,
        },
        durationMs,
      };
    }

    const body = asRecord(parsed.value) ?? {};
    const partialError = parseErrorMember(body["error"]);
    const result: LogQueryResult = {
      status: partialError === undefined ? "Succeeded" : "PartialFailure",
      tables: parseTables(body["tables"]),
      durationMs,
    };
    const statistics = asRecord(body["statistics"]);
    if (statistics !== undefined) result.statistics = statistics;
    const dataSources = asRecord(body["dataSources"]);
    if (dataSources !== undefined) result.dataSources = dataSources;
    if (partialError !== undefined) result.error = partialError;
    return result;
  }

  /**
   * Retrieves the workspace's known tables and columns via the metadata API.
   *
   * @throws {@link LogAnalyticsApiError} carrying the parsed code/message on
   *   any failure (non-2xx, transport, or malformed body).
   */
  async getWorkspaceSchema(workspaceId: string): Promise<WorkspaceTableSchema[]> {
    const token = await this.#tokenProvider.getToken(this.#scope);
    const url =
      `${this.#endpoint}/v1/workspaces/${encodeURIComponent(workspaceId)}/metadata?select=tables`;

    const response = await this.#fetchImpl(url, {
      method: "GET",
      headers: { Authorization: `Bearer ${token}` },
    });
    const rawText = await response.text();

    if (!response.ok) {
      const error = mapHttpError(response, tryParseJson(rawText).value);
      throw new LogAnalyticsApiError(
        error.code,
        `Workspace schema lookup failed (${error.code}): ${error.message}`,
        response.status,
      );
    }
    // 204 No Content (or an empty 2xx body) means the workspace has no
    // metadata to report — a success with no tables.
    if (response.status === 204 || rawText.trim() === "") return [];

    const parsed = tryParseJson(rawText);
    if (!parsed.ok) {
      throw new LogAnalyticsApiError(
        "InvalidResponse",
        `Could not parse workspace metadata response as JSON: ${parsed.reason}`,
        response.status,
      );
    }

    const rawTables = asRecord(parsed.value)?.["tables"];
    if (!Array.isArray(rawTables)) return [];
    const schemas: WorkspaceTableSchema[] = [];
    for (const entry of rawTables) {
      const rec = asRecord(entry);
      if (rec === undefined || typeof rec["name"] !== "string") continue;
      schemas.push({ table: rec["name"], columns: parseColumns(rec["columns"]) });
    }
    return schemas;
  }
}
