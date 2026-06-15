import { describe, expect, it } from "vitest";

import type { TokenProvider } from "../types.js";
import {
  LOG_ANALYTICS_SCOPE,
  LogAnalyticsApiError,
  LogAnalyticsClient,
} from "./log_analytics_client.js";

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

interface FetchCall {
  input: string | URL | Request;
  init: RequestInit | undefined;
}

/** Fake fetch that records each call and delegates to `respond`. */
function fakeFetch(respond: (call: FetchCall) => Response | Promise<Response>) {
  const calls: FetchCall[] = [];
  const fetchImpl = (async (input: string | URL | Request, init?: RequestInit) => {
    const call: FetchCall = { input, init };
    calls.push(call);
    return respond(call);
  }) as typeof fetch;
  return { calls, fetchImpl };
}

function json(body: unknown, init?: ResponseInit): Response {
  return new Response(JSON.stringify(body), {
    ...init,
    headers: { "content-type": "application/json", ...(init?.headers as Record<string, string>) },
  });
}

const stubProvider: TokenProvider = { getToken: async () => "tok-123" };

function makeClient(
  respond: (call: FetchCall) => Response | Promise<Response>,
  opts?: { endpoint?: string; scope?: string; tokenProvider?: TokenProvider },
) {
  const { calls, fetchImpl } = fakeFetch(respond);
  const client = new LogAnalyticsClient({
    tokenProvider: opts?.tokenProvider ?? stubProvider,
    fetchImpl,
    ...(opts?.endpoint !== undefined ? { endpoint: opts.endpoint } : {}),
    ...(opts?.scope !== undefined ? { scope: opts.scope } : {}),
  });
  return { client, calls };
}

/** TokenProvider that records every scope it is asked for. */
function scopeRecordingProvider(): { provider: TokenProvider; scopes: string[] } {
  const scopes: string[] = [];
  const provider: TokenProvider = {
    getToken: async (scope) => {
      scopes.push(scope);
      return "tok-recorded";
    },
  };
  return { provider, scopes };
}

function headersOf(call: FetchCall): Headers {
  return new Headers(call.init?.headers);
}

function bodyOf(call: FetchCall): Record<string, unknown> {
  return JSON.parse(call.init?.body as string) as Record<string, unknown>;
}

const baseQuery = {
  workspaceId: "11111111-2222-3333-4444-555555555555",
  query: "SigninLogs | where TimeGenerated >= ago(1d) | count",
  timespan: "P1D",
};

const successBody = {
  tables: [
    {
      name: "PrimaryResult",
      columns: [{ name: "Count", type: "long" }],
      rows: [[42]],
    },
  ],
  statistics: { query: { executionTime: 0.0125 } },
};

// ---------------------------------------------------------------------------
// runQuery: request shaping
// ---------------------------------------------------------------------------

describe("LogAnalyticsClient.runQuery request shaping", () => {
  it("POSTs to the default endpoint with the workspace ID URL-encoded", async () => {
    const { client, calls } = makeClient(() => json(successBody));
    await client.runQuery({ ...baseQuery, workspaceId: "ws id/../x" });

    expect(calls).toHaveLength(1);
    expect(String(calls[0]!.input)).toBe(
      "https://api.loganalytics.azure.com/v1/workspaces/ws%20id%2F..%2Fx/query",
    );
    expect(calls[0]!.init?.method).toBe("POST");
  });

  it("uses a custom endpoint, tolerating a trailing slash", async () => {
    const { client, calls } = makeClient(() => json(successBody), {
      endpoint: "https://api.loganalytics.us/",
    });
    await client.runQuery(baseQuery);

    expect(String(calls[0]!.input)).toBe(
      `https://api.loganalytics.us/v1/workspaces/${baseQuery.workspaceId}/query`,
    );
  });

  it("sends { query, timespan } and omits workspaces when no additional workspaces", async () => {
    const { client, calls } = makeClient(() => json(successBody));
    await client.runQuery(baseQuery);

    expect(bodyOf(calls[0]!)).toEqual({ query: baseQuery.query, timespan: "P1D" });
  });

  it("includes workspaces when additionalWorkspaces is provided", async () => {
    const { client, calls } = makeClient(() => json(successBody));
    await client.runQuery({ ...baseQuery, additionalWorkspaces: ["ws-2", "ws-3"] });

    expect(bodyOf(calls[0]!)).toEqual({
      query: baseQuery.query,
      timespan: "P1D",
      workspaces: ["ws-2", "ws-3"],
    });
  });

  it("builds the default combined Prefer header (statistics on, wait 300)", async () => {
    const { client, calls } = makeClient(() => json(successBody));
    await client.runQuery(baseQuery);

    expect(headersOf(calls[0]!).get("Prefer")).toBe("include-statistics=true, wait=300");
  });

  it("builds the Prefer header from explicit options", async () => {
    const { client, calls } = makeClient(() => json(successBody));
    await client.runQuery({
      ...baseQuery,
      includeStatistics: false,
      includeDataSources: true,
      waitSeconds: 60,
    });

    expect(headersOf(calls[0]!).get("Prefer")).toBe("include-dataSources=true, wait=60");
  });

  it("includes all three Prefer parts when everything is enabled", async () => {
    const { client, calls } = makeClient(() => json(successBody));
    await client.runQuery({
      ...baseQuery,
      includeStatistics: true,
      includeDataSources: true,
      waitSeconds: 120,
    });

    expect(headersOf(calls[0]!).get("Prefer")).toBe(
      "include-statistics=true, include-dataSources=true, wait=120",
    );
  });

  it("omits the Prefer header entirely when every part is disabled", async () => {
    const { client, calls } = makeClient(() => json(successBody));
    await client.runQuery({
      ...baseQuery,
      includeStatistics: false,
      includeDataSources: false,
      waitSeconds: 0,
    });

    expect(headersOf(calls[0]!).get("Prefer")).toBeNull();
  });

  it("sends a bearer token for the Log Analytics scope and a JSON content type", async () => {
    const scopes: string[] = [];
    const provider: TokenProvider = {
      getToken: async (scope) => {
        scopes.push(scope);
        return "tok-xyz";
      },
    };
    const { client, calls } = makeClient(() => json(successBody), { tokenProvider: provider });
    await client.runQuery(baseQuery);

    expect(scopes).toEqual(["https://api.loganalytics.azure.com/.default"]);
    expect(LOG_ANALYTICS_SCOPE).toBe("https://api.loganalytics.azure.com/.default");
    expect(headersOf(calls[0]!).get("Authorization")).toBe("Bearer tok-xyz");
    expect(headersOf(calls[0]!).get("Content-Type")).toBe("application/json");
  });
});

// ---------------------------------------------------------------------------
// runQuery: response handling
// ---------------------------------------------------------------------------

describe("LogAnalyticsClient.runQuery response handling", () => {
  it("parses a successful response", async () => {
    const { client } = makeClient(() => json(successBody));
    const result = await client.runQuery(baseQuery);

    expect(result.status).toBe("Succeeded");
    expect(result.tables).toEqual([
      { name: "PrimaryResult", columns: [{ name: "Count", type: "long" }], rows: [[42]] },
    ]);
    expect(result.statistics).toEqual({ query: { executionTime: 0.0125 } });
    expect(result.error).toBeUndefined();
    expect(typeof result.durationMs).toBe("number");
    expect(result.durationMs).toBeGreaterThanOrEqual(0);
  });

  it("surfaces dataSources when the response carries them", async () => {
    const { client } = makeClient(() =>
      json({ ...successBody, dataSources: { workspaces: ["ws-1"] } }),
    );
    const result = await client.runQuery(baseQuery);

    expect(result.dataSources).toEqual({ workspaces: ["ws-1"] });
  });

  it("defaults missing columns/rows arrays to empty arrays", async () => {
    const { client } = makeClient(() => json({ tables: [{ name: "PrimaryResult" }] }));
    const result = await client.runQuery(baseQuery);

    expect(result.status).toBe("Succeeded");
    expect(result.tables).toEqual([{ name: "PrimaryResult", columns: [], rows: [] }]);
  });

  it("defaults a missing tables array to an empty array", async () => {
    const { client } = makeClient(() => json({}));
    const result = await client.runQuery(baseQuery);

    expect(result.status).toBe("Succeeded");
    expect(result.tables).toEqual([]);
  });

  it("maps 204 No Content to Succeeded with empty tables (workspace has no data)", async () => {
    const { client } = makeClient(() => new Response(null, { status: 204 }));
    const result = await client.runQuery(baseQuery);

    expect(result.status).toBe("Succeeded");
    expect(result.tables).toEqual([]);
    expect(result.error).toBeUndefined();
    expect(typeof result.durationMs).toBe("number");
    expect(result.durationMs).toBeGreaterThanOrEqual(0);
  });

  it("maps an empty-string 200 body to Succeeded with empty tables", async () => {
    const { client } = makeClient(() => new Response("", { status: 200 }));
    const result = await client.runQuery(baseQuery);

    expect(result.status).toBe("Succeeded");
    expect(result.tables).toEqual([]);
    expect(result.error).toBeUndefined();
  });

  it("maps a whitespace-only 200 body to Succeeded with empty tables", async () => {
    const { client } = makeClient(() => new Response("  \n\t ", { status: 200 }));
    const result = await client.runQuery(baseQuery);

    expect(result.status).toBe("Succeeded");
    expect(result.tables).toEqual([]);
    expect(result.error).toBeUndefined();
  });

  it("maps a 200 response that also carries an error object to PartialFailure", async () => {
    const { client } = makeClient(() =>
      json({
        ...successBody,
        error: { code: "PartialError", message: "One or more shards failed", innererror: { code: "E1" } },
      }),
    );
    const result = await client.runQuery(baseQuery);

    expect(result.status).toBe("PartialFailure");
    expect(result.tables).toHaveLength(1);
    expect(result.error?.code).toBe("PartialError");
    expect(result.error?.message).toBe("One or more shards failed");
    expect(result.error?.details).toEqual({ code: "E1" });
  });

  it("maps 401 to a Failed result with an auth error code", async () => {
    const { client } = makeClient(() =>
      json(
        { error: { code: "InvalidAuthenticationToken", message: "Token expired" } },
        { status: 401 },
      ),
    );
    const result = await client.runQuery(baseQuery);

    expect(result.status).toBe("Failed");
    expect(result.tables).toEqual([]);
    expect(result.error?.code).toBe("AuthError");
    expect(result.error?.message).toBe("Token expired");
  });

  it("maps 403 without a body to an auth error with a sign-in hint", async () => {
    const { client } = makeClient(() => new Response("", { status: 403, statusText: "Forbidden" }));
    const result = await client.runQuery(baseQuery);

    expect(result.status).toBe("Failed");
    expect(result.error?.code).toBe("AuthError");
    expect(result.error?.message).toMatch(/403/);
  });

  it("maps 404 to WorkspaceNotFound", async () => {
    const { client } = makeClient(() =>
      json({ error: { code: "WorkspaceNotFoundError", message: "No workspace" } }, { status: 404 }),
    );
    const result = await client.runQuery(baseQuery);

    expect(result.status).toBe("Failed");
    expect(result.error?.code).toBe("WorkspaceNotFound");
    expect(result.error?.message).toBe("No workspace");
  });

  it("maps 429 to Throttled and surfaces Retry-After", async () => {
    const { client } = makeClient(() =>
      json(
        { error: { code: "RateLimited", message: "Too many requests" } },
        { status: 429, headers: { "Retry-After": "30" } },
      ),
    );
    const result = await client.runQuery(baseQuery);

    expect(result.status).toBe("Failed");
    expect(result.error?.code).toBe("Throttled");
    expect(result.error?.message).toContain("30");
    expect(result.error?.details).toEqual({ retryAfter: "30" });
  });

  it("maps 504 to QueryTimeout", async () => {
    const { client } = makeClient(
      () => new Response("", { status: 504, statusText: "Gateway Timeout" }),
    );
    const result = await client.runQuery(baseQuery);

    expect(result.status).toBe("Failed");
    expect(result.error?.code).toBe("QueryTimeout");
  });

  it("keeps the envelope code/message for other HTTP failures", async () => {
    const { client } = makeClient(() =>
      json(
        { error: { code: "SemanticError", message: "Unknown column 'Foo'" } },
        { status: 400 },
      ),
    );
    const result = await client.runQuery(baseQuery);

    expect(result.status).toBe("Failed");
    expect(result.error?.code).toBe("SemanticError");
    expect(result.error?.message).toBe("Unknown column 'Foo'");
  });

  it("falls back to status text when an HTTP failure body is not JSON", async () => {
    const { client } = makeClient(
      () => new Response("<html>oops</html>", { status: 500, statusText: "Internal Server Error" }),
    );
    const result = await client.runQuery(baseQuery);

    expect(result.status).toBe("Failed");
    expect(result.error?.code).toBe("HTTP500");
    expect(result.error?.message).toBe("Internal Server Error");
  });

  it("maps a malformed JSON body on HTTP 200 to a Failed result", async () => {
    const { client } = makeClient(() => new Response("not-json{{", { status: 200 }));
    const result = await client.runQuery(baseQuery);

    expect(result.status).toBe("Failed");
    expect(result.error?.code).toBe("InvalidResponse");
    expect(typeof result.durationMs).toBe("number");
  });

  it("maps a fetch rejection to TransportError without throwing", async () => {
    const { client } = makeClient(() => {
      throw new TypeError("fetch failed: socket hang up");
    });
    const result = await client.runQuery(baseQuery);

    expect(result.status).toBe("Failed");
    expect(result.error?.code).toBe("TransportError");
    expect(result.error?.message).toContain("socket hang up");
    expect(result.durationMs).toBeGreaterThanOrEqual(0);
  });

  it("maps a token provider failure to AuthError and never calls fetch", async () => {
    const failingProvider: TokenProvider = {
      getToken: async () => {
        throw new Error("Please run az login first");
      },
    };
    const { client, calls } = makeClient(() => json(successBody), {
      tokenProvider: failingProvider,
    });
    const result = await client.runQuery(baseQuery);

    expect(result.status).toBe("Failed");
    expect(result.error?.code).toBe("AuthError");
    expect(result.error?.message).toContain("az login");
    expect(result.durationMs).toBeGreaterThanOrEqual(0);
    expect(calls).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// Token scope derivation
// ---------------------------------------------------------------------------

describe("LogAnalyticsClient token scope derivation", () => {
  it("derives the scope from a sovereign-cloud endpoint", async () => {
    const { provider, scopes } = scopeRecordingProvider();
    const { client } = makeClient(() => json(successBody), {
      endpoint: "https://api.loganalytics.us",
      tokenProvider: provider,
    });
    await client.runQuery(baseQuery);

    expect(scopes).toEqual(["https://api.loganalytics.us/.default"]);
  });

  it("derives the public-cloud scope for the default endpoint", async () => {
    const { provider, scopes } = scopeRecordingProvider();
    const { client } = makeClient(() => json(successBody), { tokenProvider: provider });
    await client.runQuery(baseQuery);

    expect(scopes).toEqual([LOG_ANALYTICS_SCOPE]);
    expect(LOG_ANALYTICS_SCOPE).toBe("https://api.loganalytics.azure.com/.default");
  });

  it("lets an explicit scope option win over the endpoint-derived scope", async () => {
    const { provider, scopes } = scopeRecordingProvider();
    const { client } = makeClient(() => json(successBody), {
      endpoint: "https://api.loganalytics.us",
      scope: "https://custom.audience.example/.default",
      tokenProvider: provider,
    });
    await client.runQuery(baseQuery);

    expect(scopes).toEqual(["https://custom.audience.example/.default"]);
  });

  it("uses the derived scope for getWorkspaceSchema too", async () => {
    const { provider, scopes } = scopeRecordingProvider();
    const { client } = makeClient(() => json({ tables: [] }), {
      endpoint: "https://api.loganalytics.azure.cn/",
      tokenProvider: provider,
    });
    await client.getWorkspaceSchema("ws-1");

    expect(scopes).toEqual(["https://api.loganalytics.azure.cn/.default"]);
  });
});

// ---------------------------------------------------------------------------
// getWorkspaceSchema
// ---------------------------------------------------------------------------

describe("LogAnalyticsClient.getWorkspaceSchema", () => {
  const metadataBody = {
    tables: [
      {
        name: "SigninLogs",
        columns: [
          { name: "TimeGenerated", type: "datetime" },
          { name: "UserPrincipalName", type: "string" },
        ],
      },
      { name: "Heartbeat" }, // no columns array
      "garbage-entry", // not an object
      { columns: [{ name: "X", type: "string" }] }, // no usable name
    ],
  };

  it("GETs the metadata endpoint with select=tables, encoding the workspace ID", async () => {
    const { client, calls } = makeClient(() => json(metadataBody));
    await client.getWorkspaceSchema("ws id/1");

    expect(String(calls[0]!.input)).toBe(
      "https://api.loganalytics.azure.com/v1/workspaces/ws%20id%2F1/metadata?select=tables",
    );
    expect(calls[0]!.init?.method).toBe("GET");
    expect(headersOf(calls[0]!).get("Authorization")).toBe("Bearer tok-123");
  });

  it("maps tables to WorkspaceTableSchema entries defensively", async () => {
    const { client } = makeClient(() => json(metadataBody));
    const schema = await client.getWorkspaceSchema("ws-1");

    expect(schema).toEqual([
      {
        table: "SigninLogs",
        columns: [
          { name: "TimeGenerated", type: "datetime" },
          { name: "UserPrincipalName", type: "string" },
        ],
      },
      { table: "Heartbeat", columns: [] },
    ]);
  });

  it("returns an empty array when the response has no tables array", async () => {
    const { client } = makeClient(() => json({}));
    await expect(client.getWorkspaceSchema("ws-1")).resolves.toEqual([]);
  });

  it("returns an empty array on 204 No Content", async () => {
    const { client } = makeClient(() => new Response(null, { status: 204 }));
    await expect(client.getWorkspaceSchema("ws-1")).resolves.toEqual([]);
  });

  it("returns an empty array on an empty-string 200 body", async () => {
    const { client } = makeClient(() => new Response("", { status: 200 }));
    await expect(client.getWorkspaceSchema("ws-1")).resolves.toEqual([]);
  });

  it("throws an error carrying the parsed code/message on HTTP failure", async () => {
    const { client } = makeClient(() =>
      json({ error: { code: "PathNotFoundError", message: "no workspace" } }, { status: 404 }),
    );

    const promise = client.getWorkspaceSchema("ws-1");
    await expect(promise).rejects.toBeInstanceOf(LogAnalyticsApiError);
    await expect(promise).rejects.toMatchObject({ code: "WorkspaceNotFound", status: 404 });
    await expect(promise).rejects.toThrow(/no workspace/);
  });

  it("falls back to status text when the failure body is not JSON", async () => {
    const { client } = makeClient(
      () => new Response("boom", { status: 500, statusText: "Internal Server Error" }),
    );

    await expect(client.getWorkspaceSchema("ws-1")).rejects.toMatchObject({
      code: "HTTP500",
      status: 500,
    });
  });

  it("throws on a malformed JSON body with HTTP 200", async () => {
    const { client } = makeClient(() => new Response("not-json", { status: 200 }));

    await expect(client.getWorkspaceSchema("ws-1")).rejects.toMatchObject({
      code: "InvalidResponse",
    });
  });
});
