import { describe, expect, it } from "vitest";

import type {
  SentinelScheduledRuleParams,
  SentinelWorkspaceRef,
  TokenProvider,
} from "../types.js";
import {
  SENTINEL_API_VERSION,
  SentinelClient,
  WORKSPACE_API_VERSION,
} from "./sentinel_client.js";

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

interface RecordedCall {
  url: string;
  init: RequestInit | undefined;
}

interface QueuedResponse {
  status: number;
  body?: unknown;
  /** Raw (non-JSON) body text; takes precedence over `body`. */
  rawText?: string;
}

function makeFakeFetch(responses: QueuedResponse[]) {
  const calls: RecordedCall[] = [];
  const fetchImpl = (async (input: Parameters<typeof fetch>[0], init?: RequestInit) => {
    calls.push({ url: String(input), init });
    const next = responses.shift();
    if (!next) {
      throw new Error("fake fetch: no more responses queued");
    }
    const text =
      next.rawText !== undefined ? next.rawText : JSON.stringify(next.body ?? {});
    return new Response(text, {
      status: next.status,
      headers: { "content-type": "application/json" },
    });
  }) as typeof fetch;
  return { fetchImpl, calls };
}

function makeTokenProvider(token = "test-token") {
  const scopes: string[] = [];
  const provider: TokenProvider = {
    getToken: async (scope: string) => {
      scopes.push(scope);
      return token;
    },
  };
  return { provider, scopes };
}

function headerValue(init: RequestInit | undefined, name: string): string | undefined {
  const headers = (init?.headers ?? {}) as Record<string, string>;
  for (const [key, value] of Object.entries(headers)) {
    if (key.toLowerCase() === name.toLowerCase()) return value;
  }
  return undefined;
}

function parseBody(init: RequestInit | undefined): Record<string, unknown> {
  return JSON.parse(String(init?.body)) as Record<string, unknown>;
}

const ws: SentinelWorkspaceRef = {
  subscriptionId: "sub-1",
  resourceGroup: "rg-1",
  workspaceName: "ws-1",
};

const baseListUrl =
  "https://management.azure.com/subscriptions/sub-1/resourceGroups/rg-1" +
  "/providers/Microsoft.OperationalInsights/workspaces/ws-1" +
  "/providers/Microsoft.SecurityInsights/alertRules";

function minimalParams(): SentinelScheduledRuleParams {
  return {
    subscription_id: "sub-1",
    resource_group: "rg-1",
    workspace_name: "ws-1",
    rule_id: "rule-1",
    enabled: true,
    display_name: "Suspicious sign-in burst",
    severity: "Medium",
    query: "SigninLogs | where ResultType == 50126 | summarize count() by UserPrincipalName",
    query_frequency: "PT1H",
    query_period: "PT2H",
    trigger_operator: "GreaterThan",
    trigger_threshold: 5,
  };
}

// ---------------------------------------------------------------------------
// listRules
// ---------------------------------------------------------------------------

describe("SentinelClient.listRules", () => {
  it("requests the alertRules collection with the pinned api-version and bearer token", async () => {
    const { fetchImpl, calls } = makeFakeFetch([{ status: 200, body: { value: [] } }]);
    const { provider, scopes } = makeTokenProvider("tok-abc");
    const client = new SentinelClient({ tokenProvider: provider, fetchImpl });

    const rules = await client.listRules(ws);

    expect(rules).toEqual([]);
    expect(calls).toHaveLength(1);
    expect(calls[0]!.url).toBe(`${baseListUrl}?api-version=${SENTINEL_API_VERSION}`);
    expect(calls[0]!.init?.method).toBe("GET");
    expect(headerValue(calls[0]!.init, "authorization")).toBe("Bearer tok-abc");
    expect(scopes).toEqual(["https://management.azure.com/.default"]);
  });

  it("maps value[] items to SentinelRuleSummary and follows nextLink across two pages", async () => {
    const page1 = {
      value: [
        {
          id: "/subscriptions/sub-1/.../alertRules/rule-a",
          name: "rule-a",
          kind: "Scheduled",
          properties: {
            displayName: "Rule A",
            enabled: true,
            severity: "High",
            query: "SecurityEvent | where EventID == 4625",
            tactics: ["CredentialAccess"],
            techniques: ["T1110"],
          },
        },
      ],
      nextLink: `${baseListUrl}?api-version=${SENTINEL_API_VERSION}&$skipToken=abc123`,
    };
    const page2 = {
      value: [
        {
          id: "/subscriptions/sub-1/.../alertRules/rule-b",
          name: "rule-b",
          kind: "Fusion",
          // No properties at all: optional fields must stay undefined.
        },
      ],
    };
    const { fetchImpl, calls } = makeFakeFetch([
      { status: 200, body: page1 },
      { status: 200, body: page2 },
    ]);
    const { provider } = makeTokenProvider();
    const client = new SentinelClient({ tokenProvider: provider, fetchImpl });

    const rules = await client.listRules(ws);

    expect(calls).toHaveLength(2);
    expect(calls[1]!.url).toBe(page1.nextLink);
    expect(rules).toEqual([
      {
        id: "/subscriptions/sub-1/.../alertRules/rule-a",
        name: "rule-a",
        kind: "Scheduled",
        displayName: "Rule A",
        enabled: true,
        severity: "High",
        query: "SecurityEvent | where EventID == 4625",
        tactics: ["CredentialAccess"],
        techniques: ["T1110"],
      },
      {
        id: "/subscriptions/sub-1/.../alertRules/rule-b",
        name: "rule-b",
        kind: "Fusion",
      },
    ]);
    expect(rules[1]).not.toHaveProperty("displayName");
    expect(rules[1]).not.toHaveProperty("enabled");
  });

  it("is defensive about malformed items and a missing value array", async () => {
    const { fetchImpl } = makeFakeFetch([
      { status: 200, body: { value: [{ properties: { enabled: "yes", tactics: "not-an-array" } }] } },
    ]);
    const { provider } = makeTokenProvider();
    const client = new SentinelClient({ tokenProvider: provider, fetchImpl });

    const rules = await client.listRules(ws);
    expect(rules).toEqual([{ id: "", name: "", kind: "" }]);

    const { fetchImpl: fetch2 } = makeFakeFetch([{ status: 200, body: {} }]);
    const client2 = new SentinelClient({ tokenProvider: provider, fetchImpl: fetch2 });
    expect(await client2.listRules(ws)).toEqual([]);
  });

  it("URL-encodes workspace path segments", async () => {
    const { fetchImpl, calls } = makeFakeFetch([{ status: 200, body: { value: [] } }]);
    const { provider } = makeTokenProvider();
    const client = new SentinelClient({ tokenProvider: provider, fetchImpl });

    await client.listRules({
      subscriptionId: "sub 1",
      resourceGroup: "rg/with/slashes",
      workspaceName: "ws name#1",
    });

    expect(calls[0]!.url).toBe(
      "https://management.azure.com/subscriptions/sub%201" +
        "/resourceGroups/rg%2Fwith%2Fslashes" +
        "/providers/Microsoft.OperationalInsights/workspaces/ws%20name%231" +
        `/providers/Microsoft.SecurityInsights/alertRules?api-version=${SENTINEL_API_VERSION}`,
    );
  });

  it("respects a custom armEndpoint (including a trailing slash)", async () => {
    const { fetchImpl, calls } = makeFakeFetch([{ status: 200, body: { value: [] } }]);
    const { provider } = makeTokenProvider();
    const client = new SentinelClient({
      tokenProvider: provider,
      fetchImpl,
      armEndpoint: "https://management.usgovcloudapi.net/",
    });

    await client.listRules(ws);

    expect(calls[0]!.url.startsWith("https://management.usgovcloudapi.net/subscriptions/")).toBe(true);
  });

  it("surfaces ARM errors on non-2xx responses", async () => {
    const { fetchImpl } = makeFakeFetch([
      {
        status: 404,
        body: { error: { code: "ResourceNotFound", message: "Workspace not found" } },
      },
    ]);
    const { provider } = makeTokenProvider();
    const client = new SentinelClient({ tokenProvider: provider, fetchImpl });

    await expect(client.listRules(ws)).rejects.toThrow(/404/);
    const { fetchImpl: fetch2 } = makeFakeFetch([
      {
        status: 404,
        body: { error: { code: "ResourceNotFound", message: "Workspace not found" } },
      },
    ]);
    const client2 = new SentinelClient({ tokenProvider: provider, fetchImpl: fetch2 });
    await expect(client2.listRules(ws)).rejects.toThrow(/ResourceNotFound.*Workspace not found/);
  });
});

// ---------------------------------------------------------------------------
// createOrUpdateScheduledRule
// ---------------------------------------------------------------------------

describe("SentinelClient.createOrUpdateScheduledRule", () => {
  it("refuses to deploy without confirmed: true and never touches the network", async () => {
    const { fetchImpl, calls } = makeFakeFetch([{ status: 200, body: {} }]);
    const { provider, scopes } = makeTokenProvider();
    const client = new SentinelClient({ tokenProvider: provider, fetchImpl });

    await expect(
      client.createOrUpdateScheduledRule(minimalParams(), { confirmed: false }),
    ).rejects.toThrow(
      "Sentinel deployment requires explicit user approval (confirmed: true was not set).",
    );

    // Defense in depth: neither fetch nor token acquisition may have happened.
    expect(calls).toHaveLength(0);
    expect(scopes).toHaveLength(0);
  });

  it("PUTs to the encoded alertRules/{ruleId} URL with the pinned api-version", async () => {
    const { fetchImpl, calls } = makeFakeFetch([{ status: 200, body: {} }]);
    const { provider } = makeTokenProvider("tok-deploy");
    const client = new SentinelClient({ tokenProvider: provider, fetchImpl });

    const params = { ...minimalParams(), rule_id: "rule/one two" };
    await client.createOrUpdateScheduledRule(params, { confirmed: true });

    expect(calls).toHaveLength(1);
    expect(calls[0]!.init?.method).toBe("PUT");
    expect(calls[0]!.url).toBe(
      `${baseListUrl}/rule%2Fone%20two?api-version=${SENTINEL_API_VERSION}`,
    );
    expect(headerValue(calls[0]!.init, "authorization")).toBe("Bearer tok-deploy");
    expect(headerValue(calls[0]!.init, "content-type")).toBe("application/json");
  });

  it("sends kind Scheduled and applies defaults, omitting unset optional objects entirely", async () => {
    const { fetchImpl, calls } = makeFakeFetch([{ status: 201, body: {} }]);
    const { provider } = makeTokenProvider();
    const client = new SentinelClient({ tokenProvider: provider, fetchImpl });

    await client.createOrUpdateScheduledRule(minimalParams(), { confirmed: true });

    const body = parseBody(calls[0]!.init);
    expect(body.kind).toBe("Scheduled");
    const properties = body.properties as Record<string, unknown>;
    expect(properties).toEqual({
      displayName: "Suspicious sign-in burst",
      description: "",
      severity: "Medium",
      enabled: true,
      query: "SigninLogs | where ResultType == 50126 | summarize count() by UserPrincipalName",
      queryFrequency: "PT1H",
      queryPeriod: "PT2H",
      triggerOperator: "GreaterThan",
      triggerThreshold: 5,
      suppressionEnabled: false,
      suppressionDuration: "PT5H",
      tactics: [],
      techniques: [],
    });
    // Optional ARM objects must be absent, not null.
    expect(properties).not.toHaveProperty("entityMappings");
    expect(properties).not.toHaveProperty("customDetails");
    expect(properties).not.toHaveProperty("alertDetailsOverride");
    expect(properties).not.toHaveProperty("incidentConfiguration");
    expect(properties).not.toHaveProperty("eventGroupingSettings");
  });

  it("maps every provided snake_case field to its ARM camelCase property", async () => {
    const { fetchImpl, calls } = makeFakeFetch([{ status: 200, body: {} }]);
    const { provider } = makeTokenProvider();
    const client = new SentinelClient({ tokenProvider: provider, fetchImpl });

    const params: SentinelScheduledRuleParams = {
      ...minimalParams(),
      description: "Detects password-spray bursts.",
      tactics: ["CredentialAccess"],
      techniques: ["T1110.003"],
      entity_mappings: [
        {
          entityType: "Account",
          fieldMappings: [{ identifier: "FullName", columnName: "UserPrincipalName" }],
        },
      ],
      custom_details: { FailureCount: "FailedAttempts" },
      alert_details_override: { alertDisplayNameFormat: "Spray against {{UserPrincipalName}}" },
      incident_configuration: { createIncident: true },
      event_grouping_settings: { aggregationKind: "SingleAlert" },
      suppression_enabled: true,
      suppression_duration: "PT1H",
    };
    await client.createOrUpdateScheduledRule(params, { confirmed: true });

    const properties = parseBody(calls[0]!.init).properties as Record<string, unknown>;
    expect(properties.description).toBe("Detects password-spray bursts.");
    expect(properties.tactics).toEqual(["CredentialAccess"]);
    // Sub-technique IDs are normalised to the parent technique for ARM.
    expect(properties.techniques).toEqual(["T1110"]);
    expect(properties.entityMappings).toEqual(params.entity_mappings);
    expect(properties.customDetails).toEqual({ FailureCount: "FailedAttempts" });
    expect(properties.alertDetailsOverride).toEqual({
      alertDisplayNameFormat: "Spray against {{UserPrincipalName}}",
    });
    expect(properties.incidentConfiguration).toEqual({ createIncident: true });
    expect(properties.eventGroupingSettings).toEqual({ aggregationKind: "SingleAlert" });
    expect(properties.suppressionEnabled).toBe(true);
    expect(properties.suppressionDuration).toBe("PT1H");
  });

  it("normalises sub-technique IDs to parent techniques and dedupes", async () => {
    const { fetchImpl, calls } = makeFakeFetch([{ status: 200, body: {} }]);
    const { provider } = makeTokenProvider();
    const client = new SentinelClient({ tokenProvider: provider, fetchImpl });

    const params: SentinelScheduledRuleParams = {
      ...minimalParams(),
      techniques: ["T1110.003", "T1110.004", "T1110", "T1566.001"],
    };
    await client.createOrUpdateScheduledRule(params, { confirmed: true });

    const properties = parseBody(calls[0]!.init).properties as Record<string, unknown>;
    expect(properties.techniques).toEqual(["T1110", "T1566"]);
  });

  it("maps HTTP 201 to Created and uses the response body id as resourceId", async () => {
    const armId = `${"/subscriptions/sub-1/resourceGroups/rg-1"}/providers/Microsoft.OperationalInsights/workspaces/ws-1/providers/Microsoft.SecurityInsights/alertRules/rule-1`;
    const { fetchImpl } = makeFakeFetch([{ status: 201, body: { id: armId } }]);
    const { provider } = makeTokenProvider();
    const client = new SentinelClient({ tokenProvider: provider, fetchImpl });

    const result = await client.createOrUpdateScheduledRule(minimalParams(), {
      confirmed: true,
    });

    expect(result).toEqual({ ruleId: "rule-1", resourceId: armId, status: "Created" });
  });

  it("maps HTTP 200 to Updated and constructs the resourceId when the body lacks id", async () => {
    const { fetchImpl } = makeFakeFetch([{ status: 200, body: {} }]);
    const { provider } = makeTokenProvider();
    const client = new SentinelClient({ tokenProvider: provider, fetchImpl });

    const result = await client.createOrUpdateScheduledRule(minimalParams(), {
      confirmed: true,
    });

    expect(result.status).toBe("Updated");
    expect(result.ruleId).toBe("rule-1");
    expect(result.resourceId).toBe(
      "/subscriptions/sub-1/resourceGroups/rg-1" +
        "/providers/Microsoft.OperationalInsights/workspaces/ws-1" +
        "/providers/Microsoft.SecurityInsights/alertRules/rule-1",
    );
  });

  it("surfaces the ARM error code, message, and HTTP status on failure", async () => {
    const { fetchImpl } = makeFakeFetch([
      {
        status: 400,
        body: { error: { code: "BadRequest", message: "queryFrequency is invalid" } },
      },
    ]);
    const { provider } = makeTokenProvider();
    const client = new SentinelClient({ tokenProvider: provider, fetchImpl });

    await expect(
      client.createOrUpdateScheduledRule(minimalParams(), { confirmed: true }),
    ).rejects.toThrow(/400.*BadRequest.*queryFrequency is invalid/s);
  });

  it("mentions the Sentinel Contributor role on HTTP 403", async () => {
    const { fetchImpl } = makeFakeFetch([
      {
        status: 403,
        body: { error: { code: "AuthorizationFailed", message: "No permission" } },
      },
    ]);
    const { provider } = makeTokenProvider();
    const client = new SentinelClient({ tokenProvider: provider, fetchImpl });

    await expect(
      client.createOrUpdateScheduledRule(minimalParams(), { confirmed: true }),
    ).rejects.toThrow(/Sentinel Contributor/);
  });

  it("still throws a useful error when the failure body is not JSON", async () => {
    const { fetchImpl } = makeFakeFetch([{ status: 502, rawText: "Bad gateway" }]);
    const { provider } = makeTokenProvider();
    const client = new SentinelClient({ tokenProvider: provider, fetchImpl });

    await expect(
      client.createOrUpdateScheduledRule(minimalParams(), { confirmed: true }),
    ).rejects.toThrow(/502/);
  });
});

// ---------------------------------------------------------------------------
// ARM token scope derivation
// ---------------------------------------------------------------------------

describe("SentinelClient ARM token scope", () => {
  it("derives the scope from a sovereign-cloud armEndpoint", async () => {
    const { fetchImpl } = makeFakeFetch([{ status: 200, body: { value: [] } }]);
    const { provider, scopes } = makeTokenProvider();
    const client = new SentinelClient({
      tokenProvider: provider,
      fetchImpl,
      armEndpoint: "https://management.usgovcloudapi.net",
    });

    await client.listRules(ws);

    expect(scopes).toEqual(["https://management.usgovcloudapi.net/.default"]);
  });

  it("honours an explicit armScope override", async () => {
    const { fetchImpl } = makeFakeFetch([{ status: 200, body: { value: [] } }]);
    const { provider, scopes } = makeTokenProvider();
    const client = new SentinelClient({
      tokenProvider: provider,
      fetchImpl,
      armEndpoint: "https://management.usgovcloudapi.net",
      armScope: "https://custom.audience.example/.default",
    });

    await client.listRules(ws);

    expect(scopes).toEqual(["https://custom.audience.example/.default"]);
  });
});

// ---------------------------------------------------------------------------
// getWorkspaceCustomerId
// ---------------------------------------------------------------------------

describe("SentinelClient.getWorkspaceCustomerId", () => {
  const customerId = "11111111-2222-3333-4444-555555555555";

  it("GETs the encoded workspace resource with the pinned api-version and returns the GUID", async () => {
    const { fetchImpl, calls } = makeFakeFetch([
      { status: 200, body: { properties: { customerId } } },
    ]);
    const { provider } = makeTokenProvider("tok-ws");
    const client = new SentinelClient({ tokenProvider: provider, fetchImpl });

    const result = await client.getWorkspaceCustomerId({
      subscriptionId: "sub 1",
      resourceGroup: "rg/with/slashes",
      workspaceName: "ws name#1",
    });

    expect(result).toBe(customerId);
    expect(calls).toHaveLength(1);
    expect(calls[0]!.init?.method).toBe("GET");
    expect(headerValue(calls[0]!.init, "authorization")).toBe("Bearer tok-ws");
    expect(calls[0]!.url).toBe(
      "https://management.azure.com/subscriptions/sub%201" +
        "/resourceGroups/rg%2Fwith%2Fslashes" +
        "/providers/Microsoft.OperationalInsights/workspaces/ws%20name%231" +
        `?api-version=${WORKSPACE_API_VERSION}`,
    );
    expect(WORKSPACE_API_VERSION).toBe("2023-09-01");
  });

  it("surfaces the ARM error code, message, and HTTP status on 404", async () => {
    const { fetchImpl } = makeFakeFetch([
      {
        status: 404,
        body: { error: { code: "ResourceNotFound", message: "Workspace not found" } },
      },
    ]);
    const { provider } = makeTokenProvider();
    const client = new SentinelClient({ tokenProvider: provider, fetchImpl });

    await expect(client.getWorkspaceCustomerId(ws)).rejects.toThrow(
      /404.*ResourceNotFound.*Workspace not found/s,
    );
  });

  it("throws a clear error when a 2xx body lacks properties.customerId", async () => {
    const { fetchImpl } = makeFakeFetch([
      { status: 200, body: { properties: { provisioningState: "Succeeded" } } },
    ]);
    const { provider } = makeTokenProvider();
    const client = new SentinelClient({ tokenProvider: provider, fetchImpl });

    await expect(client.getWorkspaceCustomerId(ws)).rejects.toThrow(
      /did not include properties\.customerId/,
    );
  });
});
