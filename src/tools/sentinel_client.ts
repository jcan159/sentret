/**
 * Microsoft Sentinel ARM client: list analytics rules and (gated) deploy of
 * scheduled analytics rules.
 *
 * Safety: per docs/implementation_notes.md ("Sentinel Deployment") and the
 * system prompt (section 3), a rule must NEVER be created or updated without
 * explicit user approval. `createOrUpdateScheduledRule` enforces this with a
 * `confirmed` flag and refuses — before any network or token activity — when
 * it is not exactly `true`. The agent loop gates deployment as well; this
 * guard is defense in depth.
 */

import type {
  SentinelDeployResult,
  SentinelRuleSummary,
  SentinelScheduledRuleParams,
  SentinelWorkspaceRef,
  TokenProvider,
} from "../types.js";

/** Sentinel SecurityInsights ARM API version. Single const so upgrades are trivial. */
export const SENTINEL_API_VERSION = "2024-09-01";

/** Microsoft.OperationalInsights workspaces ARM API version. */
export const WORKSPACE_API_VERSION = "2023-09-01";

const DEFAULT_ARM_ENDPOINT = "https://management.azure.com";

export interface SentinelClientOptions {
  tokenProvider: TokenProvider;
  /** ARM management endpoint. Defaults to the Azure public cloud. */
  armEndpoint?: string;
  /**
   * ARM token scope. Defaults to the armEndpoint origin + "/.default" so
   * sovereign clouds (e.g. Azure Government) get the matching audience.
   * Escape hatch for clouds where audience and endpoint differ.
   */
  armScope?: string;
  /** Injectable fetch for testing. Defaults to global fetch. */
  fetchImpl?: typeof fetch;
}

// ---------------------------------------------------------------------------
// Defensive JSON helpers
// ---------------------------------------------------------------------------

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function asString(value: unknown): string | undefined {
  return typeof value === "string" ? value : undefined;
}

function asStringArray(value: unknown): string[] | undefined {
  if (!Array.isArray(value)) return undefined;
  return value.filter((item): item is string => typeof item === "string");
}

/** Maps one ARM alertRules list item to a SentinelRuleSummary, tolerating missing fields. */
function toRuleSummary(item: unknown): SentinelRuleSummary {
  const obj = isRecord(item) ? item : {};
  const props = isRecord(obj.properties) ? obj.properties : {};

  const summary: SentinelRuleSummary = {
    id: asString(obj.id) ?? "",
    name: asString(obj.name) ?? "",
    kind: asString(obj.kind) ?? "",
  };

  const displayName = asString(props.displayName);
  if (displayName !== undefined) summary.displayName = displayName;
  if (typeof props.enabled === "boolean") summary.enabled = props.enabled;
  const severity = asString(props.severity);
  if (severity !== undefined) summary.severity = severity;
  const query = asString(props.query);
  if (query !== undefined) summary.query = query;
  const tactics = asStringArray(props.tactics);
  if (tactics !== undefined) summary.tactics = tactics;
  const techniques = asStringArray(props.techniques);
  if (techniques !== undefined) summary.techniques = techniques;

  return summary;
}

/**
 * Builds an Error from a non-2xx ARM response, surfacing the standard
 * `{ error: { code, message } }` envelope plus the HTTP status.
 */
function armError(status: number, body: unknown, rawText: string): Error {
  let detail: string | undefined;
  if (isRecord(body) && isRecord(body.error)) {
    const code = asString(body.error.code);
    const message = asString(body.error.message);
    if (code !== undefined || message !== undefined) {
      detail = [code, message].filter((part) => part !== undefined).join(": ");
    }
  }
  if (detail === undefined) {
    detail = rawText.trim().slice(0, 500) || "no response body";
  }
  let message = `Sentinel ARM request failed (HTTP ${status}): ${detail}`;
  if (status === 403) {
    message +=
      " — access denied: the Microsoft Sentinel Contributor role on the target workspace is required to create or update analytics rules.";
  }
  return new Error(message);
}

// ---------------------------------------------------------------------------
// Client
// ---------------------------------------------------------------------------

/**
 * Thin Microsoft Sentinel (SecurityInsights) ARM client.
 *
 * - `listRules` enumerates all analytics rules in a workspace (follows
 *   `nextLink` paging until exhausted).
 * - `createOrUpdateScheduledRule` deploys a Scheduled analytics rule, but only
 *   when the caller passes `{ confirmed: true }` — explicit user approval.
 */
export class SentinelClient {
  private readonly tokenProvider: TokenProvider;
  private readonly armEndpoint: string;
  private readonly armScope: string;
  private readonly fetchImpl: typeof fetch;

  constructor(opts: SentinelClientOptions) {
    this.tokenProvider = opts.tokenProvider;
    this.armEndpoint = (opts.armEndpoint ?? DEFAULT_ARM_ENDPOINT).replace(/\/+$/, "");
    this.armScope = opts.armScope ?? `${new URL(this.armEndpoint).origin}/.default`;
    this.fetchImpl = opts.fetchImpl ?? fetch;
  }

  /**
   * Lists all alert rules in the given Sentinel workspace, following
   * `nextLink` pagination until the collection is exhausted.
   */
  async listRules(ws: SentinelWorkspaceRef): Promise<SentinelRuleSummary[]> {
    const rules: SentinelRuleSummary[] = [];
    let url: string | undefined =
      `${this.armEndpoint}${alertRulesPath(ws)}?api-version=${SENTINEL_API_VERSION}`;

    while (url !== undefined) {
      const { body } = await this.armRequest("GET", url);
      const value = isRecord(body) && Array.isArray(body.value) ? body.value : [];
      for (const item of value) {
        rules.push(toRuleSummary(item));
      }
      url = isRecord(body) ? asString(body.nextLink) : undefined;
    }

    return rules;
  }

  /**
   * Creates or updates a Scheduled analytics rule via ARM PUT.
   *
   * SAFETY: throws without any network or token activity unless
   * `opts.confirmed === true`. Explicit user approval is mandatory for any
   * Sentinel deployment (see docs/implementation_notes.md).
   */
  async createOrUpdateScheduledRule(
    params: SentinelScheduledRuleParams,
    opts: { confirmed: boolean },
  ): Promise<SentinelDeployResult> {
    if (opts.confirmed !== true) {
      throw new Error(
        "Sentinel deployment requires explicit user approval (confirmed: true was not set).",
      );
    }

    const rulePath = `${alertRulesPath({
      subscriptionId: params.subscription_id,
      resourceGroup: params.resource_group,
      workspaceName: params.workspace_name,
    })}/${encodeURIComponent(params.rule_id)}`;
    const url = `${this.armEndpoint}${rulePath}?api-version=${SENTINEL_API_VERSION}`;

    const { status, body } = await this.armRequest("PUT", url, {
      kind: "Scheduled",
      properties: buildScheduledRuleProperties(params),
    });

    return {
      ruleId: params.rule_id,
      resourceId: (isRecord(body) ? asString(body.id) : undefined) ?? rulePath,
      status: status === 201 ? "Created" : "Updated",
    };
  }

  /**
   * Resolves the Log Analytics workspace GUID (`properties.customerId`) for an
   * ARM workspace triple. Used to verify that the ARM coordinates actually
   * correspond to the workspace being analysed (workspace confinement).
   */
  async getWorkspaceCustomerId(ws: SentinelWorkspaceRef): Promise<string> {
    const url = `${this.armEndpoint}${workspacePath(ws)}?api-version=${WORKSPACE_API_VERSION}`;
    const { body } = await this.armRequest("GET", url);

    const props = isRecord(body) ? body.properties : undefined;
    const customerId = isRecord(props) ? asString(props.customerId) : undefined;
    if (customerId === undefined) {
      throw new Error(
        `Sentinel ARM workspace response for "${ws.workspaceName}" did not include ` +
          "properties.customerId; cannot verify the workspace GUID.",
      );
    }
    return customerId;
  }

  /** Performs an authenticated ARM request; throws an armError on non-2xx. */
  private async armRequest(
    method: "GET" | "PUT",
    url: string,
    requestBody?: unknown,
  ): Promise<{ status: number; body: unknown }> {
    const token = await this.tokenProvider.getToken(this.armScope);
    const headers: Record<string, string> = { Authorization: `Bearer ${token}` };
    if (requestBody !== undefined) {
      headers["Content-Type"] = "application/json";
    }

    const response = await this.fetchImpl(url, {
      method,
      headers,
      body: requestBody !== undefined ? JSON.stringify(requestBody) : undefined,
    });

    const text = await response.text();
    let body: unknown;
    if (text) {
      try {
        body = JSON.parse(text);
      } catch {
        body = undefined; // Non-JSON body; the raw text is used for errors.
      }
    }

    if (!response.ok) {
      throw armError(response.status, body, text);
    }
    return { status: response.status, body };
  }
}

// ---------------------------------------------------------------------------
// URL / body construction
// ---------------------------------------------------------------------------

/** ARM resource path of the Log Analytics workspace, with every segment URL-encoded. */
function workspacePath(ws: SentinelWorkspaceRef): string {
  return (
    `/subscriptions/${encodeURIComponent(ws.subscriptionId)}` +
    `/resourceGroups/${encodeURIComponent(ws.resourceGroup)}` +
    `/providers/Microsoft.OperationalInsights` +
    `/workspaces/${encodeURIComponent(ws.workspaceName)}`
  );
}

/** ARM resource path of the alertRules collection, with every segment URL-encoded. */
function alertRulesPath(ws: SentinelWorkspaceRef): string {
  return `${workspacePath(ws)}/providers/Microsoft.SecurityInsights/alertRules`;
}

/**
 * Normalises MITRE technique IDs to parent techniques and dedupes. The ARM
 * `techniques` field rejects sub-technique IDs (documented Sentinel 400: "The
 * technique 'T1071.001' is invalid. The expected format is 'T####'"), so
 * "T1110.003" must be sent as "T1110".
 */
function normaliseTechniques(techniques: string[] | undefined): string[] {
  return [...new Set((techniques ?? []).map((t) => t.split(".")[0] ?? t))];
}

/**
 * Maps snake_case tool params to the ARM camelCase `properties` payload for a
 * Scheduled rule. Optional ARM object fields are omitted entirely (never null)
 * when not provided. ARM requires both suppression fields on Scheduled rules,
 * so they always default (`false` / "PT5H").
 */
function buildScheduledRuleProperties(
  params: SentinelScheduledRuleParams,
): Record<string, unknown> {
  const properties: Record<string, unknown> = {
    displayName: params.display_name,
    description: params.description ?? "",
    severity: params.severity,
    enabled: params.enabled,
    query: params.query,
    queryFrequency: params.query_frequency,
    queryPeriod: params.query_period,
    triggerOperator: params.trigger_operator,
    triggerThreshold: params.trigger_threshold,
    suppressionEnabled: params.suppression_enabled ?? false,
    suppressionDuration: params.suppression_duration ?? "PT5H",
    tactics: params.tactics ?? [],
    techniques: normaliseTechniques(params.techniques),
  };

  if (params.entity_mappings !== undefined) {
    properties.entityMappings = params.entity_mappings;
  }
  if (params.custom_details !== undefined) {
    properties.customDetails = params.custom_details;
  }
  if (params.alert_details_override !== undefined) {
    properties.alertDetailsOverride = params.alert_details_override;
  }
  if (params.incident_configuration !== undefined) {
    properties.incidentConfiguration = params.incident_configuration;
  }
  if (params.event_grouping_settings !== undefined) {
    properties.eventGroupingSettings = params.event_grouping_settings;
  }

  return properties;
}
