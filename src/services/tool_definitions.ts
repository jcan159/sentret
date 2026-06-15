import { readFileSync } from "node:fs";
import type { LlmToolDef } from "../llm/types.js";

/**
 * Names of the tools exposed to the model. Centralised so the agent loop can
 * dispatch on them without magic strings.
 */
export const TOOL_NAMES = {
  runQuery: "run_log_analytics_query",
  getSchema: "get_workspace_schema",
  listRules: "list_sentinel_rules",
  deployRule: "create_or_update_sentinel_rule",
  mitre: "lookup_mitre_attack",
  submitReport: "submit_report",
} as const;

let cachedReportSchema: Record<string, unknown> | undefined;

/** Loads the analyser report JSON Schema (used as the submit_report input schema). */
export function loadReportSchema(): Record<string, unknown> {
  if (!cachedReportSchema) {
    cachedReportSchema = JSON.parse(
      readFileSync(new URL("../schemas/analyser_report.schema.json", import.meta.url), "utf8"),
    ) as Record<string, unknown>;
  }
  return cachedReportSchema;
}

export interface ToolGates {
  /** Expose Log Analytics query/schema tools (request.allow_query_execution). */
  allowQueryExecution: boolean;
  /** A Sentinel client is configured, so listing rules is possible. */
  sentinelConfigured: boolean;
  /** Deployment was explicitly approved by the operator (config.allowDeploy). */
  allowDeploy: boolean;
}

/**
 * Builds the provider-neutral tool definitions for one analysis run. Tools that
 * the run is not allowed to use are omitted entirely rather than gated in the
 * handler, so the model cannot even attempt them.
 */
export function buildToolDefinitions(gates: ToolGates): LlmToolDef[] {
  const tools: LlmToolDef[] = [];

  if (gates.allowQueryExecution) {
    tools.push({
      name: TOOL_NAMES.runQuery,
      description:
        "Runs a read-only KQL query against the target Azure Log Analytics workspace. " +
        "Every query passes a safety gate: an explicit bounded timespan is mandatory, " +
        "control commands and unbounded broad searches are blocked, and sample sizes are capped. " +
        "Prefer aggregated validation (count, summarize, getschema) over raw rows. " +
        "Results may be redacted server-side when raw examples are not allowed. " +
        "Always state an honest, specific purpose — it is written to an audit log.",
      inputSchema: {
        type: "object",
        properties: {
          workspace_id: {
            type: "string",
            description: "Log Analytics workspace GUID. Must be the workspace from the request.",
          },
          query: { type: "string", description: "KQL query to execute (read-only)." },
          timespan: {
            type: "string",
            description:
              'ISO 8601 duration ("PT24H", "P7D") or start/end range ("2026-06-01/2026-06-08"). Required.',
          },
          additional_workspaces: {
            type: "array",
            items: { type: "string" },
            description: "Optional additional workspace IDs for cross-workspace queries.",
          },
          prefer: {
            type: "object",
            description: "Query execution preferences.",
            properties: {
              include_statistics: {
                type: "boolean",
                description: "Request query statistics (always set true for performance review).",
              },
              include_data_sources: { type: "boolean" },
              wait_seconds: {
                type: "integer",
                description: "Server-side wait limit in seconds (default 300).",
              },
            },
          },
          purpose: {
            type: "string",
            description: "Why this query is being run. Written to the audit log.",
          },
          max_rows_expected: {
            type: "integer",
            description: "Expected maximum returned rows, for safety review.",
          },
        },
        required: ["workspace_id", "query", "timespan", "purpose"],
      },
    });

    tools.push({
      name: TOOL_NAMES.getSchema,
      description:
        "Retrieves the known tables, columns, and column types for a Log Analytics workspace " +
        "via the metadata API. Use this to verify referenced tables and fields exist before " +
        "running data queries.",
      inputSchema: {
        type: "object",
        properties: {
          workspace_id: { type: "string", description: "Log Analytics workspace GUID." },
          table_filter: {
            type: "string",
            description:
              "Optional case-insensitive substring filter on table names to keep the result small.",
          },
        },
        required: ["workspace_id"],
      },
    });
  }

  if (gates.sentinelConfigured) {
    tools.push({
      name: TOOL_NAMES.listRules,
      description:
        "Lists existing Microsoft Sentinel analytics rules in a workspace, to detect duplicate " +
        "logic, naming conflicts, and overlapping coverage before recommending a new rule. " +
        "The subscription/resource group/workspace must exactly match the operator-approved " +
        "Sentinel target given in the run constraints; anything else is blocked.",
      inputSchema: {
        type: "object",
        properties: {
          subscription_id: { type: "string" },
          resource_group: { type: "string" },
          workspace_name: { type: "string", description: "Log Analytics workspace resource name." },
        },
        required: ["subscription_id", "resource_group", "workspace_name"],
      },
    });
  }

  if (gates.sentinelConfigured && gates.allowDeploy) {
    tools.push({
      name: TOOL_NAMES.deployRule,
      description:
        "Creates or updates a Microsoft Sentinel scheduled analytics rule. The operator has " +
        "pre-approved deployment for this run, but you must still only call this after " +
        "presenting the final rule and only with the exact metadata the user approved. " +
        "The target must match the operator-approved Sentinel target from the run constraints.",
      inputSchema: {
        type: "object",
        properties: {
          subscription_id: { type: "string" },
          resource_group: { type: "string" },
          workspace_name: { type: "string" },
          rule_id: { type: "string", description: "GUID or stable identifier for the rule resource." },
          enabled: { type: "boolean" },
          display_name: { type: "string" },
          description: { type: "string" },
          severity: { type: "string", enum: ["Informational", "Low", "Medium", "High"] },
          query: { type: "string" },
          query_frequency: { type: "string", description: 'ISO 8601 duration, e.g. "PT1H".' },
          query_period: { type: "string", description: 'ISO 8601 duration, e.g. "P1D".' },
          trigger_operator: {
            type: "string",
            enum: ["GreaterThan", "LessThan", "Equal", "NotEqual"],
          },
          trigger_threshold: { type: "integer" },
          tactics: { type: "array", items: { type: "string" } },
          techniques: {
            type: "array",
            items: { type: "string" },
            description:
              "Parent technique IDs only (e.g. T1110). Sub-technique IDs are normalised to " +
              "their parent before deployment; record sub-techniques in the report instead.",
          },
          entity_mappings: { type: "array", items: { type: "object" } },
          custom_details: { type: "object" },
          alert_details_override: { type: "object" },
          incident_configuration: { type: "object" },
          event_grouping_settings: { type: "object" },
          suppression_enabled: { type: "boolean" },
          suppression_duration: { type: "string" },
        },
        required: [
          "subscription_id",
          "resource_group",
          "workspace_name",
          "rule_id",
          "display_name",
          "enabled",
          "severity",
          "query",
          "query_frequency",
          "query_period",
          "trigger_operator",
          "trigger_threshold",
        ],
      },
    });
  }

  tools.push({
    name: TOOL_NAMES.mitre,
    description:
      "Looks up MITRE ATT&CK tactics, techniques, and sub-techniques by ID or name from a " +
      "curated offline dataset. Use it to validate and normalise the tactics/techniques you " +
      "put in the Sentinel rule metadata.",
    inputSchema: {
      type: "object",
      properties: {
        query: {
          type: "string",
          description:
            'IDs or names, comma-separated. Examples: "T1110.003, TA0006", "brute force, lateral movement".',
        },
      },
      required: ["query"],
    },
  });

  tools.push({
    name: TOOL_NAMES.submitReport,
    description:
      "Submits the final structured analysis report. You MUST call this exactly once, after " +
      "your analysis is complete and before writing your final markdown answer. The input is " +
      "validated; if it is rejected, fix the listed problems and call it again.",
    inputSchema: loadReportSchema(),
  });

  return tools;
}
