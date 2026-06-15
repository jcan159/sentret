/**
 * Core domain types for the KQL Detection Rule Analyser.
 *
 * This file is the shared contract between modules. The report shape mirrors
 * schemas/json_report_schema.json; the request shape mirrors
 * examples/example_user_request.json plus the inputs listed in
 * prompts/system_prompt_full.md section 2.
 */

// ---------------------------------------------------------------------------
// Enumerations
// ---------------------------------------------------------------------------

export type AnalyserMode = "analyse_existing_rule" | "create_new_detection";
export type RiskLevel = "Low" | "Medium" | "High";
export type DataSensitivity = "Low" | "Medium" | "High" | "Restricted";
export type Severity = "Informational" | "Low" | "Medium" | "High";
export type Verdict =
  | "Deploy as-is"
  | "Deploy after changes"
  | "Test only"
  | "Do not deploy";
export type Rating =
  | "Excellent"
  | "Good"
  | "Needs Tuning"
  | "Weak"
  | "Not Deployable";
export type PerformanceRating =
  | "Excellent"
  | "Good"
  | "Moderate"
  | "Poor"
  | "Failed";
export type TriggerOperator =
  | "GreaterThan"
  | "LessThan"
  | "Equal"
  | "NotEqual";
export type ValidationQueryStatus = "Succeeded" | "Failed" | "Skipped";

// ---------------------------------------------------------------------------
// Analyser request (user input)
// ---------------------------------------------------------------------------

export interface AnalyserRequest {
  mode: AnalyserMode;
  detection_intent: string;
  workspace_id: string;
  /** ISO 8601 duration (e.g. "P7D", "PT24H") or start/end range ("2026-06-01/2026-06-08"). */
  timespan: string;
  /** Existing KQL — required when mode is "analyse_existing_rule". */
  kql?: string;
  relevant_data_sources?: string[];
  target_platform?: string;
  environment_context?: string;
  expected_entities?: string[];
  rule_frequency?: string;
  rule_period?: string;
  severity_preference?: Severity;
  mitre_tactics?: string[];
  mitre_techniques?: string[];
  noise_tolerance?: RiskLevel;
  sample_mode_allowed?: boolean;
  allow_query_execution?: boolean;
  allow_raw_examples?: boolean;
  /** Operator approval for broad patterns (union *, search, find) in validation queries. */
  allow_broad_queries?: boolean;
  data_sensitivity?: DataSensitivity;
  /**
   * Authoritative ARM coordinates for Sentinel operations. The Sentinel tools
   * are only exposed when this is present, and tool calls must match it.
   */
  sentinel_target?: {
    subscription_id: string;
    resource_group: string;
    workspace_name: string;
  };
}

// ---------------------------------------------------------------------------
// Analyser report (structured output) — mirrors schemas/json_report_schema.json
// ---------------------------------------------------------------------------

export interface AlternativeQuery {
  name: string;
  purpose: string;
  query: string;
}

export interface ValidationQueryRun {
  purpose: string;
  query: string;
  status: ValidationQueryStatus;
  row_count: number;
  error: string | null;
}

export interface DataAvailabilityEntry {
  table: string;
  exists: boolean;
  row_count: number;
  min_timegenerated: string | null;
  max_timegenerated: string | null;
}

export interface FieldPopulationEntry {
  table: string;
  field: string;
  populated_count: number;
  total_count: number;
  population_percent: number;
}

export interface SentinelEntityMapping {
  /** Sentinel entity type, e.g. "Account", "Host", "IP", "URL", "FileHash". */
  entityType: string;
  fieldMappings: { identifier: string; columnName: string }[];
}

export interface SentinelRuleConfig {
  display_name: string;
  description: string;
  enabled_recommendation: boolean;
  severity: Severity;
  query_frequency: string;
  query_period: string;
  trigger_operator: TriggerOperator;
  trigger_threshold: number;
  tactics: string[];
  techniques: string[];
  entity_mappings: SentinelEntityMapping[];
  custom_details: Record<string, string>;
  alert_details_override: Record<string, unknown>;
  incident_configuration: Record<string, unknown>;
  event_grouping_settings: Record<string, unknown>;
  suppression_enabled: boolean;
  suppression_duration: string | null;
}

export interface AnalyserReport {
  analysis_id: string;
  timestamp_utc: string;
  mode: AnalyserMode;
  workspace_id: string;
  detection_intent: string;
  verdict: Verdict;
  /** 0-100 per the scoring model in the system prompt (section 8). */
  overall_score: number;
  rating: Rating;
  summary: {
    main_finding: string;
    recommended_action: string;
    top_strengths: string[];
    top_issues: string[];
    required_fixes: string[];
  };
  kql: {
    original_query: string | null;
    recommended_query: string;
    alternative_queries: AlternativeQuery[];
  };
  static_review: {
    tables: string[];
    columns: string[];
    entities: string[];
    syntax_issues: string[];
    logic_issues: string[];
    schema_risks: string[];
    time_window_issues: string[];
    performance_risks: string[];
  };
  workspace_validation: {
    execution_allowed: boolean;
    timespan: string;
    queries_run: ValidationQueryRun[];
    data_availability: DataAvailabilityEntry[];
    field_population: FieldPopulationEntry[];
  };
  performance: {
    rating: PerformanceRating;
    execution_time_ms: number;
    statistics_available: boolean;
    statistics_summary: string;
    bottlenecks: string[];
    optimisations: string[];
  };
  detection_quality: {
    intent_alignment_score: number;
    syntax_schema_score: number;
    data_coverage_score: number;
    precision_score: number;
    recall_score: number;
    performance_score: number;
    sentinel_readiness_score: number;
    maintainability_score: number;
    false_positive_risk: RiskLevel;
    false_negative_risk: RiskLevel;
    known_blind_spots: string[];
  };
  sentinel_rule: SentinelRuleConfig;
  limitations: string[];
  assumptions: string[];
}

// ---------------------------------------------------------------------------
// Log Analytics query API
// ---------------------------------------------------------------------------

export interface KustoColumn {
  name: string;
  type: string;
}

export interface KustoTable {
  name: string;
  columns: KustoColumn[];
  rows: unknown[][];
}

export interface LogQueryError {
  code: string;
  message: string;
  details?: unknown;
}

export interface LogQueryResult {
  status: "Succeeded" | "PartialFailure" | "Failed";
  tables: KustoTable[];
  statistics?: Record<string, unknown>;
  dataSources?: Record<string, unknown>;
  error?: LogQueryError;
  /** Wall-clock duration of the HTTP round trip, in milliseconds. */
  durationMs: number;
}

export interface RunQueryOptions {
  workspaceId: string;
  query: string;
  /** ISO 8601 duration or start/end range. Always required. */
  timespan: string;
  additionalWorkspaces?: string[];
  includeStatistics?: boolean;
  includeDataSources?: boolean;
  /** Server-side wait limit in seconds (Prefer: wait=N). */
  waitSeconds?: number;
}

export interface WorkspaceTableSchema {
  table: string;
  columns: KustoColumn[];
}

// ---------------------------------------------------------------------------
// Query safety
// ---------------------------------------------------------------------------

export interface QuerySafetyOptions {
  /** Explicit user approval for broad `union *` / `search` / `find` patterns. */
  allowBroadQueries?: boolean;
  /** Maximum rows a `take`/`limit`/`sample` may request. Default 50. */
  maxSampleRows?: number;
  /** Maximum overall query length in characters. Default 20000. */
  maxQueryLength?: number;
  /**
   * When set, cross-resource resolvers (workspace(), cluster(), app(), adx(),
   * resource(), database()) are blocked unless their literal argument equals
   * this workspace ID. When unset, such resolvers are blocked outright.
   */
  allowedWorkspaceId?: string;
}

export interface QuerySafetyVerdict {
  allowed: boolean;
  /** Hard failures — the query must not be sent. */
  blockers: string[];
  /** Non-fatal concerns — the query may run but these should be surfaced. */
  warnings: string[];
}

// ---------------------------------------------------------------------------
// Audit log
// ---------------------------------------------------------------------------

export interface AuditRecord {
  timestamp_utc: string;
  workspace_id: string;
  purpose: string;
  query: string;
  timespan: string;
  outcome: "executed" | "blocked" | "failed" | "deployed";
  detail?: string;
}

// ---------------------------------------------------------------------------
// Sentinel ARM API
// ---------------------------------------------------------------------------

export interface SentinelWorkspaceRef {
  subscriptionId: string;
  resourceGroup: string;
  workspaceName: string;
}

/** Matches the create_or_update_sentinel_rule tool contract. */
export interface SentinelScheduledRuleParams {
  subscription_id: string;
  resource_group: string;
  workspace_name: string;
  rule_id: string;
  enabled: boolean;
  display_name: string;
  description?: string;
  severity: Severity;
  query: string;
  query_frequency: string;
  query_period: string;
  trigger_operator: TriggerOperator;
  trigger_threshold: number;
  tactics?: string[];
  techniques?: string[];
  entity_mappings?: SentinelEntityMapping[];
  custom_details?: Record<string, string>;
  alert_details_override?: Record<string, unknown>;
  incident_configuration?: Record<string, unknown>;
  event_grouping_settings?: Record<string, unknown>;
  suppression_enabled?: boolean;
  suppression_duration?: string;
}

export interface SentinelRuleSummary {
  id: string;
  name: string;
  kind: string;
  displayName?: string;
  enabled?: boolean;
  severity?: string;
  query?: string;
  tactics?: string[];
  techniques?: string[];
}

export interface SentinelDeployResult {
  ruleId: string;
  resourceId: string;
  status: "Created" | "Updated";
}

// ---------------------------------------------------------------------------
// MITRE ATT&CK lookup
// ---------------------------------------------------------------------------

export interface MitreTactic {
  id: string; // e.g. "TA0001"
  name: string; // e.g. "Initial Access"
  /** Sentinel tactic enum value, e.g. "InitialAccess". */
  sentinelName: string;
}

export interface MitreTechnique {
  id: string; // e.g. "T1110" or "T1110.003"
  name: string;
  tacticIds: string[];
}

export interface MitreLookupResult {
  query: string;
  tactics: MitreTactic[];
  techniques: MitreTechnique[];
  notes: string[];
}

// ---------------------------------------------------------------------------
// Auth
// ---------------------------------------------------------------------------

/** Thin abstraction over Azure credential acquisition so clients are testable. */
export interface TokenProvider {
  /** scope example: "https://api.loganalytics.azure.com/.default" */
  getToken(scope: string): Promise<string>;
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

export interface AnalyserConfig {
  /** Which LLM provider backs the agent loop. */
  provider: "anthropic" | "openai" | "azure";
  anthropicModel: string;
  /** Optional Anthropic model to retry on when the primary model refuses (stop_reason "refusal"). */
  fallbackModel?: string;
  /** Model id used when provider is "openai". */
  openaiModel: string;
  /** Base URL for OpenAI-compatible endpoints (OpenRouter, local servers). */
  openaiBaseUrl?: string;
  /** Azure AI Foundry / Azure OpenAI resource endpoint (provider "azure"). */
  azureEndpoint?: string;
  /** Azure deployment name (provider "azure"); falls back to openaiModel. */
  azureDeployment?: string;
  /** Azure OpenAI REST api-version (provider "azure"). */
  azureApiVersion: string;
  /**
   * Whether to send OpenAI/Azure reasoning_effort. "auto" infers from the model
   * name (unreliable for Azure deployment names — set "always"/"never" there).
   */
  reasoning: "auto" | "always" | "never";
  effort: "low" | "medium" | "high" | "xhigh" | "max";
  maxTokens: number;
  /** Maximum agent-loop iterations before aborting. */
  maxIterations: number;
  /** Master switch: Sentinel deployment is refused unless true. */
  allowDeploy: boolean;
  logAnalyticsEndpoint: string;
  armEndpoint: string;
  outputDir: string;
  auditLogPath: string;
  /** Cap on rows from any query result passed back to the model. */
  maxResultRows: number;
  /** Cap on serialized tool-result characters passed back to the model. */
  maxResultChars: number;
}
