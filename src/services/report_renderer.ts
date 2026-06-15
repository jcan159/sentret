/**
 * Report rendering, validation, and persistence for the KQL Detection Rule
 * Analyser.
 *
 * - {@link renderMarkdownReport} renders the 13-section markdown layout from
 *   prompts/system_prompt_full.md section 10.
 * - {@link validateReport} structurally validates LLM-produced JSON against
 *   the AnalyserReport contract before it is rendered or saved.
 * - {@link saveReport} persists a report as pretty-printed JSON and/or
 *   rendered markdown.
 * - {@link buildSampleReport} returns a fully-populated, type-checked sample
 *   report for tests and smoke checks.
 */

import { mkdir, writeFile } from "node:fs/promises";
import path from "node:path";

import type {
  AnalyserMode,
  AnalyserReport,
  PerformanceRating,
  Rating,
  RiskLevel,
  Severity,
  TriggerOperator,
  ValidationQueryStatus,
  Verdict,
} from "../types.js";

// ---------------------------------------------------------------------------
// Enum value lists (kept in sync with src/types.ts)
// ---------------------------------------------------------------------------

const MODES: readonly AnalyserMode[] = [
  "analyse_existing_rule",
  "create_new_detection",
];
const VERDICTS: readonly Verdict[] = [
  "Deploy as-is",
  "Deploy after changes",
  "Test only",
  "Do not deploy",
];
const RATINGS: readonly Rating[] = [
  "Excellent",
  "Good",
  "Needs Tuning",
  "Weak",
  "Not Deployable",
];
const PERFORMANCE_RATINGS: readonly PerformanceRating[] = [
  "Excellent",
  "Good",
  "Moderate",
  "Poor",
  "Failed",
];
const SEVERITIES: readonly Severity[] = [
  "Informational",
  "Low",
  "Medium",
  "High",
];
const TRIGGER_OPERATORS: readonly TriggerOperator[] = [
  "GreaterThan",
  "LessThan",
  "Equal",
  "NotEqual",
];
const RISK_LEVELS: readonly RiskLevel[] = ["Low", "Medium", "High"];
const VALIDATION_STATUSES: readonly ValidationQueryStatus[] = [
  "Succeeded",
  "Failed",
  "Skipped",
];

// ---------------------------------------------------------------------------
// Markdown helpers
// ---------------------------------------------------------------------------

const NONE = "None.";

function bullets(items: readonly string[]): string {
  if (items.length === 0) return NONE;
  return items.map((item) => `- ${item}`).join("\n");
}

function csv(items: readonly string[]): string {
  return items.length === 0 ? NONE : items.join(", ");
}

function kqlFence(query: string): string {
  return "```kql\n" + query + "\n```";
}

function yesNo(value: boolean): string {
  return value ? "Yes" : "No";
}

/** Escapes a value for use inside a markdown table cell. Null becomes an em dash. */
function cell(value: unknown): string {
  if (value === null || value === undefined) return "—";
  return String(value).replace(/\|/g, "\\|").replace(/\r?\n/g, " ");
}

function mdTable(headers: readonly string[], rows: readonly string[][]): string {
  if (rows.length === 0) return NONE;
  const head = `| ${headers.join(" | ")} |`;
  const separator = `| ${headers.map(() => "---").join(" | ")} |`;
  const body = rows.map((row) => `| ${row.join(" | ")} |`).join("\n");
  return [head, separator, body].join("\n");
}

function freeFormMap(value: Record<string, unknown>): string {
  return Object.keys(value).length === 0 ? NONE : `\`${JSON.stringify(value)}\``;
}

// ---------------------------------------------------------------------------
// renderMarkdownReport
// ---------------------------------------------------------------------------

/**
 * Renders an {@link AnalyserReport} as the 13-section markdown report defined
 * in the system prompt ("Output Format"). Output is fully deterministic: it
 * depends only on the report contents (no clocks, no randomness). Empty lists
 * render as "None." so every section is always present.
 */
export function renderMarkdownReport(report: AnalyserReport): string {
  const { summary, kql, static_review, workspace_validation, performance } =
    report;
  const quality = report.detection_quality;
  const rule = report.sentinel_rule;

  const sections: string[] = [];

  sections.push("# KQL Detection Rule Analysis");

  sections.push(
    [
      "## 1. Executive Summary",
      `- Verdict: ${report.verdict}`,
      `- Overall Score: ${report.overall_score} / 100`,
      `- Deployability: ${report.rating}`,
      `- Main Finding: ${summary.main_finding}`,
      `- Recommended Action: ${summary.recommended_action}`,
      "",
      "**Top Strengths**",
      "",
      bullets(summary.top_strengths),
      "",
      "**Top Issues**",
      "",
      bullets(summary.top_issues),
      "",
      "**Required Fixes**",
      "",
      bullets(summary.required_fixes),
    ].join("\n"),
  );

  sections.push(
    [
      "## 2. Detection Intent Interpretation",
      `- Analysis ID: ${report.analysis_id}`,
      `- Timestamp (UTC): ${report.timestamp_utc}`,
      `- Mode: ${report.mode}`,
      "",
      report.detection_intent,
    ].join("\n"),
  );

  const entityTypes = rule.entity_mappings.map((m) => m.entityType);
  sections.push(
    [
      "## 3. Rule Overview",
      `- Data sources (tables): ${csv(static_review.tables)}`,
      `- Key fields: ${csv(static_review.columns)}`,
      `- Entities: ${csv(static_review.entities)}`,
      `- MITRE mapping: Tactics: ${csv(rule.tactics)} — Techniques: ${csv(rule.techniques)}`,
      `- Expected alert shape: "${rule.display_name}" (Severity: ${rule.severity}; ` +
        `trigger ${rule.trigger_operator} ${rule.trigger_threshold}; ` +
        `mapped entities: ${csv(entityTypes)})`,
    ].join("\n"),
  );

  sections.push(
    [
      "## 4. Static KQL Review",
      "**Syntax issues**",
      "",
      bullets(static_review.syntax_issues),
      "",
      "**Logic issues**",
      "",
      bullets(static_review.logic_issues),
      "",
      "**Schema risks**",
      "",
      bullets(static_review.schema_risks),
      "",
      "**Time-window issues**",
      "",
      bullets(static_review.time_window_issues),
      "",
      "**Performance risks**",
      "",
      bullets(static_review.performance_risks),
    ].join("\n"),
  );

  if (!workspace_validation.execution_allowed) {
    sections.push(
      [
        "## 5. Live Workspace Validation",
        "Query execution was not allowed; static analysis only.",
      ].join("\n"),
    );
  } else {
    sections.push(
      [
        "## 5. Live Workspace Validation",
        `- Workspace: ${report.workspace_id}`,
        `- Timespan: ${workspace_validation.timespan}`,
        "",
        "**Validation queries run**",
        "",
        mdTable(
          ["#", "Purpose", "Status", "Rows", "Error"],
          workspace_validation.queries_run.map((run, index) => [
            cell(index + 1),
            cell(run.purpose),
            cell(run.status),
            cell(run.row_count),
            cell(run.error),
          ]),
        ),
        "",
        "**Data availability**",
        "",
        mdTable(
          ["Table", "Exists", "Rows", "Min TimeGenerated", "Max TimeGenerated"],
          workspace_validation.data_availability.map((entry) => [
            cell(entry.table),
            cell(yesNo(entry.exists)),
            cell(entry.row_count),
            cell(entry.min_timegenerated),
            cell(entry.max_timegenerated),
          ]),
        ),
        "",
        "**Field population**",
        "",
        mdTable(
          ["Table", "Field", "Populated", "Total", "Population %"],
          workspace_validation.field_population.map((entry) => [
            cell(entry.table),
            cell(entry.field),
            cell(entry.populated_count),
            cell(entry.total_count),
            cell(entry.population_percent),
          ]),
        ),
      ].join("\n"),
    );
  }

  sections.push(
    [
      "## 6. Performance Review",
      `- Performance rating: ${performance.rating}`,
      `- Runtime: ${performance.execution_time_ms} ms`,
      `- Statistics available: ${yesNo(performance.statistics_available)}`,
      `- Statistics summary: ${performance.statistics_summary || NONE}`,
      "",
      "**Bottlenecks**",
      "",
      bullets(performance.bottlenecks),
      "",
      "**Optimisations**",
      "",
      bullets(performance.optimisations),
    ].join("\n"),
  );

  sections.push(
    [
      "## 7. Detection Quality Assessment",
      `- Intent alignment: ${quality.intent_alignment_score} / 20`,
      `- Syntax & schema correctness: ${quality.syntax_schema_score} / 15`,
      `- Data availability & coverage: ${quality.data_coverage_score} / 10`,
      `- Precision: ${quality.precision_score} / 15`,
      `- Recall: ${quality.recall_score} / 10`,
      `- Performance: ${quality.performance_score} / 15`,
      `- Sentinel readiness: ${quality.sentinel_readiness_score} / 10`,
      `- Maintainability: ${quality.maintainability_score} / 5`,
      `- False positive risk: ${quality.false_positive_risk}`,
      `- False negative risk: ${quality.false_negative_risk}`,
      "",
      "**Known blind spots**",
      "",
      bullets(quality.known_blind_spots),
    ].join("\n"),
  );

  const recommendedKql = ["## 8. Recommended KQL", kqlFence(kql.recommended_query)];
  if (kql.alternative_queries.length > 0) {
    recommendedKql.push("", "**Alternative queries**");
    for (const alt of kql.alternative_queries) {
      recommendedKql.push("", `*${alt.name}* — ${alt.purpose}`, "", kqlFence(alt.query));
    }
  }
  sections.push(recommendedKql.join("\n"));

  if (kql.original_query === null) {
    sections.push(
      [
        "## 9. Explanation of Changes",
        "No original query was provided; the recommended query was authored " +
          "from the detection intent (create-new mode).",
      ].join("\n"),
    );
  } else {
    sections.push(
      [
        "## 9. Explanation of Changes",
        "**Original query**",
        "",
        kqlFence(kql.original_query),
        "",
        "**Changes applied / required**",
        "",
        bullets(summary.required_fixes),
      ].join("\n"),
    );
  }

  const entityMappingLines =
    rule.entity_mappings.length === 0
      ? NONE
      : rule.entity_mappings
          .map(
            (mapping) =>
              `- ${mapping.entityType}: ` +
              (mapping.fieldMappings.length === 0
                ? NONE
                : mapping.fieldMappings
                    .map((fm) => `${fm.identifier} ← ${fm.columnName}`)
                    .join(", ")),
          )
          .join("\n");

  sections.push(
    [
      "## 10. Sentinel Rule Configuration",
      `- Display name: ${rule.display_name}`,
      `- Description: ${rule.description}`,
      `- Recommended enabled state: ${rule.enabled_recommendation ? "Enabled" : "Disabled"}`,
      `- Severity: ${rule.severity}`,
      `- Query frequency: ${rule.query_frequency}`,
      `- Query period: ${rule.query_period}`,
      `- Trigger: ${rule.trigger_operator} ${rule.trigger_threshold}`,
      `- Tactics: ${csv(rule.tactics)}`,
      `- Techniques: ${csv(rule.techniques)}`,
      `- Custom details: ${freeFormMap(rule.custom_details)}`,
      `- Alert details override: ${freeFormMap(rule.alert_details_override)}`,
      `- Incident configuration: ${freeFormMap(rule.incident_configuration)}`,
      `- Event grouping: ${freeFormMap(rule.event_grouping_settings)}`,
      `- Suppression: ${
        rule.suppression_enabled
          ? `Enabled (${rule.suppression_duration ?? "no duration set"})`
          : "Disabled"
      }`,
      "",
      "**Entity mappings**",
      "",
      entityMappingLines,
    ].join("\n"),
  );

  const validationQueries = ["## 11. Validation Queries"];
  if (workspace_validation.queries_run.length === 0) {
    validationQueries.push(NONE);
  } else {
    workspace_validation.queries_run.forEach((run, index) => {
      if (index > 0) validationQueries.push("");
      validationQueries.push(
        `**${index + 1}. ${run.purpose}** — ${run.status}, ${run.row_count} row(s)` +
          (run.error === null ? "" : ` — error: ${run.error}`),
        "",
        kqlFence(run.query),
      );
    });
  }
  sections.push(validationQueries.join("\n"));

  sections.push(
    [
      "## 12. Limitations and Assumptions",
      "**Limitations**",
      "",
      bullets(report.limitations),
      "",
      "**Assumptions**",
      "",
      bullets(report.assumptions),
    ].join("\n"),
  );

  sections.push(
    [
      "## 13. Final Recommendation",
      `- Verdict: ${report.verdict}`,
      `- Guidance: ${summary.recommended_action}`,
    ].join("\n"),
  );

  return sections.join("\n\n") + "\n";
}

// ---------------------------------------------------------------------------
// validateReport
// ---------------------------------------------------------------------------

function describeValue(value: unknown): string {
  if (value === null) return "null";
  if (Array.isArray(value)) return "array";
  return typeof value;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

class Checker {
  readonly errors: string[] = [];

  private check(
    obj: Record<string, unknown>,
    key: string,
    base: string,
    predicate: (v: unknown) => boolean,
    expected: string,
  ): void {
    const fieldPath = base === "" ? key : `${base}.${key}`;
    if (!(key in obj)) {
      this.errors.push(`${fieldPath}: missing required field`);
      return;
    }
    const value = obj[key];
    if (!predicate(value)) {
      this.errors.push(
        `${fieldPath}: expected ${expected}, got ${describeValue(value)}`,
      );
    }
  }

  string(obj: Record<string, unknown>, key: string, base = ""): void {
    this.check(obj, key, base, (v) => typeof v === "string", "string");
  }

  nullableString(obj: Record<string, unknown>, key: string, base = ""): void {
    this.check(
      obj,
      key,
      base,
      (v) => v === null || typeof v === "string",
      "string or null",
    );
  }

  number(obj: Record<string, unknown>, key: string, base = ""): void {
    this.check(
      obj,
      key,
      base,
      (v) => typeof v === "number" && Number.isFinite(v),
      "number",
    );
  }

  boolean(obj: Record<string, unknown>, key: string, base = ""): void {
    this.check(obj, key, base, (v) => typeof v === "boolean", "boolean");
  }

  array(obj: Record<string, unknown>, key: string, base = ""): void {
    this.check(obj, key, base, (v) => Array.isArray(v), "array");
  }

  /**
   * Checks that obj[key] is an array whose every element is a string.
   * Element failures use dotted, indexed paths, e.g. "summary.top_issues[1]".
   */
  stringArray(obj: Record<string, unknown>, key: string, base = ""): void {
    this.array(obj, key, base);
    const value = obj[key];
    if (!Array.isArray(value)) return;
    const items: unknown[] = value;
    const fieldPath = base === "" ? key : `${base}.${key}`;
    items.forEach((item, index) => {
      if (typeof item !== "string") {
        this.errors.push(
          `${fieldPath}[${index}]: expected string, got ${describeValue(item)}`,
        );
      }
    });
  }

  /**
   * Checks that obj[key] is an array of objects and runs checkItem against
   * each element, passing the element's dotted, indexed path (e.g.
   * "sentinel_rule.entity_mappings[0]") as the base for nested checks.
   * Non-object elements are reported and skipped.
   */
  objectArray(
    obj: Record<string, unknown>,
    key: string,
    base: string,
    checkItem: (item: Record<string, unknown>, itemPath: string) => void,
  ): void {
    this.array(obj, key, base);
    const value = obj[key];
    if (!Array.isArray(value)) return;
    const items: unknown[] = value;
    const fieldPath = base === "" ? key : `${base}.${key}`;
    items.forEach((item, index) => {
      const itemPath = `${fieldPath}[${index}]`;
      if (!isRecord(item)) {
        this.errors.push(
          `${itemPath}: expected object, got ${describeValue(item)}`,
        );
        return;
      }
      checkItem(item, itemPath);
    });
  }

  object(obj: Record<string, unknown>, key: string, base = ""): void {
    this.check(obj, key, base, (v) => isRecord(v), "object");
  }

  enum(
    obj: Record<string, unknown>,
    key: string,
    allowed: readonly string[],
    base = "",
  ): void {
    this.check(
      obj,
      key,
      base,
      (v) => typeof v === "string" && allowed.includes(v),
      `one of [${allowed.join(", ")}]`,
    );
  }

  /** Returns the nested object for deeper checks, or undefined after recording an error. */
  section(
    obj: Record<string, unknown>,
    key: string,
  ): Record<string, unknown> | undefined {
    this.object(obj, key);
    const value = obj[key];
    return isRecord(value) ? value : undefined;
  }
}

/**
 * Structurally validates an unknown value (typically LLM-produced JSON)
 * against the {@link AnalyserReport} contract.
 *
 * Checks presence and primitive type of every top-level field, one level into
 * each nested section, and enum membership for mode, verdict, rating,
 * severity, trigger operator, performance rating, risk levels and validation
 * query status. Array fields are validated per element: string arrays must
 * contain only strings, and arrays of objects (alternative queries, validation
 * runs, data availability, field population, entity mappings and their field
 * mappings) have each element's shape checked with dotted, indexed error
 * paths (e.g. "sentinel_rule.entity_mappings[0].fieldMappings"). This is the
 * defensive gate for {@link renderMarkdownReport}: any report this function
 * accepts can be rendered without throwing. All errors are collected —
 * validation does not stop at the first failure.
 */
export function validateReport(value: unknown): {
  valid: boolean;
  errors: string[];
} {
  if (!isRecord(value)) {
    return {
      valid: false,
      errors: [`report: expected an object, got ${describeValue(value)}`],
    };
  }

  const c = new Checker();

  c.string(value, "analysis_id");
  c.string(value, "timestamp_utc");
  c.enum(value, "mode", MODES);
  c.string(value, "workspace_id");
  c.string(value, "detection_intent");
  c.enum(value, "verdict", VERDICTS);
  c.number(value, "overall_score");
  c.enum(value, "rating", RATINGS);

  const summary = c.section(value, "summary");
  if (summary) {
    c.string(summary, "main_finding", "summary");
    c.string(summary, "recommended_action", "summary");
    c.stringArray(summary, "top_strengths", "summary");
    c.stringArray(summary, "top_issues", "summary");
    c.stringArray(summary, "required_fixes", "summary");
  }

  const kql = c.section(value, "kql");
  if (kql) {
    c.nullableString(kql, "original_query", "kql");
    c.string(kql, "recommended_query", "kql");
    c.objectArray(kql, "alternative_queries", "kql", (item, itemPath) => {
      c.string(item, "name", itemPath);
      c.string(item, "purpose", itemPath);
      c.string(item, "query", itemPath);
    });
  }

  const staticReview = c.section(value, "static_review");
  if (staticReview) {
    for (const key of [
      "tables",
      "columns",
      "entities",
      "syntax_issues",
      "logic_issues",
      "schema_risks",
      "time_window_issues",
      "performance_risks",
    ]) {
      c.stringArray(staticReview, key, "static_review");
    }
  }

  const validation = c.section(value, "workspace_validation");
  if (validation) {
    c.boolean(validation, "execution_allowed", "workspace_validation");
    c.string(validation, "timespan", "workspace_validation");
    c.objectArray(
      validation,
      "queries_run",
      "workspace_validation",
      (item, itemPath) => {
        c.string(item, "purpose", itemPath);
        c.string(item, "query", itemPath);
        c.enum(item, "status", VALIDATION_STATUSES, itemPath);
        c.number(item, "row_count", itemPath);
        c.nullableString(item, "error", itemPath);
      },
    );
    c.objectArray(
      validation,
      "data_availability",
      "workspace_validation",
      (item, itemPath) => {
        c.string(item, "table", itemPath);
        c.boolean(item, "exists", itemPath);
        c.number(item, "row_count", itemPath);
        c.nullableString(item, "min_timegenerated", itemPath);
        c.nullableString(item, "max_timegenerated", itemPath);
      },
    );
    c.objectArray(
      validation,
      "field_population",
      "workspace_validation",
      (item, itemPath) => {
        c.string(item, "table", itemPath);
        c.string(item, "field", itemPath);
        c.number(item, "populated_count", itemPath);
        c.number(item, "total_count", itemPath);
        c.number(item, "population_percent", itemPath);
      },
    );
  }

  const performance = c.section(value, "performance");
  if (performance) {
    c.enum(performance, "rating", PERFORMANCE_RATINGS, "performance");
    c.number(performance, "execution_time_ms", "performance");
    c.boolean(performance, "statistics_available", "performance");
    c.string(performance, "statistics_summary", "performance");
    c.array(performance, "bottlenecks", "performance");
    c.array(performance, "optimisations", "performance");
  }

  const quality = c.section(value, "detection_quality");
  if (quality) {
    for (const key of [
      "intent_alignment_score",
      "syntax_schema_score",
      "data_coverage_score",
      "precision_score",
      "recall_score",
      "performance_score",
      "sentinel_readiness_score",
      "maintainability_score",
    ]) {
      c.number(quality, key, "detection_quality");
    }
    c.enum(quality, "false_positive_risk", RISK_LEVELS, "detection_quality");
    c.enum(quality, "false_negative_risk", RISK_LEVELS, "detection_quality");
    c.stringArray(quality, "known_blind_spots", "detection_quality");
  }

  const rule = c.section(value, "sentinel_rule");
  if (rule) {
    c.string(rule, "display_name", "sentinel_rule");
    c.string(rule, "description", "sentinel_rule");
    c.boolean(rule, "enabled_recommendation", "sentinel_rule");
    c.enum(rule, "severity", SEVERITIES, "sentinel_rule");
    c.string(rule, "query_frequency", "sentinel_rule");
    c.string(rule, "query_period", "sentinel_rule");
    c.enum(rule, "trigger_operator", TRIGGER_OPERATORS, "sentinel_rule");
    c.number(rule, "trigger_threshold", "sentinel_rule");
    c.stringArray(rule, "tactics", "sentinel_rule");
    c.stringArray(rule, "techniques", "sentinel_rule");
    c.objectArray(rule, "entity_mappings", "sentinel_rule", (mapping, mappingPath) => {
      c.string(mapping, "entityType", mappingPath);
      c.objectArray(mapping, "fieldMappings", mappingPath, (fm, fmPath) => {
        c.string(fm, "identifier", fmPath);
        c.string(fm, "columnName", fmPath);
      });
    });
    c.object(rule, "custom_details", "sentinel_rule");
    c.object(rule, "alert_details_override", "sentinel_rule");
    c.object(rule, "incident_configuration", "sentinel_rule");
    c.object(rule, "event_grouping_settings", "sentinel_rule");
    c.boolean(rule, "suppression_enabled", "sentinel_rule");
    c.nullableString(rule, "suppression_duration", "sentinel_rule");
  }

  c.stringArray(value, "limitations");
  c.stringArray(value, "assumptions");

  return { valid: c.errors.length === 0, errors: c.errors };
}

// ---------------------------------------------------------------------------
// saveReport
// ---------------------------------------------------------------------------

/** Replaces filesystem-unsafe characters in an analysis id with underscores. */
function sanitiseAnalysisId(analysisId: string): string {
  const safe = analysisId.replace(/[^A-Za-z0-9._-]/g, "_");
  return safe === "" ? "report" : safe;
}

/**
 * Persists a report to disk as `analysis_<analysis_id>.json` (pretty-printed,
 * 2-space indent) and/or `analysis_<analysis_id>.md` (rendered markdown).
 *
 * The output directory is created recursively if missing, and the analysis id
 * is sanitised for filesystem use ([A-Za-z0-9._-] kept, everything else
 * replaced with "_"). Defaults to writing both formats.
 *
 * @returns Absolute paths of the files written, in format order.
 */
export async function saveReport(
  report: AnalyserReport,
  opts: { outputDir: string; formats?: ("json" | "md")[] },
): Promise<string[]> {
  const formats = opts.formats ?? ["json", "md"];
  await mkdir(opts.outputDir, { recursive: true });
  const baseName = `analysis_${sanitiseAnalysisId(report.analysis_id)}`;

  const written: string[] = [];
  for (const format of formats) {
    const filePath = path.join(opts.outputDir, `${baseName}.${format}`);
    const content =
      format === "json"
        ? JSON.stringify(report, null, 2) + "\n"
        : renderMarkdownReport(report);
    await writeFile(filePath, content, "utf8");
    written.push(filePath);
  }
  return written;
}

// ---------------------------------------------------------------------------
// buildSampleReport
// ---------------------------------------------------------------------------

/**
 * Builds a fully-populated, deterministic {@link AnalyserReport} that
 * exercises every field of the contract. Used by tests (including the
 * schema-drift test) and handy for downstream smoke tests. Each call returns
 * a fresh object that is safe to mutate.
 */
export function buildSampleReport(): AnalyserReport {
  return {
    analysis_id: "sample-0001",
    timestamp_utc: "2026-06-12T00:00:00Z",
    mode: "analyse_existing_rule",
    workspace_id: "00000000-0000-0000-0000-000000000000",
    detection_intent:
      "Detect password spray activity against Entra ID accounts: many failed " +
      "sign-ins from a single IP across multiple distinct accounts within a " +
      "short window.",
    verdict: "Deploy after changes",
    overall_score: 78,
    rating: "Good",
    summary: {
      main_finding:
        "The rule detects the intended spray pattern but lacks a TimeGenerated " +
        "filter and over-counts due to an unbounded summarize.",
      recommended_action:
        "Apply the recommended query, add entity mappings, and test in audit " +
        "mode for one week before enabling.",
      top_strengths: [
        "Clear intent alignment with distinct-account thresholding",
        "Uses well-populated SigninLogs fields",
        "Output columns are analyst-actionable",
      ],
      top_issues: [
        "Missing early TimeGenerated filter",
        "No entity mappings defined in the original rule",
        "Threshold may be noisy for shared egress IPs",
      ],
      required_fixes: [
        "Add `| where TimeGenerated >= ago(1h)` before any summarize",
        "Map Account and IP entities",
        "Raise the distinct-account threshold from 3 to 8",
      ],
    },
    kql: {
      original_query:
        'SigninLogs\n| where ResultType != "0"\n| summarize Attempts = count() by IPAddress',
      recommended_query:
        "let Lookback = 1h;\n" +
        "let AccountThreshold = 8;\n" +
        "SigninLogs\n" +
        "| where TimeGenerated >= ago(Lookback)\n" +
        '| where ResultType != "0"\n' +
        "| summarize\n" +
        "    FailedAttempts = count(),\n" +
        "    DistinctAccounts = dcount(UserPrincipalName),\n" +
        "    FirstSeen = min(TimeGenerated),\n" +
        "    LastSeen = max(TimeGenerated)\n" +
        "    by IPAddress\n" +
        "| where DistinctAccounts >= AccountThreshold\n" +
        '| extend DetectionReason = strcat("Password spray from ", IPAddress)',
      alternative_queries: [
        {
          name: "Per-application spray view",
          purpose:
            "Splits the spray pattern by AppDisplayName to spot app-targeted sprays.",
          query:
            "SigninLogs\n| where TimeGenerated >= ago(1h)\n" +
            '| where ResultType != "0"\n' +
            "| summarize DistinctAccounts = dcount(UserPrincipalName) by IPAddress, AppDisplayName\n" +
            "| where DistinctAccounts >= 5",
        },
      ],
    },
    static_review: {
      tables: ["SigninLogs"],
      columns: ["TimeGenerated", "ResultType", "UserPrincipalName", "IPAddress"],
      entities: ["Account", "IP"],
      syntax_issues: [],
      logic_issues: [
        "Original query counts raw failures, not distinct accounts, so a single " +
          "noisy account can trigger it",
      ],
      schema_risks: [
        "ResultType is a string column; numeric comparison would fail silently",
      ],
      time_window_issues: [
        "No TimeGenerated filter — the query scans the full retention window",
      ],
      performance_risks: [
        "Unbounded summarize over the whole table before any filter",
      ],
    },
    workspace_validation: {
      execution_allowed: true,
      timespan: "P7D",
      queries_run: [
        {
          purpose: "Confirm SigninLogs has recent data",
          query: "SigninLogs | summarize count() by bin(TimeGenerated, 1d)",
          status: "Succeeded",
          row_count: 7,
          error: null,
        },
        {
          purpose: "Check IPAddress field population",
          query:
            "SigninLogs | summarize populated = countif(isnotempty(IPAddress)), total = count()",
          status: "Succeeded",
          row_count: 1,
          error: null,
        },
        {
          purpose: "Dry-run the recommended detection",
          query: "SigninLogs | take 0",
          status: "Failed",
          row_count: 0,
          error: "Partial failure: one shard timed out",
        },
      ],
      data_availability: [
        {
          table: "SigninLogs",
          exists: true,
          row_count: 184_230,
          min_timegenerated: "2026-06-05T00:03:11Z",
          max_timegenerated: "2026-06-12T09:58:42Z",
        },
        {
          table: "AADNonInteractiveUserSignInLogs",
          exists: false,
          row_count: 0,
          min_timegenerated: null,
          max_timegenerated: null,
        },
      ],
      field_population: [
        {
          table: "SigninLogs",
          field: "IPAddress",
          populated_count: 184_001,
          total_count: 184_230,
          population_percent: 99.9,
        },
        {
          table: "SigninLogs",
          field: "UserPrincipalName",
          populated_count: 184_230,
          total_count: 184_230,
          population_percent: 100,
        },
      ],
    },
    performance: {
      rating: "Good",
      execution_time_ms: 2350,
      statistics_available: true,
      statistics_summary:
        "Scanned ~180k rows over 7 days; single summarize stage; no cross-cluster joins.",
      bottlenecks: ["dcount over UserPrincipalName dominates CPU time"],
      optimisations: [
        "Early TimeGenerated filter reduces scanned rows by ~85%",
        "Project only required columns before summarize",
      ],
    },
    detection_quality: {
      intent_alignment_score: 18,
      syntax_schema_score: 13,
      data_coverage_score: 9,
      precision_score: 10,
      recall_score: 7,
      performance_score: 12,
      sentinel_readiness_score: 6,
      maintainability_score: 3,
      false_positive_risk: "Medium",
      false_negative_risk: "Low",
      known_blind_spots: [
        "Low-and-slow sprays below the hourly threshold",
        "Sprays distributed across many source IPs",
      ],
    },
    sentinel_rule: {
      display_name: "Password Spray From Single IP Against Multiple Accounts",
      description:
        "Detects a single source IP generating failed sign-ins across 8 or more " +
        "distinct accounts within one hour, indicating likely password spray. " +
        "Triage by checking whether the IP is a known corporate egress point.",
      enabled_recommendation: false,
      severity: "Medium",
      query_frequency: "PT1H",
      query_period: "PT1H",
      trigger_operator: "GreaterThan",
      trigger_threshold: 0,
      tactics: ["CredentialAccess"],
      techniques: ["T1110.003"],
      entity_mappings: [
        {
          entityType: "Account",
          fieldMappings: [
            { identifier: "FullName", columnName: "UserPrincipalName" },
          ],
        },
        {
          entityType: "IP",
          fieldMappings: [{ identifier: "Address", columnName: "IPAddress" }],
        },
      ],
      custom_details: {
        FailedAttempts: "FailedAttempts",
        DistinctAccounts: "DistinctAccounts",
        DetectionReason: "DetectionReason",
      },
      alert_details_override: {
        alertDisplayNameFormat: "Password spray from {{IPAddress}}",
      },
      incident_configuration: {
        createIncident: true,
        groupingConfiguration: {
          enabled: true,
          matchingMethod: "Selected",
          groupByEntities: ["IP"],
          lookbackDuration: "PT5H",
        },
      },
      event_grouping_settings: { aggregationKind: "SingleAlert" },
      suppression_enabled: false,
      suppression_duration: null,
    },
    limitations: [
      "Validation covered the last 7 days only; seasonal sign-in patterns unverified",
      "Query statistics were sampled from a single dry run",
    ],
    assumptions: [
      "SigninLogs ingestion delay is under 10 minutes",
      "ResultType \"0\" reliably indicates a successful sign-in",
    ],
  };
}
