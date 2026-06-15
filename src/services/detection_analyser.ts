import { readFileSync } from "node:fs";
import { mkdir, writeFile } from "node:fs/promises";
import { randomUUID } from "node:crypto";
import path from "node:path";

import type {
  AnalyserConfig,
  AnalyserReport,
  AnalyserRequest,
  LogQueryResult,
  SentinelScheduledRuleParams,
  SentinelWorkspaceRef,
} from "../types.js";
import type { LlmMessage, LlmProvider, LlmToolResult } from "../llm/types.js";
import { assessQuerySafety, validateTimespan } from "./query_safety.js";
import { AuditLog } from "./audit_log.js";
import { redactQueryResult, redactValue } from "./redaction.js";
import { renderMarkdownReport, saveReport, validateReport } from "./report_renderer.js";
import { lookupMitre } from "../tools/mitre.js";
import type { LogAnalyticsClient } from "../tools/log_analytics_client.js";
import type { SentinelClient } from "../tools/sentinel_client.js";
import { buildToolDefinitions, TOOL_NAMES } from "./tool_definitions.js";

// ---------------------------------------------------------------------------
// Public surface
// ---------------------------------------------------------------------------

export interface AnalyserDeps {
  /** The LLM backend (Anthropic, OpenAI, or any OpenAI-compatible endpoint). */
  provider: LlmProvider;
  logAnalytics: LogAnalyticsClient;
  sentinel?: SentinelClient;
  auditLog: AuditLog;
  config: AnalyserConfig;
  /** Streaming sink for the model's visible text (e.g. process.stdout.write). */
  onText?: (text: string) => void;
  /** Streaming sink for summarized thinking (progress signal during long pauses). */
  onThinking?: (text: string) => void;
  /** Observer for tool invocations, for progress display. */
  onToolCall?: (name: string, input: unknown) => void;
}

export interface RefusalInfo {
  category: string | null;
  explanation: string | null;
  /** Model that refused. */
  model: string;
}

export interface AnalysisOutcome {
  /** Validated structured report, or null if the run ended without one. */
  report: AnalyserReport | null;
  /** The model's final markdown answer (falls back to a rendered report). */
  markdown: string;
  /** Paths written to disk (report JSON + markdown). */
  savedFiles: string[];
  /** Model that produced the final answer. */
  modelUsed: string;
  /** Populated when the primary model refused (even if a fallback recovered). */
  refusal?: RefusalInfo;
  iterations: number;
  /** Set when the loop ended abnormally (iteration cap, unrecovered refusal...). */
  aborted?: string;
}

interface RunQueryToolInput {
  workspace_id: string;
  query: string;
  timespan: string;
  additional_workspaces?: string[];
  prefer?: {
    include_statistics?: boolean;
    include_data_sources?: boolean;
    wait_seconds?: number;
  };
  purpose: string;
  max_rows_expected?: number;
}

interface SentinelRefInput {
  subscription_id: string;
  resource_group: string;
  workspace_name: string;
}

interface ToolContext {
  request: AnalyserRequest;
  analysisId: string;
  startedAt: string;
  allowQueryExecution: boolean;
  /** Per-run memo: the Sentinel target's ARM workspace has been verified to map to the request workspace GUID. */
  state: { sentinelTargetVerified?: boolean };
  onReport: (report: AnalyserReport) => void;
}

/**
 * The agent loop: drives the configured LLM provider through the analysis
 * workflow defined in src/prompts/kql_analyser_system_prompt.md, brokering
 * every side effect (Log Analytics queries, Sentinel calls) through safety
 * gates. The loop is provider-neutral; only the provider touches a vendor SDK.
 */
export class DetectionAnalyser {
  private readonly deps: AnalyserDeps;
  private readonly systemPrompt: string;

  constructor(deps: AnalyserDeps) {
    this.deps = deps;
    this.systemPrompt = readFileSync(
      new URL("../prompts/kql_analyser_system_prompt.md", import.meta.url),
      "utf8",
    );
  }

  async analyse(request: AnalyserRequest): Promise<AnalysisOutcome> {
    validateRequest(request);

    const { config } = this.deps;
    const analysisId = `sentret_${new Date().toISOString().slice(0, 10)}_${randomUUID().slice(0, 8)}`;
    const startedAt = new Date().toISOString();
    const allowQueryExecution = request.allow_query_execution !== false;
    const sentinelConfigured = Boolean(this.deps.sentinel && request.sentinel_target);

    const tools = buildToolDefinitions({
      allowQueryExecution,
      sentinelConfigured,
      allowDeploy: config.allowDeploy && sentinelConfigured,
    });

    const messages: LlmMessage[] = [
      { role: "user", text: buildKickoffMessage(request, analysisId, startedAt, config) },
    ];

    let provider = this.deps.provider;
    let refusal: RefusalInfo | undefined;
    let report: AnalyserReport | null = null;
    let finalText = "";
    /** Visible text carried across max_tokens continuations. */
    let pendingText = "";
    let nudges = 0;
    let iterations = 0;
    let aborted: string | undefined;
    const state: ToolContext["state"] = {};
    const ctx: ToolContext = {
      request,
      analysisId,
      startedAt,
      allowQueryExecution,
      state,
      onReport: (r) => {
        report = r;
      },
    };

    loop: while (true) {
      if (iterations >= config.maxIterations) {
        aborted = `Iteration cap reached (${config.maxIterations}) before the run completed.`;
        break;
      }
      iterations += 1;

      const result = await provider.runTurn({
        system: this.systemPrompt,
        tools,
        messages,
        maxTokens: config.maxTokens,
        effort: config.effort,
        onText: this.deps.onText,
        onThinking: this.deps.onThinking,
      });

      switch (result.stopReason) {
        case "aborted": {
          aborted = result.abortReason ?? "The provider aborted the run.";
          break loop;
        }

        case "refusal": {
          const info: RefusalInfo = {
            category: result.refusal?.category ?? null,
            explanation: result.refusal?.explanation ?? null,
            model: provider.model,
          };
          refusal ??= info;
          if (provider.fallback && provider.fallback !== provider) {
            // The refused (possibly partial) output is deliberately NOT added to
            // history; the conversation is replayed as-is on the fallback model.
            this.deps.onText?.(
              `\n\n[${provider.model} declined this request (category: ${info.category ?? "unspecified"}); ` +
                `any partial output above is discarded — restarting on ${provider.fallback.model}]\n\n`,
            );
            provider = provider.fallback;
            continue loop;
          }
          aborted = `The model declined the request (category: ${info.category ?? "unspecified"}) and no fallback was available.`;
          break loop;
        }

        case "max_tokens": {
          pendingText += result.text;
          messages.push(result.assistant);
          if (result.toolCalls.length > 0) {
            // Every tool call must be answered or providers reject the next turn.
            // These were truncated and never executed; synthetic error results
            // let the model re-issue them.
            messages.push({
              role: "tool_results",
              results: result.toolCalls.map(
                (tc): LlmToolResult => ({
                  toolCallId: tc.id,
                  isError: true,
                  content:
                    "This tool call was cut off by the output token limit and was NOT executed. " +
                    "Re-issue the call (more concisely if needed).",
                }),
              ),
            });
          }
          messages.push({
            role: "user",
            text: "Your previous response hit the output token limit. Continue from where you left off.",
          });
          continue loop;
        }

        case "tool_use": {
          pendingText = "";
          messages.push(result.assistant);
          const results: LlmToolResult[] = [];
          for (const tc of result.toolCalls) {
            this.deps.onToolCall?.(tc.name, tc.input);
            const outcome = await this.executeTool(tc.name, tc.input, ctx);
            results.push({
              toolCallId: tc.id,
              content: outcome.content,
              ...(outcome.isError ? { isError: true } : {}),
            });
          }
          messages.push({ role: "tool_results", results });
          continue loop;
        }

        default: {
          // end_turn — collect visible text, including any carried across
          // max_tokens continuations.
          const text = pendingText + result.text;
          if (!report && nudges < 2) {
            nudges += 1;
            pendingText = "";
            messages.push(result.assistant);
            messages.push({
              role: "user",
              text:
                "You ended your turn without calling submit_report. Call submit_report now with " +
                "the complete structured report, then provide the final markdown report.",
            });
            continue loop;
          }
          if (!report) {
            aborted =
              "The model ended the run without submitting a structured report, despite repeated requests.";
          }
          finalText = text;
          break loop;
        }
      }
    }

    const savedFiles = report ? await this.persist(report, finalText) : [];

    return {
      report,
      markdown: finalText || (report ? this.safeRender(report) : ""),
      savedFiles,
      modelUsed: provider.model,
      refusal,
      iterations,
      aborted,
    };
  }

  // -------------------------------------------------------------------------
  // Tool execution
  // -------------------------------------------------------------------------

  private async executeTool(
    name: string,
    input: unknown,
    ctx: ToolContext,
  ): Promise<{ content: string; isError?: boolean }> {
    try {
      switch (name) {
        case TOOL_NAMES.runQuery:
          return await this.handleRunQuery(input as RunQueryToolInput, ctx);
        case TOOL_NAMES.getSchema:
          return await this.handleGetSchema(
            input as { workspace_id: string; table_filter?: string },
            ctx,
          );
        case TOOL_NAMES.listRules:
          return await this.handleListRules(input as SentinelRefInput, ctx);
        case TOOL_NAMES.deployRule:
          return await this.handleDeployRule(input as SentinelScheduledRuleParams, ctx);
        case TOOL_NAMES.mitre: {
          const result = lookupMitre((input as { query: string }).query ?? "");
          return { content: this.clip(JSON.stringify(result, null, 2)) };
        }
        case TOOL_NAMES.submitReport:
          return this.handleSubmitReport(input, ctx);
        default:
          return { content: `Unknown tool: ${name}`, isError: true };
      }
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      return { content: `Tool ${name} failed: ${message}`, isError: true };
    }
  }

  private async handleRunQuery(
    input: RunQueryToolInput,
    ctx: ToolContext,
  ): Promise<{ content: string; isError?: boolean }> {
    const { logAnalytics, auditLog } = this.deps;
    const request = ctx.request;

    const refuse = async (reason: string) => {
      await auditLog.append({
        timestamp_utc: new Date().toISOString(),
        workspace_id: input.workspace_id ?? request.workspace_id,
        purpose: input.purpose ?? "(missing)",
        query: input.query ?? "(missing)",
        timespan: input.timespan ?? "(missing)",
        outcome: "blocked",
        detail: reason,
      });
      return { content: `Query blocked: ${reason}`, isError: true };
    };

    if (!ctx.allowQueryExecution) {
      return refuse("query execution is disabled for this run.");
    }
    if (!input.query?.trim()) return refuse("no query provided.");
    if (!input.purpose?.trim()) return refuse("a purpose is required for auditability.");
    if (input.workspace_id !== request.workspace_id) {
      return refuse(
        `workspace_id must be the workspace from the request (${request.workspace_id}).`,
      );
    }
    if (input.additional_workspaces?.length) {
      return refuse("cross-workspace queries are not permitted for this run.");
    }

    const timespanCheck = validateTimespan(input.timespan ?? "");
    if (!timespanCheck.valid) {
      return refuse(`invalid timespan: ${timespanCheck.reason ?? "unparseable"}.`);
    }

    const safety = assessQuerySafety(input.query, {
      allowBroadQueries: request.allow_broad_queries === true,
      allowedWorkspaceId: request.workspace_id,
      ...(request.sample_mode_allowed === false ? { maxSampleRows: 0 } : {}),
    });
    if (!safety.allowed) {
      return refuse(safety.blockers.join(" | "));
    }

    const result = await logAnalytics.runQuery({
      workspaceId: input.workspace_id,
      query: input.query,
      timespan: input.timespan,
      includeStatistics: input.prefer?.include_statistics ?? true,
      includeDataSources: input.prefer?.include_data_sources ?? false,
      waitSeconds: input.prefer?.wait_seconds ?? 300,
    });

    await auditLog.append({
      timestamp_utc: new Date().toISOString(),
      workspace_id: input.workspace_id,
      purpose: input.purpose,
      query: input.query,
      timespan: input.timespan,
      outcome: result.status === "Failed" ? "failed" : "executed",
      detail:
        result.status === "Failed"
          ? `${result.error?.code ?? "Unknown"}: ${result.error?.message ?? ""}`
          : `status=${result.status} durationMs=${result.durationMs}`,
    });

    const shaped = this.shapeQueryResult(result, request);
    if (safety.warnings.length > 0) {
      shaped.safety_warnings = safety.warnings;
    }
    return {
      content: this.clip(JSON.stringify(shaped, null, 2)),
      ...(result.status === "Failed" ? { isError: true } : {}),
    };
  }

  /** Truncates rows, applies redaction policy, and flattens to a model-friendly shape. */
  private shapeQueryResult(
    result: LogQueryResult,
    request: AnalyserRequest,
  ): Record<string, unknown> {
    const { config } = this.deps;
    const rawAllowed = request.allow_raw_examples === true;
    const redacted = rawAllowed ? result : redactQueryResult(result);

    const tables = redacted.tables.map((table) => {
      const truncated = table.rows.length > config.maxResultRows;
      return {
        name: table.name,
        columns: table.columns,
        row_count: table.rows.length,
        rows: table.rows.slice(0, config.maxResultRows),
        ...(truncated
          ? { note: `Truncated to first ${config.maxResultRows} of ${table.rows.length} rows.` }
          : {}),
      };
    });

    // statistics/dataSources/error pass through redactQueryResult untouched by
    // design (they are metadata) — but error messages and statistics can echo
    // query literals or row values, so they get value-level redaction here.
    const statistics = rawAllowed ? redacted.statistics : (redactValue(redacted.statistics) as typeof redacted.statistics);
    const dataSources = rawAllowed ? redacted.dataSources : (redactValue(redacted.dataSources) as typeof redacted.dataSources);
    const error = rawAllowed ? redacted.error : (redactValue(redacted.error) as typeof redacted.error);

    return {
      status: redacted.status,
      duration_ms: redacted.durationMs,
      ...(error ? { error } : {}),
      tables,
      ...(statistics ? { statistics } : {}),
      ...(dataSources ? { data_sources: dataSources } : {}),
      ...(rawAllowed
        ? {}
        : { redaction: "Sensitive values were redacted server-side (raw examples not allowed)." }),
    };
  }

  private async handleGetSchema(
    input: { workspace_id: string; table_filter?: string },
    ctx: ToolContext,
  ): Promise<{ content: string; isError?: boolean }> {
    if (input.workspace_id !== ctx.request.workspace_id) {
      return {
        content: `Schema lookup blocked: workspace_id must be ${ctx.request.workspace_id}.`,
        isError: true,
      };
    }
    const schema = await this.deps.logAnalytics.getWorkspaceSchema(input.workspace_id);
    const filter = input.table_filter?.toLowerCase();
    const filtered = filter
      ? schema.filter((t) => t.table.toLowerCase().includes(filter))
      : schema;
    return {
      content: this.clip(
        JSON.stringify({ table_count: filtered.length, tables: filtered }, null, 2),
      ),
    };
  }

  /**
   * Confirms the model-supplied ARM triple matches the operator-approved
   * sentinel_target AND that the ARM workspace resolves to the analysed
   * Log Analytics workspace GUID. Memoised per run.
   */
  private async verifySentinelTarget(
    input: SentinelRefInput,
    ctx: ToolContext,
  ): Promise<{ ok: true; ref: SentinelWorkspaceRef } | { ok: false; reason: string }> {
    const target = ctx.request.sentinel_target;
    if (!this.deps.sentinel || !target) {
      return { ok: false, reason: "Sentinel access is not configured for this run." };
    }
    if (
      input.subscription_id !== target.subscription_id ||
      input.resource_group !== target.resource_group ||
      input.workspace_name !== target.workspace_name
    ) {
      return {
        ok: false,
        reason:
          "Sentinel operations are restricted to the operator-approved target " +
          `(subscription ${target.subscription_id}, resource group ${target.resource_group}, ` +
          `workspace ${target.workspace_name}).`,
      };
    }
    const ref: SentinelWorkspaceRef = {
      subscriptionId: target.subscription_id,
      resourceGroup: target.resource_group,
      workspaceName: target.workspace_name,
    };
    if (!ctx.state.sentinelTargetVerified) {
      const customerId = await this.deps.sentinel.getWorkspaceCustomerId(ref);
      if (customerId.toLowerCase() !== ctx.request.workspace_id.toLowerCase()) {
        return {
          ok: false,
          reason:
            `The Sentinel target workspace resolves to Log Analytics workspace ${customerId}, ` +
            `which is not the analysed workspace (${ctx.request.workspace_id}).`,
        };
      }
      ctx.state.sentinelTargetVerified = true;
    }
    return { ok: true, ref };
  }

  private async sentinelAudit(
    ctx: ToolContext,
    purpose: string,
    outcome: "executed" | "blocked" | "failed" | "deployed",
    detail: string,
  ): Promise<void> {
    await this.deps.auditLog.append({
      timestamp_utc: new Date().toISOString(),
      workspace_id: ctx.request.workspace_id,
      purpose,
      query: "(sentinel ARM operation)",
      timespan: "-",
      outcome,
      detail,
    });
  }

  private async handleListRules(
    input: SentinelRefInput,
    ctx: ToolContext,
  ): Promise<{ content: string; isError?: boolean }> {
    const verified = await this.verifySentinelTarget(input, ctx);
    if (!verified.ok) {
      await this.sentinelAudit(ctx, "list_sentinel_rules", "blocked", verified.reason);
      return { content: `Sentinel listing blocked: ${verified.reason}`, isError: true };
    }
    const rules = await this.deps.sentinel!.listRules(verified.ref);
    await this.sentinelAudit(ctx, "list_sentinel_rules", "executed", `${rules.length} rules`);
    return {
      content: this.clip(JSON.stringify({ rule_count: rules.length, rules }, null, 2)),
    };
  }

  private async handleDeployRule(
    params: SentinelScheduledRuleParams,
    ctx: ToolContext,
  ): Promise<{ content: string; isError?: boolean }> {
    if (!this.deps.sentinel || !this.deps.config.allowDeploy) {
      return {
        content:
          "Deployment refused: the operator has not approved Sentinel deployment for this run. " +
          "Present the rule configuration in the report instead.",
        isError: true,
      };
    }
    const verified = await this.verifySentinelTarget(params, ctx);
    if (!verified.ok) {
      await this.sentinelAudit(ctx, "create_or_update_sentinel_rule", "blocked", verified.reason);
      return { content: `Deployment blocked: ${verified.reason}`, isError: true };
    }
    try {
      const result = await this.deps.sentinel.createOrUpdateScheduledRule(params, {
        confirmed: true,
      });
      await this.sentinelAudit(
        ctx,
        "create_or_update_sentinel_rule",
        "deployed",
        `${result.status} ${result.resourceId} (rule "${params.display_name}")`,
      );
      return { content: JSON.stringify(result, null, 2) };
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      await this.sentinelAudit(ctx, "create_or_update_sentinel_rule", "failed", message);
      return { content: `Deployment failed: ${message}`, isError: true };
    }
  }

  private handleSubmitReport(
    input: unknown,
    ctx: ToolContext,
  ): { content: string; isError?: boolean } {
    const validation = validateReport(input);
    if (!validation.valid) {
      return {
        content:
          "Report rejected. Fix these problems and call submit_report again:\n- " +
          validation.errors.join("\n- "),
        isError: true,
      };
    }
    const report = input as AnalyserReport;

    // Reconcile validation-evidence claims against the run's actual state.
    if (!ctx.allowQueryExecution) {
      const claimedRuns = report.workspace_validation.queries_run.filter(
        (q) => q.status !== "Skipped",
      );
      if (
        claimedRuns.length > 0 ||
        report.workspace_validation.data_availability.length > 0 ||
        report.workspace_validation.field_population.length > 0
      ) {
        return {
          content:
            "Report rejected: query execution was disabled for this run, but the report claims " +
            "live validation results. Mark workspace validation as skipped (empty arrays, " +
            'queries_run entries only with status "Skipped") and call submit_report again.',
          isError: true,
        };
      }
    }

    // Authoritative run identity — overrides whatever the model echoed.
    report.analysis_id = ctx.analysisId;
    report.timestamp_utc = ctx.startedAt;
    report.mode = ctx.request.mode;
    report.workspace_id = ctx.request.workspace_id;
    report.workspace_validation.execution_allowed = ctx.allowQueryExecution;
    ctx.onReport(report);
    return {
      content:
        "Report accepted. Now write the final markdown report for the user, following the " +
        "standard output format.",
    };
  }

  // -------------------------------------------------------------------------
  // Persistence
  // -------------------------------------------------------------------------

  /** renderMarkdownReport must not throw, but a saved-report path should survive even if it does. */
  private safeRender(report: AnalyserReport): string {
    try {
      return renderMarkdownReport(report);
    } catch (error) {
      return (
        "# KQL Detection Rule Analysis\n\n" +
        "The markdown renderer failed on this report; see the JSON artifact for full detail.\n\n" +
        `Renderer error: ${error instanceof Error ? error.message : String(error)}\n`
      );
    }
  }

  private async persist(report: AnalyserReport, finalMarkdown: string): Promise<string[]> {
    const { config } = this.deps;
    const files = await saveReport(report, { outputDir: config.outputDir, formats: ["json"] });
    const markdown = finalMarkdown.trim() || this.safeRender(report);
    await mkdir(config.outputDir, { recursive: true });
    const mdPath = path.join(config.outputDir, `analysis_${report.analysis_id}.md`);
    await writeFile(mdPath, markdown, "utf8");
    return [...files, mdPath];
  }

  private clip(text: string): string {
    const max = this.deps.config.maxResultChars;
    if (text.length <= max) return text;
    return `${text.slice(0, max)}\n... [truncated: ${text.length - max} characters removed; re-query with tighter filters or aggregation]`;
  }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function validateRequest(request: AnalyserRequest): void {
  const problems: string[] = [];
  if (request.mode !== "analyse_existing_rule" && request.mode !== "create_new_detection") {
    problems.push(`mode must be "analyse_existing_rule" or "create_new_detection".`);
  }
  if (!request.detection_intent?.trim()) problems.push("detection_intent is required.");
  if (!request.workspace_id?.trim()) problems.push("workspace_id is required.");
  if (request.mode === "analyse_existing_rule" && !request.kql?.trim()) {
    problems.push("kql is required when mode is analyse_existing_rule.");
  }
  const timespan = validateTimespan(request.timespan ?? "");
  if (!timespan.valid) {
    problems.push(`timespan is invalid: ${timespan.reason ?? "unparseable"}.`);
  }
  if (
    (request.data_sensitivity === "High" || request.data_sensitivity === "Restricted") &&
    request.allow_raw_examples === true
  ) {
    problems.push(
      "allow_raw_examples cannot be true when data_sensitivity is High or Restricted; " +
        "remove one of the two settings.",
    );
  }
  if (request.sentinel_target) {
    const t = request.sentinel_target;
    if (!t.subscription_id?.trim() || !t.resource_group?.trim() || !t.workspace_name?.trim()) {
      problems.push(
        "sentinel_target must include subscription_id, resource_group, and workspace_name.",
      );
    }
  }
  if (problems.length > 0) {
    throw new Error(`Invalid analyser request:\n- ${problems.join("\n- ")}`);
  }
}

function buildKickoffMessage(
  request: AnalyserRequest,
  analysisId: string,
  startedAt: string,
  config: AnalyserConfig,
): string {
  const allowExecution = request.allow_query_execution !== false;
  const sampleAllowed = request.sample_mode_allowed !== false;
  const constraints = [
    `- mode: ${request.mode}`,
    `- allow_query_execution: ${allowExecution}${allowExecution ? "" : " (perform static analysis only; mark workspace validation as skipped)"}`,
    `- allow_raw_examples: ${request.allow_raw_examples === true} (when false, query results are redacted server-side before you see them — placeholders like <email:1a2b3c4d> preserve distinctness for aggregation)`,
    `- sample_mode_allowed: ${sampleAllowed}${sampleAllowed ? "" : " (do not retrieve raw row samples; take/limit/sample are blocked — use counts, summarize, and getschema only)"}`,
    `- allow_broad_queries: ${request.allow_broad_queries === true} (when false, workspace-wide search/find/union-wildcard patterns are blocked)`,
    `- Workspace access is restricted to workspace_id ${request.workspace_id}. Queries against any other workspace will be blocked, including via workspace()/cluster() functions.`,
    request.sentinel_target
      ? `- Sentinel operations are restricted to subscription ${request.sentinel_target.subscription_id}, resource group ${request.sentinel_target.resource_group}, workspace ${request.sentinel_target.workspace_name}.`
      : `- No Sentinel workspace target was supplied; Sentinel rule listing/deployment tools are unavailable.`,
    `- Sentinel deployment is ${config.allowDeploy && request.sentinel_target ? "pre-approved by the operator for this run" : "NOT approved for this run; never attempt it"}.`,
    `- Use analysis_id "${analysisId}" and timestamp_utc "${startedAt}" in your report.`,
    `- When the analysis is complete, call submit_report with the full structured report, then write the final markdown report.`,
  ];

  return [
    "Analyse the following detection engineering request.",
    "",
    "Run constraints:",
    ...constraints,
    "",
    "Request:",
    "```json",
    JSON.stringify(request, null, 2),
    "```",
  ].join("\n");
}
