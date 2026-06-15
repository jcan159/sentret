import { mkdtemp, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { beforeEach, describe, expect, it } from "vitest";

import type { AnalyserConfig, AnalyserRequest, LogQueryResult } from "../types.js";
import type { LlmProvider, LlmRunOptions, LlmStopReason, LlmToolCall } from "../llm/types.js";
import { loadConfig } from "../config.js";
import { AuditLog } from "./audit_log.js";
import { DetectionAnalyser } from "./detection_analyser.js";
import { buildSampleReport } from "./report_renderer.js";
import { buildToolDefinitions, TOOL_NAMES } from "./tool_definitions.js";
import type { LogAnalyticsClient } from "../tools/log_analytics_client.js";
import type { SentinelClient } from "../tools/sentinel_client.js";

// ---------------------------------------------------------------------------
// Test doubles
// ---------------------------------------------------------------------------

interface FakeTurn {
  stopReason: LlmStopReason;
  text?: string;
  toolCalls?: LlmToolCall[];
  refusal?: { category: string | null; explanation?: string | null };
  abortReason?: string;
}

/** Snapshot of the serializable parts of a runTurn call (callbacks omitted). */
interface RecordedTurn {
  system: string;
  tools: { name: string }[];
  messages: unknown[];
  maxTokens: number;
  effort: string;
}

function tc(id: string, name: string, input: unknown): LlmToolCall {
  return { id, name, input };
}

/** A provider that records each runTurn and replays a scripted queue of turns. */
function makeFakeProvider(
  turns: FakeTurn[],
  opts: { model?: string; fallback?: LlmProvider } = {},
) {
  const calls: RecordedTurn[] = [];
  let i = 0;
  const provider: LlmProvider = {
    name: "fake",
    model: opts.model ?? "claude-fable-5",
    fallback: opts.fallback,
    async runTurn(o: LlmRunOptions) {
      calls.push({
        system: o.system,
        tools: o.tools.map((t) => ({ name: t.name })),
        // Deep copy — the loop mutates its message array between turns.
        messages: JSON.parse(JSON.stringify(o.messages)) as unknown[],
        maxTokens: o.maxTokens,
        effort: o.effort,
      });
      const t = turns[i++];
      if (!t) throw new Error("fake provider: no scripted turns left");
      const toolCalls = t.toolCalls ?? [];
      return {
        stopReason: t.stopReason,
        text: t.text ?? "",
        toolCalls,
        assistant: { role: "assistant" as const, text: t.text ?? "", toolCalls },
        refusal: t.refusal
          ? { category: t.refusal.category, explanation: t.refusal.explanation ?? null }
          : undefined,
        abortReason: t.abortReason,
        modelUsed: provider.model,
      };
    },
  };
  return { provider, calls };
}

const WORKSPACE = "00000000-0000-0000-0000-000000000000";

function makeRequest(overrides: Partial<AnalyserRequest> = {}): AnalyserRequest {
  return {
    mode: "analyse_existing_rule",
    detection_intent: "Detect suspicious successful sign-ins from new countries.",
    workspace_id: WORKSPACE,
    timespan: "P7D",
    kql: "SigninLogs | where ResultType == 0 | summarize count() by UserPrincipalName, Location",
    allow_query_execution: true,
    allow_raw_examples: false,
    ...overrides,
  };
}

/** A report whose validation evidence is consistent with a static-only run. */
function staticReport() {
  const report = buildSampleReport();
  report.workspace_validation = {
    ...report.workspace_validation,
    execution_allowed: false,
    queries_run: [],
    data_availability: [],
    field_population: [],
  };
  return report;
}

const SENTINEL_TARGET = {
  subscription_id: "sub-1",
  resource_group: "rg-1",
  workspace_name: "ws-1",
};

function makeFakeSentinel(customerId: string = WORKSPACE) {
  const listCalls: unknown[] = [];
  const deployCalls: unknown[] = [];
  const client = {
    getWorkspaceCustomerId: async () => customerId,
    listRules: async (ref: unknown) => {
      listCalls.push(ref);
      return [{ id: "r1", name: "r1", kind: "Scheduled", displayName: "Existing rule" }];
    },
    createOrUpdateScheduledRule: async (params: unknown, opts: unknown) => {
      deployCalls.push({ params, opts });
      return { ruleId: "rule-1", resourceId: "/subscriptions/sub-1/...", status: "Created" };
    },
  } as unknown as SentinelClient;
  return { client, listCalls, deployCalls };
}

function successResult(rows: unknown[][]): LogQueryResult {
  return {
    status: "Succeeded",
    durationMs: 120,
    tables: [
      {
        name: "PrimaryResult",
        columns: [
          { name: "UserPrincipalName", type: "string" },
          { name: "Count", type: "long" },
        ],
        rows,
      },
    ],
    statistics: { query: { executionTime: 0.12 } },
  };
}

function makeFakeLogAnalytics(result: LogQueryResult) {
  const runQueryCalls: unknown[] = [];
  const client = {
    runQuery: async (opts: unknown) => {
      runQueryCalls.push(opts);
      return result;
    },
    getWorkspaceSchema: async () => [
      { table: "SigninLogs", columns: [{ name: "UserPrincipalName", type: "string" }] },
    ],
  } as unknown as LogAnalyticsClient;
  return { client, runQueryCalls };
}

let outputDir: string;
let config: AnalyserConfig;

beforeEach(async () => {
  outputDir = await mkdtemp(path.join(tmpdir(), "sentret-test-"));
  config = loadConfig({} as NodeJS.ProcessEnv, {
    outputDir,
    auditLogPath: path.join(outputDir, "audit.jsonl"),
    fallbackModel: "claude-opus-4-8",
    maxIterations: 10,
  });
});

function makeAnalyser(
  turns: FakeTurn[],
  opts: {
    model?: string;
    fallback?: LlmProvider;
    logAnalytics?: LogAnalyticsClient;
    sentinel?: SentinelClient;
    configOverrides?: Partial<AnalyserConfig>;
    onText?: (t: string) => void;
  } = {},
) {
  const { provider, calls } = makeFakeProvider(turns, {
    model: opts.model,
    fallback: opts.fallback,
  });
  const analyser = new DetectionAnalyser({
    provider,
    logAnalytics: opts.logAnalytics ?? makeFakeLogAnalytics(successResult([])).client,
    sentinel: opts.sentinel,
    auditLog: new AuditLog(path.join(outputDir, "audit.jsonl")),
    config: { ...config, ...opts.configOverrides },
    onText: opts.onText,
  });
  return { analyser, calls };
}

/** The last message in a recorded turn, typed as a tool_results message. */
function lastToolResults(turn: RecordedTurn | undefined) {
  const msg = (turn!.messages.at(-1) ?? {}) as {
    role: string;
    results?: { toolCallId: string; content: string; isError?: boolean }[];
  };
  return msg;
}

function lastUserText(turn: RecordedTurn | undefined): string {
  const msg = (turn!.messages.at(-1) ?? {}) as { role: string; text?: string };
  return msg.text ?? "";
}

// ---------------------------------------------------------------------------
// Tool definition gating
// ---------------------------------------------------------------------------

describe("buildToolDefinitions", () => {
  it("exposes only mitre + submit_report when everything is gated off", () => {
    const names = buildToolDefinitions({
      allowQueryExecution: false,
      sentinelConfigured: false,
      allowDeploy: false,
    }).map((t) => t.name);
    expect(names).toEqual([TOOL_NAMES.mitre, TOOL_NAMES.submitReport]);
  });

  it("exposes all tools when fully enabled", () => {
    const names = buildToolDefinitions({
      allowQueryExecution: true,
      sentinelConfigured: true,
      allowDeploy: true,
    }).map((t) => t.name);
    expect(names).toContain(TOOL_NAMES.runQuery);
    expect(names).toContain(TOOL_NAMES.getSchema);
    expect(names).toContain(TOOL_NAMES.listRules);
    expect(names).toContain(TOOL_NAMES.deployRule);
  });

  it("never exposes deployment without a Sentinel client, even when approved", () => {
    const names = buildToolDefinitions({
      allowQueryExecution: true,
      sentinelConfigured: false,
      allowDeploy: true,
    }).map((t) => t.name);
    expect(names).not.toContain(TOOL_NAMES.deployRule);
    expect(names).not.toContain(TOOL_NAMES.listRules);
  });

  it("loads the report schema as the submit_report input schema", () => {
    const submit = buildToolDefinitions({
      allowQueryExecution: false,
      sentinelConfigured: false,
      allowDeploy: false,
    }).find((t) => t.name === TOOL_NAMES.submitReport);
    const schema = submit?.inputSchema as { type: string; required?: string[] };
    expect(schema.type).toBe("object");
    expect(schema.required).toContain("verdict");
    expect(schema.required).toContain("detection_quality");
  });
});

// ---------------------------------------------------------------------------
// Agent loop
// ---------------------------------------------------------------------------

describe("DetectionAnalyser", () => {
  it("runs the happy path: query -> submit_report -> final markdown", async () => {
    const fakeLA = makeFakeLogAnalytics(
      successResult([
        ["alice@contoso.com", 12],
        ["bob@contoso.com", 3],
      ]),
    );
    const { analyser, calls } = makeAnalyser(
      [
        {
          stopReason: "tool_use",
          text: "Checking data availability.",
          toolCalls: [
            tc("t1", TOOL_NAMES.runQuery, {
              workspace_id: WORKSPACE,
              query: "SigninLogs | where TimeGenerated >= ago(1d) | count",
              timespan: "P1D",
              purpose: "Validate SigninLogs volume",
            }),
          ],
        },
        { stopReason: "tool_use", toolCalls: [tc("t2", TOOL_NAMES.submitReport, buildSampleReport())] },
        { stopReason: "end_turn", text: "# KQL Detection Rule Analysis\n\nFinal." },
      ],
      { logAnalytics: fakeLA.client },
    );

    const outcome = await analyser.analyse(makeRequest());

    expect(outcome.aborted).toBeUndefined();
    expect(outcome.report).not.toBeNull();
    expect(outcome.report?.analysis_id).toMatch(/^sentret_\d{4}-\d{2}-\d{2}_[0-9a-f]{8}$/);
    expect(outcome.report?.workspace_id).toBe(WORKSPACE);
    expect(outcome.markdown).toContain("Final.");
    expect(outcome.modelUsed).toBe("claude-fable-5");
    expect(outcome.iterations).toBe(3);

    // Provider-neutral request shape.
    const first = calls[0]!;
    expect(first.effort).toBe(config.effort);
    expect(first.maxTokens).toBe(config.maxTokens);
    expect(typeof first.system).toBe("string");
    expect(first.tools.map((t) => t.name)).toContain(TOOL_NAMES.runQuery);
    const firstMessages = first.messages as Array<{ role: string; text?: string }>;
    expect(firstMessages[0]!.role).toBe("user");
    expect(firstMessages[0]!.text).toContain("Run constraints");
    expect(fakeLA.runQueryCalls).toHaveLength(1);

    // The tool result fed back must be redacted (allow_raw_examples=false).
    const toolResultJson = JSON.stringify(lastToolResults(calls[1]).results);
    expect(toolResultJson).toContain("<userprincipalname:");
    expect(toolResultJson).not.toContain("alice@contoso.com");

    // Files persisted.
    expect(outcome.savedFiles).toHaveLength(2);
    const json = JSON.parse(await readFile(outcome.savedFiles[0]!, "utf8"));
    expect(json.verdict).toBe(outcome.report?.verdict);
    const md = await readFile(outcome.savedFiles[1]!, "utf8");
    expect(md).toContain("Final.");

    // Audit trail recorded the executed query.
    const audit = (await readFile(path.join(outputDir, "audit.jsonl"), "utf8"))
      .trim()
      .split("\n")
      .map((line) => JSON.parse(line));
    expect(audit).toHaveLength(1);
    expect(audit[0].outcome).toBe("executed");
    expect(audit[0].purpose).toBe("Validate SigninLogs volume");
  });

  it("blocks unsafe queries and audits the block", async () => {
    const fakeLA = makeFakeLogAnalytics(successResult([]));
    const { analyser, calls } = makeAnalyser(
      [
        {
          stopReason: "tool_use",
          toolCalls: [
            tc("t1", TOOL_NAMES.runQuery, {
              workspace_id: WORKSPACE,
              query: "search *",
              timespan: "P1D",
              purpose: "broad sweep",
            }),
          ],
        },
        { stopReason: "tool_use", toolCalls: [tc("t2", TOOL_NAMES.submitReport, buildSampleReport())] },
        { stopReason: "end_turn", text: "done" },
      ],
      { logAnalytics: fakeLA.client },
    );

    await analyser.analyse(makeRequest());

    expect(fakeLA.runQueryCalls).toHaveLength(0);
    const result = lastToolResults(calls[1]).results![0]!;
    expect(result.isError).toBe(true);
    expect(result.content).toContain("Query blocked");

    const audit = (await readFile(path.join(outputDir, "audit.jsonl"), "utf8"))
      .trim()
      .split("\n")
      .map((line) => JSON.parse(line));
    expect(audit[0].outcome).toBe("blocked");
  });

  it("rejects queries against a different workspace", async () => {
    const fakeLA = makeFakeLogAnalytics(successResult([]));
    const { analyser, calls } = makeAnalyser(
      [
        {
          stopReason: "tool_use",
          toolCalls: [
            tc("t1", TOOL_NAMES.runQuery, {
              workspace_id: "11111111-1111-1111-1111-111111111111",
              query: "SigninLogs | count",
              timespan: "P1D",
              purpose: "probe another workspace",
            }),
          ],
        },
        { stopReason: "tool_use", toolCalls: [tc("t2", TOOL_NAMES.submitReport, buildSampleReport())] },
        { stopReason: "end_turn", text: "done" },
      ],
      { logAnalytics: fakeLA.client },
    );

    await analyser.analyse(makeRequest());
    expect(fakeLA.runQueryCalls).toHaveLength(0);
    expect(lastToolResults(calls[1]).results![0]!.content).toContain("workspace_id must be");
  });

  it("falls back to the secondary provider on refusal and reports it", async () => {
    const fb = makeFakeProvider(
      [
        { stopReason: "tool_use", toolCalls: [tc("t1", TOOL_NAMES.submitReport, buildSampleReport())] },
        { stopReason: "end_turn", text: "fallback finished" },
      ],
      { model: "claude-opus-4-8" },
    );
    const { analyser, calls } = makeAnalyser(
      [{ stopReason: "refusal", refusal: { category: "cyber" } }],
      { model: "claude-fable-5", fallback: fb.provider },
    );

    const outcome = await analyser.analyse(makeRequest());

    expect(outcome.refusal?.category).toBe("cyber");
    expect(outcome.refusal?.model).toBe("claude-fable-5");
    expect(outcome.modelUsed).toBe("claude-opus-4-8");
    expect(outcome.report).not.toBeNull();
    expect(calls).toHaveLength(1); // primary called once, then refused
    expect(fb.calls).toHaveLength(2); // fallback completed the run
  });

  it("aborts on refusal when no fallback is configured", async () => {
    const { analyser } = makeAnalyser([{ stopReason: "refusal", refusal: { category: "cyber" } }]);
    const outcome = await analyser.analyse(makeRequest());
    expect(outcome.aborted).toContain("declined");
    expect(outcome.report).toBeNull();
    expect(outcome.savedFiles).toHaveLength(0);
  });

  it("emits a visible boundary marker through onText on a mid-run refusal", async () => {
    const chunks: string[] = [];
    const fb = makeFakeProvider(
      [
        { stopReason: "tool_use", toolCalls: [tc("t1", TOOL_NAMES.submitReport, buildSampleReport())] },
        { stopReason: "end_turn", text: "fallback finished" },
      ],
      { model: "claude-opus-4-8" },
    );
    const { analyser } = makeAnalyser(
      [{ stopReason: "refusal", refusal: { category: "cyber" } }],
      { model: "claude-fable-5", fallback: fb.provider, onText: (t) => chunks.push(t) },
    );

    await analyser.analyse(makeRequest());

    expect(chunks.join("")).toContain("declined this request");
    expect(chunks.join("")).toContain("restarting on claude-opus-4-8");
  });

  it("nudges the model when it ends without submitting a report", async () => {
    const { analyser, calls } = makeAnalyser([
      { stopReason: "end_turn", text: "I think we're done." },
      { stopReason: "tool_use", toolCalls: [tc("t1", TOOL_NAMES.submitReport, buildSampleReport())] },
      { stopReason: "end_turn", text: "final answer" },
    ]);

    const outcome = await analyser.analyse(makeRequest());

    expect(outcome.report).not.toBeNull();
    expect(outcome.markdown).toBe("final answer");
    expect(lastUserText(calls[1])).toContain("without calling submit_report");
  });

  it("rejects an invalid report and lets the model retry", async () => {
    const broken = { ...buildSampleReport(), verdict: "Ship it" };
    const { analyser, calls } = makeAnalyser([
      { stopReason: "tool_use", toolCalls: [tc("t1", TOOL_NAMES.submitReport, broken)] },
      { stopReason: "tool_use", toolCalls: [tc("t2", TOOL_NAMES.submitReport, buildSampleReport())] },
      { stopReason: "end_turn", text: "done" },
    ]);

    const outcome = await analyser.analyse(makeRequest());
    expect(outcome.report?.verdict).not.toBe("Ship it");
    const result = lastToolResults(calls[1]).results![0]!;
    expect(result.isError).toBe(true);
    expect(result.content).toContain("Report rejected");
  });

  it("omits query tools and flags static-only mode when execution is disallowed", async () => {
    const { analyser, calls } = makeAnalyser([
      { stopReason: "tool_use", toolCalls: [tc("t1", TOOL_NAMES.submitReport, staticReport())] },
      { stopReason: "end_turn", text: "static analysis done" },
    ]);

    const outcome = await analyser.analyse(makeRequest({ allow_query_execution: false }));

    expect(calls[0]!.tools.map((t) => t.name)).not.toContain(TOOL_NAMES.runQuery);
    expect(calls[0]!.tools.map((t) => t.name)).not.toContain(TOOL_NAMES.getSchema);
    expect(JSON.stringify(calls[0]!.messages)).toContain("static analysis only");
    expect(outcome.report?.workspace_validation.execution_allowed).toBe(false);
  });

  it("rejects a report claiming live validation on a static-only run", async () => {
    const fabricated = buildSampleReport();
    fabricated.workspace_validation.queries_run = [
      { purpose: "x", query: "SigninLogs | count", status: "Succeeded", row_count: 1, error: null },
    ];
    const { analyser, calls } = makeAnalyser([
      { stopReason: "tool_use", toolCalls: [tc("t1", TOOL_NAMES.submitReport, fabricated)] },
      { stopReason: "tool_use", toolCalls: [tc("t2", TOOL_NAMES.submitReport, staticReport())] },
      { stopReason: "end_turn", text: "done" },
    ]);

    const outcome = await analyser.analyse(makeRequest({ allow_query_execution: false }));

    const result = lastToolResults(calls[1]).results![0]!;
    expect(result.isError).toBe(true);
    expect(result.content).toContain("query execution was disabled");
    expect(outcome.report?.workspace_validation.execution_allowed).toBe(false);
  });

  it("answers tool calls cut off by max_tokens with synthetic error results", async () => {
    const { analyser, calls } = makeAnalyser([
      {
        stopReason: "max_tokens",
        text: "Working... ",
        toolCalls: [tc("cut1", TOOL_NAMES.runQuery, { workspace_id: WORKSPACE })],
      },
      { stopReason: "tool_use", toolCalls: [tc("t2", TOOL_NAMES.submitReport, buildSampleReport())] },
      { stopReason: "end_turn", text: "done" },
    ]);

    const outcome = await analyser.analyse(makeRequest());

    expect(outcome.aborted).toBeUndefined();
    const continuation = calls[1]!.messages as Array<{
      role: string;
      results?: { toolCallId: string; isError?: boolean }[];
      text?: string;
    }>;
    const synthetic = continuation.find((m) => m.role === "tool_results");
    expect(synthetic?.results?.[0]).toMatchObject({ toolCallId: "cut1", isError: true });
    const trailing = continuation.at(-1)!;
    expect(trailing.role).toBe("user");
    expect(trailing.text).toContain("output token limit");
  });

  it("accumulates final markdown across max_tokens continuations", async () => {
    const { analyser } = makeAnalyser([
      { stopReason: "tool_use", toolCalls: [tc("t1", TOOL_NAMES.submitReport, buildSampleReport())] },
      { stopReason: "max_tokens", text: "PART-ONE " },
      { stopReason: "end_turn", text: "PART-TWO end" },
    ]);

    const outcome = await analyser.analyse(makeRequest());

    expect(outcome.markdown).toContain("PART-ONE");
    expect(outcome.markdown).toContain("PART-TWO end");
    const md = await readFile(outcome.savedFiles[1]!, "utf8");
    expect(md).toContain("PART-ONE");
  });

  it("marks the run aborted when the model never submits a report", async () => {
    const { analyser } = makeAnalyser([
      { stopReason: "end_turn", text: "first" },
      { stopReason: "end_turn", text: "second" },
      { stopReason: "end_turn", text: "third" },
    ]);

    const outcome = await analyser.analyse(makeRequest());

    expect(outcome.report).toBeNull();
    expect(outcome.aborted).toContain("without submitting a structured report");
  });

  it("aborts when the provider signals an aborted turn", async () => {
    const { analyser } = makeAnalyser([
      { stopReason: "aborted", abortReason: "The conversation exceeded the model context window." },
    ]);
    const outcome = await analyser.analyse(makeRequest());
    expect(outcome.report).toBeNull();
    expect(outcome.aborted).toContain("context window");
  });

  it("rejects High/Restricted data sensitivity combined with raw examples", async () => {
    const { analyser } = makeAnalyser([]);
    await expect(
      analyser.analyse(makeRequest({ data_sensitivity: "Restricted", allow_raw_examples: true })),
    ).rejects.toThrow(/allow_raw_examples cannot be true/);
  });

  it("does not expose Sentinel tools without an operator-approved sentinel_target", async () => {
    const fakeSentinel = makeFakeSentinel();
    const { analyser, calls } = makeAnalyser(
      [
        { stopReason: "tool_use", toolCalls: [tc("t1", TOOL_NAMES.submitReport, buildSampleReport())] },
        { stopReason: "end_turn", text: "done" },
      ],
      { sentinel: fakeSentinel.client },
    );

    await analyser.analyse(makeRequest());

    expect(calls[0]!.tools.map((t) => t.name)).not.toContain(TOOL_NAMES.listRules);
    expect(calls[0]!.tools.map((t) => t.name)).not.toContain(TOOL_NAMES.deployRule);
  });

  it("allows Sentinel listing only for the verified operator target", async () => {
    const fakeSentinel = makeFakeSentinel();
    const { analyser, calls } = makeAnalyser(
      [
        {
          stopReason: "tool_use",
          toolCalls: [
            tc("t1", TOOL_NAMES.listRules, {
              subscription_id: "attacker-sub",
              resource_group: "rg-1",
              workspace_name: "ws-1",
            }),
          ],
        },
        { stopReason: "tool_use", toolCalls: [tc("t2", TOOL_NAMES.listRules, SENTINEL_TARGET)] },
        { stopReason: "tool_use", toolCalls: [tc("t3", TOOL_NAMES.submitReport, buildSampleReport())] },
        { stopReason: "end_turn", text: "done" },
      ],
      { sentinel: fakeSentinel.client },
    );

    await analyser.analyse(makeRequest({ sentinel_target: SENTINEL_TARGET }));

    // Mismatched triple blocked without touching ARM list.
    const blocked = lastToolResults(calls[1]).results![0]!;
    expect(blocked.isError).toBe(true);
    expect(blocked.content).toContain("operator-approved target");
    expect(fakeSentinel.listCalls).toHaveLength(1);

    // Matching triple succeeded.
    const ok = lastToolResults(calls[2]).results![0]!;
    expect(ok.isError).toBeUndefined();
    expect(ok.content).toContain("rule_count");
  });

  it("blocks Sentinel operations when the ARM workspace does not resolve to the analysed workspace", async () => {
    const fakeSentinel = makeFakeSentinel("99999999-9999-9999-9999-999999999999");
    const { analyser, calls } = makeAnalyser(
      [
        { stopReason: "tool_use", toolCalls: [tc("t1", TOOL_NAMES.listRules, SENTINEL_TARGET)] },
        { stopReason: "tool_use", toolCalls: [tc("t2", TOOL_NAMES.submitReport, buildSampleReport())] },
        { stopReason: "end_turn", text: "done" },
      ],
      { sentinel: fakeSentinel.client },
    );

    await analyser.analyse(makeRequest({ sentinel_target: SENTINEL_TARGET }));

    const blocked = lastToolResults(calls[1]).results![0]!;
    expect(blocked.isError).toBe(true);
    expect(blocked.content).toContain("not the analysed workspace");
    expect(fakeSentinel.listCalls).toHaveLength(0);
  });

  it("deploys through the verified target when the operator approved it, and audits the result", async () => {
    const fakeSentinel = makeFakeSentinel();
    const { analyser } = makeAnalyser(
      [
        {
          stopReason: "tool_use",
          toolCalls: [
            tc("t1", TOOL_NAMES.deployRule, {
              ...SENTINEL_TARGET,
              rule_id: "rule-1",
              enabled: true,
              display_name: "x",
              severity: "Low",
              query: "SigninLogs | count",
              query_frequency: "PT1H",
              query_period: "P1D",
              trigger_operator: "GreaterThan",
              trigger_threshold: 0,
            }),
          ],
        },
        { stopReason: "tool_use", toolCalls: [tc("t2", TOOL_NAMES.submitReport, buildSampleReport())] },
        { stopReason: "end_turn", text: "done" },
      ],
      { sentinel: fakeSentinel.client, configOverrides: { allowDeploy: true } },
    );

    await analyser.analyse(makeRequest({ sentinel_target: SENTINEL_TARGET }));

    expect(fakeSentinel.deployCalls).toHaveLength(1);
    expect((fakeSentinel.deployCalls[0] as { opts: { confirmed: boolean } }).opts.confirmed).toBe(true);
    const audit = (await readFile(path.join(outputDir, "audit.jsonl"), "utf8"))
      .trim()
      .split("\n")
      .map((line) => JSON.parse(line));
    expect(audit.some((a) => a.outcome === "deployed")).toBe(true);
  });

  it("refuses deployment in the handler when not approved, even if the tool is invoked", async () => {
    const fakeSentinel = makeFakeSentinel();
    const { analyser, calls } = makeAnalyser(
      [
        {
          stopReason: "tool_use",
          toolCalls: [
            tc("t1", TOOL_NAMES.deployRule, {
              ...SENTINEL_TARGET,
              rule_id: "rule-1",
              enabled: true,
              display_name: "x",
              severity: "Low",
              query: "SigninLogs | count",
              query_frequency: "PT1H",
              query_period: "P1D",
              trigger_operator: "GreaterThan",
              trigger_threshold: 0,
            }),
          ],
        },
        { stopReason: "tool_use", toolCalls: [tc("t2", TOOL_NAMES.submitReport, buildSampleReport())] },
        { stopReason: "end_turn", text: "done" },
      ],
      { sentinel: fakeSentinel.client },
    );

    await analyser.analyse(makeRequest({ sentinel_target: SENTINEL_TARGET }));
    expect(fakeSentinel.deployCalls).toHaveLength(0);
    const result = lastToolResults(calls[1]).results![0]!;
    expect(result.isError).toBe(true);
    expect(result.content).toContain("Deployment refused");
  });

  it("aborts at the iteration cap", async () => {
    const spin: FakeTurn[] = Array.from({ length: 5 }, () => ({
      stopReason: "tool_use" as const,
      toolCalls: [tc("t", TOOL_NAMES.mitre, { query: "T1110" })],
    }));
    const { analyser } = makeAnalyser(spin, { configOverrides: { maxIterations: 3 } });
    const outcome = await analyser.analyse(makeRequest());
    expect(outcome.aborted).toContain("Iteration cap");
    expect(outcome.iterations).toBe(3);
  });

  it("rejects structurally invalid requests up front", async () => {
    const { analyser } = makeAnalyser([]);
    await expect(analyser.analyse(makeRequest({ kql: undefined }))).rejects.toThrow(/kql is required/);
    await expect(analyser.analyse(makeRequest({ timespan: "yesterday-ish" }))).rejects.toThrow(
      /timespan is invalid/,
    );
    await expect(
      analyser.analyse(makeRequest({ mode: "audit_everything" as AnalyserRequest["mode"] })),
    ).rejects.toThrow(/mode must be/);
  });
});
