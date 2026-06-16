import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import type { AddressInfo } from "node:net";
import type { Server } from "node:http";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { loadConfig } from "../config.js";
import type { AnalyserConfig } from "../types.js";
import { createSentretServer, type AnalyserFactory, type AnalyserSinks } from "./server.js";
import type { DetectionAnalyser } from "../services/detection_analyser.js";

let server: Server;
let base: string;
let config: AnalyserConfig;
/** Captures the config the factory received, to assert per-request guards. */
let receivedConfig: AnalyserConfig | undefined;

/** A factory that returns a stub analyser exercising every sink + an outcome. */
const fakeFactory: AnalyserFactory = (cfg, sinks: AnalyserSinks) => {
  receivedConfig = cfg;
  const analyse = async () => {
    sinks.onToolCall("run_log_analytics_query", { purpose: "Validate volume" });
    sinks.onText("Working on it. ");
    sinks.onThinking("considering schema");
    sinks.onText("Done.");
    return {
      report: {
        analysis_id: "sentret_test_abc",
        verdict: "Deploy after changes",
        overall_score: 72,
        rating: "Needs Tuning",
        kql: { recommended_query: "SigninLogs | count" },
        summary: { main_finding: "ok", recommended_action: "tune", top_strengths: [], top_issues: [], required_fixes: [] },
      },
      markdown: "# KQL Detection Rule Analysis\n\nFinal.",
      savedFiles: [],
      modelUsed: "fake-model",
      iterations: 1,
    };
  };
  return { analyse } as unknown as DetectionAnalyser;
};

async function startTestServer(factory: AnalyserFactory): Promise<void> {
  const dir = await mkdtemp(path.join(tmpdir(), "sentret-web-"));
  config = loadConfig({} as NodeJS.ProcessEnv, {
    outputDir: dir,
    auditLogPath: path.join(dir, "audit.jsonl"),
    allowDeploy: true, // ensure the web layer forces this back to false
  });
  server = createSentretServer({
    baseConfig: config,
    analyserFactory: factory,
    env: { ANTHROPIC_API_KEY: "test-key" } as NodeJS.ProcessEnv,
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const addr = server.address() as AddressInfo;
  base = `http://127.0.0.1:${addr.port}`;
}

beforeEach(async () => {
  receivedConfig = undefined;
  await startTestServer(fakeFactory);
});

afterEach(async () => {
  await new Promise<void>((resolve) => server.close(() => resolve()));
});

/** Parse a captured SSE body into [{event, data}] records. */
function parseSse(body: string): { event: string; data: unknown }[] {
  const out: { event: string; data: unknown }[] = [];
  for (const chunk of body.split("\n\n")) {
    if (!chunk.trim()) continue;
    let event = "message";
    let dataStr = "";
    for (const line of chunk.split("\n")) {
      if (line.startsWith("event:")) event = line.slice(6).trim();
      else if (line.startsWith("data:")) dataStr += line.slice(5).trim();
    }
    out.push({ event, data: dataStr ? JSON.parse(dataStr) : null });
  }
  return out;
}

describe("Sentret web server", () => {
  it("GET /api/health returns ok", async () => {
    const res = await fetch(`${base}/api/health`);
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ status: "ok" });
  });

  it("GET /api/config exposes non-secret config only", async () => {
    const res = await fetch(`${base}/api/config`);
    const cfg = (await res.json()) as Record<string, unknown>;
    expect(cfg.provider).toBe(config.provider);
    expect(cfg).toHaveProperty("anthropicModel");
    expect(cfg).toHaveProperty("effort");
    // Provider availability is booleans only (derived from injected env).
    expect(cfg.available).toEqual({ anthropic: true, openai: false, azure: false });
    // No secret material should ever appear — not even the injected key value.
    const serialized = JSON.stringify(cfg).toLowerCase();
    expect(serialized).not.toContain("api_key");
    expect(serialized).not.toContain("apikey");
    expect(serialized).not.toContain("token");
    expect(serialized).not.toContain("test-key");
  });

  it("GET / serves the web UI", async () => {
    const res = await fetch(`${base}/`);
    expect(res.status).toBe(200);
    expect(res.headers.get("content-type")).toContain("text/html");
    expect(await res.text()).toContain("sentret");
  });

  it("rejects path traversal on static assets", async () => {
    const res = await fetch(`${base}/../server.ts`);
    expect(res.status).not.toBe(200);
    expect(await res.text()).not.toContain("createSentretServer");
  });

  it("POST /api/analyse streams start/tool/text/report/done events", async () => {
    const res = await fetch(`${base}/api/analyse`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        request: {
          mode: "analyse_existing_rule",
          detection_intent: "x",
          workspace_id: "00000000-0000-0000-0000-000000000000",
          timespan: "P7D",
          kql: "SigninLogs | count",
        },
      }),
    });
    expect(res.status).toBe(200);
    expect(res.headers.get("content-type")).toContain("text/event-stream");

    const events = parseSse(await res.text());
    const types = events.map((e) => e.event);
    expect(types).toContain("start");
    expect(types).toContain("tool");
    expect(types).toContain("text");
    expect(types).toContain("report");
    expect(types).toContain("done");

    const tool = events.find((e) => e.event === "tool")!.data as { name: string; purpose: string };
    expect(tool).toMatchObject({ name: "run_log_analytics_query", purpose: "Validate volume" });

    const text = events.filter((e) => e.event === "text").map((e) => (e.data as { text: string }).text).join("");
    expect(text).toBe("Working on it. Done.");

    const done = events.find((e) => e.event === "done")!.data as Record<string, unknown>;
    expect(done.verdict).toBe("Deploy after changes");
    expect(done.overall_score).toBe(72);
    expect(done.markdown).toContain("Final.");
    expect(done.modelUsed).toBe("fake-model");
  });

  it("forces allowDeploy off for web runs even when base config enables it", async () => {
    await fetch(`${base}/api/analyse`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        request: {
          mode: "analyse_existing_rule",
          detection_intent: "x",
          workspace_id: "00000000-0000-0000-0000-000000000000",
          timespan: "P7D",
          kql: "SigninLogs | count",
        },
      }),
    });
    expect(config.allowDeploy).toBe(true); // base config had it on
    expect(receivedConfig?.allowDeploy).toBe(false); // web layer forced it off
  });

  it("applies provider/effort overrides", async () => {
    await fetch(`${base}/api/analyse`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        request: {
          mode: "create_new_detection",
          detection_intent: "x",
          workspace_id: "00000000-0000-0000-0000-000000000000",
          timespan: "P7D",
        },
        overrides: { provider: "openai", effort: "low" },
      }),
    });
    expect(receivedConfig?.provider).toBe("openai");
    expect(receivedConfig?.effort).toBe("low");
  });

  it("returns 400 on a malformed body", async () => {
    const res = await fetch(`${base}/api/analyse`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: "not json",
    });
    expect(res.status).toBe(400);
  });
});
