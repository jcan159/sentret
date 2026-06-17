/**
 * Generates README screenshots of the Sentret web UI.
 *
 * Spins up the real server with a FAKE analyser (canned stream + the canonical
 * sample report) so no API keys or network are needed, drives the system Chrome
 * over the DevTools Protocol (no extra dependency), and captures two PNGs:
 *   docs/screenshots/web-ui-form.png    — the request form (themed)
 *   docs/screenshots/web-ui-report.png  — a completed analysis with report
 *
 * Run with: npm run screenshots
 */
import { spawn, type ChildProcess } from "node:child_process";
import { mkdir, mkdtemp, readFile, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import type { AddressInfo } from "node:net";
import type { Server } from "node:http";

import { loadConfig } from "../src/config.js";
import { createSentretServer, type AnalyserFactory } from "../src/server/server.js";
import { buildSampleReport, renderMarkdownReport } from "../src/services/report_renderer.js";
import type { DetectionAnalyser } from "../src/services/detection_analyser.js";

const CHROME = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome";
const OUT_DIR = fileURLToPath(new URL("../docs/screenshots/", import.meta.url));

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

// --- Fake analyser: a believable run with no network -----------------------
const factory: AnalyserFactory = (_cfg, sinks) => {
  const analyse = async () => {
    sinks.onText("Restating the detection intent and parsing the supplied KQL.\n");
    sinks.onToolCall("get_workspace_schema", { purpose: "Confirm SigninLogs schema and fields" });
    sinks.onText("SigninLogs is present with the expected columns.\n");
    sinks.onToolCall("run_log_analytics_query", {
      purpose: "Validate SigninLogs volume and field population over P7D",
    });
    sinks.onThinking("weighing precision vs recall for the country-anomaly threshold");
    sinks.onText("Data is well populated. Tuning thresholds and finalising the Sentinel rule.\n");
    const report = buildSampleReport();
    return {
      report,
      markdown: renderMarkdownReport(report),
      savedFiles: [],
      modelUsed: "claude-fable-5",
      iterations: 3,
    };
  };
  return { analyse } as unknown as DetectionAnalyser;
};

// --- Minimal CDP client over the system Chrome -----------------------------
class CDP {
  #ws: WebSocket;
  #id = 0;
  #pending = new Map<number, (v: unknown) => void>();
  #events = new Map<string, ((p: unknown) => void)[]>();

  private constructor(ws: WebSocket) {
    this.#ws = ws;
    ws.addEventListener("message", (e) => {
      const msg = JSON.parse(String(e.data)) as {
        id?: number;
        result?: unknown;
        method?: string;
        params?: unknown;
      };
      if (msg.id !== undefined && this.#pending.has(msg.id)) {
        this.#pending.get(msg.id)!(msg.result);
        this.#pending.delete(msg.id);
      } else if (msg.method) {
        for (const cb of this.#events.get(msg.method) ?? []) cb(msg.params);
      }
    });
  }

  static connect(wsUrl: string): Promise<CDP> {
    return new Promise((resolve, reject) => {
      const ws = new WebSocket(wsUrl);
      ws.addEventListener("open", () => resolve(new CDP(ws)));
      ws.addEventListener("error", () => reject(new Error("CDP websocket error")));
    });
  }

  send(method: string, params: Record<string, unknown> = {}): Promise<any> {
    const id = ++this.#id;
    return new Promise((resolve) => {
      this.#pending.set(id, resolve);
      this.#ws.send(JSON.stringify({ id, method, params }));
    });
  }

  once(method: string): Promise<unknown> {
    return new Promise((resolve) => {
      const list = this.#events.get(method) ?? [];
      list.push((p) => resolve(p));
      this.#events.set(method, list);
    });
  }

  async evaluate<T = unknown>(expression: string): Promise<T> {
    const r = (await this.send("Runtime.evaluate", {
      expression,
      returnByValue: true,
      awaitPromise: true,
    })) as { result?: { value?: T } };
    return r.result?.value as T;
  }

  async shot(file: string): Promise<void> {
    const r = (await this.send("Page.captureScreenshot", {
      format: "png",
      captureBeyondViewport: true,
    })) as { data: string };
    await writeFile(file, Buffer.from(r.data, "base64"));
  }

  close(): void {
    this.#ws.close();
  }
}

async function launchChrome(): Promise<{ proc: ChildProcess; wsUrl: string; userDir: string }> {
  const userDir = await mkdtemp(path.join(tmpdir(), "sentret-shot-"));
  const proc = spawn(CHROME, [
    "--headless=new",
    "--disable-gpu",
    "--no-first-run",
    "--no-default-browser-check",
    "--hide-scrollbars",
    "--force-device-scale-factor=2",
    "--window-size=1280,1000",
    `--user-data-dir=${userDir}`,
    "--remote-debugging-port=0",
    "about:blank",
  ]);
  proc.stderr?.on("data", () => {}); // silence Chrome chatter

  // Chrome writes the chosen port to DevToolsActivePort once ready.
  const portFile = path.join(userDir, "DevToolsActivePort");
  let port = "";
  for (let i = 0; i < 100; i++) {
    try {
      const lines = (await readFile(portFile, "utf8")).split("\n");
      if (lines[0]) {
        port = lines[0].trim();
        break;
      }
    } catch {
      /* not ready */
    }
    await sleep(100);
  }
  if (!port) throw new Error("Chrome did not expose a debugging port");

  const targets = (await (await fetch(`http://127.0.0.1:${port}/json/list`)).json()) as {
    type: string;
    webSocketDebuggerUrl: string;
  }[];
  const page = targets.find((t) => t.type === "page");
  if (!page) throw new Error("No Chrome page target found");
  return { proc, wsUrl: page.webSocketDebuggerUrl, userDir };
}

async function main(): Promise<void> {
  await mkdir(OUT_DIR, { recursive: true });
  const server: Server = createSentretServer({
    baseConfig: loadConfig({} as NodeJS.ProcessEnv),
    analyserFactory: factory,
    env: { ANTHROPIC_API_KEY: "demo" } as NodeJS.ProcessEnv,
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  const port = (server.address() as AddressInfo).port;
  const url = `http://127.0.0.1:${port}/`;

  const { proc, wsUrl, userDir } = await launchChrome();
  const cdp = await CDP.connect(wsUrl);
  try {
    await cdp.send("Page.enable");
    await cdp.send("Runtime.enable");

    // 1) Form view — load the example so it looks alive.
    const loaded = cdp.once("Page.loadEventFired");
    await cdp.send("Page.navigate", { url });
    await loaded;
    await sleep(400); // let /api/config populate the provider selector
    await cdp.evaluate("document.getElementById('example').click()");
    await sleep(250);
    await cdp.shot(path.join(OUT_DIR, "web-ui-form.png"));
    console.log("captured web-ui-form.png");

    // 2) Completed-run view — submit and wait for the report card.
    await cdp.evaluate(
      "document.getElementById('form').requestSubmit ? document.getElementById('form').requestSubmit() : document.getElementById('run').click()",
    );
    let ready = false;
    for (let i = 0; i < 100; i++) {
      ready = await cdp.evaluate<boolean>(
        "!document.getElementById('report-card').classList.contains('hidden') && document.getElementById('verdict').classList.contains('show')",
      );
      if (ready) break;
      await sleep(100);
    }
    if (!ready) throw new Error("report did not render in time");
    await sleep(300);
    await cdp.shot(path.join(OUT_DIR, "web-ui-report.png"));
    console.log("captured web-ui-report.png");
  } finally {
    cdp.close();
    proc.kill("SIGKILL");
    await new Promise<void>((r) => server.close(() => r()));
    await rm(userDir, { recursive: true, force: true });
  }
}

main().then(
  () => process.exit(0),
  (e: unknown) => {
    console.error("screenshot failed:", e instanceof Error ? e.message : e);
    process.exit(1);
  },
);
