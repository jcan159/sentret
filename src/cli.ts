#!/usr/bin/env node
/**
 * sentret CLI — analyse or create a Microsoft Sentinel KQL detection rule.
 *
 * Usage:
 *   sentret --input request.json [options]
 *
 * Options:
 *   -i, --input <file>     Path to the analyser request JSON (see examples/).
 *   --output-dir <dir>     Where to write the report (default ./reports).
 *   --model <id>           Override the Anthropic model.
 *   --effort <level>       low | medium | high | xhigh | max.
 *   --static-only          Force allow_query_execution=false (no live queries).
 *   --allow-deploy         Approve Sentinel rule deployment for this run.
 *   --no-fallback          Disable the refusal-fallback model.
 *   -h, --help             Show this help.
 */
import { readFileSync } from "node:fs";
import { parseArgs } from "node:util";
import process from "node:process";

import { loadConfig } from "./config.js";
import type { AnalyserConfig, AnalyserRequest } from "./types.js";
import { buildProvider } from "./llm/factory.js";
import { AuditLog } from "./services/audit_log.js";
import { DetectionAnalyser } from "./services/detection_analyser.js";
import { AzureTokenProvider } from "./tools/azure_auth.js";
import { LogAnalyticsClient } from "./tools/log_analytics_client.js";
import { SentinelClient } from "./tools/sentinel_client.js";

const HELP = `sentret — KQL Detection Rule Analyser (provider-agnostic)

Usage: sentret --input request.json [options]

Options:
  -i, --input <file>     Analyser request JSON (see examples/example_user_request.json)
  --output-dir <dir>     Report output directory (default ./reports)
  --provider <name>      anthropic | openai | azure (default: auto-detected from env)
  --model <id>           Model override (Azure: the deployment name)
  --effort <level>       low | medium | high | xhigh | max (default high)
  --static-only          Skip all live workspace queries (static analysis only)
  --allow-deploy         Approve Sentinel rule deployment for this run
  --no-fallback          Disable the refusal-fallback model (Anthropic only)
  -h, --help             Show this help

Environment: set ANTHROPIC_API_KEY, OPENAI_API_KEY, or (Azure AI Foundry)
AZURE_OPENAI_ENDPOINT + AZURE_OPENAI_DEPLOYMENT. The provider is auto-detected
from whichever is present unless --provider / SENTRET_PROVIDER is set. Azure
auth uses AZURE_OPENAI_API_KEY if set, else Entra ID via DefaultAzureCredential
(az login / managed identity). Azure also reads AZURE_OPENAI_API_VERSION and
SENTRET_REASONING (auto|always|never). Azure access for Log Analytics queries
uses DefaultAzureCredential too. A .env file in the working directory is loaded
automatically if present.
`;

function parseCliArgs() {
  return parseArgs({
    options: {
      input: { type: "string", short: "i" },
      "output-dir": { type: "string" },
      provider: { type: "string" },
      model: { type: "string" },
      effort: { type: "string" },
      "static-only": { type: "boolean", default: false },
      "allow-deploy": { type: "boolean", default: false },
      "no-fallback": { type: "boolean", default: false },
      help: { type: "boolean", short: "h", default: false },
    },
  }).values;
}

async function main(): Promise<number> {
  try {
    process.loadEnvFile?.(".env");
  } catch {
    // No .env file — environment variables are used directly.
  }

  let values: ReturnType<typeof parseCliArgs>;
  try {
    values = parseCliArgs();
  } catch (error) {
    process.stderr.write(
      `Error: ${error instanceof Error ? error.message : error}\n\n${HELP}`,
    );
    return 2;
  }

  if (values.help || !values.input) {
    process.stdout.write(HELP);
    return values.help ? 0 : 2;
  }

  let request: AnalyserRequest;
  try {
    request = JSON.parse(readFileSync(values.input, "utf8")) as AnalyserRequest;
  } catch (error) {
    process.stderr.write(
      `Error: could not read request file ${values.input}: ${error instanceof Error ? error.message : error}\n`,
    );
    return 2;
  }

  if (values["static-only"]) {
    request.allow_query_execution = false;
  }

  const overrides: Partial<AnalyserConfig> = {
    allowDeploy: values["allow-deploy"] ?? false,
  };
  if (values["output-dir"]) overrides.outputDir = values["output-dir"];
  if (values["no-fallback"]) overrides.fallbackModel = undefined;
  if (values.provider) {
    if (!["anthropic", "openai", "azure"].includes(values.provider)) {
      process.stderr.write(
        `Error: invalid provider "${values.provider}" (use anthropic, openai, or azure).\n`,
      );
      return 2;
    }
    overrides.provider = values.provider as AnalyserConfig["provider"];
  }
  if (values.effort) {
    const effort = values.effort as AnalyserConfig["effort"];
    if (!["low", "medium", "high", "xhigh", "max"].includes(effort)) {
      process.stderr.write(`Error: invalid effort "${values.effort}".\n`);
      return 2;
    }
    overrides.effort = effort;
  }

  let config = loadConfig(process.env, overrides);
  // --model targets the active provider's model (the deployment name for Azure).
  if (values.model) {
    if (config.provider === "azure") config = { ...config, azureDeployment: values.model };
    else if (config.provider === "openai") config = { ...config, openaiModel: values.model };
    else config = { ...config, anthropicModel: values.model };
  }

  // Credential preflight per provider. Azure auth can come from Entra ID, so we
  // only require the endpoint + deployment here, not a key.
  if (config.provider === "azure") {
    const missing: string[] = [];
    if (!config.azureEndpoint) missing.push("AZURE_OPENAI_ENDPOINT");
    if (!(config.azureDeployment ?? config.openaiModel))
      missing.push("AZURE_OPENAI_DEPLOYMENT (or --model)");
    if (missing.length > 0) {
      process.stderr.write(`Error: ${missing.join(" and ")} not set (provider: azure).\n`);
      return 2;
    }
    if (!process.env.AZURE_OPENAI_API_KEY) {
      process.stderr.write("Note: AZURE_OPENAI_API_KEY not set; using Entra ID (DefaultAzureCredential).\n");
    }
  } else {
    const keyMissing =
      config.provider === "openai"
        ? !process.env.OPENAI_API_KEY
        : !process.env.ANTHROPIC_API_KEY && !process.env.ANTHROPIC_AUTH_TOKEN;
    if (keyMissing) {
      const needed = config.provider === "openai" ? "OPENAI_API_KEY" : "ANTHROPIC_API_KEY";
      process.stderr.write(`Error: ${needed} is not set (provider: ${config.provider}).\n`);
      return 2;
    }
  }

  const tokenProvider = new AzureTokenProvider();

  const analyser = new DetectionAnalyser({
    provider: buildProvider(config),
    logAnalytics: new LogAnalyticsClient({
      tokenProvider,
      endpoint: config.logAnalyticsEndpoint,
    }),
    sentinel: new SentinelClient({ tokenProvider, armEndpoint: config.armEndpoint }),
    auditLog: new AuditLog(config.auditLogPath),
    config,
    onText: (text) => process.stdout.write(text),
    // Summarized thinking goes to stderr so stdout stays the clean text channel.
    onThinking: (text) => process.stderr.write(text),
    onToolCall: (name, input) => {
      const purpose =
        typeof input === "object" && input !== null && "purpose" in input
          ? ` — ${(input as { purpose?: string }).purpose}`
          : "";
      process.stderr.write(`\n[tool] ${name}${purpose}\n`);
    },
  });

  const outcome = await analyser.analyse(request);
  process.stdout.write("\n\n");

  if (outcome.refusal) {
    const recovered = !outcome.aborted && outcome.modelUsed !== outcome.refusal.model;
    process.stderr.write(
      `Note: ${outcome.refusal.model} declined (category: ${outcome.refusal.category ?? "unspecified"}); ` +
        (recovered
          ? `completed on fallback model ${outcome.modelUsed}.\n`
          : "the run did not complete on a fallback model.\n"),
    );
  }
  if (outcome.aborted) {
    process.stderr.write(`Run aborted: ${outcome.aborted}\n`);
  }
  if (outcome.report) {
    process.stderr.write(
      `Verdict: ${outcome.report.verdict} | Score: ${outcome.report.overall_score}/100 (${outcome.report.rating})\n`,
    );
  }
  for (const file of outcome.savedFiles) {
    process.stderr.write(`Saved: ${file}\n`);
  }

  return outcome.report ? 0 : 1;
}

/** Resolves once all previously queued writes on the stream reach the OS. */
function flush(stream: NodeJS.WriteStream): Promise<void> {
  return new Promise((resolve) => stream.write("", () => resolve()));
}

main().then(
  async (code) => {
    await Promise.all([flush(process.stdout), flush(process.stderr)]);
    process.exit(code);
  },
  async (error) => {
    process.stderr.write(`Fatal: ${error instanceof Error ? error.message : error}\n`);
    await Promise.all([flush(process.stdout), flush(process.stderr)]);
    process.exit(1);
  },
);
