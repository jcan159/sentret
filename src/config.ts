import type { AnalyserConfig } from "./types.js";

const DEFAULTS: AnalyserConfig = {
  provider: "anthropic",
  anthropicModel: "claude-fable-5",
  fallbackModel: "claude-opus-4-8",
  openaiModel: "gpt-4.1",
  // Best-guess default; set AZURE_OPENAI_API_VERSION to match your Foundry deployment.
  azureApiVersion: "2025-04-01-preview",
  reasoning: "auto",
  effort: "high",
  maxTokens: 64_000,
  maxIterations: 40,
  allowDeploy: false,
  logAnalyticsEndpoint: "https://api.loganalytics.azure.com",
  armEndpoint: "https://management.azure.com",
  outputDir: "./reports",
  auditLogPath: "./audit/queries.jsonl",
  maxResultRows: 100,
  maxResultChars: 40_000,
};

const EFFORT_LEVELS = new Set(["low", "medium", "high", "xhigh", "max"]);

function intFromEnv(value: string | undefined, fallback: number): number {
  if (!value) return fallback;
  const parsed = Number.parseInt(value, 10);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback;
}

/**
 * Builds the analyser configuration from environment variables (SENTRET_*)
 * with optional programmatic overrides taking precedence.
 */
export function loadConfig(
  env: NodeJS.ProcessEnv = process.env,
  overrides: Partial<AnalyserConfig> = {},
): AnalyserConfig {
  const effortEnv = env.SENTRET_EFFORT;
  const effort =
    effortEnv && EFFORT_LEVELS.has(effortEnv)
      ? (effortEnv as AnalyserConfig["effort"])
      : DEFAULTS.effort;

  // An explicitly empty SENTRET_FALLBACK_MODEL disables refusal fallback.
  const fallbackModel =
    env.SENTRET_FALLBACK_MODEL === undefined
      ? DEFAULTS.fallbackModel
      : env.SENTRET_FALLBACK_MODEL.trim() || undefined;

  // Provider: explicit setting wins, else auto-detect from whichever key/endpoint is present.
  const providerEnv = env.SENTRET_PROVIDER?.trim().toLowerCase();
  let provider: AnalyserConfig["provider"];
  if (providerEnv === "openai" || providerEnv === "anthropic" || providerEnv === "azure") {
    provider = providerEnv;
  } else if (env.ANTHROPIC_API_KEY || env.ANTHROPIC_AUTH_TOKEN) {
    provider = "anthropic";
  } else if (env.AZURE_OPENAI_ENDPOINT) {
    provider = "azure";
  } else if (env.OPENAI_API_KEY) {
    provider = "openai";
  } else {
    provider = DEFAULTS.provider;
  }

  const reasoningEnv = env.SENTRET_REASONING?.trim().toLowerCase();
  const reasoning: AnalyserConfig["reasoning"] =
    reasoningEnv === "always" || reasoningEnv === "never" || reasoningEnv === "auto"
      ? reasoningEnv
      : DEFAULTS.reasoning;

  const config: AnalyserConfig = {
    ...DEFAULTS,
    provider,
    anthropicModel: env.SENTRET_MODEL?.trim() || DEFAULTS.anthropicModel,
    fallbackModel,
    openaiModel:
      env.SENTRET_OPENAI_MODEL?.trim() || env.OPENAI_MODEL?.trim() || DEFAULTS.openaiModel,
    openaiBaseUrl:
      env.SENTRET_OPENAI_BASE_URL?.trim() || env.OPENAI_BASE_URL?.trim() || undefined,
    azureEndpoint: env.AZURE_OPENAI_ENDPOINT?.trim() || undefined,
    azureDeployment:
      env.AZURE_OPENAI_DEPLOYMENT?.trim() || env.SENTRET_OPENAI_MODEL?.trim() || undefined,
    azureApiVersion: env.AZURE_OPENAI_API_VERSION?.trim() || DEFAULTS.azureApiVersion,
    reasoning,
    effort,
    maxTokens: intFromEnv(env.SENTRET_MAX_TOKENS, DEFAULTS.maxTokens),
    maxIterations: intFromEnv(env.SENTRET_MAX_ITERATIONS, DEFAULTS.maxIterations),
    logAnalyticsEndpoint:
      env.SENTRET_LOG_ANALYTICS_ENDPOINT?.trim() || DEFAULTS.logAnalyticsEndpoint,
    armEndpoint: env.SENTRET_ARM_ENDPOINT?.trim() || DEFAULTS.armEndpoint,
    outputDir: env.SENTRET_OUTPUT_DIR?.trim() || DEFAULTS.outputDir,
    auditLogPath: env.SENTRET_AUDIT_LOG?.trim() || DEFAULTS.auditLogPath,
    maxResultRows: intFromEnv(env.SENTRET_MAX_RESULT_ROWS, DEFAULTS.maxResultRows),
    maxResultChars: intFromEnv(env.SENTRET_MAX_RESULT_CHARS, DEFAULTS.maxResultChars),
  };

  return { ...config, ...overrides };
}
