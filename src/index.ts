/**
 * sentret — Claude-powered KQL Detection Rule Analyser for
 * Microsoft Sentinel / Azure Log Analytics.
 */
export * from "./types.js";
export { loadConfig } from "./config.js";
export {
  DetectionAnalyser,
  type AnalyserDeps,
  type AnalysisOutcome,
  type RefusalInfo,
} from "./services/detection_analyser.js";
export * from "./llm/types.js";
export { buildProvider } from "./llm/factory.js";
export { AnthropicProvider } from "./llm/anthropic_provider.js";
export { OpenAIProvider, type OpenAIProviderOptions } from "./llm/openai_provider.js";
export { buildToolDefinitions, loadReportSchema, TOOL_NAMES } from "./services/tool_definitions.js";
export { assessQuerySafety, validateTimespan } from "./services/query_safety.js";
export { AuditLog } from "./services/audit_log.js";
export {
  renderMarkdownReport,
  saveReport,
  validateReport,
  buildSampleReport,
} from "./services/report_renderer.js";
export { AzureTokenProvider } from "./tools/azure_auth.js";
export { LogAnalyticsClient } from "./tools/log_analytics_client.js";
export { SentinelClient, SENTINEL_API_VERSION } from "./tools/sentinel_client.js";
export { lookupMitre, MITRE_TACTICS, MITRE_TECHNIQUES } from "./tools/mitre.js";
