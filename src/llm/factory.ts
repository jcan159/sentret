import Anthropic from "@anthropic-ai/sdk";
import OpenAI, { AzureOpenAI } from "openai";
import { DefaultAzureCredential, getBearerTokenProvider } from "@azure/identity";

import type { AnalyserConfig } from "../types.js";
import type { LlmProvider } from "./types.js";
import { AnthropicProvider } from "./anthropic_provider.js";
import { OpenAIProvider } from "./openai_provider.js";

/** Entra ID scope for Azure AI Foundry / Azure OpenAI. */
const AZURE_COGNITIVE_SCOPE = "https://cognitiveservices.azure.com/.default";

/**
 * Constructs the configured LLM provider. API keys come from the standard
 * environment variables the underlying SDKs read (ANTHROPIC_API_KEY /
 * OPENAI_API_KEY / AZURE_OPENAI_API_KEY); only the endpoint, model, deployment,
 * and provider choice are config.
 */
export function buildProvider(
  config: AnalyserConfig,
  env: NodeJS.ProcessEnv = process.env,
): LlmProvider {
  if (config.provider === "azure") {
    return buildAzureProvider(config, env);
  }

  if (config.provider === "openai") {
    const client = new OpenAI(config.openaiBaseUrl ? { baseURL: config.openaiBaseUrl } : {});
    return new OpenAIProvider({ client, model: config.openaiModel, reasoning: config.reasoning });
  }

  const client = new Anthropic();
  const fallback = config.fallbackModel
    ? new AnthropicProvider({ client, model: config.fallbackModel })
    : undefined;
  return new AnthropicProvider({ client, model: config.anthropicModel, fallback });
}

function buildAzureProvider(config: AnalyserConfig, env: NodeJS.ProcessEnv): LlmProvider {
  if (!config.azureEndpoint) {
    throw new Error(
      "Azure provider requires AZURE_OPENAI_ENDPOINT (your Foundry/Azure OpenAI resource URL).",
    );
  }
  // On Azure the "model" is the deployment name.
  const deployment = config.azureDeployment ?? config.openaiModel;
  const apiVersion = config.azureApiVersion;
  const apiKey = env.AZURE_OPENAI_API_KEY;

  // Prefer an explicit api-key; otherwise authenticate with Entra ID via
  // DefaultAzureCredential (the same identity used for Log Analytics — az login,
  // managed identity, or AZURE_* service-principal vars).
  const client = apiKey
    ? new AzureOpenAI({ endpoint: config.azureEndpoint, apiKey, apiVersion, deployment })
    : new AzureOpenAI({
        endpoint: config.azureEndpoint,
        apiVersion,
        deployment,
        azureADTokenProvider: getBearerTokenProvider(
          new DefaultAzureCredential(),
          AZURE_COGNITIVE_SCOPE,
        ),
      });

  return new OpenAIProvider({ client, model: deployment, reasoning: config.reasoning });
}
