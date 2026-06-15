import { afterEach, describe, expect, it } from "vitest";

import type OpenAI from "openai";

import { loadConfig } from "../config.js";
import { buildProvider } from "./factory.js";
import { OpenAIProvider } from "./openai_provider.js";
import type { LlmRunOptions } from "./types.js";

// ---------------------------------------------------------------------------
// Azure provider config resolution
// ---------------------------------------------------------------------------

const AZ_ENV = {
  AZURE_OPENAI_ENDPOINT: "https://my-foundry.openai.azure.com",
  AZURE_OPENAI_DEPLOYMENT: "gpt-5-5-prod",
} as NodeJS.ProcessEnv;

describe("loadConfig — Azure", () => {
  it("auto-selects azure when AZURE_OPENAI_ENDPOINT is set and no Anthropic key", () => {
    expect(loadConfig(AZ_ENV).provider).toBe("azure");
  });

  it("prefers Anthropic when both an Anthropic key and an Azure endpoint are present", () => {
    expect(loadConfig({ ...AZ_ENV, ANTHROPIC_API_KEY: "x" }).provider).toBe("anthropic");
  });

  it("honours an explicit SENTRET_PROVIDER=azure even without an endpoint signal", () => {
    expect(loadConfig({ SENTRET_PROVIDER: "azure" } as NodeJS.ProcessEnv).provider).toBe("azure");
  });

  it("resolves deployment, api-version, and reasoning from env", () => {
    const c = loadConfig({
      ...AZ_ENV,
      AZURE_OPENAI_API_VERSION: "2025-09-01-preview",
      SENTRET_REASONING: "always",
    } as NodeJS.ProcessEnv);
    expect(c.azureEndpoint).toBe("https://my-foundry.openai.azure.com");
    expect(c.azureDeployment).toBe("gpt-5-5-prod");
    expect(c.azureApiVersion).toBe("2025-09-01-preview");
    expect(c.reasoning).toBe("always");
  });

  it("falls back deployment to SENTRET_OPENAI_MODEL and api-version to the default", () => {
    const c = loadConfig({
      SENTRET_PROVIDER: "azure",
      AZURE_OPENAI_ENDPOINT: "https://x.openai.azure.com",
      SENTRET_OPENAI_MODEL: "gpt-5.5",
    } as NodeJS.ProcessEnv);
    expect(c.azureDeployment).toBe("gpt-5.5");
    expect(c.azureApiVersion).toBe("2025-04-01-preview");
    expect(c.reasoning).toBe("auto");
  });

  it("ignores an invalid SENTRET_REASONING value", () => {
    expect(loadConfig({ ...AZ_ENV, SENTRET_REASONING: "loud" } as NodeJS.ProcessEnv).reasoning).toBe(
      "auto",
    );
  });
});

// ---------------------------------------------------------------------------
// buildProvider — Azure
// ---------------------------------------------------------------------------

describe("buildProvider — Azure", () => {
  it("builds an AzureOpenAI-backed provider via api-key, with the deployment as the model", () => {
    const config = loadConfig(AZ_ENV);
    const provider = buildProvider(config, { AZURE_OPENAI_API_KEY: "dummy-key" } as NodeJS.ProcessEnv);
    expect(provider.name).toBe("openai");
    expect(provider.model).toBe("gpt-5-5-prod");
    expect(provider.fallback).toBeUndefined();
  });

  it("builds via Entra ID (DefaultAzureCredential) when no api-key is present", () => {
    const config = loadConfig(AZ_ENV);
    // No AZURE_OPENAI_API_KEY -> Entra token provider; construction must not throw or hit the network.
    const provider = buildProvider(config, {} as NodeJS.ProcessEnv);
    expect(provider.name).toBe("openai");
    expect(provider.model).toBe("gpt-5-5-prod");
  });

  it("throws a clear error when the Azure endpoint is missing", () => {
    const config = loadConfig({ SENTRET_PROVIDER: "azure" } as NodeJS.ProcessEnv);
    expect(() => buildProvider(config, {} as NodeJS.ProcessEnv)).toThrow(/AZURE_OPENAI_ENDPOINT/);
  });
});

// ---------------------------------------------------------------------------
// Reasoning override (deployment names are opaque, so it must not rely on name-sniffing)
// ---------------------------------------------------------------------------

function makeFakeClient() {
  const calls: Record<string, unknown>[] = [];
  const client = {
    chat: {
      completions: {
        create(params: Record<string, unknown>) {
          calls.push(params);
          return (async function* () {
            yield { choices: [{ delta: { content: "" }, finish_reason: "stop" }] };
          })();
        },
      },
    },
  } as unknown as OpenAI;
  return { client, calls };
}

const RUN_OPTS: LlmRunOptions = {
  system: "s",
  tools: [],
  messages: [{ role: "user", text: "hi" }],
  maxTokens: 100,
  effort: "high",
};

function reasoningEffortOf(params: Record<string, unknown> | undefined): unknown {
  return params?.reasoning_effort;
}

describe("OpenAIProvider reasoning override", () => {
  it('reasoning "always" sends reasoning_effort even for a non-reasoning-named model', async () => {
    const { client, calls } = makeFakeClient();
    const p = new OpenAIProvider({ client, model: "my-azure-deployment", reasoning: "always" });
    await p.runTurn(RUN_OPTS);
    expect(reasoningEffortOf(calls[0])).toBe("high");
  });

  it('reasoning "never" omits reasoning_effort even for a reasoning-named model', async () => {
    const { client, calls } = makeFakeClient();
    const p = new OpenAIProvider({ client, model: "o3", reasoning: "never" });
    await p.runTurn(RUN_OPTS);
    expect(reasoningEffortOf(calls[0])).toBeUndefined();
  });

  it('reasoning "auto" infers from the model name', async () => {
    const a = makeFakeClient();
    await new OpenAIProvider({ client: a.client, model: "gpt-4.1", reasoning: "auto" }).runTurn(RUN_OPTS);
    expect(reasoningEffortOf(a.calls[0])).toBeUndefined();

    const b = makeFakeClient();
    await new OpenAIProvider({ client: b.client, model: "gpt-5.5", reasoning: "auto" }).runTurn(RUN_OPTS);
    expect(reasoningEffortOf(b.calls[0])).toBe("high");
  });

  it("maps effort tiers to OpenAI reasoning_effort", async () => {
    for (const [effort, expected] of [
      ["low", "low"],
      ["medium", "medium"],
      ["high", "high"],
      ["xhigh", "high"],
      ["max", "high"],
    ] as const) {
      const { client, calls } = makeFakeClient();
      await new OpenAIProvider({ client, model: "gpt-5.5", reasoning: "always" }).runTurn({
        ...RUN_OPTS,
        effort,
      });
      expect(reasoningEffortOf(calls[0])).toBe(expected);
    }
  });
});

afterEach(() => {
  // No process.env mutation in these tests; explicit hook kept for clarity.
});
