import { afterEach, describe, expect, it } from "vitest";

import { loadConfig } from "../config.js";
import { buildProvider } from "./factory.js";

// ---------------------------------------------------------------------------
// loadConfig — provider resolution
//
// These tests pass an explicit env object to loadConfig, so they never depend
// on (or mutate) the ambient process.env. The SDK constructors are only
// exercised in the buildProvider section below, where dummy API keys are set.
// ---------------------------------------------------------------------------

describe("loadConfig provider auto-detection", () => {
  it("selects anthropic when only ANTHROPIC_API_KEY is set", () => {
    const config = loadConfig({ ANTHROPIC_API_KEY: "sk-ant-test" });
    expect(config.provider).toBe("anthropic");
  });

  it("selects anthropic when only ANTHROPIC_AUTH_TOKEN is set", () => {
    const config = loadConfig({ ANTHROPIC_AUTH_TOKEN: "tok-test" });
    expect(config.provider).toBe("anthropic");
  });

  it("selects openai when only OPENAI_API_KEY is set", () => {
    const config = loadConfig({ OPENAI_API_KEY: "sk-openai-test" });
    expect(config.provider).toBe("openai");
  });

  it("prefers anthropic when both keys are set", () => {
    const config = loadConfig({
      ANTHROPIC_API_KEY: "sk-ant-test",
      OPENAI_API_KEY: "sk-openai-test",
    });
    expect(config.provider).toBe("anthropic");
  });

  it("defaults to anthropic when neither key is set", () => {
    const config = loadConfig({});
    expect(config.provider).toBe("anthropic");
  });
});

describe("loadConfig explicit SENTRET_PROVIDER", () => {
  it("overrides auto-detection to openai despite ANTHROPIC_API_KEY present", () => {
    const config = loadConfig({
      SENTRET_PROVIDER: "openai",
      ANTHROPIC_API_KEY: "sk-ant-test",
    });
    expect(config.provider).toBe("openai");
  });

  it("overrides auto-detection to anthropic despite OPENAI_API_KEY present", () => {
    const config = loadConfig({
      SENTRET_PROVIDER: "anthropic",
      OPENAI_API_KEY: "sk-openai-test",
    });
    expect(config.provider).toBe("anthropic");
  });

  it("is case-insensitive and trims whitespace", () => {
    const config = loadConfig({
      SENTRET_PROVIDER: "  OpenAI  ",
      ANTHROPIC_API_KEY: "sk-ant-test",
    });
    expect(config.provider).toBe("openai");
  });

  it("falls back to auto-detect when the value is invalid", () => {
    const config = loadConfig({
      SENTRET_PROVIDER: "gemini",
      OPENAI_API_KEY: "sk-openai-test",
    });
    // Invalid provider -> ignored, auto-detect from the present key.
    expect(config.provider).toBe("openai");
  });

  it("falls back to the default when the value is invalid and no key is present", () => {
    const config = loadConfig({ SENTRET_PROVIDER: "not-a-provider" });
    expect(config.provider).toBe("anthropic");
  });
});

describe("loadConfig openaiModel precedence", () => {
  it("prefers SENTRET_OPENAI_MODEL over OPENAI_MODEL and the default", () => {
    const config = loadConfig({
      SENTRET_OPENAI_MODEL: "gpt-5-mini",
      OPENAI_MODEL: "gpt-4o",
    });
    expect(config.openaiModel).toBe("gpt-5-mini");
  });

  it("uses OPENAI_MODEL when SENTRET_OPENAI_MODEL is absent", () => {
    const config = loadConfig({ OPENAI_MODEL: "gpt-4o" });
    expect(config.openaiModel).toBe("gpt-4o");
  });

  it("defaults to gpt-4.1 when neither model env var is set", () => {
    const config = loadConfig({});
    expect(config.openaiModel).toBe("gpt-4.1");
  });

  it("ignores a whitespace-only SENTRET_OPENAI_MODEL and uses OPENAI_MODEL", () => {
    const config = loadConfig({
      SENTRET_OPENAI_MODEL: "   ",
      OPENAI_MODEL: "gpt-4o",
    });
    expect(config.openaiModel).toBe("gpt-4o");
  });
});

describe("loadConfig openaiBaseUrl resolution", () => {
  it("prefers SENTRET_OPENAI_BASE_URL over OPENAI_BASE_URL", () => {
    const config = loadConfig({
      SENTRET_OPENAI_BASE_URL: "https://kql.example/v1",
      OPENAI_BASE_URL: "https://openai.example/v1",
    });
    expect(config.openaiBaseUrl).toBe("https://kql.example/v1");
  });

  it("uses OPENAI_BASE_URL when SENTRET_OPENAI_BASE_URL is absent", () => {
    const config = loadConfig({ OPENAI_BASE_URL: "https://openai.example/v1" });
    expect(config.openaiBaseUrl).toBe("https://openai.example/v1");
  });

  it("is undefined when neither base-url env var is set", () => {
    const config = loadConfig({});
    expect(config.openaiBaseUrl).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// buildProvider — wiring
//
// buildProvider constructs the real provider classes, which in turn call
// `new Anthropic()` / `new OpenAI()`. Those constructors read API keys from
// process.env (no network at construction). We set dummy keys for the duration
// of each test and restore the prior values afterward.
// ---------------------------------------------------------------------------

describe("buildProvider", () => {
  const saved: Record<string, string | undefined> = {};
  const KEYS = ["ANTHROPIC_API_KEY", "OPENAI_API_KEY"] as const;

  function setDummyKeys(): void {
    for (const k of KEYS) {
      saved[k] = process.env[k];
      process.env[k] = "test-dummy-key";
    }
  }

  afterEach(() => {
    for (const k of KEYS) {
      if (saved[k] === undefined) delete process.env[k];
      else process.env[k] = saved[k];
    }
  });

  it("returns an AnthropicProvider with a fallback when fallbackModel is set", () => {
    setDummyKeys();
    const config = loadConfig(
      { SENTRET_PROVIDER: "anthropic" },
      { anthropicModel: "claude-fable-5", fallbackModel: "claude-opus-4-8" },
    );

    const provider = buildProvider(config);

    expect(provider.name).toBe("anthropic");
    expect(provider.model).toBe("claude-fable-5");
    expect(provider.fallback).toBeDefined();
    expect(provider.fallback?.name).toBe("anthropic");
    expect(provider.fallback?.model).toBe("claude-opus-4-8");
  });

  it("returns an AnthropicProvider without a fallback when fallbackModel is undefined", () => {
    setDummyKeys();
    const config = loadConfig(
      { SENTRET_PROVIDER: "anthropic" },
      { anthropicModel: "claude-fable-5", fallbackModel: undefined },
    );

    const provider = buildProvider(config);

    expect(provider.name).toBe("anthropic");
    expect(provider.model).toBe("claude-fable-5");
    expect(provider.fallback).toBeUndefined();
  });

  it("disables the fallback when SENTRET_FALLBACK_MODEL is explicitly empty", () => {
    setDummyKeys();
    // An empty SENTRET_FALLBACK_MODEL resolves to fallbackModel === undefined.
    const config = loadConfig({ SENTRET_PROVIDER: "anthropic", SENTRET_FALLBACK_MODEL: "" });
    expect(config.fallbackModel).toBeUndefined();

    const provider = buildProvider(config);

    expect(provider.name).toBe("anthropic");
    expect(provider.fallback).toBeUndefined();
  });

  it("returns an OpenAIProvider using config.openaiModel", () => {
    setDummyKeys();
    const config = loadConfig(
      { SENTRET_PROVIDER: "openai" },
      { openaiModel: "gpt-4.1" },
    );

    const provider = buildProvider(config);

    expect(provider.name).toBe("openai");
    expect(provider.model).toBe("gpt-4.1");
    // The factory never wires a fallback for the openai branch.
    expect(provider.fallback).toBeUndefined();
  });

  it("constructs the OpenAIProvider with a custom base url without throwing", () => {
    setDummyKeys();
    const config = loadConfig(
      { SENTRET_PROVIDER: "openai" },
      { openaiModel: "gpt-4o", openaiBaseUrl: "https://compat.example/v1" },
    );

    const provider = buildProvider(config);

    expect(provider.name).toBe("openai");
    expect(provider.model).toBe("gpt-4o");
  });
});
