import { describe, it, expect } from "vitest";
import type Anthropic from "@anthropic-ai/sdk";

import { AnthropicProvider } from "./anthropic_provider.js";
import type { LlmMessage, LlmRunOptions, LlmToolDef } from "./types.js";

/**
 * Minimal stand-in for an Anthropic-style streamed message returned by
 * `stream.finalMessage()`. Only the fields the provider reads are required.
 */
interface FakeMessage {
  stop_reason: string | null;
  content: unknown[];
  stop_details?: { category?: string | null; explanation?: string | null } | null;
}

/** Records the params passed to `stream()` and the handlers registered on it. */
interface FakeAnthropic {
  client: Anthropic;
  /** Params captured from the most recent `messages.stream()` call. */
  lastParams: () => Record<string, unknown>;
  /** Event names (and callbacks) recorded via `stream.on(event, cb)`. */
  handlers: () => Map<string, (arg: string) => void>;
}

/**
 * Build a fake Anthropic client whose `messages.stream()` captures its params,
 * records `.on(event, cb)` handlers, and resolves `.finalMessage()` to the
 * scripted message. No network is touched.
 */
function makeFakeClient(message: FakeMessage): FakeAnthropic {
  let captured: Record<string, unknown> = {};
  const handlers = new Map<string, (arg: string) => void>();

  const client = {
    messages: {
      stream(params: Record<string, unknown>) {
        captured = params;
        return {
          on(event: string, cb: (arg: string) => void) {
            handlers.set(event, cb);
            return this;
          },
          finalMessage(): Promise<FakeMessage> {
            return Promise.resolve(message);
          },
        };
      },
    },
  } as unknown as Anthropic;

  return {
    client,
    lastParams: () => captured,
    handlers: () => handlers,
  };
}

const MODEL = "claude-fable-5-test";

function baseOptions(overrides: Partial<LlmRunOptions> = {}): LlmRunOptions {
  return {
    system: "You are a defensive security analyst.",
    tools: [],
    messages: [],
    maxTokens: 4096,
    effort: "high",
    ...overrides,
  };
}

const sampleTool: LlmToolDef = {
  name: "run_kql",
  description: "Execute a KQL query against the workspace.",
  inputSchema: {
    type: "object",
    properties: { query: { type: "string" } },
    required: ["query"],
  },
};

describe("AnthropicProvider request shape", () => {
  it("maps model, max_tokens, effort, thinking, cache_control, system and tools", async () => {
    const fake = makeFakeClient({ stop_reason: "end_turn", content: [{ type: "text", text: "ok" }] });
    const provider = new AnthropicProvider({ client: fake.client, model: MODEL });

    await provider.runTurn(
      baseOptions({
        tools: [sampleTool],
        messages: [
          { role: "user", text: "first" },
          { role: "user", text: "second" },
        ],
        maxTokens: 8192,
        effort: "max",
      }),
    );

    const params = fake.lastParams();
    expect(params.model).toBe(MODEL);
    expect(params.max_tokens).toBe(8192);
    expect(params.output_config).toEqual({ effort: "max" });
    expect(params.thinking).toEqual({ type: "adaptive", display: "summarized" });
    expect(params.cache_control).toEqual({ type: "ephemeral" });

    // System is a single text block carrying cache_control.
    expect(params.system).toEqual([
      { type: "text", text: "You are a defensive security analyst.", cache_control: { type: "ephemeral" } },
    ]);

    // Tools translate inputSchema -> input_schema.
    expect(params.tools).toEqual([
      {
        name: "run_kql",
        description: "Execute a KQL query against the workspace.",
        input_schema: sampleTool.inputSchema,
      },
    ]);
    const tools = params.tools as Array<Record<string, unknown>>;
    expect(tools[0]).not.toHaveProperty("inputSchema");
  });

  it("honours thinkingDisplay: 'omitted'", async () => {
    const fake = makeFakeClient({ stop_reason: "end_turn", content: [] });
    const provider = new AnthropicProvider({
      client: fake.client,
      model: MODEL,
      thinkingDisplay: "omitted",
    });

    await provider.runTurn(baseOptions());

    expect(fake.lastParams().thinking).toEqual({ type: "adaptive", display: "omitted" });
  });
});

describe("AnthropicProvider message translation", () => {
  it("translates user, tool_results, native-assistant and foreign-assistant messages", async () => {
    const fake = makeFakeClient({ stop_reason: "end_turn", content: [] });
    const provider = new AnthropicProvider({ client: fake.client, model: MODEL });

    const nativePayload = [
      { type: "thinking", thinking: "...", signature: "sig-abc" },
      { type: "text", text: "native reply" },
    ];
    const foreignPayload = [{ type: "thinking", thinking: "FOREIGN", signature: "foreign-sig" }];

    const messages: LlmMessage[] = [
      { role: "user", text: "hello" },
      {
        role: "tool_results",
        results: [
          { toolCallId: "call_1", content: "result body", isError: false },
          { toolCallId: "call_2", content: "boom", isError: true },
        ],
      },
      // Same-model assistant: native payload is reused verbatim.
      {
        role: "assistant",
        text: "ignored when native present",
        toolCalls: [],
        native: { model: MODEL, payload: nativePayload },
      },
      // Foreign-model assistant: reconstructed from text + toolCalls, never the foreign payload.
      {
        role: "assistant",
        text: "reconstructed text",
        toolCalls: [{ id: "tc_9", name: "run_kql", input: { query: "x" } }],
        native: { model: "some-other-model", payload: foreignPayload },
      },
    ];

    await provider.runTurn(baseOptions({ messages }));

    const sent = fake.lastParams().messages as Array<Record<string, unknown>>;
    expect(sent).toHaveLength(4);

    // user
    expect(sent[0]).toEqual({ role: "user", content: "hello" });

    // tool_results -> user message with tool_result blocks
    expect(sent[1]).toEqual({
      role: "user",
      content: [
        { type: "tool_result", tool_use_id: "call_1", content: "result body" },
        { type: "tool_result", tool_use_id: "call_2", content: "boom", is_error: true },
      ],
    });
    // is_error omitted when not an error.
    const trBlocks = (sent[1]?.content ?? []) as Array<Record<string, unknown>>;
    expect(trBlocks[0]).not.toHaveProperty("is_error");

    // same-model assistant -> native payload reused verbatim
    expect(sent[2]).toEqual({ role: "assistant", content: nativePayload });

    // foreign-model assistant -> reconstructed from text + tool_use blocks
    expect(sent[3]).toEqual({
      role: "assistant",
      content: [
        { type: "text", text: "reconstructed text" },
        { type: "tool_use", id: "tc_9", name: "run_kql", input: { query: "x" } },
      ],
    });
    // The foreign payload must NOT have leaked into the request.
    expect(JSON.stringify(sent[3])).not.toContain("FOREIGN");
    expect(JSON.stringify(sent[3])).not.toContain("foreign-sig");
  });
});

describe("AnthropicProvider result mapping", () => {
  it("maps tool_use stop reason and tool calls", async () => {
    const fake = makeFakeClient({
      stop_reason: "tool_use",
      content: [
        { type: "text", text: "let me check" },
        { type: "tool_use", id: "tu_1", name: "run_kql", input: { query: "SigninLogs | count" } },
      ],
    });
    const provider = new AnthropicProvider({ client: fake.client, model: MODEL });

    const result = await provider.runTurn(baseOptions());

    expect(result.stopReason).toBe("tool_use");
    expect(result.toolCalls).toEqual([
      { id: "tu_1", name: "run_kql", input: { query: "SigninLogs | count" } },
    ]);
    expect(result.text).toBe("let me check");
    expect(result.modelUsed).toBe(MODEL);
    expect(result.refusal).toBeUndefined();
    expect(result.abortReason).toBeUndefined();
  });

  it("maps end_turn with concatenated text", async () => {
    const fake = makeFakeClient({
      stop_reason: "end_turn",
      content: [
        { type: "text", text: "part one " },
        { type: "thinking", thinking: "internal" },
        { type: "text", text: "part two" },
      ],
    });
    const provider = new AnthropicProvider({ client: fake.client, model: MODEL });

    const result = await provider.runTurn(baseOptions());

    expect(result.stopReason).toBe("end_turn");
    expect(result.text).toBe("part one part two");
    expect(result.toolCalls).toEqual([]);
  });

  it("maps max_tokens", async () => {
    const fake = makeFakeClient({ stop_reason: "max_tokens", content: [{ type: "text", text: "cut" }] });
    const provider = new AnthropicProvider({ client: fake.client, model: MODEL });

    const result = await provider.runTurn(baseOptions());

    expect(result.stopReason).toBe("max_tokens");
  });

  it("maps refusal with stop_details into refusal field", async () => {
    const fake = makeFakeClient({
      stop_reason: "refusal",
      content: [],
      stop_details: { category: "harmful", explanation: "declined to assist" },
    });
    const provider = new AnthropicProvider({ client: fake.client, model: MODEL });

    const result = await provider.runTurn(baseOptions());

    expect(result.stopReason).toBe("refusal");
    expect(result.refusal).toEqual({ category: "harmful", explanation: "declined to assist" });
  });

  it("populates refusal with nulls when stop_details is absent", async () => {
    const fake = makeFakeClient({ stop_reason: "refusal", content: [] });
    const provider = new AnthropicProvider({ client: fake.client, model: MODEL });

    const result = await provider.runTurn(baseOptions());

    expect(result.stopReason).toBe("refusal");
    expect(result.refusal).toEqual({ category: null, explanation: null });
  });

  it("resolves pause_turn with no tool calls to end_turn", async () => {
    const fake = makeFakeClient({ stop_reason: "pause_turn", content: [{ type: "text", text: "paused" }] });
    const provider = new AnthropicProvider({ client: fake.client, model: MODEL });

    const result = await provider.runTurn(baseOptions());

    expect(result.stopReason).toBe("end_turn");
    expect(result.toolCalls).toEqual([]);
  });

  it("maps model_context_window_exceeded to aborted with an abortReason about the context window", async () => {
    const fake = makeFakeClient({ stop_reason: "model_context_window_exceeded", content: [] });
    const provider = new AnthropicProvider({ client: fake.client, model: MODEL });

    const result = await provider.runTurn(baseOptions());

    expect(result.stopReason).toBe("aborted");
    expect(result.abortReason).toBeDefined();
    expect(result.abortReason).toMatch(/context window/i);
  });

  it("carries native payload (this model + response content) and text/toolCalls on result.assistant", async () => {
    const content = [
      { type: "text", text: "answer" },
      { type: "tool_use", id: "tu_2", name: "run_kql", input: { query: "q" } },
    ];
    const fake = makeFakeClient({ stop_reason: "tool_use", content });
    const provider = new AnthropicProvider({ client: fake.client, model: MODEL });

    const result = await provider.runTurn(baseOptions());

    expect(result.assistant.role).toBe("assistant");
    expect(result.assistant.text).toBe("answer");
    expect(result.assistant.toolCalls).toEqual([
      { id: "tu_2", name: "run_kql", input: { query: "q" } },
    ]);
    expect(result.assistant.native).toEqual({ model: MODEL, payload: content });
  });
});

describe("AnthropicProvider streaming handlers", () => {
  it("registers onText and onThinking handlers when supplied", async () => {
    const fake = makeFakeClient({ stop_reason: "end_turn", content: [{ type: "text", text: "hi" }] });
    const provider = new AnthropicProvider({ client: fake.client, model: MODEL });

    const seenText: string[] = [];
    const seenThinking: string[] = [];

    await provider.runTurn(
      baseOptions({
        onText: (t) => seenText.push(t),
        onThinking: (t) => seenThinking.push(t),
      }),
    );

    const handlers = fake.handlers();
    expect(handlers.has("text")).toBe(true);
    expect(handlers.has("thinking")).toBe(true);

    // The registered handlers are the callbacks we supplied.
    handlers.get("text")?.("streamed text");
    handlers.get("thinking")?.("streamed thinking");
    expect(seenText).toEqual(["streamed text"]);
    expect(seenThinking).toEqual(["streamed thinking"]);
  });

  it("does not register handlers when callbacks are absent", async () => {
    const fake = makeFakeClient({ stop_reason: "end_turn", content: [] });
    const provider = new AnthropicProvider({ client: fake.client, model: MODEL });

    await provider.runTurn(baseOptions());

    const handlers = fake.handlers();
    expect(handlers.has("text")).toBe(false);
    expect(handlers.has("thinking")).toBe(false);
  });
});

describe("AnthropicProvider identity", () => {
  it("exposes name, model and optional fallback", () => {
    const fake = makeFakeClient({ stop_reason: "end_turn", content: [] });
    const fallback = new AnthropicProvider({ client: fake.client, model: "fallback-model" });
    const provider = new AnthropicProvider({ client: fake.client, model: MODEL, fallback });

    expect(provider.name).toBe("anthropic");
    expect(provider.model).toBe(MODEL);
    expect(provider.fallback).toBe(fallback);
  });

  it("reports modelUsed as the configured model", async () => {
    const fake = makeFakeClient({ stop_reason: "end_turn", content: [] });
    const provider = new AnthropicProvider({ client: fake.client, model: MODEL });

    const result = await provider.runTurn(baseOptions());

    expect(result.modelUsed).toBe(MODEL);
  });
});
