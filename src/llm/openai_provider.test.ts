import { describe, expect, it } from "vitest";

import type OpenAI from "openai";

import type { LlmMessage, LlmRunOptions, LlmToolDef } from "./types.js";
import { OpenAIProvider } from "./openai_provider.js";

// ---------------------------------------------------------------------------
// Fakes — no real network calls. The fake mirrors the slice of the OpenAI
// streaming API the provider touches: chat.completions.create(params) returns
// an async iterable of streaming chunks.
// ---------------------------------------------------------------------------

/** Minimal shape of an OpenAI streaming chunk the provider reads. */
interface FakeToolCallDelta {
  index: number;
  id?: string;
  function?: { name?: string; arguments?: string };
}
interface FakeChunk {
  choices: Array<{
    delta?: { content?: string; tool_calls?: FakeToolCallDelta[] };
    finish_reason?: string;
  }>;
  usage?: Record<string, unknown>;
}

/** Build an async iterable from a static array of chunks. */
async function* asyncIterable<T>(items: T[]): AsyncGenerator<T> {
  for (const item of items) {
    yield item;
  }
}

interface FakeClient {
  client: OpenAI;
  /** The params object passed to the most recent create() call. */
  lastParams: () => Record<string, unknown>;
  /** Every params object create() has been called with. */
  allParams: () => Record<string, unknown>[];
}

/**
 * Create a fake OpenAI client whose create() records params and streams the
 * scripted chunks. Cast to OpenAI for the constructor — we only implement the
 * fraction of the surface OpenAIProvider exercises.
 */
function makeFakeClient(chunks: FakeChunk[]): FakeClient {
  const recorded: Record<string, unknown>[] = [];
  const fake = {
    chat: {
      completions: {
        // eslint-disable-next-line @typescript-eslint/require-await
        async create(params: Record<string, unknown>): Promise<AsyncGenerator<FakeChunk>> {
          recorded.push(params);
          return asyncIterable(chunks);
        },
      },
    },
  };
  return {
    client: fake as unknown as OpenAI,
    lastParams: () => {
      const p = recorded[recorded.length - 1];
      if (!p) throw new Error("create() was never called");
      return p;
    },
    allParams: () => recorded,
  };
}

// ---------------------------------------------------------------------------
// Convenience chunk builders for the OpenAI streaming wire shape.
// ---------------------------------------------------------------------------

function contentChunk(content: string): FakeChunk {
  return { choices: [{ delta: { content } }] };
}

function finishChunk(finish_reason: string): FakeChunk {
  return { choices: [{ delta: {}, finish_reason }] };
}

function usageChunk(usage: Record<string, unknown>): FakeChunk {
  return { choices: [], usage };
}

function toolCallChunk(delta: FakeToolCallDelta): FakeChunk {
  return { choices: [{ delta: { tool_calls: [delta] } }] };
}

// ---------------------------------------------------------------------------
// Run-options helpers.
// ---------------------------------------------------------------------------

function baseOpts(overrides: Partial<LlmRunOptions> = {}): LlmRunOptions {
  return {
    system: "SYS",
    tools: [],
    messages: [],
    maxTokens: 1024,
    effort: "medium",
    ...overrides,
  };
}

const sampleTool: LlmToolDef = {
  name: "run_query",
  description: "Run a KQL query",
  inputSchema: { type: "object", properties: { kql: { type: "string" } }, required: ["kql"] },
};

// ===========================================================================
// Request shape
// ===========================================================================

describe("OpenAIProvider request shape", () => {
  it("sends model, stream, tool_choice, max_completion_tokens, mapped tools and usage opts", async () => {
    const fake = makeFakeClient([finishChunk("stop"), usageChunk({ total_tokens: 5 })]);
    const provider = new OpenAIProvider({ client: fake.client, model: "gpt-4.1" });

    await provider.runTurn(baseOpts({ tools: [sampleTool], maxTokens: 777 }));

    const p = fake.lastParams();
    expect(p.model).toBe("gpt-4.1");
    expect(p.stream).toBe(true);
    expect(p.tool_choice).toBe("auto");
    expect(p.max_completion_tokens).toBe(777);
    expect(p.stream_options).toEqual({ include_usage: true });
    expect(p.tools).toEqual([
      {
        type: "function",
        function: {
          name: "run_query",
          description: "Run a KQL query",
          parameters: sampleTool.inputSchema,
        },
      },
    ]);
  });

  it("passes inputSchema through by reference as the function parameters", async () => {
    const fake = makeFakeClient([finishChunk("stop"), usageChunk({})]);
    const provider = new OpenAIProvider({ client: fake.client, model: "gpt-4.1" });

    await provider.runTurn(baseOpts({ tools: [sampleTool] }));

    const tools = fake.lastParams().tools as Array<{ function: { parameters: unknown } }>;
    expect(tools[0]?.function.parameters).toBe(sampleTool.inputSchema);
  });
});

// ===========================================================================
// reasoning_effort
// ===========================================================================

describe("OpenAIProvider reasoning_effort", () => {
  it("omits reasoning_effort for a non-reasoning model (gpt-4.1)", async () => {
    const fake = makeFakeClient([finishChunk("stop"), usageChunk({})]);
    const provider = new OpenAIProvider({ client: fake.client, model: "gpt-4.1" });

    await provider.runTurn(baseOpts({ effort: "high" }));

    expect("reasoning_effort" in fake.lastParams()).toBe(false);
  });

  it.each([
    ["o3", "low" as const, "low"],
    ["o3", "medium" as const, "medium"],
    ["o3", "high" as const, "high"],
    ["gpt-5.1", "xhigh" as const, "high"],
    ["gpt-5.1", "max" as const, "high"],
    ["gpt-5.1", "low" as const, "low"],
  ])("maps effort for reasoning model %s: %s -> %s", async (model, effort, expected) => {
    const fake = makeFakeClient([finishChunk("stop"), usageChunk({})]);
    const provider = new OpenAIProvider({ client: fake.client, model });

    await provider.runTurn(baseOpts({ effort }));

    expect(fake.lastParams().reasoning_effort).toBe(expected);
  });
});

// ===========================================================================
// Message translation
// ===========================================================================

describe("OpenAIProvider message translation", () => {
  it("prepends a system message and translates a neutral user message", async () => {
    const fake = makeFakeClient([finishChunk("stop"), usageChunk({})]);
    const provider = new OpenAIProvider({ client: fake.client, model: "gpt-4.1" });

    const messages: LlmMessage[] = [{ role: "user", text: "hello" }];
    await provider.runTurn(baseOpts({ system: "you are helpful", messages }));

    expect(fake.lastParams().messages).toEqual([
      { role: "system", content: "you are helpful" },
      { role: "user", content: "hello" },
    ]);
  });

  it("emits one tool message per tool_result, with [ERROR] prefix when isError", async () => {
    const fake = makeFakeClient([finishChunk("stop"), usageChunk({})]);
    const provider = new OpenAIProvider({ client: fake.client, model: "gpt-4.1" });

    const messages: LlmMessage[] = [
      {
        role: "tool_results",
        results: [
          { toolCallId: "call_ok", content: "rows: 3" },
          { toolCallId: "call_bad", content: "boom", isError: true },
        ],
      },
    ];
    await provider.runTurn(baseOpts({ messages }));

    const out = fake.lastParams().messages as unknown[];
    expect(out).toEqual([
      { role: "system", content: "SYS" },
      { role: "tool", tool_call_id: "call_ok", content: "rows: 3" },
      { role: "tool", tool_call_id: "call_bad", content: "[ERROR] boom" },
    ]);
  });

  it("translates a neutral assistant turn with toolCalls (content text, JSON-stringified input)", async () => {
    const fake = makeFakeClient([finishChunk("stop"), usageChunk({})]);
    const provider = new OpenAIProvider({ client: fake.client, model: "gpt-4.1" });

    const messages: LlmMessage[] = [
      {
        role: "assistant",
        text: "Looking it up",
        toolCalls: [{ id: "call_1", name: "run_query", input: { kql: "Heartbeat" } }],
      },
    ];
    await provider.runTurn(baseOpts({ messages }));

    const out = fake.lastParams().messages as unknown[];
    expect(out[1]).toEqual({
      role: "assistant",
      content: "Looking it up",
      tool_calls: [
        {
          id: "call_1",
          type: "function",
          function: { name: "run_query", arguments: JSON.stringify({ kql: "Heartbeat" }) },
        },
      ],
    });
  });

  it("uses null content for an assistant turn with no text", async () => {
    const fake = makeFakeClient([finishChunk("stop"), usageChunk({})]);
    const provider = new OpenAIProvider({ client: fake.client, model: "gpt-4.1" });

    const messages: LlmMessage[] = [
      {
        role: "assistant",
        text: "",
        toolCalls: [{ id: "call_1", name: "run_query", input: { kql: "X" } }],
      },
    ];
    await provider.runTurn(baseOpts({ messages }));

    const out = fake.lastParams().messages as Array<{ content: unknown }>;
    expect(out[1]?.content).toBeNull();
  });

  it("omits tool_calls for a plain assistant text turn", async () => {
    const fake = makeFakeClient([finishChunk("stop"), usageChunk({})]);
    const provider = new OpenAIProvider({ client: fake.client, model: "gpt-4.1" });

    const messages: LlmMessage[] = [{ role: "assistant", text: "done", toolCalls: [] }];
    await provider.runTurn(baseOpts({ messages }));

    const out = fake.lastParams().messages as Array<Record<string, unknown>>;
    expect(out[1]).toEqual({ role: "assistant", content: "done" });
    expect("tool_calls" in (out[1] ?? {})).toBe(false);
  });
});

// ===========================================================================
// Streaming accumulation
// ===========================================================================

describe("OpenAIProvider streaming accumulation", () => {
  it("concatenates content deltas into text and streams them to onText in order", async () => {
    const fake = makeFakeClient([
      contentChunk("Hello"),
      contentChunk(", "),
      contentChunk("world"),
      finishChunk("stop"),
      usageChunk({}),
    ]);
    const provider = new OpenAIProvider({ client: fake.client, model: "gpt-4.1" });

    const seen: string[] = [];
    const result = await provider.runTurn(baseOpts({ onText: (t) => seen.push(t) }));

    expect(result.text).toBe("Hello, world");
    expect(seen).toEqual(["Hello", ", ", "world"]);
    expect(result.assistant.text).toBe("Hello, world");
  });

  it("accumulates tool_call deltas by index (id, then name, then argument fragments)", async () => {
    const fake = makeFakeClient([
      toolCallChunk({ index: 0, id: "call_abc", function: { name: "run_query" } }),
      toolCallChunk({ index: 0, function: { arguments: '{"kql":' } }),
      toolCallChunk({ index: 0, function: { arguments: '"Heartbeat"}' } }),
      finishChunk("tool_calls"),
      usageChunk({}),
    ]);
    const provider = new OpenAIProvider({ client: fake.client, model: "gpt-4.1" });

    const result = await provider.runTurn(baseOpts());

    expect(result.toolCalls).toEqual([
      { id: "call_abc", name: "run_query", input: { kql: "Heartbeat" } },
    ]);
  });

  it("returns multiple parallel tool calls in index order", async () => {
    const fake = makeFakeClient([
      // Interleaved deltas across two indices, second index seen first.
      toolCallChunk({ index: 1, id: "call_two", function: { name: "tool_b" } }),
      toolCallChunk({ index: 0, id: "call_one", function: { name: "tool_a" } }),
      toolCallChunk({ index: 1, function: { arguments: '{"b":2}' } }),
      toolCallChunk({ index: 0, function: { arguments: '{"a":1}' } }),
      finishChunk("tool_calls"),
      usageChunk({}),
    ]);
    const provider = new OpenAIProvider({ client: fake.client, model: "gpt-4.1" });

    const result = await provider.runTurn(baseOpts());

    expect(result.toolCalls).toEqual([
      { id: "call_one", name: "tool_a", input: { a: 1 } },
      { id: "call_two", name: "tool_b", input: { b: 2 } },
    ]);
  });

  it("falls back to a synthetic call id when none is streamed", async () => {
    const fake = makeFakeClient([
      toolCallChunk({ index: 0, function: { name: "tool_a", arguments: "{}" } }),
      finishChunk("tool_calls"),
      usageChunk({}),
    ]);
    const provider = new OpenAIProvider({ client: fake.client, model: "gpt-4.1" });

    const result = await provider.runTurn(baseOpts());

    expect(result.toolCalls[0]?.id).toBe("call_0");
  });
});

// ===========================================================================
// finish_reason mapping
// ===========================================================================

describe("OpenAIProvider finish_reason mapping", () => {
  it("maps tool_calls -> tool_use", async () => {
    const fake = makeFakeClient([
      toolCallChunk({ index: 0, id: "c", function: { name: "t", arguments: "{}" } }),
      finishChunk("tool_calls"),
      usageChunk({}),
    ]);
    const provider = new OpenAIProvider({ client: fake.client, model: "gpt-4.1" });

    const result = await provider.runTurn(baseOpts());
    expect(result.stopReason).toBe("tool_use");
  });

  it("maps stop -> end_turn", async () => {
    const fake = makeFakeClient([contentChunk("hi"), finishChunk("stop"), usageChunk({})]);
    const provider = new OpenAIProvider({ client: fake.client, model: "gpt-4.1" });

    const result = await provider.runTurn(baseOpts());
    expect(result.stopReason).toBe("end_turn");
  });

  it("maps length -> max_tokens", async () => {
    const fake = makeFakeClient([contentChunk("hi"), finishChunk("length"), usageChunk({})]);
    const provider = new OpenAIProvider({ client: fake.client, model: "gpt-4.1" });

    const result = await provider.runTurn(baseOpts());
    expect(result.stopReason).toBe("max_tokens");
  });

  it("maps content_filter -> refusal and sets result.refusal", async () => {
    const fake = makeFakeClient([finishChunk("content_filter"), usageChunk({})]);
    const provider = new OpenAIProvider({ client: fake.client, model: "gpt-4.1" });

    const result = await provider.runTurn(baseOpts());
    expect(result.stopReason).toBe("refusal");
    expect(result.refusal).toEqual({ category: "content_filter", explanation: null });
  });

  it("yields tool_use when finish_reason is stop but tool calls are present", async () => {
    const fake = makeFakeClient([
      toolCallChunk({ index: 0, id: "c", function: { name: "t", arguments: "{}" } }),
      finishChunk("stop"),
      usageChunk({}),
    ]);
    const provider = new OpenAIProvider({ client: fake.client, model: "gpt-4.1" });

    const result = await provider.runTurn(baseOpts());
    expect(result.stopReason).toBe("tool_use");
  });

  it("does not set refusal for a normal end_turn", async () => {
    const fake = makeFakeClient([contentChunk("ok"), finishChunk("stop"), usageChunk({})]);
    const provider = new OpenAIProvider({ client: fake.client, model: "gpt-4.1" });

    const result = await provider.runTurn(baseOpts());
    expect(result.refusal).toBeUndefined();
  });
});

// ===========================================================================
// Malformed arguments + misc
// ===========================================================================

describe("OpenAIProvider malformed tool arguments", () => {
  it("produces __unparsed_arguments sentinel and does not throw on malformed JSON", async () => {
    const fake = makeFakeClient([
      toolCallChunk({ index: 0, id: "c", function: { name: "t", arguments: "{not valid" } }),
      finishChunk("tool_calls"),
      usageChunk({}),
    ]);
    const provider = new OpenAIProvider({ client: fake.client, model: "gpt-4.1" });

    const result = await provider.runTurn(baseOpts());

    expect(result.toolCalls[0]?.input).toEqual({ __unparsed_arguments: "{not valid" });
  });

  it("treats empty/whitespace arguments as an empty object", async () => {
    const fake = makeFakeClient([
      toolCallChunk({ index: 0, id: "c", function: { name: "t", arguments: "   " } }),
      finishChunk("tool_calls"),
      usageChunk({}),
    ]);
    const provider = new OpenAIProvider({ client: fake.client, model: "gpt-4.1" });

    const result = await provider.runTurn(baseOpts());
    expect(result.toolCalls[0]?.input).toEqual({});
  });
});

describe("OpenAIProvider misc", () => {
  it("reports modelUsed equal to the configured model", async () => {
    const fake = makeFakeClient([finishChunk("stop"), usageChunk({})]);
    const provider = new OpenAIProvider({ client: fake.client, model: "gpt-4.1" });

    const result = await provider.runTurn(baseOpts());
    expect(result.modelUsed).toBe("gpt-4.1");
  });

  it("exposes provider name and configured model/fallback", () => {
    const fakeFb = makeFakeClient([]);
    const fallback = new OpenAIProvider({ client: fakeFb.client, model: "gpt-4.1" });
    const fake = makeFakeClient([]);
    const provider = new OpenAIProvider({ client: fake.client, model: "o3", fallback });

    expect(provider.name).toBe("openai");
    expect(provider.model).toBe("o3");
    expect(provider.fallback).toBe(fallback);
  });

  it("skips chunks with no choice (e.g. the trailing usage chunk)", async () => {
    const fake = makeFakeClient([
      contentChunk("only text"),
      usageChunk({ total_tokens: 9 }),
      finishChunk("stop"),
    ]);
    const provider = new OpenAIProvider({ client: fake.client, model: "gpt-4.1" });

    const result = await provider.runTurn(baseOpts());
    expect(result.text).toBe("only text");
    expect(result.stopReason).toBe("end_turn");
  });
});
