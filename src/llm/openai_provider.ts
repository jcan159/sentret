import OpenAI from "openai";

import type {
  EffortLevel,
  LlmMessage,
  LlmProvider,
  LlmRunOptions,
  LlmStopReason,
  LlmToolCall,
  LlmTurnResult,
} from "./types.js";

export interface OpenAIProviderOptions {
  client: OpenAI;
  model: string;
  fallback?: LlmProvider;
  /**
   * Whether to send reasoning_effort. "auto" infers from the model name; set
   * "always"/"never" when the model id is opaque (e.g. an Azure deployment name).
   */
  reasoning?: "auto" | "always" | "never";
}

/** Reasoning models accept reasoning_effort and ignore sampling params. */
function isReasoningModel(model: string): boolean {
  return /^o\d/i.test(model) || /^gpt-5/i.test(model);
}

function toReasoningEffort(effort: EffortLevel): "low" | "medium" | "high" {
  if (effort === "low") return "low";
  if (effort === "medium") return "medium";
  return "high"; // high | xhigh | max all map to OpenAI's top tier
}

function safeParseArgs(raw: string): unknown {
  if (!raw.trim()) return {};
  try {
    return JSON.parse(raw);
  } catch {
    // Surfaced to the loop; tool validators reject it and the model retries.
    return { __unparsed_arguments: raw };
  }
}

/**
 * OpenAI Chat Completions provider. Works against api.openai.com or any
 * OpenAI-compatible endpoint (Azure OpenAI, OpenRouter, local servers) via a
 * custom baseURL on the injected client. Structured output and the report
 * submission both ride on function calling, so no provider-specific report
 * handling is needed.
 */
export class OpenAIProvider implements LlmProvider {
  readonly name = "openai";
  readonly model: string;
  readonly fallback?: LlmProvider;
  readonly #client: OpenAI;
  readonly #reasoning: "auto" | "always" | "never";

  constructor(opts: OpenAIProviderOptions) {
    this.#client = opts.client;
    this.model = opts.model;
    this.fallback = opts.fallback;
    this.#reasoning = opts.reasoning ?? "auto";
  }

  #useReasoning(): boolean {
    if (this.#reasoning === "always") return true;
    if (this.#reasoning === "never") return false;
    return isReasoningModel(this.model);
  }

  async runTurn(opts: LlmRunOptions): Promise<LlmTurnResult> {
    const tools: OpenAI.Chat.Completions.ChatCompletionTool[] = opts.tools.map((t) => ({
      type: "function",
      function: { name: t.name, description: t.description, parameters: t.inputSchema },
    }));

    const params: OpenAI.Chat.Completions.ChatCompletionCreateParamsStreaming = {
      model: this.model,
      messages: this.#toNative(opts.system, opts.messages),
      tools,
      tool_choice: "auto",
      max_completion_tokens: opts.maxTokens,
      stream: true,
      stream_options: { include_usage: true },
    };
    if (this.#useReasoning()) {
      // reasoning_effort may not be in older SDK type defs; assign defensively.
      (params as { reasoning_effort?: "low" | "medium" | "high" }).reasoning_effort =
        toReasoningEffort(opts.effort);
    }

    const stream = await this.#client.chat.completions.create(params);

    let text = "";
    let finishReason: string | null = null;
    const toolAcc = new Map<number, { id: string; name: string; args: string }>();

    for await (const chunk of stream) {
      const choice = chunk.choices[0];
      if (!choice) continue;
      const delta = choice.delta;
      if (delta?.content) {
        text += delta.content;
        opts.onText?.(delta.content);
      }
      if (delta?.tool_calls) {
        for (const tc of delta.tool_calls) {
          const slot = toolAcc.get(tc.index) ?? { id: "", name: "", args: "" };
          if (tc.id) slot.id = tc.id;
          if (tc.function?.name) slot.name = tc.function.name;
          if (tc.function?.arguments) slot.args += tc.function.arguments;
          toolAcc.set(tc.index, slot);
        }
      }
      if (choice.finish_reason) finishReason = choice.finish_reason;
    }

    const toolCalls: LlmToolCall[] = [...toolAcc.entries()]
      .sort((a, b) => a[0] - b[0])
      .map(([index, s]) => ({
        id: s.id || `call_${index}`,
        name: s.name,
        input: safeParseArgs(s.args),
      }));

    let stopReason: LlmStopReason;
    switch (finishReason) {
      case "tool_calls":
        stopReason = "tool_use";
        break;
      case "length":
      case "max_tokens":
        stopReason = "max_tokens";
        break;
      case "content_filter":
        stopReason = "refusal";
        break;
      default:
        stopReason = toolCalls.length > 0 ? "tool_use" : "end_turn";
        break;
    }

    const assistant = { role: "assistant" as const, text, toolCalls };
    const refusal =
      stopReason === "refusal" ? { category: "content_filter", explanation: null } : undefined;

    return { stopReason, text, toolCalls, assistant, refusal, modelUsed: this.model };
  }

  #toNative(
    system: string,
    messages: LlmMessage[],
  ): OpenAI.Chat.Completions.ChatCompletionMessageParam[] {
    const out: OpenAI.Chat.Completions.ChatCompletionMessageParam[] = [
      { role: "system", content: system },
    ];
    for (const m of messages) {
      if (m.role === "user") {
        out.push({ role: "user", content: m.text });
      } else if (m.role === "tool_results") {
        // OpenAI carries each result as a separate tool message; no is_error flag,
        // so prefix errors inline.
        for (const r of m.results) {
          out.push({
            role: "tool",
            tool_call_id: r.toolCallId,
            content: (r.isError ? "[ERROR] " : "") + r.content,
          });
        }
      } else {
        const msg: OpenAI.Chat.Completions.ChatCompletionAssistantMessageParam = {
          role: "assistant",
          content: m.text || null,
        };
        if (m.toolCalls.length > 0) {
          msg.tool_calls = m.toolCalls.map((tc) => ({
            id: tc.id,
            type: "function",
            function: { name: tc.name, arguments: JSON.stringify(tc.input ?? {}) },
          }));
        }
        out.push(msg);
      }
    }
    return out;
  }
}
