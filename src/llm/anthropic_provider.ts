import Anthropic from "@anthropic-ai/sdk";

import type {
  LlmMessage,
  LlmProvider,
  LlmRunOptions,
  LlmStopReason,
  LlmToolCall,
  LlmTurnResult,
} from "./types.js";

export interface AnthropicProviderOptions {
  client: Anthropic;
  model: string;
  fallback?: LlmProvider;
  /** Adaptive-thinking display; "summarized" streams progress, "omitted" stays silent. */
  thinkingDisplay?: "summarized" | "omitted";
}

/**
 * Anthropic Messages API provider. Uses always-on adaptive thinking and the
 * effort parameter, top-level prompt caching, and maps the refusal stop reason
 * so the agent loop can fall back to another model.
 */
export class AnthropicProvider implements LlmProvider {
  readonly name = "anthropic";
  readonly model: string;
  readonly fallback?: LlmProvider;
  readonly #client: Anthropic;
  readonly #thinkingDisplay: "summarized" | "omitted";

  constructor(opts: AnthropicProviderOptions) {
    this.#client = opts.client;
    this.model = opts.model;
    this.fallback = opts.fallback;
    this.#thinkingDisplay = opts.thinkingDisplay ?? "summarized";
  }

  async runTurn(opts: LlmRunOptions): Promise<LlmTurnResult> {
    const tools: Anthropic.Tool[] = opts.tools.map((t) => ({
      name: t.name,
      description: t.description,
      input_schema: t.inputSchema as Anthropic.Tool["input_schema"],
    }));
    const system: Anthropic.TextBlockParam[] = [
      { type: "text", text: opts.system, cache_control: { type: "ephemeral" } },
    ];

    const stream = this.#client.messages.stream({
      model: this.model,
      max_tokens: opts.maxTokens,
      // Cache both the tools+system prefix and the conversation suffix so each
      // turn reads prior history from cache rather than reprocessing it.
      cache_control: { type: "ephemeral" },
      system,
      tools,
      messages: this.#toNative(opts.messages),
      thinking: { type: "adaptive", display: this.#thinkingDisplay },
      output_config: { effort: opts.effort },
    });
    if (opts.onText) stream.on("text", opts.onText);
    if (opts.onThinking) stream.on("thinking", opts.onThinking);
    const response = await stream.finalMessage();

    const text = response.content
      .filter((b): b is Anthropic.TextBlock => b.type === "text")
      .map((b) => b.text)
      .join("");
    const toolCalls: LlmToolCall[] = response.content
      .filter((b): b is Anthropic.ToolUseBlock => b.type === "tool_use")
      .map((b) => ({ id: b.id, name: b.name, input: b.input }));

    const assistant = {
      role: "assistant" as const,
      text,
      toolCalls,
      native: { model: this.model, payload: response.content },
    };

    const raw = (response.stop_reason as string | null) ?? "end_turn";
    let stopReason: LlmStopReason;
    let abortReason: string | undefined;
    switch (raw) {
      case "refusal":
        stopReason = "refusal";
        break;
      case "max_tokens":
        stopReason = "max_tokens";
        break;
      case "tool_use":
        stopReason = "tool_use";
        break;
      case "pause_turn":
        // Only arises with server-side tools (unused here); resolve locally.
        stopReason = toolCalls.length > 0 ? "tool_use" : "end_turn";
        break;
      case "model_context_window_exceeded":
        stopReason = "aborted";
        abortReason = "The conversation exceeded the model context window.";
        break;
      default:
        stopReason = toolCalls.length > 0 ? "tool_use" : "end_turn";
        break;
    }

    const refusal =
      stopReason === "refusal"
        ? {
            category: response.stop_details?.category ?? null,
            explanation:
              response.stop_details && "explanation" in response.stop_details
                ? (response.stop_details.explanation ?? null)
                : null,
          }
        : undefined;

    return { stopReason, text, toolCalls, assistant, refusal, abortReason, modelUsed: this.model };
  }

  #toNative(messages: LlmMessage[]): Anthropic.MessageParam[] {
    return messages.map((m): Anthropic.MessageParam => {
      if (m.role === "user") return { role: "user", content: m.text };
      if (m.role === "tool_results") {
        return {
          role: "user",
          content: m.results.map(
            (r): Anthropic.ToolResultBlockParam => ({
              type: "tool_result",
              tool_use_id: r.toolCallId,
              content: r.content,
              ...(r.isError ? { is_error: true } : {}),
            }),
          ),
        };
      }
      // assistant: reuse native blocks only when produced by THIS model, so a
      // fallback model never receives another model's thinking-block signatures.
      if (m.native && m.native.model === this.model) {
        return { role: "assistant", content: m.native.payload as Anthropic.ContentBlockParam[] };
      }
      const blocks: Anthropic.ContentBlockParam[] = [];
      if (m.text) blocks.push({ type: "text", text: m.text });
      for (const tc of m.toolCalls) {
        blocks.push({ type: "tool_use", id: tc.id, name: tc.name, input: tc.input });
      }
      return { role: "assistant", content: blocks.length > 0 ? blocks : m.text };
    });
  }
}
