/**
 * Provider-neutral LLM abstraction.
 *
 * The agent loop (detection_analyser) talks only to {@link LlmProvider} and the
 * neutral message/tool types below — never to a vendor SDK directly. Each
 * provider translates these to and from its native wire format, so swapping
 * Anthropic for OpenAI (or any OpenAI-compatible endpoint) is a config change.
 */

export type EffortLevel = "low" | "medium" | "high" | "xhigh" | "max";

export interface LlmToolDef {
  name: string;
  description: string;
  /** JSON Schema for the tool input. */
  inputSchema: Record<string, unknown>;
}

export interface LlmToolCall {
  id: string;
  name: string;
  /** Parsed tool input (object), or a sentinel object when the model emitted unparseable arguments. */
  input: unknown;
}

export interface LlmToolResult {
  toolCallId: string;
  content: string;
  isError?: boolean;
}

export interface LlmAssistantMessage {
  role: "assistant";
  text: string;
  toolCalls: LlmToolCall[];
  /**
   * Provider-native payload, kept so a provider can replay its own prior turns
   * faithfully on the SAME model (e.g. Anthropic thinking-block signatures).
   * Ignored by other providers / models, which reconstruct from text+toolCalls.
   */
  native?: { model: string; payload: unknown };
}

export type LlmMessage =
  | { role: "user"; text: string }
  | { role: "tool_results"; results: LlmToolResult[] }
  | LlmAssistantMessage;

export type LlmStopReason = "end_turn" | "tool_use" | "max_tokens" | "refusal" | "aborted";

export interface LlmRefusal {
  category: string | null;
  explanation: string | null;
}

export interface LlmTurnResult {
  stopReason: LlmStopReason;
  /** Visible text emitted this turn. */
  text: string;
  toolCalls: LlmToolCall[];
  /** The assistant message to append to history (carries native payload where applicable). */
  assistant: LlmAssistantMessage;
  /** Present when stopReason is "refusal". */
  refusal?: LlmRefusal;
  /** Human-readable reason when stopReason is "aborted". */
  abortReason?: string;
  modelUsed: string;
}

export interface LlmRunOptions {
  system: string;
  tools: LlmToolDef[];
  messages: LlmMessage[];
  maxTokens: number;
  effort: EffortLevel;
  /** Streaming sink for visible text. */
  onText?: (text: string) => void;
  /** Streaming sink for reasoning/thinking summaries (where the provider exposes them). */
  onThinking?: (text: string) => void;
}

export interface LlmProvider {
  /** Provider family, e.g. "anthropic" | "openai". */
  readonly name: string;
  /** Active model id. */
  readonly model: string;
  /** Optional provider to retry on when this one refuses (e.g. Anthropic Fable -> Opus). */
  readonly fallback?: LlmProvider;
  runTurn(opts: LlmRunOptions): Promise<LlmTurnResult>;
}
