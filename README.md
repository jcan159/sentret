# Sentret — KQL Detection Rule Analyser

A provider-agnostic, LLM-powered analyser for Microsoft Sentinel / Azure Log
Analytics KQL detection rules — implemented as a TypeScript backend + CLI. Runs
on Anthropic (Claude) or OpenAI (and any OpenAI-compatible endpoint); pick the
backend with a config flag.

The analyser can:

- Review existing Microsoft Sentinel / Log Analytics KQL detection rules.
- Run safe, bounded validation queries against a Log Analytics workspace.
- Assess detection quality, correctness, schema fit, false positives, false negatives, and performance.
- Generate improved or new KQL detections from a user-provided detection intent.
- Produce Sentinel-ready scheduled analytics rule metadata, and (only with explicit
  operator approval) deploy it.

## Quick start

```bash
npm install
npm run build

# Authentication — set ONE LLM key (the provider is auto-detected from it)
export ANTHROPIC_API_KEY=sk-ant-...   # Claude (default), or
export OPENAI_API_KEY=sk-...          # OpenAI
az login                              # Azure access uses DefaultAzureCredential

# Analyse an existing rule (uses whichever key is set)
npx tsx src/cli.ts --input examples/example_user_request.json

# Force a provider / model
npx tsx src/cli.ts --input examples/example_user_request.json --provider openai --model gpt-4.1

# Create a new detection from intent
npx tsx src/cli.ts --input examples/example_create_new_request.json

# Static analysis only (no live workspace queries)
npx tsx src/cli.ts --input examples/example_user_request.json --static-only
```

### Choosing a provider

The provider is **auto-detected** from your environment: an Anthropic key →
`anthropic` (preferred when several are set), then `AZURE_OPENAI_ENDPOINT` →
`azure`, then an OpenAI key → `openai`. Override with
`--provider anthropic|openai|azure` or `SENTRET_PROVIDER`. Set the model with
`--model`, `SENTRET_MODEL` (Anthropic), `OPENAI_MODEL`, or — on Azure — the
deployment name. For OpenRouter / local OpenAI-compatible servers, set
`OPENAI_BASE_URL`.

| Capability | Anthropic | OpenAI | Azure AI Foundry |
| --- | --- | --- | --- |
| Tool-use agent loop, structured report, streaming | ✅ | ✅ | ✅ |
| Reasoning depth control (`--effort`) | adaptive thinking + effort | `reasoning_effort` (o-series / GPT-5) | `reasoning_effort` (force with `SENTRET_REASONING`) |
| Refusal fallback to a second model | ✅ (Fable → Opus) | — | — |
| Streamed reasoning summaries to stderr | ✅ | — | — |
| Auth | API key | API key | API key **or** Entra ID (`az login`) |

### Azure AI Foundry (e.g. GPT-5.5)

Azure routes by **deployment name** and uses a resource endpoint + `api-version`,
so it has its own settings (it does **not** use `OPENAI_BASE_URL`). The official
`AzureOpenAI` client handles the wire details; auth is an API key if you set one,
otherwise Entra ID via `DefaultAzureCredential` — the same `az login` identity
you already use for Log Analytics.

```bash
export AZURE_OPENAI_ENDPOINT=https://my-foundry.openai.azure.com   # resource URL, not the deployment URL
export AZURE_OPENAI_DEPLOYMENT=gpt-5-5-prod                        # your deployment name
export AZURE_OPENAI_API_VERSION=2025-04-01-preview                # match your deployment
# export AZURE_OPENAI_API_KEY=...    # optional; omit to use Entra ID (az login)
az login                                                           # if using Entra ID

npx tsx src/cli.ts --input examples/example_user_request.json     # azure auto-detected from the endpoint
```

> **Two settings you must get right for GPT-5.5:**
> 1. `AZURE_OPENAI_API_VERSION` must match what your Foundry deployment serves —
>    the default is a best guess and a wrong value returns a 400.
> 2. GPT-5.x is a reasoning model, but Azure deployment names are opaque, so
>    name-based detection can miss. If `reasoning_effort` isn't being applied,
>    set `SENTRET_REASONING=always`.

The model streams its working notes to stdout; tool invocations and summarized
thinking are echoed to stderr. The run produces `reports/analysis_<id>.json` (structured report) and
`reports/analysis_<id>.md` (the full markdown report), and every Log Analytics
query — executed or blocked — is appended to `audit/queries.jsonl` with its purpose.

### CLI options

| Flag | Effect |
| --- | --- |
| `-i, --input <file>` | Analyser request JSON (required; see `examples/`) |
| `--output-dir <dir>` | Report output directory (default `./reports`) |
| `--provider <name>` | `anthropic` \| `openai` \| `azure` (default: auto-detected from your env) |
| `--model <id>` | Model override for the active provider (Azure: the deployment name) |
| `--effort <level>` | `low` \| `medium` \| `high` \| `xhigh` \| `max` (default `high`) |
| `--static-only` | Force `allow_query_execution=false` |
| `--allow-deploy` | Approve Sentinel rule deployment for this run |
| `--no-fallback` | Disable the refusal-fallback model (Anthropic only) |

Configuration can also be set through `SENTRET_*` environment variables — see
`.env.example`.

## How it works

```text
src/
  cli.ts                      CLI entry point
  config.ts                   env + override configuration
  types.ts                    shared domain contract (request, report, clients)
  prompts/
    kql_analyser_system_prompt.md   the model's operating specification
  schemas/
    analyser_report.schema.json     report contract (submit_report tool schema)
    tool_contracts.json             original tool contract reference
  llm/
    types.ts                  provider-neutral LLM contract (LlmProvider, messages)
    anthropic_provider.ts     Anthropic Messages API backend (thinking, refusal fallback)
    openai_provider.ts        OpenAI Chat Completions backend (+ OpenAI-compatible URLs)
    factory.ts                builds the configured provider
  services/
    detection_analyser.ts     the provider-neutral agent loop (tools, safety gates)
    tool_definitions.ts       gated, provider-neutral tool definitions
    query_safety.ts           timespan validation + KQL safety gate
    redaction.ts              deterministic, distinctness-preserving redaction
    audit_log.ts              JSONL audit trail of every query
    report_renderer.ts        report validation, markdown rendering, persistence
  tools/
    azure_auth.ts             DefaultAzureCredential token provider
    log_analytics_client.ts   Azure Monitor Logs query + metadata API client
    sentinel_client.ts        Sentinel ARM client (list rules, gated deploy)
    mitre.ts                  offline MITRE ATT&CK tactic/technique lookup
```

The agent loop gives the model these tools, each gated per run:

| Tool | Gate |
| --- | --- |
| `run_log_analytics_query` | omitted when `allow_query_execution` is false; every call passes the safety gate and is audited |
| `get_workspace_schema` | same gate as queries |
| `list_sentinel_rules` | requires a `sentinel_target` in the request; calls must match it, and the ARM workspace must resolve to the analysed workspace GUID |
| `create_or_update_sentinel_rule` | additionally requires `--allow-deploy`; the client refuses unconfirmed calls, and MITRE sub-technique IDs are normalised to parent IDs for ARM |
| `lookup_mitre_attack` | always available (offline dataset) |
| `submit_report` | always available; the loop requires it before the run can finish |

The model must call `submit_report` with a JSON report matching
`schemas/analyser_report.schema.json` (validated in the loop, with retry on
rejection) before writing its final markdown report. Report persistence happens
automatically after a valid submission. The loop is provider-neutral — it talks
only to the `LlmProvider` abstraction in `src/llm/`, so the same tools, safety
gates, and report contract apply on every backend.

### Safety controls (enforced in code, not just prompted)

- Every query requires an explicit, validated timespan and an audited purpose.
- Kusto control commands (`.something`), workspace-wide `search`/`find`,
  wildcard unions (`union *`, `union App*`), and `externaldata` are blocked
  unless the request sets `allow_broad_queries`; sample sizes are capped, and
  `sample_mode_allowed: false` blocks row sampling entirely.
- Queries are confined to the workspace named in the request; cross-workspace
  escapes — `additional_workspaces`, `workspace()`, `cluster()`, `app()`,
  `adx()` — are rejected regardless of approvals.
- `data_sensitivity: High`/`Restricted` cannot be combined with
  `allow_raw_examples: true`; the request is rejected up front.
- Sentinel operations require an operator-supplied `sentinel_target`
  (subscription, resource group, workspace name) and are verified against the
  analysed workspace GUID via ARM before the first call; listing and
  deployment are both written to the audit log.
- Query results are redacted by default (emails/UPNs, IPs, GUIDs, URLs, hosts,
  paths, tokens, resource IDs, and well-known sensitive columns) with
  deterministic placeholders that preserve distinctness for aggregation;
  `allow_raw_examples: true` must be set explicitly to disable this.
- Sentinel deployment is double-gated: the tool is not even defined without
  `--allow-deploy`, and the ARM client refuses unconfirmed calls.
- Results fed to the model are row- and character-capped.

### Refusal handling (Anthropic)

Claude Fable 5's safety classifiers can occasionally decline benign
security-adjacent work (`stop_reason: "refusal"`). When that happens the
conversation is replayed as-is on the configured fallback model (default
`claude-opus-4-8`) and the run continues; the refusal is reported in the CLI
output. Disable with `--no-fallback` or `SENTRET_FALLBACK_MODEL=`. This path is
Anthropic-specific; on OpenAI a content-filter stop ends the run (no fallback).

## Development

```bash
npm test            # vitest (unit + agent-loop integration tests)
npm run typecheck   # tsc --noEmit
npm run build       # compile to dist/ and copy prompt/schema assets
```

## Reference documents

- `prompts/system_prompt_full.md` — full operating specification given to the model.
- `prompts/system_prompt_compact.md` — shorter production-friendly variant.
- `docs/implementation_notes.md` — architecture, API notes, safety controls.
- `schemas/` — tool contracts and the report schema.
- `examples/` — sample analyser requests.

## Important Notes

- The tool is for authorised defensive security engineering only.
- Do not deploy or modify Microsoft Sentinel rules without explicit user approval.
- Always use bounded timespans when running KQL against Log Analytics.
- Prefer aggregated summaries over raw sensitive log output.
- Request query statistics when performing performance analysis.
