/**
 * Privacy redaction for Log Analytics query results.
 *
 * Implements system prompt "Core Operating Principles" #7 (minimise data
 * exposure) and section 15 (privacy guardrails): usernames, IPs, hostnames,
 * domains, URLs, tokens, secret-shaped credentials (API keys, password=value
 * pairs), resource IDs and file paths are redacted by default before any
 * query result is forwarded to the model.
 *
 * Redaction is deterministic and distinctness-preserving: the same input
 * value always maps to the same placeholder, and different values map to
 * different placeholders ("user@contoso.com" -> "<email:1a2b3c4d>"). This
 * keeps aggregate analysis (grouping, counting, joining on redacted values)
 * possible without exposing the raw values.
 */

import { createHash } from "node:crypto";

import type { KustoTable, LogQueryResult } from "../types.js";

/** Options for {@link redactQueryResult}. (Local type — not part of src/types.ts.) */
export interface RedactQueryResultOptions {
  /** Extra column names (case-insensitive) to force-mask in addition to {@link DEFAULT_SENSITIVE_COLUMNS}. */
  sensitiveColumns?: string[];
}

/**
 * Column names whose cells are ALWAYS masked in query results, even when the
 * cell value matches none of the textual patterns. Matched case-insensitively.
 */
export const DEFAULT_SENSITIVE_COLUMNS: readonly string[] = [
  "UserPrincipalName",
  "UserId",
  "AccountUPN",
  "IPAddress",
  "ClientIP",
  "CallerIpAddress",
  "Caller",
  "AadUserId",
  "SamAccountName",
  "OnPremisesSecurityIdentifier",
  "DeviceName",
  "HostName",
  "Computer",
  "FileName",
  "FilePath",
  "FolderPath",
  "Url",
  "RemoteUrl",
  "EmailAddress",
  "SenderFromAddress",
  "RecipientEmailAddress",
  "AccountName",
  "AccountDomain",
  "InitiatedBy",
  "TargetUserName",
  "Identity",
  "UserDisplayName",
  "AccountDisplayName",
  "TargetUserDisplayName",
  "DisplayName",
  "RequesterUpn",
  "UserName",
];

/** First 8 hex chars of sha256 — short, deterministic, distinctness-preserving. */
function shortHash(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex").slice(0, 8);
}

function placeholder(tag: string, rawValue: string): string {
  return `<${tag}:${shortHash(rawValue)}>`;
}

/**
 * Redaction patterns, applied in order: most specific first so that e.g. a
 * URL is consumed before its hostname, and an Azure resource ID before the
 * GUID inside it would be matched on its own.
 *
 * Placeholders emitted by earlier patterns ("<tag:hex8>") contain no dots and
 * only a single colon, so later patterns cannot re-match inside them.
 */
const PATTERNS: ReadonlyArray<{ tag: string; regex: RegExp }> = [
  // Secret-shaped values run FIRST so no later pattern can split a credential
  // and so the raw secret never survives a partial match. Free-text columns
  // such as ProcessCommandLine are deliberately NOT force-masked wholesale
  // (the analyser needs them); these patterns strip the secrets inside them.
  //
  // 1) Well-known credential token prefixes: GitHub PATs (ghp_/gho_/
  // github_pat_), sk- API keys (OpenAI/Anthropic style, hyphenated tails
  // allowed), Slack xox[abprs]- tokens, AWS access key IDs (AKIA + 16),
  // GitLab PATs (glpat-). Case-sensitive: real tokens use these exact
  // prefixes, which keeps prose false-positives low.
  {
    tag: "secret",
    regex:
      /(?<![A-Za-z0-9_-])(?:github_pat_[A-Za-z0-9_]{20,}|gh[po]_[A-Za-z0-9]{20,}|sk-[A-Za-z0-9-]{19,}[A-Za-z0-9]|xox[abprs]-[A-Za-z0-9-]{10,}[A-Za-z0-9]|AKIA[0-9A-Z]{16}|glpat-[\w-]{20,})/g,
  },
  // 2) Credential key=value / key:value forms ("password=...",
  // "client_secret: ..."). The WHOLE key+value pair is replaced so the secret
  // value never survives. The value class excludes <> and the (?<!<)
  // lookbehind guards the key, so placeholders already emitted (e.g.
  // "<secret:..>" from the prefix pattern above) are never re-matched.
  // Bare "time"/"key" are intentionally not in the key list, so
  // "time: 2026-06-12T..." and "risk_level: high" pass through.
  {
    tag: "secret",
    regex:
      /(?<!<)(?:password|passwd|pwd|client_secret|clientsecret|api[_-]?key|accountkey|sharedaccesssignature|sas_token|token|secret)\s*[=:]\s*[^\s;&"'<>]{4,}/gi,
  },
  // 3) net.exe-style credential switches: "net use \\srv\c$ /user:CORP\admin".
  // The lookbehind keeps URL paths ("https://x/user:..") and words untouched.
  {
    tag: "secret",
    regex: /(?<![\w@.-])\/user:[^\s"',;<>]{2,}/gi,
  },
  // JWTs: three dot-separated base64url segments, header starting with eyJ ('{"').
  {
    tag: "token",
    regex: /(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/g,
  },
  // URLs. Final char class refuses trailing punctuation so prose like
  // "see https://x.example/." does not change the hash with the trailing dot.
  {
    tag: "url",
    regex: /\b(?:https?|ftp):\/\/[^\s"'<>()[\],]*[^\s"'<>()[\],.;:!?]/gi,
  },
  // Emails / UserPrincipalNames (incl. guest UPNs with #EXT#).
  {
    tag: "email",
    regex:
      /(?<![A-Za-z0-9._%+#'-])[A-Za-z0-9._%+#'-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}\b/g,
  },
  // Azure resource IDs — matched as a whole before the GUID pattern would
  // split them and before the Unix-path pattern would consume them.
  {
    tag: "resourceid",
    regex: /\/subscriptions\/[0-9A-Za-z-]+(?:\/[\w.()-]+)*/gi,
  },
  // IPv6 before IPv4 so IPv4-mapped addresses (::ffff:192.0.2.1) stay whole.
  // Alternatives: full 8-group form; compressed with "::" in the middle;
  // trailing "::"; leading "::". Times/ISO timestamps ("10:30:00") never
  // contain "::" nor 7 colons, so they cannot match.
  {
    tag: "ip",
    regex:
      /(?<![\w:.])(?:(?:[0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}|(?:[0-9A-Fa-f]{1,4}:){1,6}(?::[0-9A-Fa-f]{1,4}){1,6}|(?:[0-9A-Fa-f]{1,4}:){1,7}:|::(?:[0-9A-Fa-f]{1,4}:){0,6}(?:\d{1,3}(?:\.\d{1,3}){3}|[0-9A-Fa-f]{1,4}))(?![\w:])/g,
  },
  // IPv4 with realistic octet bounds (0-255), not embedded in a longer
  // dotted/numeric run (rejects "1.2.3.4.5", "build 10.0.19041.1" and
  // "256.1.1.1"). The trailing guard rejects a digit (longer number) or a
  // dot followed by an alphanumeric (longer dotted run, or an IP-prefixed
  // FQDN like "1.2.3.4.example.com" which the host pattern redacts whole),
  // but allows a sentence-ending dot: "from 10.2.3.4." -> "from <ip:..>.".
  {
    tag: "ip",
    regex:
      /(?<![\d.])(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?!\d|\.[0-9A-Za-z])/g,
  },
  // GUIDs (resource IDs containing GUIDs were already consumed above).
  {
    tag: "guid",
    regex:
      /(?<![0-9A-Fa-f-])[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}(?![0-9A-Fa-f-])/g,
  },
  // Windows paths: drive-letter ("C:\...") or UNC ("\\server\share\..").
  // Segments exclude characters invalid in Windows file names plus
  // whitespace, so the match never runs across prose. "\\+" tolerates
  // JSON-style doubled backslashes.
  {
    tag: "path",
    regex:
      /(?:(?<![A-Za-z0-9])[A-Za-z]:\\+|\\\\+)[^\\/:*?"<>|\s]+(?:\\+[^\\/:*?"<>|\s]+)*\\?/g,
  },
  // Unix absolute paths: at least two segments so "/v1" or a lone "/tmp"
  // route fragment is not consumed; lookbehind rejects "2026/06/12"-style
  // slashes inside words/dates.
  {
    tag: "path",
    regex: /(?<![\w.:])(?:\/[A-Za-z0-9][\w.-]*){2,}\/?/g,
  },
  // FQDNs / hostnames: dotted labels with an alphabetic TLD of 2+ chars.
  // KQL table/function names contain no dot and never match; numbers and
  // ISO timestamps fail the alphabetic-TLD requirement. A trailing dot
  // (DNS root form "host.example.com.") is left outside the match.
  {
    tag: "host",
    regex:
      /(?<![\w.@-])(?:[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?\.)+[A-Za-z]{2,}(?![\w-])/g,
  },
];

/**
 * Redacts sensitive substrings (tokens, URLs, emails, IPs, GUIDs, Azure
 * resource IDs, file paths, hostnames) from free text, replacing each with a
 * deterministic `<tag:hash>` placeholder.
 *
 * Plain numbers, booleans, ISO 8601 timestamps and KQL keywords/table names
 * pass through unchanged.
 */
export function redactText(text: string): string {
  let out = text;
  for (const { tag, regex } of PATTERNS) {
    out = out.replace(regex, (match) => placeholder(tag, match));
  }
  return out;
}

/**
 * Recursively redacts a value of unknown shape.
 *
 * Strings go through {@link redactText}; numbers, booleans, null and
 * undefined pass through untouched; arrays and plain objects are rebuilt with
 * every nested value redacted. The input is never mutated — new structures
 * are returned. Object keys are treated as schema (field names), not data,
 * and are preserved.
 */
export function redactValue(value: unknown): unknown {
  if (typeof value === "string") {
    return redactText(value);
  }
  if (Array.isArray(value)) {
    return value.map((item) => redactValue(item));
  }
  if (value !== null && typeof value === "object") {
    if (value instanceof Date) {
      return new Date(value.getTime());
    }
    const out: Record<string, unknown> = {};
    for (const [key, nested] of Object.entries(value)) {
      out[key] = redactValue(nested);
    }
    return out;
  }
  return value;
}

/** Stable string form of a cell used as hash input for forced column masking. */
function cellToHashInput(cell: unknown): string {
  if (typeof cell === "string") return cell;
  try {
    return JSON.stringify(cell) ?? String(cell);
  } catch {
    return String(cell);
  }
}

/** Masks a cell under a sensitive column as `<colname:hash>`; null/undefined stay as-is. */
function maskSensitiveCell(columnName: string, cell: unknown): unknown {
  if (cell === null || cell === undefined) {
    return cell;
  }
  return placeholder(columnName.toLowerCase(), cellToHashInput(cell));
}

function redactTable(table: KustoTable, sensitive: ReadonlySet<string>): KustoTable {
  return {
    name: table.name,
    columns: table.columns.map((column) => ({ ...column })),
    rows: table.rows.map((row) =>
      row.map((cell, index) => {
        const column = table.columns[index];
        if (column !== undefined && sensitive.has(column.name.toLowerCase())) {
          return maskSensitiveCell(column.name, cell);
        }
        return redactValue(cell);
      }),
    ),
  };
}

/**
 * Returns a redacted deep copy of a Log Analytics query result, suitable for
 * forwarding to the model when raw examples are not allowed.
 *
 * Every cell is value-redacted via {@link redactValue}. Cells under columns
 * whose name case-insensitively matches {@link DEFAULT_SENSITIVE_COLUMNS}
 * (plus any `opts.sensitiveColumns` extras) are always masked as
 * `<colname:hash>`, even when the value matches no textual pattern (null and
 * undefined cells are kept so sparseness analysis still works).
 *
 * `statistics` and `dataSources` metadata pass through unredacted (deep-
 * copied), as does any `error`. The input is never mutated.
 */
export function redactQueryResult(
  result: LogQueryResult,
  opts?: RedactQueryResultOptions,
): LogQueryResult {
  const sensitive = new Set(DEFAULT_SENSITIVE_COLUMNS.map((name) => name.toLowerCase()));
  for (const extra of opts?.sensitiveColumns ?? []) {
    sensitive.add(extra.toLowerCase());
  }

  const redacted: LogQueryResult = {
    status: result.status,
    tables: result.tables.map((table) => redactTable(table, sensitive)),
    durationMs: result.durationMs,
  };
  if (result.statistics !== undefined) {
    redacted.statistics = structuredClone(result.statistics);
  }
  if (result.dataSources !== undefined) {
    redacted.dataSources = structuredClone(result.dataSources);
  }
  if (result.error !== undefined) {
    redacted.error = structuredClone(result.error);
  }
  return redacted;
}
