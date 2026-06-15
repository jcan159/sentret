/**
 * Query safety gate for the KQL Detection Rule Analyser.
 *
 * Every query bound for Log Analytics passes through {@link assessQuerySafety}
 * first, and every timespan through {@link validateTimespan}. The gate is
 * deliberately conservative: management commands, workspace-wide scans
 * (search/find/wildcard union), cross-resource resolvers that escape the
 * target workspace, and oversized samples are hard blockers; performance
 * smells are warnings that are surfaced but do not stop execution.
 *
 * Spec: docs/implementation_notes.md "Query Safety Controls" and
 * prompts/system_prompt_full.md sections 3, 5 (step 3), and 13.
 */

import type { QuerySafetyOptions, QuerySafetyVerdict } from "../types.js";

/**
 * Defaults applied by {@link assessQuerySafety} when options are omitted.
 * `allowedWorkspaceId` deliberately has no default: when it is unset,
 * cross-resource resolvers (workspace()/app()/database()) are blocked outright.
 */
export const DEFAULT_SAFETY_OPTIONS: Required<
  Omit<QuerySafetyOptions, "allowedWorkspaceId">
> = {
  allowBroadQueries: false,
  maxSampleRows: 50,
  maxQueryLength: 20000,
};

// ---------------------------------------------------------------------------
// Timespan validation
// ---------------------------------------------------------------------------

/**
 * ISO 8601 duration, e.g. "PT24H", "P7D", "P1DT12H". At least one component is
 * required ("P" / "PT" alone are invalid); a fraction is permitted on any
 * component value.
 */
const DURATION_RE =
  /^P(?=\d|T\d)(?:(\d+(?:\.\d+)?)Y)?(?:(\d+(?:\.\d+)?)M)?(?:(\d+(?:\.\d+)?)W)?(?:(\d+(?:\.\d+)?)D)?(?:T(?=\d)(?:(\d+(?:\.\d+)?)H)?(?:(\d+(?:\.\d+)?)M)?(?:(\d+(?:\.\d+)?)S)?)?$/;

const DATE_RE = /^(\d{4})-(\d{2})-(\d{2})$/;
const DATETIME_RE =
  /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2})(?::(\d{2})(?:\.(\d{1,9}))?)?(Z|[+-]\d{2}:\d{2})?$/;

/**
 * Parses one endpoint of a start/end range as a UTC epoch-millisecond value.
 * A date-only endpoint means midnight UTC; a datetime without a timezone
 * designator is treated as UTC so range comparison is deterministic.
 */
function parseRangeEndpoint(part: string): { ms: number } | { error: string } {
  let year: number;
  let month: number;
  let day: number;
  let hour = 0;
  let minute = 0;
  let second = 0;
  let fractionMs = 0;
  let offsetMinutes = 0;

  const dateMatch = DATE_RE.exec(part);
  if (dateMatch) {
    year = Number(dateMatch[1]);
    month = Number(dateMatch[2]);
    day = Number(dateMatch[3]);
  } else {
    const dtMatch = DATETIME_RE.exec(part);
    if (!dtMatch) {
      return { error: `"${part}" is not an ISO 8601 date or datetime` };
    }
    year = Number(dtMatch[1]);
    month = Number(dtMatch[2]);
    day = Number(dtMatch[3]);
    hour = Number(dtMatch[4]);
    minute = Number(dtMatch[5]);
    second = Number(dtMatch[6] ?? "0");
    fractionMs = dtMatch[7] !== undefined ? Number(`0.${dtMatch[7]}`) * 1000 : 0;
    const tz = dtMatch[8];
    if (tz !== undefined && tz !== "Z") {
      const sign = tz.startsWith("-") ? -1 : 1;
      const offsetHour = Number(tz.slice(1, 3));
      const offsetMinute = Number(tz.slice(4, 6));
      if (offsetHour > 23 || offsetMinute > 59) {
        return { error: `"${part}" has an invalid timezone offset` };
      }
      offsetMinutes = sign * (offsetHour * 60 + offsetMinute);
    }
    if (hour > 23 || minute > 59 || second > 59) {
      return { error: `"${part}" has an out-of-range time component` };
    }
  }

  // Reject impossible calendar dates instead of letting Date roll them over
  // (e.g. 2026-02-30 silently becoming March 2).
  const probe = new Date(Date.UTC(year, month - 1, day));
  if (
    month < 1 ||
    month > 12 ||
    probe.getUTCFullYear() !== year ||
    probe.getUTCMonth() !== month - 1 ||
    probe.getUTCDate() !== day
  ) {
    return { error: `"${part}" is not a real calendar date` };
  }

  const ms =
    Date.UTC(year, month - 1, day, hour, minute, second) + fractionMs - offsetMinutes * 60_000;
  return { ms };
}

/**
 * Validates a query timespan: either an ISO 8601 duration ("PT24H", "P7D",
 * "P1DT12H") or a start/end range of ISO dates or datetimes separated by "/"
 * ("2026-06-01/2026-06-08"). Zero-length durations and reversed or zero-width
 * ranges are rejected with an explanatory reason.
 */
export function validateTimespan(timespan: string): { valid: boolean; reason?: string } {
  if (timespan.trim() === "") {
    return { valid: false, reason: "Timespan is empty; an explicit timespan is required." };
  }

  if (timespan.includes("/")) {
    const parts = timespan.split("/");
    if (parts.length !== 2 || parts[0] === "" || parts[1] === "") {
      return {
        valid: false,
        reason: `Range "${timespan}" must be exactly two ISO dates/datetimes separated by "/".`,
      };
    }
    const start = parseRangeEndpoint(parts[0] ?? "");
    if ("error" in start) {
      return { valid: false, reason: `Invalid range start: ${start.error}.` };
    }
    const end = parseRangeEndpoint(parts[1] ?? "");
    if ("error" in end) {
      return { valid: false, reason: `Invalid range end: ${end.error}.` };
    }
    if (start.ms >= end.ms) {
      return {
        valid: false,
        reason: `Range start must be strictly before range end (got "${timespan}").`,
      };
    }
    return { valid: true };
  }

  if (timespan.startsWith("P")) {
    const match = DURATION_RE.exec(timespan);
    if (!match) {
      return {
        valid: false,
        reason: `"${timespan}" is not a valid ISO 8601 duration (expected e.g. "PT24H", "P7D", "P1DT12H").`,
      };
    }
    const total = match
      .slice(1)
      .reduce((sum, group) => sum + (group !== undefined ? Number(group) : 0), 0);
    if (total === 0) {
      return { valid: false, reason: `Duration "${timespan}" has zero length.` };
    }
    return { valid: true };
  }

  return {
    valid: false,
    reason: `"${timespan}" is not recognised as an ISO 8601 duration (e.g. "PT24H") or a start/end range (e.g. "2026-06-01/2026-06-08").`,
  };
}

// ---------------------------------------------------------------------------
// Comment / string-literal stripping
// ---------------------------------------------------------------------------

/**
 * Returns the query with line-comment text and string-literal CONTENTS
 * replaced by spaces, preserving length and character positions. Quote
 * delimiters are kept so the structure stays parseable. KQL doubled-quote
 * escaping ("" inside "..." and '' inside '...') is respected. Pattern
 * matching on the result means threats cannot hide inside literals/comments
 * and literal text cannot trigger false positives.
 *
 * The output is the same UTF-16 length as the input with every index aligned,
 * so callers may map a position in the stripped text back to the original
 * query (used to recover string-literal arguments of cross-resource
 * resolvers). split("") is used rather than Array.from so indices stay UTF-16
 * code units, matching charAt()/slice() positions even around astral chars.
 */
function stripCommentsAndStrings(query: string): string {
  const out = query.split("");
  const n = query.length;
  let i = 0;
  while (i < n) {
    const ch = query.charAt(i);
    if (ch === "/" && query.charAt(i + 1) === "/") {
      while (i < n && query.charAt(i) !== "\n") {
        out[i] = " ";
        i++;
      }
    } else if (ch === '"' || ch === "'") {
      i++; // keep the opening delimiter
      while (i < n) {
        if (query.charAt(i) === ch) {
          if (query.charAt(i + 1) === ch) {
            // doubled quote = escaped quote inside the literal
            out[i] = " ";
            out[i + 1] = " ";
            i += 2;
            continue;
          }
          break;
        }
        out[i] = " ";
        i++;
      }
      if (i < n) i++; // keep the closing delimiter
    } else {
      i++;
    }
  }
  return out.join("");
}

// ---------------------------------------------------------------------------
// Safety assessment
// ---------------------------------------------------------------------------

/**
 * Detects wildcard table references in a `union` table list: `union *`,
 * `union App*`, `union withsource=Src Sig*`, `union SecurityEvent, App*`.
 * After each `union` keyword the table list is scanned at paren depth 0 until
 * the next pipe/semicolon, so `*` used as multiplication inside a
 * parenthesised subquery or in a later pipeline stage does not match.
 * Optional name=value parameters (kind=, withsource=, isfuzzy=) contain no
 * `*` and are scanned over harmlessly.
 */
function hasWildcardUnion(stripped: string): boolean {
  const unionRe = /\bunion\b/gi;
  let match: RegExpExecArray | null;
  while ((match = unionRe.exec(stripped)) !== null) {
    let depth = 0;
    let i = match.index + match[0].length;
    while (i < stripped.length) {
      const ch = stripped.charAt(i);
      if (ch === "(") {
        depth++;
      } else if (ch === ")") {
        if (depth === 0) break; // left the enclosing scope of this union
        depth--;
      } else if (depth === 0) {
        if (ch === "|" || ch === ";") break; // end of the union table list
        if (ch === "*") return true;
      }
      i++;
    }
  }
  return false;
}

/** Table-scoped find: `find in (T1, T2) ...`, optionally `find withsource=Col in (...)`. */
const FIND_SCOPED_RE = /^find\s+(?:withsource\s*=\s*[\w-]+\s+)?in\s*\(([^)]*)\)/i;

/** Cross-resource resolver call sites: workspace(, app(, resource(, cluster(, database(, adx(. */
const CROSS_RESOURCE_RE = /\b(workspace|app|resource|cluster|database|adx)\s*\(/gi;

interface CrossResourceHit {
  /** Lower-cased resolver name, e.g. "workspace". */
  resolver: string;
  /**
   * The resolver's single string-literal argument, recovered from the
   * ORIGINAL query (the stripped text blanks literal contents). Undefined
   * when the argument is not a single string literal (non-literal/unparseable).
   */
  literal: string | undefined;
}

/**
 * Finds cross-resource resolver calls in the stripped text and recovers each
 * one's quoted argument from the original query. Index parity between the two
 * strings is guaranteed by {@link stripCommentsAndStrings}'s space-padding, so
 * resolver mentions inside string literals or comments never match while real
 * call sites yield the true literal text.
 */
function findCrossResourceResolvers(original: string, stripped: string): CrossResourceHit[] {
  const hits: CrossResourceHit[] = [];
  CROSS_RESOURCE_RE.lastIndex = 0;
  let match: RegExpExecArray | null;
  while ((match = CROSS_RESOURCE_RE.exec(stripped)) !== null) {
    const resolver = (match[1] ?? "").toLowerCase();
    let i = CROSS_RESOURCE_RE.lastIndex; // just past the opening paren
    while (i < stripped.length && /\s/.test(stripped.charAt(i))) i++;
    const quote = stripped.charAt(i);
    if (quote !== '"' && quote !== "'") {
      hits.push({ resolver, literal: undefined }); // non-literal argument
      continue;
    }
    // Literal contents are blanked in `stripped`, so the next matching quote
    // char is necessarily the closing delimiter (escapes were blanked too).
    const close = stripped.indexOf(quote, i + 1);
    if (close === -1) {
      hits.push({ resolver, literal: undefined }); // unterminated literal
      continue;
    }
    let j = close + 1;
    while (j < stripped.length && /\s/.test(stripped.charAt(j))) j++;
    if (stripped.charAt(j) !== ")") {
      hits.push({ resolver, literal: undefined }); // not a single literal argument
      continue;
    }
    hits.push({ resolver, literal: original.slice(i + 1, close) });
  }
  return hits;
}

/** First arg position of make_set( / make_list( (make_set_if etc. do not match). */
const MAKE_AGGREGATE_RE = /\b(make_set|make_list)\s*\(/gi;

/** Finds make_set(/make_list( calls that have no second (cap) argument. */
function findUncappedAggregates(stripped: string): string[] {
  const found: string[] = [];
  MAKE_AGGREGATE_RE.lastIndex = 0;
  let match: RegExpExecArray | null;
  while ((match = MAKE_AGGREGATE_RE.exec(stripped)) !== null) {
    let depth = 1;
    let hasTopLevelComma = false;
    let i = MAKE_AGGREGATE_RE.lastIndex; // just past the opening paren
    while (i < stripped.length && depth > 0) {
      const ch = stripped.charAt(i);
      if (ch === "(") depth++;
      else if (ch === ")") depth--;
      else if (ch === "," && depth === 1) hasTopLevelComma = true;
      i++;
    }
    if (!hasTopLevelComma) {
      found.push((match[1] ?? "").toLowerCase());
    }
  }
  return found;
}

/**
 * Assesses a KQL query against the safety policy before it may be sent to
 * Log Analytics. Returns hard blockers (management commands, workspace-wide
 * scans via search/find/wildcard union, cross-resource resolvers that escape
 * the allowed workspace, oversized samples/queries) and soft warnings (missing time scoping,
 * expensive operators, poor operator ordering). The query is allowed only if
 * no blockers are found; warnings never block.
 */
export function assessQuerySafety(
  query: string,
  opts?: QuerySafetyOptions,
): QuerySafetyVerdict {
  const allowBroadQueries =
    opts?.allowBroadQueries ?? DEFAULT_SAFETY_OPTIONS.allowBroadQueries;
  const maxSampleRows = opts?.maxSampleRows ?? DEFAULT_SAFETY_OPTIONS.maxSampleRows;
  const maxQueryLength = opts?.maxQueryLength ?? DEFAULT_SAFETY_OPTIONS.maxQueryLength;
  // Empty/blank is treated as unset so workspace('') can never slip through.
  const allowedWorkspaceId =
    opts?.allowedWorkspaceId !== undefined && opts.allowedWorkspaceId.trim() !== ""
      ? opts.allowedWorkspaceId
      : undefined;

  const blockers: string[] = [];
  const warnings: string[] = [];

  if (query.trim() === "") {
    return { allowed: false, blockers: ["Query is empty or whitespace-only."], warnings };
  }

  const stripped = stripCommentsAndStrings(query);
  if (stripped.trim() === "") {
    return {
      allowed: false,
      blockers: ["Query contains only comments/whitespace; nothing executable."],
      warnings,
    };
  }

  if (query.length > maxQueryLength) {
    blockers.push(
      `Query is ${query.length} characters long, exceeding the maximum of ${maxQueryLength}.`,
    );
  }

  // Per-statement checks: semicolons separate Kusto statements, so a control
  // command or workspace-wide search can hide after a benign statement.
  for (const rawStatement of stripped.split(";")) {
    const statement = rawStatement.trim();
    if (statement === "") continue;

    if (statement.startsWith(".")) {
      const name = /^\.([A-Za-z][\w-]*)/.exec(statement)?.[1] ?? "";
      blockers.push(
        `Kusto control/management command ".${name}" is not allowed; only read-only queries may run.`,
      );
      continue;
    }

    if (
      /^search\b/i.test(statement) &&
      !/^search\s+in\s*\(/i.test(statement) &&
      !allowBroadQueries
    ) {
      blockers.push(
        `Workspace-wide "search" operator is blocked; scope it to specific tables (e.g. "search in (Table) ...") or set allowBroadQueries.`,
      );
    }

    // "find" scans every table unless scoped with "in (...)"; a wildcard in
    // the in-list ("find in (Security*)") is just as broad, so it blocks too.
    if (/^find\b/i.test(statement) && !allowBroadQueries) {
      const scoped = FIND_SCOPED_RE.exec(statement);
      if (scoped === null) {
        blockers.push(
          `Workspace-wide "find" operator is blocked; scope it to specific tables (e.g. "find in (Table) where ...") or set allowBroadQueries.`,
        );
      } else if ((scoped[1] ?? "").includes("*")) {
        blockers.push(
          `"find in (...)" with a wildcard table pattern is blocked; name the tables explicitly or set allowBroadQueries.`,
        );
      }
    }
  }

  if (hasWildcardUnion(stripped) && !allowBroadQueries) {
    blockers.push(
      `Wildcard table union ("union *" / "union App*") is blocked; name the tables explicitly or set allowBroadQueries.`,
    );
  }

  // Cross-resource resolver confinement. These are CONFINEMENT blockers, not
  // breadth approvals: allowBroadQueries deliberately has no effect here. An
  // operator may approve scanning every table in the target workspace, but
  // reading a different workspace/app/cluster is never an approval matter for
  // this single-workspace tool. Note that database() also appears in
  // legitimate cluster(...).database(...) chains — blocking it is correct
  // here, since any database() reference escapes the bound workspace.
  for (const hit of findCrossResourceResolvers(query, stripped)) {
    if (hit.resolver === "cluster" || hit.resolver === "adx" || hit.resolver === "resource") {
      blockers.push(
        `Cross-cluster resolver "${hit.resolver}()" is not allowed: it reaches outside the target workspace's cluster. Queries are confined to the allowed workspace.`,
      );
    } else if (hit.literal === undefined) {
      blockers.push(
        `Cross-resource resolver "${hit.resolver}()" has a non-literal or unparseable argument, so its target cannot be verified. Queries are confined to the allowed workspace.`,
      );
    } else if (allowedWorkspaceId === undefined) {
      blockers.push(
        `Cross-resource resolver "${hit.resolver}('${hit.literal}')" is not allowed: no allowed workspace ID is configured. Queries are confined to the allowed workspace.`,
      );
    } else if (hit.literal.toLowerCase() !== allowedWorkspaceId.toLowerCase()) {
      blockers.push(
        `Cross-resource resolver "${hit.resolver}('${hit.literal}')" does not match the allowed workspace ID. Queries are confined to the allowed workspace.`,
      );
    }
  }

  if (/\bexternaldata\b/i.test(stripped) && !allowBroadQueries) {
    blockers.push(
      `"externaldata" operator is blocked: it reaches external URIs. Set allowBroadQueries to permit it.`,
    );
  }

  for (const match of stripped.matchAll(/\b(take|limit|sample)\s+(\d+)\b/gi)) {
    const operator = match[1] ?? "";
    const rows = Number(match[2] ?? "0");
    if (rows > maxSampleRows) {
      blockers.push(
        `"${operator} ${rows}" requests more than the maximum of ${maxSampleRows} sample rows.`,
      );
    }
  }

  // --- Warnings (never block) ---

  if (
    !/TimeGenerated/i.test(stripped) &&
    !/\bago\s*\(/i.test(stripped) &&
    !/\bbetween\s*\(/i.test(stripped)
  ) {
    warnings.push(
      "No time scoping detected (no TimeGenerated, ago(), or between()); the request timespan still bounds the query server-side, but explicit scoping is recommended.",
    );
  }

  if (/\b!?contains(_cs)?\b/i.test(stripped)) {
    warnings.push(
      `Filter uses "contains"; prefer "has" for indexed token matching where possible.`,
    );
  }

  if (/\bmatches\s+regex\b/i.test(stripped)) {
    warnings.push(
      `Regex matching via "matches regex" can be expensive; run it after cheaper filters.`,
    );
  }
  if (/\bextract(_all)?\s*\(/i.test(stripped)) {
    warnings.push(
      `Regex extraction via "extract()" can be expensive; run it after cheaper filters.`,
    );
  }
  if (/\bparse\s*\(/i.test(stripped)) {
    warnings.push(`"parse()" detected; excessive dynamic parsing can be expensive.`);
  }

  const firstWhere = stripped.search(/\bwhere\b/i);
  const firstJoin = stripped.search(/\bjoin\b/i);
  if (firstJoin >= 0 && (firstWhere < 0 || firstJoin < firstWhere)) {
    warnings.push(
      `"join" appears before any "where" filter; filter both sides before joining to reduce cost.`,
    );
  }

  const firstMvExpand = stripped.search(/\bmv-expand\b|\bmvexpand\b/i);
  if (firstMvExpand >= 0 && (firstWhere < 0 || firstMvExpand < firstWhere)) {
    warnings.push(
      `"mv-expand" appears before any "where" filter; expanding unfiltered rows is expensive.`,
    );
  }

  for (const fn of findUncappedAggregates(stripped)) {
    warnings.push(
      `"${fn}()" is used without an explicit cap argument; uncapped aggregation can produce very large dynamic values.`,
    );
  }

  const firstSort = stripped.search(/\b(?:sort|order)\s+by\b/i);
  const firstReduction = stripped.search(/\b(?:take|limit|top|summarize)\b/i);
  if (firstSort >= 0 && (firstReduction < 0 || firstSort < firstReduction)) {
    warnings.push(
      `"sort/order by" appears before any take/top/summarize reduction; sorting an unreduced result set is expensive.`,
    );
  }

  return { allowed: blockers.length === 0, blockers, warnings };
}
