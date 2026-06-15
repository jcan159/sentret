import { describe, it, expect } from "vitest";
import {
  validateTimespan,
  assessQuerySafety,
  DEFAULT_SAFETY_OPTIONS,
} from "./query_safety.js";

// ---------------------------------------------------------------------------
// validateTimespan
// ---------------------------------------------------------------------------

describe("validateTimespan", () => {
  describe("ISO 8601 durations", () => {
    it.each(["PT24H", "P7D", "P1DT12H", "PT30M", "P1W", "P1Y2M3D", "PT1H30M", "PT0.5S"])(
      "accepts %s",
      (timespan) => {
        expect(validateTimespan(timespan)).toEqual({ valid: true });
      },
    );

    it.each(["P0D", "PT0H", "P0DT0H0M", "PT0S"])("rejects zero-length duration %s", (timespan) => {
      const result = validateTimespan(timespan);
      expect(result.valid).toBe(false);
      expect(result.reason).toMatch(/zero/i);
    });

    it.each(["P", "PT", "P7", "7D", "PT24", "P7D8H", "pt24h "])(
      "rejects malformed duration %j",
      (timespan) => {
        const result = validateTimespan(timespan);
        expect(result.valid).toBe(false);
        expect(result.reason).toBeTruthy();
      },
    );

    it("does not accept durations via substring (garbage around a valid token)", () => {
      expect(validateTimespan("xP7Dx").valid).toBe(false);
      expect(validateTimespan("P7D extra").valid).toBe(false);
    });
  });

  describe("start/end ranges", () => {
    it("accepts a date-only range", () => {
      expect(validateTimespan("2026-06-01/2026-06-08")).toEqual({ valid: true });
    });

    it("accepts a datetime range", () => {
      expect(
        validateTimespan("2026-06-01T00:00:00Z/2026-06-08T00:00:00Z"),
      ).toEqual({ valid: true });
    });

    it("accepts a mixed date/datetime range", () => {
      expect(validateTimespan("2026-06-01/2026-06-08T12:30:00Z")).toEqual({ valid: true });
    });

    it("accepts datetimes with fractional seconds and offsets", () => {
      expect(
        validateTimespan("2026-06-01T00:00:00.123+02:00/2026-06-02T00:00:00Z"),
      ).toEqual({ valid: true });
    });

    it("rejects a reversed range", () => {
      const result = validateTimespan("2026-06-08/2026-06-01");
      expect(result.valid).toBe(false);
      expect(result.reason).toMatch(/before/i);
    });

    it("rejects a zero-width range (start === end)", () => {
      const result = validateTimespan("2026-06-01/2026-06-01");
      expect(result.valid).toBe(false);
      expect(result.reason).toMatch(/before/i);
    });

    it("rejects impossible calendar dates (no rollover)", () => {
      const result = validateTimespan("2026-02-30/2026-03-05");
      expect(result.valid).toBe(false);
      expect(result.reason).toMatch(/date/i);
    });

    it("rejects out-of-range time components", () => {
      expect(validateTimespan("2026-06-01T25:00:00Z/2026-06-02T00:00:00Z").valid).toBe(false);
      expect(validateTimespan("2026-06-01T10:61:00Z/2026-06-02T00:00:00Z").valid).toBe(false);
    });

    it.each(["2026-06-01/", "/2026-06-08", "2026-06-01/2026-06-02/2026-06-03", "2026-6-1/2026-6-8"])(
      "rejects malformed range %j",
      (timespan) => {
        const result = validateTimespan(timespan);
        expect(result.valid).toBe(false);
        expect(result.reason).toBeTruthy();
      },
    );
  });

  describe("garbage input", () => {
    it.each(["", "   ", "yesterday", "24h", "last week", "\n"])("rejects %j with a reason", (timespan) => {
      const result = validateTimespan(timespan);
      expect(result.valid).toBe(false);
      expect(result.reason).toBeTruthy();
    });
  });
});

// ---------------------------------------------------------------------------
// DEFAULT_SAFETY_OPTIONS
// ---------------------------------------------------------------------------

describe("DEFAULT_SAFETY_OPTIONS", () => {
  it("matches the documented defaults", () => {
    expect(DEFAULT_SAFETY_OPTIONS).toEqual({
      allowBroadQueries: false,
      maxSampleRows: 50,
      maxQueryLength: 20000,
    });
  });
});

// ---------------------------------------------------------------------------
// assessQuerySafety — blockers
// ---------------------------------------------------------------------------

describe("assessQuerySafety blockers", () => {
  it("blocks an empty query", () => {
    const verdict = assessQuerySafety("");
    expect(verdict.allowed).toBe(false);
    expect(verdict.blockers.length).toBeGreaterThan(0);
  });

  it("blocks a whitespace-only query", () => {
    const verdict = assessQuerySafety("   \n\t ");
    expect(verdict.allowed).toBe(false);
  });

  it("blocks a comment-only query", () => {
    const verdict = assessQuerySafety("// just a comment\n// another");
    expect(verdict.allowed).toBe(false);
  });

  describe("Kusto control commands (dot statements)", () => {
    it.each([
      ".drop table SigninLogs",
      ".ingest inline into table T <| 1",
      ".set-or-append T <| print 1",
      ".purge table T records",
      ".alter table T policy retention",
      "  .show tables",
    ])("blocks %j", (query) => {
      const verdict = assessQuerySafety(query);
      expect(verdict.allowed).toBe(false);
      expect(verdict.blockers.join(" ")).toMatch(/control|management|command/i);
    });

    it("blocks a dot command hidden after a semicolon", () => {
      const verdict = assessQuerySafety("SigninLogs | count; .drop table SigninLogs");
      expect(verdict.allowed).toBe(false);
      expect(verdict.blockers.join(" ")).toMatch(/\.drop/);
    });

    it("blocks a dot command after a semicolon and newline", () => {
      const verdict = assessQuerySafety("let x = 1;\n.purge table T records");
      expect(verdict.allowed).toBe(false);
    });

    it("does not block a dot inside a string literal", () => {
      const verdict = assessQuerySafety(
        'SigninLogs | where CommandLine == ".drop table X" | count',
      );
      expect(verdict.allowed).toBe(true);
    });

    it("does not block a statement that is only a string literal after a semicolon", () => {
      const verdict = assessQuerySafety(
        'let label = ".ingest"; SigninLogs | where TimeGenerated > ago(1h) | count',
      );
      expect(verdict.allowed).toBe(true);
    });
  });

  describe("workspace-wide search", () => {
    it('blocks bare search of a term', () => {
      const verdict = assessQuerySafety('search "mimikatz"');
      expect(verdict.allowed).toBe(false);
      expect(verdict.blockers.join(" ")).toMatch(/search/i);
    });

    it("blocks search *", () => {
      const verdict = assessQuerySafety("search *");
      expect(verdict.allowed).toBe(false);
    });

    it("blocks bare search appearing after a let statement", () => {
      const verdict = assessQuerySafety('let a = 1; search "foo"');
      expect(verdict.allowed).toBe(false);
    });

    it("allows table-scoped search in (...)", () => {
      const verdict = assessQuerySafety('search in (SecurityEvent) "4625"');
      expect(verdict.allowed).toBe(true);
    });

    it("allows bare search with allowBroadQueries", () => {
      const verdict = assessQuerySafety('search "mimikatz"', { allowBroadQueries: true });
      expect(verdict.allowed).toBe(true);
    });

    it('does not block the literal string "search *" used as a filter value', () => {
      const verdict = assessQuerySafety(
        'AuditLogs | where TimeGenerated > ago(1d) | where QueryText == "search *" | count',
      );
      expect(verdict.allowed).toBe(true);
    });

    it("does not block 'search' mentioned in a comment", () => {
      const verdict = assessQuerySafety(
        "// search * would be too broad here\nSigninLogs | where TimeGenerated > ago(1h) | count",
      );
      expect(verdict.allowed).toBe(true);
    });
  });

  describe("wildcard union", () => {
    it("blocks union *", () => {
      const verdict = assessQuerySafety("union * | where TimeGenerated > ago(1h) | count");
      expect(verdict.allowed).toBe(false);
      expect(verdict.blockers.join(" ")).toMatch(/union/i);
    });

    it("blocks union withsource=... *", () => {
      const verdict = assessQuerySafety(
        "union withsource=SourceTable * | where TimeGenerated > ago(1h) | count",
      );
      expect(verdict.allowed).toBe(false);
    });

    it("blocks union kind=outer withsource=Src isfuzzy=true *", () => {
      const verdict = assessQuerySafety(
        "union kind=outer withsource=Src isfuzzy=true * | count",
      );
      expect(verdict.allowed).toBe(false);
    });

    it("allows union over named tables", () => {
      const verdict = assessQuerySafety(
        "union SecurityEvent, Syslog | where TimeGenerated > ago(1h) | count",
      );
      expect(verdict.allowed).toBe(true);
    });

    it("allows union * with allowBroadQueries", () => {
      const verdict = assessQuerySafety("union * | count", { allowBroadQueries: true });
      expect(verdict.allowed).toBe(true);
    });

    it('does not block the literal string "union *"', () => {
      const verdict = assessQuerySafety(
        'AuditLogs | where TimeGenerated > ago(1d) | where QueryText has "union *" | count',
      );
      expect(verdict.allowed).toBe(true);
    });
  });

  describe("externaldata", () => {
    it("blocks externaldata", () => {
      const verdict = assessQuerySafety(
        'externaldata(ip: string) [ "https://example.com/feed.csv" ] | count',
      );
      expect(verdict.allowed).toBe(false);
      expect(verdict.blockers.join(" ")).toMatch(/externaldata/i);
    });

    it("allows externaldata with allowBroadQueries", () => {
      const verdict = assessQuerySafety(
        'externaldata(ip: string) [ "https://example.com/feed.csv" ] | count',
        { allowBroadQueries: true },
      );
      expect(verdict.allowed).toBe(true);
    });

    it("does not block externaldata mentioned in a string literal", () => {
      const verdict = assessQuerySafety(
        'T | where TimeGenerated > ago(1h) | where Msg == "externaldata" | count',
      );
      expect(verdict.allowed).toBe(true);
    });
  });

  describe("sample row caps", () => {
    it("blocks take above the default cap and names the cap", () => {
      const verdict = assessQuerySafety("SigninLogs | where TimeGenerated > ago(1h) | take 500");
      expect(verdict.allowed).toBe(false);
      expect(verdict.blockers.join(" ")).toMatch(/50/);
    });

    it("allows take at the cap", () => {
      const verdict = assessQuerySafety("SigninLogs | where TimeGenerated > ago(1h) | take 50");
      expect(verdict.allowed).toBe(true);
    });

    it("blocks limit above the cap", () => {
      const verdict = assessQuerySafety("SigninLogs | where TimeGenerated > ago(1h) | limit 100");
      expect(verdict.allowed).toBe(false);
    });

    it("blocks sample above the cap", () => {
      const verdict = assessQuerySafety("SigninLogs | where TimeGenerated > ago(1h) | sample 100");
      expect(verdict.allowed).toBe(false);
    });

    it("respects a custom maxSampleRows", () => {
      const verdict = assessQuerySafety(
        "SigninLogs | where TimeGenerated > ago(1h) | take 500",
        { maxSampleRows: 1000 },
      );
      expect(verdict.allowed).toBe(true);

      const blocked = assessQuerySafety(
        "SigninLogs | where TimeGenerated > ago(1h) | take 11",
        { maxSampleRows: 10 },
      );
      expect(blocked.allowed).toBe(false);
      expect(blocked.blockers.join(" ")).toMatch(/10/);
    });

    it("ignores take counts inside string literals", () => {
      const verdict = assessQuerySafety(
        'T | where TimeGenerated > ago(1h) | where Msg == "take 9999" | take 10',
      );
      expect(verdict.allowed).toBe(true);
    });
  });

  describe("query length", () => {
    it("blocks a query longer than the default cap", () => {
      const query = "SigninLogs | where TimeGenerated > ago(1h) // " + "x".repeat(20001);
      const verdict = assessQuerySafety(query);
      expect(verdict.allowed).toBe(false);
      expect(verdict.blockers.join(" ")).toMatch(/20000|20,000/);
    });

    it("respects a custom maxQueryLength", () => {
      const verdict = assessQuerySafety(
        "SigninLogs | where TimeGenerated > ago(1h) | count",
        { maxQueryLength: 10 },
      );
      expect(verdict.allowed).toBe(false);
    });
  });

  it("reports multiple blockers at once", () => {
    const verdict = assessQuerySafety("union * | take 500; .drop table T");
    expect(verdict.allowed).toBe(false);
    expect(verdict.blockers.length).toBeGreaterThanOrEqual(3);
  });
});

// ---------------------------------------------------------------------------
// assessQuerySafety — warnings
// ---------------------------------------------------------------------------

describe("assessQuerySafety warnings", () => {
  const TIME_SCOPED = "SecurityEvent | where TimeGenerated > ago(1h) ";

  it("warnings never flip allowed to false", () => {
    const verdict = assessQuerySafety("SecurityEvent | count");
    expect(verdict.allowed).toBe(true);
    expect(verdict.warnings.length).toBeGreaterThan(0);
  });

  describe("time scoping", () => {
    it("warns when no TimeGenerated / ago( / between( appears", () => {
      const verdict = assessQuerySafety("SecurityEvent | count");
      expect(verdict.warnings.join(" ")).toMatch(/time/i);
    });

    it.each([
      "SecurityEvent | where TimeGenerated > datetime(2026-06-01) | count",
      "SecurityEvent | where EventTime > ago(1d) | count",
      "SecurityEvent | where EventTime between (datetime(2026-06-01) .. datetime(2026-06-02)) | count",
    ])("does not warn for %j", (query) => {
      const verdict = assessQuerySafety(query);
      expect(verdict.warnings.join(" ")).not.toMatch(/no time|time scop/i);
    });

    it("does not count TimeGenerated inside a string literal as time scoping", () => {
      const verdict = assessQuerySafety('SecurityEvent | where Msg == "TimeGenerated" | count');
      expect(verdict.warnings.join(" ")).toMatch(/time/i);
    });
  });

  describe("contains", () => {
    it("warns on contains and suggests has", () => {
      const verdict = assessQuerySafety(TIME_SCOPED + '| where Account contains "admin"');
      expect(verdict.allowed).toBe(true);
      expect(verdict.warnings.join(" ")).toMatch(/contains/);
      expect(verdict.warnings.join(" ")).toMatch(/\bhas\b/);
    });

    it("does not warn when contains only appears in a string literal", () => {
      const verdict = assessQuerySafety(TIME_SCOPED + '| where Msg == "contains" | count');
      expect(verdict.warnings.join(" ")).not.toMatch(/contains/);
    });
  });

  describe("regex operators", () => {
    it("warns on matches regex", () => {
      const verdict = assessQuerySafety(TIME_SCOPED + '| where Account matches regex "adm.*"');
      expect(verdict.warnings.join(" ")).toMatch(/regex/i);
    });

    it("warns on extract(", () => {
      const verdict = assessQuerySafety(
        TIME_SCOPED + '| extend User = extract("user=(\\\\w+)", 1, Msg)',
      );
      expect(verdict.warnings.join(" ")).toMatch(/extract/i);
    });

    it("warns on parse(", () => {
      const verdict = assessQuerySafety(TIME_SCOPED + "| extend P = parse(Msg)");
      expect(verdict.warnings.join(" ")).toMatch(/parse/i);
    });

    it("does not warn when regex constructs only appear in string literals", () => {
      const verdict = assessQuerySafety(
        TIME_SCOPED + '| where Msg == "matches regex extract( parse(" | count',
      );
      expect(verdict.warnings.join(" ")).not.toMatch(/regex|extract|parse/i);
    });
  });

  describe("join / mv-expand ordering", () => {
    it("warns when join appears before any where", () => {
      const verdict = assessQuerySafety(
        "SecurityEvent | join kind=inner (SigninLogs) on Account | where TimeGenerated > ago(1h)",
      );
      expect(verdict.warnings.join(" ")).toMatch(/join/i);
    });

    it("does not warn when where precedes join", () => {
      const verdict = assessQuerySafety(
        "SecurityEvent | where TimeGenerated > ago(1h) | join kind=inner (SigninLogs) on Account",
      );
      expect(verdict.warnings.join(" ")).not.toMatch(/join/i);
    });

    it("warns when mv-expand appears before any where", () => {
      const verdict = assessQuerySafety(
        "AuditLogs | mv-expand TargetResources | where TimeGenerated > ago(1h)",
      );
      expect(verdict.warnings.join(" ")).toMatch(/mv-expand/i);
    });

    it("does not warn when where precedes mv-expand", () => {
      const verdict = assessQuerySafety(
        "AuditLogs | where TimeGenerated > ago(1h) | mv-expand TargetResources",
      );
      expect(verdict.warnings.join(" ")).not.toMatch(/mv-expand/i);
    });
  });

  describe("uncapped make_set / make_list", () => {
    it("warns on make_set without a cap", () => {
      const verdict = assessQuerySafety(TIME_SCOPED + "| summarize Hosts = make_set(Computer)");
      expect(verdict.warnings.join(" ")).toMatch(/make_set/);
    });

    it("does not warn on make_set with a cap", () => {
      const verdict = assessQuerySafety(
        TIME_SCOPED + "| summarize Hosts = make_set(Computer, 100)",
      );
      expect(verdict.warnings.join(" ")).not.toMatch(/make_set/);
    });

    it("warns on make_list without a cap, even with nested parens in the argument", () => {
      const verdict = assessQuerySafety(
        TIME_SCOPED + "| summarize L = make_list(tostring(Computer))",
      );
      expect(verdict.warnings.join(" ")).toMatch(/make_list/);
    });

    it("does not warn on make_list with a cap after a nested-paren argument", () => {
      const verdict = assessQuerySafety(
        TIME_SCOPED + "| summarize L = make_list(tostring(Computer), 64)",
      );
      expect(verdict.warnings.join(" ")).not.toMatch(/make_list/);
    });
  });

  describe("sort/order before reduction", () => {
    it("warns on sort with no reduction at all", () => {
      const verdict = assessQuerySafety(TIME_SCOPED + "| sort by TimeGenerated desc");
      expect(verdict.warnings.join(" ")).toMatch(/sort|order/i);
    });

    it("warns on order by before a take", () => {
      const verdict = assessQuerySafety(TIME_SCOPED + "| order by TimeGenerated desc | take 10");
      expect(verdict.warnings.join(" ")).toMatch(/sort|order/i);
    });

    it("does not warn when summarize precedes the sort", () => {
      const verdict = assessQuerySafety(
        TIME_SCOPED + "| summarize Count = count() by Account | sort by Count desc",
      );
      expect(verdict.warnings.join(" ")).not.toMatch(/sort|order/i);
    });
  });

  it("a clean validation query produces no warnings", () => {
    const verdict = assessQuerySafety(
      "SigninLogs | where TimeGenerated >= ago(1d) | summarize Count=count(), FirstSeen=min(TimeGenerated), LastSeen=max(TimeGenerated)",
    );
    expect(verdict.allowed).toBe(true);
    expect(verdict.warnings).toEqual([]);
    expect(verdict.blockers).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// string/comment stripping behaviour
// ---------------------------------------------------------------------------

describe("string and comment stripping", () => {
  it("handles KQL doubled-quote escaping inside double-quoted strings", () => {
    const verdict = assessQuerySafety(
      'T | where TimeGenerated > ago(1h) | where Msg == "he said ""search *"" loudly" | take 10',
    );
    expect(verdict.allowed).toBe(true);
  });

  it("handles doubled-quote escaping inside single-quoted strings", () => {
    const verdict = assessQuerySafety(
      "T | where TimeGenerated > ago(1h) | where Msg == 'it''s a union * trap' | take 10",
    );
    expect(verdict.allowed).toBe(true);
  });

  it("still detects threats after a string literal closes", () => {
    const verdict = assessQuerySafety('T | where Msg == "benign"; .drop table T');
    expect(verdict.allowed).toBe(false);
  });

  it("does not let a comment hide a threat on the next line", () => {
    const verdict = assessQuerySafety("// harmless comment\n.drop table T");
    expect(verdict.allowed).toBe(false);
  });

  it("quote characters inside comments do not open strings", () => {
    const verdict = assessQuerySafety(
      'T | where TimeGenerated > ago(1h) // it"s fine\n| union * | count',
    );
    expect(verdict.allowed).toBe(false);
  });

  it("an unterminated string does not hide the rest of the line from blockers it contains", () => {
    // The unterminated literal swallows the rest of the text as string content;
    // nothing after it should be treated as executable, and the query itself is fine.
    const verdict = assessQuerySafety(
      'T | where TimeGenerated > ago(1h) | where Msg == "unterminated union *',
    );
    expect(verdict.allowed).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// cross-resource resolver confinement (workspace/app/database/cluster/adx/resource)
// ---------------------------------------------------------------------------

describe("cross-resource resolver confinement", () => {
  const ALLOWED = "AAAAAAAA-1111-2222-3333-444444444444";
  const OPTS = { allowedWorkspaceId: ALLOWED };

  it("blocks the union-wrapped cross-workspace exploit", () => {
    const verdict = assessQuerySafety(
      "union (SigninLogs),(workspace('victim-guid').SigninLogs) | where TimeGenerated > ago(1h) | count",
      OPTS,
    );
    expect(verdict.allowed).toBe(false);
    expect(verdict.blockers.join(" ")).toMatch(/workspace/i);
  });

  it("allows workspace() whose literal matches allowedWorkspaceId (case-insensitive)", () => {
    const verdict = assessQuerySafety(
      `union SigninLogs, (workspace('${ALLOWED.toLowerCase()}').SigninLogs) | where TimeGenerated > ago(1h) | count`,
      OPTS,
    );
    expect(verdict.allowed).toBe(true);
    expect(verdict.blockers).toEqual([]);
  });

  it("allows a matching workspace() argument in double quotes", () => {
    const verdict = assessQuerySafety(
      `workspace("${ALLOWED}").SigninLogs | where TimeGenerated > ago(1h) | count`,
      OPTS,
    );
    expect(verdict.allowed).toBe(true);
  });

  it("blocks workspace() with a mismatched id and names the resolver", () => {
    const verdict = assessQuerySafety(
      "workspace('00000000-0000-0000-0000-000000000001').SigninLogs | where TimeGenerated > ago(1h) | count",
      OPTS,
    );
    expect(verdict.allowed).toBe(false);
    expect(verdict.blockers.join(" ")).toMatch(/workspace\(/i);
  });

  it("blocks workspace() outright when allowedWorkspaceId is unset", () => {
    const verdict = assessQuerySafety(
      `workspace('${ALLOWED}').SigninLogs | where TimeGenerated > ago(1h) | count`,
    );
    expect(verdict.allowed).toBe(false);
    expect(verdict.blockers.join(" ")).toMatch(/workspace/i);
  });

  it("blocks workspace() with a non-literal argument even when allowedWorkspaceId is set", () => {
    const verdict = assessQuerySafety(
      "let wsId = 'x'; workspace(wsId).SigninLogs | where TimeGenerated > ago(1h) | count",
      OPTS,
    );
    expect(verdict.allowed).toBe(false);
    expect(verdict.blockers.join(" ")).toMatch(/non-literal|unparseable/i);
  });

  it("blocks cluster(...).database(...).Table chains", () => {
    const verdict = assessQuerySafety(
      "cluster('help.kusto.windows.net').database('Samples').StormEvents | where TimeGenerated > ago(1h) | count",
      OPTS,
    );
    expect(verdict.allowed).toBe(false);
    expect(verdict.blockers.join(" ")).toMatch(/cluster/i);
    expect(verdict.blockers.join(" ")).toMatch(/database/i);
  });

  it("blocks adx()", () => {
    const verdict = assessQuerySafety(
      "adx('https://help.kusto.windows.net/Samples').StormEvents | count",
      OPTS,
    );
    expect(verdict.allowed).toBe(false);
    expect(verdict.blockers.join(" ")).toMatch(/adx/i);
  });

  it("blocks resource()", () => {
    const verdict = assessQuerySafety(
      "resource('/subscriptions/123/resourceGroups/rg').Heartbeat | count",
      OPTS,
    );
    expect(verdict.allowed).toBe(false);
    expect(verdict.blockers.join(" ")).toMatch(/resource/i);
  });

  it("blocks app() with a mismatched id and allows a matching one", () => {
    expect(
      assessQuerySafety("app('other-app').requests | where TimeGenerated > ago(1h) | count", OPTS)
        .allowed,
    ).toBe(false);
    expect(
      assessQuerySafety(
        `app('${ALLOWED}').requests | where TimeGenerated > ago(1h) | count`,
        OPTS,
      ).allowed,
    ).toBe(true);
  });

  it("blocks standalone database()", () => {
    const verdict = assessQuerySafety(
      "database('Other').Table | where TimeGenerated > ago(1h) | count",
      OPTS,
    );
    expect(verdict.allowed).toBe(false);
    expect(verdict.blockers.join(" ")).toMatch(/database/i);
  });

  it("confinement ignores allowBroadQueries: mismatched workspace() stays blocked", () => {
    const verdict = assessQuerySafety(
      "workspace('victim-guid').SigninLogs | where TimeGenerated > ago(1h) | count",
      { ...OPTS, allowBroadQueries: true },
    );
    expect(verdict.allowed).toBe(false);
  });

  it("confinement ignores allowBroadQueries: cluster()/adx()/resource() stay blocked", () => {
    for (const query of [
      "cluster('x').database('y').T | count",
      "adx('https://x/y').T | count",
      "resource('/subscriptions/s').T | count",
    ]) {
      expect(assessQuerySafety(query, { ...OPTS, allowBroadQueries: true }).allowed).toBe(false);
    }
  });

  it("does not block resolver names appearing inside a string literal", () => {
    const verdict = assessQuerySafety(
      `SigninLogs | where TimeGenerated > ago(1h) | where Message == "workspace('x')" | count`,
    );
    expect(verdict.allowed).toBe(true);
    expect(verdict.blockers).toEqual([]);
  });

  it("does not block resolver names appearing inside a comment", () => {
    const verdict = assessQuerySafety(
      "// cluster('x').database('y') would escape\nSigninLogs | where TimeGenerated > ago(1h) | count",
    );
    expect(verdict.allowed).toBe(true);
  });

  it("does not match identifiers that merely end in a resolver word (myworkspace()", () => {
    const verdict = assessQuerySafety(
      "SigninLogs | where TimeGenerated > ago(1h) | extend V = myworkspace(UserId) | count",
    );
    expect(verdict.allowed).toBe(true);
    expect(verdict.blockers).toEqual([]);
  });

  it("treats a blank allowedWorkspaceId as unset (workspace('') is blocked)", () => {
    const verdict = assessQuerySafety(
      "workspace('').SigninLogs | where TimeGenerated > ago(1h) | count",
      { allowedWorkspaceId: "  " },
    );
    expect(verdict.allowed).toBe(false);
  });

  it("keeps original/stripped positions aligned across astral characters", () => {
    // The emoji in the comment occupies two UTF-16 units; literal extraction
    // must still recover the exact workspace id from the original query.
    const verdict = assessQuerySafety(
      `// \u{1F3AF} self-reference below\nworkspace('${ALLOWED}').SigninLogs | where TimeGenerated > ago(1h) | count`,
      OPTS,
    );
    expect(verdict.allowed).toBe(true);
    expect(verdict.blockers).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// find operator
// ---------------------------------------------------------------------------

describe("find operator", () => {
  it("blocks unscoped find", () => {
    const verdict = assessQuerySafety("find where EventID == 4625");
    expect(verdict.allowed).toBe(false);
    expect(verdict.blockers.join(" ")).toMatch(/find/i);
  });

  it("allows table-scoped find in (...)", () => {
    const verdict = assessQuerySafety("find in (SecurityEvent) where EventID == 4625");
    expect(verdict.allowed).toBe(true);
  });

  it("allows find withsource=... in (...)", () => {
    const verdict = assessQuerySafety(
      "find withsource=Src in (SecurityEvent, Syslog) where EventID == 4625",
    );
    expect(verdict.allowed).toBe(true);
  });

  it("blocks find in (...) when the table list contains a wildcard", () => {
    const verdict = assessQuerySafety("find in (Security*) where EventID == 4625");
    expect(verdict.allowed).toBe(false);
    expect(verdict.blockers.join(" ")).toMatch(/wildcard/i);
  });

  it("allows unscoped find with allowBroadQueries", () => {
    const verdict = assessQuerySafety("find where EventID == 4625", {
      allowBroadQueries: true,
    });
    expect(verdict.allowed).toBe(true);
  });

  it("blocks find hidden after a semicolon", () => {
    const verdict = assessQuerySafety("let a = 1; find where EventID == 4625");
    expect(verdict.allowed).toBe(false);
  });

  it("does not block a table name that starts with 'find'", () => {
    const verdict = assessQuerySafety("Findings | where TimeGenerated > ago(1h) | count");
    expect(verdict.allowed).toBe(true);
  });

  it("does not block 'find' inside a string literal", () => {
    const verdict = assessQuerySafety(
      'SigninLogs | where TimeGenerated > ago(1h) | where Msg == "find where x" | count',
    );
    expect(verdict.allowed).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// wildcard table prefixes in union
// ---------------------------------------------------------------------------

describe("wildcard table prefixes in union", () => {
  it("blocks union App*", () => {
    const verdict = assessQuerySafety("union App* | where TimeGenerated > ago(1h) | count");
    expect(verdict.allowed).toBe(false);
    expect(verdict.blockers.join(" ")).toMatch(/union/i);
  });

  it("blocks union Sig* | count", () => {
    const verdict = assessQuerySafety("union Sig* | count");
    expect(verdict.allowed).toBe(false);
  });

  it("blocks union withsource=Src App*", () => {
    const verdict = assessQuerySafety(
      "union withsource=Src App* | where TimeGenerated > ago(1h) | count",
    );
    expect(verdict.allowed).toBe(false);
  });

  it("blocks a wildcard later in the union table list", () => {
    const verdict = assessQuerySafety(
      "union SecurityEvent, App* | where TimeGenerated > ago(1h) | count",
    );
    expect(verdict.allowed).toBe(false);
  });

  it("allows wildcard union forms with allowBroadQueries", () => {
    expect(assessQuerySafety("union App* | count", { allowBroadQueries: true }).allowed).toBe(
      true,
    );
    expect(
      assessQuerySafety("union withsource=Src Sig* | count", { allowBroadQueries: true })
        .allowed,
    ).toBe(true);
  });

  it("does not flag multiplication after the pipe that follows a union", () => {
    const verdict = assessQuerySafety(
      "union SecurityEvent, Syslog | where TimeGenerated > ago(1h) | extend Y = EventID * 2 | count",
    );
    expect(verdict.allowed).toBe(true);
  });

  it("does not flag multiplication inside a parenthesised union operand", () => {
    const verdict = assessQuerySafety(
      "SigninLogs | union (SecurityEvent | where TimeGenerated > ago(1h) | extend Y = EventID * 2) | count",
    );
    expect(verdict.allowed).toBe(true);
  });
});
