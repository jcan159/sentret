import { describe, expect, it } from "vitest";

import type { LogQueryResult } from "../types.js";
import {
  DEFAULT_SENSITIVE_COLUMNS,
  redactQueryResult,
  redactText,
  redactValue,
} from "./redaction.js";

/** Extracts every placeholder of the given tag, e.g. tag "email" -> ["<email:1a2b3c4d>"]. */
function placeholders(text: string, tag: string): string[] {
  return text.match(new RegExp(`<${tag}:[0-9a-f]{8}>`, "g")) ?? [];
}

describe("redactText: JWTs", () => {
  const jwt =
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." +
    "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4ifQ." +
    "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

  it("replaces a bearer token with <token:hash>", () => {
    const out = redactText(`Authorization: Bearer ${jwt}`);
    expect(out).toBe(`Authorization: Bearer ${placeholders(out, "token")[0]}`);
    expect(out).not.toContain("eyJ");
  });

  it("consumes the JWT before the email pattern can split it", () => {
    const out = redactText(jwt);
    expect(placeholders(out, "token")).toHaveLength(1);
    expect(placeholders(out, "email")).toHaveLength(0);
  });
});

describe("redactText: URLs", () => {
  it("replaces http/https/ftp URLs", () => {
    for (const url of [
      "https://login.microsoftonline.com/common/oauth2/token?client_id=1",
      "http://evil-c2.example.net/payload.bin",
      "ftp://files.contoso.com/drop/x.zip",
    ]) {
      const out = redactText(`saw ${url} in logs`);
      expect(placeholders(out, "url")).toHaveLength(1);
      expect(out).not.toContain("example");
      expect(out).not.toContain("contoso");
      expect(out).not.toContain("microsoftonline");
    }
  });

  it("consumes the URL before host/path/ip patterns", () => {
    const out = redactText("GET https://10.0.0.5/admin/login.php");
    expect(placeholders(out, "url")).toHaveLength(1);
    expect(placeholders(out, "ip")).toHaveLength(0);
    expect(placeholders(out, "host")).toHaveLength(0);
    expect(placeholders(out, "path")).toHaveLength(0);
  });
});

describe("redactText: emails / UPNs", () => {
  it("replaces an email with <email:hash>", () => {
    const out = redactText("sign-in by user@contoso.com failed");
    expect(out).toBe(`sign-in by ${placeholders(out, "email")[0]} failed`);
  });

  it("handles guest UPNs containing #EXT#", () => {
    const out = redactText("jdoe_gmail.com#EXT#@corp.onmicrosoft.com");
    expect(out).not.toContain("@");
    expect(out).not.toContain("onmicrosoft");
  });

  it("consumes emails before the bare hostname pattern", () => {
    const out = redactText("alice@contoso.com");
    expect(placeholders(out, "email")).toHaveLength(1);
    expect(placeholders(out, "host")).toHaveLength(0);
  });
});

describe("redactText: IPv4", () => {
  it("replaces valid IPv4 addresses", () => {
    for (const ip of ["10.1.2.3", "192.168.0.254", "255.255.255.255", "0.0.0.0"]) {
      const out = redactText(`from ${ip} port 443`);
      expect(out).toBe(`from ${placeholders(out, "ip")[0]} port 443`);
    }
  });

  it("keeps an IP followed by a port", () => {
    const out = redactText("connected to 10.0.0.5:8080");
    expect(placeholders(out, "ip")).toHaveLength(1);
    expect(out).toContain(":8080");
  });

  it("rejects out-of-range octets", () => {
    expect(redactText("256.1.1.1")).toBe("256.1.1.1");
    expect(redactText("999.999.999.999")).toBe("999.999.999.999");
    expect(redactText("1.2.3.456")).toBe("1.2.3.456");
  });

  it("does not match inside longer dotted sequences", () => {
    expect(redactText("1.2.3.4.5")).toBe("1.2.3.4.5");
    expect(redactText("build 10.0.19041.1")).toBe("build 10.0.19041.1");
  });

  it("redacts an IP followed by a sentence-ending dot", () => {
    const out = redactText("Failed login from 10.2.3.4.");
    expect(out).toMatch(/^Failed login from <ip:[0-9a-f]{8}>\.$/);
    expect(out).not.toContain("10.2.3.4");
  });

  it("redacts an IP at the end of a sentence mid-text", () => {
    const out = redactText("Blocked 192.168.1.99. Retrying now.");
    expect(out).toBe(`Blocked ${placeholders(out, "ip")[0]}. Retrying now.`);
    expect(out).not.toContain("192.168.1.99");
  });

  it("still defers IP-prefixed FQDNs to the host pattern as a single placeholder", () => {
    const out = redactText("1.2.3.4.example.com");
    expect(placeholders(out, "host")).toHaveLength(1);
    expect(placeholders(out, "ip")).toHaveLength(0);
    expect(out).toBe(placeholders(out, "host")[0]);
  });
});

describe("redactText: secrets — well-known token prefixes", () => {
  const tokens = [
    "ghp_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789",
    "gho_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789",
    "github_pat_11ABCDEFG0_aBcDeFgHiJkLmNoPqRsTuVwXyZ012345",
    "sk-AbCdEfGhIjKlMnOpQrStUvWx",
    "sk-ant-api03-AbCdEfGhIjKlMnOpQrStUvWx",
    // Assembled from fragments so push-protection / secret scanners don't flag
    // this synthetic Slack-token fixture (no contiguous token literal in source).
    "xox" + "b-1234567890-1234567890123-AbCdEfGhIjKlMnOp",
    "AKIAIOSFODNN7EXAMPLE",
    "glpat-AbCdEfGhIjKlMnOpQrSt",
  ];

  it("replaces each well-known token with <secret:hash>", () => {
    for (const token of tokens) {
      const out = redactText(`leaked ${token} in logs`);
      expect(placeholders(out, "secret"), token).toHaveLength(1);
      expect(out, token).toBe(`leaked ${placeholders(out, "secret")[0]} in logs`);
      expect(out, token).not.toContain(token);
    }
  });

  it("ignores short tails and prefixes embedded inside other words", () => {
    expect(redactText("ghp_short tail")).toBe("ghp_short tail");
    expect(redactText("sk-1234 ref")).toBe("sk-1234 ref");
    expect(redactText("AKIA1234 case")).toBe("AKIA1234 case");
    expect(redactText("task-force 9 assembled")).toBe("task-force 9 assembled");
  });
});

describe("redactText: secrets — credential key=value forms", () => {
  it("replaces the whole key=value pair so the secret never survives", () => {
    const out = redactText("net user svc password=Sup3rS3cret! /add");
    expect(placeholders(out, "secret")).toHaveLength(1);
    expect(out).toBe(`net user svc ${placeholders(out, "secret")[0]} /add`);
    expect(out).not.toContain("Sup3rS3cret");
    expect(out).not.toContain("password");
  });

  it("handles key: value with a colon and spaces", () => {
    const out = redactText("client_secret: 9a8bC7d6e5F4aaaa");
    expect(out).toMatch(/^<secret:[0-9a-f]{8}>$/);
  });

  it("covers the documented key aliases case-insensitively", () => {
    for (const text of [
      "passwd=hunter42x",
      "pwd=hunter42x",
      "PASSWORD=hunter42x",
      "clientsecret=deadbeef99",
      "api_key=abcd1234",
      "api-key=abcd1234",
      "apikey: zzzz9999",
      "AccountKey=abc123def456==",
      "SharedAccessSignature=sv2026sig",
      "sas_token: sigabc123",
      "Token: abcd1234",
      "secret=tooManyCooks1",
    ]) {
      const out = redactText(text);
      expect(placeholders(out, "secret"), text).toHaveLength(1);
      expect(out, text).toMatch(/^<secret:[0-9a-f]{8}>$/);
    }
  });

  it("does not redact non-credential key/value pairs", () => {
    expect(redactText("ResultType: 0")).toBe("ResultType: 0");
    expect(redactText("risk_level: high")).toBe("risk_level: high");
    expect(redactText("logon time: 2026-06-12T10:30:00Z")).toBe(
      "logon time: 2026-06-12T10:30:00Z",
    );
    expect(redactText("failed_logon_count=12345")).toBe("failed_logon_count=12345");
  });

  it("requires a value of at least 4 characters", () => {
    expect(redactText("password=abc")).toBe("password=abc");
  });

  it("keeps the JWT pinned behaviour: bare bearer tokens stay <token:hash>", () => {
    const jwt =
      "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." +
      "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4ifQ." +
      "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    const out = redactText(`Authorization: Bearer ${jwt}`);
    expect(placeholders(out, "token")).toHaveLength(1);
    expect(placeholders(out, "secret")).toHaveLength(0);
  });
});

describe("redactText: secrets — net.exe /user: credential args", () => {
  it("redacts the /user: switch value", () => {
    const out = redactText("net use \\\\fs01\\c$ /user:CORP\\backupadmin pw");
    expect(placeholders(out, "secret")).toHaveLength(1);
    expect(out).not.toContain("backupadmin");
    expect(out).not.toContain("/user:");
  });

  it("leaves /user/ URL-style segments to the path pattern, not the secret tag", () => {
    const out = redactText("endpoint /user/profile ok");
    expect(placeholders(out, "secret")).toHaveLength(0);
  });
});

describe("redactText: secrets — determinism", () => {
  it("maps the same secret to the same placeholder across calls and contexts", () => {
    const a = redactText("password=Hunter2!abc");
    const b = redactText("cmd ran with password=Hunter2!abc today");
    expect(placeholders(a, "secret")).toHaveLength(1);
    expect(placeholders(b, "secret")[0]).toBe(placeholders(a, "secret")[0]);
  });

  it("maps different secrets to different placeholders", () => {
    const out = redactText("password=aaaa1111 password=bbbb2222");
    const tags = placeholders(out, "secret");
    expect(tags).toHaveLength(2);
    expect(tags[0]).not.toBe(tags[1]);
  });
});

describe("redactText: IPv6", () => {
  it("replaces full and compressed forms", () => {
    for (const ip of [
      "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
      "2001:db8::8a2e:370:7334",
      "fe80::1",
      "::1",
      "2001:db8::",
    ]) {
      const out = redactText(`src ${ip} end`);
      expect(placeholders(out, "ip"), ip).toHaveLength(1);
      expect(out, ip).not.toContain(ip);
    }
  });

  it("does not match times or ISO 8601 timestamps", () => {
    expect(redactText("10:30:00")).toBe("10:30:00");
    expect(redactText("2026-06-12T10:30:00Z")).toBe("2026-06-12T10:30:00Z");
    expect(redactText("2026-06-12T10:30:00.1234567Z")).toBe(
      "2026-06-12T10:30:00.1234567Z",
    );
  });
});

describe("redactText: GUIDs", () => {
  it("replaces a GUID with <guid:hash>", () => {
    const out = redactText("CorrelationId d3adbeef-1234-4abc-9def-001122334455");
    expect(out).toBe(`CorrelationId ${placeholders(out, "guid")[0]}`);
  });

  it("ignores plain hex that is not GUID-shaped", () => {
    expect(redactText("d3adbeef12344abc9def001122334455")).toBe(
      "d3adbeef12344abc9def001122334455",
    );
  });
});

describe("redactText: Azure resource IDs", () => {
  const resourceId =
    "/subscriptions/d3adbeef-1234-4abc-9def-001122334455" +
    "/resourceGroups/rg-prod/providers/Microsoft.OperationalInsights/workspaces/law-sec";

  it("replaces the whole resource ID as one placeholder (before GUID splits it)", () => {
    const out = redactText(`caller touched ${resourceId} today`);
    expect(out).toBe(`caller touched ${placeholders(out, "resourceid")[0]} today`);
    expect(placeholders(out, "guid")).toHaveLength(0);
    expect(placeholders(out, "path")).toHaveLength(0);
  });
});

describe("redactText: file paths", () => {
  it("replaces Windows drive-letter paths", () => {
    const out = redactText("ran C:\\Windows\\System32\\cmd.exe /c whoami");
    expect(placeholders(out, "path")).toHaveLength(1);
    expect(out).not.toContain("cmd.exe");
  });

  it("replaces UNC paths", () => {
    const out = redactText("copied \\\\fileserver01\\share\\secret.docx out");
    expect(placeholders(out, "path")).toHaveLength(1);
    expect(out).not.toContain("fileserver01");
  });

  it("replaces Unix absolute paths with 2+ segments", () => {
    const out = redactText("tail /var/log/auth.log shows failures");
    expect(out).toBe(`tail ${placeholders(out, "path")[0]} shows failures`);
  });

  it('does not eat short API segments like "/v1"', () => {
    expect(redactText("POST /v1 endpoint")).toBe("POST /v1 endpoint");
  });

  it("does not eat KQL comments or date-like slashes", () => {
    expect(redactText("// this is a comment")).toBe("// this is a comment");
    expect(redactText("2026/06/12")).toBe("2026/06/12");
  });
});

describe("redactText: hostnames / FQDNs", () => {
  it("replaces dotted hostnames with an alphabetic TLD", () => {
    const out = redactText("beacon to evil-c2.badguys.io observed");
    expect(out).toBe(`beacon to ${placeholders(out, "host")[0]} observed`);
  });

  it("handles DNS names with a trailing dot", () => {
    const out = redactText("query for c2.example.net. NXDOMAIN");
    expect(placeholders(out, "host")).toHaveLength(1);
    expect(out).not.toContain("example");
  });

  it("does not match KQL table or function names (no dot)", () => {
    const kql =
      "SigninLogs | where TimeGenerated >= ago(7d) | summarize count() by bin(TimeGenerated, 1h)";
    expect(redactText(kql)).toBe(kql);
  });

  it("does not match plain numbers, booleans, decimals, or timestamps", () => {
    for (const s of ["42", "3.14", "true", "false", "2026-06-12T10:30:00.123Z"]) {
      expect(redactText(s)).toBe(s);
    }
  });
});

describe("redactText: determinism and distinctness", () => {
  it("maps the same input to the same placeholder across calls", () => {
    const a = redactText("user@contoso.com");
    const b = redactText("login by user@contoso.com from 10.1.2.3");
    expect(placeholders(b, "email")[0]).toBe(a);
  });

  it("maps different inputs to different placeholders", () => {
    const out = redactText("alice@contoso.com mailed bob@contoso.com");
    const tags = placeholders(out, "email");
    expect(tags).toHaveLength(2);
    expect(tags[0]).not.toBe(tags[1]);
  });

  it("preserves distinctness so aggregate analysis still works", () => {
    const out = redactText("10.0.0.1 10.0.0.2 10.0.0.1");
    const tags = placeholders(out, "ip");
    expect(tags).toHaveLength(3);
    expect(tags[0]).toBe(tags[2]);
    expect(tags[0]).not.toBe(tags[1]);
  });
});

describe("redactValue", () => {
  it("passes numbers, booleans, null and undefined through untouched", () => {
    expect(redactValue(42)).toBe(42);
    expect(redactValue(3.14)).toBe(3.14);
    expect(redactValue(true)).toBe(true);
    expect(redactValue(false)).toBe(false);
    expect(redactValue(null)).toBeNull();
    expect(redactValue(undefined)).toBeUndefined();
  });

  it("redacts strings", () => {
    const out = redactValue("admin@contoso.com") as string;
    expect(placeholders(out, "email")).toHaveLength(1);
  });

  it("deep-redacts nested objects and arrays without mutating the input", () => {
    const input = {
      user: "alice@contoso.com",
      attempts: 3,
      hosts: ["dc01.corp.contoso.com", "10.0.0.5"],
      nested: { path: "/etc/shadow/backup", ok: true, none: null },
    };
    const snapshot = structuredClone(input);

    const out = redactValue(input) as typeof input;

    expect(input).toEqual(snapshot); // not mutated
    expect(out).not.toBe(input);
    expect(out.hosts).not.toBe(input.hosts);
    expect(out.nested).not.toBe(input.nested);
    expect(placeholders(out.user, "email")).toHaveLength(1);
    expect(out.attempts).toBe(3);
    expect(placeholders(out.hosts[0] as string, "host")).toHaveLength(1);
    expect(placeholders(out.hosts[1] as string, "ip")).toHaveLength(1);
    expect(placeholders(out.nested.path, "path")).toHaveLength(1);
    expect(out.nested.ok).toBe(true);
    expect(out.nested.none).toBeNull();
  });
});

describe("DEFAULT_SENSITIVE_COLUMNS", () => {
  it("contains the documented identity / network / file columns", () => {
    for (const col of ["UserPrincipalName", "IPAddress", "Caller", "FilePath", "Computer"]) {
      expect(DEFAULT_SENSITIVE_COLUMNS).toContain(col);
    }
  });

  it("contains the expanded identity / display-name columns", () => {
    for (const col of [
      "Identity",
      "UserDisplayName",
      "AccountDisplayName",
      "TargetUserDisplayName",
      "DisplayName",
      "RequesterUpn",
      "UserName",
    ]) {
      expect(DEFAULT_SENSITIVE_COLUMNS).toContain(col);
    }
  });

  it("does not force-mask command-line columns wholesale", () => {
    expect(DEFAULT_SENSITIVE_COLUMNS).not.toContain("CommandLine");
    expect(DEFAULT_SENSITIVE_COLUMNS).not.toContain("ProcessCommandLine");
  });
});

function signinLogsResult(): LogQueryResult {
  return {
    status: "Succeeded",
    durationMs: 412,
    tables: [
      {
        name: "PrimaryResult",
        columns: [
          { name: "TimeGenerated", type: "datetime" },
          { name: "UserPrincipalName", type: "string" },
          { name: "IPAddress", type: "string" },
          { name: "AppDisplayName", type: "string" },
          { name: "ResultType", type: "string" },
          { name: "Details", type: "string" },
        ],
        rows: [
          [
            "2026-06-12T10:30:00.123Z",
            "alice@contoso.com",
            "10.0.0.5",
            "Azure Portal",
            "50126",
            "failed login from 10.0.0.5",
          ],
          [
            "2026-06-12T10:31:00.456Z",
            "bob@contoso.com",
            "10.0.0.6",
            "Azure Portal",
            "0",
            null,
          ],
          [
            "2026-06-12T10:32:00.789Z",
            "alice@contoso.com",
            null,
            "Office 365",
            "0",
            "ok",
          ],
        ],
      },
    ],
    statistics: { query: { executionTime: 0.41, datasetStatistics: [{ tableRowCount: 3 }] } },
    dataSources: { tables: ["SigninLogs"] },
  };
}

describe("redactQueryResult", () => {
  it("masks sensitive columns as <colname:hash> and pattern-redacts the rest", () => {
    const out = redactQueryResult(signinLogsResult());
    const rows = out.tables[0]!.rows;

    // Sensitive columns are force-masked with the column-name tag.
    expect(rows[0]![1]).toMatch(/^<userprincipalname:[0-9a-f]{8}>$/);
    expect(rows[0]![2]).toMatch(/^<ipaddress:[0-9a-f]{8}>$/);

    // Timestamps and benign values are untouched.
    expect(rows[0]![0]).toBe("2026-06-12T10:30:00.123Z");
    expect(rows[0]![3]).toBe("Azure Portal");
    expect(rows[0]![4]).toBe("50126");

    // Non-sensitive columns still get pattern redaction.
    expect(placeholders(rows[0]![5] as string, "ip")).toHaveLength(1);
    expect(rows[0]![5]).not.toContain("10.0.0.5");
  });

  it("is deterministic and distinctness-preserving across rows", () => {
    const out = redactQueryResult(signinLogsResult());
    const rows = out.tables[0]!.rows;
    expect(rows[0]![1]).toBe(rows[2]![1]); // same UPN -> same placeholder
    expect(rows[0]![1]).not.toBe(rows[1]![1]); // different UPN -> different placeholder
  });

  it("leaves null cells in sensitive columns as null", () => {
    const out = redactQueryResult(signinLogsResult());
    expect(out.tables[0]!.rows[2]![2]).toBeNull();
  });

  it("matches sensitive column names case-insensitively", () => {
    const result: LogQueryResult = {
      status: "Succeeded",
      durationMs: 1,
      tables: [
        {
          name: "PrimaryResult",
          columns: [{ name: "IPADDRESS", type: "string" }],
          rows: [["10.0.0.5"]],
        },
      ],
    };
    const out = redactQueryResult(result);
    expect(out.tables[0]!.rows[0]![0]).toMatch(/^<ipaddress:[0-9a-f]{8}>$/);
  });

  it("force-masks sensitive columns even when the value matches no pattern", () => {
    const result: LogQueryResult = {
      status: "Succeeded",
      durationMs: 1,
      tables: [
        {
          name: "PrimaryResult",
          columns: [{ name: "Caller", type: "string" }],
          rows: [["LocalSystem"]],
        },
      ],
    };
    const out = redactQueryResult(result);
    expect(out.tables[0]!.rows[0]![0]).toMatch(/^<caller:[0-9a-f]{8}>$/);
  });

  it("honours caller-supplied extra sensitive columns", () => {
    const result: LogQueryResult = {
      status: "Succeeded",
      durationMs: 1,
      tables: [
        {
          name: "PrimaryResult",
          columns: [{ name: "CustomSecret", type: "string" }],
          rows: [["nothing-pattern-shaped"]],
        },
      ],
    };
    const out = redactQueryResult(result, { sensitiveColumns: ["customsecret"] });
    expect(out.tables[0]!.rows[0]![0]).toMatch(/^<customsecret:[0-9a-f]{8}>$/);
  });

  it("passes statistics and dataSources through unredacted", () => {
    const input = signinLogsResult();
    const out = redactQueryResult(input);
    expect(out.statistics).toEqual(input.statistics);
    expect(out.dataSources).toEqual(input.dataSources);
  });

  it("never mutates the input result", () => {
    const input = signinLogsResult();
    const snapshot = structuredClone(input);
    const out = redactQueryResult(input);

    expect(input).toEqual(snapshot);
    expect(out).not.toBe(input);
    expect(out.tables).not.toBe(input.tables);
    expect(out.tables[0]!.rows).not.toBe(input.tables[0]!.rows);
    expect(out.tables[0]!.rows[0]).not.toBe(input.tables[0]!.rows[0]);
  });

  it("preserves status, durationMs and column metadata", () => {
    const out = redactQueryResult(signinLogsResult());
    expect(out.status).toBe("Succeeded");
    expect(out.durationMs).toBe(412);
    expect(out.tables[0]!.columns).toEqual(signinLogsResult().tables[0]!.columns);
  });

  it("force-masks the expanded display-name columns but only exact names", () => {
    const result: LogQueryResult = {
      status: "Succeeded",
      durationMs: 1,
      tables: [
        {
          name: "PrimaryResult",
          columns: [
            { name: "Identity", type: "string" },
            { name: "AccountDisplayName", type: "string" },
            { name: "AppDisplayName", type: "string" },
          ],
          rows: [["Jane Doe", "JANE DOE", "Azure Portal"]],
        },
      ],
    };
    const out = redactQueryResult(result);
    const row = out.tables[0]!.rows[0]!;
    expect(row[0]).toMatch(/^<identity:[0-9a-f]{8}>$/);
    expect(row[1]).toMatch(/^<accountdisplayname:[0-9a-f]{8}>$/);
    // AppDisplayName is not in the list (exact-name matching, no suffix match).
    expect(row[2]).toBe("Azure Portal");
  });

  it("does not force-mask ProcessCommandLine but strips secrets inside it", () => {
    const result: LogQueryResult = {
      status: "Succeeded",
      durationMs: 1,
      tables: [
        {
          name: "PrimaryResult",
          columns: [{ name: "ProcessCommandLine", type: "string" }],
          rows: [["net user svc password=Sup3rS3cret! /add"]],
        },
      ],
    };
    const out = redactQueryResult(result);
    const cell = out.tables[0]!.rows[0]![0] as string;
    expect(cell).toContain("net user svc");
    expect(cell).toContain("/add");
    expect(cell).not.toContain("Sup3rS3cret");
    expect(placeholders(cell, "secret")).toHaveLength(1);
  });

  it("pattern-redacts cells beyond the declared columns instead of crashing", () => {
    const result: LogQueryResult = {
      status: "Succeeded",
      durationMs: 1,
      tables: [
        {
          name: "PrimaryResult",
          columns: [{ name: "A", type: "string" }],
          rows: [["plain", "stray 10.0.0.9 cell"]],
        },
      ],
    };
    const out = redactQueryResult(result);
    expect(out.tables[0]!.rows[0]![0]).toBe("plain");
    expect(placeholders(out.tables[0]!.rows[0]![1] as string, "ip")).toHaveLength(1);
  });
});
