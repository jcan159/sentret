import { describe, it, expect } from "vitest";
import { mkdtemp, readFile, rm, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";

import {
  buildSampleReport,
  renderMarkdownReport,
  saveReport,
  validateReport,
} from "./report_renderer.js";
import type { AnalyserReport } from "../types.js";

const SCHEMA_URL = new URL(
  "../schemas/analyser_report.schema.json",
  import.meta.url,
);

const EXPECTED_HEADINGS = [
  "## 1. Executive Summary",
  "## 2. Detection Intent Interpretation",
  "## 3. Rule Overview",
  "## 4. Static KQL Review",
  "## 5. Live Workspace Validation",
  "## 6. Performance Review",
  "## 7. Detection Quality Assessment",
  "## 8. Recommended KQL",
  "## 9. Explanation of Changes",
  "## 10. Sentinel Rule Configuration",
  "## 11. Validation Queries",
  "## 12. Limitations and Assumptions",
  "## 13. Final Recommendation",
];

describe("buildSampleReport", () => {
  it("returns a fresh object on each call", () => {
    const a = buildSampleReport();
    const b = buildSampleReport();
    expect(a).toEqual(b);
    expect(a).not.toBe(b);
    a.summary.top_issues.push("mutated");
    expect(buildSampleReport().summary.top_issues).not.toContain("mutated");
  });
});

describe("validateReport", () => {
  it("accepts the sample report", () => {
    const result = validateReport(buildSampleReport());
    expect(result.errors).toEqual([]);
    expect(result.valid).toBe(true);
  });

  it("rejects non-object values", () => {
    for (const value of [null, undefined, "report", 42, [1, 2]]) {
      const result = validateReport(value);
      expect(result.valid).toBe(false);
      expect(result.errors.length).toBeGreaterThan(0);
    }
  });

  it("collects multiple specific errors from a corrupted report", () => {
    const bad = structuredClone(buildSampleReport()) as unknown as Record<
      string,
      unknown
    >;
    bad["verdict"] = "Ship it"; // invalid enum
    delete bad["summary"]; // missing nested section
    bad["overall_score"] = "ninety"; // wrong type
    (bad["sentinel_rule"] as Record<string, unknown>)["trigger_operator"] =
      "Above"; // invalid nested enum
    (bad["static_review"] as Record<string, unknown>)["tables"] = "SigninLogs"; // not an array
    (bad["performance"] as Record<string, unknown>)["rating"] = "Blazing"; // invalid enum

    const result = validateReport(bad);
    expect(result.valid).toBe(false);
    expect(result.errors.length).toBeGreaterThanOrEqual(6);
    expect(result.errors.some((e) => e.includes("verdict"))).toBe(true);
    expect(result.errors.some((e) => e.includes("summary"))).toBe(true);
    expect(result.errors.some((e) => e.includes("overall_score"))).toBe(true);
    expect(
      result.errors.some((e) => e.includes("sentinel_rule.trigger_operator")),
    ).toBe(true);
    expect(
      result.errors.some((e) => e.includes("static_review.tables")),
    ).toBe(true);
    expect(result.errors.some((e) => e.includes("performance.rating"))).toBe(
      true,
    );
  });

  it("flags invalid mode, severity and risk enums", () => {
    const bad = structuredClone(buildSampleReport()) as unknown as Record<
      string,
      unknown
    >;
    bad["mode"] = "audit";
    (bad["sentinel_rule"] as Record<string, unknown>)["severity"] = "Critical";
    (bad["detection_quality"] as Record<string, unknown>)[
      "false_positive_risk"
    ] = "Extreme";

    const result = validateReport(bad);
    expect(result.valid).toBe(false);
    expect(result.errors.some((e) => e.includes("mode"))).toBe(true);
    expect(
      result.errors.some((e) => e.includes("sentinel_rule.severity")),
    ).toBe(true);
    expect(
      result.errors.some((e) =>
        e.includes("detection_quality.false_positive_risk"),
      ),
    ).toBe(true);
  });

  it("flags nullable fields that hold the wrong type", () => {
    const bad = structuredClone(buildSampleReport()) as unknown as Record<
      string,
      unknown
    >;
    (bad["kql"] as Record<string, unknown>)["original_query"] = 5;
    (bad["sentinel_rule"] as Record<string, unknown>)["suppression_duration"] =
      false;

    const result = validateReport(bad);
    expect(result.valid).toBe(false);
    expect(result.errors.some((e) => e.includes("kql.original_query"))).toBe(
      true,
    );
    expect(
      result.errors.some((e) =>
        e.includes("sentinel_rule.suppression_duration"),
      ),
    ).toBe(true);
  });

  it("accepts null in nullable fields", () => {
    const report = buildSampleReport();
    report.kql.original_query = null;
    report.sentinel_rule.suppression_duration = null;
    expect(validateReport(report).valid).toBe(true);
  });
});

describe("validateReport element shapes", () => {
  type Mutable = Record<string, unknown>;

  /**
   * Each entry corrupts one array ELEMENT of an otherwise-valid report. These
   * are exactly the shapes that previously passed shallow validation but made
   * renderMarkdownReport throw (or rendered garbage). `path` is the dotted,
   * indexed path the validation error must carry.
   */
  const ELEMENT_CORRUPTIONS: {
    name: string;
    path: string;
    corrupt: (report: AnalyserReport) => void;
  }[] = [
    {
      name: "alternative_queries element that is null",
      path: "kql.alternative_queries[0]",
      corrupt: (r) => {
        (r.kql as unknown as Mutable)["alternative_queries"] = [null];
      },
    },
    {
      name: "alternative_queries element with non-string name",
      path: "kql.alternative_queries[0].name",
      corrupt: (r) => {
        (r.kql.alternative_queries[0] as unknown as Mutable)["name"] = 7;
      },
    },
    {
      name: "alternative_queries element missing query",
      path: "kql.alternative_queries[0].query",
      corrupt: (r) => {
        delete (r.kql.alternative_queries[0] as unknown as Mutable)["query"];
      },
    },
    {
      name: "queries_run element that is null",
      path: "workspace_validation.queries_run[0]",
      corrupt: (r) => {
        (r.workspace_validation as unknown as Mutable)["queries_run"] = [null];
      },
    },
    {
      name: "queries_run element with invalid status",
      path: "workspace_validation.queries_run[0].status",
      corrupt: (r) => {
        (r.workspace_validation.queries_run[0] as unknown as Mutable)[
          "status"
        ] = "Running";
      },
    },
    {
      name: "queries_run element with string row_count",
      path: "workspace_validation.queries_run[0].row_count",
      corrupt: (r) => {
        (r.workspace_validation.queries_run[0] as unknown as Mutable)[
          "row_count"
        ] = "7";
      },
    },
    {
      name: "queries_run element with numeric error",
      path: "workspace_validation.queries_run[0].error",
      corrupt: (r) => {
        (r.workspace_validation.queries_run[0] as unknown as Mutable)[
          "error"
        ] = 42;
      },
    },
    {
      name: "data_availability element with string exists",
      path: "workspace_validation.data_availability[0].exists",
      corrupt: (r) => {
        (r.workspace_validation.data_availability[0] as unknown as Mutable)[
          "exists"
        ] = "yes";
      },
    },
    {
      name: "data_availability element with numeric min_timegenerated",
      path: "workspace_validation.data_availability[0].min_timegenerated",
      corrupt: (r) => {
        (r.workspace_validation.data_availability[0] as unknown as Mutable)[
          "min_timegenerated"
        ] = 1718150000000;
      },
    },
    {
      name: "field_population element missing table",
      path: "workspace_validation.field_population[0].table",
      corrupt: (r) => {
        delete (r.workspace_validation.field_population[0] as unknown as Mutable)[
          "table"
        ];
      },
    },
    {
      name: "field_population element with string population_percent",
      path: "workspace_validation.field_population[0].population_percent",
      corrupt: (r) => {
        (r.workspace_validation.field_population[0] as unknown as Mutable)[
          "population_percent"
        ] = "99.9";
      },
    },
    {
      name: "entity mapping missing fieldMappings (the reported crash)",
      path: "sentinel_rule.entity_mappings[0].fieldMappings",
      corrupt: (r) => {
        (r.sentinel_rule as unknown as Mutable)["entity_mappings"] = [
          { entityType: "Account" },
        ];
      },
    },
    {
      name: "entity mapping with non-string entityType",
      path: "sentinel_rule.entity_mappings[0].entityType",
      corrupt: (r) => {
        (r.sentinel_rule.entity_mappings[0] as unknown as Mutable)[
          "entityType"
        ] = 1;
      },
    },
    {
      name: "entity mapping with non-array fieldMappings",
      path: "sentinel_rule.entity_mappings[0].fieldMappings",
      corrupt: (r) => {
        (r.sentinel_rule.entity_mappings[0] as unknown as Mutable)[
          "fieldMappings"
        ] = "FullName";
      },
    },
    {
      name: "fieldMappings element that is null",
      path: "sentinel_rule.entity_mappings[0].fieldMappings[0]",
      corrupt: (r) => {
        (r.sentinel_rule.entity_mappings[0] as unknown as Mutable)[
          "fieldMappings"
        ] = [null];
      },
    },
    {
      name: "fieldMappings element with non-string columnName",
      path: "sentinel_rule.entity_mappings[0].fieldMappings[0].columnName",
      corrupt: (r) => {
        (r.sentinel_rule.entity_mappings[0]!.fieldMappings[0] as unknown as Mutable)[
          "columnName"
        ] = 3;
      },
    },
    {
      name: "non-string element in summary.top_strengths",
      path: "summary.top_strengths[1]",
      corrupt: (r) => {
        (r.summary as unknown as Mutable)["top_strengths"] = ["fine", 5];
      },
    },
    {
      name: "null element in summary.top_issues",
      path: "summary.top_issues[0]",
      corrupt: (r) => {
        (r.summary as unknown as Mutable)["top_issues"] = [null];
      },
    },
    {
      name: "object element in summary.required_fixes",
      path: "summary.required_fixes[0]",
      corrupt: (r) => {
        (r.summary as unknown as Mutable)["required_fixes"] = [{}];
      },
    },
    {
      name: "null element in static_review.tables",
      path: "static_review.tables[0]",
      corrupt: (r) => {
        (r.static_review as unknown as Mutable)["tables"] = [null];
      },
    },
    {
      name: "numeric element in static_review.performance_risks",
      path: "static_review.performance_risks[0]",
      corrupt: (r) => {
        (r.static_review as unknown as Mutable)["performance_risks"] = [42];
      },
    },
    {
      name: "boolean element in detection_quality.known_blind_spots",
      path: "detection_quality.known_blind_spots[0]",
      corrupt: (r) => {
        (r.detection_quality as unknown as Mutable)["known_blind_spots"] = [
          false,
        ];
      },
    },
    {
      name: "numeric element in sentinel_rule.tactics",
      path: "sentinel_rule.tactics[0]",
      corrupt: (r) => {
        (r.sentinel_rule as unknown as Mutable)["tactics"] = [0];
      },
    },
    {
      name: "nested-array element in sentinel_rule.techniques",
      path: "sentinel_rule.techniques[0]",
      corrupt: (r) => {
        (r.sentinel_rule as unknown as Mutable)["techniques"] = [["T1110"]];
      },
    },
    {
      name: "null element in limitations",
      path: "limitations[0]",
      corrupt: (r) => {
        (r as unknown as Mutable)["limitations"] = [null];
      },
    },
    {
      name: "numeric element in assumptions",
      path: "assumptions[0]",
      corrupt: (r) => {
        (r as unknown as Mutable)["assumptions"] = [7];
      },
    },
  ];

  it.each(ELEMENT_CORRUPTIONS)(
    "rejects $name with a dotted-path error",
    ({ path: errorPath, corrupt }) => {
      const report = buildSampleReport();
      corrupt(report);
      const result = validateReport(report);
      expect(result.valid).toBe(false);
      expect(
        result.errors.some((e) => e.startsWith(`${errorPath}:`)),
        `expected an error starting with "${errorPath}:", got:\n${result.errors.join("\n")}`,
      ).toBe(true);
    },
  );

  it("guarantees renderMarkdownReport does not throw on anything validateReport accepts", () => {
    // Defensive invariant the integrator relies on: every corrupted variant is
    // either rejected by validateReport, or renders without throwing.
    for (const { corrupt } of ELEMENT_CORRUPTIONS) {
      const report = buildSampleReport();
      corrupt(report);
      const result = validateReport(report);
      if (result.valid) {
        expect(() => renderMarkdownReport(report)).not.toThrow();
      } else {
        expect(result.errors.length).toBeGreaterThan(0);
      }
    }
  });

  it("sanity: buildSampleReport() still validates and renders", () => {
    const report = buildSampleReport();
    const result = validateReport(report);
    expect(result.errors).toEqual([]);
    expect(result.valid).toBe(true);
    expect(() => renderMarkdownReport(report)).not.toThrow();
    expect(renderMarkdownReport(report)).toContain(
      "# KQL Detection Rule Analysis",
    );
  });
});

describe("renderMarkdownReport", () => {
  it("renders the title and all 13 numbered section headings", () => {
    const md = renderMarkdownReport(buildSampleReport());
    expect(md).toContain("# KQL Detection Rule Analysis");
    for (const heading of EXPECTED_HEADINGS) {
      expect(md).toContain(heading);
    }
  });

  it("renders the recommended query in a kql fence", () => {
    const report = buildSampleReport();
    const md = renderMarkdownReport(report);
    expect(md).toContain("```kql\n" + report.kql.recommended_query + "\n```");
  });

  it("renders the original query and alternative queries in kql fences", () => {
    const report = buildSampleReport();
    const md = renderMarkdownReport(report);
    expect(report.kql.original_query).not.toBeNull();
    expect(md).toContain("```kql\n" + report.kql.original_query + "\n```");
    const alt = report.kql.alternative_queries[0];
    expect(alt).toBeDefined();
    expect(md).toContain("```kql\n" + alt!.query + "\n```");
  });

  it("renders the static-only message when execution was not allowed", () => {
    const report = buildSampleReport();
    report.workspace_validation.execution_allowed = false;
    const md = renderMarkdownReport(report);
    expect(md).toContain(
      "Query execution was not allowed; static analysis only.",
    );
  });

  it("renders workspace validation detail when execution was allowed", () => {
    const report = buildSampleReport();
    expect(report.workspace_validation.execution_allowed).toBe(true);
    const md = renderMarkdownReport(report);
    expect(md).not.toContain(
      "Query execution was not allowed; static analysis only.",
    );
    const firstRun = report.workspace_validation.queries_run[0];
    const firstAvail = report.workspace_validation.data_availability[0];
    const firstField = report.workspace_validation.field_population[0];
    expect(firstRun).toBeDefined();
    expect(firstAvail).toBeDefined();
    expect(firstField).toBeDefined();
    expect(md).toContain(firstRun!.purpose);
    expect(md).toContain(firstAvail!.table);
    expect(md).toContain(firstField!.field);
  });

  it('renders "None." for empty arrays instead of dropping content', () => {
    const report = buildSampleReport();
    report.summary.top_strengths = [];
    report.static_review.syntax_issues = [];
    report.workspace_validation.queries_run = [];
    report.workspace_validation.data_availability = [];
    report.workspace_validation.field_population = [];
    report.performance.bottlenecks = [];
    report.detection_quality.known_blind_spots = [];
    report.sentinel_rule.entity_mappings = [];
    report.limitations = [];
    const md = renderMarkdownReport(report);
    expect(md).toContain("None.");
    // Every numbered heading must still be present.
    for (const heading of EXPECTED_HEADINGS) {
      expect(md).toContain(heading);
    }
  });

  it("handles a create-new report with no original query", () => {
    const report = buildSampleReport();
    report.mode = "create_new_detection";
    report.kql.original_query = null;
    const md = renderMarkdownReport(report);
    expect(md).toContain("No original query was provided");
  });

  it("is deterministic", () => {
    const report = buildSampleReport();
    expect(renderMarkdownReport(report)).toBe(renderMarkdownReport(report));
  });
});

describe("saveReport", () => {
  async function withTempDir(
    fn: (dir: string) => Promise<void>,
  ): Promise<void> {
    const dir = await mkdtemp(path.join(tmpdir(), "sentret-report-"));
    try {
      await fn(dir);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  }

  it("round-trips JSON and writes non-empty markdown by default", async () => {
    await withTempDir(async (dir) => {
      const report = buildSampleReport();
      const written = await saveReport(report, { outputDir: dir });
      expect(written).toHaveLength(2);
      const jsonPath = written.find((p) => p.endsWith(".json"));
      const mdPath = written.find((p) => p.endsWith(".md"));
      expect(jsonPath).toBeDefined();
      expect(mdPath).toBeDefined();

      const parsed = JSON.parse(
        await readFile(jsonPath!, "utf8"),
      ) as AnalyserReport;
      expect(parsed).toEqual(report);

      const md = await readFile(mdPath!, "utf8");
      expect(md.length).toBeGreaterThan(0);
      expect(md).toContain("# KQL Detection Rule Analysis");
    });
  });

  it("sanitises the analysis_id for filesystem use", async () => {
    await withTempDir(async (dir) => {
      const report = buildSampleReport();
      report.analysis_id = "a/b\\c:d e*?<>|f";
      const written = await saveReport(report, {
        outputDir: dir,
        formats: ["json"],
      });
      expect(written).toHaveLength(1);
      // "a/b\c:d e*?<>|f" — each of / \ : space * ? < > | becomes "_"
      expect(path.basename(written[0]!)).toBe("analysis_a_b_c_d_e_____f.json");
      await expect(stat(written[0]!)).resolves.toBeTruthy();
    });
  });

  it("keeps allowed filename characters intact", async () => {
    await withTempDir(async (dir) => {
      const report = buildSampleReport();
      report.analysis_id = "RUN-2026.06.12_001";
      const written = await saveReport(report, {
        outputDir: dir,
        formats: ["md"],
      });
      expect(path.basename(written[0]!)).toBe(
        "analysis_RUN-2026.06.12_001.md",
      );
    });
  });

  it("respects an explicit single-format request", async () => {
    await withTempDir(async (dir) => {
      const written = await saveReport(buildSampleReport(), {
        outputDir: dir,
        formats: ["md"],
      });
      expect(written).toHaveLength(1);
      expect(written[0]!.endsWith(".md")).toBe(true);
    });
  });

  it("creates nested output directories recursively", async () => {
    await withTempDir(async (dir) => {
      const nested = path.join(dir, "deeply", "nested", "out");
      const written = await saveReport(buildSampleReport(), {
        outputDir: nested,
      });
      expect(written).toHaveLength(2);
      for (const p of written) {
        expect(p.startsWith(nested)).toBe(true);
        await expect(stat(p)).resolves.toBeTruthy();
      }
    });
  });
});

describe("analyser_report.schema.json", () => {
  async function loadSchema(): Promise<Record<string, unknown>> {
    return JSON.parse(await readFile(SCHEMA_URL, "utf8")) as Record<
      string,
      unknown
    >;
  }

  it("parses as JSON and describes an object", async () => {
    const schema = await loadSchema();
    expect(schema["type"]).toBe("object");
    expect(typeof schema["description"]).toBe("string");
    expect(schema["properties"]).toBeTypeOf("object");
  });

  it("requires exactly the AnalyserReport top-level fields", async () => {
    const schema = await loadSchema();
    const required = (schema["required"] as string[]).slice().sort();
    const sampleKeys = Object.keys(buildSampleReport()).sort();
    expect(required).toEqual(sampleKeys);
  });

  it("declares a property for every required field", async () => {
    const schema = await loadSchema();
    const properties = Object.keys(
      schema["properties"] as Record<string, unknown>,
    ).sort();
    const sampleKeys = Object.keys(buildSampleReport()).sort();
    expect(properties).toEqual(sampleKeys);
  });

  it("uses exact enum values from the type contract", async () => {
    const schema = await loadSchema();
    const props = schema["properties"] as Record<
      string,
      Record<string, unknown>
    >;
    expect(props["verdict"]!["enum"]).toEqual([
      "Deploy as-is",
      "Deploy after changes",
      "Test only",
      "Do not deploy",
    ]);
    expect(props["mode"]!["enum"]).toEqual([
      "analyse_existing_rule",
      "create_new_detection",
    ]);
    expect(props["rating"]!["enum"]).toEqual([
      "Excellent",
      "Good",
      "Needs Tuning",
      "Weak",
      "Not Deployable",
    ]);
    const perf = props["performance"]!["properties"] as Record<
      string,
      Record<string, unknown>
    >;
    expect(perf["rating"]!["enum"]).toEqual([
      "Excellent",
      "Good",
      "Moderate",
      "Poor",
      "Failed",
    ]);
    const rule = props["sentinel_rule"]!["properties"] as Record<
      string,
      Record<string, unknown>
    >;
    expect(rule["severity"]!["enum"]).toEqual([
      "Informational",
      "Low",
      "Medium",
      "High",
    ]);
    expect(rule["trigger_operator"]!["enum"]).toEqual([
      "GreaterThan",
      "LessThan",
      "Equal",
      "NotEqual",
    ]);
  });

  it("marks nullable fields as string-or-null and omits numeric range keywords", async () => {
    const raw = await readFile(SCHEMA_URL, "utf8");
    expect(raw).not.toContain('"minimum"');
    expect(raw).not.toContain('"maximum"');
    expect(raw).not.toContain('"$ref"');
    expect(raw).not.toContain('"$defs"');

    const schema = JSON.parse(raw) as Record<string, unknown>;
    const props = schema["properties"] as Record<
      string,
      Record<string, unknown>
    >;
    const kqlProps = props["kql"]!["properties"] as Record<
      string,
      Record<string, unknown>
    >;
    expect(kqlProps["original_query"]!["type"]).toEqual(["string", "null"]);
    const ruleProps = props["sentinel_rule"]!["properties"] as Record<
      string,
      Record<string, unknown>
    >;
    expect(ruleProps["suppression_duration"]!["type"]).toEqual([
      "string",
      "null",
    ]);
  });
});
