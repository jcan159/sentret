import { describe, expect, it } from "vitest";

import {
  MITRE_TACTICS,
  MITRE_TECHNIQUES,
  isValidTacticId,
  isValidTechniqueId,
  lookupMitre,
  toSentinelTactic,
} from "./mitre.js";

/** Expected (id, display name, Sentinel enum spelling) for every Enterprise tactic. */
const EXPECTED_TACTICS: ReadonlyArray<[string, string, string]> = [
  ["TA0043", "Reconnaissance", "Reconnaissance"],
  ["TA0042", "Resource Development", "ResourceDevelopment"],
  ["TA0001", "Initial Access", "InitialAccess"],
  ["TA0002", "Execution", "Execution"],
  ["TA0003", "Persistence", "Persistence"],
  ["TA0004", "Privilege Escalation", "PrivilegeEscalation"],
  ["TA0005", "Defense Evasion", "DefenseEvasion"],
  ["TA0006", "Credential Access", "CredentialAccess"],
  ["TA0007", "Discovery", "Discovery"],
  ["TA0008", "Lateral Movement", "LateralMovement"],
  ["TA0009", "Collection", "Collection"],
  ["TA0011", "Command and Control", "CommandAndControl"],
  ["TA0010", "Exfiltration", "Exfiltration"],
  ["TA0040", "Impact", "Impact"],
];

describe("MITRE_TACTICS", () => {
  it("contains exactly the 14 Enterprise tactics with correct ids, names and Sentinel spellings", () => {
    expect(MITRE_TACTICS).toHaveLength(14);
    for (const [id, name, sentinelName] of EXPECTED_TACTICS) {
      const tactic = MITRE_TACTICS.find((t) => t.id === id);
      expect(tactic, `tactic ${id} missing`).toBeDefined();
      expect(tactic?.name).toBe(name);
      expect(tactic?.sentinelName).toBe(sentinelName);
    }
  });

  it("has unique, format-valid ids and space-free Sentinel names", () => {
    const ids = new Set(MITRE_TACTICS.map((t) => t.id));
    expect(ids.size).toBe(14);
    for (const tactic of MITRE_TACTICS) {
      expect(isValidTacticId(tactic.id), tactic.id).toBe(true);
      expect(tactic.sentinelName).not.toMatch(/\s/);
    }
  });
});

describe("MITRE_TECHNIQUES dataset integrity", () => {
  it("is a curated subset of roughly 80-120 entries", () => {
    expect(MITRE_TECHNIQUES.length).toBeGreaterThanOrEqual(80);
    expect(MITRE_TECHNIQUES.length).toBeLessThanOrEqual(120);
  });

  it("every entry has a valid technique id, unique within the set", () => {
    const seen = new Set<string>();
    for (const tech of MITRE_TECHNIQUES) {
      expect(isValidTechniqueId(tech.id), tech.id).toBe(true);
      expect(seen.has(tech.id), `duplicate id ${tech.id}`).toBe(false);
      seen.add(tech.id);
    }
  });

  it("every entry references at least one tactic id that exists in MITRE_TACTICS", () => {
    const tacticIds = new Set(MITRE_TACTICS.map((t) => t.id));
    for (const tech of MITRE_TECHNIQUES) {
      expect(tech.tacticIds.length, `${tech.id} has no tactics`).toBeGreaterThan(0);
      for (const tid of tech.tacticIds) {
        expect(tacticIds.has(tid), `${tech.id} references unknown tactic ${tid}`).toBe(true);
      }
    }
  });

  it("every sub-technique has its parent in the set", () => {
    const ids = new Set(MITRE_TECHNIQUES.map((t) => t.id));
    for (const tech of MITRE_TECHNIQUES) {
      const dot = tech.id.indexOf(".");
      if (dot !== -1) {
        const parent = tech.id.slice(0, dot);
        expect(ids.has(parent), `${tech.id} missing parent ${parent}`).toBe(true);
      }
    }
  });

  it("includes all spec-mandated techniques and sub-techniques", () => {
    const required = [
      "T1110", "T1110.001", "T1110.002", "T1110.003", "T1110.004",
      "T1078", "T1078.004",
      "T1566", "T1566.001", "T1566.002",
      "T1098", "T1098.001", "T1098.005",
      "T1556", "T1621", "T1530", "T1537", "T1048", "T1567",
      "T1059", "T1059.001", "T1059.003",
      "T1071", "T1105",
      "T1136", "T1136.003",
      "T1484",
      "T1562", "T1562.001", "T1562.008",
      "T1114", "T1114.003",
      "T1539", "T1528",
      "T1550", "T1550.001", "T1550.004",
      "T1606", "T1648", "T1526",
      "T1087", "T1069", "T1018", "T1046", "T1003", "T1555",
      "T1021", "T1021.001", "T1021.002",
      "T1486", "T1490", "T1489",
      "T1027", "T1036", "T1204",
      "T1547", "T1543", "T1053",
      "T1568", "T1572", "T1041", "T1020",
    ];
    const ids = new Set(MITRE_TECHNIQUES.map((t) => t.id));
    for (const id of required) {
      expect(ids.has(id), `required technique ${id} missing`).toBe(true);
    }
  });

  it("has correct names and tactic associations for key entries", () => {
    const byId = new Map(MITRE_TECHNIQUES.map((t) => [t.id, t]));
    expect(byId.get("T1110")?.name).toBe("Brute Force");
    expect(byId.get("T1110")?.tacticIds).toEqual(["TA0006"]);
    expect(byId.get("T1110.003")?.name).toBe("Password Spraying");
    expect(byId.get("T1078.004")?.name).toBe("Cloud Accounts");
    expect(byId.get("T1078")?.tacticIds).toEqual(
      expect.arrayContaining(["TA0001", "TA0003", "TA0004", "TA0005"]),
    );
    expect(byId.get("T1566.001")?.name).toBe("Spearphishing Attachment");
    expect(byId.get("T1098.001")?.name).toBe("Additional Cloud Credentials");
    expect(byId.get("T1562.008")?.name).toBe("Disable or Modify Cloud Logs");
    expect(byId.get("T1114.003")?.name).toBe("Email Forwarding Rule");
    expect(byId.get("T1136.003")?.name).toBe("Cloud Account");
    expect(byId.get("T1021.002")?.name).toBe("SMB/Windows Admin Shares");
    expect(byId.get("T1621")?.name).toBe("Multi-Factor Authentication Request Generation");
    expect(byId.get("T1486")?.name).toBe("Data Encrypted for Impact");
    expect(byId.get("T1486")?.tacticIds).toEqual(["TA0040"]);
    expect(byId.get("T1053")?.tacticIds).toEqual(
      expect.arrayContaining(["TA0002", "TA0003", "TA0004"]),
    );
    expect(byId.get("T1550")?.tacticIds).toEqual(
      expect.arrayContaining(["TA0005", "TA0008"]),
    );
  });
});

describe("isValidTacticId", () => {
  it.each([
    ["TA0001", true],
    ["TA0043", true],
    ["TA9999", true],
    ["ta0001", false],
    ["TA001", false],
    ["TA00011", false],
    ["T1110", false],
    ["TA0001 ", false],
    ["", false],
  ])("%s -> %s", (input, expected) => {
    expect(isValidTacticId(input)).toBe(expected);
  });
});

describe("isValidTechniqueId", () => {
  it.each([
    ["T1110", true],
    ["T1110.001", true],
    ["T1078.004", true],
    ["T9999.999", true],
    ["t1110", false],
    ["T111", false],
    ["T11100", false],
    ["T1110.01", false],
    ["T1110.0011", false],
    ["T1110.", false],
    [".001", false],
    ["TA0001", false],
    ["1110", false],
    ["", false],
  ])("%s -> %s", (input, expected) => {
    expect(isValidTechniqueId(input)).toBe(expected);
  });
});

describe("toSentinelTactic", () => {
  it("maps display name, Sentinel spelling and TA id for every tactic", () => {
    for (const tactic of MITRE_TACTICS) {
      expect(toSentinelTactic(tactic.name)).toBe(tactic.sentinelName);
      expect(toSentinelTactic(tactic.sentinelName)).toBe(tactic.sentinelName);
      expect(toSentinelTactic(tactic.id)).toBe(tactic.sentinelName);
    }
  });

  it("is case-insensitive and ignores spaces", () => {
    expect(toSentinelTactic("lateral movement")).toBe("LateralMovement");
    expect(toSentinelTactic("LATERAL MOVEMENT")).toBe("LateralMovement");
    expect(toSentinelTactic("lateralmovement")).toBe("LateralMovement");
    expect(toSentinelTactic("command and control")).toBe("CommandAndControl");
    expect(toSentinelTactic("ta0008")).toBe("LateralMovement");
    expect(toSentinelTactic("  initial access ")).toBe("InitialAccess");
  });

  it("returns undefined for unknown or empty input", () => {
    expect(toSentinelTactic("Pivoting")).toBeUndefined();
    expect(toSentinelTactic("TA9999")).toBeUndefined();
    expect(toSentinelTactic("")).toBeUndefined();
    expect(toSentinelTactic("   ")).toBeUndefined();
  });
});

describe("lookupMitre", () => {
  it("always includes the curated-offline-subset caveat in notes", () => {
    for (const q of ["T1110", "nonsense-term-xyz", ""]) {
      const result = lookupMitre(q);
      expect(result.notes.some((n) => /curated offline subset/i.test(n))).toBe(true);
    }
  });

  it("echoes the original query", () => {
    expect(lookupMitre("T1110, brute force").query).toBe("T1110, brute force");
  });

  it("matches a tactic by TA id, case-insensitively", () => {
    const result = lookupMitre("ta0006");
    expect(result.tactics.map((t) => t.id)).toEqual(["TA0006"]);
    expect(result.techniques).toEqual([]);
  });

  it("matches a technique by T id, case-insensitively", () => {
    const result = lookupMitre("t1566");
    expect(result.techniques.map((t) => t.id)).toEqual(["T1566"]);
    expect(result.tactics).toEqual([]);
  });

  it("a sub-technique id also pulls in its parent technique", () => {
    const result = lookupMitre("T1110.003");
    const ids = result.techniques.map((t) => t.id);
    expect(ids).toContain("T1110.003");
    expect(ids).toContain("T1110");
  });

  it("matches technique names by phrase: 'brute force' returns the T1110 family", () => {
    const ids = lookupMitre("brute force").techniques.map((t) => t.id);
    for (const id of ["T1110", "T1110.001", "T1110.002", "T1110.003", "T1110.004"]) {
      expect(ids).toContain(id);
    }
  });

  it("matches tactic names by phrase: 'lateral movement' returns the tactic", () => {
    const result = lookupMitre("lateral movement");
    expect(result.tactics.map((t) => t.id)).toEqual(["TA0008"]);
  });

  it("name matching is case-insensitive", () => {
    const ids = lookupMitre("PASSWORD SPRAYING").techniques.map((t) => t.id);
    expect(ids).toContain("T1110.003");
  });

  it("splits comma-separated terms and matches each independently", () => {
    const result = lookupMitre("password spraying, T1078.004");
    const ids = result.techniques.map((t) => t.id);
    expect(ids).toContain("T1110.003");
    expect(ids).toContain("T1078.004");
    expect(ids).toContain("T1078"); // parent pulled in by sub id
  });

  it("splits whitespace-separated ids within one segment", () => {
    const result = lookupMitre("T1110 TA0006");
    expect(result.techniques.map((t) => t.id)).toContain("T1110");
    expect(result.tactics.map((t) => t.id)).toContain("TA0006");
  });

  it("dedupes when a term matches both by id and by name", () => {
    const tacticResult = lookupMitre("TA0008, lateral movement");
    expect(tacticResult.tactics.filter((t) => t.id === "TA0008")).toHaveLength(1);

    const techResult = lookupMitre("T1110, brute force");
    expect(techResult.techniques.filter((t) => t.id === "T1110")).toHaveLength(1);
  });

  it("notes any query terms that matched nothing", () => {
    const result = lookupMitre("T1110, quantum hacking");
    expect(result.techniques.map((t) => t.id)).toContain("T1110");
    expect(result.notes.some((n) => n.includes("quantum hacking"))).toBe(true);
  });

  it("treats a well-formed but unknown id as unmatched", () => {
    const result = lookupMitre("T9999");
    expect(result.tactics).toEqual([]);
    expect(result.techniques).toEqual([]);
    expect(result.notes.some((n) => n.includes("T9999"))).toBe(true);
  });

  it("handles an empty or delimiter-only query without matches or unmatched notes", () => {
    for (const q of ["", "  ", " , ,, "]) {
      const result = lookupMitre(q);
      expect(result.tactics).toEqual([]);
      expect(result.techniques).toEqual([]);
      expect(result.notes.some((n) => /no match/i.test(n))).toBe(false);
    }
  });
});
