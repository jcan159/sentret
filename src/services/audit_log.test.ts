import { describe, it, expect } from "vitest";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { AuditLog } from "./audit_log.js";
import type { AuditRecord } from "../types.js";

function makeRecord(overrides: Partial<AuditRecord> = {}): AuditRecord {
  return {
    timestamp_utc: "2026-06-12T10:00:00.000Z",
    workspace_id: "11111111-2222-3333-4444-555555555555",
    purpose: "table existence check",
    query: "SigninLogs | where TimeGenerated >= ago(1d) | count",
    timespan: "P1D",
    outcome: "executed",
    ...overrides,
  };
}

async function withTmpDir(fn: (dir: string) => Promise<void>): Promise<void> {
  const dir = await mkdtemp(path.join(tmpdir(), "sentret-audit-"));
  try {
    await fn(dir);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}

async function readJsonl(filePath: string): Promise<unknown[]> {
  const raw = await readFile(filePath, "utf8");
  expect(raw.endsWith("\n")).toBe(true);
  return raw
    .split("\n")
    .filter((line) => line.length > 0)
    .map((line) => JSON.parse(line) as unknown);
}

describe("AuditLog", () => {
  it("round-trips records through JSONL", async () => {
    await withTmpDir(async (dir) => {
      const filePath = path.join(dir, "audit.jsonl");
      const log = new AuditLog(filePath);
      const records: AuditRecord[] = [
        makeRecord({ purpose: "first", outcome: "executed" }),
        makeRecord({ purpose: "second", outcome: "blocked", detail: "union * detected" }),
        makeRecord({ purpose: "third", outcome: "failed", detail: "SemanticError" }),
      ];
      for (const record of records) {
        await log.append(record);
      }
      const parsed = await readJsonl(filePath);
      expect(parsed).toEqual(records);
    });
  });

  it("creates missing parent directories on first write", async () => {
    await withTmpDir(async (dir) => {
      const filePath = path.join(dir, "deeply", "nested", "logs", "audit.jsonl");
      const log = new AuditLog(filePath);
      await log.append(makeRecord());
      const parsed = await readJsonl(filePath);
      expect(parsed).toHaveLength(1);
    });
  });

  it("appends to an existing file rather than truncating", async () => {
    await withTmpDir(async (dir) => {
      const filePath = path.join(dir, "audit.jsonl");
      await new AuditLog(filePath).append(makeRecord({ purpose: "from first instance" }));
      await new AuditLog(filePath).append(makeRecord({ purpose: "from second instance" }));
      const parsed = (await readJsonl(filePath)) as AuditRecord[];
      expect(parsed.map((r) => r.purpose)).toEqual([
        "from first instance",
        "from second instance",
      ]);
    });
  });

  it("serializes concurrent appends without interleaving half-lines", async () => {
    await withTmpDir(async (dir) => {
      const filePath = path.join(dir, "audit.jsonl");
      const log = new AuditLog(filePath);
      const count = 50;
      await Promise.all(
        Array.from({ length: count }, (_, i) =>
          log.append(makeRecord({ purpose: `query-${i}`, query: "x".repeat(2000) })),
        ),
      );
      const parsed = (await readJsonl(filePath)) as AuditRecord[];
      expect(parsed).toHaveLength(count);
      // Every line parsed as a full record, in submission order.
      expect(parsed.map((r) => r.purpose)).toEqual(
        Array.from({ length: count }, (_, i) => `query-${i}`),
      );
    });
  });

  it("round-trips records containing newlines and quotes in the query", async () => {
    await withTmpDir(async (dir) => {
      const filePath = path.join(dir, "audit.jsonl");
      const log = new AuditLog(filePath);
      const record = makeRecord({
        query: 'SigninLogs\n| where Name == "O\'Brien"\n| count',
        detail: 'line1\nline2\t"quoted"',
      });
      await log.append(record);
      const parsed = await readJsonl(filePath);
      expect(parsed).toEqual([record]);
    });
  });

  it("rejects when the parent directory cannot be created, and stays usable for error reporting", async () => {
    await withTmpDir(async (dir) => {
      const blocker = path.join(dir, "blocker");
      await writeFile(blocker, "i am a file, not a directory");
      const log = new AuditLog(path.join(blocker, "sub", "audit.jsonl"));
      await expect(log.append(makeRecord())).rejects.toThrow();
      // The internal chain must survive a failed write: the next append still
      // settles (rejecting again here, since the path is permanently broken).
      await expect(log.append(makeRecord())).rejects.toThrow();
    });
  });
});
