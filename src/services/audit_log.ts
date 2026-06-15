/**
 * Append-only JSONL audit log.
 *
 * Every query the analyser executes (or blocks, or fails) is recorded with
 * its purpose, per docs/implementation_notes.md "Query Safety Controls":
 * "Log the purpose of every query."
 */

import { appendFile, mkdir } from "node:fs/promises";
import { dirname } from "node:path";
import type { AuditRecord } from "../types.js";

/**
 * Appends {@link AuditRecord}s to a JSONL file (one JSON object per line).
 *
 * - Parent directories are created on the first write.
 * - Appends within a process are serialized through an internal promise
 *   chain, so concurrent calls cannot interleave partial lines.
 * - A failed write rejects the promise returned to its caller, but does not
 *   poison the chain: later appends still run.
 */
export class AuditLog {
  readonly filePath: string;
  #chain: Promise<void> = Promise.resolve();
  #dirReady = false;

  constructor(filePath: string) {
    this.filePath = filePath;
  }

  /**
   * Appends one record as a single JSON line. Resolves once the line is
   * durably handed to the filesystem; rejects if the directory cannot be
   * created or the write fails.
   */
  append(record: AuditRecord): Promise<void> {
    const line = `${JSON.stringify(record)}\n`;
    const write = this.#chain.then(async () => {
      if (!this.#dirReady) {
        await mkdir(dirname(this.filePath), { recursive: true });
        this.#dirReady = true;
      }
      await appendFile(this.filePath, line, { encoding: "utf8" });
    });
    // Swallow the error on the chain only; the caller still observes it via
    // the returned promise.
    this.#chain = write.then(
      () => undefined,
      () => undefined,
    );
    return write;
  }
}
