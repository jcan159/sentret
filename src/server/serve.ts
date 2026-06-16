#!/usr/bin/env node
/**
 * Entry point for the Sentret local web UI: `npm run serve`.
 *
 * Binds to localhost by default. Credentials are read from the environment on
 * the server side and never sent to the browser. Configure with:
 *   SENTRET_WEB_HOST (default 127.0.0.1), SENTRET_WEB_PORT (default 8787),
 *   plus the usual provider/Azure env vars (see .env.example).
 */
import process from "node:process";

import { loadConfig } from "../config.js";
import { startServer } from "./server.js";

async function main(): Promise<void> {
  try {
    process.loadEnvFile?.(".env");
  } catch {
    // No .env file — environment variables are used directly.
  }

  const host = process.env.SENTRET_WEB_HOST ?? "127.0.0.1";
  const port = Number(process.env.SENTRET_WEB_PORT ?? 8787);
  const config = loadConfig();

  await startServer({ host, port });

  const url = `http://${host}:${port}`;
  process.stdout.write(`Sentret web UI listening on ${url}\n`);
  process.stdout.write(`Active LLM provider: ${config.provider} (effort: ${config.effort})\n`);

  const keyHint =
    config.provider === "openai"
      ? process.env.OPENAI_API_KEY
        ? null
        : "OPENAI_API_KEY is not set"
      : config.provider === "azure"
        ? config.azureEndpoint
          ? null
          : "AZURE_OPENAI_ENDPOINT is not set"
        : process.env.ANTHROPIC_API_KEY || process.env.ANTHROPIC_AUTH_TOKEN
          ? null
          : "ANTHROPIC_API_KEY is not set";
  if (keyHint) {
    process.stderr.write(`Warning: ${keyHint} — analysis runs will fail until it is configured.\n`);
  }
}

main().catch((error: unknown) => {
  process.stderr.write(`Fatal: ${error instanceof Error ? error.message : String(error)}\n`);
  process.exit(1);
});
