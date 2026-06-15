/**
 * Microsoft Entra token acquisition for the KQL Detection Rule Analyser.
 *
 * Wraps an Azure credential (DefaultAzureCredential by default) behind the
 * shared {@link TokenProvider} contract, adding per-scope caching with a
 * near-expiry refresh margin. Token values are never logged and never appear
 * in error messages.
 */

import type { TokenProvider } from "../types.js";

/**
 * Structural subset of `@azure/identity`'s `TokenCredential`. Typed
 * structurally so tests (and other callers) can inject a fake credential
 * without importing any Azure SDK types.
 */
export interface MinimalTokenCredential {
  getToken(
    scopes: string | string[],
  ): Promise<{ token: string; expiresOnTimestamp: number } | null>;
}

interface CachedToken {
  token: string;
  expiresOnTimestamp: number;
}

/** Refresh tokens once they are within this margin of expiry. */
const REFRESH_MARGIN_MS = 2 * 60 * 1000;

function signInError(scope: string, cause?: string): string {
  const base =
    `Failed to acquire a Microsoft Entra access token for scope "${scope}". ` +
    'Sign in first (e.g. run "az login") or configure service-principal ' +
    "environment variables for DefaultAzureCredential.";
  return cause === undefined ? base : `${base} Underlying error: ${cause}`;
}

/**
 * Caching {@link TokenProvider} backed by an Azure credential.
 *
 * - Caches one token per scope and reuses it until it is within 2 minutes of
 *   expiry, then transparently refreshes.
 * - Defaults to `DefaultAzureCredential` from `@azure/identity` (loaded
 *   lazily, so injecting a fake credential avoids loading the Azure SDK).
 * - Failures (credential throws, or returns null) are surfaced as a clear
 *   Error pointing at Microsoft Entra sign-in; token values are never
 *   included in errors.
 */
export class AzureTokenProvider implements TokenProvider {
  #credential: MinimalTokenCredential | undefined;
  readonly #cache = new Map<string, CachedToken>();

  constructor(credential?: MinimalTokenCredential) {
    this.#credential = credential;
  }

  /**
   * Returns a bearer token for `scope` (e.g.
   * `"https://api.loganalytics.azure.com/.default"`), from cache when the
   * cached token has more than 2 minutes of life left.
   *
   * @throws Error with Microsoft Entra sign-in guidance when the credential
   *   cannot produce a token.
   */
  async getToken(scope: string): Promise<string> {
    const cached = this.#cache.get(scope);
    if (cached !== undefined && cached.expiresOnTimestamp - Date.now() > REFRESH_MARGIN_MS) {
      return cached.token;
    }

    const credential = await this.#resolveCredential();
    let acquired: { token: string; expiresOnTimestamp: number } | null;
    try {
      acquired = await credential.getToken(scope);
    } catch (err) {
      const cause = err instanceof Error ? err.message : String(err);
      throw new Error(signInError(scope, cause));
    }
    if (acquired === null || acquired.token === "") {
      throw new Error(signInError(scope));
    }

    this.#cache.set(scope, {
      token: acquired.token,
      expiresOnTimestamp: acquired.expiresOnTimestamp,
    });
    return acquired.token;
  }

  async #resolveCredential(): Promise<MinimalTokenCredential> {
    if (this.#credential === undefined) {
      const { DefaultAzureCredential } = await import("@azure/identity");
      this.#credential = new DefaultAzureCredential();
    }
    return this.#credential;
  }
}
