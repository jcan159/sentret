import { describe, expect, it } from "vitest";

import { AzureTokenProvider } from "./azure_auth.js";

/** One scripted credential response: a token + lifetime, a null, or a throw. */
type CredentialStep = { token: string; expiresInMs: number } | null | Error;

/**
 * Builds a structural fake credential that replays `plan` step by step
 * (repeating the last step once exhausted) and records every scope request.
 */
function fakeCredential(plan: CredentialStep[]) {
  const calls: (string | string[])[] = [];
  let index = 0;
  const credential = {
    async getToken(
      scopes: string | string[],
    ): Promise<{ token: string; expiresOnTimestamp: number } | null> {
      calls.push(scopes);
      const step = plan[Math.min(index, plan.length - 1)];
      index += 1;
      if (step === undefined || step === null) return null;
      if (step instanceof Error) throw step;
      return { token: step.token, expiresOnTimestamp: Date.now() + step.expiresInMs };
    },
  };
  return { credential, calls };
}

const SCOPE = "https://api.loganalytics.azure.com/.default";
const HOUR = 3_600_000;

describe("AzureTokenProvider", () => {
  it("returns the token and forwards the scope to the credential", async () => {
    const { credential, calls } = fakeCredential([{ token: "tok-1", expiresInMs: HOUR }]);
    const provider = new AzureTokenProvider(credential);

    await expect(provider.getToken(SCOPE)).resolves.toBe("tok-1");
    expect(calls).toEqual([SCOPE]);
  });

  it("caches tokens per scope while they are far from expiry", async () => {
    const { credential, calls } = fakeCredential([
      { token: "tok-1", expiresInMs: HOUR },
      { token: "tok-2", expiresInMs: HOUR },
    ]);
    const provider = new AzureTokenProvider(credential);

    await expect(provider.getToken(SCOPE)).resolves.toBe("tok-1");
    await expect(provider.getToken(SCOPE)).resolves.toBe("tok-1");
    expect(calls).toHaveLength(1);
  });

  it("caches each scope independently", async () => {
    const calls: (string | string[])[] = [];
    const credential = {
      async getToken(scopes: string | string[]) {
        calls.push(scopes);
        return { token: `tok-for-${String(scopes)}`, expiresOnTimestamp: Date.now() + HOUR };
      },
    };
    const provider = new AzureTokenProvider(credential);

    await expect(provider.getToken("scope-a")).resolves.toBe("tok-for-scope-a");
    await expect(provider.getToken("scope-b")).resolves.toBe("tok-for-scope-b");
    await expect(provider.getToken("scope-a")).resolves.toBe("tok-for-scope-a");
    expect(calls).toEqual(["scope-a", "scope-b"]);
  });

  it("refreshes a cached token that is within 2 minutes of expiry", async () => {
    const { credential, calls } = fakeCredential([
      { token: "stale", expiresInMs: 60_000 }, // 1 min left: inside the refresh margin
      { token: "fresh", expiresInMs: HOUR },
    ]);
    const provider = new AzureTokenProvider(credential);

    await expect(provider.getToken(SCOPE)).resolves.toBe("stale");
    await expect(provider.getToken(SCOPE)).resolves.toBe("fresh");
    expect(calls).toHaveLength(2);
  });

  it("keeps a cached token that is just outside the 2-minute margin", async () => {
    const { credential, calls } = fakeCredential([
      { token: "tok-1", expiresInMs: 2 * 60_000 + 5_000 },
      { token: "tok-2", expiresInMs: HOUR },
    ]);
    const provider = new AzureTokenProvider(credential);

    await expect(provider.getToken(SCOPE)).resolves.toBe("tok-1");
    await expect(provider.getToken(SCOPE)).resolves.toBe("tok-1");
    expect(calls).toHaveLength(1);
  });

  it("throws a Microsoft Entra sign-in error when the credential returns null", async () => {
    const { credential } = fakeCredential([null]);
    const provider = new AzureTokenProvider(credential);

    await expect(provider.getToken(SCOPE)).rejects.toThrow(/Microsoft Entra/);
    await expect(provider.getToken(SCOPE)).rejects.toThrow(/az login/);
  });

  it("wraps credential exceptions with sign-in guidance and the underlying message", async () => {
    const { credential } = fakeCredential([new Error("MSAL device flow unavailable")]);
    const provider = new AzureTokenProvider(credential);

    const rejection = provider.getToken(SCOPE);
    await expect(rejection).rejects.toThrow(/az login/);
    await expect(provider.getToken(SCOPE)).rejects.toThrow(/MSAL device flow unavailable/);
  });

  it("handles non-Error throwables from the credential", async () => {
    const credential = {
      async getToken(): Promise<{ token: string; expiresOnTimestamp: number } | null> {
        throw "string failure"; // eslint-disable-line no-throw-literal
      },
    };
    const provider = new AzureTokenProvider(credential);

    await expect(provider.getToken(SCOPE)).rejects.toThrow(/string failure/);
  });

  it("recovers after a failed acquisition instead of caching the failure", async () => {
    const { credential, calls } = fakeCredential([null, { token: "tok-ok", expiresInMs: HOUR }]);
    const provider = new AzureTokenProvider(credential);

    await expect(provider.getToken(SCOPE)).rejects.toThrow();
    await expect(provider.getToken(SCOPE)).resolves.toBe("tok-ok");
    expect(calls).toHaveLength(2);
  });

  it("never includes the token value in error messages", async () => {
    // A credential that succeeds once, then fails: the failure message must not
    // leak the previously issued token.
    const { credential } = fakeCredential([
      { token: "SUPER-SECRET-TOKEN", expiresInMs: 1_000 }, // expires immediately -> refresh
      new Error("refresh failed"),
    ]);
    const provider = new AzureTokenProvider(credential);

    await provider.getToken(SCOPE);
    try {
      await provider.getToken(SCOPE);
      expect.unreachable("second acquisition should have thrown");
    } catch (err) {
      expect(String(err)).not.toContain("SUPER-SECRET-TOKEN");
    }
  });
});
