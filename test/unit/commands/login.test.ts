// Unit tests for `src/commands/login.ts`: argument parsing and the status
// listing. The interactive flow itself is covered by the provider and broker
// tests; this file pins the CLI surface.
import { describe, expect, it } from "vitest";
import { listBrokeredProviders } from "../../../src/auth/provider.ts";
import { CREDENTIAL_FILE_VERSION, CredentialFileError, type StoredCredential } from "../../../src/auth/store.ts";
import { parseLoginArgs, parseLogoutArgs, renderLoginStatus } from "../../../src/commands/login.ts";

const NOW = Date.UTC(2026, 9, 24);

function credential(overrides: Partial<StoredCredential> = {}): StoredCredential {
  return {
    version: CREDENTIAL_FILE_VERSION,
    provider: "openai-codex",
    type: "oauth",
    access: "secret-access",
    refresh: "secret-refresh",
    expires: NOW + 3_600_000,
    accountId: "acct-1",
    updatedAt: "2026-10-24T00:00:00.000Z",
    ...overrides,
  };
}

describe("parseLoginArgs", () => {
  it("lists providers when no provider is given", () => {
    expect(parseLoginArgs([])).toEqual({});
  });

  it("takes a provider and an optional --device-code", () => {
    expect(parseLoginArgs(["openai-codex"])).toEqual({ provider: "openai-codex" });
    expect(parseLoginArgs(["openai-codex", "--device-code"])).toEqual({ provider: "openai-codex", method: "device-code" });
  });

  it("rejects extra arguments, unknown flags, and --device-code without a provider", () => {
    expect(() => parseLoginArgs(["a", "b"])).toThrow(/unexpected argument 'b'/);
    expect(() => parseLoginArgs(["openai-codex", "--nope"])).toThrow();
    expect(() => parseLoginArgs(["--device-code"])).toThrow(/needs a provider/);
  });
});

describe("parseLogoutArgs", () => {
  it("takes exactly one provider", () => {
    expect(parseLogoutArgs(["openai-codex"])).toEqual({ provider: "openai-codex" });
    expect(() => parseLogoutArgs([])).toThrow(/exactly one provider/);
    expect(() => parseLogoutArgs(["a", "b"])).toThrow(/exactly one provider/);
  });
});

describe("renderLoginStatus", () => {
  const providers = listBrokeredProviders();

  it("reports a missing login", () => {
    expect(renderLoginStatus(providers, () => undefined, NOW)).toBe("openai-codex  OpenAI Codex (ChatGPT Plus/Pro): not logged in");
  });

  it("reports a valid login without printing any token", () => {
    const text = renderLoginStatus(providers, () => credential(), NOW);
    expect(text).toContain("logged in (account acct-1), access token valid until 2026-10-24T01:00:00.000Z");
    expect(text).not.toContain("secret-access");
    expect(text).not.toContain("secret-refresh");
  });

  it("reports an expired access token as refreshed on next use", () => {
    expect(renderLoginStatus(providers, () => credential({ expires: NOW - 1 }), NOW)).toContain("access token expired, refreshed on next use");
  });

  it("reports an unusable credential file instead of failing", () => {
    const text = renderLoginStatus(
      providers,
      () => {
        throw new CredentialFileError("/x/openai-codex.json", "not valid JSON", "openai-codex");
      },
      NOW,
    );
    expect(text).toContain("unusable login:");
    expect(text).toContain("not valid JSON");
  });
});
