// Unit tests for `src/auth/provider.ts`'s registry.
import { describe, expect, it } from "vitest";
import {
  UnknownProviderError,
  findBrokeredProvider,
  getBrokeredProvider,
  listBrokeredProviders,
  unreachableApiHosts,
} from "../../../src/auth/provider.ts";
import { assertValidProviderId } from "../../../src/auth/store.ts";

describe("auth/provider registry", () => {
  it("lists openai-codex as the only brokered provider", () => {
    expect(listBrokeredProviders().map((provider) => provider.id)).toEqual(["openai-codex"]);
  });

  it("finds a provider by id and returns undefined for API-key providers", () => {
    expect(findBrokeredProvider("openai-codex")?.id).toBe("openai-codex");
    expect(findBrokeredProvider("anthropic")).toBeUndefined();
    expect(findBrokeredProvider(undefined)).toBeUndefined();
  });

  it("throws a helpful error for an unknown provider", () => {
    expect(() => getBrokeredProvider("openai")).toThrow(UnknownProviderError);
    expect(() => getBrokeredProvider("openai")).toThrow(/Available: openai-codex/);
  });

  it("gives every provider a file-safe id, a default login method, and exact API hosts", () => {
    for (const provider of listBrokeredProviders()) {
      expect(() => assertValidProviderId(provider.id)).not.toThrow();
      expect(provider.loginMethods.length).toBeGreaterThan(0);
      expect(provider.apiHosts.length).toBeGreaterThan(0);
      for (const host of provider.apiHosts) {
        expect(host).toMatch(/^[a-z0-9.-]+$/);
      }
    }
  });
});

describe("unreachableApiHosts", () => {
  const codex = getBrokeredProvider("openai-codex");

  it("reports API hosts egress.allow does not permit", () => {
    expect(unreachableApiHosts(codex, undefined)).toEqual(["chatgpt.com"]);
    expect(unreachableApiHosts(codex, [])).toEqual(["chatgpt.com"]);
    expect(unreachableApiHosts(codex, ["api.openai.com", "chat.gpt.com"])).toEqual(["chatgpt.com"]);
  });

  it("accepts an exact, case-insensitive or wildcard match, as Gondolin does", () => {
    expect(unreachableApiHosts(codex, ["chatgpt.com"])).toEqual([]);
    expect(unreachableApiHosts(codex, [" ChatGPT.com "])).toEqual([]);
    expect(unreachableApiHosts(codex, ["*"])).toEqual([]);
    expect(unreachableApiHosts(codex, ["*gpt.com"])).toEqual([]);
    expect(unreachableApiHosts(codex, ["*.chatgpt.com"])).toEqual(["chatgpt.com"]);
  });
});
