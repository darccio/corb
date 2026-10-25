import { describe, expect, it } from "vitest";
import { agentProviderLayer, applyImpliedHosts, describeImpliedHostSource, type ImpliedHost } from "../../../src/config/implied.ts";
import { mergeConfigLayers } from "../../../src/config/load.ts";
import type { ConfigLayer } from "../../../src/config/schema.ts";

describe("config/implied", () => {
  it.each([
    { allow: undefined, hosts: ["chatgpt.com"] },
    { allow: ["pi.dev"], hosts: ["chatgpt.com"] },
    { allow: ["chatgpt.com"], hosts: [] },
    { allow: [" ChatGPT.com "], hosts: [] },
    { allow: ["*"], hosts: [] },
    { allow: ["*.chatgpt.com"], hosts: ["chatgpt.com"] },
  ])("adds only uncovered API hosts for $allow", ({ allow, hosts }) => {
    const config = mergeConfigLayers([{ agent: { provider: "openai-codex" }, egress: allow === undefined ? {} : { allow } }]);
    const result = applyImpliedHosts(config);
    expect(result.config.egress.allow).toEqual([...(allow ?? []), ...hosts]);
    expect(result.implied).toEqual(hosts.map((host) => ({
      host,
      source: { kind: "agent-provider", provider: "openai-codex", layer: "global" },
    })));
  });

  it.each([undefined, "anthropic"])("adds nothing for provider %s", (provider) => {
    const config = mergeConfigLayers(provider === undefined ? [] : [{ agent: { provider } }]);
    const result = applyImpliedHosts(config);
    expect(result.config.egress.allow).toEqual([]);
    expect(result.implied).toEqual([]);
  });

  it("returns a new config and allow list without mutating the input", () => {
    const config = mergeConfigLayers([{ agent: { provider: "openai-codex" }, egress: { allow: ["pi.dev"] } }]);
    const original = structuredClone(config);
    Object.freeze(config.egress.allow);
    Object.freeze(config.egress);
    Object.freeze(config);
    const result = applyImpliedHosts(config);
    expect(config).toEqual(original);
    expect(result.config).not.toBe(config);
    expect(result.config.egress).not.toBe(config.egress);
    expect(result.config.egress.allow).not.toBe(config.egress.allow);
  });

  it("describes the provider setting that implied a host", () => {
    expect(describeImpliedHostSource({ kind: "agent-provider", provider: "openai-codex", layer: "global" }))
      .toBe('[agent] provider = "openai-codex"');
  });
});

describe("config/implied: workspace sources and extra hosts", () => {
  it.each([
    { global: {}, workspace: undefined, expected: { layer: "global" } },
    { global: { agent: { provider: "openai-codex" } }, workspace: undefined, expected: { layer: "global" } },
    { global: {}, workspace: { name: "acme", layer: {} }, expected: { layer: "global" } },
    { global: {}, workspace: { name: "acme", layer: { agent: { provider: "openai-codex" } } }, expected: { layer: "workspace", workspace: "acme" } },
    { global: { agent: { provider: "openai-codex" } }, workspace: { name: "acme", layer: { agent: { provider: "anthropic" } } }, expected: { layer: "workspace", workspace: "acme" } },
    { global: { agent: { provider: "openai-codex" } }, workspace: { name: "acme", layer: { agent: { provider: "openai-codex" } } }, expected: { layer: "workspace", workspace: "acme" } },
    { global: { agent: { provider: "openai-codex" } }, workspace: { name: "acme", layer: { agent: { model: "personal-model" } } }, expected: { layer: "global" } },
  ] as Array<{ global: ConfigLayer; workspace: { name: string; layer: ConfigLayer } | undefined; expected: object }>)("finds the last layer that set a provider: $expected", ({ global, workspace, expected }) => {
    expect(agentProviderLayer(global, workspace)).toEqual(expected);
  });

  it("records and describes a workspace provider", () => {
    const config = mergeConfigLayers([{ agent: { provider: "openai-codex" } }]);
    const result = applyImpliedHosts(config, { providerLayer: { layer: "workspace", workspace: "acme" } });
    expect(result.implied).toEqual([{
      host: "chatgpt.com",
      source: { kind: "agent-provider", provider: "openai-codex", layer: "workspace", workspace: "acme" },
    }]);
    expect(describeImpliedHostSource(result.implied[0]!.source))
      .toBe('[agent] provider = "openai-codex" in workspace "acme"');
  });

  it("keeps the first source and processes provider hosts before extra hosts", () => {
    const config = mergeConfigLayers([{ agent: { provider: "openai-codex" }, egress: { allow: ["*.covered.test"] } }]);
    const extraSource = { kind: "agent-provider" as const, provider: "another-provider", layer: "global" as const };
    const extraHosts: ImpliedHost[] = [
      { host: "api.covered.test", source: extraSource },
      { host: "CHATGPT.COM", source: extraSource },
      { host: "first.test", source: extraSource },
      { host: "FIRST.test", source: { ...extraSource, provider: "later-provider" } },
      { host: "second.test", source: extraSource },
    ];
    const result = applyImpliedHosts(config, { providerLayer: { layer: "workspace", workspace: "acme" }, extraHosts });
    expect(result.config.egress.allow).toEqual(["*.covered.test", "chatgpt.com", "first.test", "second.test"]);
    expect(result.implied).toEqual([
      { host: "chatgpt.com", source: { kind: "agent-provider", provider: "openai-codex", layer: "workspace", workspace: "acme" } },
      extraHosts[2], extraHosts[4],
    ]);
  });

  it("adds extra hosts without a brokered provider and does not mutate any input", () => {
    const config = mergeConfigLayers([]);
    const extraHosts: ImpliedHost[] = [{ host: "extra.test", source: { kind: "agent-provider", provider: "future-provider", layer: "global" } }];
    const originalConfig = structuredClone(config);
    const originalExtraHosts = structuredClone(extraHosts);
    Object.freeze(config.egress.allow);
    Object.freeze(config.egress);
    Object.freeze(config);
    Object.freeze(extraHosts[0]!.source);
    Object.freeze(extraHosts[0]);
    Object.freeze(extraHosts);
    const result = applyImpliedHosts(config, { extraHosts });
    expect(result.config.egress.allow).toEqual(["extra.test"]);
    expect(result.implied).toEqual(originalExtraHosts);
    expect(config).toEqual(originalConfig);
    expect(extraHosts).toEqual(originalExtraHosts);
    expect(result.config.egress.allow).not.toBe(config.egress.allow);
  });
});
