import { describe, expect, it } from "vitest";
import { applyImpliedHosts, describeImpliedHostSource } from "../../../src/config/implied.ts";
import { mergeConfigLayers } from "../../../src/config/load.ts";

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
