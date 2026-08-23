// Unit tests for `src/config/render.ts` — M2.5. Covers: text output
// contains the key sections and a visible trust verdict, JSON output
// round-trips through `JSON.parse` to something matching the resolved data,
// and a widening diff is visible in both formats.
import { describe, expect, it } from "vitest";
import type { EffectiveConfig } from "../../../src/config/load.ts";
import type { ResolvedWorkspace } from "../../../src/config/resolve.ts";
import { renderJson, renderText } from "../../../src/config/render.ts";

function baseConfig(): EffectiveConfig {
  return {
    version: 1,
    name: "corb-dev",
    vm: { image: "corb:0.1.0", memory: "4G", cpus: 2 },
    agent: { provider: "anthropic", model: "claude-opus-4-5" },
    secrets: { ANTHROPIC_API_KEY: { hosts: ["api.anthropic.com"] } },
    egress: {
      allow: ["api.anthropic.com"],
      "allow-internal": [],
      "block-internal-ranges": true,
      websockets: false,
    },
    git: { "ssh-agent": true, "allow-push": false },
    dir: [{ name: "myproj", host: "/home/user/myproj", mode: "rw", rules: [] }],
    policy: { enabled: true, "secret-scan": true, "fail-open": true },
  };
}

function noChangeWorkspace(): ResolvedWorkspace {
  return {
    dir: "/home/user/myproj",
    effectiveConfig: baseConfig(),
    trustKey: "/home/user/myproj",
    priorRecord: undefined,
    trustEvaluation: { verdict: "trusted", widened: [], narrowed: [] },
  };
}

function wideningWorkspace(): ResolvedWorkspace {
  const config = baseConfig();
  config.egress.allow = ["api.anthropic.com", "example.com"];
  return {
    dir: "/home/user/myproj",
    effectiveConfig: config,
    trustKey: "/home/user/myproj",
    priorRecord: undefined,
    trustEvaluation: {
      verdict: "requires-confirmation",
      widened: [{ field: "egress.allow", description: "egress.allow gained 'example.com'" }],
      narrowed: [],
    },
  };
}

describe("config/render: renderText", () => {
  it("contains the key config sections and a visible trust verdict for a no-change workspace", () => {
    const text = renderText(noChangeWorkspace());
    expect(text).toContain("workspace: /home/user/myproj");
    expect(text).toContain("vm:");
    expect(text).toContain("corb:0.1.0");
    expect(text).toContain("agent:");
    expect(text).toContain("secrets:");
    expect(text).toContain("ANTHROPIC_API_KEY");
    expect(text).toContain("egress:");
    expect(text).toContain("git:");
    expect(text).toContain("dir:");
    expect(text).toContain("myproj");
    expect(text).toContain("policy:");
    expect(text).toContain("trust:");
    expect(text).toContain("verdict: TRUSTED");
  });

  it("never prints a secret value, only the secret's name and host-binding metadata", () => {
    const text = renderText(noChangeWorkspace());
    // Only 'hosts'/'optional' metadata should appear next to the secret name — no room for a value field to leak, since EffectiveConfig itself never carries one.
    expect(text).toMatch(/ANTHROPIC_API_KEY: hosts=\[api\.anthropic\.com\] optional=\(unset\)/);
  });

  it("makes a widening diff visible: verdict and itemized widened change both appear", () => {
    const text = renderText(wideningWorkspace());
    expect(text).toContain("verdict: REQUIRES-CONFIRMATION");
    expect(text).toContain("widened");
    expect(text).toContain("egress.allow gained 'example.com'");
  });
});

describe("config/render: renderJson", () => {
  it("round-trips through JSON.parse to data matching the resolved workspace", () => {
    const resolved = noChangeWorkspace();
    const json = renderJson(resolved);
    const parsed = JSON.parse(json);
    expect(parsed).toEqual({
      dir: resolved.dir,
      trustKey: resolved.trustKey,
      config: resolved.effectiveConfig,
      trust: resolved.trustEvaluation,
    });
  });

  it("is pretty-printed (indented), not minified", () => {
    const json = renderJson(noChangeWorkspace());
    expect(json).toContain("\n");
    expect(json).toContain("  ");
  });

  it("makes a widening diff visible in the JSON output", () => {
    const json = renderJson(wideningWorkspace());
    const parsed = JSON.parse(json);
    expect(parsed.trust.verdict).toBe("requires-confirmation");
    expect(parsed.trust.widened).toEqual([{ field: "egress.allow", description: "egress.allow gained 'example.com'" }]);
  });
});
