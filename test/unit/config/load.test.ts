// Unit tests for `src/config/load.ts` — M2.2. Covers the full
// defaults->config.toml->workspace->CLI merge chain, each merge rule in
// isolation (scalar replace, additive-dedup arrays, name-keyed dir merge
// with rules appending but other fields replacing, nested scalar-object
// merge), the built-in-defaults layer's own baked-in call pattern, and that
// an invalid mount target surfaces as a thrown error rather than a silent
// drop.
import { describe, expect, it } from "vitest";
import type { ConfigLayer } from "../../../src/config/schema.ts";
import { BUILTIN_DEFAULTS, ConfigMergeError, mergeConfigLayers } from "../../../src/config/load.ts";
import { GuestPathError } from "../../../src/config/guestpaths.ts";

describe("config/load", () => {
  it("BUILTIN_DEFAULTS sets only the documented minimal, structural defaults", () => {
    expect(BUILTIN_DEFAULTS).toEqual({
      egress: { "block-internal-ranges": true, websockets: false },
      git: { "ssh-agent": true, "allow-push": false },
      policy: { enabled: true, "secret-scan": true, "fail-open": true },
    });
  });

  it("mergeConfigLayers([]) and mergeConfigLayers([BUILTIN_DEFAULTS]) are equivalent — BUILTIN_DEFAULTS is always merged in, callers don't pass it themselves", () => {
    const fromEmpty = mergeConfigLayers([]);
    const fromExplicitDefaults = mergeConfigLayers([BUILTIN_DEFAULTS]);
    expect(fromEmpty).toEqual(fromExplicitDefaults);
    expect(fromEmpty).toEqual({
      egress: { "block-internal-ranges": true, websockets: false },
      git: { "ssh-agent": true, "allow-push": false },
      dir: [],
      policy: { enabled: true, "secret-scan": true, "fail-open": true },
    });
  });

  it("merges the full defaults -> config.toml -> workspace -> CLI chain (intended call pattern: BUILTIN_DEFAULTS is not passed by the caller)", () => {
    const configToml: ConfigLayer = {
      version: 1,
      name: "corb-dev",
      vm: { image: "corb:0.1.0", memory: "4G", limits: { "memory-max": "6G" } },
      agent: { provider: "anthropic", model: "claude-opus-4-5" },
      egress: {
        allow: ["api.anthropic.com", "api.github.com"],
        "github-api": { methods: ["GET"] },
      },
      git: { "allow-hosts": ["github.com"], "allow-repos": ["dario/corb"] },
      dir: [
        {
          name: "corb",
          host: "~/Code/corb",
          mode: "rw",
          rules: [{ glob: "**/.env*", mode: "hidden", reason: "local secrets file" }],
        },
      ],
      policy: { "max-changed-files": 40 },
    };

    const workspace: ConfigLayer = {
      name: "corb-dev-ws",
      dir: [
        {
          name: "corb",
          rules: [{ glob: "**/*_test.go", mode: "deny-write", reason: "tests are frozen" }],
        },
        { name: "scratch", host: "~/.cache/corb/scratch", mode: "rw", create: true },
      ],
    };

    const cliLayer: ConfigLayer = {
      vm: { memory: "8G" },
      egress: { allow: ["api.anthropic.com", "registry.npmjs.org"] },
      dir: [{ name: "scratch", mode: "ro" }],
    };

    const effective = mergeConfigLayers([configToml, workspace, cliLayer]);

    expect(effective).toEqual({
      version: 1,
      name: "corb-dev-ws",
      vm: { image: "corb:0.1.0", memory: "8G", limits: { "memory-max": "6G" } },
      agent: { provider: "anthropic", model: "claude-opus-4-5" },
      egress: {
        allow: ["api.anthropic.com", "api.github.com", "registry.npmjs.org"],
        "block-internal-ranges": true,
        websockets: false,
        "github-api": { methods: ["GET"] },
      },
      git: {
        "ssh-agent": true,
        "allow-push": false,
        "allow-hosts": ["github.com"],
        "allow-repos": ["dario/corb"],
      },
      dir: [
        {
          name: "corb",
          host: "~/Code/corb",
          mode: "rw",
          rules: [
            { glob: "**/.env*", mode: "hidden", reason: "local secrets file" },
            { glob: "**/*_test.go", mode: "deny-write", reason: "tests are frozen" },
          ],
        },
        {
          name: "scratch",
          host: "~/.cache/corb/scratch",
          mode: "ro",
          create: true,
          rules: [],
        },
      ],
      policy: { enabled: true, "secret-scan": true, "max-changed-files": 40, "fail-open": true },
    });
  });

  it("scalar fields: a later layer's explicit value overrides an earlier one", () => {
    const base: ConfigLayer = { agent: { model: "claude-opus-4-5" } };
    const override: ConfigLayer = { agent: { model: "claude-haiku-4-5" } };
    const effective = mergeConfigLayers([base, override]);
    expect(effective.agent).toEqual({ model: "claude-haiku-4-5" });
  });

  it("scalar fields: a later layer that doesn't mention a field keeps the accumulated value", () => {
    const base: ConfigLayer = { agent: { model: "claude-opus-4-5", provider: "anthropic" } };
    const partial: ConfigLayer = { agent: { model: "claude-haiku-4-5" } };
    const effective = mergeConfigLayers([base, partial]);
    expect(effective.agent).toEqual({ model: "claude-haiku-4-5", provider: "anthropic" });
  });

  it("array-valued security settings are additive across layers, deduplicated", () => {
    const first: ConfigLayer = { egress: { allow: ["api.anthropic.com", "api.github.com"] } };
    const second: ConfigLayer = { egress: { allow: ["api.github.com", "registry.npmjs.org"] } };
    const effective = mergeConfigLayers([first, second]);
    expect(effective.egress.allow).toEqual(["api.anthropic.com", "api.github.com", "registry.npmjs.org"]);
  });

  it("dir: same name in two layers replaces host/mode wholesale from the later layer, but rules from both layers are present", () => {
    const first: ConfigLayer = {
      dir: [{ name: "corb", host: "~/Code/corb", mode: "rw", rules: [{ glob: "a", mode: "hidden" }] }],
    };
    const second: ConfigLayer = {
      dir: [{ name: "corb", host: "~/Code/corb-2", mode: "ro", rules: [{ glob: "b", mode: "deny-write" }] }],
    };
    const effective = mergeConfigLayers([first, second]);
    expect(effective.dir).toEqual([
      {
        name: "corb",
        host: "~/Code/corb-2",
        mode: "ro",
        rules: [
          { glob: "a", mode: "hidden" },
          { glob: "b", mode: "deny-write" },
        ],
      },
    ]);
  });

  it("dir: a brand-new name in a later layer appends rather than replacing", () => {
    const first: ConfigLayer = { dir: [{ name: "corb", host: "~/Code/corb", mode: "rw" }] };
    const second: ConfigLayer = { dir: [{ name: "reference", host: "~/Code/reference-docs", mode: "ro" }] };
    const effective = mergeConfigLayers([first, second]);
    expect(effective.dir).toEqual([
      { name: "corb", host: "~/Code/corb", mode: "rw", rules: [] },
      { name: "reference", host: "~/Code/reference-docs", mode: "ro", rules: [] },
    ]);
  });

  it("nested scalar object merge: vm.limits fields set across two layers are both present in the result", () => {
    const first: ConfigLayer = { vm: { limits: { "memory-max": "6G" } } };
    const second: ConfigLayer = { vm: { limits: { "pids-max": 1024 } } };
    const effective = mergeConfigLayers([first, second]);
    expect(effective.vm?.limits).toEqual({ "memory-max": "6G", "pids-max": 1024 });
  });

  it("nested scalar object merge: a later layer's field wins over an earlier layer's same field", () => {
    const first: ConfigLayer = { vm: { limits: { "cpu-quota": "200%" } } };
    const second: ConfigLayer = { vm: { limits: { "cpu-quota": "400%" } } };
    const effective = mergeConfigLayers([first, second]);
    expect(effective.vm?.limits).toEqual({ "cpu-quota": "400%" });
  });

  it("an empty layer list produces dir: [] and the documented default booleans, not undefined", () => {
    const effective = mergeConfigLayers([]);
    expect(effective.dir).toEqual([]);
    expect(effective.egress["block-internal-ranges"]).toBe(true);
    expect(effective.egress.websockets).toBe(false);
    expect(effective.git["ssh-agent"]).toBe(true);
    expect(effective.git["allow-push"]).toBe(false);
    expect(effective.policy.enabled).toBe(true);
    expect(effective.policy["secret-scan"]).toBe(true);
    expect(effective.policy["fail-open"]).toBe(true);
  });

  it("fields with no default and no layer setting them stay genuinely absent (undefined), not defaulted", () => {
    const effective = mergeConfigLayers([]);
    expect(effective.vm).toBeUndefined();
    expect(effective.agent).toBeUndefined();
    expect(effective.egress.allow).toBeUndefined();
    expect(effective.policy["max-changed-files"]).toBeUndefined();
  });

  it("secrets merge per-name, field-by-field, later layer winning per field", () => {
    const first: ConfigLayer = {
      secrets: {
        ANTHROPIC_API_KEY: { hosts: ["api.anthropic.com"] },
        GITHUB_TOKEN: { hosts: ["api.github.com"], optional: true },
      },
    };
    const second: ConfigLayer = {
      secrets: { GITHUB_TOKEN: { optional: false } },
    };
    const effective = mergeConfigLayers([first, second]);
    expect(effective.secrets).toEqual({
      ANTHROPIC_API_KEY: { hosts: ["api.anthropic.com"] },
      GITHUB_TOKEN: { hosts: ["api.github.com"], optional: false },
    });
  });

  it("throws ConfigMergeError for a [[dir]] entry with no name", () => {
    expect(() => mergeConfigLayers([{ dir: [{ host: "~/x" }] }])).toThrow(ConfigMergeError);
  });

  it("propagates GuestPathError from guestpaths validation rather than silently dropping an invalid dir", () => {
    expect(() => mergeConfigLayers([{ dir: [{ name: "..", host: "~/x" }] }])).toThrow(GuestPathError);
  });

  it("two distinct, validly-named dirs in the same layer do not collide (sanity check that the merge doesn't over-trigger guestpaths)", () => {
    const layer: ConfigLayer = {
      dir: [
        { name: "corb", host: "~/Code/corb" },
        { name: "corb-2", host: "~/Code/corb-2" },
      ],
    };
    expect(() => mergeConfigLayers([layer])).not.toThrow();
  });
});
