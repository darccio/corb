// Unit tests for `src/config/trust.ts` — M2.3. Covers: no-op and pure-
// narrowing changes staying "trusted"; every individual widening rule in the
// table (egress/git/dir/policy/secrets); the `policy.max-changed-files`
// unset-vs-set direction judgment call in both directions; the "unclassified
// field defaults to widening" fallback; a simultaneously widening-and-
// narrowing change overall requiring confirmation; `previous === undefined`
// requiring confirmation; hash stability under differently-ordered object
// keys and divergence for different configs; and `recordAcceptance` producing
// a new store/record without mutating its inputs.
import { describe, expect, it } from "vitest";
import type { EffectiveConfig } from "../../../src/config/load.ts";
import { evaluateTrust, hashEffectiveConfig, recordAcceptance, type TrustStore } from "../../../src/config/trust.ts";

function baseConfig(): EffectiveConfig {
  return {
    version: 1,
    name: "corb-dev",
    vm: { image: "corb:0.1.0", memory: "4G", cpus: 2 },
    agent: { provider: "anthropic", model: "claude-opus-4-5" },
    secrets: {
      ANTHROPIC_API_KEY: { hosts: ["api.anthropic.com"] },
      GITHUB_TOKEN: { hosts: ["api.github.com"], optional: true },
    },
    egress: {
      allow: ["api.anthropic.com", "api.github.com"],
      "allow-internal": [],
      "block-internal-ranges": true,
      websockets: false,
      "github-api": { methods: ["GET"] },
    },
    git: {
      "ssh-agent": true,
      "allow-hosts": ["github.com"],
      "allow-repos": ["dario/corb"],
      "allow-push": false,
    },
    dir: [
      {
        name: "corb",
        host: "~/Code/corb",
        mode: "rw",
        create: false,
        rules: [{ glob: "**/.env*", mode: "hidden", reason: "local secrets file" }],
      },
      {
        name: "scratch",
        host: "~/.cache/corb/scratch",
        mode: "ro",
        rules: [],
      },
    ],
    policy: { enabled: true, "secret-scan": true, "max-changed-files": 40, "fail-open": false },
    audit: { path: "~/.cache/corb/audit.log" },
  };
}

function clone(config: EffectiveConfig): EffectiveConfig {
  return structuredClone(config);
}

describe("config/trust: evaluateTrust", () => {
  it("no change at all is trusted, with nothing widened or narrowed", () => {
    const config = baseConfig();
    const result = evaluateTrust(clone(config), clone(config));
    expect(result.verdict).toBe("trusted");
    expect(result.widened).toEqual([]);
    expect(result.narrowed).toEqual([]);
  });

  it("a pure narrowing change (a host removed from egress.allow) is trusted and reported as narrowed", () => {
    const previous = baseConfig();
    const current = clone(previous);
    current.egress.allow = ["api.anthropic.com"];
    const result = evaluateTrust(previous, current);
    expect(result.verdict).toBe("trusted");
    expect(result.widened).toEqual([]);
    expect(result.narrowed).toEqual([{ field: "egress.allow", description: "egress.allow lost 'api.github.com'" }]);
  });

  it("previous === undefined (first time seeing this workspace) requires confirmation", () => {
    const current = baseConfig();
    const result = evaluateTrust(undefined, current);
    expect(result.verdict).toBe("requires-confirmation");
    expect(result.widened).toHaveLength(1);
    expect(result.widened[0]?.description).toContain("no prior trust record");
    expect(result.narrowed).toEqual([]);
  });

  describe("each widening rule, exercised individually", () => {
    it("egress.allow gains an entry", () => {
      const previous = baseConfig();
      const current = clone(previous);
      current.egress.allow = [...(previous.egress.allow ?? []), "registry.npmjs.org"];
      const result = evaluateTrust(previous, current);
      expect(result.verdict).toBe("requires-confirmation");
      expect(result.widened).toContainEqual({ field: "egress.allow", description: "egress.allow gained 'registry.npmjs.org'" });
    });

    it("egress.allow-internal gains an entry", () => {
      const previous = baseConfig();
      const current = clone(previous);
      current.egress["allow-internal"] = ["10.0.0.5"];
      const result = evaluateTrust(previous, current);
      expect(result.verdict).toBe("requires-confirmation");
      expect(result.widened).toContainEqual({ field: "egress.allow-internal", description: "egress.allow-internal gained '10.0.0.5'" });
    });

    it("egress.block-internal-ranges: true -> false", () => {
      const previous = baseConfig();
      const current = clone(previous);
      current.egress["block-internal-ranges"] = false;
      const result = evaluateTrust(previous, current);
      expect(result.verdict).toBe("requires-confirmation");
      expect(result.widened).toContainEqual({
        field: "egress.block-internal-ranges",
        description: "egress.block-internal-ranges changed from true to false",
      });
    });

    it("egress.websockets: false -> true", () => {
      const previous = baseConfig();
      const current = clone(previous);
      current.egress.websockets = true;
      const result = evaluateTrust(previous, current);
      expect(result.verdict).toBe("requires-confirmation");
      expect(result.widened).toContainEqual({ field: "egress.websockets", description: "egress.websockets changed from false to true" });
    });

    it("git.allow-hosts gains an entry", () => {
      const previous = baseConfig();
      const current = clone(previous);
      current.git["allow-hosts"] = [...(previous.git["allow-hosts"] ?? []), "gitlab.com"];
      const result = evaluateTrust(previous, current);
      expect(result.verdict).toBe("requires-confirmation");
      expect(result.widened).toContainEqual({ field: "git.allow-hosts", description: "git.allow-hosts gained 'gitlab.com'" });
    });

    it("git.allow-repos gains an entry", () => {
      const previous = baseConfig();
      const current = clone(previous);
      current.git["allow-repos"] = [...(previous.git["allow-repos"] ?? []), "dario/other-repo"];
      const result = evaluateTrust(previous, current);
      expect(result.verdict).toBe("requires-confirmation");
      expect(result.widened).toContainEqual({ field: "git.allow-repos", description: "git.allow-repos gained 'dario/other-repo'" });
    });

    it("git.allow-push: false -> true", () => {
      const previous = baseConfig();
      const current = clone(previous);
      current.git["allow-push"] = true;
      const result = evaluateTrust(previous, current);
      expect(result.verdict).toBe("requires-confirmation");
      expect(result.widened).toContainEqual({ field: "git.allow-push", description: "git.allow-push changed from false to true" });
    });

    it("git.ssh-agent: false -> true", () => {
      const previous = baseConfig();
      previous.git["ssh-agent"] = false;
      const current = clone(previous);
      current.git["ssh-agent"] = true;
      const result = evaluateTrust(previous, current);
      expect(result.verdict).toBe("requires-confirmation");
      expect(result.widened).toContainEqual({ field: "git.ssh-agent", description: "git.ssh-agent changed from false to true" });
    });

    it("dir: a brand-new directory name appears, regardless of its mode", () => {
      const previous = baseConfig();
      const current = clone(previous);
      current.dir.push({ name: "reference", host: "~/Code/reference-docs", mode: "ro", rules: [] });
      const result = evaluateTrust(previous, current);
      expect(result.verdict).toBe("requires-confirmation");
      expect(result.widened).toContainEqual({ field: "dir.reference", description: "dir 'reference' added" });
    });

    it("dir: an existing directory changes mode from 'ro' to 'rw'", () => {
      const previous = baseConfig();
      const current = clone(previous);
      const scratch = current.dir.find((d) => d.name === "scratch");
      if (scratch === undefined) {
        throw new Error("test fixture missing 'scratch' dir");
      }
      scratch.mode = "rw";
      const result = evaluateTrust(previous, current);
      expect(result.verdict).toBe("requires-confirmation");
      expect(result.widened).toContainEqual({ field: "dir.scratch.mode", description: "dir 'scratch' mode changed from 'ro' to 'rw'" });
    });

    it("dir: an existing directory loses a rule present in the previous config", () => {
      const previous = baseConfig();
      const current = clone(previous);
      const corb = current.dir.find((d) => d.name === "corb");
      if (corb === undefined) {
        throw new Error("test fixture missing 'corb' dir");
      }
      corb.rules = [];
      const result = evaluateTrust(previous, current);
      expect(result.verdict).toBe("requires-confirmation");
      expect(result.widened).toContainEqual({
        field: "dir.corb.rules",
        description: "dir 'corb' lost rule '**/.env*' (hidden)",
      });
    });

    it("dir: rules reordered (same rules, different sequence) requires confirmation since enforcement is first-match-wins", () => {
      const previous = baseConfig();
      const corbPrev = previous.dir.find((d) => d.name === "corb");
      if (corbPrev === undefined) {
        throw new Error("test fixture missing 'corb' dir");
      }
      corbPrev.rules = [
        { glob: "secrets/**", mode: "hidden" },
        { glob: "**", mode: "deny-write" },
      ];
      const current = clone(previous);
      const corbCurr = current.dir.find((d) => d.name === "corb");
      if (corbCurr === undefined) {
        throw new Error("test fixture missing 'corb' dir");
      }
      corbCurr.rules = [
        { glob: "**", mode: "deny-write" },
        { glob: "secrets/**", mode: "hidden" },
      ];

      const result = evaluateTrust(previous, current);

      expect(result.verdict).toBe("requires-confirmation");
      expect(result.widened).toContainEqual({
        field: "dir.corb.rules",
        description: "dir 'corb' rules reordered (first-match-wins order changed; treated as widening)",
      });
      // The Set-membership diff must not fire here: no rule was actually
      // added or removed, only reordered.
      expect(result.widened.some((c) => c.description.includes("lost rule"))).toBe(false);
      expect(result.narrowed.some((c) => c.description.includes("gained rule"))).toBe(false);
    });

    it("dir: a broader rule prepended ahead of an existing rule requires confirmation (regression: previously misclassified as pure narrowing)", () => {
      const previous = baseConfig();
      const corbPrev = previous.dir.find((d) => d.name === "corb");
      if (corbPrev === undefined) {
        throw new Error("test fixture missing 'corb' dir");
      }
      corbPrev.rules = [{ glob: "**/.env", mode: "hidden" }];
      const current = clone(previous);
      const corbCurr = current.dir.find((d) => d.name === "corb");
      if (corbCurr === undefined) {
        throw new Error("test fixture missing 'corb' dir");
      }
      // The new rule is broader (`shadow-write` matches everything) and is
      // prepended *ahead of* the still-present `.env` rule. Nothing is lost
      // (`.env`'s rule is untouched), so a plain Set-membership diff sees
      // this as pure narrowing (one rule gained). But enforcement
      // (first-match-wins) now hits the prepended rule before ever reaching
      // `.env`'s, silently shadowing it -- this must require confirmation.
      corbCurr.rules = [
        { glob: "**", mode: "shadow-write" },
        { glob: "**/.env", mode: "hidden" },
      ];

      const result = evaluateTrust(previous, current);

      expect(result.verdict).toBe("requires-confirmation");
      expect(result.widened).toContainEqual({
        field: "dir.corb.rules",
        description:
          "dir 'corb' rules changed in a way that is not a safe append (first-match-wins order may have changed; treated as widening)",
      });
      // The rule causing the widening must not also be reported as a
      // separate, narrowing "gained rule" addition alongside the widening
      // flag -- that would misleadingly suggest part of this change is
      // safely narrowing when the whole change requires confirmation.
      expect(result.narrowed.some((c) => c.field === "dir.corb.rules")).toBe(false);
    });

    it("dir: a rule appended purely at the end (existing rule unchanged and in the same position) is trusted", () => {
      const previous = baseConfig();
      const corbPrev = previous.dir.find((d) => d.name === "corb");
      if (corbPrev === undefined) {
        throw new Error("test fixture missing 'corb' dir");
      }
      corbPrev.rules = [{ glob: "**/.env", mode: "hidden" }];
      const current = clone(previous);
      const corbCurr = current.dir.find((d) => d.name === "corb");
      if (corbCurr === undefined) {
        throw new Error("test fixture missing 'corb' dir");
      }
      corbCurr.rules = [
        { glob: "**/.env", mode: "hidden" },
        { glob: "**/*.log", mode: "deny-write" },
      ];

      const result = evaluateTrust(previous, current);

      expect(result.verdict).toBe("trusted");
      expect(result.narrowed).toContainEqual({
        field: "dir.corb.rules",
        description: "dir 'corb' gained rule '**/*.log' (deny-write)",
      });
      expect(result.widened.some((c) => c.field === "dir.corb.rules")).toBe(false);
    });

    it("dir: a rule inserted between two existing, unmoved rules requires confirmation", () => {
      const previous = baseConfig();
      const corbPrev = previous.dir.find((d) => d.name === "corb");
      if (corbPrev === undefined) {
        throw new Error("test fixture missing 'corb' dir");
      }
      corbPrev.rules = [
        { glob: "**/.env", mode: "hidden" },
        { glob: "**/*.log", mode: "deny-write" },
      ];
      const current = clone(previous);
      const corbCurr = current.dir.find((d) => d.name === "corb");
      if (corbCurr === undefined) {
        throw new Error("test fixture missing 'corb' dir");
      }
      // Both original rules are still present and in the same relative
      // order as each other -- only a plain Set-membership diff would call
      // this pure narrowing. A new rule landing strictly between two
      // untouched rules still breaks the prefix invariant (index 1 no
      // longer matches), so this must also require confirmation, exercising
      // a prefix mismatch past index 0 rather than at the very front.
      corbCurr.rules = [
        { glob: "**/.env", mode: "hidden" },
        { glob: "**", mode: "shadow-write" },
        { glob: "**/*.log", mode: "deny-write" },
      ];

      const result = evaluateTrust(previous, current);

      expect(result.verdict).toBe("requires-confirmation");
      expect(result.widened).toContainEqual({
        field: "dir.corb.rules",
        description:
          "dir 'corb' rules changed in a way that is not a safe append (first-match-wins order may have changed; treated as widening)",
      });
      expect(result.widened.some((c) => c.description.includes("lost rule"))).toBe(false);
      expect(result.narrowed.some((c) => c.field === "dir.corb.rules")).toBe(false);
    });

    it("policy.enabled: true -> false", () => {
      const previous = baseConfig();
      const current = clone(previous);
      current.policy.enabled = false;
      const result = evaluateTrust(previous, current);
      expect(result.verdict).toBe("requires-confirmation");
      expect(result.widened).toContainEqual({ field: "policy.enabled", description: "policy.enabled changed from true to false" });
    });

    it("policy['secret-scan']: true -> false", () => {
      const previous = baseConfig();
      const current = clone(previous);
      current.policy["secret-scan"] = false;
      const result = evaluateTrust(previous, current);
      expect(result.verdict).toBe("requires-confirmation");
      expect(result.widened).toContainEqual({ field: "policy.secret-scan", description: "policy.secret-scan changed from true to false" });
    });

    it("policy['fail-open']: false -> true", () => {
      const previous = baseConfig();
      const current = clone(previous);
      current.policy["fail-open"] = true;
      const result = evaluateTrust(previous, current);
      expect(result.verdict).toBe("requires-confirmation");
      expect(result.widened).toContainEqual({ field: "policy.fail-open", description: "policy.fail-open changed from false to true" });
    });

    it("policy['max-changed-files'] numerically increases", () => {
      const previous = baseConfig();
      const current = clone(previous);
      current.policy["max-changed-files"] = 100;
      const result = evaluateTrust(previous, current);
      expect(result.verdict).toBe("requires-confirmation");
      expect(result.widened).toContainEqual({
        field: "policy.max-changed-files",
        description: "policy.max-changed-files increased from 40 to 100",
      });
    });

    it("secrets gains a new entry", () => {
      const previous = baseConfig();
      const current = clone(previous);
      current.secrets = { ...current.secrets, NPM_TOKEN: { hosts: ["registry.npmjs.org"] } };
      const result = evaluateTrust(previous, current);
      expect(result.verdict).toBe("requires-confirmation");
      expect(result.widened).toContainEqual({ field: "secrets.NPM_TOKEN", description: "secret 'NPM_TOKEN' added" });
    });

    it("an existing secret entry's hosts list gains an entry", () => {
      const previous = baseConfig();
      const current = clone(previous);
      const token = current.secrets?.GITHUB_TOKEN;
      if (token === undefined) {
        throw new Error("test fixture missing GITHUB_TOKEN secret");
      }
      token.hosts = [...(token.hosts ?? []), "raw.githubusercontent.com"];
      const result = evaluateTrust(previous, current);
      expect(result.verdict).toBe("requires-confirmation");
      expect(result.widened).toContainEqual({
        field: "secrets.GITHUB_TOKEN.hosts",
        description: "secret 'GITHUB_TOKEN' gained host 'raw.githubusercontent.com'",
      });
    });
  });

  describe("dir.mode: all six transitions (absent means 'rw' downstream — src/commands/run.ts, src/vm/session.ts)", () => {
    function withScratchMode(config: EffectiveConfig, mode: "ro" | "rw" | undefined): EffectiveConfig {
      const next = clone(config);
      const scratch = next.dir.find((d) => d.name === "scratch");
      if (scratch === undefined) {
        throw new Error("test fixture missing 'scratch' dir");
      }
      if (mode === undefined) {
        delete scratch.mode;
      } else {
        scratch.mode = mode;
      }
      return next;
    }

    it("'ro' -> 'rw' is widening", () => {
      const previous = withScratchMode(baseConfig(), "ro");
      const current = withScratchMode(previous, "rw");
      const result = evaluateTrust(previous, current);
      expect(result.verdict).toBe("requires-confirmation");
      expect(result.widened).toContainEqual({ field: "dir.scratch.mode", description: "dir 'scratch' mode changed from 'ro' to 'rw'" });
    });

    it("'rw' -> 'ro' is narrowing", () => {
      const previous = withScratchMode(baseConfig(), "rw");
      const current = withScratchMode(previous, "ro");
      const result = evaluateTrust(previous, current);
      expect(result.verdict).toBe("trusted");
      expect(result.narrowed).toContainEqual({ field: "dir.scratch.mode", description: "dir 'scratch' mode changed from 'rw' to 'ro'" });
    });

    it("undefined -> 'rw' is a no-op (both mean rw)", () => {
      const previous = withScratchMode(baseConfig(), undefined);
      const current = withScratchMode(previous, "rw");
      const result = evaluateTrust(previous, current);
      expect(result.widened.some((c) => c.field.startsWith("dir.scratch"))).toBe(false);
      expect(result.narrowed.some((c) => c.field.startsWith("dir.scratch"))).toBe(false);
    });

    it("'rw' -> undefined is a no-op (both mean rw)", () => {
      const previous = withScratchMode(baseConfig(), "rw");
      const current = withScratchMode(previous, undefined);
      const result = evaluateTrust(previous, current);
      expect(result.widened.some((c) => c.field.startsWith("dir.scratch"))).toBe(false);
      expect(result.narrowed.some((c) => c.field.startsWith("dir.scratch"))).toBe(false);
    });

    it("undefined -> 'ro' is narrowing (regression: previously silently ignored)", () => {
      const previous = withScratchMode(baseConfig(), undefined);
      const current = withScratchMode(previous, "ro");
      const result = evaluateTrust(previous, current);
      expect(result.verdict).toBe("trusted");
      expect(result.narrowed).toContainEqual({ field: "dir.scratch.mode", description: "dir 'scratch' mode changed from 'rw' to 'ro'" });
    });

    it("'ro' -> undefined is widening (regression: deleting a 'mode = \"ro\"' line used to convert a read-only mount to read-write with no confirmation)", () => {
      const previous = withScratchMode(baseConfig(), "ro");
      const current = withScratchMode(previous, undefined);
      const result = evaluateTrust(previous, current);
      expect(result.verdict).toBe("requires-confirmation");
      expect(result.widened).toContainEqual({ field: "dir.scratch.mode", description: "dir 'scratch' mode changed from 'ro' to 'rw'" });
    });

    it("'ro' -> 'rw' reports exactly one mode change, not a second duplicate from the fallback rule", () => {
      const previous = withScratchMode(baseConfig(), "ro");
      const current = withScratchMode(previous, "rw");
      const result = evaluateTrust(previous, current);
      const modeChanges = [...result.widened, ...result.narrowed].filter((c) => c.field === "dir.scratch.mode");
      expect(modeChanges).toHaveLength(1);
    });
  });

  describe("fail-closed: a field with no RULES entry defaults to widening (deny-list fallback, not an allow-list)", () => {
    it("a new field on git.* is widening, not silently trusted", () => {
      const previous = baseConfig();
      const current = clone(previous) as EffectiveConfig & { git: EffectiveConfig["git"] & Record<string, unknown> };
      current.git["allow-force-push"] = true;
      const result = evaluateTrust(previous, current);
      expect(result.verdict).toBe("requires-confirmation");
      const unclassified = result.widened.find((c) => c.field === "git.allow-force-push");
      expect(unclassified).toBeDefined();
      expect(unclassified?.description).toContain("unclassified field");
    });

    it("a new field on policy.* is widening, not silently trusted", () => {
      const previous = baseConfig();
      const current = clone(previous) as EffectiveConfig & { policy: EffectiveConfig["policy"] & Record<string, unknown> };
      current.policy["skip-scan-for"] = ["**"];
      const result = evaluateTrust(previous, current);
      expect(result.verdict).toBe("requires-confirmation");
      const unclassified = result.widened.find((c) => c.field === "policy.skip-scan-for");
      expect(unclassified).toBeDefined();
    });

    it("a new field on egress.* outside the classified leaves is widening", () => {
      const previous = baseConfig();
      const current = clone(previous) as EffectiveConfig & { egress: EffectiveConfig["egress"] & Record<string, unknown> };
      current.egress["allow-dns"] = ["*"];
      const result = evaluateTrust(previous, current);
      expect(result.verdict).toBe("requires-confirmation");
      const unclassified = result.widened.find((c) => c.field === "egress.allow-dns");
      expect(unclassified).toBeDefined();
    });

    it("a new field on a dir[] entry is widening", () => {
      const previous = baseConfig();
      const current = clone(previous);
      const scratch = current.dir.find((d) => d.name === "scratch") as (typeof current.dir)[number] & Record<string, unknown>;
      if (scratch === undefined) {
        throw new Error("test fixture missing 'scratch' dir");
      }
      scratch["escape-hatch"] = true;
      const result = evaluateTrust(previous, current);
      expect(result.verdict).toBe("requires-confirmation");
      const unclassified = result.widened.find((c) => c.field === "dir.scratch.escape-hatch");
      expect(unclassified).toBeDefined();
    });

    it("a wholly new top-level field is widening", () => {
      const previous = baseConfig();
      const current = clone(previous) as EffectiveConfig & Record<string, unknown>;
      current.sandbox = { escape: true };
      const result = evaluateTrust(previous, current);
      expect(result.verdict).toBe("requires-confirmation");
      const unclassified = result.widened.find((c) => c.field === "sandbox");
      expect(unclassified).toBeDefined();
      expect(unclassified?.description).toContain("unclassified field");
    });
  });

  describe("policy['max-changed-files'] unset-vs-set direction (judgment call)", () => {
    it("unset -> a finite limit is a narrowing (a cap now exists where none did)", () => {
      const previous = baseConfig();
      delete previous.policy["max-changed-files"];
      const current = clone(previous);
      current.policy["max-changed-files"] = 40;
      const result = evaluateTrust(previous, current);
      expect(result.verdict).toBe("trusted");
      expect(result.narrowed).toContainEqual({
        field: "policy.max-changed-files",
        description: "policy.max-changed-files set to 40 (was unlimited)",
      });
    });

    it("a finite limit -> unset is a widening (the cap is removed)", () => {
      const previous = baseConfig();
      const current = clone(previous);
      delete current.policy["max-changed-files"];
      const result = evaluateTrust(previous, current);
      expect(result.verdict).toBe("requires-confirmation");
      expect(result.widened).toContainEqual({
        field: "policy.max-changed-files",
        description: "policy.max-changed-files removed (was 40, now unlimited)",
      });
    });
  });

  it("an unclassified field change (e.g. vm.memory) requires confirmation via the fallback rule", () => {
    const previous = baseConfig();
    const current = clone(previous);
    current.vm = { ...current.vm, memory: "8G" };
    const result = evaluateTrust(previous, current);
    expect(result.verdict).toBe("requires-confirmation");
    const unclassified = result.widened.find((c) => c.field === "vm.memory");
    expect(unclassified).toBeDefined();
    expect(unclassified?.description).toContain("unclassified field");
    expect(unclassified?.description).not.toContain("gained");
    expect(unclassified?.description).not.toContain("lost");
  });

  it("a secret's 'optional' flag flipping is an unclassified change (fallback widening), not silently ignored", () => {
    const previous = baseConfig();
    const current = clone(previous);
    const token = current.secrets?.GITHUB_TOKEN;
    if (token === undefined) {
      throw new Error("test fixture missing GITHUB_TOKEN secret");
    }
    token.optional = false;
    const result = evaluateTrust(previous, current);
    expect(result.verdict).toBe("requires-confirmation");
    const unclassified = result.widened.find((c) => c.field === "secrets.GITHUB_TOKEN.optional");
    expect(unclassified).toBeDefined();
    expect(unclassified?.description).toContain("unclassified field");
  });

  it("a change simultaneously widening in one field and narrowing in another overall requires confirmation", () => {
    const previous = baseConfig();
    const current = clone(previous);
    current.egress.allow = [...(previous.egress.allow ?? []), "registry.npmjs.org"];
    current.git["allow-hosts"] = [];
    const result = evaluateTrust(previous, current);
    expect(result.verdict).toBe("requires-confirmation");
    expect(result.widened.length).toBeGreaterThan(0);
    expect(result.narrowed.length).toBeGreaterThan(0);
    expect(result.narrowed).toContainEqual({ field: "git.allow-hosts", description: "git.allow-hosts lost 'github.com'" });
  });
});

describe("config/trust: hashEffectiveConfig", () => {
  it("produces the same hash for structurally-equal configs built with keys in different insertion order", () => {
    const configA: EffectiveConfig = {
      name: "corb-dev",
      egress: { allow: ["a", "b"], "block-internal-ranges": true, websockets: false },
      git: { "ssh-agent": true, "allow-push": false },
      dir: [{ name: "corb", host: "~/Code/corb", mode: "rw", rules: [{ glob: "a", mode: "hidden", reason: "r" }] }],
      policy: { enabled: true, "secret-scan": true, "fail-open": true },
    };
    const configB: EffectiveConfig = {
      policy: { "fail-open": true, enabled: true, "secret-scan": true },
      dir: [{ rules: [{ reason: "r", mode: "hidden", glob: "a" }], mode: "rw", host: "~/Code/corb", name: "corb" }],
      git: { "allow-push": false, "ssh-agent": true },
      egress: { websockets: false, "block-internal-ranges": true, allow: ["a", "b"] },
      name: "corb-dev",
    };
    expect(hashEffectiveConfig(configA)).toBe(hashEffectiveConfig(configB));
  });

  it("produces different hashes for different configs", () => {
    const configA = baseConfig();
    const configB = clone(configA);
    configB.egress.allow = ["api.anthropic.com"];
    expect(hashEffectiveConfig(configA)).not.toBe(hashEffectiveConfig(configB));
  });
});

describe("config/trust: recordAcceptance", () => {
  it("adds a new workspace record with the given timestamp, without mutating the original (empty) store", () => {
    const config = baseConfig();
    const store: TrustStore = {};
    const updated = recordAcceptance(store, "corb-dev", config, 1_700_000_000_000);
    expect(store).toEqual({});
    expect(updated).not.toBe(store);
    expect(updated["corb-dev"]).toEqual({
      configHash: hashEffectiveConfig(config),
      acceptedConfig: config,
      acceptedAt: 1_700_000_000_000,
    });
  });

  it("updates an existing store's entry without mutating the original store object", () => {
    const config1 = baseConfig();
    const store: TrustStore = {
      "corb-dev": { configHash: hashEffectiveConfig(config1), acceptedConfig: config1, acceptedAt: 1 },
    };
    const storeSnapshot = structuredClone(store);
    const config2 = baseConfig();
    config2.vm = { ...config2.vm, memory: "8G" };

    const updated = recordAcceptance(store, "corb-dev", config2, 2);

    expect(store).toEqual(storeSnapshot);
    expect(updated["corb-dev"]?.acceptedAt).toBe(2);
    expect(updated["corb-dev"]?.acceptedConfig).toEqual(config2);
  });

  it("does not mutate the config object passed in", () => {
    const config = baseConfig();
    const configSnapshot = structuredClone(config);
    recordAcceptance({}, "corb-dev", config, 1);
    expect(config).toEqual(configSnapshot);
  });
});
