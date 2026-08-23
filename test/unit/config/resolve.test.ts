// Unit tests for `src/config/resolve.ts` — M2.5/M2.6. Covers: no
// config.toml present (empty layer merged with the synthesized dir layer,
// no error), a real config.toml present and merged in, a malformed
// config.toml surfacing a clear error, no trusted.json present (empty
// store, first-time verdict), a trusted.json with a matching prior record
// for this exact directory's path (trusted, no changes), a trusted.json
// with a prior record showing a widening change (requires-confirmation,
// itemized), a malformed trusted.json surfacing a clear error rather than
// silently defaulting to an empty store — plus M2.6's persistent/full
// config split and `acceptWorkspace`'s write behavior.
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  ConfigReadError,
  TrustStoreError,
  WorkspaceDirectoryError,
  acceptWorkspace,
  resolveWorkspace,
} from "../../../src/config/resolve.ts";
import { ConfigParseError } from "../../../src/config/schema.ts";
import type { EffectiveConfig } from "../../../src/config/load.ts";

describe("config/resolve: resolveWorkspace", () => {
  let workDir: string;
  let configDir: string;

  beforeEach(() => {
    workDir = fs.mkdtempSync(path.join(os.tmpdir(), "corb-resolve-work-"));
    configDir = fs.mkdtempSync(path.join(os.tmpdir(), "corb-resolve-config-"));
  });

  afterEach(() => {
    fs.rmSync(workDir, { recursive: true, force: true });
    fs.rmSync(configDir, { recursive: true, force: true });
  });

  it("throws WorkspaceDirectoryError when the directory does not exist", () => {
    const missing = path.join(workDir, "does-not-exist");
    expect(() => resolveWorkspace(missing, {}, { configDir })).toThrow(WorkspaceDirectoryError);
  });

  it("throws WorkspaceDirectoryError when the path is not a directory", () => {
    const filePath = path.join(workDir, "not-a-dir");
    fs.writeFileSync(filePath, "hello");
    expect(() => resolveWorkspace(filePath, {}, { configDir })).toThrow(WorkspaceDirectoryError);
  });

  it("with no config.toml present, merges only the synthesized dir layer with BUILTIN_DEFAULTS — no error", () => {
    const resolved = resolveWorkspace(workDir, {}, { configDir });
    expect(resolved.dir).toBe(fs.realpathSync(workDir));
    expect(resolved.persistentConfig.dir).toEqual([
      { name: path.basename(workDir), host: resolved.dir, mode: "rw", rules: [] },
    ]);
    // BUILTIN_DEFAULTS structural defaults are present.
    expect(resolved.persistentConfig.egress["block-internal-ranges"]).toBe(true);
    expect(resolved.persistentConfig.policy.enabled).toBe(true);
  });

  it("with a real config.toml present, merges it under the synthesized dir layer", () => {
    fs.writeFileSync(
      path.join(configDir, "config.toml"),
      [
        'version = 1',
        'name = "corb-dev"',
        "",
        "[vm]",
        'image = "corb:0.1.0"',
        'memory = "4G"',
        "",
        "[egress]",
        'allow = ["api.anthropic.com"]',
      ].join("\n"),
    );

    const resolved = resolveWorkspace(workDir, {}, { configDir });
    expect(resolved.persistentConfig.version).toBe(1);
    expect(resolved.persistentConfig.name).toBe("corb-dev");
    expect(resolved.persistentConfig.vm).toEqual({ image: "corb:0.1.0", memory: "4G" });
    expect(resolved.persistentConfig.egress.allow).toEqual(["api.anthropic.com"]);
    expect(resolved.persistentConfig.dir).toEqual([
      { name: path.basename(workDir), host: resolved.dir, mode: "rw", rules: [] },
    ]);
  });

  it("a malformed config.toml surfaces a clear ConfigParseError", () => {
    fs.writeFileSync(path.join(configDir, "config.toml"), "this is not [ valid toml");
    expect(() => resolveWorkspace(workDir, {}, { configDir })).toThrow(ConfigParseError);
  });

  it("a config.toml that cannot be read for a non-ENOENT reason surfaces a clear ConfigReadError", () => {
    const tomlPath = path.join(configDir, "config.toml");
    fs.mkdirSync(tomlPath); // a directory where a file is expected -> EISDIR on readFile
    expect(() => resolveWorkspace(workDir, {}, { configDir })).toThrow(ConfigReadError);
  });

  it("with no trusted.json present, treats the trust store as empty and returns the first-time verdict", () => {
    const resolved = resolveWorkspace(workDir, {}, { configDir });
    expect(resolved.priorRecord).toBeUndefined();
    expect(resolved.trustEvaluation.verdict).toBe("requires-confirmation");
    expect(resolved.trustEvaluation.widened).toEqual([
      { field: "workspace", description: "no prior trust record exists for this workspace; treated as first-time widening" },
    ]);
  });

  it("a trusted.json with a matching prior record for this exact directory's key is trusted, with no changes", () => {
    const resolvedDir = fs.realpathSync(workDir);
    const priorConfig: EffectiveConfig = resolveWorkspace(workDir, {}, { configDir }).persistentConfig;
    fs.writeFileSync(
      path.join(configDir, "trusted.json"),
      JSON.stringify({
        [resolvedDir]: { configHash: "irrelevant-for-evaluateTrust", acceptedConfig: priorConfig, acceptedAt: 1000 },
      }),
    );

    const resolved = resolveWorkspace(workDir, {}, { configDir });
    expect(resolved.trustKey).toBe(resolvedDir);
    expect(resolved.priorRecord).toBeDefined();
    expect(resolved.trustEvaluation.verdict).toBe("trusted");
    expect(resolved.trustEvaluation.widened).toEqual([]);
    expect(resolved.trustEvaluation.narrowed).toEqual([]);
  });

  it("a trusted.json with a prior record showing a widening change is requires-confirmation, itemized", () => {
    const resolvedDir = fs.realpathSync(workDir);
    const priorConfig: EffectiveConfig = resolveWorkspace(workDir, {}, { configDir }).persistentConfig;
    // Simulate a previously-accepted config that was *more* restrictive on egress than now.
    const narrowerPrior: EffectiveConfig = { ...priorConfig, egress: { ...priorConfig.egress, allow: [] } };
    fs.writeFileSync(
      path.join(configDir, "trusted.json"),
      JSON.stringify({
        [resolvedDir]: { configHash: "irrelevant-for-evaluateTrust", acceptedConfig: narrowerPrior, acceptedAt: 1000 },
      }),
    );
    fs.writeFileSync(path.join(configDir, "config.toml"), ['[egress]', 'allow = ["api.anthropic.com"]'].join("\n"));

    const resolved = resolveWorkspace(workDir, {}, { configDir });
    expect(resolved.trustEvaluation.verdict).toBe("requires-confirmation");
    expect(resolved.trustEvaluation.widened).toEqual([
      { field: "egress.allow", description: "egress.allow gained 'api.anthropic.com'" },
    ]);
  });

  it("a malformed trusted.json (invalid JSON) surfaces a clear TrustStoreError, not a silent empty store", () => {
    fs.writeFileSync(path.join(configDir, "trusted.json"), "{ this is not json");
    expect(() => resolveWorkspace(workDir, {}, { configDir })).toThrow(TrustStoreError);
  });

  it("a malformed trusted.json (wrong shape) surfaces a clear TrustStoreError", () => {
    fs.writeFileSync(path.join(configDir, "trusted.json"), JSON.stringify(["not", "a", "map"]));
    expect(() => resolveWorkspace(workDir, {}, { configDir })).toThrow(TrustStoreError);
  });

  it("a malformed trusted.json (entry missing required fields) surfaces a clear TrustStoreError", () => {
    fs.writeFileSync(
      path.join(configDir, "trusted.json"),
      JSON.stringify({ "/some/dir": { configHash: "abc" } }),
    );
    expect(() => resolveWorkspace(workDir, {}, { configDir })).toThrow(TrustStoreError);
  });

  it("defaults configDir to corbConfigDir() (CORB_CONFIG_DIR) when opts.configDir is not passed", () => {
    const previous = process.env.CORB_CONFIG_DIR;
    process.env.CORB_CONFIG_DIR = configDir;
    try {
      const resolved = resolveWorkspace(workDir, {});
      expect(resolved.persistentConfig.dir[0]?.name).toBe(path.basename(workDir));
    } finally {
      if (previous === undefined) {
        delete process.env.CORB_CONFIG_DIR;
      } else {
        process.env.CORB_CONFIG_DIR = previous;
      }
    }
  });

  describe("persistent vs. full config", () => {
    it("cliLayer: {} produces fullConfig structurally equal to persistentConfig", () => {
      fs.writeFileSync(path.join(configDir, "config.toml"), 'name = "corb-dev"\n');
      const resolved = resolveWorkspace(workDir, {}, { configDir });
      expect(resolved.fullConfig).toEqual(resolved.persistentConfig);
    });

    it("a non-empty cliLayer adds a dir to fullConfig.dir but leaves trustEvaluation computed as if it didn't exist", () => {
      const priorConfig = resolveWorkspace(workDir, {}, { configDir }).persistentConfig;
      const resolvedDir = fs.realpathSync(workDir);
      fs.writeFileSync(
        path.join(configDir, "trusted.json"),
        JSON.stringify({
          [resolvedDir]: { configHash: "irrelevant", acceptedConfig: priorConfig, acceptedAt: 1000 },
        }),
      );

      const otherDir = fs.mkdtempSync(path.join(os.tmpdir(), "corb-resolve-extra-"));
      try {
        const resolved = resolveWorkspace(workDir, { dir: [{ name: "extra", host: otherDir, mode: "ro" }] }, { configDir });
        expect(resolved.fullConfig.dir).toEqual([
          ...resolved.persistentConfig.dir,
          { name: "extra", host: otherDir, mode: "ro", rules: [] },
        ]);
        // Trust is unaffected by the CLI-added 'extra' dir: still trusted, no changes.
        expect(resolved.trustEvaluation.verdict).toBe("trusted");
        expect(resolved.trustEvaluation.widened).toEqual([]);
        expect(resolved.trustEvaluation.narrowed).toEqual([]);
      } finally {
        fs.rmSync(otherDir, { recursive: true, force: true });
      }
    });

    it("re-merging a persistent config that already includes BUILTIN_DEFAULTS' values doesn't perturb them", () => {
      const resolved = resolveWorkspace(workDir, {}, { configDir });
      // BUILTIN_DEFAULTS values survive being merged in twice (once inside
      // resolveWorkspace's persistentConfig, once again inside
      // mergeConfigLayers([persistentConfig, cliLayer])).
      expect(resolved.fullConfig.egress["block-internal-ranges"]).toBe(true);
      expect(resolved.fullConfig.egress.websockets).toBe(false);
      expect(resolved.fullConfig.git["ssh-agent"]).toBe(true);
      expect(resolved.fullConfig.git["allow-push"]).toBe(false);
      expect(resolved.fullConfig.policy.enabled).toBe(true);
      expect(resolved.fullConfig.policy["secret-scan"]).toBe(true);
      expect(resolved.fullConfig.policy["fail-open"]).toBe(true);
    });
  });

  describe("acceptWorkspace", () => {
    it("writes a real file to configDir, and a subsequent resolveWorkspace call sees the updated trust store", () => {
      const resolved = resolveWorkspace(workDir, {}, { configDir });
      expect(resolved.trustEvaluation.verdict).toBe("requires-confirmation");

      acceptWorkspace(resolved.trustKey, resolved.persistentConfig, 12345, { configDir });

      expect(fs.existsSync(path.join(configDir, "trusted.json"))).toBe(true);
      const reResolved = resolveWorkspace(workDir, {}, { configDir });
      expect(reResolved.trustEvaluation.verdict).toBe("trusted");
      expect(reResolved.priorRecord?.acceptedAt).toBe(12345);
    });

    it("creates the config directory if it doesn't exist yet", () => {
      const freshConfigDir = path.join(configDir, "not-yet-created");
      const resolved = resolveWorkspace(workDir, {}, { configDir: freshConfigDir });

      expect(fs.existsSync(freshConfigDir)).toBe(false);
      acceptWorkspace(resolved.trustKey, resolved.persistentConfig, 999, { configDir: freshConfigDir });
      expect(fs.existsSync(path.join(freshConfigDir, "trusted.json"))).toBe(true);
    });
  });
});
