// Unit tests for `src/config/resolve.ts` — M2.5. Covers: no config.toml
// present (empty layer merged with the synthesized dir layer, no error), a
// real config.toml present and merged in, a malformed config.toml surfacing
// a clear error, no trusted.json present (empty store, first-time verdict),
// a trusted.json with a matching prior record for this exact directory's
// path (trusted, no changes), a trusted.json with a prior record showing a
// widening change (requires-confirmation, itemized), and a malformed
// trusted.json surfacing a clear error rather than silently defaulting to an
// empty store.
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  ConfigReadError,
  TrustStoreError,
  WorkspaceDirectoryError,
  resolveWorkspaceForDirectory,
} from "../../../src/config/resolve.ts";
import { ConfigParseError } from "../../../src/config/schema.ts";
import type { EffectiveConfig } from "../../../src/config/load.ts";

describe("config/resolve: resolveWorkspaceForDirectory", () => {
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
    expect(() => resolveWorkspaceForDirectory(missing, { configDir })).toThrow(WorkspaceDirectoryError);
  });

  it("throws WorkspaceDirectoryError when the path is not a directory", () => {
    const filePath = path.join(workDir, "not-a-dir");
    fs.writeFileSync(filePath, "hello");
    expect(() => resolveWorkspaceForDirectory(filePath, { configDir })).toThrow(WorkspaceDirectoryError);
  });

  it("with no config.toml present, merges only the synthesized dir layer with BUILTIN_DEFAULTS — no error", () => {
    const resolved = resolveWorkspaceForDirectory(workDir, { configDir });
    expect(resolved.dir).toBe(fs.realpathSync(workDir));
    expect(resolved.effectiveConfig.dir).toEqual([
      { name: path.basename(workDir), host: resolved.dir, mode: "rw", rules: [] },
    ]);
    // BUILTIN_DEFAULTS structural defaults are present.
    expect(resolved.effectiveConfig.egress["block-internal-ranges"]).toBe(true);
    expect(resolved.effectiveConfig.policy.enabled).toBe(true);
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

    const resolved = resolveWorkspaceForDirectory(workDir, { configDir });
    expect(resolved.effectiveConfig.version).toBe(1);
    expect(resolved.effectiveConfig.name).toBe("corb-dev");
    expect(resolved.effectiveConfig.vm).toEqual({ image: "corb:0.1.0", memory: "4G" });
    expect(resolved.effectiveConfig.egress.allow).toEqual(["api.anthropic.com"]);
    expect(resolved.effectiveConfig.dir).toEqual([
      { name: path.basename(workDir), host: resolved.dir, mode: "rw", rules: [] },
    ]);
  });

  it("a malformed config.toml surfaces a clear ConfigParseError", () => {
    fs.writeFileSync(path.join(configDir, "config.toml"), "this is not [ valid toml");
    expect(() => resolveWorkspaceForDirectory(workDir, { configDir })).toThrow(ConfigParseError);
  });

  it("a config.toml that cannot be read for a non-ENOENT reason surfaces a clear ConfigReadError", () => {
    const tomlPath = path.join(configDir, "config.toml");
    fs.mkdirSync(tomlPath); // a directory where a file is expected -> EISDIR on readFile
    expect(() => resolveWorkspaceForDirectory(workDir, { configDir })).toThrow(ConfigReadError);
  });

  it("with no trusted.json present, treats the trust store as empty and returns the first-time verdict", () => {
    const resolved = resolveWorkspaceForDirectory(workDir, { configDir });
    expect(resolved.priorRecord).toBeUndefined();
    expect(resolved.trustEvaluation.verdict).toBe("requires-confirmation");
    expect(resolved.trustEvaluation.widened).toEqual([
      { field: "workspace", description: "no prior trust record exists for this workspace; treated as first-time widening" },
    ]);
  });

  it("a trusted.json with a matching prior record for this exact directory's key is trusted, with no changes", () => {
    const resolvedDir = fs.realpathSync(workDir);
    const priorConfig: EffectiveConfig = resolveWorkspaceForDirectory(workDir, { configDir }).effectiveConfig;
    fs.writeFileSync(
      path.join(configDir, "trusted.json"),
      JSON.stringify({
        [resolvedDir]: { configHash: "irrelevant-for-evaluateTrust", acceptedConfig: priorConfig, acceptedAt: 1000 },
      }),
    );

    const resolved = resolveWorkspaceForDirectory(workDir, { configDir });
    expect(resolved.trustKey).toBe(resolvedDir);
    expect(resolved.priorRecord).toBeDefined();
    expect(resolved.trustEvaluation.verdict).toBe("trusted");
    expect(resolved.trustEvaluation.widened).toEqual([]);
    expect(resolved.trustEvaluation.narrowed).toEqual([]);
  });

  it("a trusted.json with a prior record showing a widening change is requires-confirmation, itemized", () => {
    const resolvedDir = fs.realpathSync(workDir);
    const priorConfig: EffectiveConfig = resolveWorkspaceForDirectory(workDir, { configDir }).effectiveConfig;
    // Simulate a previously-accepted config that was *more* restrictive on egress than now.
    const narrowerPrior: EffectiveConfig = { ...priorConfig, egress: { ...priorConfig.egress, allow: [] } };
    fs.writeFileSync(
      path.join(configDir, "trusted.json"),
      JSON.stringify({
        [resolvedDir]: { configHash: "irrelevant-for-evaluateTrust", acceptedConfig: narrowerPrior, acceptedAt: 1000 },
      }),
    );
    fs.writeFileSync(path.join(configDir, "config.toml"), ['[egress]', 'allow = ["api.anthropic.com"]'].join("\n"));

    const resolved = resolveWorkspaceForDirectory(workDir, { configDir });
    expect(resolved.trustEvaluation.verdict).toBe("requires-confirmation");
    expect(resolved.trustEvaluation.widened).toEqual([
      { field: "egress.allow", description: "egress.allow gained 'api.anthropic.com'" },
    ]);
  });

  it("a malformed trusted.json (invalid JSON) surfaces a clear TrustStoreError, not a silent empty store", () => {
    fs.writeFileSync(path.join(configDir, "trusted.json"), "{ this is not json");
    expect(() => resolveWorkspaceForDirectory(workDir, { configDir })).toThrow(TrustStoreError);
  });

  it("a malformed trusted.json (wrong shape) surfaces a clear TrustStoreError", () => {
    fs.writeFileSync(path.join(configDir, "trusted.json"), JSON.stringify(["not", "a", "map"]));
    expect(() => resolveWorkspaceForDirectory(workDir, { configDir })).toThrow(TrustStoreError);
  });

  it("a malformed trusted.json (entry missing required fields) surfaces a clear TrustStoreError", () => {
    fs.writeFileSync(
      path.join(configDir, "trusted.json"),
      JSON.stringify({ "/some/dir": { configHash: "abc" } }),
    );
    expect(() => resolveWorkspaceForDirectory(workDir, { configDir })).toThrow(TrustStoreError);
  });

  it("defaults configDir to corbConfigDir() (CORB_CONFIG_DIR) when opts.configDir is not passed", () => {
    const previous = process.env.CORB_CONFIG_DIR;
    process.env.CORB_CONFIG_DIR = configDir;
    try {
      const resolved = resolveWorkspaceForDirectory(workDir);
      expect(resolved.effectiveConfig.dir[0]?.name).toBe(path.basename(workDir));
    } finally {
      if (previous === undefined) {
        delete process.env.CORB_CONFIG_DIR;
      } else {
        process.env.CORB_CONFIG_DIR = previous;
      }
    }
  });
});
