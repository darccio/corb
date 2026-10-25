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
import { builtinGitRules } from "../../../src/config/gitprotect.ts";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  ConfigReadError,
  ForbiddenMountError,
  TrustStoreError,
  WorkspaceDirectoryError,
  acceptWorkspace,
  resolveWorkspace,
} from "../../../src/config/resolve.ts";
import { ConfigParseError } from "../../../src/config/schema.ts";
import type { EffectiveConfig } from "../../../src/config/load.ts";
import { hashEffectiveConfig } from "../../../src/config/trust.ts";

describe("config/resolve: workspace source guard", () => {
  let root: string;
  let configDir: string;
  let source: string;
  let workDir: string;
  const previousStateDir = process.env.CORB_STATE_DIR;

  beforeEach(() => {
    root = fs.mkdtempSync(path.join(os.tmpdir(), "corb-source-guard-"));
    configDir = path.join(root, "config");
    source = path.join(root, "source");
    workDir = path.join(root, "work");
    for (const dir of [configDir, source, workDir]) fs.mkdirSync(dir);
    process.env.CORB_STATE_DIR = path.join(root, "state");
    writeSources([source]);
  });

  afterEach(() => {
    if (previousStateDir === undefined) delete process.env.CORB_STATE_DIR;
    else process.env.CORB_STATE_DIR = previousStateDir;
    fs.rmSync(root, { recursive: true, force: true });
  });

  function writeSources(paths: string[], extra = "") {
    fs.writeFileSync(path.join(configDir, "config.toml"), `[workspaces]\npaths = ${JSON.stringify(paths)}\n${extra}`);
  }

  function mount(host: string) {
    return () => resolveWorkspace(workDir, { dir: [{ name: "mounted", host }] }, { configDir });
  }

  function workspace(parent: string, name: string): string {
    const dir = path.join(parent, name);
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(path.join(dir, "corb.toml"), "");
    return dir;
  }

  it("rejects mounts equal to, inside, or containing a source", () => {
    const nested = path.join(source, "nested");
    fs.mkdirSync(nested);
    for (const host of [source, nested]) expect(mount(host)).toThrow("workspace source directory");
    const parent = path.join(root, "external");
    const childSource = path.join(parent, "definitions");
    fs.mkdirSync(childSource, { recursive: true });
    writeSources([childSource]);
    expect(mount(parent)).toThrow("workspace source directory");
  });

  it("rejects a child whose name starts with two dots without rejecting siblings", () => {
    const nested = path.join(source, "..cache");
    const sibling = `${source}-sibling`;
    fs.mkdirSync(nested);
    fs.mkdirSync(sibling);
    expect(mount(nested)).toThrow("workspace source directory");
    expect(mount(sibling)).not.toThrow();
  });

  it("protects a symlinked default source through its target and its original path", () => {
    const checkout = path.join(root, "checkout");
    const target = path.join(checkout, "definitions");
    fs.mkdirSync(target, { recursive: true });
    const alias = path.join(configDir, "workspaces");
    fs.symlinkSync(target, alias);
    fs.writeFileSync(path.join(configDir, "config.toml"), "");
    expect(mount(checkout)).toThrow("workspace source directory");
    expect(mount(alias)).toThrow(ForbiddenMountError);
  });

  it("rejects a mount host that is a symlink to a source", () => {
    const alias = path.join(root, "alias");
    fs.symlinkSync(source, alias);
    expect(mount(alias)).toThrow("workspace source directory");
  });

  it("protects missing sources when their parent is mounted", () => {
    const parent = path.join(root, "external");
    fs.mkdirSync(parent);
    writeSources([path.join(parent, "missing")]);
    expect(mount(parent)).toThrow("workspace source directory");
  });

  it.each(["project", "bad name"])("protects symlinked workspace %s and both overlap directions", (name) => {
    const parent = path.join(root, "outside");
    const target = workspace(parent, "target");
    const nested = path.join(target, "nested");
    fs.mkdirSync(nested);
    fs.symlinkSync(target, path.join(source, name));
    for (const host of [parent, target, nested]) expect(mount(host)).toThrow("workspace directory");
  });

  it("protects replaced workspace directories and their external configuration files", () => {
    const firstTarget = workspace(root, "old-target");
    const otherSource = path.join(root, "second-source");
    workspace(otherSource, "project");
    fs.symlinkSync(firstTarget, path.join(source, "project"));
    const files = path.join(root, "old-files");
    fs.mkdirSync(files);
    const toml = path.join(files, "config.toml");
    fs.writeFileSync(toml, "");
    fs.unlinkSync(path.join(firstTarget, "corb.toml"));
    fs.symlinkSync(toml, path.join(firstTarget, "corb.toml"));
    writeSources([source, otherSource]);
    expect(mount(firstTarget)).toThrow("workspace directory");
    expect(mount(files)).toThrow("workspace file");
  });

  it.each(["corb.toml", "corb.sum"])("protects an external target of %s", (filename) => {
    const dir = workspace(source, "project");
    const files = path.join(root, "external-files");
    fs.mkdirSync(files);
    const target = path.join(files, filename);
    fs.writeFileSync(target, "");
    if (filename === "corb.toml") fs.unlinkSync(path.join(dir, filename));
    fs.symlinkSync(target, path.join(dir, filename));
    expect(mount(files)).toThrow("workspace file");
  });

  it("checks global entries, CLI entries, and the positional directory", () => {
    writeSources([source], `\n[[dir]]\nname = "source"\nhost = ${JSON.stringify(source)}`);
    expect(() => resolveWorkspace(workDir, {}, { configDir })).toThrow(ForbiddenMountError);
    writeSources([source]);
    expect(mount(source)).toThrow(ForbiddenMountError);
    expect(() => resolveWorkspace(source, {}, { configDir })).toThrow(ForbiddenMountError);
  });

  it("fails the run on a listing error and keeps unrelated directories usable", () => {
    expect(mount(workDir)).not.toThrow();
    const file = path.join(root, "source-file");
    fs.writeFileSync(file, "");
    writeSources([file]);
    expect(() => resolveWorkspace(workDir, {}, { configDir })).toThrow("not a directory");
  });

  it("lists workspaces without layering their settings or hashing source configuration", () => {
    workspace(source, "project");
    fs.writeFileSync(path.join(source, "project", "corb.toml"), 'name = "not-applied"\n[git]\nallow-push = true');
    const resolved = resolveWorkspace(workDir, {}, { configDir });
    expect(resolved.workspaces.workspaces[0]?.name).toBe("project");
    expect(resolved.persistentConfig.name).toBeUndefined();
    expect(resolved.persistentConfig.git["allow-push"]).toBe(false);
    expect(resolved.persistentConfig).not.toHaveProperty("workspaces");
    acceptWorkspace(resolved.trustKey, resolved.persistentConfig, 1, { configDir });
    writeSources([]);
    expect(resolveWorkspace(workDir, {}, { configDir }).trustEvaluation.verdict).toBe("trusted");
  });
});

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
      { name: path.basename(workDir), host: resolved.dir, mode: "rw", "builtin-rules": builtinGitRules(), rules: [] },
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
      { name: path.basename(workDir), host: resolved.dir, mode: "rw", "builtin-rules": builtinGitRules(), rules: [] },
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
        [resolvedDir]: { configHash: hashEffectiveConfig(priorConfig), acceptedConfig: priorConfig, acceptedAt: 1000 },
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
        [resolvedDir]: { configHash: hashEffectiveConfig(narrowerPrior), acceptedConfig: narrowerPrior, acceptedAt: 1000 },
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

  describe("implied provider hosts", () => {
    function writeConfig(provider: string, allow: string[] = []): void {
      fs.writeFileSync(path.join(configDir, "config.toml"), [
        "[agent]", `provider = ${JSON.stringify(provider)}`, "[egress]", `allow = ${JSON.stringify(allow)}`,
      ].join("\n"));
    }

    it("adds the host before trust and includes it in both configs", () => {
      writeConfig("openai-codex", ["pi.dev"]);
      const resolved = resolveWorkspace(workDir, {}, { configDir });
      expect(resolved.persistentConfig.egress.allow).toEqual(["pi.dev", "chatgpt.com"]);
      expect(resolved.fullConfig.egress.allow).toEqual(["pi.dev", "chatgpt.com"]);
      expect(resolved.impliedHosts).toEqual([{
        host: "chatgpt.com",
        source: { kind: "agent-provider", provider: "openai-codex", layer: "global" },
      }]);
    });

    it("does not duplicate or mark an explicitly allowed host as implied", () => {
      writeConfig("openai-codex", ["chatgpt.com"]);
      const resolved = resolveWorkspace(workDir, {}, { configDir });
      expect(resolved.persistentConfig.egress.allow).toEqual(["chatgpt.com"]);
      expect(resolved.fullConfig.egress.allow).toEqual(["chatgpt.com"]);
      expect(resolved.impliedHosts).toEqual([]);
    });

    it("reports both a provider change and its newly allowed host as widening", () => {
      writeConfig("anthropic");
      const previous = resolveWorkspace(workDir, {}, { configDir });
      acceptWorkspace(previous.trustKey, previous.persistentConfig, 1000, { configDir });
      writeConfig("openai-codex");
      const resolved = resolveWorkspace(workDir, {}, { configDir });
      expect(resolved.trustEvaluation.verdict).toBe("requires-confirmation");
      expect(resolved.trustEvaluation.widened).toEqual(expect.arrayContaining([
        expect.objectContaining({ field: "agent.provider" }),
        { field: "egress.allow", description: "egress.allow gained 'chatgpt.com'" },
      ]));
    });

    it("keeps a prior codex record trusted when it already allowed the host", () => {
      writeConfig("openai-codex", ["chatgpt.com"]);
      const previous = resolveWorkspace(workDir, {}, { configDir });
      acceptWorkspace(previous.trustKey, previous.persistentConfig, 1000, { configDir });
      writeConfig("openai-codex");
      const resolved = resolveWorkspace(workDir, {}, { configDir });
      expect(resolved.trustEvaluation.verdict).toBe("trusted");
      expect(resolved.trustEvaluation.widened).toEqual([]);
    });

    it("stores implied hosts in accepted config without storing source metadata", () => {
      writeConfig("openai-codex");
      const resolved = resolveWorkspace(workDir, {}, { configDir });
      acceptWorkspace(resolved.trustKey, resolved.persistentConfig, 1000, { configDir });
      const stored = JSON.parse(fs.readFileSync(path.join(configDir, "trusted.json"), "utf8"))[resolved.trustKey];
      expect(stored.acceptedConfig.egress.allow).toEqual(["chatgpt.com"]);
      expect(stored.acceptedConfig).not.toHaveProperty("impliedHosts");
      expect(resolveWorkspace(workDir, {}, { configDir }).trustEvaluation.verdict).toBe("trusted");
    });

    it("requires acceptance once for an old codex record that never allowed the host", () => {
      writeConfig("openai-codex");
      const resolved = resolveWorkspace(workDir, {}, { configDir });
      const oldConfig = structuredClone(resolved.persistentConfig);
      oldConfig.egress.allow = [];
      acceptWorkspace(resolved.trustKey, oldConfig, 1000, { configDir });
      const widened = resolveWorkspace(workDir, {}, { configDir });
      expect(widened.trustEvaluation.widened).toEqual([
        { field: "egress.allow", description: "egress.allow gained 'chatgpt.com'" },
      ]);
      acceptWorkspace(widened.trustKey, widened.persistentConfig, 2000, { configDir });
      expect(resolveWorkspace(workDir, {}, { configDir }).trustEvaluation.verdict).toBe("trusted");
    });
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
          [resolvedDir]: { configHash: hashEffectiveConfig(priorConfig), acceptedConfig: priorConfig, acceptedAt: 1000 },
        }),
      );

      const otherDir = fs.mkdtempSync(path.join(os.tmpdir(), "corb-resolve-extra-"));
      try {
        const resolved = resolveWorkspace(workDir, { dir: [{ name: "extra", host: otherDir, mode: "ro" }] }, { configDir });
        expect(resolved.fullConfig.dir).toEqual([
          ...resolved.persistentConfig.dir,
          { name: "extra", host: otherDir, mode: "ro", "builtin-rules": [], rules: [] },
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

  describe("mount host paths overlapping Corb's own config/state dirs are refused", () => {
    let stateDir: string;
    let previousStateDir: string | undefined;

    beforeEach(() => {
      stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "corb-resolve-state-"));
      previousStateDir = process.env.CORB_STATE_DIR;
      process.env.CORB_STATE_DIR = stateDir;
    });

    afterEach(() => {
      if (previousStateDir === undefined) {
        delete process.env.CORB_STATE_DIR;
      } else {
        process.env.CORB_STATE_DIR = previousStateDir;
      }
      fs.rmSync(stateDir, { recursive: true, force: true });
    });

    it("a --dir whose host is exactly the config dir is rejected", () => {
      expect(() =>
        resolveWorkspace(workDir, { dir: [{ name: "cfg", host: configDir, mode: "rw" }] }, { configDir }),
      ).toThrow(ForbiddenMountError);
    });

    it("a --dir whose host is exactly the state dir is rejected", () => {
      expect(() =>
        resolveWorkspace(workDir, { dir: [{ name: "state", host: stateDir, mode: "rw" }] }, { configDir }),
      ).toThrow(ForbiddenMountError);
    });

    it("a --dir whose host is an ancestor of the config dir is rejected", () => {
      const ancestor = path.dirname(fs.realpathSync(configDir));
      expect(() =>
        resolveWorkspace(workDir, { dir: [{ name: "home", host: ancestor, mode: "rw" }] }, { configDir }),
      ).toThrow(ForbiddenMountError);
    });

    it("a --dir whose host is a path *inside* the config dir is rejected", () => {
      const nested = path.join(configDir, "workspaces");
      fs.mkdirSync(nested);
      expect(() =>
        resolveWorkspace(workDir, { dir: [{ name: "nested", host: nested, mode: "rw" }] }, { configDir }),
      ).toThrow(ForbiddenMountError);
    });

    it("a symlink pointing at the config dir is rejected (realpath, not lexical, comparison)", () => {
      const linkParent = fs.mkdtempSync(path.join(os.tmpdir(), "corb-resolve-symlink-"));
      const link = path.join(linkParent, "config-alias");
      fs.symlinkSync(configDir, link);
      try {
        expect(() =>
          resolveWorkspace(workDir, { dir: [{ name: "alias", host: link, mode: "rw" }] }, { configDir }),
        ).toThrow(ForbiddenMountError);
      } finally {
        fs.rmSync(linkParent, { recursive: true, force: true });
      }
    });

    it("a config.toml [[dir]] entry (not just --dir) whose host overlaps is also rejected", () => {
      fs.writeFileSync(
        path.join(configDir, "config.toml"),
        ['[[dir]]', 'name = "cfg"', `host = ${JSON.stringify(configDir)}`, 'mode = "rw"'].join("\n"),
      );
      expect(() => resolveWorkspace(workDir, {}, { configDir })).toThrow(ForbiddenMountError);
    });

    it("an explicit audit.path set to a location inside a --dir mount's host is rejected", () => {
      const mountDir = fs.mkdtempSync(path.join(os.tmpdir(), "corb-resolve-mount-"));
      try {
        const auditPath = path.join(mountDir, "audit.jsonl");
        expect(() =>
          resolveWorkspace(
            workDir,
            { dir: [{ name: "mount", host: mountDir, mode: "rw" }], audit: { path: auditPath } },
            { configDir },
          ),
        ).toThrow(ForbiddenMountError);
      } finally {
        fs.rmSync(mountDir, { recursive: true, force: true });
      }
    });

    it("a config.toml [[dir]] entry plus config.toml [audit] path (not just --dir/cliLayer) inside it is also rejected", () => {
      const mountDir = fs.mkdtempSync(path.join(os.tmpdir(), "corb-resolve-mount-"));
      try {
        const auditPath = path.join(mountDir, "audit.jsonl");
        fs.writeFileSync(
          path.join(configDir, "config.toml"),
          [
            "[[dir]]",
            'name = "mount"',
            `host = ${JSON.stringify(mountDir)}`,
            'mode = "rw"',
            "",
            "[audit]",
            `path = ${JSON.stringify(auditPath)}`,
          ].join("\n"),
        );
        expect(() => resolveWorkspace(workDir, {}, { configDir })).toThrow(ForbiddenMountError);
      } finally {
        fs.rmSync(mountDir, { recursive: true, force: true });
      }
    });

    it("an audit.path that is itself a symlink whose target lands inside a mount is rejected (realpath, not lexical)", () => {
      const mountDir = fs.mkdtempSync(path.join(os.tmpdir(), "corb-resolve-mount-"));
      const linkParent = fs.mkdtempSync(path.join(os.tmpdir(), "corb-resolve-auditlink-"));
      try {
        const target = path.join(mountDir, "audit.jsonl");
        fs.writeFileSync(target, "");
        const auditLink = path.join(linkParent, "audit-alias.jsonl");
        fs.symlinkSync(target, auditLink);

        expect(() =>
          resolveWorkspace(
            workDir,
            { dir: [{ name: "mount", host: mountDir, mode: "rw" }], audit: { path: auditLink } },
            { configDir },
          ),
        ).toThrow(ForbiddenMountError);
      } finally {
        fs.rmSync(mountDir, { recursive: true, force: true });
        fs.rmSync(linkParent, { recursive: true, force: true });
      }
    });

    it("an audit.path with a symlinked ancestor directory that resolves inside a mount is rejected", () => {
      const mountDir = fs.mkdtempSync(path.join(os.tmpdir(), "corb-resolve-mount-"));
      const linkParent = fs.mkdtempSync(path.join(os.tmpdir(), "corb-resolve-auditlink-"));
      try {
        const realSubdir = path.join(mountDir, "logs");
        fs.mkdirSync(realSubdir);
        const ancestorAlias = path.join(linkParent, "logs-alias");
        fs.symlinkSync(realSubdir, ancestorAlias);
        // The leaf file itself deliberately does not exist yet, matching the
        // real first-run case: `ensureOpen()` (src/policy/audit.ts) creates
        // it lazily on the first `record()` call, well after `resolveWorkspace`
        // has already run this check.
        const auditPath = path.join(ancestorAlias, "audit.jsonl");

        expect(() =>
          resolveWorkspace(
            workDir,
            { dir: [{ name: "mount", host: mountDir, mode: "rw" }], audit: { path: auditPath } },
            { configDir },
          ),
        ).toThrow(ForbiddenMountError);
      } finally {
        fs.rmSync(mountDir, { recursive: true, force: true });
        fs.rmSync(linkParent, { recursive: true, force: true });
      }
    });

    it("an explicit audit.path outside every mount does not throw", () => {
      const mountDir = fs.mkdtempSync(path.join(os.tmpdir(), "corb-resolve-mount-"));
      const auditParent = fs.mkdtempSync(path.join(os.tmpdir(), "corb-resolve-auditdir-"));
      try {
        const auditPath = path.join(auditParent, "audit.jsonl");
        expect(() =>
          resolveWorkspace(
            workDir,
            { dir: [{ name: "mount", host: mountDir, mode: "rw" }], audit: { path: auditPath } },
            { configDir },
          ),
        ).not.toThrow();
      } finally {
        fs.rmSync(mountDir, { recursive: true, force: true });
        fs.rmSync(auditParent, { recursive: true, force: true });
      }
    });

    it("a sibling path merely sharing a name prefix with the config dir is accepted", () => {
      const sibling = `${configDir}-sibling`;
      fs.mkdirSync(sibling);
      try {
        expect(() =>
          resolveWorkspace(workDir, { dir: [{ name: "sibling", host: sibling, mode: "rw" }] }, { configDir }),
        ).not.toThrow();
      } finally {
        fs.rmSync(sibling, { recursive: true, force: true });
      }
    });

    it("a normal workspace directory unrelated to config/state dirs is accepted", () => {
      expect(() => resolveWorkspace(workDir, {}, { configDir })).not.toThrow();
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

    it("writes trusted.json with 0600 permissions (src/util/secure-write.ts)", () => {
      const resolved = resolveWorkspace(workDir, {}, { configDir });
      acceptWorkspace(resolved.trustKey, resolved.persistentConfig, 12345, { configDir });

      const mode = fs.statSync(path.join(configDir, "trusted.json")).mode & 0o777;
      expect(mode).toBe(0o600);
    });
  });
});

describe("config/resolve: workspace selection and layering", () => {
  let root: string;
  let configDir: string;
  let source: string;
  let projects: string;
  let workDir: string;
  let previousHome: string | undefined;
  let previousState: string | undefined;

  beforeEach(() => {
    root = fs.mkdtempSync(path.join(os.tmpdir(), "corb-layering-"));
    configDir = path.join(root, "config");
    source = path.join(root, "definitions");
    projects = path.join(root, "projects");
    workDir = path.join(projects, "outside");
    for (const dir of [configDir, source, workDir]) fs.mkdirSync(dir, { recursive: true });
    previousHome = process.env.HOME;
    previousState = process.env.CORB_STATE_DIR;
    process.env.HOME = root;
    process.env.CORB_STATE_DIR = path.join(root, "state");
    global();
  });

  afterEach(() => {
    if (previousHome === undefined) delete process.env.HOME;
    else process.env.HOME = previousHome;
    if (previousState === undefined) delete process.env.CORB_STATE_DIR;
    else process.env.CORB_STATE_DIR = previousState;
    fs.rmSync(root, { recursive: true, force: true });
  });

  function global(text = "", rootPath?: string) {
    fs.writeFileSync(path.join(configDir, "config.toml"), `${text}\n[workspaces]\npaths = ${JSON.stringify([source])}\n${rootPath === undefined ? "" : `projects-root = ${JSON.stringify(rootPath)}\n`}`);
  }

  function workspace(text: string, name = "team") {
    const dir = path.join(source, name);
    fs.mkdirSync(dir, { recursive: true });
    const file = path.join(dir, "corb.toml");
    fs.writeFileSync(file, text);
    return file;
  }

  function resolve(dir: string | undefined = workDir, cli = {}, extra = {}) {
    return resolveWorkspace(dir, cli, { configDir, workspace: "team", ...extra });
  }

  function host(name = "app", host = path.join(projects, "app"), extra = "") {
    return `[[dir]]\nname = ${JSON.stringify(name)}\nhost = ${JSON.stringify(host)}\n${extra}`;
  }

  it("layers every table while retaining additive values and global directory entries", () => {
    const globalMount = path.join(projects, "global");
    const oldApp = path.join(projects, "old-app");
    const newApp = path.join(projects, "app");
    global(`version = 1
name = "global"
[vm]
image = "global:1"
memory = "1G"
cpus = 1
max-session = "1h"
[vm.limits]
memory-max = "2G"
pids-max = 10
cpu-quota = "50%"
[agent]
provider = "anthropic"
model = "global-model"
[secrets.TOKEN]
hosts = ["old.example"]
optional = false
[secrets.TOKEN.verify]
url = "https://old.example/verify"
header = "X-Old"
expect-status = [200]
[egress]
allow = ["global.example"]
allow-internal = ["internal.global"]
block-internal-ranges = true
websockets = false
[egress.github-api]
hosts = ["global.api"]
methods = ["GET"]
deny-paths = ["/old"]
[git]
allow-hosts = ["global.git"]
allow-repos = ["global/repo"]
ssh-agent = true
allow-push = false
${host("global", globalMount, 'mode = "ro"')}
${host("app", oldApp, 'mode = "ro"\ncreate = false\nprotect-git = false\nrules = [{ glob = "global", mode = "deny-write" }]')}
[policy]
enabled = true
secret-scan = true
max-changed-files = 10
fail-open = false
[audit]
path = ${JSON.stringify(path.join(root, "old-audit"))}`);
    workspace(`version = 1
name = "team-label"
[vm]
image = "workspace:2"
memory = "2G"
cpus = 2
max-session = "2h"
[vm.limits]
memory-max = "3G"
pids-max = 20
cpu-quota = "75%"
[agent]
provider = "openai-codex"
model = "workspace-model"
[secrets.TOKEN]
hosts = ["new.example"]
optional = true
[secrets.TOKEN.verify]
url = "https://new.example/check"
header = "X-New"
expect-status = [204]
[secrets.OTHER]
hosts = ["other.example"]
[egress]
allow = ["workspace.example"]
allow-internal = ["internal.workspace"]
block-internal-ranges = false
websockets = true
[egress.github-api]
hosts = ["workspace.api"]
methods = ["POST"]
deny-paths = ["/new"]
[git]
allow-hosts = ["workspace.git"]
allow-repos = ["workspace/repo"]
ssh-agent = false
allow-push = true
${host("app", newApp, 'mode = "rw"\ncreate = true\nprotect-git = true\nrules = [{ glob = "workspace", mode = "hidden" }]')}
[policy]
enabled = false
secret-scan = false
max-changed-files = 20
fail-open = true
[audit]
path = ${JSON.stringify(path.join(root, "new-audit"))}`);
    const result = resolve();
    const config = result.persistentConfig;
    expect(config).toMatchObject({
      version: 1, name: "team-label",
      vm: { image: "workspace:2", memory: "2G", cpus: 2, "max-session": "2h", limits: { "memory-max": "3G", "pids-max": 20, "cpu-quota": "75%" } },
      agent: { provider: "openai-codex", model: "workspace-model" },
      secrets: { TOKEN: { hosts: ["new.example"], optional: true, verify: { url: "https://new.example/check", header: "X-New", "expect-status": [204] } }, OTHER: { hosts: ["other.example"] } },
      egress: { allow: ["global.example", "workspace.example", "chatgpt.com"], "allow-internal": ["internal.global", "internal.workspace"], "block-internal-ranges": false, websockets: true, "github-api": { hosts: ["global.api", "workspace.api"], methods: ["GET", "POST"], "deny-paths": ["/old", "/new"] } },
      git: { "allow-hosts": ["global.git", "workspace.git"], "allow-repos": ["global/repo", "workspace/repo"], "ssh-agent": false, "allow-push": true },
      policy: { enabled: false, "secret-scan": false, "max-changed-files": 20, "fail-open": true },
      audit: { path: path.join(root, "new-audit") },
    });
    expect(config.dir.map((entry) => entry.name)).toEqual(["global", "app", "outside"]);
    expect(config.dir[0]).toMatchObject({ name: "global", host: globalMount, mode: "ro" });
    expect(config.dir[1]).toEqual({ name: "app", host: newApp, mode: "rw", create: true, "protect-git": true, rules: [{ glob: "global", mode: "deny-write" }, { glob: "workspace", mode: "hidden" }], "builtin-rules": builtinGitRules() });
    expect(result.fullConfig.dir[1]?.["builtin-rules"]).toEqual(builtinGitRules());
    expect(result.impliedHosts).toEqual([{ host: "chatgpt.com", source: { kind: "agent-provider", provider: "openai-codex", layer: "global" } }]);
    expect(config).not.toHaveProperty("workspaces");
    expect(config).not.toHaveProperty("selectedWorkspace");
    expect(result.selectedWorkspace).toMatchObject({ name: "team", selectedBy: "name", source: { index: 0, raw: source, path: source }, corbToml: path.join(source, "team", "corb.toml") });
  });

  it("selects an inside path without adding a mount and uses the deepest host", () => {
    const app = path.join(projects, "app");
    const deep = path.join(app, "deep");
    const child = path.join(deep, "child");
    fs.mkdirSync(child, { recursive: true });
    workspace(`${host("outer", app)}\n${host("inner", deep, 'mode = "ro"')}`);
    const result = resolveWorkspace(child, {}, { configDir });
    expect(result.selectedWorkspace?.selectedBy).toBe("path");
    expect(result.primary).toBe("inner");
    expect(result.persistentConfig.dir.map((entry) => entry.name)).toEqual(["outer", "inner"]);
    expect(result.positionalDirAdded).toBe(false);
    expect(result.trustKey).toBe(`workspace:team:${deep}`);
  });

  it("uses only workspace-owned hosts for selection and inside matching", () => {
    global(host("outside", workDir, 'mode = "ro"'));
    workspace('[[dir]]\nname = "outside"\nprotect-git = false');
    expect(resolveWorkspace(workDir, {}, { configDir }).selectedWorkspace).toBeUndefined();
    expect(() => resolve()).toThrow("Use --dir NAME=HOST");
  });

  it("a host-less basename entry is allowed when adding the positional mount", () => {
    workspace('[[dir]]\nname = "outside"\nprotect-git = false');
    const result = resolve();
    expect(result.primary).toBe("outside");
    expect(result.persistentConfig.dir[0]).toMatchObject({ name: "outside", host: workDir, "protect-git": false });
    expect(result.trustKey).toBe(`workspace:team:${workDir}`);
  });

  it("rejects a hosted basename collision in the global or workspace layer", () => {
    workspace(host("outside"));
    expect(() => resolve()).toThrow("Use --dir NAME=HOST");
    global(host("outside"));
    workspace("");
    expect(() => resolve()).toThrow("Use --dir NAME=HOST");
  });

  it("keeps non-workspace positional basename overrides unchanged", () => {
    global(host("outside", path.join(projects, "other"), 'mode = "ro"'));
    const result = resolveWorkspace(workDir, {}, { configDir });
    expect(result.selectedWorkspace).toBeUndefined();
    expect(result.trustKey).toBe(workDir);
    expect(result.persistentConfig.dir[0]).toMatchObject({ host: workDir, mode: "rw" });
  });

  it("named selection without DIR uses its first own host and never adds cwd", () => {
    global(host("global", path.join(projects, "global")));
    workspace(`[[dir]]\nname = "hostless"\n${host("app")}\n${host("second", path.join(projects, "second"))}`);
    const result = resolveWorkspace(undefined, {}, { configDir, workspace: "team" });
    expect(result.dir).toBeUndefined();
    expect(result.primary).toBe("app");
    expect(result.positionalDirAdded).toBe(false);
    expect(result.persistentConfig.dir.map((entry) => entry.name)).toEqual(["global", "hostless", "app", "second"]);
    expect(result.trustKey).toBe(`workspace:team:${path.join(projects, "app")}`);
  });

  it("requires an explicit primary when a named workspace has no own host", () => {
    global(host("global", workDir));
    workspace("");
    expect(() => resolveWorkspace(undefined, {}, { configDir, workspace: "team" })).toThrow("no hosted directory of its own");
    const result = resolveWorkspace(undefined, {}, { configDir, workspace: "team", primary: "global" });
    expect(result.primary).toBe("global");
    expect(result.trustKey).toBe(`workspace:team:${workDir}`);
    const cli = resolveWorkspace(undefined, { dir: [{ name: "cli", host: workDir }] }, { configDir, workspace: "team", primary: "cli" });
    expect(cli.primary).toBe("cli");
    expect(cli.persistentConfig.dir.some((entry) => entry.name === "cli")).toBe(false);
  });

  it("requires a directory or explicit workspace name", () => {
    expect(() => resolveWorkspace(undefined, {}, { configDir })).toThrow("a directory or --workspace");
  });

  it("reports workspace read failures with ConfigReadError and the real file path", () => {
    const file = workspace(host());
    const original = fs.readFileSync;
    const read = vi.spyOn(fs, "readFileSync").mockImplementation((...args: Parameters<typeof fs.readFileSync>) => {
      if (args[0] === file) throw new Error("permission denied");
      return original(...args);
    });
    try {
      expect(() => resolve()).toThrow(ConfigReadError);
      expect(() => resolve()).toThrow(file);
    } finally {
      read.mockRestore();
    }
  });

  it("canonicalizes a symlinked workspace host for shared subdirectory trust", () => {
    const app = path.join(projects, "app");
    const first = path.join(app, "one");
    const second = path.join(app, "two");
    fs.mkdirSync(first, { recursive: true });
    fs.mkdirSync(second);
    const alias = path.join(root, "alias");
    fs.symlinkSync(app, alias);
    workspace(host("app", alias));
    const initial = resolveWorkspace(first, {}, { configDir });
    acceptWorkspace(initial.trustKey, initial.persistentConfig, 1, { configDir });
    const next = resolveWorkspace(path.join(alias, "two"), {}, { configDir });
    expect(initial.trustKey).toBe(`workspace:team:${app}`);
    expect(next.trustKey).toBe(initial.trustKey);
    expect(next.trustEvaluation.verdict).toBe("trusted");
  });

  it("shares one trust record across subdirectories and never reuses a path record", () => {
    const app = path.join(projects, "app");
    const first = path.join(app, "one");
    const second = path.join(app, "two");
    fs.mkdirSync(first, { recursive: true });
    fs.mkdirSync(second);
    workspace(host());
    const initial = resolveWorkspace(first, {}, { configDir });
    acceptWorkspace(app, initial.persistentConfig, 1, { configDir });
    expect(resolveWorkspace(first, {}, { configDir }).trustEvaluation.verdict).toBe("requires-confirmation");
    acceptWorkspace(initial.trustKey, initial.persistentConfig, 2, { configDir });
    const next = resolveWorkspace(second, {}, { configDir });
    expect(next.trustKey).toBe(initial.trustKey);
    expect(next.trustEvaluation.verdict).toBe("trusted");
    expect(next.priorRecord?.acceptedAt).toBe(2);
  });

  it.each([
    ['[egress]\nallow = ["one.example"]', '[egress]\nallow = ["one.example", "two.example"]', "egress.allow"],
    [host("app", path.join(os.tmpdir(), "corb-ro"), 'mode = "ro"'), host("app", path.join(os.tmpdir(), "corb-ro"), 'mode = "rw"'), "dir.app.mode"],
    [host("app", path.join(os.tmpdir(), "corb-old")), host("app", path.join(os.tmpdir(), "corb-new")), "dir.app.host"],
    ['[secrets.TOKEN]\nhosts = ["one.example"]', '[secrets.TOKEN]\nhosts = ["two.example"]', "secrets.TOKEN.hosts"],
  ])("requires confirmation for a workspace edit to %s", (before, after, field) => {
    workspace(before);
    const initial = resolve();
    acceptWorkspace(initial.trustKey, initial.persistentConfig, 1, { configDir });
    workspace(after);
    const edited = resolve();
    expect(edited.trustEvaluation.verdict).toBe("requires-confirmation");
    expect(edited.trustEvaluation.widened.some((change) => change.field === field)).toBe(true);
  });

  it("trusts narrowing after a workspace edit and keeps CLI settings outside trust", () => {
    workspace('[egress]\nallow = ["one.example", "two.example"]');
    const initial = resolve();
    acceptWorkspace(initial.trustKey, initial.persistentConfig, 1, { configDir });
    workspace('[egress]\nallow = ["one.example"]');
    const result = resolve(workDir, { egress: { allow: ["cli.example"] }, dir: [{ name: "extra", host: path.join(projects, "extra") }] });
    expect(result.trustEvaluation.verdict).toBe("trusted");
    expect(result.trustEvaluation.narrowed).not.toHaveLength(0);
    expect(result.persistentConfig.egress.allow).toEqual(["one.example"]);
    expect(result.fullConfig.egress.allow).toEqual(["one.example", "cli.example"]);
    expect(result.persistentConfig.dir.map((entry) => entry.name)).toEqual(["outside"]);
  });

  it("expands global and workspace hosts with home and projects-root before trust", () => {
    global(host("global", "$HOME/projects/global"), "~/projects");
    workspace(host("app", "app"));
    const result = resolve();
    expect(result.persistentConfig.dir[0]?.host).toBe(path.join(projects, "global"));
    expect(result.persistentConfig.dir[1]?.host).toBe(path.join(projects, "app"));
    expect(result.workspaces.projectsRoot).toBe(projects);
  });

  it("rejects a relative global host without projects-root", () => {
    global(host("global", "relative"));
    expect(() => resolveWorkspace(workDir, {}, { configDir })).toThrow("config.toml");
    expect(() => resolveWorkspace(workDir, {}, { configDir })).toThrow("not resolved against the current directory");
  });

  it.each(["config", "state", "definitions"])("guards expanded home and relative hosts that overlap %s", (protectedDir) => {
    global("", "~");
    workspace(host("protected", `~/${protectedDir}`));
    expect(() => resolve()).toThrow(ForbiddenMountError);
    workspace(host("protected", protectedDir));
    expect(() => resolve()).toThrow(ForbiddenMountError);
  });

  it("an inside mount retains its own Git rules and ignores a basename-only setting", () => {
    const app = path.join(projects, "app");
    const child = path.join(app, "child");
    fs.mkdirSync(child, { recursive: true });
    global('[[dir]]\nname = "child"\nprotect-git = false');
    workspace(host());
    const result = resolveWorkspace(child, {}, { configDir });
    expect(result.primary).toBe("app");
    expect(result.persistentConfig.dir.find((entry) => entry.name === "app")?.["builtin-rules"]).toEqual(builtinGitRules());
    expect(result.persistentConfig.dir.find((entry) => entry.name === "child")?.host).toBeUndefined();
  });
});
