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
import { afterEach, beforeEach, describe, expect, it } from "vitest";
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
