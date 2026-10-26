import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { acceptWorkspace, resolveWorkspace } from "../../../src/config/resolve.ts";
import { renderJson, renderText, renderTrustedSnapshot } from "../../../src/config/render.ts";
import { evaluateTrust, recordAcceptance } from "../../../src/config/trust.ts";
import { mergeConfigLayers } from "../../../src/config/load.ts";
import { describeImpliedHostSource } from "../../../src/config/implied.ts";
import { hashLayerDefinition, normalizeLayerDefinition } from "../../../src/layer/definition.ts";
import { serializeLayerLock } from "../../../src/layer/pins.ts";
import { loadWorkspaceShow } from "../../../src/commands/workspace.ts";
import { runRunCommand } from "../../../src/commands/run.ts";
import { hash, pins } from "../layer/fixtures.ts";

let root: string;
let configDir: string;
let source: string;
let workspace: string;
let project: string;
let text: string;

beforeEach(() => {
  root = fs.mkdtempSync(path.join(os.tmpdir(), "corb-layer-config-"));
  configDir = path.join(root, "config");
  source = path.join(root, "source");
  workspace = path.join(source, "sdk");
  project = path.join(root, "project");
  for (const dir of [configDir, workspace, project]) fs.mkdirSync(dir, { recursive: true });
  vi.stubEnv("CORB_CONFIG_DIR", configDir);
  vi.stubEnv("CORB_STATE_DIR", path.join(root, "state"));
  vi.stubEnv("CORB_CACHE_DIR", path.join(root, "cache"));
  vi.stubEnv("GONDOLIN_IMAGE_STORE", path.join(root, "external-images"));
  fs.writeFileSync(path.join(configDir, "config.toml"), `[workspaces]\npaths = [${JSON.stringify(source)}]\n`);
  text = `[[dir]]\nname='project'\nhost=${JSON.stringify(project)}\n[image.layer]\npackages=['go']\n`;
  fs.writeFileSync(path.join(workspace, "corb.toml"), text);
});
afterEach(() => { vi.restoreAllMocks(); vi.unstubAllEnvs(); fs.rmSync(root, { recursive: true, force: true }); });
function resolve() { return resolveWorkspace(undefined, {}, { configDir, workspace: "sdk", targetArch: "x86_64" }); }
function lock(target = pins()) { fs.writeFileSync(path.join(workspace, "corb.sum"), serializeLayerLock({ version: 1, target: { x86_64: target } })); }

describe("layer trust and inspection", () => {
  it("inspects missing pins without a generation and includes the exact command hint", () => {
    const resolved = resolve();
    expect(resolved.persistentConfig.image?.layer.packages).toEqual(["go"]);
    expect(resolved.persistentConfig.image).not.toHaveProperty("pins");
    expect(renderText(resolved)).toContain("corb image pin --workspace sdk");
    expect(JSON.parse(renderJson(resolved)).imageLayer).toEqual({ definitionSha256: hashLayerDefinition(resolved.persistentConfig.image!.layer), pinsState: "missing", pinCommand: "corb image pin --workspace sdk" });
    expect(loadWorkspaceShow("sdk", configDir).error).toBeNull();
  });
  it("loads the winning workspace lock rather than cwd or a replaced source", () => {
    const shadow = path.join(root, "shadow");
    fs.mkdirSync(path.join(shadow, "sdk"), { recursive: true });
    fs.writeFileSync(path.join(shadow, "sdk", "corb.toml"), text);
    fs.writeFileSync(path.join(shadow, "sdk", "corb.sum"), "malformed");
    fs.writeFileSync(path.join(configDir, "config.toml"), `[workspaces]\npaths = ${JSON.stringify([shadow, source])}\n`);
    lock();
    expect(resolve().persistentConfig.image?.pins).toEqual(pins());
  });
  it("treats an absent selected architecture as missing pins", () => {
    const arm = pins();
    arm.index = arm.index.map((row) => ({ ...row, url: row.url.replace("x86_64", "aarch64") }));
    fs.writeFileSync(path.join(workspace, "corb.sum"), serializeLayerLock({ version: 1, target: { aarch64: arm } }));
    expect(resolve().persistentConfig.image).not.toHaveProperty("pins");
  });
  it("fails inspection on malformed or dangling selected pins", () => {
    fs.writeFileSync(path.join(workspace, "corb.sum"), "version=2\n[target]");
    expect(() => resolve()).toThrow("version = 1");
    expect(loadWorkspaceShow("sdk", configDir).error).toContain("version = 1");
    fs.unlinkSync(path.join(workspace, "corb.sum"));
    fs.symlinkSync("missing", path.join(workspace, "corb.sum"));
    expect(() => resolve()).toThrow("corb.sum");
  });
  it("omits the entire image without a layer and does not parse a malformed lock", () => {
    fs.writeFileSync(path.join(workspace, "corb.toml"), text.slice(0, text.indexOf("[image.layer]")));
    fs.writeFileSync(path.join(workspace, "corb.sum"), "malformed");
    const current = resolve();
    expect(current.fullConfig).not.toHaveProperty("image");
    acceptWorkspace(current.trustKey, current.persistentConfig, 1, { configDir });
    expect(resolve().trustEvaluation).toEqual({ verdict: "trusted", widened: [], narrowed: [] });
    fs.unlinkSync(path.join(workspace, "corb.sum"));
    fs.symlinkSync("missing", path.join(workspace, "corb.sum"));
    expect(() => resolve()).toThrow("corb.sum");
  });
  it("treats every definition or pin addition, edit or removal as widening", () => {
    const noLayer = mergeConfigLayers([]);
    const withoutPins = mergeConfigLayers([{ image: { layer: normalizeLayerDefinition({ packages: ["go"] }) } }]);
    const withPins = mergeConfigLayers([{ image: { layer: normalizeLayerDefinition({ packages: ["go"] }), pins: pins() } }]);
    for (const [before, after] of [[noLayer, withoutPins], [withoutPins, noLayer], [withoutPins, withPins], [withPins, withoutPins],
      [withPins, { ...withPins, image: { ...withPins.image!, pins: { ...pins(), artifact: `ghcr.io/org/layer@sha256:${hash()}` } } }],
      [withoutPins, { ...withoutPins, image: { layer: normalizeLayerDefinition({ packages: ["bash"] }) } }],
    ]) expect(evaluateTrust(before, after).verdict).toBe("requires-confirmation");
  });
  it("changes trust from pins alone and preserves unrelated target independence", () => {
    lock();
    const first = resolve();
    acceptWorkspace(first.trustKey, first.persistentConfig, 1, { configDir });
    const arm = pins();
    arm.index = arm.index.map((row) => ({ ...row, url: row.url.replace("x86_64", "aarch64") }));
    fs.writeFileSync(path.join(workspace, "corb.sum"), serializeLayerLock({ version: 1, target: { x86_64: pins(), aarch64: arm } }));
    expect(resolve().trustEvaluation.verdict).toBe("trusted");
    lock({ ...pins(), package: pins().package.map((row) => ({ ...row, version: row.requested ? "1.26.1-r0" : row.version })) });
    expect(resolve().trustEvaluation.verdict).toBe("requires-confirmation");
  });
  it("preserves lost built-in Git protection widening when directory mode narrows", () => {
    const before = mergeConfigLayers([{ dir: [{ name: "code", mode: "rw" }] }]);
    const after = mergeConfigLayers([{ dir: [{ name: "code", mode: "ro" }] }]);
    expect(evaluateTrust(before, after).verdict).toBe("requires-confirmation");
    expect(evaluateTrust(before, after).widened.some((change) => change.field.includes("builtin-rules"))).toBe(true);
  });
  it("keeps provider-first hosts and runtime-only host implication", () => {
    fs.writeFileSync(path.join(workspace, "corb.toml"), `${text}hosts=['chatgpt.com','sdk.example']\nbuild-hosts=['build.example']\n[agent]\nprovider='openai-codex'\n`);
    const resolved = resolve();
    expect(resolved.impliedHosts[0]?.source.kind).toBe("agent-provider");
    expect(resolved.impliedHosts.filter((entry) => entry.host === "chatgpt.com")).toHaveLength(1);
    expect(resolved.impliedHosts.find((entry) => entry.host === "sdk.example")?.source).toEqual({ kind: "image-layer", layer: "workspace", workspace: "sdk" });
    expect(resolved.fullConfig.egress.allow).not.toContain("build.example");
    expect(describeImpliedHostSource({ kind: "image-layer", layer: "workspace", workspace: "sdk" })).toBe('[image.layer] hosts in workspace "sdk"');
  });
  it("shows shareable recipes and pins in accepted snapshots without current source labels", () => {
    lock();
    const current = resolve();
    const record = recordAcceptance({}, "key", current.persistentConfig, 1).key!;
    const snapshot = renderTrustedSnapshot(record).join("\n");
    expect(snapshot).toContain("recipe-pins-sha256");
    expect(snapshot).toContain("definition-sha256");
    expect(snapshot).toContain("unpinned root install steps");
    expect(snapshot).not.toContain("implied by");
    expect(snapshot).not.toContain(source);
  });
  it("renders SDK and command order and runtime requests in accepted snapshots", () => {
    const layer = normalizeLayerDefinition({ packages: [], commands: ["echo second", "echo first"], payload: [{
      name: "sdk", url: "https://example.com/sdk.tar.gz", sha256: hash(), arch: "x86_64", destination: "/opt/corb/toolchains/sdk", path: ["tools", "bin"],
    }], "runtime-dir": [{ path: "/run/app", owner: "app", group: "app", mode: "0700" }] });
    const config = mergeConfigLayers([{ image: { layer } }]);
    const record = recordAcceptance({}, "key", config, 1).key!;
    const output = renderTrustedSnapshot(record).join("\n");
    expect(output).toContain("url=https://example.com/sdk.tar.gz");
    expect(output).toContain(`sha256=${hash()}`);
    expect(output).toContain("path=[tools, bin]");
    expect(output).toContain("/run/app: mode=0700 owner=app group=app");
    expect(output.indexOf("echo second")).toBeLessThan(output.indexOf("echo first"));
  });
  it("reports payload compatibility before a missing-pin or runtime operation", () => {
    fs.writeFileSync(path.join(workspace, "corb.toml"), text.replace("packages=['go']", "packages=[]") + `[[image.layer.payload]]\nname='sdk'\nurl='https://example.com/sdk.tar.gz'\nsha256='${hash()}'\narch='aarch64'\ndestination='/opt/corb/toolchains/sdk'\n`);
    expect(() => resolve()).toThrow("incompatible with selected target");
  });
  it("keeps dry-run usable and rejects a real run before accepting trust or booting", async () => {
    const log = vi.spyOn(console, "log").mockImplementation(() => {});
    await runRunCommand(["--workspace", "sdk", "--dry-run"]);
    expect(log).toHaveBeenCalledWith(expect.stringContaining("pins: missing"));
    await expect(runRunCommand(["--workspace", "sdk", "--trust-config"])).rejects.toThrow("image integration implementation");
    expect(fs.existsSync(path.join(configDir, "trusted.json"))).toBe(false);
  });
});

describe("layer cache mount protection", () => {
  it.each(["CORB_CACHE_DIR", "GONDOLIN_IMAGE_STORE"])("rejects both overlap directions and symlink aliases for %s", (variable) => {
    const store = process.env[variable]!;
    fs.mkdirSync(path.join(store, "nested"), { recursive: true });
    const alias = path.join(root, "alias");
    fs.symlinkSync(store, alias);
    for (const host of [store, path.join(store, "nested"), alias]) {
      expect(() => resolveWorkspace(undefined, { dir: [{ name: "extra", host, mode: "ro" }] }, { configDir, workspace: "sdk" })).toThrow(/cache directory|image store/);
    }
    const outer = path.join(root, "outer");
    vi.stubEnv(variable, path.join(outer, "store"));
    expect(() => resolveWorkspace(undefined, { dir: [{ name: "extra", host: outer }] }, { configDir, workspace: "sdk" })).toThrow(/cache directory|image store/);
  });
  it("covers positional and configured mounts and leaves no-layer cache behavior intact", () => {
    const cache = process.env.CORB_CACHE_DIR!;
    fs.mkdirSync(cache);
    expect(() => resolveWorkspace(cache, {}, { configDir, workspace: "sdk" })).toThrow("cache directory");
    fs.writeFileSync(path.join(workspace, "corb.toml"), text.replace(JSON.stringify(project), JSON.stringify(cache)));
    expect(() => resolve()).toThrow("cache directory");
    fs.writeFileSync(path.join(workspace, "corb.toml"), text.slice(0, text.indexOf("[image.layer]")));
    expect(() => resolveWorkspace(undefined, { dir: [{ name: "extra", host: cache }] }, { configDir, workspace: "sdk" })).not.toThrow();
  });
});
