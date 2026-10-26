import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, expect, it, vi } from "vitest";
const state = vi.hoisted(() => ({ base: vi.fn(), graph: vi.fn(), verified: vi.fn(), current: vi.fn(), authenticate: vi.fn(), builder: vi.fn(), guest: vi.fn() }));
vi.mock("../../../src/layer/local-base.ts", async (load) => ({ ...await load<object>(), resolveLayerBase: state.base, requireLayerExecution: () => {} }));
vi.mock("../../../src/layer/graph.ts", async (load) => ({ ...await load<object>(), inputsForContext: state.graph }));
vi.mock("../../../src/layer/vm.ts", async (load) => ({ ...await load<object>(), verifyLayerBase: state.verified, withLayerVm: state.builder, layerGuest: state.guest }));
vi.mock("../../../src/layer/generation.ts", async (load) => ({ ...await load<object>(), currentGeneration: state.current }));
vi.mock("../../../src/layer/prepare.ts", async (load) => ({ ...await load<object>(), authenticateGraph: state.authenticate }));
import { composeLayer } from "../../../src/layer/compose.ts";
import { selectLayerWorkspace } from "../../../src/layer/context.ts";
import { hashLayerDefinition } from "../../../src/layer/definition.ts";
import { refreshLayerPins } from "../../../src/layer/pins.ts";
const dirs: string[] = [];
afterEach(() => { vi.restoreAllMocks(); vi.unstubAllEnvs(); vi.clearAllMocks(); for (const dir of dirs.splice(0)) fs.rmSync(dir, { recursive: true, force: true }); });
it("removes only owned staging when generation setup fails", async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "corb-compose-crash-")); dirs.push(root); const config = path.join(root, "config"); const workspace = path.join(config, "workspaces", "named");
  fs.mkdirSync(workspace, { recursive: true }); fs.writeFileSync(path.join(workspace, "corb.toml"), '[image.layer]\npackages=[]\ncommands=["true"]\n');
  vi.stubEnv("CORB_CONFIG_DIR", config); vi.stubEnv("CORB_STATE_DIR", path.join(root, "state")); vi.stubEnv("CORB_CACHE_DIR", path.join(root, "cache"));
  const initial = selectLayerWorkspace("named"); refreshLayerPins(workspace, "x86_64", { os: "linux", abi: "musl", "alpine-branch": "v3.23", "definition-sha256": hashLayerDefinition(initial.definition), index: [], package: [] });
  const context = selectLayerWorkspace("named");
  state.base.mockResolvedValue({ manifest: { buildId: "8d1ad38c-602a-50b2-a6b4-247a2b6824bc", config: { arch: "x86_64" } } }); state.graph.mockResolvedValue({ digest: "sha256:" + "a".repeat(64) }); state.current.mockResolvedValue(undefined); state.verified.mockResolvedValue({ baseline: {} });
  const mkdir = fs.mkdirSync;
  vi.spyOn(fs, "mkdirSync").mockImplementation(((directory: string, options: fs.MakeDirectoryOptions) => { if (/generations\/[a-f0-9-]+$/.test(directory)) throw Object.assign(new Error("generation permission failure"), { code: "EACCES" }); return mkdir(directory, options); }) as typeof fs.mkdirSync);
  await expect(composeLayer(context)).rejects.toThrow("generation permission failure");
  expect(fs.readdirSync(path.join(root, "cache/layer-inputs/v1/staging"))).toEqual([]);
});

it("removes its builder disk and a partial destination when SDK checkpoint creation fails", async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "corb-checkpoint-crash-")); dirs.push(root);
  const workspace = path.join(root, "config/workspaces/named"); fs.mkdirSync(workspace, { recursive: true });
  fs.writeFileSync(path.join(workspace, "corb.toml"), '[image.layer]\npackages=[]\ncommands=["true"]\n');
  vi.stubEnv("CORB_CONFIG_DIR", path.join(root, "config")); vi.stubEnv("CORB_STATE_DIR", path.join(root, "state")); vi.stubEnv("CORB_CACHE_DIR", path.join(root, "cache"));
  const initial = selectLayerWorkspace("named"); refreshLayerPins(workspace, "x86_64", { os: "linux", abi: "musl", "alpine-branch": "v3.23", "definition-sha256": hashLayerDefinition(initial.definition), index: [], package: [] });
  const baseId = "8d1ad38c-602a-50b2-a6b4-247a2b6824bc"; const raw = path.join(root, "rootfs"); fs.writeFileSync(raw, Buffer.alloc(4096));
  state.base.mockResolvedValue({ manifest: { buildId: baseId, config: { arch: "x86_64" } }, assets: { rootfs: { path: raw } } }); state.graph.mockResolvedValue({ digest: "sha256:" + "a".repeat(64) }); state.current.mockResolvedValue(undefined); state.verified.mockResolvedValue({ baseline: { packages: [] } });
  state.authenticate.mockResolvedValue({ payloads: [], archives: [], input: root });
  state.guest.mockImplementation(async (_vm, action) => action === "database" ? { database: "", world: "" } : action === "runtime" ? [] : action === "record" ? { sha256: "a".repeat(64) } : { path: "/bin" });
  let source: string | undefined; let destination: string | undefined;
  state.builder.mockImplementation(async (_base, _label, _hosts, callback, options) => {
    source = options.builderDisk; expect(fs.statSync(source!).isFile()).toBe(true);
    return callback({ exec: async () => ({ ok: true, stdout: "", stderr: "" }), getHostPid: () => 123,
      checkpoint: async (filename: string) => { destination = filename; fs.writeFileSync(filename, "partial trailer"); throw Error("checkpoint write failed"); } });
  });
  const parent = path.join(root, "state/layers/named/x86_64/bases", baseId); fs.mkdirSync(parent, { recursive: true });
  const pointer = path.join(parent, "current.json"); fs.writeFileSync(pointer, "previous current");
  await expect(composeLayer(selectLayerWorkspace("named"))).rejects.toThrow("checkpoint write failed");
  expect(fs.existsSync(source!)).toBe(false); expect(fs.existsSync(destination!)).toBe(false); expect(fs.readFileSync(pointer, "utf8")).toBe("previous current");
  expect(fs.readdirSync(path.join(root, "cache/layer-inputs/v1/staging"))).toEqual([]);
});
