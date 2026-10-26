import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, expect, it, vi } from "vitest";
const state = vi.hoisted(() => ({ staging: vi.fn(), preflight: vi.fn(), inputs: vi.fn() }));
vi.mock("../../../src/layer/prepare.ts", async (load) => ({ ...await load<object>(), ownedLayerStaging: state.staging }));
vi.mock("../../../src/layer/graph.ts", async (load) => ({ ...await load<object>(), inputsForContext: state.inputs }));
vi.mock("../../../src/layer/generation.ts", async (load) => ({ ...await load<object>(), preflightComposition: state.preflight }));
import { runLayerPush } from "../../../src/commands/image-layer-transport.ts";
import { acquireWorkspaceLock } from "../../../src/layer/state.ts";
const dirs: string[] = [];
afterEach(() => { vi.restoreAllMocks(); vi.unstubAllEnvs(); vi.clearAllMocks(); for (const dir of dirs.splice(0)) fs.rmSync(dir, { recursive: true, force: true }); });
it("releases the writer after failed staging setup and permits a retry", async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "corb-layer-crash-")); dirs.push(root); const config = path.join(root, "config"); const workspace = path.join(config, "workspaces", "named");
  fs.mkdirSync(workspace, { recursive: true }); fs.writeFileSync(path.join(workspace, "corb.toml"), '[image.layer]\npackages=[]\ncommands=["true"]\n');
  vi.stubEnv("CORB_CONFIG_DIR", config); vi.stubEnv("CORB_STATE_DIR", path.join(root, "state")); vi.stubEnv("CORB_CACHE_DIR", path.join(root, "cache"));
  state.staging.mockImplementationOnce(() => { throw new Error("staging permission failure"); });
  await expect(runLayerPush(["registry.example/repo:tag", "--workspace", "named"])).rejects.toThrow("staging permission failure");
  const staging = path.join(root, "retry"); state.staging.mockImplementationOnce(() => { fs.mkdirSync(staging); return staging; }); state.preflight.mockRejectedValue(new Error("no valid generation"));
  await expect(runLayerPush(["registry.example/repo:tag", "--workspace", "named"])).rejects.toThrow("no valid generation");
  expect(fs.existsSync(staging)).toBe(false); const release = acquireWorkspaceLock("named"); release();
});

it.each(["copy", "check"])("reports possible remote state after %s fails and preserves pins", async (stage) => {
  const { publishInputGraph } = await import("../../../src/layer/graph.ts"); const { normalizeLayerDefinition, hashLayerDefinition } = await import("../../../src/layer/definition.ts"); const { refreshLayerPins } = await import("../../../src/layer/pins.ts"); const { OrasTransport } = await import("../../../src/layer/transport.ts");
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "corb-layer-publication-")); dirs.push(root); const config = path.join(root, "config"); const workspace = path.join(config, "workspaces", "named"); fs.mkdirSync(workspace, { recursive: true }); fs.writeFileSync(path.join(workspace, "corb.toml"), '[image.layer]\npackages=[]\ncommands=["true"]\n');
  vi.stubEnv("CORB_CONFIG_DIR", config); vi.stubEnv("CORB_STATE_DIR", path.join(root, "state")); vi.stubEnv("CORB_CACHE_DIR", path.join(root, "cache"));
  const definition = normalizeLayerDefinition({ packages: [], commands: ["true"] }); const pins = { os: "linux" as const, abi: "musl" as const, "alpine-branch": "v3.23", "definition-sha256": hashLayerDefinition(definition), index: [], package: [] };
  refreshLayerPins(workspace, "x86_64", pins); const before = fs.readFileSync(path.join(workspace, "corb.sum")); const graph = await publishInputGraph({ version: 1, definition, pins }, "x86_64"); state.inputs.mockResolvedValue(graph); state.preflight.mockResolvedValue({ recheck: vi.fn() });
  state.staging.mockImplementation(() => { const directory = path.join(root, "staging"); fs.mkdirSync(directory); return directory; });
  vi.spyOn(OrasTransport.prototype, "run").mockImplementation(async (args) => { if (args[0] === "cp" && stage === "check") return "copied"; throw new Error("simulated remote transfer failure"); });
  const error = vi.spyOn(process.stderr, "write").mockImplementation(() => true);
  await expect(runLayerPush(["registry.example/repo:tag", "--workspace", "named"])).rejects.toThrow("simulated remote transfer failure");
  expect(fs.readFileSync(path.join(workspace, "corb.sum"))).toEqual(before); const output = error.mock.calls.map((row) => String(row[0])).join(""); expect(output).toContain(graph.digest); expect(output).toContain("Remote blobs or the manifest may remain"); expect(output).toContain("Publication was not verified");
});
