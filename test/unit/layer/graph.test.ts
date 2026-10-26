import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, expect, it, vi } from "vitest";
import { normalizeLayerDefinition, hashLayerDefinition } from "../../../src/layer/definition.ts";
import { hashRecipePins } from "../../../src/layer/pins.ts";
import { publishInputGraph, publishPinReceipt, readInputGraph } from "../../../src/layer/graph.ts";
import { blobPath } from "../../../src/layer/state.ts";
const dirs: string[] = [];
afterEach(() => { vi.unstubAllEnvs(); for (const dir of dirs.splice(0)) fs.rmSync(dir, { recursive: true, force: true }); });
function fixture() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "corb-graph-")); dirs.push(dir); vi.stubEnv("CORB_CACHE_DIR", dir);
  const definition = normalizeLayerDefinition({ packages: [], commands: ["true"] });
  const pins = { os: "linux" as const, abi: "musl" as const, "alpine-branch": "v3.23", "definition-sha256": hashLayerDefinition(definition), index: [], package: [] };
  return { version: 1 as const, definition, pins };
}
it("publishes deterministic input-only graph bytes and an immutable receipt", async () => {
  const config = fixture(); const graph = await publishInputGraph(config, "x86_64");
  expect((await publishInputGraph(config, "x86_64")).digest).toBe(graph.digest);
  expect(graph.manifest.layers).toEqual([]); expect(graph.rootBytes.toString()).not.toMatch(/base|checkpoint|buildId|hostPath/);
  publishPinReceipt(hashRecipePins(config.pins, "x86_64"), graph); publishPinReceipt(hashRecipePins(config.pins, "x86_64"), graph);
  expect(() => publishPinReceipt(hashRecipePins(config.pins, "x86_64"), { ...graph, digest: `sha256:${"a".repeat(64)}` })).toThrow("inconsistent");
});
it("revalidates complete cached graph bytes before reuse", async () => {
  const config = fixture(); const graph = await publishInputGraph(config, "x86_64");
  const file = blobPath(graph.manifest.config.digest); fs.chmodSync(file, 0o600); fs.writeFileSync(file, "{}");
  await expect(readInputGraph(graph.digest, "x86_64")).rejects.toThrow("corrupt");
});
it("rejects a wrong-node immutable receipt winner before reading it", async () => {
  const config = fixture(); const graph = await publishInputGraph(config, "x86_64"); const key = hashRecipePins(config.pins, "x86_64");
  publishPinReceipt(key, graph);
  const { layerCache } = await import("../../../src/layer/state.ts"); const filename = path.join(layerCache(), "receipts", `${key}.json`);
  fs.unlinkSync(filename); fs.mkdirSync(filename);
  expect(() => publishPinReceipt(key, graph)).toThrow("regular file");
});
