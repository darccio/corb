import fs from "node:fs";
import path from "node:path";
import { randomUUID } from "node:crypto";
import { expectedInputBlobs, serializeInputConfig, serializeInputManifest, validateInputArtifact, type LayerInputConfig } from "./inputs.ts";
import { hashRecipePins, recipePins } from "./pins.ts";
import { blobPath, layerCache, privateDirectory, publishBytes, readJson, verifyBlob } from "./state.ts";
import { fail, same, sha256, table, string, SHA256, type LayerArch } from "./validate.ts";
import { parseMetadata, type LayerArtifactManifest } from "./metadata.ts";
import type { LayerContext } from "./context.ts";

export interface InputGraph { digest: string; config: LayerInputConfig; manifest: LayerArtifactManifest; rootBytes: Buffer; configBytes: Buffer }
export async function publishInputGraph(config: LayerInputConfig, arch: LayerArch): Promise<InputGraph> {
  const sizes = new Map<string, number>();
  for (const blob of expectedInputBlobs(config)) { const file = await verifyBlob(blob.sha256); sizes.set(`sha256:${blob.sha256}`, fs.statSync(file).size); }
  const configBytes = serializeInputConfig(config, arch);
  await publishBytes(configBytes);
  const rootBytes = serializeInputManifest(config, arch, sizes);
  const digest = await publishBytes(rootBytes);
  return readInputGraph(digest, arch);
}
export async function readInputGraph(digest: string, arch: LayerArch): Promise<InputGraph> {
  const rootFile = await verifyBlob(digest);
  if (fs.statSync(rootFile).size > 1024 * 1024) fail("input root exceeds 1 MiB");
  const rootBytes = fs.readFileSync(rootFile);
  const raw = table(parseMetadata(rootBytes, "input root"), "input root", ["schemaVersion", "mediaType", "artifactType", "config", "layers"]);
  const descriptor = table(raw.config, "input config descriptor", ["mediaType", "digest", "size"]);
  const configFile = await verifyBlob(string(descriptor.digest, "config digest", /^sha256:[a-f0-9]{64}$/));
  if (fs.statSync(configFile).size > 1024 * 1024) fail("input config exceeds 1 MiB");
  const configBytes = fs.readFileSync(configFile);
  const preliminary = parseMetadata(configBytes, "input config") as LayerInputConfig;
  // The strict config parser runs before its role list can select any file.
  const { normalizeInputConfig } = await import("./inputs.ts");
  const config = normalizeInputConfig(preliminary, arch);
  const sizes = new Map<string, number>();
  for (const blob of expectedInputBlobs(config)) { const filename = await verifyBlob(blob.sha256); sizes.set(`sha256:${blob.sha256}`, fs.statSync(filename).size); }
  const { manifest } = validateInputArtifact(rootBytes, configBytes, arch, sizes);
  return { digest, config, manifest, rootBytes, configBytes };
}
function receiptPath(recipeHash: string): string { if (!SHA256.test(recipeHash)) fail("invalid pin receipt key"); return path.join(layerCache(), "receipts", `${recipeHash}.json`); }
export function publishPinReceipt(recipeHash: string, graph: InputGraph): void {
  const filename = receiptPath(recipeHash);
  privateDirectory(path.dirname(filename));
  const receipt = JSON.stringify({ version: 1, recipePinsSha256: recipeHash, inputDigest: graph.digest });
  const temporary = path.join(path.dirname(filename), `.receipt-${randomUUID()}`);
  try {
    fs.writeFileSync(temporary, receipt, { flag: "wx", mode: 0o400 });
    try { fs.linkSync(temporary, filename); } catch (error) { if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error; }
    const winner = table(readJson(filename), "pin receipt", ["version", "recipePinsSha256", "inputDigest"]);
    if (!same(winner, JSON.parse(receipt))) fail("inconsistent immutable pin receipt");
  } finally { fs.rmSync(temporary, { force: true }); }
}
export async function inputsForContext(context: LayerContext): Promise<InputGraph> {
  if (context.pins === undefined) fail(`missing pins. Run corb image pin --workspace ${context.selected.name}`);
  let digest = context.pins.artifact?.split("@")[1];
  if (digest === undefined) {
    try {
      const receipt = table(readJson(receiptPath(hashRecipePins(context.pins, context.arch))), "input receipt", ["version", "recipePinsSha256", "inputDigest"]);
      if (receipt.version !== 1 || receipt.recipePinsSha256 !== hashRecipePins(context.pins, context.arch)) fail("pin receipt mismatch");
      digest = string(receipt.inputDigest, "receipt digest", /^sha256:[a-f0-9]{64}$/);
    } catch (error) { if ((error as NodeJS.ErrnoException).code === "ENOENT") fail("missing exact local pin receipt. Run corb image pin to explicitly refresh inputs"); throw error; }
  }
  const graph = await readInputGraph(digest, context.arch);
  if (!same(graph.config.definition, context.definition) || !same(graph.config.pins, recipePins(context.pins, context.arch))) fail("input graph does not match selected definition and recipe pins");
  if (sha256(graph.rootBytes) !== digest.slice(7)) fail("input graph root digest mismatch");
  return graph;
}
export function inputBlobFile(graph: InputGraph, role: string): string {
  const descriptor = graph.manifest.layers.find((layer) => layer.annotations["org.opencontainers.image.title"] === role);
  if (descriptor === undefined) fail(`missing authenticated input role '${role}'`);
  return blobPath(descriptor.digest);
}
