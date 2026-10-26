import fs from "node:fs";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { VmCheckpoint } from "@earendil-works/gondolin";
import { hashLayerDefinition } from "./definition.ts";
import { hashRecipePins } from "./pins.ts";
import { inputsForContext, type InputGraph } from "./graph.ts";
import { resolveLayerBase, requireLayerExecution, type LayerBase } from "./local-base.ts";
import { layerState, hashFile, readJson } from "./state.ts";
import { fail, same, sha256, string, table } from "./validate.ts";
import { isSameOrDescendant, realpathOrResolve } from "../config/hostpaths.ts";
import type { LayerContext } from "./context.ts";
import type { Verification } from "./vm.ts";

export const COMPOSITION_POLICY = "corb-composition-v2";
const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
export interface GenerationMetadata {
  version: 1; policy: typeof COMPOSITION_POLICY; workspace: string; source: string; definitionSha256: string; recipePinsSha256: string;
  inputDigest: string; compositionKey: string; base: LayerBase; arch: string; generation: string; createdAt: string;
  checkpoint: { sha256: string; backing: string; trailerSha256: string };
  evidenceSha256: string; guestEvidenceSha256: string; runtime: unknown[]; mapping: unknown[]; path: string;
  packageCoherence: true; verification: Verification;
}
export function baseGenerationRoot(context: LayerContext, base: LayerBase): string { return path.join(realpathOrResolve(layerState(context.selected.name)), context.arch, "bases", base.manifest.buildId); }
export function compositionKey(context: LayerContext, base: LayerBase, graph: InputGraph): string {
  return sha256(JSON.stringify({ policy: COMPOSITION_POLICY, arch: context.arch, baseId: base.manifest.buildId, assets: Object.fromEntries(Object.entries(base.assets).map(([role, asset]) => [role, asset.sha256])),
    recipePinsSha256: hashRecipePins(context.pins!, context.arch), inputDigest: graph.digest }));
}
export function inspectCheckpointTrailer(filename: string, baseId: string): { hash: string; data: unknown } {
  const fd = fs.openSync(filename, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK);
  try {
    const stat = fs.fstatSync(fd);
    if (!stat.isFile() || stat.size < 16) fail("checkpoint requires a regular qcow2 file and bounded trailer");
    const footer = Buffer.alloc(16); fs.readSync(fd, footer, 0, 16, stat.size - 16);
    if (footer.subarray(0, 8).toString() !== "GONDCPT1") fail("checkpoint has no SDK trailer");
    const size = footer.readBigUInt64BE(8);
    if (size === 0n || size > 65536n || size > BigInt(stat.size - 16)) fail("checkpoint trailer exceeds safe bounds");
    const bytes = Buffer.alloc(Number(size)); fs.readSync(fd, bytes, 0, bytes.length, stat.size - 16 - bytes.length);
    const data = table(JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes)), "checkpoint trailer", ["version", "name", "createdAt", "diskFile", "guestAssetBuildId", "snapshotKind", "createdWithVmm", "compatibleVmm"]);
    if (data.version !== 1 || data.snapshotKind !== "disk" || data.guestAssetBuildId !== baseId || data.createdWithVmm !== "qemu" || !Array.isArray(data.compatibleVmm) || !data.compatibleVmm.includes("qemu") || data.diskFile !== path.basename(filename)) fail("checkpoint is not a disk cache for this exact qemu base");
    return { hash: sha256(bytes), data };
  } finally { fs.closeSync(fd); }
}
export function inspectCheckpointBacking(filename: string, rootfs: string): void {
  const info = JSON.parse(execFileSync("qemu-img", ["info", "--output=json", filename], { encoding: "utf8", timeout: 30_000, maxBuffer: 1024 * 1024 })) as Record<string, unknown>;
  if (info.format !== "qcow2" || info["backing-filename"] !== rootfs || info["full-backing-filename"] !== rootfs || fs.realpathSync(rootfs) !== rootfs || (info["backing-filename-format"] !== undefined && info["backing-filename-format"] !== "raw")) fail("checkpoint backing changed. Recompose with corb image layer build or pull. Refusing SDK backing mutation");
}
export function assertCompositionMounts(hosts: readonly string[], generationDirectory: string, base: LayerBase): void {
  for (const host of hosts) for (const protectedPath of [generationDirectory, base.directory]) {
    const actual = realpathOrResolve(host); const protectedActual = realpathOrResolve(protectedPath);
    if (isSameOrDescendant(actual, protectedActual) || isSameOrDescendant(protectedActual, actual)) fail(`mount '${host}' overlaps the bound composition or canonical base '${protectedPath}'`);
  }
}
export async function validateGeneration(context: LayerContext, base: LayerBase, graph: InputGraph, generation: string) {
  if (!UUID.test(generation)) fail("unsafe local generation ID");
  const directory = path.join(baseGenerationRoot(context, base), "generations", generation);
  if (fs.realpathSync(directory) !== directory || !fs.lstatSync(directory).isDirectory()) fail("unsafe generation directory");
  const filename = path.join(directory, "metadata.json");
  const complete = table(readJson(path.join(directory, "complete.json")), "generation completion", ["version", "metadataSha256"]);
  if (complete.version !== 1 || await hashFile(filename, 1024 * 1024) !== complete.metadataSha256) fail("generation metadata hash mismatch");
  const raw = table(readJson(filename), "generation metadata", ["version", "policy", "workspace", "source", "definitionSha256", "recipePinsSha256", "inputDigest", "compositionKey", "base", "arch", "generation", "createdAt", "checkpoint", "evidenceSha256", "guestEvidenceSha256", "runtime", "mapping", "path", "packageCoherence", "verification"]);
  const metadata = raw as unknown as GenerationMetadata;
  if (metadata.version !== 1 || metadata.policy !== COMPOSITION_POLICY || metadata.workspace !== context.selected.name || metadata.source !== context.selected.entry.corbToml || metadata.generation !== generation || metadata.arch !== context.arch || metadata.definitionSha256 !== hashLayerDefinition(context.definition) || metadata.recipePinsSha256 !== hashRecipePins(context.pins!, context.arch) || metadata.inputDigest !== graph.digest || metadata.compositionKey !== compositionKey(context, base, graph) || !same(metadata.base, base) || !same(metadata.runtime, context.definition["runtime-dir"])) fail("local generation does not match the selected source, recipe, inputs or exact base. Run corb image layer build or pull");
  const verification = metadata.verification;
  const required = ["user", "privilege-drop", "suid", "removals", "ca-trust", "git-gh-shimmed", "pi"];
  if (metadata.packageCoherence !== true || verification?.ok !== true || verification.gates?.length !== 7 || required.some((name) => verification.gates.filter((gate) => gate.name === name && gate.ok === true).length !== 1)) fail("local generation lacks seven-gate and package-coherence success");
  if (!Array.isArray(metadata.mapping) || typeof metadata.path !== "string") fail("invalid generation runtime metadata");
  if (await hashFile(path.join(directory, "evidence.json"), 64 * 1024 ** 2) !== metadata.evidenceSha256) fail("composition evidence changed");
  const evidence = JSON.parse(fs.readFileSync(path.join(directory, "evidence.json"), "utf8")) as { world?: unknown; installer?: { sha256?: unknown; size?: unknown } };
  if (typeof evidence.world !== "string") fail("composition lacks complete APK world evidence. Run corb image layer build or pull");
  if (context.pins?.installer !== undefined && (evidence.installer === undefined || typeof evidence.installer.sha256 !== "string" || !/^[a-f0-9]{64}$/.test(evidence.installer.sha256) || !Number.isSafeInteger(evidence.installer.size) || (evidence.installer.size as number) <= 0 || (evidence.installer.size as number) > 16 * 1024 ** 2)) fail("missing authenticated installer absence evidence. Run corb image layer build or pull");
  const checkpoint = path.join(directory, "checkpoint.qcow2");
  if (await hashFile(checkpoint) !== metadata.checkpoint.sha256) fail("checkpoint hash mismatch. Run corb image layer build or pull");
  const trailer = inspectCheckpointTrailer(checkpoint, base.manifest.buildId);
  if (trailer.hash !== metadata.checkpoint.trailerSha256 || metadata.checkpoint.backing !== base.assets.rootfs!.path) fail("checkpoint trailer or exact base binding changed");
  inspectCheckpointBacking(checkpoint, base.assets.rootfs!.path);
  return { metadata, directory, checkpoint, base, load: () => VmCheckpoint.load(checkpoint) };
}
export async function currentGeneration(context: LayerContext, base: LayerBase, graph: InputGraph) {
  const filename = path.join(baseGenerationRoot(context, base), "current.json");
  let pointer: Record<string, unknown>;
  try { pointer = table(readJson(filename), "current composition", ["version", "generation"]); }
  catch (error) { if ((error as NodeJS.ErrnoException).code === "ENOENT") return undefined; throw error; }
  if (pointer.version !== 1) fail("unsupported current composition version");
  return validateGeneration(context, base, graph, string(pointer.generation, "generation ID", UUID));
}
export async function preflightComposition(context: LayerContext, hosts: readonly string[] = []) {
  if (context.pins === undefined) fail(`missing pins. Run corb image pin --workspace ${context.selected.name}`);
  const base = await resolveLayerBase(context.config.vm?.image); requireLayerExecution(base);
  const graph = await inputsForContext(context);
  const current = await currentGeneration(context, base, graph);
  if (current === undefined) fail(`missing exact-base composition. Run corb image layer build --workspace ${context.selected.name} or corb image layer pull --workspace ${context.selected.name}`);
  assertCompositionMounts(hosts, current.directory, base);
  context.recheck();
  return { ...current, context, graph,
    recheck: async () => {
      context.recheck(); const latestBase = await resolveLayerBase(context.config.vm?.image);
      requireLayerExecution(latestBase);
      const latestGraph = await inputsForContext(context);
      await validateGeneration(context, latestBase, latestGraph, current.metadata.generation);
      assertCompositionMounts(hosts, current.directory, latestBase);
    } };
}
export type ValidatedComposition = Awaited<ReturnType<typeof preflightComposition>>;
