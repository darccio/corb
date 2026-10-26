import { parseLayerCommandArgs } from "./image-layer.ts";
import { selectLayerWorkspace } from "../layer/context.ts";
import { acquireWorkspaceLock } from "../layer/state.ts";
import { composeLayer } from "../layer/compose.ts";
import { inputsForContext, readInputGraph } from "../layer/graph.ts";
import { preflightComposition } from "../layer/generation.ts";
import { bindLayerArtifact, recipePins, assertPinsMatchDefinition } from "../layer/pins.ts";
import { OrasTransport, validatePushDestination, fetchArtifactMetadata, copyArtifactToCache } from "../layer/transport.ts";
import { validateInputArtifact } from "../layer/inputs.ts";
import { fail, same } from "../layer/validate.ts";
import { ownedLayerStaging, removeLayerStaging } from "../layer/prepare.ts";

export async function runLayerPush(argv: string[]): Promise<void> {
  const args = parseLayerCommandArgs(argv, { transport: true, destination: true });
  const destination = validatePushDestination(args.destination!);
  const context = selectLayerWorkspace(args.workspace); const release = acquireWorkspaceLock(context.selected.name);
  let staging: string | undefined; let published: string | undefined; let transferStage: string | undefined; let expectedDigest: string | undefined; let bound = false;
  try {
    staging = ownedLayerStaging();
    context.recheck(); const generation = await preflightComposition(context); const graph = await inputsForContext(context);
    const { pushArtifact } = await import("../layer/transport.ts");
    const transport = new OrasTransport({ ...(args.registryConfig === undefined ? {} : { registryConfig: args.registryConfig }), ...(args.caFile === undefined ? {} : { caFile: args.caFile }) });
    expectedDigest = graph.digest;
    published = await pushArtifact(transport, destination, graph.manifest, graph.digest, staging, (stage) => { transferStage = stage; });
    await generation.recheck(); context.recheck();
    bindLayerArtifact(context.selected.entry.dir, context.arch, context.pins!, published);
    bound = true;
    console.log(`corb image layer push: ${published}`);
  } catch (error) {
    if (bound) process.stderr.write("corb image layer push: publication and lock binding succeeded, but output reporting failed.\n");
    else if (published !== undefined) process.stderr.write(`corb image layer push: remote publication succeeded at ${published}. The previous corb.sum remains authoritative.\n`);
    if (!bound && published === undefined && transferStage !== undefined) process.stderr.write(`corb image layer push: ${transferStage} transfer to ${destination} failed (expected ${expectedDigest}). Remote blobs or the manifest may remain. Publication was not verified. The previous corb.sum remains authoritative.\n`);
    throw error;
  } finally { try { if (staging !== undefined) removeLayerStaging(staging); } finally { release(); } }
}
export async function runLayerPull(argv: string[]): Promise<void> {
  const args = parseLayerCommandArgs(argv, { transport: true });
  const context = selectLayerWorkspace(args.workspace); const release = acquireWorkspaceLock(context.selected.name);
  let staging: string | undefined;
  try {
    context.recheck();
    if (context.pins?.artifact === undefined) fail("layer pull requires an immutable artifact in the selected corb.sum target");
    assertPinsMatchDefinition(context.pins, context.definition, context.arch);
    try {
      const installed = await preflightComposition(context);
      console.log(`corb image layer pull: already installed base=${installed.base.manifest.buildId} generation=${installed.metadata.generation}`);
      return;
    } catch (error) {
      if (!(error instanceof Error) || !/missing |does not match|hash mismatch|backing changed|evidence changed/.test(error.message)) throw error;
    }
    let graph;
    try { graph = await inputsForContext(context); }
    catch (error) {
      if (!(error instanceof Error) || !error.message.includes("missing authenticated input")) throw error;
      staging = ownedLayerStaging();
      const transport = new OrasTransport({ ...(args.registryConfig === undefined ? {} : { registryConfig: args.registryConfig }), ...(args.caFile === undefined ? {} : { caFile: args.caFile }) });
      const fetched = await fetchArtifactMetadata(transport, context.pins.artifact, "input", staging);
      const sizes = new Map(fetched.manifest.layers.map((row) => [row.digest, row.size]));
      const validated = validateInputArtifact(fetched.root, fetched.config, context.arch, sizes);
      if (!same(validated.config.definition, context.definition) || !same(validated.config.pins, recipePins(context.pins, context.arch))) fail("remote input artifact does not match the selected definition and recipe pins");
      await copyArtifactToCache(transport, context.pins.artifact, fetched.manifest, staging, fetched.root.length);
      graph = await readInputGraph(context.pins.artifact.split("@")[1]!, context.arch);
    }
    const result = await composeLayer(context, graph);
    console.log(`corb image layer pull: verified base=${result.base.manifest.buildId} generation=${result.metadata.generation} inputs=${result.metadata.inputDigest}`);
  } finally { try { if (staging !== undefined) removeLayerStaging(staging); } finally { release(); } }
}
