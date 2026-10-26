import fs from "node:fs";
import path from "node:path";
import { randomUUID } from "node:crypto";
import { VmCheckpoint } from "@earendil-works/gondolin";
import { authenticateGraph, ownedLayerStaging, removeLayerStaging, inputMount, APK_PREFIX } from "./prepare.ts";
import { inputsForContext, type InputGraph } from "./graph.ts";
import { hashLayerDefinition } from "./definition.ts";
import { hashRecipePins, assertPinsMatchDefinition } from "./pins.ts";
import { requireLayerExecution, recheckLayerBase, resolveLayerBase } from "./local-base.ts";
import { baseGenerationRoot, compositionKey, COMPOSITION_POLICY, currentGeneration, inspectCheckpointBacking, inspectCheckpointTrailer, validateGeneration, type GenerationMetadata } from "./generation.ts";
import { atomicJson, hashFile, privateDirectory } from "./state.ts";
import { BASE_PATH, layerExec, layerGuest, VERIFIER_HOSTS, verifyLayerBase, verifyProductionVm, withLayerVm } from "./vm.ts";
import { parseInstalledIdentities, parsePackagePlan, assertPackageIdentities, validateHookRepositoryQuery } from "./plan.ts";
import { fail, sha256 } from "./validate.ts";
import type { LayerContext } from "./context.ts";

export function displayLayerPlan(context: LayerContext): void {
  process.stderr.write(`corb image layer: workspace=${context.selected.name}\n`);
  for (const [label, value] of [["requested packages", context.pins?.package.filter((row) => row.requested).map((row) => `${row.name}=${row.version}`) ?? context.definition.packages], ["SDKs", context.definition.payload], ["runtime dirs", context.definition["runtime-dir"]], ["build hosts", context.definition["build-hosts"]], ["unpinned root commands", context.definition.commands]]) process.stderr.write(`corb image layer: ${label}: ${JSON.stringify(value)}\n`);
}
export async function composeLayer(context: LayerContext, suppliedGraph?: InputGraph) {
  if (context.pins === undefined) fail(`missing pins. Run corb image pin --workspace ${context.selected.name}`);
  assertPinsMatchDefinition(context.pins, context.definition, context.arch);
  const base = await resolveLayerBase(context.config.vm?.image); requireLayerExecution(base);
  if (base.manifest.config.arch !== context.arch) fail("base and layer target architectures differ");
  const graph = await inputsForContext(context);
  if (suppliedGraph !== undefined && suppliedGraph.digest !== graph.digest) fail("supplied inputs differ from selected locked graph");
  try {
    const existing = await currentGeneration(context, base, graph);
    if (existing !== undefined) return { ...existing, alreadyInstalled: true };
  } catch (error) { process.stderr.write(`corb image layer: recomposing after local cache rejection: ${error instanceof Error ? error.message : String(error)}\n`); }
  displayLayerPlan(context);
  const { baseline } = await verifyLayerBase(base);
  let staging: string | undefined;
  const generation = randomUUID();
  const directory = path.join(baseGenerationRoot(context, base), "generations", generation);
  let ownedCandidate = false;
  let complete = false;
  try {
    staging = ownedLayerStaging();
    privateDirectory(path.dirname(directory));
    fs.mkdirSync(directory, { mode: 0o700 });
    ownedCandidate = true;
    const prepared = await authenticateGraph(graph, context, base, baseline, staging);
    const payloadPath = prepared.payloads.flatMap((payload) => payload.path.map((entry) => path.posix.join(payload.destination, entry))).concat(BASE_PATH.split(":"));
    const built = await withLayerVm(base, "corb-layer-builder", context.definition["build-hosts"], async (vm) => {
      const processBaseline = await layerGuest(vm, "processes");
      let additions: ReturnType<typeof parsePackagePlan> = [];
      let hookDefaults: { noNetwork: true; packages: string[] } | undefined;
      if (context.definition.packages.length > 0) {
        const requested = context.pins!.package.filter((row) => row.requested).map((row) => `${row.name}=${row.version}`);
        const simulated = await layerExec(vm, [...APK_PREFIX, "add", "--simulate", ...requested]);
        if (!simulated.ok) fail(`incompatible base: APK simulation rejected: ${(simulated.stderr || simulated.stdout).slice(-8000)}`);
        additions = parsePackagePlan(simulated.stdout, baseline.packages, context.pins!);
        await layerGuest(vm, "apk-context-start");
        try {
          const child = await layerExec(vm, ["/usr/bin/env", "-i", `PATH=${BASE_PATH}`, "/sbin/apk", "fetch", "--recursive", "--url", "--simulate", ...requested]);
          if (!child.ok) fail("sanitized bare APK child rejected its frozen defaults");
          hookDefaults = { noNetwork: true, packages: validateHookRepositoryQuery(child.stdout + child.stderr, context.pins!, context.arch) };
          process.stderr.write("corb image: sanitized bare APK child uses frozen repository defaults\n");
          const installed = await layerExec(vm, [...APK_PREFIX, "add", ...requested], 5 * 60_000);
          process.stderr.write(installed.stdout + installed.stderr);
          if (!installed.ok) fail("signed APK transaction failed");
          const repaired = await layerExec(vm, [...APK_PREFIX, "fix", "--simulate"]);
          if (!repaired.ok || parsePackagePlan(repaired.stdout, baseline.packages, context.pins!).length !== 0) fail("composed APK dependency/provider closure is incoherent");
        } finally { await layerGuest(vm, "apk-context-end"); await layerGuest(vm, "clean"); }
      }
      const after = await layerGuest<{ database: string; world: string }>(vm, "database");
      assertPackageIdentities(baseline.packages, parseInstalledIdentities(after.database), additions);
      await layerGuest(vm, "copy", prepared.payloads);
      const mapping = await layerGuest<unknown[]>(vm, "runtime", { plan: context.definition["runtime-dir"] });
      for (const command of context.definition.commands) {
        process.stderr.write(`corb image layer: unpinned root step: ${JSON.stringify(command)}\n`);
        const result = await vm.exec(["/bin/sh", "-ec", command], { cwd: "/", env: { PATH: payloadPath.join(":") }, stdout: "buffer", stderr: "buffer", signal: AbortSignal.timeout(5 * 60_000) });
        process.stderr.write((result.stdout + result.stderr).slice(-64 * 1024));
        if (!result.ok) fail(`unpinned root step failed (${result.exitCode})`);
      }
      await layerGuest(vm, "stop", processBaseline);
      const plan = { baseline, world: after.world, ...(hookDefaults === undefined ? {} : { hookDefaults }), ...(prepared.installer?.binary === undefined ? {} : { installer: { sha256: sha256(prepared.installer.binary), size: prepared.installer.binary.length } }), additions, archives: prepared.archives, payloads: prepared.payloads, runtime: context.definition["runtime-dir"], mapping };
      const evidence = await layerGuest<{ path: string }>(vm, "verify", plan);
      const guestEvidence = await layerGuest<{ sha256: string }>(vm, "record", evidence);
      const finalDatabase = await layerGuest<{ database: string; world: string }>(vm, "database");
      assertPackageIdentities(baseline.packages, parseInstalledIdentities(finalDatabase.database), additions);
      if (finalDatabase.world !== after.world) fail("APK world changed outside the signed transaction");
      // The SDK closes the builder during checkpoint creation. The returned object retains builder options and is discarded.
      process.stderr.write(`corb image: checkpointing builder host PID ${vm.getHostPid()}\n`);
      await vm.checkpoint(path.join(directory, "checkpoint.qcow2"));
      return { evidence, plan, mapping, guestEvidenceSha256: guestEvidence.sha256 };
    }, { mounts: inputMount(prepared.input) });
    const checkpoint = path.join(directory, "checkpoint.qcow2");
    const trailer = inspectCheckpointTrailer(checkpoint, base.manifest.buildId);
    inspectCheckpointBacking(checkpoint, base.assets.rootfs!.path);
    const beforeHash = await hashFile(checkpoint);
    const verification = await withLayerVm(base, "corb-layer-checkpoint-verifier", VERIFIER_HOSTS, async (vm) => {
      await layerGuest(vm, "runtime", { plan: context.definition["runtime-dir"], expected: built.mapping });
      await layerGuest(vm, "verify", built.plan);
      const observed = await layerGuest<{ sha256: string }>(vm, "record-check");
      if (observed.sha256 !== built.guestEvidenceSha256) fail("checkpoint composition evidence changed");
      return verifyProductionVm(vm);
    }, { checkpoint: VmCheckpoint.load(checkpoint), verifier: true });
    if (await hashFile(checkpoint) !== beforeHash) fail("checkpoint verifier mutated the immutable candidate");
    atomicJson(path.join(directory, "evidence.json"), { ...built.plan, result: built.evidence });
    const metadata: GenerationMetadata = {
      version: 1, policy: COMPOSITION_POLICY, workspace: context.selected.name, source: context.selected.entry.corbToml,
      definitionSha256: hashLayerDefinition(context.definition), recipePinsSha256: hashRecipePins(context.pins, context.arch), inputDigest: graph.digest,
      compositionKey: compositionKey(context, base, graph), base, arch: context.arch, generation, createdAt: new Date().toISOString(),
      checkpoint: { sha256: beforeHash, backing: base.assets.rootfs!.path, trailerSha256: trailer.hash }, evidenceSha256: await hashFile(path.join(directory, "evidence.json")),
      guestEvidenceSha256: built.guestEvidenceSha256, runtime: context.definition["runtime-dir"], mapping: built.mapping, path: built.evidence.path, packageCoherence: true, verification,
    };
    atomicJson(path.join(directory, "metadata.json"), metadata);
    atomicJson(path.join(directory, "complete.json"), { version: 1, metadataSha256: await hashFile(path.join(directory, "metadata.json")) });
    for (const name of ["checkpoint.qcow2", "evidence.json", "metadata.json", "complete.json"]) fs.chmodSync(path.join(directory, name), 0o400);
    const result = await validateGeneration(context, base, graph, generation);
    complete = true;
    await recheckLayerBase(base); context.recheck();
    atomicJson(path.join(baseGenerationRoot(context, base), "current.json"), { version: 1, generation });
    return { ...result, alreadyInstalled: false };
  } finally {
    try { if (staging !== undefined) removeLayerStaging(staging); }
    finally { if (!complete && ownedCandidate) removeLayerStaging(directory); }
  }
}
