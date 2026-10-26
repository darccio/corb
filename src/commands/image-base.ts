import fs from "node:fs";
import path from "node:path";
import { parseArgs } from "node:util";
import { getImageObjectDirectory, importImageFromDirectory, tagImage } from "@earendil-works/gondolin";
import { resolveLayerBase, recheckLayerBase } from "../layer/local-base.ts";
import { verifyLocalBase } from "../layer/vm.ts";
import { BASE_ASSET_ROLES, serializeBaseConfig, serializeBaseManifest, serializePortableSdkManifest, validateBaseArtifact, type PortableSdkManifest } from "../layer/base.ts";
import { OrasTransport, validatePushDestination, fetchArtifactMetadata, copyArtifactToCache, pushArtifact } from "../layer/transport.ts";
import { validateArtifactReference } from "../layer/reference.ts";
import { blobPath, privateDirectory, publishBlob, publishBytes } from "../layer/state.ts";
import { ownedLayerStaging, removeLayerStaging } from "../layer/prepare.ts";
import { fail, same, sha256 } from "../layer/validate.ts";

export function parseBaseCommandArgs(argv: string[], command: "push" | "pull") {
  const { values, positionals } = parseArgs({ args: argv, strict: true, allowPositionals: true, options: {
    ...(command === "push" ? { image: { type: "string" } } : { tag: { type: "string" } }) as Record<string, { type: "string" }>,
    "registry-config": { type: "string" }, "ca-file": { type: "string" },
  } });
  if (positionals.length !== 1) fail(`image ${command} requires exactly one artifact reference`);
  const reference = command === "push" ? validatePushDestination(positionals[0]!) : validateArtifactReference(positionals[0]);
  return { reference, image: (values as Record<string, string | undefined>).image, tag: (values as Record<string, string | undefined>).tag,
    registry: { ...(values["registry-config"] === undefined ? {} : { registryConfig: values["registry-config"] as string }), ...(values["ca-file"] === undefined ? {} : { caFile: values["ca-file"] as string }) } };
}
export async function runImagePush(argv: string[]): Promise<void> {
  const args = parseBaseCommandArgs(argv, "push");
  const base = await resolveLayerBase(args.image); await verifyLocalBase(base);
  const sdk = base.manifest; const config = { version: 1 as const, arch: sdk.config.arch, "alpine-version": sdk.config.alpine.version };
  const configBytes = serializeBaseConfig(config); const sdkBytes = serializePortableSdkManifest(sdk);
  await publishBytes(configBytes); await publishBytes(sdkBytes);
  const sizes = new Map<string, number>();
  for (const asset of Object.values(base.assets)) { await publishBlob(asset.path, `sha256:${asset.sha256}`, asset.size); sizes.set(`sha256:${asset.sha256}`, asset.size); }
  const root = serializeBaseManifest(config, sdk, sizes); const digest = await publishBytes(root);
  sizes.set(`sha256:${sha256(sdkBytes)}`, Buffer.byteLength(sdkBytes));
  const graph = validateBaseArtifact(root, configBytes, sdkBytes, sizes);
  const staging = ownedLayerStaging();
  let transferStage: string | undefined;
  let published: string | undefined;
  try {
    await recheckLayerBase(base);
    const immutable = await pushArtifact(new OrasTransport(args.registry), args.reference, graph.manifest, digest, staging, (stage) => { transferStage = stage; });
    published = immutable;
    console.log(`corb image push: ${immutable}`);
  } catch (error) {
    if (published !== undefined) process.stderr.write(`corb image push: publication verified at ${published}. Local refs remain unchanged. Reporting the result failed.\n`);
    else if (transferStage !== undefined) process.stderr.write(`corb image push: ${transferStage} transfer to ${args.reference} failed (expected ${digest}). Remote blobs or the manifest may remain. Publication was not verified. Local refs remain unchanged.\n`);
    throw error;
  } finally { removeLayerStaging(staging); }
}
export async function assertExistingBase(sdk: PortableSdkManifest): Promise<string | undefined> {
  const directory = getImageObjectDirectory(sdk.buildId);
  if (!fs.existsSync(directory)) return undefined;
  const existing = await resolveLayerBase(sdk.buildId);
  if (!same(existing.manifest.config, sdk.config) || !same(existing.manifest.checksums, sdk.checksums)) fail("existing SDK object has inconsistent portable config, essential role bytes or architecture");
  return existing.directory;
}
export async function runImagePull(argv: string[]): Promise<void> {
  const args = parseBaseCommandArgs(argv, "pull"); const transport = new OrasTransport(args.registry); const staging = ownedLayerStaging();
  let imported: { buildId: string; assetDir: string } | undefined;
  let verified = false; let tagAttempted = false; let tagged = false;
  try {
    const fetched = await fetchArtifactMetadata(transport, args.reference, "base", staging);
    const sizes = new Map(fetched.manifest.layers.map((row) => [row.digest, row.size]));
    const graph = validateBaseArtifact(fetched.root, fetched.config, fetched.sdk!, sizes);
    await copyArtifactToCache(transport, args.reference, fetched.manifest, staging, fetched.root.length);
    let existing = await assertExistingBase(graph.sdk);
    if (existing === undefined) {
      const assets = privateDirectory(path.join(staging, "sdk"));
      fs.writeFileSync(path.join(assets, "manifest.json"), serializePortableSdkManifest(graph.sdk), { flag: "wx", mode: 0o600 });
      for (const role of BASE_ASSET_ROLES) {
        const filename = graph.sdk.assets[role]; if (filename === undefined) continue;
        fs.copyFileSync(blobPath(graph.sdk.checksums[role]!), path.join(assets, filename), fs.constants.COPYFILE_EXCL);
      }
      const result = importImageFromDirectory(assets); imported = result; existing = result.assetDir;
    } else imported = { buildId: graph.sdk.buildId, assetDir: existing };
    const base = await resolveLayerBase(imported.assetDir);
    if (base.manifest.buildId !== graph.sdk.buildId || !same(base.manifest.checksums, graph.sdk.checksums) || !same(base.manifest.config, graph.sdk.config)) fail("imported SDK object differs from authenticated portable assets");
    await verifyLocalBase(base); await recheckLayerBase(base);
    verified = true;
    if (args.tag !== undefined) { tagAttempted = true; tagImage(base.manifest.buildId, args.tag, base.manifest.config.arch); tagged = true; }
    console.log(`corb image pull: buildId=${base.manifest.buildId} assets=${base.directory}${args.tag === undefined ? " (untagged)" : ` tag=${args.tag}`}`);
  } catch (error) {
    if (imported !== undefined) {
      const status = !verified ? "Production image verification did not finish." : tagged ? `Production image verification and tag ${args.tag} completed. Reporting the result failed.` : tagAttempted ? `Production image verification completed. Tag ${args.tag} was attempted and may already point to this image; inspect local refs before retrying.` : "Production image verification completed. Reporting the result failed.";
      process.stderr.write(`corb image pull: authenticated bytes remain imported at ${imported.assetDir}. ${status}\n`);
    }
    throw error;
  } finally { removeLayerStaging(staging); }
}
