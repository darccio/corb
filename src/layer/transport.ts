import fs from "node:fs";
import path from "node:path";
import { spawn } from "node:child_process";
import { randomUUID } from "node:crypto";
import { validateArtifactReference } from "./reference.ts";
import { OCI_MANIFEST, METADATA_LIMIT, GRAPH_LIMIT, parseMetadata, type ConfigDescriptor, type LayerArtifactManifest } from "./metadata.ts";
import { INPUT_ARTIFACT_TYPE, INPUT_CONFIG_TYPE, INPUT_BLOB_LIMIT, INPUT_DESCRIPTOR_LIMIT } from "./inputs.ts";
import { BASE_ARTIFACT_TYPE, BASE_CONFIG_TYPE, BASE_ASSET_LIMIT } from "./base.ts";
import { fail, integer, string, table, sha256 } from "./validate.ts";
import { hashFile, privateDirectory, publishBlob, blobPath } from "./state.ts";
import { RegistryDiagnosticRedactor } from "./diagnostics.ts";

export interface RegistryOptions { registryConfig?: string; caFile?: string }
export function validatePushDestination(reference: string): string {
  const match = /^(.*):([A-Za-z0-9_][A-Za-z0-9_.-]{0,127})$/.exec(reference);
  if (match === null || match[1]!.includes("@")) fail("push destination must be REGISTRY/REPOSITORY:TAG with an explicit tag");
  validateArtifactReference(`${match[1]}@sha256:${"0".repeat(64)}`);
  return reference;
}
export function artifactRepository(reference: string): string { return validateArtifactReference(reference).split("@")[0]!; }
export function registryFlags(options: RegistryOptions, direction = ""): string[] {
  const prefix = direction === "" ? "" : `${direction}-`;
  // ORAS infers HTTP for localhost unless this option is explicitly false.
  return [`--${prefix}plain-http=false`, ...(options.registryConfig === undefined ? [] : [`--${prefix}registry-config`, path.resolve(options.registryConfig)]), ...(options.caFile === undefined ? [] : [`--${prefix}ca-file`, path.resolve(options.caFile)])];
}
export class OrasTransport {
  private readonly deadline = Date.now() + 60 * 60_000;
  private checked = false;
  readonly options: RegistryOptions;
  constructor(options: RegistryOptions) { this.options = options; }
  async run(args: string[], output?: { filename: string; limit: number }): Promise<string> {
    if (!this.checked) {
      const version = await this.command(["version"]);
      if (!/^Version:[ \t]+1\.3\.5[ \t]*$/m.test(version)) fail("ORAS exactly 1.3.5 is required. Install it from https://github.com/oras-project/oras/releases/tag/v1.3.5 and place oras on PATH");
      this.checked = true;
    }
    return this.command(args, output);
  }
  private async command(args: string[], output?: { filename: string; limit: number }): Promise<string> {
    if (Date.now() >= this.deadline) fail("OCI transport exceeded one hour");
    let fd: number | undefined;
    if (output !== undefined) fd = fs.openSync(output.filename, "wx", 0o600);
    try {
      return await new Promise<string>((resolve, reject) => {
        const child = spawn("oras", args, { stdio: ["ignore", "pipe", "pipe"], shell: false });
        let stdout = ""; let stderr = ""; let bytes = 0; let failure: Error | undefined;
        const diagnostics = new RegistryDiagnosticRedactor();
        let force: ReturnType<typeof setTimeout> | undefined;
        const stop = (error: Error) => { failure ??= error; child.kill("SIGTERM"); force ??= setTimeout(() => child.kill("SIGKILL"), 1000); };
        const cancelled = () => stop(new Error("ORAS transfer cancelled"));
        process.once("SIGINT", cancelled); process.once("SIGTERM", cancelled);
        const timeout = setTimeout(() => stop(new Error("ORAS transfer exceeded its time limit")), Math.max(1, Math.min(30 * 60_000, this.deadline - Date.now())));

        child.stdout.on("data", (chunk: Buffer) => {
          bytes += chunk.length;
          if (output !== undefined) {
            if (bytes > output.limit) stop(new Error("ORAS output exceeds descriptor bounds"));
            else try { fs.writeSync(fd!, chunk); } catch (error) { stop(error as Error); }
          } else { stdout = (stdout + chunk.toString("utf8")).slice(-64 * 1024); }
        });
        child.stderr.on("data", (chunk: Buffer) => { stderr = (stderr + diagnostics.write(chunk.toString("utf8"))).slice(-64 * 1024); });
        child.on("error", (error) => { failure = (error as NodeJS.ErrnoException).code === "ENOENT" ? new Error("ORAS 1.3.5 is required on PATH. Install https://github.com/oras-project/oras/releases/tag/v1.3.5") : error; });
        child.on("close", (code, signal) => {
          stderr = (stderr + diagnostics.flush()).slice(-64 * 1024);
          clearTimeout(timeout); if (force !== undefined) clearTimeout(force);
          process.removeListener("SIGINT", cancelled); process.removeListener("SIGTERM", cancelled);
          if (failure !== undefined) reject(failure);
          else if (code !== 0) reject(new Error(`ORAS failed (${code ?? signal}): ${stderr.slice(-8000)}`));
          else resolve(stdout);
        });
      });
    } finally { if (fd !== undefined) fs.closeSync(fd); }
  }
}
export type ArtifactKind = "input" | "base";
export function inspectArtifactRoot(bytes: Buffer, kind: ArtifactKind, digest: string): LayerArtifactManifest {
  if (bytes.length > METADATA_LIMIT || `sha256:${sha256(bytes)}` !== digest) fail("root manifest digest or size mismatch");
  const root = table(parseMetadata(bytes, "OCI root"), "OCI root", ["schemaVersion", "mediaType", "artifactType", "config", "layers"]);
  if (root.schemaVersion !== 2 || root.mediaType !== OCI_MANIFEST || root.artifactType !== (kind === "input" ? INPUT_ARTIFACT_TYPE : BASE_ARTIFACT_TYPE)) fail("unsupported OCI artifact type");
  function descriptor(value: unknown, layer: boolean): ConfigDescriptor {
    const row = table(value, "OCI descriptor", ["mediaType", "digest", "size", ...(layer ? ["annotations"] : [])]);
    const result = { mediaType: string(row.mediaType, "descriptor mediaType"), digest: string(row.digest, "descriptor digest", /^sha256:[a-f0-9]{64}$/), size: integer(row.size, "descriptor size", 0, layer ? kind === "input" ? INPUT_BLOB_LIMIT : BASE_ASSET_LIMIT : METADATA_LIMIT) };
    if (!layer) return result;
    const annotations = table(row.annotations, "OCI annotations", ["org.opencontainers.image.title"]);
    string(annotations["org.opencontainers.image.title"], "OCI role", /^[a-z][a-z0-9-]*\/[a-z0-9][a-zA-Z0-9+_.-]*$|^installer$/);
    return { ...result, annotations } as ConfigDescriptor;
  }
  const config = descriptor(root.config, false);
  if (config.mediaType !== (kind === "input" ? INPUT_CONFIG_TYPE : BASE_CONFIG_TYPE)) fail("unsupported OCI config media type");
  if (!Array.isArray(root.layers) || root.layers.length > (kind === "input" ? INPUT_DESCRIPTOR_LIMIT : 6)) fail("excessive OCI descriptors");
  const layers = root.layers.map((row) => descriptor(row, true));
  if (bytes.length + config.size + layers.reduce((sum, row) => sum + row.size, 0) > GRAPH_LIMIT) fail("OCI graph exceeds 32 GiB");
  return { schemaVersion: 2, mediaType: OCI_MANIFEST, artifactType: root.artifactType, config, layers } as LayerArtifactManifest;
}
export function writeOciLayout(directory: string, manifest: LayerArtifactManifest, digest: string): void {
  privateDirectory(directory); privateDirectory(path.join(directory, "blobs/sha256"));
  fs.writeFileSync(path.join(directory, "oci-layout"), '{"imageLayoutVersion":"1.0.0"}', { flag: "wx", mode: 0o600 });
  fs.writeFileSync(path.join(directory, "index.json"), JSON.stringify({ schemaVersion: 2, manifests: [{ mediaType: OCI_MANIFEST, digest, size: fs.statSync(blobPath(digest)).size, annotations: { "org.opencontainers.image.ref.name": "artifact" } }] }), { flag: "wx", mode: 0o600 });
  for (const value of new Set([{ digest }, manifest.config, ...manifest.layers].map((row) => row.digest))) fs.copyFileSync(blobPath(value), path.join(directory, "blobs/sha256", value.slice(7)), fs.constants.COPYFILE_EXCL);
}
export async function fetchArtifactMetadata(transport: OrasTransport, reference: string, kind: ArtifactKind, staging: string): Promise<{ manifest: LayerArtifactManifest; root: Buffer; config: Buffer; sdk?: Buffer }> {
  validateArtifactReference(reference); const digest = reference.split("@")[1]!;
  const rootFile = path.join(staging, `root-${randomUUID()}`);
  const descriptorText = await transport.run(["manifest", "fetch", "--descriptor", ...registryFlags(transport.options), reference]);
  const descriptor = table(parseMetadata(descriptorText, "remote root descriptor"), "remote root descriptor", ["mediaType", "digest", "size", "artifactType", "annotations"]);
  if (descriptor.digest !== digest || descriptor.mediaType !== OCI_MANIFEST) fail("remote root descriptor identity mismatch");
  integer(descriptor.size, "root descriptor size", 0, METADATA_LIMIT);
  await transport.run(["manifest", "fetch", ...registryFlags(transport.options), reference], { filename: rootFile, limit: METADATA_LIMIT });
  const root = fs.readFileSync(rootFile);
  if (root.length !== descriptor.size) fail("remote root descriptor size mismatch");
  const manifest = inspectArtifactRoot(root, kind, digest);
  const configFile = path.join(staging, `config-${randomUUID()}`);
  await transport.run(["blob", "fetch", "--output", "-", ...registryFlags(transport.options), `${artifactRepository(reference)}@${manifest.config.digest}`], { filename: configFile, limit: manifest.config.size });
  const config = fs.readFileSync(configFile);
  if (config.length !== manifest.config.size || `sha256:${sha256(config)}` !== manifest.config.digest) fail("remote config descriptor mismatch");
  if (kind === "input") return { manifest, root, config };
  const sdkDescriptor = manifest.layers[0];
  if (sdkDescriptor === undefined || sdkDescriptor.size > METADATA_LIMIT) fail("base graph has no bounded SDK projection");
  const sdkFile = path.join(staging, `sdk-${randomUUID()}`);
  await transport.run(["blob", "fetch", "--output", "-", ...registryFlags(transport.options), `${artifactRepository(reference)}@${sdkDescriptor.digest}`], { filename: sdkFile, limit: sdkDescriptor.size });
  const sdk = fs.readFileSync(sdkFile);
  if (sdk.length !== sdkDescriptor.size || `sha256:${sha256(sdk)}` !== sdkDescriptor.digest) fail("remote SDK projection digest mismatch");
  return { manifest, root, config, sdk };
}
export async function copyArtifactToCache(transport: OrasTransport, reference: string, manifest: LayerArtifactManifest, staging: string, rootSize: number): Promise<void> {
  const layout = path.join(staging, `layout-${randomUUID()}`);
  await transport.run(["cp", "--no-tty", "--to-oci-layout", ...registryFlags(transport.options, "from"), reference, `${layout}:artifact`]);
  for (const descriptor of [{ digest: reference.split("@")[1]!, size: rootSize }, manifest.config, ...manifest.layers]) {
    const filename = path.join(layout, "blobs/sha256", descriptor.digest.slice(7));
    if (await hashFile(filename, descriptor.size) !== descriptor.digest.slice(7) || (descriptor.size !== undefined && fs.statSync(filename).size !== descriptor.size)) fail("transferred OCI blob digest or size mismatch");
    await publishBlob(filename, descriptor.digest, descriptor.size);
  }
}
export async function pushArtifact(transport: OrasTransport, destination: string, manifest: LayerArtifactManifest, digest: string, staging: string, progress?: (stage: "copying" | "checking") => void): Promise<string> {
  validatePushDestination(destination);
  const layout = path.join(staging, `layout-${randomUUID()}`); writeOciLayout(layout, manifest, digest);
  progress?.("copying");
  await transport.run(["cp", "--no-tty", "--from-oci-layout", ...registryFlags(transport.options, "to"), `${layout}:artifact`, destination]);
  progress?.("checking");
  const immutable = `${destination.slice(0, destination.lastIndexOf(":"))}@${digest}`;
  const filename = path.join(staging, `published-${randomUUID()}`);
  await transport.run(["manifest", "fetch", ...registryFlags(transport.options), immutable], { filename, limit: METADATA_LIMIT });
  if (await hashFile(filename, METADATA_LIMIT) !== digest.slice(7)) fail("published OCI manifest differs from expected digest");
  return immutable;
}
