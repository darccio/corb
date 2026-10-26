import { fail, integer, sha256, string, table } from "./validate.ts";

export const OCI_MANIFEST = "application/vnd.oci.image.manifest.v1+json";
export const METADATA_LIMIT = 1024 * 1024;
export const GRAPH_LIMIT = 32 * 1024 ** 3;
export const TITLE = "org.opencontainers.image.title";
export interface LayerDescriptor { mediaType: string; digest: string; size: number; annotations: { [TITLE]: string } }
export interface ConfigDescriptor { mediaType: string; digest: string; size: number }
export interface LayerArtifactManifest {
  schemaVersion: 2;
  mediaType: typeof OCI_MANIFEST;
  artifactType: string;
  config: ConfigDescriptor;
  layers: LayerDescriptor[];
}
export interface ExpectedInput { role: string; mediaType: string; sha256: string }

export function parseMetadata(bytes: string | Uint8Array, location: string): unknown {
  const data = typeof bytes === "string" ? Buffer.from(bytes, "utf8") : bytes;
  if (data.byteLength > METADATA_LIMIT) fail(`${location} exceeds 1 MiB`);
  let text: string;
  try { text = new TextDecoder("utf-8", { fatal: true }).decode(data); }
  catch { fail(`${location} must be UTF-8`); }
  let value: unknown;
  try { value = JSON.parse(text); } catch { fail(`invalid ${location} JSON`); }
  // JSON.parse accepts duplicate keys. Scan valid JSON tokens to reject them at every depth.
  const tokens = text.match(/"(?:[^"\\]|\\.)*"|[{}[\]:,]|-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?|true|false|null/g)!;
  let position = 0;
  function visit(): void {
    const token = tokens[position++];
    if (token === "{") {
      const seen = new Set<string>();
      while (tokens[position] !== "}") {
        const key = JSON.parse(tokens[position++]!) as string;
        if (seen.has(key)) fail(`duplicate JSON key '${key}' in ${location}`);
        seen.add(key);
        position++;
        visit();
        if (tokens[position] === ",") position++;
      }
      position++;
    } else if (token === "[") {
      while (tokens[position] !== "]") { visit(); if (tokens[position] === ",") position++; }
      position++;
    }
  }
  visit();
  return value;
}

function descriptor(value: unknown, annotation: boolean, maxSize: number): ConfigDescriptor | LayerDescriptor {
  const entry = table(value, "descriptor", ["mediaType", "digest", "size", ...(annotation ? ["annotations"] : [])]);
  const result: ConfigDescriptor = { mediaType: string(entry.mediaType, "descriptor.mediaType"),
    digest: string(entry.digest, "descriptor.digest", /^sha256:[a-f0-9]{64}$/), size: integer(entry.size, "descriptor.size", 0, maxSize) };
  if (!annotation) return result;
  const annotations = table(entry.annotations, "descriptor.annotations", [TITLE]);
  return { ...result, annotations: { [TITLE]: string(annotations[TITLE], "descriptor role", /^[a-z][a-z0-9-]*\/[a-z0-9][a-zA-Z0-9+_.-]*$|^installer$/) } };
}

export function validateManifest(
  rootBytes: string | Uint8Array, configBytes: string | Uint8Array,
  expected: readonly ExpectedInput[], blobSizes: ReadonlyMap<string, number>,
  contract: { artifactType: string; configType: string; maxDescriptors: number; maxBlob: number },
): LayerArtifactManifest {
  const root = table(parseMetadata(rootBytes, "root manifest"), "manifest", ["schemaVersion", "mediaType", "artifactType", "config", "layers"]);
  if (root.schemaVersion !== 2 || root.mediaType !== OCI_MANIFEST || root.artifactType !== contract.artifactType) fail("unsupported artifact manifest type or version");
  const config = descriptor(root.config, false, METADATA_LIMIT);
  if (config.mediaType !== contract.configType || config.size !== Buffer.byteLength(configBytes)
    || config.digest !== `sha256:${sha256(configBytes)}`) fail("config descriptor does not match config bytes");
  if (!Array.isArray(root.layers) || root.layers.length > contract.maxDescriptors || root.layers.length !== expected.length) fail("missing, extra or excessive layer descriptors");
  const layers = root.layers.map((value) => descriptor(value, true, contract.maxBlob) as LayerDescriptor);
  let total = Buffer.byteLength(rootBytes) + config.size;
  for (const [index, layer] of layers.entries()) {
    const input = expected[index]!;
    if (layer.annotations[TITLE] !== input.role || layer.mediaType !== input.mediaType || layer.digest !== `sha256:${input.sha256}`) fail(`descriptor does not match pinned role '${input.role}'`);
    if (!blobSizes.has(layer.digest) || blobSizes.get(layer.digest) !== layer.size) fail(`descriptor size does not match observed blob '${input.role}'`);
    total += layer.size;
  }
  if (total > GRAPH_LIMIT) fail("artifact graph exceeds 32 GiB");
  return { schemaVersion: 2, mediaType: OCI_MANIFEST, artifactType: contract.artifactType, config, layers };
}

export function serializeManifest(configBytes: string, inputs: readonly ExpectedInput[], blobSizes: ReadonlyMap<string, number>, artifactType: string, configType: string): string {
  return JSON.stringify({ schemaVersion: 2, mediaType: OCI_MANIFEST, artifactType,
    config: { mediaType: configType, digest: `sha256:${sha256(configBytes)}`, size: Buffer.byteLength(configBytes) },
    layers: inputs.map((input) => ({ mediaType: input.mediaType, digest: `sha256:${input.sha256}`, size: blobSizes.get(`sha256:${input.sha256}`), annotations: { [TITLE]: input.role } })) });
}
