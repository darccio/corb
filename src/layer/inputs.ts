import { assertLayerTarget, normalizeLayerDefinition, serializeLayerDefinition, type LayerDefinition } from "./definition.ts";
import { assertPinsMatchDefinition, normalizeTargetPins, recipePins, type LayerRecipePins } from "./pins.ts";
import { parseMetadata, serializeManifest, validateManifest, type ExpectedInput, type LayerArtifactManifest } from "./metadata.ts";
import { architecture, fail, same, table, type LayerArch } from "./validate.ts";

export const INPUT_ARTIFACT_TYPE = "application/vnd.corb.layer-inputs.v1";
export const INPUT_CONFIG_TYPE = "application/vnd.corb.layer-inputs.config.v1+json";
export const INPUT_BLOB_LIMIT = 512 * 1024 ** 2;
export const INPUT_DESCRIPTOR_LIMIT = 1024;
export const INDEX_MEDIA_TYPE = "application/vnd.corb.apk-index.v1+gzip";
export const APK_MEDIA_TYPE = "application/vnd.corb.apk.v1";
export const SDK_MEDIA_TYPE = "application/vnd.corb.sdk.v1+tar+gzip";
export interface LayerInputConfig { version: 1; definition: LayerDefinition; pins: LayerRecipePins }

export function normalizeInputConfig(value: unknown, arch: LayerArch): LayerInputConfig {
  architecture(arch);
  const config = table(value, "input config", ["version", "definition", "pins"]);
  if (config.version !== 1) fail("input config version must equal 1");
  const definition = normalizeLayerDefinition(config.definition);
  assertLayerTarget(definition, arch);
  const pins = normalizeTargetPins(config.pins, arch);
  if (pins.artifact !== undefined) fail("artifact config recipe pins cannot include their own artifact reference");
  assertPinsMatchDefinition(pins, definition, arch);
  // Require explicit defaults and sorted set arrays.
  if (!same(JSON.parse(serializeLayerDefinition(definition)), config.definition)) fail("input config definition is not normalized");
  const recipe = recipePins(pins, arch);
  if (!same(recipe, config.pins)) fail("input config pins are not normalized");
  return { version: 1, definition, pins: recipe };
}
export function serializeInputConfig(config: LayerInputConfig, arch: LayerArch): string {
  return JSON.stringify(normalizeInputConfig(config, arch));
}
export function expectedInputBlobs(config: LayerInputConfig): ExpectedInput[] {
  return [
    ...config.pins.index.map((item) => ({ role: `index/${item.repository}`, mediaType: INDEX_MEDIA_TYPE, sha256: item.sha256 })),
    ...(config.pins.installer === undefined ? [] : [{ role: "installer", mediaType: APK_MEDIA_TYPE, sha256: config.pins.installer["archive-sha256"] }]),
    ...config.pins.package.map((item) => ({ role: `package/${item.name}`, mediaType: APK_MEDIA_TYPE, sha256: item["archive-sha256"] })),
    ...config.definition.payload.map((item) => ({ role: `payload/${item.name}`, mediaType: SDK_MEDIA_TYPE, sha256: item.sha256 })),
  ];
}
export function validateInputArtifact(rootBytes: string | Uint8Array, configBytes: string | Uint8Array, arch: LayerArch, blobSizes: ReadonlyMap<string, number>): { manifest: LayerArtifactManifest; config: LayerInputConfig } {
  const config = normalizeInputConfig(parseMetadata(configBytes, "input config"), arch);
  const manifest = validateManifest(rootBytes, configBytes, expectedInputBlobs(config), blobSizes, {
    artifactType: INPUT_ARTIFACT_TYPE, configType: INPUT_CONFIG_TYPE, maxDescriptors: INPUT_DESCRIPTOR_LIMIT, maxBlob: INPUT_BLOB_LIMIT,
  });
  return { manifest, config };
}
export function serializeInputManifest(config: LayerInputConfig, arch: LayerArch, blobSizes: ReadonlyMap<string, number>): string {
  const configBytes = serializeInputConfig(config, arch);
  const root = serializeManifest(configBytes, expectedInputBlobs(normalizeInputConfig(config, arch)), blobSizes, INPUT_ARTIFACT_TYPE, INPUT_CONFIG_TYPE);
  validateInputArtifact(root, configBytes, arch, blobSizes);
  return root;
}
