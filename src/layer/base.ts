import { createHash } from "node:crypto";
import { parseMetadata, serializeManifest, validateManifest, type ExpectedInput, type LayerArtifactManifest } from "./metadata.ts";
import { architecture, fail, SHA256, sha256, string, table, type LayerArch } from "./validate.ts";

export const BASE_ARTIFACT_TYPE = "application/vnd.corb.base.v1";
export const BASE_CONFIG_TYPE = "application/vnd.corb.base.config.v1+json";
export const SDK_MANIFEST_TYPE = "application/vnd.corb.sdk-manifest.v1+json";
export const BASE_ASSET_LIMIT = 8 * 1024 ** 3;
export const BASE_ASSET_ROLES = ["kernel", "initramfs", "rootfs", "krunKernel", "krunInitrd"] as const;
export type BaseAssetRole = typeof BASE_ASSET_ROLES[number];
type Assets<T> = Record<"kernel" | "initramfs" | "rootfs", T> & Partial<Record<"krunKernel" | "krunInitrd", T>>;
export interface PortableSdkManifest {
  version: 1;
  buildId: string;
  assets: Assets<string>;
  checksums: Assets<string>;
  config: { arch: LayerArch; distro: "alpine"; alpine: { version: string } };
}
export interface BaseArtifactConfig { version: 1; arch: LayerArch; "alpine-version": string }

/** Matches Gondolin 0.12.0 assets.js computeAssetBuildId, which is not a public package export. */
export function computePortableBuildId(checksums: Assets<string>, arch: LayerArch): string {
  const parts = ["gondolin-asset-build", `kernel=${checksums.kernel}`, `initramfs=${checksums.initramfs}`, `rootfs=${checksums.rootfs}`];
  if (checksums.krunKernel !== undefined) parts.push(`krunKernel=${checksums.krunKernel}`);
  if (checksums.krunInitrd !== undefined) parts.push(`krunInitrd=${checksums.krunInitrd}`);
  parts.push(`arch=${arch}`);
  const namespace = Buffer.from("7b6ed0c07e7f4c2a8b2d0bf3d5be9d52", "hex");
  const bytes = createHash("sha1").update(namespace).update(parts.join("\n"), "utf8").digest().subarray(0, 16);
  bytes[6] = (bytes[6]! & 0x0f) | 0x50;
  bytes[8] = (bytes[8]! & 0x3f) | 0x80;
  const hex = bytes.toString("hex");
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

export function normalizePortableSdkManifest(value: unknown): PortableSdkManifest {
  const root = table(value, "SDK manifest", ["version", "buildId", "assets", "checksums", "config"]);
  if (root.version !== 1) fail("SDK manifest version must equal 1");
  const config = table(root.config, "SDK config", ["arch", "distro", "alpine"]);
  const arch = architecture(config.arch);
  if (config.distro !== "alpine") fail("SDK config distro must equal alpine");
  const alpine = table(config.alpine, "SDK alpine", ["version"]);
  const alpineVersion = string(alpine.version, "SDK alpine.version", /^\d+\.\d+(?:\.\d+)?$/);
  const rawAssets = table(root.assets, "SDK assets", BASE_ASSET_ROLES);
  const rawChecksums = table(root.checksums, "SDK checksums", BASE_ASSET_ROLES);
  const assets = {} as Assets<string>;
  const checksums = {} as Assets<string>;
  for (const role of BASE_ASSET_ROLES) {
    if (rawAssets[role] === undefined && (role === "krunKernel" || role === "krunInitrd")) {
      if (rawChecksums[role] !== undefined) fail(`unexpected checksum role '${role}'`);
      continue;
    }
    assets[role] = string(rawAssets[role], `SDK assets.${role}`, /^[a-zA-Z0-9][a-zA-Z0-9._-]*$/);
    checksums[role] = string(rawChecksums[role], `SDK checksums.${role}`, SHA256);
  }
  if (new Set(Object.values(assets)).size !== Object.keys(assets).length) fail("duplicate SDK asset filename");
  const buildId = string(root.buildId, "SDK buildId");
  if (buildId !== computePortableBuildId(checksums, arch)) fail("SDK buildId does not match content checksums and architecture");
  return { version: 1, buildId, assets, checksums, config: { arch, distro: "alpine", alpine: { version: alpineVersion } } };
}

/** Project a local SDK manifest. Build paths, times and other local build settings stay local. */
export function projectPortableSdkManifest(value: unknown): PortableSdkManifest {
  if (typeof value !== "object" || value === null || Array.isArray(value)) fail("local SDK manifest must be a table");
  const raw = value as Record<string, unknown>;
  if (typeof raw.config !== "object" || raw.config === null) fail("local SDK config must be a table");
  const config = raw.config as Record<string, unknown>;
  const alpine = config.alpine as Record<string, unknown> | undefined;
  return normalizePortableSdkManifest({ version: raw.version, buildId: raw.buildId, assets: raw.assets, checksums: raw.checksums,
    config: { arch: config.arch, distro: config.distro, alpine: { version: alpine?.version } } });
}
export function serializePortableSdkManifest(manifest: PortableSdkManifest): string {
  return JSON.stringify(normalizePortableSdkManifest(manifest));
}
export function normalizeBaseConfig(value: unknown): BaseArtifactConfig {
  const config = table(value, "base config", ["version", "arch", "alpine-version"]);
  if (config.version !== 1) fail("base config version must equal 1");
  return { version: 1, arch: architecture(config.arch), "alpine-version": string(config["alpine-version"], "base alpine-version", /^\d+\.\d+(?:\.\d+)?$/) };
}
export function serializeBaseConfig(config: BaseArtifactConfig): string { return JSON.stringify(normalizeBaseConfig(config)); }

function expectedBaseBlobs(manifest: PortableSdkManifest, sdkBytes: string | Uint8Array): ExpectedInput[] {
  return [{ role: "base/manifest", mediaType: SDK_MANIFEST_TYPE, sha256: sha256(sdkBytes) },
    ...BASE_ASSET_ROLES.filter((role) => manifest.assets[role] !== undefined).map((role) => ({ role: `base/${role}`, mediaType: "application/octet-stream", sha256: manifest.checksums[role]! }))];
}
export function validateBaseArtifact(rootBytes: string | Uint8Array, configBytes: string | Uint8Array, sdkBytes: string | Uint8Array, blobSizes: ReadonlyMap<string, number>): { manifest: LayerArtifactManifest; config: BaseArtifactConfig; sdk: PortableSdkManifest } {
  const config = normalizeBaseConfig(parseMetadata(configBytes, "base config"));
  const sdk = normalizePortableSdkManifest(parseMetadata(sdkBytes, "SDK manifest"));
  if (config.arch !== sdk.config.arch || config["alpine-version"] !== sdk.config.alpine.version) fail("base config and SDK manifest disagree");
  if (Buffer.from(sdkBytes).toString("utf8") !== serializePortableSdkManifest(sdk)) fail("SDK manifest must contain the canonical portable projection");
  const manifest = validateManifest(rootBytes, configBytes, expectedBaseBlobs(sdk, sdkBytes), blobSizes, {
    artifactType: BASE_ARTIFACT_TYPE, configType: BASE_CONFIG_TYPE, maxDescriptors: 6, maxBlob: BASE_ASSET_LIMIT,
  });
  if (manifest.layers[0]!.size !== Buffer.byteLength(sdkBytes)) fail("SDK manifest descriptor size mismatch");
  return { manifest, config, sdk };
}
export function serializeBaseManifest(config: BaseArtifactConfig, sdk: PortableSdkManifest, assetSizes: ReadonlyMap<string, number>): string {
  const configBytes = serializeBaseConfig(config);
  const sdkBytes = serializePortableSdkManifest(sdk);
  const sizes = new Map(assetSizes).set(`sha256:${sha256(sdkBytes)}`, Buffer.byteLength(sdkBytes));
  const root = serializeManifest(configBytes, expectedBaseBlobs(normalizePortableSdkManifest(sdk), sdkBytes), sizes, BASE_ARTIFACT_TYPE, BASE_CONFIG_TYPE);
  validateBaseArtifact(root, configBytes, sdkBytes, sizes);
  return root;
}
