import { createRequire } from "node:module";
import path from "node:path";
import { pathToFileURL } from "node:url";
import { describe, expect, it } from "vitest";
import { computePortableBuildId, normalizePortableSdkManifest, projectPortableSdkManifest, serializeBaseConfig, serializeBaseManifest, serializePortableSdkManifest, validateBaseArtifact } from "../../../src/layer/base.ts";
import { sha256 } from "../../../src/layer/validate.ts";
import { hash } from "./fixtures.ts";

function fixture(optional = false) {
  const checksums = { kernel: hash("a"), initramfs: hash("b"), rootfs: hash("c"), ...(optional ? { krunKernel: hash("d"), krunInitrd: hash("e") } : {}) };
  const assets = { kernel: "vmlinuz", initramfs: "initramfs.lz4", rootfs: "rootfs.ext4", ...(optional ? { krunKernel: "vmlinuz.krun", krunInitrd: "krun.initrd" } : {}) };
  const sdk = normalizePortableSdkManifest({ version: 1, buildId: computePortableBuildId(checksums, "x86_64"), assets, checksums, config: { arch: "x86_64", distro: "alpine", alpine: { version: "3.23.0" } } });
  const config = { version: 1 as const, arch: "x86_64" as const, "alpine-version": "3.23.0" };
  const sizes = new Map(Object.values(checksums).map((value) => [`sha256:${value}`, 10]));
  const sdkBytes = serializePortableSdkManifest(sdk);
  sizes.set(`sha256:${sha256(sdkBytes)}`, Buffer.byteLength(sdkBytes));
  return { sdk, config, sizes, sdkBytes, configBytes: serializeBaseConfig(config), root: serializeBaseManifest(config, sdk, sizes) };
}

describe("portable base contract", () => {
  it("matches the installed SDK build ID for all configured asset roles", async () => {
    const sdkPackage = createRequire(import.meta.url).resolve("@earendil-works/gondolin/package.json");
    const { computeAssetBuildId } = await import(pathToFileURL(path.join(path.dirname(sdkPackage), "dist/src/assets.js")).href);
    for (const optional of [false, true]) {
      const { sdk } = fixture(optional);
      expect(sdk.buildId).toBe(computeAssetBuildId({ checksums: sdk.checksums, arch: sdk.config.arch }));
    }
  });
  it("projects machine paths and build times out of local manifests", () => {
    const { sdk } = fixture();
    expect(projectPortableSdkManifest({ ...sdk, buildTime: "today", config: { ...sdk.config, postBuild: { copy: [{ src: "/tmp/host" }] } } })).toEqual(sdk);
  });
  it.each([false, true])("accepts exactly configured raw assets, optional=%s", (optional) => {
    const { root, configBytes, sdkBytes, sizes } = fixture(optional);
    const result = validateBaseArtifact(root, configBytes, sdkBytes, sizes);
    expect(result.manifest.layers.length).toBe(optional ? 6 : 4);
    expect(result.manifest.layers.slice(1).every((item) => item.mediaType === "application/octet-stream")).toBe(true);
  });
  it("rejects local metadata, unsafe filenames, wrong IDs and missing checksum roles", () => {
    const { sdk } = fixture();
    for (const value of [{ ...sdk, buildTime: "today" }, { ...sdk, buildId: "wrong" },
      { ...sdk, assets: { ...sdk.assets, kernel: "../kernel" } }, { ...sdk, checksums: { ...sdk.checksums, rootfs: undefined } },
      { ...sdk, checksums: { ...sdk.checksums, krunInitrd: hash() } },
    ]) expect(() => normalizePortableSdkManifest(value)).toThrow();
  });
  it.each(["kernel", "initramfs", "rootfs", "krunKernel", "krunInitrd"])("rejects reserved manifest filename for %s before import", (role) => {
    const { sdk, config, sizes, root, configBytes } = fixture(true);
    const changed = { ...sdk, assets: { ...sdk.assets, [role]: "manifest.json" } };
    expect(() => normalizePortableSdkManifest(changed)).toThrow("reserved manifest.json");
    expect(() => projectPortableSdkManifest({ ...changed, buildTime: "local" })).toThrow("reserved manifest.json");
    expect(() => serializeBaseManifest(config, changed, sizes)).toThrow("reserved manifest.json");
    const sdkBytes = JSON.stringify(changed);
    const manifest = JSON.parse(root);
    manifest.layers[0].digest = `sha256:${sha256(sdkBytes)}`;
    manifest.layers[0].size = Buffer.byteLength(sdkBytes);
    sizes.set(manifest.layers[0].digest, Buffer.byteLength(sdkBytes));
    expect(() => validateBaseArtifact(JSON.stringify(manifest), configBytes, sdkBytes, sizes)).toThrow("reserved manifest.json");
  });
  it("rejects architecture and Alpine mismatches", () => {
    const { config, sdk, sizes } = fixture();
    expect(() => serializeBaseManifest({ ...config, arch: "aarch64" }, sdk, sizes)).toThrow("disagree");
    expect(() => serializeBaseManifest({ ...config, "alpine-version": "3.24.0" }, sdk, sizes)).toThrow("disagree");
  });
  it("bounds raw blobs and total graph while preserving separate base size limits", () => {
    const { config, sdk, sizes } = fixture(true);
    for (const digest of Object.values(sdk.checksums)) sizes.set(`sha256:${digest}`, 7 * 1024 ** 3);
    expect(() => serializeBaseManifest(config, sdk, sizes)).toThrow("32 GiB");
    for (const digest of Object.values(sdk.checksums)) sizes.set(`sha256:${digest}`, 10);
    sizes.set(`sha256:${sdk.checksums.rootfs}`, 8 * 1024 ** 3 + 1);
    expect(() => serializeBaseManifest(config, sdk, sizes)).toThrow();
  });
  it("rejects missing, extra, compressed and size-mismatched base roles", () => {
    const { root, configBytes, sdkBytes, sizes } = fixture();
    for (const mutate of [(root: any) => root.layers.pop(), (root: any) => root.layers.push(root.layers[0]),
      (root: any) => { root.layers[1].mediaType = "application/gzip"; }, (root: any) => { root.layers[1].size++; }]) {
      const parsed = JSON.parse(root);
      mutate(parsed);
      expect(() => validateBaseArtifact(JSON.stringify(parsed), configBytes, sdkBytes, sizes)).toThrow();
    }
  });
});
