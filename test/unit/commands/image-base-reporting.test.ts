import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, expect, it, vi } from "vitest";
import { computePortableBuildId, serializeBaseConfig, serializeBaseManifest, serializePortableSdkManifest, type PortableSdkManifest } from "../../../src/layer/base.ts";
import { sha256 } from "../../../src/layer/validate.ts";
const mocks = vi.hoisted(() => ({ metadata: vi.fn(), copy: vi.fn(), push: vi.fn(), resolve: vi.fn(), verify: vi.fn(), recheck: vi.fn() }));
vi.mock("../../../src/layer/transport.ts", async (original) => ({ ...await original<object>(), OrasTransport: class {}, fetchArtifactMetadata: mocks.metadata, copyArtifactToCache: mocks.copy, pushArtifact: mocks.push }));
vi.mock("../../../src/layer/local-base.ts", () => ({ resolveLayerBase: mocks.resolve, recheckLayerBase: mocks.recheck }));
vi.mock("../../../src/layer/vm.ts", () => ({ verifyLocalBase: mocks.verify }));
import { runImagePull, runImagePush } from "../../../src/commands/image-base.ts";
const dirs: string[] = [];
afterEach(() => { vi.restoreAllMocks(); vi.unstubAllEnvs(); vi.clearAllMocks(); for (const dir of dirs.splice(0)) fs.rmSync(dir, { recursive: true, force: true }); });
function fixture() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "corb-base-report-")); dirs.push(root);
  vi.stubEnv("GONDOLIN_IMAGE_STORE", path.join(root, "store")); vi.stubEnv("CORB_CACHE_DIR", path.join(root, "cache"));
  const bytes = { kernel: "kernel", initramfs: "init", rootfs: "root" }; const checksums = Object.fromEntries(Object.entries(bytes).map(([role, data]) => [role, sha256(data)])) as PortableSdkManifest["checksums"];
  const sdk: PortableSdkManifest = { version: 1, buildId: computePortableBuildId(checksums, "x86_64"), assets: { kernel: "kernel", initramfs: "init", rootfs: "root" }, checksums, config: { arch: "x86_64", distro: "alpine", alpine: { version: "3.23.0" } } };
  const directory = path.join(root, "store/objects", sdk.buildId); fs.mkdirSync(directory, { recursive: true });
  const assets = Object.fromEntries(Object.entries(bytes).map(([role, data]) => { const filename = path.join(directory, sdk.assets[role as keyof typeof sdk.assets]!); fs.writeFileSync(filename, data); return [role, { path: filename, sha256: sha256(data), size: Buffer.byteLength(data) }]; }));
  fs.writeFileSync(path.join(directory, "manifest.json"), JSON.stringify(sdk));
  const base = { directory, manifest: sdk, assets, branch: "v3.23" }; mocks.resolve.mockResolvedValue(base);
  const config = { version: 1 as const, arch: "x86_64" as const, "alpine-version": "3.23.0" };
  const rootBytes = serializeBaseManifest(config, sdk, new Map(Object.entries(bytes).map(([role, data]) => [`sha256:${checksums[role as keyof typeof checksums]}`, Buffer.byteLength(data)])));
  mocks.metadata.mockResolvedValue({ root: Buffer.from(rootBytes), config: serializeBaseConfig(config), sdk: serializePortableSdkManifest(sdk), manifest: JSON.parse(rootBytes) });
  return { root, sdk, directory };
}
it("reports a real SDK failure after the requested ref was already written", async () => {
  const { root, directory } = fixture();
  const refs = path.join(root, "store/refs/private/base"); fs.mkdirSync(refs, { recursive: true });
  fs.writeFileSync(path.join(refs, "aarch64"), "malformed other architecture ref");
  const stderr = vi.spyOn(process.stderr, "write").mockImplementation(() => true);
  await expect(runImagePull(["registry.example/base@sha256:" + "a".repeat(64), "--tag", "private:base"])).rejects.toThrow("not a symlink");
  expect(fs.realpathSync(path.join(refs, "x86_64"))).toBe(directory);
  expect(stderr.mock.calls.flat().join("")).toContain("Tag private:base was attempted and may already point to this image");
});
it("preserves the verified push verdict when reporting fails afterward", async () => {
  fixture(); const immutable = "registry.example/base@sha256:" + "b".repeat(64); mocks.push.mockResolvedValue(immutable);
  vi.spyOn(console, "log").mockImplementation(() => { throw new Error("closed output"); }); const stderr = vi.spyOn(process.stderr, "write").mockImplementation(() => true);
  await expect(runImagePush(["registry.example/base:tag"])).rejects.toThrow("closed output");
  expect(stderr.mock.calls.flat().join("")).toContain(`publication verified at ${immutable}`);
  expect(stderr.mock.calls.flat().join("")).not.toContain("Publication was not verified");
});
