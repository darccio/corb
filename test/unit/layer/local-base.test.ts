import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, expect, it, vi } from "vitest";
import { computePortableBuildId } from "../../../src/layer/base.ts";
import { resolveLayerBase, requireLayerExecution } from "../../../src/layer/local-base.ts";
import { sha256 } from "../../../src/layer/validate.ts";
const { resolve } = vi.hoisted(() => ({ resolve: vi.fn() }));
vi.mock("../../../src/vm/image.ts", () => ({ resolveRuntimeImage: resolve }));
const directories: string[] = [];
afterEach(() => { vi.restoreAllMocks(); vi.unstubAllEnvs(); for (const directory of directories.splice(0)) fs.rmSync(directory, { recursive: true, force: true }); });
function fixture() {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "corb-base-")); directories.push(directory);
  const assets = { kernel: "kernel", initramfs: "initramfs", rootfs: "rootfs" };
  const checksums = { kernel: sha256("kernel"), initramfs: sha256("initramfs"), rootfs: sha256("rootfs") };
  const buildId = computePortableBuildId(checksums, "x86_64");
  for (const value of Object.values(assets)) fs.writeFileSync(path.join(directory, value), value);
  fs.writeFileSync(path.join(directory, "manifest.json"), JSON.stringify({ version: 1, buildId, assets, checksums, config: { arch: "x86_64", distro: "alpine", alpine: { version: "3.23.0" }, local: "ignored" } }));
  resolve.mockReturnValue({ selector: "private:base", assetDir: directory, arch: "x86_64", buildId });
  return directory;
}
it("binds actual assets, content ID, branch and canonical paths", async () => {
  fixture(); const base = await resolveLayerBase("private:base"); expect(base.branch).toBe("v3.23"); requireLayerExecution(base);
});
it("rejects tampered assets before VM creation", async () => {
  const directory = fixture(); fs.writeFileSync(path.join(directory, "rootfs"), "tampered"); await expect(resolveLayerBase()).rejects.toThrow("base asset");
});
it("rejects an unsupported layer backend", async () => {
  fixture(); const base = await resolveLayerBase(); vi.stubEnv("GONDOLIN_VMM", "krun"); expect(() => requireLayerExecution(base)).toThrow("qemu");
});
