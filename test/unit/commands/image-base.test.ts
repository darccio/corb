import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, expect, it, vi } from "vitest";
import { parseBaseCommandArgs } from "../../../src/commands/image-base.ts";
const dirs: string[] = [];
afterEach(() => { vi.restoreAllMocks(); vi.unstubAllEnvs(); for (const dir of dirs.splice(0)) fs.rmSync(dir, { recursive: true, force: true }); });
it.each([["registry.example/repo:tag", "--unknown"], ["registry.example/repo:tag", "extra"], ["repo:tag"], ["registry.example/repo"], ["registry.example/repo:tag", "--tag", "local:tag"]])("rejects invalid base push %j", (args) => { expect(() => parseBaseCommandArgs(args, "push")).toThrow(); });
it.each([["registry.example/repo:tag"], ["registry.example/repo@sha256:" + "a".repeat(64), "extra"], ["registry.example/repo@sha256:" + "a".repeat(64), "--image", "local"]])("rejects mutable or extra base pull input %j", (args) => { expect(() => parseBaseCommandArgs(args, "pull")).toThrow(); });
it("uses only the requested selector/tag and registry options", () => {
  expect(parseBaseCommandArgs(["registry.example/repo:tag", "--image", "private:base", "--ca-file", "ca"], "push")).toMatchObject({ image: "private:base", registry: { caFile: "ca" } });
  expect(parseBaseCommandArgs(["registry.example/repo@sha256:" + "a".repeat(64), "--tag", "private:import"], "pull").tag).toBe("private:import");
});
it("accepts an existing exact SDK object with harmless manifest and filename differences", async () => {
  const { computePortableBuildId } = await import("../../../src/layer/base.ts"); const { sha256 } = await import("../../../src/layer/validate.ts"); const { assertExistingBase } = await import("../../../src/commands/image-base.ts");
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "corb-existing-base-")); dirs.push(root); vi.stubEnv("GONDOLIN_IMAGE_STORE", root);
  const checksums = { kernel: sha256("kernel bytes"), initramfs: sha256("init bytes"), rootfs: sha256("root bytes") }; const buildId = computePortableBuildId(checksums, "x86_64");
  const directory = path.join(root, "objects", buildId); fs.mkdirSync(directory, { recursive: true });
  const assets = { kernel: "local-kernel", initramfs: "local-init", rootfs: "local-root" };
  for (const [name, bytes] of [[assets.kernel, "kernel bytes"], [assets.initramfs, "init bytes"], [assets.rootfs, "root bytes"]]) fs.writeFileSync(path.join(directory, name!), bytes!);
  const config = { arch: "x86_64" as const, distro: "alpine" as const, alpine: { version: "3.23.0" } };
  fs.writeFileSync(path.join(directory, "manifest.json"), JSON.stringify({ version: 1, buildId, assets, checksums, config: { ...config, source: "/other/recipe" }, buildTime: "other time" }, null, 4));
  const portable = { version: 1 as const, buildId, assets: { kernel: "kernel", initramfs: "init", rootfs: "root" }, checksums, config };
  expect(await assertExistingBase(portable)).toBe(directory);
  await expect(assertExistingBase({ ...portable, config: { ...config, alpine: { version: "3.22.0" } } })).rejects.toThrow("inconsistent portable config");
  fs.writeFileSync(path.join(directory, assets.rootfs), "tampered"); await expect(assertExistingBase(portable)).rejects.toThrow("base asset");
});
