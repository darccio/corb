import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, expect, it, vi } from "vitest";
import { VmCheckpoint } from "@earendil-works/gondolin";
import { inspectCheckpointTrailer, inspectCheckpointBacking, assertCompositionMounts } from "../../../src/layer/generation.ts";
const { info } = vi.hoisted(() => ({ info: vi.fn() }));
vi.mock("node:child_process", () => ({ execFileSync: info, spawn: vi.fn() }));
const dirs: string[] = [];
afterEach(() => { vi.restoreAllMocks(); info.mockReset(); for (const dir of dirs.splice(0)) fs.rmSync(dir, { recursive: true, force: true }); });
function fixture(changes = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "corb-checkpoint-")); dirs.push(dir); const file = path.join(dir, "checkpoint.qcow2"); fs.writeFileSync(file, Buffer.alloc(64));
  const data = { version: 1 as const, name: "checkpoint", createdAt: new Date().toISOString(), diskFile: "checkpoint.qcow2", guestAssetBuildId: "8d1ad38c-602a-50b2-a6b4-247a2b6824bc", snapshotKind: "disk" as const, createdWithVmm: "qemu" as const, compatibleVmm: ["qemu" as const], ...changes };
  VmCheckpoint.writeTrailer(file, data); return { dir, file, data };
}
it("bounds the raw trailer before the SDK can allocate it", () => {
  const { file, data } = fixture(); expect(inspectCheckpointTrailer(file, data.guestAssetBuildId).hash).toMatch(/^[a-f0-9]{64}$/);
  const bytes = fs.readFileSync(file); bytes.writeBigUInt64BE(1000000000000n, bytes.length - 8); fs.writeFileSync(file, bytes);
  const sdk = vi.spyOn(VmCheckpoint, "load"); expect(() => inspectCheckpointTrailer(file, data.guestAssetBuildId)).toThrow("safe bounds"); expect(sdk).not.toHaveBeenCalled();
});
it.each([{ snapshotKind: "memory" }, { createdWithVmm: "krun" }, { compatibleVmm: ["krun"] }, { guestAssetBuildId: "foreign" }])("rejects foreign or unsupported trailer %j", (changes) => {
  const { file } = fixture(changes); expect(() => inspectCheckpointTrailer(file, "8d1ad38c-602a-50b2-a6b4-247a2b6824bc")).toThrow("exact qemu base");
});
it("requires exact direct backing spelling before SDK resume can rebase", () => {
  const { dir, file } = fixture(); const root = path.join(dir, "base.ext4"); fs.writeFileSync(root, "base");
  info.mockReturnValue(JSON.stringify({ format: "qcow2", "backing-filename": root, "full-backing-filename": root, "backing-filename-format": "raw" }));
  expect(() => inspectCheckpointBacking(file, root)).not.toThrow();
  const link = path.join(dir, "alias"); fs.symlinkSync(root, link);
  info.mockReturnValue(JSON.stringify({ format: "qcow2", "backing-filename": link, "full-backing-filename": root }));
  expect(() => inspectCheckpointBacking(file, root)).toThrow("Refusing SDK backing mutation");
  info.mockReturnValue(JSON.stringify({ format: "qcow2", "backing-filename": "base.ext4", "full-backing-filename": root }));
  expect(() => inspectCheckpointBacking(file, root)).toThrow("backing changed");
});
it("guards external base/generation mounts and their symlinks in both overlap directions", () => {
  const { dir } = fixture(); const base = path.join(dir, "external-base"); const generation = path.join(dir, "state/generation"); fs.mkdirSync(base); fs.mkdirSync(generation, { recursive: true });
  const link = path.join(dir, "link"); fs.symlinkSync(base, link); const bound = { directory: base } as Parameters<typeof assertCompositionMounts>[2];
  for (const host of [dir, base, path.join(base, "child"), link, generation, path.join(generation, "child")]) expect(() => assertCompositionMounts([host], generation, bound)).toThrow("overlaps");
  expect(() => assertCompositionMounts([path.join(dir, "safe")], generation, bound)).not.toThrow();
});
it("rejects a FIFO checkpoint in a bounded child before SDK loading", async () => {
  const { spawnSync } = await vi.importActual<typeof import("node:child_process")>("node:child_process");
  const { dir } = fixture(); const fifo = path.join(dir, "checkpoint-fifo"); expect(spawnSync("mkfifo", [fifo]).status).toBe(0);
  const module = new URL("../../../src/layer/generation.ts", import.meta.url).href;
  const script = `import { inspectCheckpointTrailer } from ${JSON.stringify(module)}; try { inspectCheckpointTrailer(${JSON.stringify(fifo)}, "base"); process.exitCode=2; } catch(error) { console.log(error.message); }`;
  const result = spawnSync(process.execPath, ["--input-type=module", "-e", script], { encoding: "utf8", timeout: 2000 });
  expect(result.error).toBeUndefined(); expect(result.status).toBe(0); expect(result.stdout).toContain("regular qcow2 file");
});
