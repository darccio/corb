import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { Readable } from "node:stream";
import { afterEach, expect, it, vi } from "vitest";
import { acquireWorkspaceLock, blobPath, boundedCopy, hashFile, layerState, publishBlob, publishBytes, verifyBlob } from "../../../src/layer/state.ts";
import { sha256 } from "../../../src/layer/validate.ts";
const directories: string[] = [];
afterEach(() => { vi.restoreAllMocks(); vi.unstubAllEnvs(); for (const directory of directories.splice(0)) fs.rmSync(directory, { recursive: true, force: true }); });
function setup() { const directory = fs.mkdtempSync(path.join(os.tmpdir(), "corb-cas-")); directories.push(directory); vi.stubEnv("CORB_CACHE_DIR", path.join(directory, "cache")); vi.stubEnv("CORB_STATE_DIR", path.join(directory, "state")); return directory; }
it("publishes bytes once and rehashes existing complete objects", async () => {
  setup();
  const digest = await publishBytes("verified");
  expect(await publishBytes("verified")).toBe(digest);
  expect(fs.statSync(blobPath(digest)).mode & 0o777).toBe(0o400);
  fs.chmodSync(blobPath(digest), 0o600);
  fs.writeFileSync(blobPath(digest), "corrupt");
  await expect(publishBytes("verified")).rejects.toThrow("corrupt");
  expect(fs.readFileSync(blobPath(digest), "utf8")).toBe("corrupt");
});
it("rejects bad candidate data before publication", async () => {
  const directory = setup(); const file = path.join(directory, "source"); fs.writeFileSync(file, "wrong");
  await expect(publishBlob(file, `sha256:${sha256("expected")}`)).rejects.toThrow("mismatch");
  expect(fs.existsSync(blobPath(sha256("expected")))).toBe(false);
});
it("rejects a symlink cache object and missing objects", async () => {
  const directory = setup(); const file = path.join(directory, "source"); fs.writeFileSync(file, "x");
  fs.symlinkSync(file, path.join(directory, "link"));
  await expect(hashFile(path.join(directory, "link"))).rejects.toThrow("invalid");
  await expect(verifyBlob(sha256("missing"))).rejects.toThrow("layer pull");
});
it("fails a live lock and releases only its own token", () => {
  setup(); const release = acquireWorkspaceLock("named");
  expect(() => acquireWorkspaceLock("named")).toThrow("live or uncertain");
  const file = path.join(layerState("named"), "writer.json");
  const replacement = { ...JSON.parse(fs.readFileSync(file, "utf8")), token: "other" };
  fs.writeFileSync(file, JSON.stringify(replacement)); release();
  expect(fs.existsSync(file)).toBe(true);
});
it("recovers only a provably dead owner", () => {
  setup(); acquireWorkspaceLock("named");
  const kill = vi.spyOn(process, "kill").mockImplementation(() => { throw Object.assign(new Error("dead"), { code: "ESRCH" }); });
  const release = acquireWorkspaceLock("named"); release(); expect(kill).toHaveBeenCalled();
  expect(fs.existsSync(path.join(layerState("named"), "writer.json"))).toBe(false);
});
it("does not recover uncertain ownership", () => {
  setup(); acquireWorkspaceLock("named");
  vi.spyOn(process, "kill").mockImplementation(() => { throw Object.assign(new Error("permission"), { code: "EPERM" }); });
  expect(() => acquireWorkspaceLock("named")).toThrow("live or uncertain");
});
it("bounds streamed downloads", async () => {
  const directory = setup();
  await expect(boundedCopy(Readable.from([Buffer.alloc(4), Buffer.alloc(4)]), path.join(directory, "bounded"), 5)).rejects.toThrow("exceeds");
});
it("verifies copied candidate bytes before exposing a complete CAS object", async () => {
  const directory = setup(); const file = path.join(directory, "source"); fs.writeFileSync(file, "expected");
  const original = fs.copyFileSync;
  vi.spyOn(fs, "copyFileSync").mockImplementation((source, destination, mode) => { fs.writeFileSync(source, "changed"); original(source, destination, mode); });
  const digest = `sha256:${sha256("expected")}`;
  await expect(publishBlob(file, digest)).rejects.toThrow("staged blob");
  expect(fs.existsSync(blobPath(digest))).toBe(false);
});
