import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { Readable } from "node:stream";
import { afterEach, expect, it } from "vitest";
import { stageSdkArchive, walkTar } from "../../../src/layer/tar.ts";
import { sha256 } from "../../../src/layer/validate.ts";
import { payload } from "./fixtures.ts";
import { gzipTar, tar, pax } from "./tar-fixtures.ts";
const dirs: string[] = [];
afterEach(() => { for (const dir of dirs.splice(0)) { for (const filename of fs.readdirSync(dir, { recursive: true, withFileTypes: true }).filter((row) => row.isDirectory()).reverse()) fs.chmodSync(path.join(filename.parentPath, filename.name), 0o700); fs.rmSync(dir, { recursive: true, force: true }); } });
async function extract(rows: Parameters<typeof tar>[0]) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "corb-tar-")); dirs.push(dir); const archive = path.join(dir, "sdk.gz");
  const bytes = gzipTar(rows); fs.writeFileSync(archive, bytes);
  const plan = { ...payload(), arch: "x86_64" as const, sha256: sha256(bytes) };
  return { tree: await stageSdkArchive(archive, plan, path.join(dir, "tree")), dir };
}
it("copies a complete tree and preserves only executable bits", async () => {
  const { tree, dir } = await extract([{ path: "go/", type: "5" }, { path: "go/bin/", type: "5" }, { path: "go/bin/go", body: "binary", mode: 0o755 }, { path: "go/README", body: "text", mode: 0o644 }]);
  expect(tree.entries).toHaveLength(3); expect(fs.readFileSync(path.join(dir, "tree/bin/go"), "utf8")).toBe("binary");
  expect(fs.statSync(path.join(dir, "tree/README")).mode & 0o777).toBe(0o444);
});
it.each(["../escape", "/absolute", "go/../escape", "go//bad"])("rejects path %s", async (name) => { await expect(extract([{ path: name, body: "bad" }])).rejects.toThrow(); });
it.each(["1", "2", "3", "4", "6"])("rejects links and special node %s", async (type) => { await expect(extract([{ path: "go/bad", type, link: "/escape" }])).rejects.toThrow(); });
it("validates the effective PAX and GNU long names", async () => {
  await expect(extract([{ path: "PaxHeader", type: "x", body: pax("path", "go/../../escape") }, { path: "go/safe", body: "bad" }])).rejects.toThrow();
  await expect(extract([{ path: "././@LongLink", type: "L", body: "go/../../escape\0" }, { path: "go/safe", body: "bad" }])).rejects.toThrow();
});
it("rejects duplicate stripped paths and malformed checksums", async () => {
  await expect(extract([{ path: "go/file", body: "one" }, { path: "other/file", body: "two" }])).rejects.toThrow("duplicate");
  const bytes = tar([{ path: "go/file", body: "one" }]); bytes[0] = 65;
  await expect(walkTar(Readable.from([bytes]), async (_entry, chunks) => { for await (const _ of chunks) { /* consume */ } })).rejects.toThrow("checksum");
});
it("bounds expanded bytes and entry count", async () => {
  const bytes = tar([{ path: "a", body: "body" }]);
  await expect(walkTar(Readable.from([bytes]), async (_entry, chunks) => { for await (const _ of chunks) { /* consume */ } }, { limit: 100 })).rejects.toThrow("limit");
  await expect(walkTar(Readable.from([bytes]), async (_entry, chunks) => { for await (const _ of chunks) { /* consume */ } }, { entries: 0 })).rejects.toThrow("entries");
});
