import { createHash, generateKeyPairSync, sign } from "node:crypto";
import { gzipSync } from "node:zlib";
import { expect, it } from "vitest";
import { apkGzipMembers, verifiedApk, verifiedIndex } from "../../../src/layer/apk.ts";
import { sha256 } from "../../../src/layer/validate.ts";
import { tar } from "./tar-fixtures.ts";
const keys = generateKeyPairSync("rsa", { modulusLength: 2048 });
const trusted = { "alpine-devel@lists.alpinelinux.org-6165ee59.rsa.pub": keys.publicKey.export({ type: "spki", format: "pem" }).toString() };
function signature(control: Buffer) { return gzipSync(tar([{ path: ".SIGN.RSA.alpine-devel@lists.alpinelinux.org-6165ee59.rsa.pub", body: sign("RSA-SHA1", control, keys.privateKey) }])); }
function fixture(changes: Record<string, string> = {}) {
  const data = gzipSync(tar([{ path: "sbin/apk.static", body: Buffer.from("7f454c460001", "hex") }]));
  const fields = { pkgname: "apk-tools-static", pkgver: "3.0.8-r0", arch: "x86_64", datahash: sha256(data), ...changes };
  const control = gzipSync(tar([{ path: ".PKGINFO", body: Object.entries(fields).map(([key, value]) => `${key} = ${value}\n`).join("") }]));
  const bytes = Buffer.concat([signature(control), control, data]);
  const record = { P: "apk-tools-static", V: "3.0.8-r0", A: "x86_64", C: `Q1${createHash("sha1").update(control).digest("base64")}`, S: bytes.length, D: "", p: "", repository: "main" as const };
  return { bytes, record };
}
it("authenticates signed control C, identity, payload and exact binary", async () => {
  const { bytes, record } = fixture(); const apk = await verifiedApk(bytes, record, trusted, "x86_64", sha256(bytes), true);
  expect(apk.binary?.subarray(0, 4).toString("hex")).toBe("7f454c46"); expect(apk.key).toBe("alpine-devel@lists.alpinelinux.org-6165ee59.rsa.pub");
});
it.each([{ pkgname: "other" }, { pkgver: "0-r0" }, { arch: "aarch64" }, { datahash: "0".repeat(64) }])("rejects signed but inconsistent APK fields %j", async (changes) => {
  const { bytes, record } = fixture(changes); await expect(verifiedApk(bytes, record, trusted, "x86_64")).rejects.toThrow();
});
it("rejects checksum, digest, signature, archive size and untrusted keys", async () => {
  const { bytes, record } = fixture();
  await expect(verifiedApk(bytes, { ...record, C: `Q1${Buffer.alloc(20).toString("base64")}` }, trusted, "x86_64")).rejects.toThrow("checksum");
  await expect(verifiedApk(bytes, record, trusted, "x86_64", "0".repeat(64))).rejects.toThrow("SHA-256");
  await expect(verifiedApk(bytes, { ...record, S: bytes.length + 1 }, trusted, "x86_64")).rejects.toThrow("size");
  await expect(verifiedApk(bytes, record, {}, "x86_64")).rejects.toThrow("trusted");
  const other = generateKeyPairSync("rsa", { modulusLength: 2048 });
  await expect(verifiedApk(bytes, record, { "alpine-devel@lists.alpinelinux.org-6165ee59.rsa.pub": other.publicKey.export({ type: "spki", format: "pem" }).toString() }, "x86_64")).rejects.toThrow("signature verification");
});
it("authenticates an index before parsing identities", async () => {
  const { record } = fixture(); const content = gzipSync(tar([{ path: "APKINDEX", body: `P:${record.P}\nV:${record.V}\nA:x86_64\nC:${record.C}\nS:${record.S}\n\n` }]));
  const bytes = Buffer.concat([signature(content), content]);
  expect((await verifiedIndex(bytes, trusted, "main", "x86_64"))[0]?.P).toBe("apk-tools-static");
  await expect(verifiedIndex(bytes, {}, "main", "x86_64")).rejects.toThrow("trusted");
  await expect(verifiedIndex(bytes, trusted, "main", "aarch64")).rejects.toThrow("architecture");
});
it("rejects unsupported archive formats", () => { expect(() => apkGzipMembers(Buffer.from("not gzip"))).toThrow("unsupported"); });
it("retains unrelated signed real-index names and sizes without making them input artifacts", async () => {
  const { record } = fixture();
  const content = gzipSync(tar([{ path: "APKINDEX", body: `P:freeswitch-sounds-ru-RU-elena-32000\nV:1-r0\nA:x86_64\nC:${record.C}\nS:900000000\n\nP:${record.P}\nV:${record.V}\nA:x86_64\nC:${record.C}\nS:${record.S}\n\n` }]));
  const records = await verifiedIndex(Buffer.concat([signature(content), content]), trusted, "main", "x86_64");
  expect(records[0]).toMatchObject({ P: "freeswitch-sounds-ru-RU-elena-32000", S: 900000000 });
});
