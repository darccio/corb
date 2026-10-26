import { createHash, verify, createPublicKey } from "node:crypto";
import { inflateRawSync, gunzipSync } from "node:zlib";
import { tarBuffer } from "./tar.ts";
import { fail, sha256, type LayerArch } from "./validate.ts";
import { validateApkindexChecksum } from "./pins.ts";

export interface ApkIndexRecord { P: string; V: string; A: string; C: string; S: number; D: string; p: string; repository: "main" | "community" }
export interface ApkMember { compressed: Buffer; data: Buffer }
export function apkGzipMembers(bytes: Buffer): ApkMember[] {
  const members: ApkMember[] = [];
  let offset = 0;
  let expanded = 0;
  while (offset < bytes.length) {
    if (members.length >= 3) fail("unsupported APK format: more than three gzip members");
    const start = offset;
    if (bytes[offset] !== 31 || bytes[offset + 1] !== 139 || bytes[offset + 2] !== 8 || bytes.length - offset < 18) fail("unsupported or truncated APK gzip format");
    const flags = bytes[offset + 3]!;
    if (flags & 0xe0) fail("unsupported APK gzip flags");
    offset += 10;
    if (flags & 4) { if (offset + 2 > bytes.length) fail("truncated gzip extra"); const length = bytes.readUInt16LE(offset); offset += 2 + length; }
    for (const flag of [8, 16]) if (flags & flag) { let length = 0; while (bytes[offset++] !== 0) { if (++length > 4096 || offset >= bytes.length) fail("invalid gzip filename/comment"); } }
    if (flags & 2) offset += 2;
    if (offset >= bytes.length) fail("truncated gzip header");
    const inflated = inflateRawSync(bytes.subarray(offset), { info: true, maxOutputLength: 512 * 1024 ** 2 }) as unknown as { engine: { bytesWritten: number } };
    offset += inflated.engine.bytesWritten + 8;
    if (offset > bytes.length) fail("truncated gzip member");
    const compressed = bytes.subarray(start, offset);
    // gunzip also verifies CRC and ISIZE, which raw DEFLATE does not cover.
    const data = gunzipSync(compressed, { maxOutputLength: 512 * 1024 ** 2 });
    expanded += data.length;
    if (expanded > 512 * 1024 ** 2) fail("APK expansion exceeds 512 MiB");
    members.push({ compressed, data });
  }
  return members;
}
export type ApkKeys = Readonly<Record<string, string>>;
export async function verifyApkSignature(members: readonly ApkMember[], keys: ApkKeys): Promise<string> {
  if (members.length < 2) fail("signed APK archive needs a signature and control member");
  const signatures = await tarBuffer(members[0]!.data);
  let trusted = false;
  for (const [name, { entry, bytes }] of signatures) {
    const match = /^\.SIGN\.(RSA|RSA256|RSA512)\.([A-Za-z0-9][A-Za-z0-9._@+-]*)$/.exec(name);
    if (match === null || entry.type !== "file" || bytes.length > 16 * 1024) fail(`unsupported APK signature format '${name}'`);
    const pem = keys[match[2]!];
    if (pem === undefined) continue;
    trusted = true;
    const key = createPublicKey(pem);
    if (key.asymmetricKeyType !== "rsa") fail("unsupported APK signing key type");
    const algorithm = { RSA: "RSA-SHA1", RSA256: "RSA-SHA256", RSA512: "RSA-SHA512" }[match[1]!]!;
    if (verify(algorithm, members[1]!.compressed, key, bytes)) return match[2]!;
  }
  fail(trusted ? "APK signature verification failed" : "APK has no signature from a trusted base key");
}
export async function verifiedIndex(bytes: Buffer, keys: ApkKeys, repository: ApkIndexRecord["repository"], arch: LayerArch): Promise<ApkIndexRecord[]> {
  if (bytes.length > 16 * 1024 ** 2) fail("APK index exceeds 16 MiB");
  const members = apkGzipMembers(bytes);
  if (members.length !== 2) fail("unsupported signed APK index archive format");
  await verifyApkSignature(members, keys);
  const entries = await tarBuffer(members[1]!.data);
  const index = entries.get("APKINDEX");
  if (index?.entry.type !== "file") fail("signed index has no APKINDEX file");
  const text = new TextDecoder("utf-8", { fatal: true }).decode(index.bytes);
  const seen = new Set<string>();
  return text.trim().split(/\n\n+/).filter(Boolean).map((block) => {
    const fields: Record<string, string> = {};
    for (const line of block.split("\n")) {
      if (line[1] !== ":" || line[0]! in fields) fail("malformed or duplicate signed APKINDEX field");
      fields[line[0]!] = line.slice(2);
    }
    if (!/^[A-Za-z0-9][A-Za-z0-9+_.-]*$/.test(fields.P ?? "") || !/^[^\s/\0:@]+$/.test(fields.V ?? "") || ![arch, "noarch"].includes(fields.A ?? "") || !/^[1-9][0-9]*$/.test(fields.S ?? "")) fail("invalid signed APKINDEX identity, size or architecture");
    const size = Number(fields.S);
    if (!Number.isSafeInteger(size)) fail("invalid signed APK archive size");
    validateApkindexChecksum(fields.C);
    const identity = `${fields.P}=${fields.V}`;
    if (seen.has(identity)) fail("duplicate signed APKINDEX identity");
    seen.add(identity);
    return { P: fields.P!, V: fields.V!, A: fields.A!, C: fields.C!, S: size, D: fields.D ?? "", p: fields.p ?? "", repository };
  });
}
export interface VerifiedApk {
  name: string; version: string; arch: string; checksum: string; archiveSha256: string; key: string;
  dependencies: string[]; provides: string[];
  files: Array<{ path: string; type: string; mode: number; sha256?: string; link?: string; native?: boolean }>;
  binary?: Buffer;
}
export async function verifiedApk(bytes: Buffer, record: ApkIndexRecord, keys: ApkKeys, arch: LayerArch, expectedSha256?: string, installer = false): Promise<VerifiedApk> {
  if (bytes.length !== record.S || bytes.length > 512 * 1024 ** 2) fail("APK archive size differs from signed index");
  const archiveSha256 = sha256(bytes);
  if (expectedSha256 !== undefined && archiveSha256 !== expectedSha256) fail("APK archive SHA-256 differs from locked bytes");
  const members = apkGzipMembers(bytes);
  if (members.length !== 3) fail("unsupported signed v2 APK archive format");
  const checksum = `Q1${createHash("sha1").update(members[1]!.compressed).digest("base64")}`;
  if (checksum !== record.C) fail("APK signed C checksum differs from index");
  const key = await verifyApkSignature(members, keys);
  const control = await tarBuffer(members[1]!.data);
  const info = control.get(".PKGINFO");
  if (info?.entry.type !== "file") fail("APK has no signed .PKGINFO");
  const fields: Record<string, string[]> = {};
  for (const line of info.bytes.toString("utf8").split("\n")) {
    const match = /^([a-zA-Z0-9_]+) = (.*)$/.exec(line);
    if (match !== null) (fields[match[1]!] ??= []).push(match[2]!);
  }
  for (const field of ["pkgname", "pkgver", "arch", "datahash"]) if (fields[field]?.length !== 1) fail(`missing or duplicate signed APK field '${field}'`);
  if (fields.pkgname![0] !== record.P || fields.pkgver![0] !== record.V || ![arch, "noarch"].includes(fields.arch![0]!) || (fields.arch![0] !== record.A && fields.arch![0] !== "noarch")) fail("APK name, version or architecture differs from signed index");
  if (!/^[a-f0-9]{64}$/.test(fields.datahash![0]!) || sha256(members[2]!.compressed) !== fields.datahash![0]) fail("APK payload differs from signed payload hash");
  const payload = await tarBuffer(members[2]!.data);
  const files: VerifiedApk["files"] = [];
  let binary: Buffer | undefined;
  for (const [name, { entry, bytes: content }] of payload) {
    const filename = name.replace(/^\.\//, "").replace(/\/$/, "");
    if (filename.startsWith("/") || filename.split("/").some((component) => component === "" || component === "." || component === "..") || filename.includes("\0")) fail("unsafe signed APK payload path");
    if (!["file", "directory", "1", "2"].includes(entry.type)) fail("unsupported signed APK payload node");
    if (installer && filename === "sbin/apk.static") {
      if (entry.type !== "file" || binary !== undefined || content.length > 16 * 1024 ** 2 || (entry.mode & 0o111) === 0 || content.subarray(0, 4).toString("hex") !== "7f454c46") fail("invalid static APK installer binary");
      binary = content;
    }
    files.push({ path: `/${filename}`, type: entry.type, mode: entry.mode,
      ...(entry.type === "file" ? { sha256: sha256(content), native: content.subarray(0, 4).toString("hex") === "7f454c46" } : {}),
      ...(["1", "2"].includes(entry.type) ? { link: entry.link } : {}) });
  }
  if (installer && (record.P !== "apk-tools-static" || binary === undefined)) fail("APK installer has no intended sbin/apk.static binary");
  return { name: record.P, version: record.V, arch: fields.arch![0]!, checksum, archiveSha256, key, dependencies: fields.depend ?? [], provides: fields.provides ?? [], files, ...(binary === undefined ? {} : { binary }) };
}
