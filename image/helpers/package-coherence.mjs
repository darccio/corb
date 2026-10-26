import fs from "node:fs";
import path from "node:path";
import { createHash } from "node:crypto";
import { inflateRawSync } from "node:zlib";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const digest = (bytes, algorithm = "sha256", encoding = "hex") => createHash(algorithm).update(bytes).digest(encoding);
export const REQUIRED_PACKAGES = [
  "linux-virt", "bash", "ca-certificates", "curl", "git", "openssh-client-krb5",
  "ripgrep", "fd", "jq", "less", "nodejs", "npm", "github-cli", "tzdata",
  "fuse3-libs", "libstdc++", "libgcc", "zstd-libs", "libssl3", "libcrypto3",
];
export function parseInstalled(text) {
  return text.trim().split(/\n\n+/).filter(Boolean).map((block) => {
    const record = { files: [] };
    let directory = "";
    for (const line of block.split("\n")) {
      if (line[1] !== ":") continue;
      const value = line.slice(2);
      if (line[0] === "F") directory = value;
      else if (line[0] === "R") record.files.push(`/${directory}/${value}`.replaceAll("//", "/"));
      else if (["P", "V", "A", "C", "D", "p"].includes(line[0])) record[line[0]] = value;
    }
    return record;
  });
}
export function assertRequired(records) {
  const byName = new Map(records.map((record) => [record.P, record]));
  for (const name of REQUIRED_PACKAGES) {
    if (!byName.has(name)) throw new Error(`${name}: recorded version (missing), required package record absent`);
  }
  if (byName.has("openssh-client-default")) {
    throw new Error(`openssh-client-default: recorded version ${byName.get("openssh-client-default").V}, conflicts with required openssh-client-krb5`);
  }
  const providers = records.filter((record) => record.p?.split(" ").some((entry) => entry.startsWith("cmd:ssh=")));
  if (providers.length !== 1 || providers[0].P !== "openssh-client-krb5") {
    throw new Error(`openssh-client-krb5: recorded version ${byName.get("openssh-client-krb5").V}, conflicting or missing cmd:ssh providers`);
  }
}
export function gzipMembers(bytes) {
  const members = [];
  let offset = 0;
  while (offset < bytes.length) {
    const start = offset;
    if (bytes[offset] !== 31 || bytes[offset + 1] !== 139 || bytes[offset + 2] !== 8) throw new Error("invalid APK gzip member");
    const flags = bytes[offset + 3];
    offset += 10;
    if (flags & 4) { const length = bytes.readUInt16LE(offset); offset += 2 + length; }
    for (const flag of [8, 16]) if (flags & flag) { while (bytes[offset++] !== 0) if (offset >= bytes.length) throw new Error("invalid gzip header"); }
    if (flags & 2) offset += 2;
    const inflated = inflateRawSync(bytes.subarray(offset), { info: true });
    offset += inflated.engine.bytesWritten + 8;
    if (offset > bytes.length) throw new Error("truncated APK gzip member");
    members.push({ compressed: bytes.subarray(start, offset), data: inflated.buffer });
  }
  return members;
}
export function tarEntries(bytes) {
  const entries = new Map();
  for (let offset = 0; offset + 512 <= bytes.length;) {
    const header = bytes.subarray(offset, offset + 512);
    if (header.every((byte) => byte === 0)) { offset += 512; continue; }
    const string = (start, length) => header.subarray(start, start + length).toString().split("\0")[0];
    const name = [string(345, 155), string(0, 100)].filter(Boolean).join("/").replace(/^\.\//, "");
    const size = Number.parseInt(string(124, 12), 8) || 0;
    const type = string(156, 1);
    offset += 512;
    if (offset + size > bytes.length) throw new Error(`truncated archive entry ${name}`);
    entries.set(name, { type, bytes: bytes.subarray(offset, offset + size), link: string(157, 100) });
    offset += Math.ceil(size / 512) * 512;
  }
  return entries;
}
export function archiveIdentity(bytes) {
  const members = gzipMembers(bytes);
  const control = members.find((member) => tarEntries(member.data).has(".PKGINFO"));
  if (!control) throw new Error("signed APK has no .PKGINFO control member");
  const fields = Object.fromEntries(tarEntries(control.data).get(".PKGINFO").bytes.toString().split("\n")
    .filter((line) => line.includes(" = ")).map((line) => line.split(" = ")));
  const payload = members.at(-1);
  if (digest(payload.compressed) !== fields.datahash) throw new Error(`${fields.pkgname}: signed datahash differs from archive payload`);
  const signatures = [...tarEntries(members[0].data).keys()].filter((name) => name.startsWith(".SIGN."));
  return { name: fields.pkgname, version: fields.pkgver, arch: fields.arch, signatures,
    checksum: `Q1${digest(control.compressed, "sha1", "base64")}`, archiveSha256: digest(bytes), payload: tarEntries(payload.data) };
}
export function assertIdentity(record, archive) {
  for (const [key, observed] of [["P", archive.name], ["V", archive.version], ["A", archive.arch], ["C", archive.checksum]]) {
    const compatibleNoarch = key === "A" && observed === "noarch" && ["x86_64", "aarch64"].includes(record.A);
    if (record[key] !== observed && !compatibleNoarch) {
      throw new Error(`${record.P}: recorded version ${record.V}, ${key}=${record[key]} differs from signed archive ${observed}`);
    }
  }
}
export function assertFile(record, filename, expected, observed) {
  const expectedSha256 = digest(expected);
  const observedSha256 = digest(observed);
  if (expectedSha256 !== observedSha256) {
    throw new Error(`${record.P}: recorded version ${record.V}, ${filename} bytes ${observedSha256} differ from signed archive ${expectedSha256}`);
  }
  return observedSha256;
}
function command(argv) {
  return execFileSync(argv[0], argv.slice(1), { encoding: "utf8", timeout: 120_000, maxBuffer: 16 * 1024 * 1024 });
}
export function validateReport(report, database, readFile = fs.readFileSync) {
  const records = parseInstalled(database.toString());
  assertRequired(records);
  if (records.length !== report.packages?.length || new Set(report.packages.map((entry) => entry.name)).size !== records.length) {
    throw new Error("APK package identities differ from the complete signed validation report");
  }
  for (const identity of report.packages) {
    const record = records.find((entry) => entry.P === identity.name);
    if (!record) throw new Error(`${identity.name}: recorded version (missing), validated package record absent`);
    assertIdentity(record, identity);
  }
  if (digest(database) !== report.databaseSha256) throw new Error("APK database changed after trusted package-coherence validation");
  for (const check of report.files) {
    const record = records.find((entry) => entry.P === check.package);
    if (!record || record.V !== check.version || record.C !== check.checksum) {
      throw new Error(`${check.package}: recorded version ${record?.V ?? "(missing)"}, differs from validated archive ${check.version}`);
    }
    const observed = digest(readFile(check.path));
    if (observed !== check.sha256) throw new Error(`${record.P}: recorded version ${record.V}, ${check.path} bytes ${observed} differ from signed archive ${check.sha256}`);
  }
  return report;
}
function main() {
  const reportPath = "/etc/corb/package-coherence.json";
  const database = fs.readFileSync("/lib/apk/db/installed");
  if (process.argv.includes("--validate-report")) {
    validateReport(JSON.parse(fs.readFileSync(reportPath, "utf8")), database);
    console.log("package-coherence: recorded identities and native library bytes match validated signed archives");
    return;
  }
  const records = parseInstalled(database.toString());
  assertRequired(records);
  command(["/sbin/apk", "fix", "--simulate", "--no-network"]);
  command(["/sbin/apk", "update"]);
  const temporary = fs.mkdtempSync("/tmp/corb-coherence-");
  try {
    const owners = new Map(records.flatMap((record) => record.files.map((filename) => [filename, record])));
    const requiredFiles = new Set(["/usr/bin/ssh", "/usr/lib/libssl.so.3", "/usr/lib/libcrypto.so.3"]);
    for (const binary of ["/bin/bash", "/usr/bin/ssh", "/usr/bin/curl", "/usr/libexec/git-core/git-remote-http", "/usr/bin/node", "/usr/bin/bindfs", "/usr/bin/jq", "/usr/bin/rg", "/usr/bin/fd", "/usr/bin/less"]) {
      const linked = command(["/usr/bin/ldd", binary]);
      if (/not found|Error loading|Error relocating/.test(linked)) throw new Error(`${binary}: unresolved native dependency: ${linked}`);
      for (const match of linked.matchAll(/(?:=>\s+|^\s*)(\/[^\s()]+)/gm)) requiredFiles.add(match[1]);
    }
    const paths = [...requiredFiles].map((filename) => fs.realpathSync(filename));
    for (const filename of paths) if (!owners.has(filename)) throw new Error(`${filename}: required native library or SSH provider has no recorded package`);
    const packages = [];
    const files = [];
    for (const record of records) {
      command(["/sbin/apk", "fetch", "--output", temporary, record.P]);
      const downloaded = fs.readdirSync(temporary);
      if (downloaded.length !== 1) throw new Error(`${record.P}: recorded version ${record.V}, expected one signed archive`);
      const filename = path.join(temporary, downloaded[0]);
      command(["/sbin/apk", "verify", filename]);
      const archive = archiveIdentity(fs.readFileSync(filename));
      assertIdentity(record, archive);
      packages.push({ name: record.P, version: record.V, arch: record.A, archiveArch: archive.arch, checksum: record.C, archiveSha256: archive.archiveSha256, signatures: archive.signatures });
      for (const filename of new Set(paths.filter((entry) => owners.get(entry) === record))) {
        let entry = archive.payload.get(filename.slice(1));
        if (entry?.type === "1") entry = archive.payload.get(entry.link);
        if (!entry || !["0", ""].includes(entry.type)) throw new Error(`${record.P}: recorded version ${record.V}, ${filename} absent from signed payload`);
        const sha256 = assertFile(record, filename, entry.bytes, fs.readFileSync(filename));
        files.push({ path: filename, package: record.P, version: record.V, checksum: record.C, sha256 });
      }
      fs.unlinkSync(filename);
    }
    const trustedKeys = fs.readdirSync("/etc/apk/keys").sort().map((name) => ({ name, sha256: digest(fs.readFileSync(path.join("/etc/apk/keys", name))) }));
    const report = { databaseSha256: digest(database), trustedKeys, packages, files };
    fs.mkdirSync(path.dirname(reportPath), { recursive: true });
    fs.writeFileSync(reportPath, `${JSON.stringify(report, null, 2)}\n`, { mode: 0o644 });
    console.log(`package-coherence: ${packages.length} signed package/control identities and ${files.length} native files verified`);
  } finally { fs.rmSync(temporary, { recursive: true, force: true }); }
}
if (process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1])) main();
