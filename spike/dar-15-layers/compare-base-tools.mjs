import fs from "node:fs";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { runtime, read } from "./common.mjs";

const candidates = [
  ["bash", "/bin/bash"], ["curl", "/usr/bin/curl"], ["git", "/usr/local/libexec/real-git"],
  ["nodejs", "/usr/bin/node"], ["github-cli", "/usr/local/libexec/real-gh"],
  ["jq", "/usr/bin/jq"], ["openssh-client-default", "/usr/bin/ssh"], ["bindfs", "/usr/bin/bindfs"],
];
const hashes = {};
for (const variant of ["plain", "fixed"]) {
  const image = read("image-" + variant);
  const database = read("image-" + variant + "-database");
  const directory = path.join(runtime, "base-tools", variant);
  fs.mkdirSync(directory, { recursive: true });
  for (const [pkg, file] of candidates) {
    const target = path.join(directory, pkg);
    execFileSync("/usr/sbin/debugfs", ["-R", "dump " + file + " " + target, path.join(image.assetDir, "rootfs.ext4")]);
    const digest = createHash("sha256").update(fs.readFileSync(target)).digest("hex");
    hashes[pkg] ??= { file };
    hashes[pkg][variant] = { sha256: digest, database: database.packages.find(record => record.P === pkg) ?? null };
  }
}
for (const [pkg, value] of Object.entries(hashes)) {
  console.log(JSON.stringify({ package: pkg, ...value, bytesUnchanged: value.plain.sha256 === value.fixed.sha256 }));
}
