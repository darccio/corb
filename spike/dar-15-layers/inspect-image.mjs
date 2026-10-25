import { execFileSync } from "node:child_process";
import { listImageRefs, resolveImageSelector } from "@earendil-works/gondolin";

const image = resolveImageSelector("corb:0.1.0");
console.log(JSON.stringify({ image, refs: listImageRefs() }, null, 2));
const db = execFileSync("/usr/sbin/debugfs", ["-R", "cat /lib/apk/db/installed", image.assetDir + "/rootfs.ext4"], { encoding: "utf8" });
const records = db.split("\n\n").map(block => Object.fromEntries(
  block.split("\n").filter(line => line.includes(":")).map(line => [line.slice(0, line.indexOf(":")), line.slice(line.indexOf(":") + 1)]),
));
for (const name of ["apk-tools", "libapk", "nodejs", "git", "curl", "bash", "fuse3-libs", "libcrypto3", "libssl3"]) {
  const record = records.find(item => item.P === name);
  console.log(JSON.stringify({ name, entry: record ? { name: record.P, version: record.V, checksum: record.C } : null }));
}
console.log("installed-count", records.filter(record => record.P).length);
console.log("world", execFileSync("/usr/sbin/debugfs", ["-R", "cat /etc/apk/world", image.assetDir + "/rootfs.ext4"], { encoding: "utf8" }));
