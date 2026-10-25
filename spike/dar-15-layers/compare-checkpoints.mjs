import fs from "node:fs";
import path from "node:path";
import { createHash } from "node:crypto";
import { spawnSync, execFileSync } from "node:child_process";
import { VmCheckpoint } from "@earendil-works/gondolin";
import { runtime, read, log, sha256, diskInfo } from "./common.mjs";

const first = read("fixed-layer");
const second = read("fixed-layer-repeat");
const metadata = [first, second].map(value => VmCheckpoint.load(value.path).toJSON());
log("repeat-artifact", {
  files: [first, second].map(value => ({ path: value.path, sha256: sha256(value.path), info: diskInfo(value.path) })),
  metadata,
  differingMetadataKeys: Object.keys(metadata[0]).filter(key => JSON.stringify(metadata[0][key]) !== JSON.stringify(metadata[1][key])),
});
const comparison = spawnSync("qemu-img", ["compare", "-f", "qcow2", "-F", "qcow2", first.path, second.path], { encoding: "utf8" });
log("repeat-guest-disk-comparison", { status: comparison.status, stdout: comparison.stdout, stderr: comparison.stderr });
if (![0, 1].includes(comparison.status)) throw new Error("qemu-img compare failed");
const logs = ["evidence-25-fixed-install-retry.log", "evidence-31-repeat-layer.log"].map(filename => fs.readFileSync(path.join(import.meta.dirname, filename), "utf8").trim().split("\n").map(line => JSON.parse(line)));
const manifests = logs.map(entries => {
  const record = entries.find(entry => entry.label.endsWith("-base-files-after"));
  return new Map(fs.readFileSync(record.file, "utf8").trim().split("\n").map(line => [line.slice(66), line.slice(0, 64)]));
});
log("repeat-content-manifests", {
  different: [...manifests[0]].filter(([file, digest]) => manifests[1].get(file) !== digest).map(([file]) => file),
  added: [...manifests[1].keys()].filter(file => !manifests[0].has(file)),
});
const candidates = ["/etc/apk/world", "/lib/apk/db/installed", "/etc/ssl/certs/ca-certificates.crt", "/usr/local/share/ca-certificates/gondolin-mitm-ca.crt"];
for (const [index, value] of [first, second].entries()) {
  const raw = path.join(runtime, "repeat-inspect-" + index + ".ext4");
  try {
    execFileSync("qemu-img", ["convert", "-O", "raw", value.path, raw]);
    for (const file of candidates) {
      const stat = spawnSync("/usr/sbin/debugfs", ["-R", "stat " + file, raw], { encoding: "utf8" });
      const data = spawnSync("/usr/sbin/debugfs", ["-R", "cat " + file, raw], { encoding: null });
      if (stat.error || data.error) throw stat.error ?? data.error;
      log("repeat-file-details", { index, file, stat: stat.stdout, stderr: stat.stderr, bytes: data.stdout.length, sha256: createHash("sha256").update(data.stdout).digest("hex") });
    }
  } finally {
    fs.rmSync(raw, { force: true });
  }
}
