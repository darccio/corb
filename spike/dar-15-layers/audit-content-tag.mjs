import fs from "node:fs";
import path from "node:path";
import { createHash } from "node:crypto";
import { resolveArchPlaceholders } from "../../src/commands/image.ts";

const root = import.meta.dirname;
const sourceDir = path.resolve(root, "../../image");
const scratch = path.join(root, "runtime/content-tag-inputs");
const configDir = path.join(scratch, "image");
fs.mkdirSync(configDir, { recursive: true });
const config = JSON.parse(fs.readFileSync(path.join(sourceDir, "corb-image.json"), "utf8"));
resolveArchPlaceholders(config, "x86_64");
for (const entry of config.postBuild.copy) {
  let source = path.resolve(sourceDir, entry.src);
  if (!fs.existsSync(source)) source = source.replace(path.resolve(root, "../.."), "/home/dario/Code/corb");
  const target = path.resolve(configDir, entry.src);
  fs.mkdirSync(path.dirname(target), { recursive: true });
  fs.copyFileSync(source, target);
}
const initSource = path.resolve(sourceDir, config.init.rootfsInitExtra);
const initTarget = path.resolve(configDir, config.init.rootfsInitExtra);
fs.mkdirSync(path.dirname(initTarget), { recursive: true });
fs.copyFileSync(initSource, initTarget);

function contentHash() {
  const hash = createHash("sha256").update(JSON.stringify(config));
  for (const entry of config.postBuild.copy) {
    hash.update(entry.dest);
    hash.update(fs.readFileSync(path.resolve(configDir, entry.src)));
  }
  return hash.digest("hex").slice(0, 8);
}

const before = contentHash();
fs.appendFileSync(initTarget, "\n# DAR-15 content-tag probe\n");
const changedInit = contentHash();
fs.appendFileSync(path.resolve(configDir, config.postBuild.copy[0].src), "DAR-15");
const changedPostBuildCopy = contentHash();
console.log(JSON.stringify({
  source: "src/commands/image.ts:155-164",
  originalHash: before,
  changedInitHash: changedInit,
  initChangeDetected: before !== changedInit,
  changedPostBuildCopyHash: changedPostBuildCopy,
  postBuildCopyChangeDetected: before !== changedPostBuildCopy,
}, null, 2));
if (before !== changedInit || before === changedPostBuildCopy) throw new Error("Unexpected content-tag audit result");
