import fs from "node:fs";
import path from "node:path";
import { buildAssets, importImageFromDirectory, tagImage, resolveImageSelector } from "@earendil-works/gondolin";
import { root, runtime, log, save } from "./common.mjs";

const variant = process.argv[2] ?? "fixed";
if (!["fixed", "plain"].includes(variant)) throw new Error("Expected fixed or plain");
const original = resolveImageSelector("corb:0.1.0");
const configDir = path.resolve(root, "../../image");
const config = JSON.parse(fs.readFileSync(path.join(configDir, "corb-image.json"), "utf8"));
for (const item of config.postBuild.copy) {
  item.src = path.resolve(configDir, item.src.replace("{arch}", "amd64"));
  if (!fs.existsSync(item.src) && item.src.includes("guest/build/")) {
    item.src = item.src.replace(path.resolve(root, "../.."), "/home/dario/Code/corb");
  }
  if (!fs.existsSync(item.src)) throw new Error("Missing build input: " + item.src);
}
if (variant === "fixed") {
  config.postBuild.commands.unshift("apk add --no-cache " + config.alpine.rootfsPackages.filter(name => name !== "linux-virt").join(" "));
  const removals = config.postBuild.commands.findIndex(command => command.startsWith("rm -f /usr/bin/npm"));
  config.postBuild.commands[removals] = config.postBuild.commands[removals].replace(" /sbin/apk", "");
  config.postBuild.commands.splice(removals, 0, "apk del apk-tools");
}
fs.writeFileSync(path.join(runtime, "build-" + variant + ".json"), JSON.stringify(config, null, 2) + "\n");
const start = performance.now();
const built = await buildAssets(config, { outputDir: path.join(runtime, "image-" + variant), configDir, verbose: true });
const buildMs = performance.now() - start;
const imported = importImageFromDirectory(built.outputDir);
const tag = tagImage(imported.buildId, "corb-spike:dar-15-" + variant, config.arch);
const result = {
  variant, buildMs, buildId: imported.buildId, assetDir: built.outputDir, tag,
  rootfsBytes: fs.statSync(path.join(built.outputDir, "rootfs.ext4")).size,
  rootfsAllocatedBytes: fs.statSync(path.join(built.outputDir, "rootfs.ext4")).blocks * 512,
};
save("image-" + variant, result);
log("build-result", result);
const after = resolveImageSelector("corb:0.1.0");
if (after.buildId !== original.buildId) throw new Error("Runtime tag changed unexpectedly");
log("runtime-tag-unchanged", { before: original.buildId, after: after.buildId });
