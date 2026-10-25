import fs from "node:fs";
import path from "node:path";
import { root, repo, runtime, sdk, read, state, save, log, assert, fileSha } from "./common.mjs";

const prior = path.join(runtime, "base-b.json");
if (fs.existsSync(prior)) throw new Error("base B already exists for this runtime; keep it or use a fresh runtime");
const refs = sdk.listImageRefs();
const configDir = path.join(repo, "image");
const config = JSON.parse(fs.readFileSync(path.join(configDir, "corb-image.json"), "utf8"));
for (const item of config.postBuild.copy) {
  item.src = path.resolve(configDir, item.src.replace("{arch}", "amd64"));
  if (!fs.existsSync(item.src) && item.src.includes("guest/build/")) item.src = item.src.replace(repo, "/home/dario/Code/corb");
  assert(fs.existsSync(item.src), "missing base build input " + item.src);
}
config.postBuild.commands.unshift("apk add --no-cache " + config.alpine.rootfsPackages.filter(name => name !== "linux-virt").join(" "));
const removals = config.postBuild.commands.findIndex(command => command.startsWith("rm -f /usr/bin/npm"));
assert(removals >= 0, "base recipe removals changed");
config.postBuild.commands[removals] = config.postBuild.commands[removals].replace(" /sbin/apk", "");
const tree = read("prepared").targets.find(row => row.P === "tree");
config.postBuild.commands.splice(removals, 0,
  "apk add --no-cache tree=" + tree.V,
  "addgroup -g 350 redis && adduser -D -H -u 350 -G redis -h /var/lib/redis -s /sbin/nologin redis",
  "addgroup -g 351 apkconsumer && adduser -D -H -u 351 -G apkconsumer -h /var/lib/apkconsumer -s /sbin/nologin apkconsumer",
  "mkdir -p /var/lib/redis /var/lib/apkconsumer && printf 'consumer redis data\\n' > /var/lib/redis/consumer.txt && chown -R 350:350 /var/lib/redis && printf 'consumer-only account data\\n' > /var/lib/apkconsumer/sentinel && chown -R 351:351 /var/lib/apkconsumer",
  "printf '# APK portability consumer config\\nport 0\\n' > /etc/redis.conf",
  "apk del apk-tools");
state("base-b-build-config", config);
log("base-b-build-start", { root: runtime, tree: tree.V, consumerUids: [350, 351] });
const started = performance.now();
const built = await sdk.buildAssets(config, { outputDir: path.join(runtime, "base-b-assets"), configDir, verbose: true });
assert(sdk.verifyAssets(built.outputDir), "new base B assets failed verification");
const imported = sdk.importImageFromDirectory(built.outputDir);
assert(JSON.stringify(sdk.listImageRefs()) === JSON.stringify(refs), "base build changed a global ref");
const result = { name: "variant", buildId: imported.buildId, assetDir: imported.assetDir, manifest: built.manifest,
  manifestSha256: await fileSha(path.join(imported.assetDir, "manifest.json")), buildMs: Math.round(performance.now() - started),
  configSha256: await fileSha(path.join(runtime, "base-b-build-config.json")), createdRef: false };
state("base-b", result);
save("base-b", result);
log("base-b-built", result);
