import fs from "node:fs";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { resolveImageSelector } from "@earendil-works/gondolin";
import { runtime, root, read, save, log } from "./common.mjs";

const config = JSON.parse(fs.readFileSync(path.resolve(root, "../../image/corb-image.json"), "utf8"));
for (const variant of ["plain", "fixed"]) {
  const record = read("image-" + variant);
  const resolved = resolveImageSelector(record.tag.reference);
  const image = path.join(resolved.assetDir, "rootfs.ext4");
  const debugfs = command => execFileSync("/usr/sbin/debugfs", ["-R", command, image], { encoding: "utf8", maxBuffer: 16 * 1024 * 1024 });
  const db = debugfs("cat /lib/apk/db/installed");
  const packages = db.split("\n\n").map(block => Object.fromEntries(
    block.split("\n").filter(line => /^[PVCp]:/.test(line)).map(line => [line[0], line.slice(2)]),
  )).filter(record => record.P);
  const statistics = debugfs("stats");
  const number = name => Number(new RegExp("^" + name + ":\\s*(\\d+)", "m").exec(statistics)?.[1]);
  const expected = config.alpine.rootfsPackages.filter(name => name !== "linux-virt");
  const result = {
    variant, buildId: resolved.buildId, assetDir: resolved.assetDir, packages,
    missingRootfsPackages: expected.filter(name => !packages.some(pkg => pkg.P === name || pkg.p?.split(" ").some(capability => capability.split("=")[0] === name))),
    world: debugfs("cat /etc/apk/world"),
    fileBytes: fs.statSync(image).size,
    filesystemUsedBytes: (number("Block count") - number("Free blocks")) * number("Block size"),
  };
  log("build-database", result);
  save("image-" + variant + "-database", result);
  const outputDir = record.outputDir ?? record.assetDir;
  record.outputDir = outputDir;
  record.assetDir = resolved.assetDir;
  save("image-" + variant, record);
  if (process.argv.includes("--discard-output")) {
    const expectedOutput = path.join(runtime, "image-" + variant);
    if (outputDir !== expectedOutput || outputDir === resolved.assetDir) throw new Error("Unexpected duplicate output path");
    if (resolved.buildId !== record.buildId || !fs.existsSync(image)) throw new Error("Imported image missing or mismatched");
    fs.rmSync(outputDir, { recursive: true, force: true });
    log("discarded-duplicate-output", { outputDir, preservedImage: resolved.assetDir, buildId: resolved.buildId });
  }
}
log("runtime-tag", resolveImageSelector("corb:0.1.0"));
