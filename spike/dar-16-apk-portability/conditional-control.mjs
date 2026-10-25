import fs from "node:fs";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { fileURLToPath, pathToFileURL } from "node:url";
import { assertPreimages } from "./plan.mjs";

const action = process.argv[3];
if (!["prepare", "run"].includes(action)) throw new Error("Pass the APK runtime and an explicit prepare or run action");
const evidenceDirectory = path.resolve(process.env.DAR16_CONDITIONAL_EVIDENCE_DIR ??
  path.join(process.env.DAR16_APK_EVIDENCE_DIR ?? path.join(import.meta.dirname, "evidence"), "conditional-control"));
for (const filename of ["fixed.json", "variant.json", "resolution.json"]) {
  if (fs.existsSync(path.join(evidenceDirectory, filename))) throw new Error("refuse to overwrite a matrix evidence directory");
}
process.env.DAR16_APK_EVIDENCE_DIR = evidenceDirectory;
const { runtime, root, evidence, sdk, fixed, read, state, save, log, sha, fileSha, assert, usingVm, execute,
  database, protectedSet, gates, assertGateReports, closeAndCheck, sourceIdentity } = await import("./common.mjs");
const helperPath = path.join(path.dirname(fileURLToPath(import.meta.resolve("@earendil-works/gondolin"))), "assets.js");
const { computeAssetBuildId } = await import(pathToFileURL(helperPath).href);
const marker = "/etc/corb/apk-portability-control.txt";
const markerBytes = "Conditional APK delta control: unrelated base config remains present.\n";
const source = read("fixed-result");
const diff = read("fixed-delta");
const archive = path.join(runtime, "output/delta.tar");
const diffBytes = JSON.stringify(diff);
assert(JSON.stringify(JSON.parse(fs.readFileSync(path.join(runtime, "output/delta.json"), "utf8"))) === diffBytes, "replay metadata differs from the producer delta");
assert(await fileSha(archive) === read("delta-result").deltaTarSha256, "producer delta tar changed");
assert(!diff.changed.some(row => row.path === marker) && !diff.deleted.includes(marker), "control marker overlaps the delta");
assert(sdk.verifyAssets(fixed.assetDir), "source A asset verification failed");
const manifestA = JSON.parse(fs.readFileSync(path.join(fixed.assetDir, "manifest.json"), "utf8"));
assert(computeAssetBuildId({ checksums: manifestA.checksums, arch: manifestA.config.arch }) === fixed.buildId, "private SDK helper disagrees with source A identity");
const refsBefore = sdk.listImageRefs();
const baseFile = path.join(runtime, "base-c.json");

async function prepareC() {
  assert(!fs.existsSync(baseFile), "base C already exists: keep it or use a new task runtime");
  const privateDir = path.join(runtime, "base-c-private");
  fs.mkdirSync(privateDir);
  const copies = [];
  for (const filename of Object.values(manifestA.assets)) {
    assert(path.basename(filename) === filename, "unexpected nested base asset path");
    const original = path.join(fixed.assetDir, filename);
    const target = path.join(privateDir, filename);
    const before = fs.lstatSync(original);
    assert(before.isFile() && !before.isSymbolicLink(), "source asset is not a regular file");
    fs.copyFileSync(original, target, fs.constants.COPYFILE_EXCL | fs.constants.COPYFILE_FICLONE);
    const copied = fs.lstatSync(target);
    assert(copied.isFile() && !copied.isSymbolicLink() && copied.nlink === 1, "private copy is linked or not regular");
    assert(copied.dev !== before.dev || copied.ino !== before.ino, "private copy shares the canonical inode");
    assert(fs.realpathSync(target) !== fs.realpathSync(original), "private copy resolves to original asset");
    const copiedHash = await fileSha(target);
    assert(copiedHash === await fileSha(original), "private copy differs before mutation");
    copies.push({ filename, sourceInode: before.ino, sourceDevice: before.dev, privateInode: copied.ino,
      privateDevice: copied.dev, privateNlink: copied.nlink, beforeSha256: copiedHash });
  }
  const privateRoot = path.join(privateDir, manifestA.assets.rootfs);
  fs.chmodSync(privateRoot, 0o600);
  const markerInput = path.join(runtime, "conditional-control-marker.txt");
  fs.writeFileSync(markerInput, markerBytes);
  const written = execFileSync("/usr/sbin/debugfs", ["-w", "-R", "write " + markerInput + " " + marker, privateRoot], { encoding: "utf8", timeout: 60_000 });
  const actual = execFileSync("/usr/sbin/debugfs", ["-R", "cat " + marker, privateRoot], { timeout: 60_000 });
  assert(actual.equals(Buffer.from(markerBytes)), "private marker write failed");
  const manifest = structuredClone(manifestA);
  for (const [name, filename] of Object.entries(manifest.assets)) manifest.checksums[name] = await fileSha(path.join(privateDir, filename));
  manifest.buildId = computeAssetBuildId({ checksums: manifest.checksums, arch: manifest.config.arch });
  assert(manifest.buildId !== fixed.buildId && manifest.checksums.rootfs !== manifestA.checksums.rootfs, "control did not change actual content identity");
  fs.writeFileSync(path.join(privateDir, "manifest.json"), JSON.stringify(manifest, null, 2) + "\n");
  assert(sdk.verifyAssets(privateDir), "private C assets failed checksums");
  const imported = sdk.importImageFromDirectory(privateDir);
  assert(imported.buildId === manifest.buildId && sdk.verifyAssets(imported.assetDir), "imported C identity failed");
  assert(sdk.verifyAssets(fixed.assetDir), "source A changed during private preparation");
  assert(JSON.stringify(sdk.listImageRefs()) === JSON.stringify(refsBefore), "private preparation changed a global ref");
  const result = { name: "conditional", buildId: imported.buildId, assetDir: imported.assetDir, manifest,
    sourceBuildId: fixed.buildId, sourceManifestSha256: await fileSha(path.join(fixed.assetDir, "manifest.json")),
    manifestSha256: await fileSha(path.join(imported.assetDir, "manifest.json")), marker, markerSha256: sha(markerBytes), copies,
    helper: { path: helperPath, sourceSha256: await fileSha(helperPath), sourceLines: "assets.js:219-234", privateExperimentalUseOnly: true },
    createdRef: false, producerDeltaSha256: sha(diffBytes), deltaTarSha256: await fileSha(archive), debugfsWrite: written };
  state("base-c", result); save("base-c", result);
  log("conditional-base-ready", { buildId: result.buildId, rootfsSha256: manifest.checksums.rootfs, vmBoots: 0 });
}
async function snapshot(vm, label) {
  return JSON.parse((await execute(vm, label, "node /work/work/snapshot.cjs", { output: false })).stdout);
}
async function native(vm, label) {
  await execute(vm, label + "-native", "test \"$(id -u)\" = 1000; node /work/work/native.cjs", { agent: true, timeout: 90_000 });
  await execute(vm, label + "-seven-removals", "for name in npm npx su sudo doas apk apk.static; do if command -v \"$name\"; then exit 1; fi; done; echo ALL_SEVEN_ABSENT", { agent: true });
  return JSON.parse(fs.readFileSync(path.join(runtime, "workspace-conditional/native-report.json"), "utf8"));
}
async function runC() {
  const base = read("base-c");
  assert(base.producerDeltaSha256 === sha(diffBytes) && base.deltaTarSha256 === await fileSha(archive), "C preparation uses different delta bytes");
  assert(base.buildId !== fixed.buildId && sdk.verifyAssets(base.assetDir), "invalid distinct C base");
  assert(await fileSha(path.join(base.assetDir, "manifest.json")) === base.manifestSha256, "C manifest changed");
  const checkpoint = path.join(runtime, "conditional-apk.qcow2");
  assert(!fs.existsSync(checkpoint), "conditional checkpoint exists: use a new task runtime");
  const result = await usingVm(base, "conditional-replay", { output: true, verify: true }, undefined, async vm => {
    const protectedBefore = await protectedSet(vm, "conditional-protected-before");
    assert(protectedBefore.split("\n").filter(line => line && !line.endsWith("  " + marker)).join("\n") + "\n" === source.baseline.protectedHashes,
      "C has unrelated protected changes beyond the marker");
    const before = await snapshot(vm, "conditional-before");
    assertPreimages(diff.preimages, before);
    log("conditional-preimages-match", { count: diff.preimages.length, allMatch: true, replayNotYetStarted: true });
    const databaseBefore = await database(vm, "conditional-before-db");
    assert(databaseBefore.sha256 === source.baseline.database.sha256, "C database differs from A before replay");
    const baselineGates = await gates(vm, "conditional-baseline-gate");
    assertGateReports(baselineGates);
    const beforeApply = await snapshot(vm, "conditional-before-apply");
    assertPreimages(diff.preimages, beforeApply);
    await execute(vm, "conditional-guarded-full-delta-replay", "cd /; tar -xf /opt/corb-apk-output/delta.tar; node /work/work/replay.cjs", { timeout: 180_000 });
    const after = new Map((await snapshot(vm, "conditional-after")).map(row => [row.path, row]));
    for (const row of diff.changed) assert(JSON.stringify(after.get(row.path)) === JSON.stringify(row), "C postimage mismatch: " + row.path);
    for (const filename of diff.deleted) assert(!after.has(filename), "C deleted path survived");
    const agent = await native(vm, "conditional-installed");
    assert(await protectedSet(vm, "conditional-protected-installed") === protectedBefore, "conditional replay changed C protected files");
    const markerCheck = await execute(vm, "conditional-marker", "sha256sum " + marker);
    assert(markerCheck.stdout.startsWith(base.markerSha256 + " "), "C marker lost after replay");
    const databaseAfter = await database(vm, "conditional-after-db");
    assert(databaseAfter.sha256 === source.installedDatabase.sha256, "C installed database differs from producer postimage");
    const candidateGates = await gates(vm, "conditional-candidate-gate");
    assertGateReports(baselineGates, candidateGates);
    const cache = await vm.checkpoint(checkpoint);
    return { preimagesChecked: diff.preimages.length, preconditionsEnabled: true, allPostimagesMatch: true,
      baselineGates, candidateGates, agent, protectedBefore, databaseBeforeSha256: databaseBefore.sha256,
      databaseAfterSha256: databaseAfter.sha256, markerPreserved: true, checkpoint: cache.toJSON(), checkpointSha256: await fileSha(checkpoint) };
  });
  const resumed = await usingVm(base, "conditional-resume", { verify: true }, checkpoint, async vm => {
    const agent = await native(vm, "conditional-resumed");
    assert(await protectedSet(vm, "conditional-protected-resumed") === result.protectedBefore, "C resume changed protected files");
    assert((await database(vm, "conditional-resumed-db")).sha256 === result.databaseAfterSha256, "C resume changed installed database");
    const report = await gates(vm, "conditional-resumed-gate");
    assertGateReports(result.baselineGates, result.candidateGates, report);
    return { agent, gates: report, protectedUnchanged: true, databaseUnchanged: true };
  });
  assert(await fileSha(checkpoint) === result.checkpointSha256, "C resume changed canonical checkpoint");
  assert(sdk.verifyAssets(fixed.assetDir) && sdk.verifyAssets(base.assetDir), "A or C canonical assets changed");
  assert(await fileSha(path.join(fixed.assetDir, "manifest.json")) === base.sourceManifestSha256, "A manifest changed");
  assert(await fileSha(path.join(base.assetDir, "manifest.json")) === base.manifestSha256, "C manifest changed");
  assert(JSON.stringify(sdk.listImageRefs()) === JSON.stringify(refsBefore), "C trial changed global refs");
  const summary = { verdict: "conditional-replay-works-for-this-matching-touched-state-control", baseBuildId: base.buildId,
    producerBaseBuildId: fixed.buildId, sourceIdentity, controlSourceSha256: await fileSha(import.meta.filename),
    producerDeltaSha256: base.producerDeltaSha256, deltaTarSha256: base.deltaTarSha256, ...result, resume: resumed,
    nativeCases: result.agent.tests + resumed.agent.tests, refsUnchanged: true, canonicalAssetsUnchanged: true,
    xattrsTested: false, productionApplierImplemented: false };
  state("conditional-result", summary); save("result", summary);
}
const overall = setTimeout(async () => { await closeAndCheck(); process.exit(1); }, 20 * 60_000);
try {
  if (action === "prepare") await prepareC();
  else await runC();
} finally { clearTimeout(overall); await closeAndCheck(); }
