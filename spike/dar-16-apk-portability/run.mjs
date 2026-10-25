import fs from "node:fs";
import path from "node:path";
import { root, runtime, evidence, sdk, fixed, installer, prepare, read, save, state, sha, fileSha, assert,
  usingVm, execute, database, protectedSet, gates, assertGateReports, closeAndCheck, sourceIdentity, globalBaseline, log } from "./common.mjs";
import { parsePlan, delta, assertPreimages } from "./plan.mjs";

const phase = process.argv[3] ?? "all";
assert(["all", "fixed", "variant", "delta", "sudo", "hooks", "audit"].includes(phase), "unknown phase");
prepare("verify");
const prepared = read("prepared");
const variant = read("base-b");
const bases = [fixed, variant];
const refsBefore = sdk.listImageRefs();
assert(JSON.stringify(refsBefore) === JSON.stringify(globalBaseline.refs), "refs differ from the first task invocation");
save("global-baseline", globalBaseline);
const targets = prepared.targets.map(row => row.P + "=" + row.V).join(" ");
const packageByName = new Map(prepared.packages.map(row => [row.name, row]));
const bundleIdentity = { version: 1, branch: prepared.branch, arch: prepared.arch, indexes: prepared.indexes,
  packages: read("resolution").positive.map(row => packageByName.get(row.name)), installer: prepared.installer };
const bundleSha256 = sha(JSON.stringify(bundleIdentity));
state("bundle", { ...bundleIdentity, sha256: bundleSha256 });
save("bundle", { ...bundleIdentity, sha256: bundleSha256 });
for (const base of bases) {
  assert(sdk.verifyAssets(base.assetDir), "invalid base assets");
  base.manifest = JSON.parse(fs.readFileSync(path.join(base.assetDir, "manifest.json"), "utf8"));
  assert(base.manifest.buildId === base.buildId && base.manifest.config.arch === "x86_64", "unexpected base identity");
  base.manifestSha256 = await fileSha(path.join(base.assetDir, "manifest.json"));
  prepare("verify-base", base.assetDir);
}
const inputs = { bases, refsBefore, bundleSha256, sourceIdentity, harnessSha256: await fileSha(import.meta.filename),
  preparationSha256: await fileSha(path.join(root, "prepare.py")), commonSha256: await fileSha(path.join(root, "common.mjs")),
  planSha256: await fileSha(path.join(root, "plan.mjs")), fixture: Object.fromEntries(await Promise.all(fs.readdirSync(path.join(root, "fixture")).map(async name => [name, await fileSha(path.join(root, "fixture", name))]))) };
save("inputs", inputs); save("inputs-" + phase, inputs);
for (const name of ["negative-checksum", "negative-signature"]) save(name, read(name));
const overall = setTimeout(async () => { await closeAndCheck(); process.exit(1); }, 45 * 60_000);

async function snapshot(vm, label) {
  const result = await execute(vm, label, "node /work/work/snapshot.cjs", { output: false });
  const rows = JSON.parse(result.stdout);
  state(label, rows);
  return rows;
}
async function guestState(vm, label) {
  const result = await execute(vm, label, "node /work/work/state.cjs");
  return JSON.parse(result.stdout);
}
function checkRecords(before, after, additions) {
  const byName = new Map(after.records.map(row => [row.P, row]));
  for (const row of before.records) assert(JSON.stringify(row) === JSON.stringify(byName.get(row.P)), "existing package identity changed: " + row.P);
  const expectedNames = new Set([...before.records.map(row => row.P), ...additions.map(row => row.name)]);
  assert(after.records.length === expectedNames.size, "unexpected package record count");
  for (const row of additions) {
    const actual = byName.get(row.name); const signed = packageByName.get(row.name);
    assert(actual?.V === row.version && actual?.C === signed.checksum, "installed identity differs from signed bundle: " + row.name);
  }
}
async function agent(vm, label) {
  await execute(vm, label + "-native", "id; test \"$(id -u)\" = 1000; node /work/work/native.cjs", { agent: true, timeout: 90_000 });
  await execute(vm, label + "-seven-removals", "for name in npm npx su sudo doas apk apk.static; do if command -v \"$name\"; then exit 1; fi; done; echo ALL_SEVEN_ABSENT", { agent: true });
  return JSON.parse(fs.readFileSync(path.join(runtime, "workspace-" + label.split("-")[0], "native-report.json"), "utf8"));
}
async function trial(base) {
  const pendingPath = path.join(runtime, base.name + "-pending.json");
  const checkpoint = path.join(runtime, base.name + "-apk.qcow2");
  let result;
  if (fs.existsSync(pendingPath)) {
    result = read(base.name + "-pending");
    assert(result.identity.bundleSha256 === bundleSha256 && result.identity.baseBuildId === base.buildId, "saved trial inputs differ");
    assert(await fileSha(checkpoint) === result.checkpointSha256, "saved checkpoint changed");
    log("recover-trial", { base: base.name, reusedCompletedInstall: true });
  } else {
    assert(!fs.existsSync(checkpoint), "unrecorded checkpoint exists: use a new runtime");
    const baseline = await usingVm(base, base.name + "-baseline", { verify: true }, undefined, async vm => {
      const protectedHashes = await protectedSet(vm, base.name + "-protected-before");
      const db = await database(vm, base.name + "-baseline-db");
      const guest = await guestState(vm, base.name + "-baseline-state");
      const identity = await execute(vm, base.name + "-abi", "cat /etc/alpine-release; uname -m; /lib/ld-musl-x86_64.so.1 2>&1 || true; /usr/bin/openssl version 2>/dev/null || true");
      const report = await gates(vm, base.name + "-baseline-gate");
      assertGateReports(report);
      return { protectedHashes, database: db, state: guest, identity: identity.stdout, gates: report };
    });
    result = await usingVm(base, base.name + "-install", { install: true, output: true }, undefined, async vm => {
      const before = await database(vm, base.name + "-before-db");
      assert(before.sha256 === baseline.database.sha256, "base database differs between fresh VMs");
      const original = await snapshot(vm, base.name + "-snapshot-before");
      const planned = await execute(vm, base.name + "-plan", installer + " --no-cache add --simulate " + targets);
      const additions = parsePlan(planned.stdout, before.records);
      for (const row of additions) assert(packageByName.get(row.name)?.version === row.version, "plan requires a package outside shared bundle");
      const installation = await execute(vm, base.name + "-install-packages", installer + " --no-cache add " + targets);
      await execute(vm, base.name + "-repeat-removals", "rm -f /usr/bin/npm /usr/bin/npx /bin/su /usr/bin/su /usr/bin/sudo /usr/bin/doas /sbin/apk /sbin/apk.static");
      const after = await database(vm, base.name + "-after-db");
      checkRecords(before, after, additions);
      const protectedHashes = await protectedSet(vm, base.name + "-protected-installed");
      assert(protectedHashes === baseline.protectedHashes, "installation changed protected files");
      const installedState = await guestState(vm, base.name + "-installed-state");
      const native = await agent(vm, base.name + "-installed");
      const composed = await snapshot(vm, base.name + "-snapshot-after");
      const diff = delta(original, composed);
      assert(!diff.changed.some(row => row.type === "special"), "delta contains unsupported special nodes");
      state(base.name + "-delta", diff);
      save(base.name + "-delta", diff);
      if (base.name === "fixed") {
        fs.writeFileSync(path.join(runtime, "output", "delta.json"), JSON.stringify(diff));
        const paths = diff.changed.filter(row => row.type !== "directory").map(row => row.path.slice(1));
        assert(paths.every(filename => !filename.includes("\n") && !filename.startsWith("-")), "invalid tar path");
        fs.writeFileSync(path.join(runtime, "output", "paths.txt"), paths.join("\n") + "\n");
        await execute(vm, "fixed-capture-full-state-delta", "cd /; tar -cf /opt/corb-apk-output/delta.tar -T /opt/corb-apk-output/paths.txt", { timeout: 180_000 });
      }
      const identity = { version: 1, policy: "signed-apk-per-base-v1", baseBuildId: base.buildId,
        baseManifestSha256: base.manifestSha256, baseAssetChecksums: base.manifest.checksums, bundleSha256 };
      const cache = await vm.checkpoint(checkpoint);
      return { base: base.name, identity, compositionSha256: sha(JSON.stringify(identity)), checkpoint: cache.toJSON(),
        checkpointSha256: await fileSha(checkpoint), baseline, additions,
        installedDatabase: after, installedState, native, changedPaths: diff.changed.length, deletedPaths: diff.deleted.length,
        installation: { exitCode: installation.exitCode, stdout: installation.stdout, stderr: installation.stderr } };
    });
    state(base.name + "-pending", result);
  }
  const resumed = await usingVm(base, base.name + "-resume", { verify: true }, checkpoint, async vm => {
    const native = await agent(vm, base.name + "-resumed");
    const protectedHashes = await protectedSet(vm, base.name + "-protected-resumed");
    assert(protectedHashes === result.baseline.protectedHashes, "resumed protected files changed");
    const db = await database(vm, base.name + "-resumed-db");
    assert(db.sha256 === result.installedDatabase.sha256, "resumed database changed");
    const resumedState = await guestState(vm, base.name + "-resumed-state");
    const report = await gates(vm, base.name + "-candidate-resumed-gate");
    assertGateReports(result.baseline.gates, report);
    return { native, state: resumedState, gates: report, protectedUnchanged: true, databaseUnchanged: true };
  });
  assert(await fileSha(checkpoint) === result.checkpointSha256, "resume mutated canonical checkpoint");
  result.resume = resumed;
  state(base.name + "-result", result); save(base.name, result);
  return result;
}
async function replay() {
  const diff = read("fixed-delta");
  const outcome = await usingVm(variant, "unsafe-delta", { output: true, verify: true }, undefined, async vm => {
    const before = await guestState(vm, "delta-before");
    const destination = await snapshot(vm, "delta-destination-before");
    let rejected;
    try { assertPreimages(diff.preimages, destination); } catch (error) { rejected = String(error); }
    assert(rejected, "conditional delta should reject differing consumer state");
    log("conditional-delta-rejected", { error: rejected, beforeReplay: true });
    await execute(vm, "unsafe-full-delta-replay", "cd /; tar -xf /opt/corb-apk-output/delta.tar; node /work/work/replay.cjs", { timeout: 180_000 });
    const after = await guestState(vm, "delta-after");
    const actual = await snapshot(vm, "delta-destination-after");
    const byPath = new Map(actual.map(row => [row.path, row]));
    for (const row of diff.changed) assert(JSON.stringify(byPath.get(row.path)) === JSON.stringify(row), "replay postimage mismatch: " + row.path);
    for (const filename of diff.deleted) assert(!byPath.has(filename), "deleted path survived replay");
    assert(before.accounts.some(row => row.name === "apkconsumer") && !after.accounts.some(row => row.name === "apkconsumer"), "full replay did not reproduce account loss");
    assert(after.paths["/var/lib/apkconsumer/sentinel"].uid === 351, "consumer data unexpectedly disappeared");
    assert(before.paths["/etc/redis.conf"].sha256 !== after.paths["/etc/redis.conf"].sha256, "consumer config was not overwritten");
    const native = await agent(vm, "variant-replayed");
    const protectedHashes = await protectedSet(vm, "delta-protected");
    assert(protectedHashes === fs.readFileSync(path.join(evidence, "variant-protected-before.sha256"), "utf8"), "unsafe replay modified protected files");
    const report = await gates(vm, "delta-gate");
    assertGateReports(read("base-variant-gates").gates, report);
    return { conditionalRejected: rejected, unconditionalReplayCounterexample: true, before, after, native, gates: report,
      replayedPaths: diff.changed.length, deletedPaths: diff.deleted.length, deltaTarSha256: await fileSha(path.join(runtime, "output/delta.tar")) };
  });
  state("delta-result", outcome); save("delta-replay", outcome);
}
async function sudoNegative() {
  const row = prepared.negativeTargets.find(row => row.P === "sudo");
  const outcome = await usingVm(fixed, "sudo-negative", { install: true }, undefined, async vm => {
    const before = await database(vm, "sudo-before-db");
    const plan = await execute(vm, "sudo-plan", installer + " --no-cache add --simulate sudo=" + row.V);
    parsePlan(plan.stdout, before.records);
    await execute(vm, "sudo-install", installer + " --no-cache add sudo=" + row.V);
    const report = [];
    const { GATES } = await import("./common.mjs");
    for (const gate of GATES) if (["gateSuid", "gateRemovals"].includes(gate.name)) {
      const result = await gate(vm); report.push(result);
    }
    assert(report.some(gate => gate.name === "suid" && !gate.ok && gate.detail.includes("sudo")), "sudo SUID detector did not reject");
    assert(report.some(gate => gate.name === "removals" && !gate.ok && gate.detail.includes("sudo")), "sudo PATH detector did not reject");
    return { rejected: true, intendedSecurityFailures: report, checkpointPublished: false };
  });
  state("sudo-result", outcome); save("negative-sudo", outcome);
}
async function audit() {
  const results = bases.map(base => read(base.name + "-result"));
  for (const item of results) assertGateReports(item.baseline.gates, item.resume.gates);
  let wrongBaseRejected = false;
  try {
    const unexpected = await sdk.VmCheckpoint.load(path.join(runtime, "fixed-apk.qcow2")).resume({ sandbox: { imagePath: variant.assetDir, vmm: "qemu" }, memory: "1G", cpus: 2 });
    await unexpected.close();
  } catch (error) { wrongBaseRejected = /do not match checkpoint buildId/.test(String(error)); log("wrong-base-negative", { error: String(error), rejected: wrongBaseRejected }); }
  assert(wrongBaseRejected, "wrong-base checkpoint accepted");
  for (const item of results) assert(await fileSha(path.join(runtime, item.base + "-apk.qcow2")) === item.checkpointSha256, "checkpoint changed after wrong-base rejection");
  prepare("verify");
  assert(JSON.stringify(sdk.listImageRefs()) === JSON.stringify(refsBefore), "existing refs changed");
  for (const base of bases) assert(sdk.verifyAssets(base.assetDir) && await fileSha(path.join(base.assetDir, "manifest.json")) === base.manifestSha256, "canonical base changed");
  for (const base of globalBaseline.objects) assert(sdk.verifyAssets(base.assetDir) && await fileSha(path.join(base.assetDir, "manifest.json")) === base.manifestSha256, "existing referenced asset changed");
  const result = { signedBundleReuse: "go-with-limits", unconditionalInstalledDeltaReuse: "no-go-for-differing-touched-state",
    conditionalDelta: "requires-matching-preimages-not-tested-as-production-applier", localCheckpointReuse: "exact-base-only",
    bundleSha256, unchangedSignedInputs: true, refsUnchanged: true, canonicalBasesUnchanged: true, wrongBaseRejected,
    bases: results.map(item => ({ name: item.base, buildId: item.identity.baseBuildId, rootfsSha256: item.identity.baseAssetChecksums.rootfs,
      additions: item.additions, checkpointSha256: item.checkpointSha256, compositionSha256: item.compositionSha256,
      baselineGatePasses: item.baseline.gates.filter(gate => gate.ok).length, resumedGatePasses: item.resume.gates.filter(gate => gate.ok).length,
      installedRedis: item.installedState.accounts.find(row => row.name === "redis"), resumedRedisRunDirectory: item.resume.state.paths["/run/redis"] })),
    nativeExecutions: results.reduce((count, item) => count + item.native.tests + item.resume.native.tests, 0),
    sourceIdentity, imageGatesAllPassed: results.every(item => [...item.baseline.gates, ...item.resume.gates].every(gate => gate.ok)),
    negativeSudo: read("sudo-result"), delta: read("delta-result"), temporaryApkHookContext: read("hooks-result"), registryTransportTested: false, crossArchTested: false };
  state("result", result); save("result", result);
}
async function hookVariant() {
  const baseline = read("fixed-result");
  const checkpoint = path.join(runtime, "hooks-apk.qcow2");
  assert(!fs.existsSync(checkpoint), "hook-variant checkpoint exists: use a fresh runtime");
  const built = await usingVm(fixed, "hook-context-install", { install: true }, undefined, async vm => {
    const before = await database(vm, "hooks-before-db");
    const plan = await execute(vm, "hooks-plan", installer + " --no-cache add --simulate " + targets);
    const additions = parsePlan(plan.stdout, before.records);
    await execute(vm, "hooks-temporary-apk", "test ! -e /sbin/apk; ln -s " + installer + " /sbin/apk");
    const installed = await execute(vm, "hooks-install-packages", installer + " --no-cache add " + targets);
    assert(installed.stdout.includes("Executing postgresql-common-") && installed.stdout.includes(".trigger"), "PG trigger did not execute");
    assert(!installed.stderr.includes("apk: not found"), "temporary hook context did not remove missing-apk failure");
    await execute(vm, "hooks-remove-temporary-apk", "rm -f /usr/bin/npm /usr/bin/npx /bin/su /usr/bin/su /usr/bin/sudo /usr/bin/doas /sbin/apk /sbin/apk.static; test ! -e /sbin/apk");
    const after = await database(vm, "hooks-after-db");
    checkRecords(before, after, additions);
    const native = await agent(vm, "fixed-hooks-installed");
    const protectedHashes = await protectedSet(vm, "hooks-protected-installed");
    assert(protectedHashes === baseline.baseline.protectedHashes, "temporary hook context changed protected files");
    const cache = await vm.checkpoint(checkpoint);
    return { installation: { exitCode: installed.exitCode, stdout: installed.stdout, stderr: installed.stderr }, additions,
      native, databaseSha256: after.sha256, checkpoint: cache.toJSON(), checkpointSha256: await fileSha(checkpoint) };
  });
  const resumed = await usingVm(fixed, "hook-context-resume", { verify: true }, checkpoint, async vm => {
    const native = await agent(vm, "fixed-hooks-resumed");
    await execute(vm, "hooks-installer-not-published", "test ! -e /sbin/apk; test -z \"$(ls -A /opt/corb-apk-input)\"");
    assert(await protectedSet(vm, "hooks-protected-resumed") === baseline.baseline.protectedHashes, "hook resume changed protected files");
    assert((await database(vm, "hooks-resumed-db")).sha256 === built.databaseSha256, "hook resume changed database");
    const report = await gates(vm, "hooks-candidate-gate");
    assertGateReports(baseline.baseline.gates, report);
    return { native, gates: report, installerAbsent: true, protectedUnchanged: true, databaseUnchanged: true };
  });
  assert(await fileSha(checkpoint) === built.checkpointSha256, "hook resume changed canonical checkpoint");
  const result = { experimentOnly: true, productionPolicyApproved: false, duringTransactionOnly: "/sbin/apk -> readonly external apk.static",
    strictCaseStderr: baseline.installation.stderr, ...built, resume: resumed };
  state("hooks-result", result); save("hooks", result);
}
try {
  for (const base of bases) if (phase === "all" || phase === base.name) {
    const result = await trial(base);
    state("base-" + base.name + "-gates", { gates: result.baseline.gates });
  }
  if (phase === "all" || phase === "delta") await replay();
  if (phase === "all" || phase === "sudo") await sudoNegative();
  if (phase === "all" || phase === "hooks") await hookVariant();
  if (phase === "all" || phase === "audit") await audit();
} finally { clearTimeout(overall); await closeAndCheck(); }
