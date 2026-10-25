import fs from "node:fs";
import path from "node:path";
import { createHash } from "node:crypto";
import { pathToFileURL } from "node:url";
import { assertGateReports } from "./gate-report.mjs";

const runtime = path.resolve(process.argv[2] ?? "");
if (!process.argv[2] || runtime === "/") throw new Error("Pass the prepared task runtime directory");
const auditOnly = process.argv[3] === "--audit-only";
if (process.argv[3] && !auditOnly) throw new Error("Only --audit-only is supported after the runtime path");
const root = import.meta.dirname;
const repo = path.resolve(root, "../..");
const evidence = path.resolve(process.env.DAR16_EVIDENCE_DIR ?? path.join(root, "evidence"));
fs.mkdirSync(evidence, { recursive: true });
fs.mkdirSync(path.join(runtime, "tmp"), { recursive: true });
process.env.TMPDIR = path.join(runtime, "tmp");
process.env.GONDOLIN_SESSIONS_DIR = path.join(runtime, "sessions");

const { VM, VmCheckpoint, RealFSProvider, ReadonlyProvider, createHttpHooks, verifyAssets, listImageRefs, listSessions } = await import("@earendil-works/gondolin");
const { buildGateConfigMount, GATE_CONFIG_RAW_ROOT } = await import("../../src/vm/session.ts");
const prepared = JSON.parse(fs.readFileSync(path.join(runtime, "prepare.json"), "utf8"));
const basePath = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";
const sdkPath = "/opt/corb/go";
const inputPath = "/mnt/corb-sdk-input";
const definitions = [
  { name: "stock", buildId: "2747a805-7a7e-5798-84ca-077fb5086311", rootfsSha256: "66dcee4cc7bcc04b67f1567a806bc16e8d0c00e0b09763593f72b4841533b5cf" },
  { name: "fixed", buildId: "e8292a0a-0a1a-52d5-959b-9ed372068d54", rootfsSha256: "de13c9757a2aaef4aecbc331bbb54416940e8f0dca4367ffbd7b766e9716cec7" },
];
let liveVm;
let deniedDuringGo = 0;
let pureGo = false;
const ownedPids = [];
const outcomes = [];
const events = [];

function sha(value) { return createHash("sha256").update(value).digest("hex"); }
async function fileSha(filename) {
  const hash = createHash("sha256");
  for await (const chunk of fs.createReadStream(filename)) hash.update(chunk);
  return hash.digest("hex");
}
function save(name, value) { fs.writeFileSync(path.join(evidence, name + ".json"), JSON.stringify(value, null, 2) + "\n"); }
function log(label, value) {
  const item = { label, ...value };
  events.push(item);
  console.log(JSON.stringify(item));
  fs.appendFileSync(path.join(evidence, "events.jsonl"), JSON.stringify(item) + "\n");
}
function assert(value, reason) { if (!value) throw new Error(reason); }
function destination(value) {
  if (value !== sdkPath) throw new Error("destination outside the dedicated SDK prefix");
  return value;
}
function treeManifest() {
  const directory = path.join(runtime, "payload");
  const rows = [];
  function walk(current) {
    for (const entry of fs.readdirSync(current, { withFileTypes: true })) {
      const full = path.join(current, entry.name);
      const relative = path.relative(directory, full).split(path.sep).join("/");
      const stat = fs.lstatSync(full);
      assert(!stat.isSymbolicLink() && (stat.isDirectory() || stat.isFile()), "invalid payload entry");
      const mode = "0o" + (stat.mode & 0o777).toString(8);
      rows.push({ relative, line: (stat.isDirectory() ? "d" : sha(fs.readFileSync(full))) + " " + mode + " " + relative });
      if (stat.isDirectory()) walk(full);
    }
  }
  walk(directory);
  return rows.sort((a, b) => a.relative < b.relative ? -1 : a.relative > b.relative ? 1 : 0).map(row => row.line).join("\n") + "\n";
}
async function execute(vm, label, script, { agent = false, output = true, required = true, env = {}, timeout = 300_000 } = {}) {
  const started = performance.now();
  const result = await vm.exec(agent ? ["/usr/local/bin/dropcap", "1000", "1000", "/bin/sh", "-ec", script] : ["/bin/sh", "-ec", script], {
    env: { PATH: basePath, HOME: agent ? "/home/agent" : "/root", CORB_GATE_CONFIG: "/run/corb/gate.json", ...env },
    stdout: "buffer", stderr: "buffer", signal: AbortSignal.timeout(timeout),
  });
  const pid = vm.getHostPid();
  if (pid && !ownedPids.includes(pid)) {
    ownedPids.push(pid);
    log("owned-vm", { pid });
  }
  log(label, { exitCode: result.exitCode, ms: Math.round(performance.now() - started),
    ...(output ? { stdout: result.stdout, stderr: result.stderr } : { stdoutSha256: sha(result.stdout), stdoutBytes: Buffer.byteLength(result.stdout), stderr: result.stderr }) });
  if (required) assert(result.ok, label + " failed: " + result.stderr);
  return result;
}
function options(base, label, mountPayload) {
  const hooks = createHttpHooks({ allowedHosts: ["api.anthropic.com", "github.com"], allowedInternalHosts: [] });
  const request = hooks.httpHooks.onRequest;
  hooks.httpHooks.onRequest = async value => {
    if (pureGo) {
      deniedDuringGo += 1;
      return new Response("Pure Go trial forbids outbound HTTP", { status: 403 });
    }
    return request ? await request(value) : undefined;
  };
  const workspace = path.join(runtime, "workspace-" + base.name);
  fs.mkdirSync(workspace, { recursive: true });
  for (const name of fs.readdirSync(path.join(root, "fixture"))) fs.copyFileSync(path.join(root, "fixture", name), path.join(workspace, name));
  const mounts = { [GATE_CONFIG_RAW_ROOT]: buildGateConfigMount(), "/mnt/corb-raw/work": new RealFSProvider(workspace) };
  if (mountPayload) mounts[inputPath] = new ReadonlyProvider(new RealFSProvider(path.join(runtime, "payload")));
  return { sandbox: { imagePath: base.assetDir, vmm: "qemu" }, memory: "1G", cpus: 2, startTimeoutMs: 90_000,
    dns: { mode: "synthetic", syntheticHostMapping: "per-host" }, httpHooks: hooks.httpHooks, env: hooks.env,
    allowWebSockets: false, ssh: { allowedHosts: [] }, vfs: { mounts }, sessionLabel: "dar16-go-" + label };
}
async function usingVm(base, label, mountPayload, checkpoint, action) {
  assert(!liveVm, "a VM is already running");
  const started = performance.now();
  const opts = options(base, label, mountPayload);
  liveVm = checkpoint ? await VmCheckpoint.load(checkpoint).resume(opts) : await VM.create(opts);
  const vm = liveVm;
  const pid = vm.getHostPid();
  if (pid) ownedPids.push(pid);
  log("vm-start", { base: base.name, phase: label, pid, ms: Math.round(performance.now() - started), resumed: Boolean(checkpoint) });
  try { return await action(vm); }
  finally {
    pureGo = false;
    await vm.close();
    liveVm = undefined;
    log("vm-closed", { base: base.name, phase: label, pid: vm.getHostPid() ?? pid });
  }
}
async function protectedSet(vm, name) {
  const result = await execute(vm, name, "find /init /usr/local/bin/dropcap /usr/local/libexec /etc/corb /usr/bin/bindfs /etc/apk/keys -type f -exec sha256sum '{}' ';' | sort", { output: false });
  fs.writeFileSync(path.join(evidence, name + ".sha256"), result.stdout);
  return result.stdout;
}
async function database(vm, label) {
  const result = await execute(vm, label, "cat /lib/apk/db/installed", { output: false });
  const identities = result.stdout.split("\n\n").filter(Boolean).map(record => {
    const fields = Object.fromEntries(record.split("\n").filter(line => /^[PVA]:/.test(line)).map(line => [line[0], line.slice(2)]));
    return fields;
  }).sort((a, b) => (a.P ?? "").localeCompare(b.P ?? ""));
  return { sha256: sha(result.stdout), identities };
}
const source = fs.readFileSync(path.join(repo, "image/verify.ts"), "utf8");
assert(source.includes("const GATES:"), "image gate adapter source changed");
const adapter = source.replace('"../src/vm/session.ts"', JSON.stringify(pathToFileURL(path.join(repo, "src/vm/session.ts")).href)).replace("const GATES:", "export const GATES:");
const adapterPath = path.join(runtime, "verify-adapter.ts");
fs.writeFileSync(adapterPath, adapter);
const { GATES } = await import(pathToFileURL(adapterPath).href);
async function gates(vm, label) {
  const bounded = new Proxy(vm, { get(target, key) {
    if (key === "exec") return (argv, opts) => target.exec(argv, { ...opts, signal: AbortSignal.timeout(90_000) });
    return Reflect.get(target, key);
  } });
  const results = [];
  for (const gate of GATES) {
    try { results.push(await gate(bounded)); }
    catch (error) { results.push({ name: gate.name, ok: false, detail: String(error) }); }
    log(label, results.at(-1));
  }
  return results;
}
const goEnv = { PATH: sdkPath + "/bin:" + basePath, GOROOT: sdkPath, GOTOOLCHAIN: "local", CGO_ENABLED: "0",
  GOPROXY: "off", GOSUMDB: "off", GOENV: "off", GOMAXPROCS: "2", GOCACHE: "/home/agent/go-cache/build",
  GOMODCACHE: "/home/agent/go-cache/mod", GOPATH: "/home/agent/go-cache/path" };
async function agentChecks(vm, label) {
  const before = deniedDuringGo;
  pureGo = true;
  try {
    await execute(vm, label + "-go-env", "id; test \"$(id -u)\" = 1000; go version; go env -json GOROOT GOCACHE GOMODCACHE GOPATH GOTOOLCHAIN CGO_ENABLED GOOS GOARCH GOVERSION GOPROXY", { agent: true, env: goEnv });
    await execute(vm, label + "-compile-test", "mkdir -p \"$GOCACHE\" \"$GOMODCACHE\" \"$GOPATH\"; cd /work/work; go build -p 2 -o app .; ./app; go test -p 2 -count=1 -v ./...; test -s report.json; printf workspace-write > write-probe; cat /run/corb/gate.json", { agent: true, env: goEnv });
    const readonly = await execute(vm, label + "-sdk-readonly", "printf bad >> /opt/corb/go/VERSION", { agent: true, env: goEnv, required: false });
    assert(!readonly.ok, "agent changed SDK bytes");
    await execute(vm, label + "-seven-removals", "for name in npm npx su sudo doas apk apk.static; do if command -v \"$name\"; then exit 1; fi; done; echo ALL_SEVEN_ABSENT", { agent: true, env: goEnv });
    const manifest = await execute(vm, label + "-sdk-files", "cd /opt/corb; find go -type f -exec sha256sum '{}' ';' | LC_ALL=C sort -k2", { output: false });
    assert(sha(manifest.stdout) === prepared.filesSha256, "composed SDK tree differs from official payload");
    assert(deniedDuringGo === before, "pure Go commands attempted outbound HTTP");
  } finally { pureGo = false; }
  const report = JSON.parse(fs.readFileSync(path.join(runtime, "workspace-" + label.split("-")[0], "report.json"), "utf8"));
  assert(report[0].name === "alpha" && report[0].total === 10 && report[1].total === 21, "workspace program result mismatch");
  return { pureGoHttpRequests: deniedDuringGo - before, sdkFilesSha256: prepared.filesSha256, report };
}

const overall = setTimeout(async () => {
  console.error("DAR-16 experiment exceeded 45 minutes");
  await liveVm?.close();
  process.exit(1);
}, 45 * 60_000);
for (const signal of ["SIGINT", "SIGTERM"]) process.once(signal, async () => { await liveVm?.close(); process.exit(1); });
if (!auditOnly) fs.writeFileSync(path.join(evidence, "events.jsonl"), "");
try {
  assert(process.platform === "linux" && process.arch === "x64", "only native Linux/x86_64 is tested");
  assert(await fileSha(path.join(runtime, "go1.27.3.linux-amd64.tar.gz")) === prepared.actualArchiveSha256, "archive changed after preparation");
  const treeBefore = sha(treeManifest());
  assert(treeBefore === prepared.treeSha256, "payload changed after archive verification");
  save("preparation", prepared);
  let rejected = false;
  try { destination("/usr/local/bin/dropcap"); } catch (error) { rejected = true; log("negative-destination", { error: String(error), vmStarted: false }); }
  assert(rejected, "protected destination was accepted");
  const refsBefore = auditOnly ? JSON.parse(fs.readFileSync(path.join(evidence, "baseline.json"), "utf8")).refs : listImageRefs();
  assert(JSON.stringify(listImageRefs()) === JSON.stringify(refsBefore), "image refs changed since the experiment baseline");
  for (const base of definitions) {
    base.assetDir = path.join("/home/dario/.cache/gondolin/images/objects", base.buildId);
    base.manifest = JSON.parse(fs.readFileSync(path.join(base.assetDir, "manifest.json"), "utf8"));
    assert(base.manifest.buildId === base.buildId && base.manifest.checksums.rootfs === base.rootfsSha256, "unexpected base identity");
    assert(verifyAssets(base.assetDir), "base asset checksum failure");
    base.manifestSha256 = await fileSha(path.join(base.assetDir, "manifest.json"));
  }
  if (!auditOnly) save("baseline", { refs: refsBefore, bases: definitions, gateSourceSha256: sha(source), adapterSha256: sha(adapter),
    harnessSha256: await fileSha(import.meta.filename), treeBefore });
  for (const base of definitions) {
    const checkpoint = path.join(runtime, base.name + "-composed.qcow2");
    if (auditOnly) {
      const result = JSON.parse(fs.readFileSync(path.join(evidence, base.name + ".json"), "utf8"));
      assert(result.identity.baseBuildId === base.buildId && result.identity.goArchiveSha256 === prepared.actualArchiveSha256,
        "saved trial identity does not match prepared inputs");
      assert(result.resume?.protectedUnchanged && result.resume?.packageDatabaseUnchanged, "saved resume trial is incomplete");
      assert(await fileSha(checkpoint) === result.checkpointSha256, "saved trial checkpoint changed");
      outcomes.push(result);
      continue;
    }
    assert(!fs.existsSync(checkpoint), "use a fresh runtime or remove only this task's old checkpoint before rerun");
    const result = await usingVm(base, base.name + "-compose", true, undefined, async vm => {
      const protectedBefore = await protectedSet(vm, base.name + "-protected-before");
      const dbBefore = await database(vm, base.name + "-db-before");
      const identity = await execute(vm, base.name + "-identity", "cat /etc/alpine-release; uname -a; /usr/local/libexec/real-git --version; cat /etc/corb/image.json");
      const baselineGates = await gates(vm, base.name + "-baseline-gate");
      assertGateReports(baselineGates);
      await execute(vm, base.name + "-input-readonly", "if printf bad >> /mnt/corb-sdk-input/go/VERSION; then exit 1; else echo INPUT_READONLY; fi");
      destination(sdkPath);
      await execute(vm, base.name + "-compose", "test ! -e /opt/corb/go; mkdir -p /opt/corb; cp -R /mnt/corb-sdk-input/go /opt/corb/go; chown -R 0:0 /opt/corb/go; chmod -R a-w /opt/corb/go");
      const agent = await agentChecks(vm, base.name + "-composed");
      const protectedAfter = await protectedSet(vm, base.name + "-protected-composed");
      const dbAfter = await database(vm, base.name + "-db-composed");
      assert(protectedBefore === protectedAfter && dbBefore.sha256 === dbAfter.sha256, "composition changed protected files or APK records");
      const candidateGates = await gates(vm, base.name + "-composed-gate");
      assertGateReports(baselineGates, candidateGates);
      const identityData = { version: 1, policy: "portable-go-copy-v1", baseBuildId: base.buildId,
        baseManifestSha256: base.manifestSha256, baseAssetChecksums: base.manifest.checksums,
        goArchiveSha256: prepared.actualArchiveSha256, goTreeSha256: prepared.treeSha256 };
      const snapshot = await vm.checkpoint(checkpoint);
      return { base: base.name, identity: identityData, compositionSha256: sha(JSON.stringify(identityData)),
        checkpoint: snapshot.toJSON(), checkpointSha256: await fileSha(checkpoint), baselineGates, candidateGates,
        protectedUnchanged: true, packageDatabaseUnchanged: true, database: dbBefore, agent, guestIdentity: identity.stdout };
    });
    const resumed = await usingVm(base, base.name + "-resume", false, checkpoint, async vm => {
      await execute(vm, base.name + "-no-input-mount", "test -z \"$(ls -A /mnt/corb-sdk-input)\"; echo SDK_INPUT_NOT_MOUNTED");
      const agent = await agentChecks(vm, base.name + "-resumed");
      const hashes = await protectedSet(vm, base.name + "-protected-resumed");
      assert(hashes === fs.readFileSync(path.join(evidence, base.name + "-protected-before.sha256"), "utf8"), "resumed protected hashes changed");
      const db = await database(vm, base.name + "-db-resumed");
      assert(db.sha256 === result.database.sha256, "resumed package database changed");
      return { agent, protectedUnchanged: true, packageDatabaseUnchanged: true, gates: await gates(vm, base.name + "-resumed-gate") };
    });
    assert(await fileSha(checkpoint) === result.checkpointSha256, "canonical checkpoint mutated during own-base resume");
    result.resume = resumed;
    assertGateReports(result.baselineGates, result.candidateGates, resumed.gates);
    save(base.name, result);
    outcomes.push(result);
  }
  let wrongBaseRejected = false;
  try {
    const unexpected = await VmCheckpoint.load(path.join(runtime, "stock-composed.qcow2")).resume(options(definitions[1], "wrong-base", false));
    await unexpected.close();
  } catch (error) {
    wrongBaseRejected = /do not match checkpoint buildId/.test(String(error));
    log("wrong-base-negative", { rejected: wrongBaseRejected, error: String(error) });
  }
  assert(wrongBaseRejected, "wrong-base checkpoint was not rejected");
  for (const result of outcomes) {
    assertGateReports(result.baselineGates, result.candidateGates, result.resume.gates);
    assert(await fileSha(path.join(runtime, result.base + "-composed.qcow2")) === result.checkpointSha256,
      "wrong-base rejection mutated a canonical checkpoint");
  }
  assert(sha(treeManifest()) === treeBefore, "shared host SDK payload changed");
  assert(JSON.stringify(listImageRefs()) === JSON.stringify(refsBefore), "image refs changed");
  for (const base of definitions) {
    assert(await fileSha(path.join(base.assetDir, "manifest.json")) === base.manifestSha256,
      "base manifest changed during experiment");
    assert(verifyAssets(base.assetDir), "base assets changed during experiment");
  }
  assert((await listSessions()).length === 0, "task VM registry still has sessions");
  save("result", { portability: "go-with-limits", payloadSha256: prepared.actualArchiveSha256, treeSha256: treeBefore,
    summaryAudit: { reusedCompletedTrials: auditOnly, newVmBoots: auditOnly ? 0 : outcomes.length * 2,
      harnessSha256: await fileSha(import.meta.filename), gateSourceSha256: sha(source), adapterSha256: sha(adapter) },
    bases: outcomes.map(item => ({ name: item.base, buildId: item.identity.baseBuildId, rootfsSha256: item.identity.baseAssetChecksums.rootfs,
      compositionSha256: item.compositionSha256, checkpointSha256: item.checkpointSha256,
      baselineGatePasses: item.baselineGates.filter(gate => gate.ok).length,
      composedGatePasses: item.candidateGates.filter(gate => gate.ok).length,
      resumedGatePasses: item.resume.gates.filter(gate => gate.ok).length })),
    treeUnchanged: true, refsUnchanged: true, baseAssetsUnchanged: true, wrongBaseRejected,
    pureGoHttpRequests: deniedDuringGo, directSdkMountTested: false, copyingTested: true, checkpointCacheTested: true,
    imageGatesAllPassed: outcomes.every(item => [...item.baselineGates, ...item.candidateGates, ...item.resume.gates].every(gate => gate.ok)),
    ownedPids, vmRegistryEmpty: true, cgoTested: false, registryTransportTested: false });
} finally {
  clearTimeout(overall);
  await liveVm?.close();
  const surviving = ownedPids.filter(pid => { try { process.kill(pid, 0); return true; } catch { return false; } });
  save("cleanup", { auditOnly, ownedPids, surviving, sessions: await listSessions() });
  assert(surviving.length === 0, "owned VM process still exists");
}
