import fs from "node:fs";
import path from "node:path";
import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { pathToFileURL } from "node:url";
import { assertGateReports } from "../dar-16-portable-go/gate-report.mjs";

export const root = import.meta.dirname;
export const repo = path.resolve(root, "../..");
export const runtime = path.resolve(process.argv[2] ?? "");
if (!process.argv[2] || runtime === "/") throw new Error("Pass the separate APK task runtime");
export const evidence = path.resolve(process.env.DAR16_APK_EVIDENCE_DIR ?? path.join(root, "evidence"));
for (const directory of [runtime, evidence, path.join(runtime, "tmp"), path.join(runtime, "output")]) fs.mkdirSync(directory, { recursive: true });
process.env.TMPDIR = path.join(runtime, "tmp");
process.env.GONDOLIN_SESSIONS_DIR = path.join(runtime, "sessions");
export const sdk = await import("@earendil-works/gondolin");
const { buildGateConfigMount, GATE_CONFIG_RAW_ROOT } = await import("../../src/vm/session.ts");
export const basePath = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";
export const installer = "/opt/corb-apk-input/bin/apk.static";
export const fixedId = "e8292a0a-0a1a-52d5-959b-9ed372068d54";
export const fixed = { name: "fixed", buildId: fixedId, assetDir: path.join("/home/dario/.cache/gondolin/images/objects", fixedId) };
export const ownedPids = [];
export let liveVm;
export let requests = [];

export function sha(value) { return createHash("sha256").update(value).digest("hex"); }
export async function fileSha(filename) {
  const hash = createHash("sha256");
  for await (const chunk of fs.createReadStream(filename)) hash.update(chunk);
  return hash.digest("hex");
}
const baselineFile = path.join(runtime, "global-baseline.json");
export const globalBaseline = fs.existsSync(baselineFile) ? JSON.parse(fs.readFileSync(baselineFile, "utf8")) : {
  capturedAt: new Date().toISOString(), refs: sdk.listImageRefs(), objects: [],
};
if (!fs.existsSync(baselineFile)) {
  for (const buildId of new Set(globalBaseline.refs.flatMap(row => Object.values(row.targets)))) {
    const assetDir = path.join("/home/dario/.cache/gondolin/images/objects", buildId);
    if (!sdk.verifyAssets(assetDir)) throw new Error("existing canonical asset verification failed");
    const manifest = JSON.parse(fs.readFileSync(path.join(assetDir, "manifest.json"), "utf8"));
    globalBaseline.objects.push({ buildId, assetDir, manifestSha256: await fileSha(path.join(assetDir, "manifest.json")), checksums: manifest.checksums });
  }
  fs.writeFileSync(baselineFile, JSON.stringify(globalBaseline, null, 2) + "\n");
}
export function assert(condition, reason) { if (!condition) throw new Error(reason); }
export function save(name, value) { fs.writeFileSync(path.join(evidence, name + ".json"), JSON.stringify(value, null, 2) + "\n"); }
export function read(name) { return JSON.parse(fs.readFileSync(path.join(runtime, name + ".json"), "utf8")); }
export function state(name, value) { fs.writeFileSync(path.join(runtime, name + ".json"), JSON.stringify(value, null, 2) + "\n"); }
export function log(label, value) {
  const item = { label, ...value };
  console.log(JSON.stringify(item));
  fs.appendFileSync(path.join(evidence, "events.jsonl"), JSON.stringify(item) + "\n");
}
export function prepare(action, extra) {
  const output = execFileSync("python3", [path.join(root, "prepare.py"), action, runtime, ...(extra ? [extra] : [])],
    { encoding: "utf8", timeout: 300_000, maxBuffer: 4 * 1024 * 1024 });
  log("host-" + action, { output });
}
export async function execute(vm, label, script, { agent = false, output = true, required = true, timeout = 300_000 } = {}) {
  const started = performance.now();
  const result = await vm.exec(agent ? ["/usr/local/bin/dropcap", "1000", "1000", "/bin/sh", "-ec", script] : ["/bin/sh", "-ec", script], {
    env: { PATH: basePath, HOME: agent ? "/home/agent" : "/root", CORB_GATE_CONFIG: "/run/corb/gate.json" },
    stdout: "buffer", stderr: "buffer", signal: AbortSignal.timeout(timeout),
  });
  const pid = vm.getHostPid();
  if (pid && !ownedPids.includes(pid)) { ownedPids.push(pid); log("owned-vm", { pid }); }
  log(label, { exitCode: result.exitCode, ms: Math.round(performance.now() - started),
    ...(output ? { stdout: result.stdout, stderr: result.stderr } : { stdoutSha256: sha(result.stdout), stdoutBytes: Buffer.byteLength(result.stdout), stderr: result.stderr }) });
  if (required) assert(result.ok, label + " failed: " + result.stderr);
  return result;
}
function options(base, label, { install = false, verify = false, output = false } = {}) {
  const prepared = read("prepared");
  const allowedHosts = verify ? ["api.anthropic.com", "github.com"] : ["dl-cdn.alpinelinux.org"];
  const hooks = sdk.createHttpHooks({ allowedHosts, allowedInternalHosts: [] });
  if (install) {
    const files = new Map(prepared.indexes.map(row => [new URL(row.url).pathname, { filename: path.join(runtime, "input/indexes", row.repository + ".tar.gz"), sha256: row.sha256 }]));
    for (const row of [...prepared.packages, prepared.installer]) files.set("/alpine/v3.23/" + row.repository + "/x86_64/" + row.filename,
      { filename: path.join(runtime, "input/packages", row.filename), sha256: row.archiveSha256 });
    hooks.httpHooks.onRequest = request => {
      const url = new URL(request.url);
      assert(url.protocol === "https:" && url.hostname === "dl-cdn.alpinelinux.org" && request.method === "GET", "unexpected installer request");
      const found = files.get(url.pathname);
      assert(found, "installer requested an unprepared package or index: " + url.pathname);
      const bytes = fs.readFileSync(found.filename);
      assert(sha(bytes) === found.sha256, "cached input changed before consumption");
      requests.push(url.pathname);
      return new Response(bytes, { headers: { "content-type": "application/octet-stream", "content-length": String(bytes.length) } });
    };
  }
  const workspace = path.join(runtime, "workspace-" + base.name);
  fs.mkdirSync(workspace, { recursive: true });
  const fixture = path.join(root, "fixture");
  if (fs.existsSync(fixture)) for (const name of fs.readdirSync(fixture)) fs.copyFileSync(path.join(fixture, name), path.join(workspace, name));
  const mounts = { [GATE_CONFIG_RAW_ROOT]: buildGateConfigMount(), "/mnt/corb-raw/work": new sdk.RealFSProvider(workspace) };
  if (install) mounts["/opt/corb-apk-input"] = new sdk.ReadonlyProvider(new sdk.RealFSProvider(path.join(runtime, "input")));
  if (output) mounts["/opt/corb-apk-output"] = new sdk.RealFSProvider(path.join(runtime, "output"));
  return { sandbox: { imagePath: base.assetDir, vmm: "qemu" }, memory: "1G", cpus: 2, startTimeoutMs: 90_000,
    dns: { mode: "synthetic", syntheticHostMapping: "per-host" }, httpHooks: hooks.httpHooks, env: hooks.env,
    allowWebSockets: false, ssh: { allowedHosts: [] }, vfs: { mounts }, sessionLabel: "dar16-apk-" + label };
}
export async function usingVm(base, label, settings, checkpoint, callback) {
  assert(!liveVm, "a previous VM is still active");
  liveVm = checkpoint ? await sdk.VmCheckpoint.load(checkpoint).resume(options(base, label, settings)) : await sdk.VM.create(options(base, label, settings));
  const vm = liveVm;
  log("vm-start", { base: base.name, phase: label, resumed: Boolean(checkpoint) });
  try { return await callback(vm); }
  finally { await vm.close(); liveVm = undefined; log("vm-closed", { base: base.name, phase: label }); }
}
export async function protectedSet(vm, name) {
  const result = await execute(vm, name, "find /init /usr/local/bin/dropcap /usr/local/libexec /etc/corb /usr/bin/bindfs /etc/apk/keys -type f -exec sha256sum '{}' ';' | sort", { output: false });
  fs.writeFileSync(path.join(evidence, name + ".sha256"), result.stdout);
  return result.stdout;
}
export async function database(vm, label) {
  const result = await execute(vm, label, "cat /lib/apk/db/installed", { output: false });
  const records = result.stdout.split("\n\n").filter(Boolean).map(block => Object.fromEntries(block.split("\n").filter(line => /^[PCVADp]:/.test(line)).map(line => [line[0], line.slice(2)])));
  return { sha256: sha(result.stdout), records };
}
const gateSource = fs.readFileSync(path.join(repo, "image/verify.ts"), "utf8");
const adapter = gateSource.replace('"../src/vm/session.ts"', JSON.stringify(pathToFileURL(path.join(repo, "src/vm/session.ts")).href)).replace("const GATES:", "export const GATES:");
assert(adapter !== gateSource && adapter.includes("export const GATES:"), "gate source adapter mismatch");
const adapterPath = path.join(runtime, "verify-adapter.ts");
fs.writeFileSync(adapterPath, adapter);
export const sourceIdentity = { gateSourceSha256: sha(gateSource), gateAdapterSha256: sha(adapter) };
export const { GATES } = await import(pathToFileURL(adapterPath).href);
export async function gates(vm, label) {
  const bounded = new Proxy(vm, { get(target, key) {
    if (key === "exec") return (argv, opts) => target.exec(argv, { ...opts, signal: AbortSignal.timeout(90_000) });
    return Reflect.get(target, key);
  } });
  const result = [];
  for (const gate of GATES) {
    try { result.push(await gate(bounded)); }
    catch (error) { result.push({ name: gate.name, ok: false, detail: String(error) }); }
    log(label, result.at(-1));
  }
  return result;
}
export { assertGateReports };
export async function closeAndCheck() {
  await liveVm?.close();
  const surviving = ownedPids.filter(pid => { try { process.kill(pid, 0); return true; } catch { return false; } });
  const sessions = await sdk.listSessions();
  save("cleanup", { ownedPids, surviving, sessions });
  assert(!surviving.length && !sessions.length, "owned VM cleanup failed");
}
for (const signal of ["SIGINT", "SIGTERM"]) process.once(signal, async () => { await liveVm?.close(); process.exit(1); });
