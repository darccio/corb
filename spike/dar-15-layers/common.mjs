import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { VM, VmCheckpoint, RealFSProvider, ReadonlyProvider, createHttpHooks } from "@earendil-works/gondolin";
import { resolveRuntimeImage } from "../../src/vm/image.ts";
import { buildEgressConfig, forceIdentityAcceptEncoding } from "../../src/vm/egress.ts";
import { buildGateConfigMount, GATE_CONFIG_RAW_ROOT } from "../../src/vm/session.ts";

export const root = import.meta.dirname;
export const runtime = path.join(root, "runtime");
export const base = resolveRuntimeImage();
export const basePath = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";
export const cache = path.join(process.env.CORB_CACHE_DIR ?? path.join(os.homedir(), ".cache/corb"), "dar-15-layers");
export const bootstrap = JSON.parse(fs.readFileSync(path.join(cache, "bootstrap.json"), "utf8"));
fs.mkdirSync(runtime, { recursive: true });

export function log(label, value) {
  console.log(JSON.stringify({ label, ...value }));
}

export function sha256(file) {
  return createHash("sha256").update(fs.readFileSync(file)).digest("hex");
}

export function save(name, value) {
  fs.writeFileSync(path.join(runtime, name + ".json"), JSON.stringify(value, null, 2) + "\n");
}

export function read(name) {
  return JSON.parse(fs.readFileSync(path.join(runtime, name + ".json"), "utf8"));
}

export async function run(vm, label, script, { agent = false, required = true, env = {} } = {}) {
  const start = performance.now();
  const argv = agent
    ? ["/usr/local/bin/dropcap", "1000", "1000", "/bin/sh", "-c", script]
    : ["/bin/sh", "-c", script];
  const result = await vm.exec(argv, {
    env: {
      PATH: basePath,
      HOME: agent ? "/home/agent" : "/root",
      NODE_EXTRA_CA_CERTS: "/run/gondolin/ca-certificates.crt",
      SSL_CERT_FILE: "/run/gondolin/ca-certificates.crt",
      CORB_GATE_CONFIG: "/run/corb/gate.json",
      ...env,
    },
    stdout: "buffer",
    stderr: "buffer",
    signal: AbortSignal.timeout(300_000),
  });
  log(label, { exitCode: result.exitCode, ms: performance.now() - start, stdout: result.stdout, stderr: result.stderr });
  if (required && !result.ok) throw new Error(label + " failed with " + result.exitCode);
  return result;
}

export function options(label, { image = base.assetDir, build = false, workspace = false, verify = false } = {}) {
  const hosts = ["dl-cdn.alpinelinux.org"];
  if (verify) hosts.push("api.anthropic.com", "github.com");
  const audit = {
    record(event) { if (event.channel === "http") log("http", event); },
    addRedactedSecrets() {},
    flush() {},
  };
  const egress = build
    ? createHttpHooks({
      allowedHosts: ["dl-cdn.alpinelinux.org"],
      allowedInternalHosts: [],
      onRequest: request => forceIdentityAcceptEncoding(request),
      onResponse: (response, request) => {
        log("http", { host: new URL(request.url).hostname, status: response.status });
      },
    })
    : buildEgressConfig({ allow: hosts, "block-internal-ranges": true, websockets: false }, undefined, {}, audit, label);
  const mounts = { [GATE_CONFIG_RAW_ROOT]: buildGateConfigMount() };
  if (build) mounts["/opt/corb-build"] = new ReadonlyProvider(new RealFSProvider(bootstrap.binaryDir));
  if (workspace) {
    const dir = path.join(runtime, "workspace");
    fs.mkdirSync(dir, { recursive: true });
    mounts["/mnt/corb-raw/work"] = new RealFSProvider(dir);
    mounts[GATE_CONFIG_RAW_ROOT] = buildGateConfigMount();
  }
  return {
    sandbox: { imagePath: image, vmm: "qemu" },
    dns: { mode: "synthetic", syntheticHostMapping: "per-host" },
    httpHooks: egress.httpHooks,
    env: egress.env,
    vfs: { mounts },
    ssh: { allowedHosts: [] },
    sessionLabel: "dar-15-" + label,
  };
}

export async function boot(label, opts, checkpoint) {
  const start = performance.now();
  const vm = checkpoint ? await VmCheckpoint.load(checkpoint).resume(opts) : await VM.create(opts);
  try {
    await run(vm, label + "-first-exec", "cat /etc/corb/image.json");
    log(label + "-boot", { ms: performance.now() - start, tmpdir: os.tmpdir(), tmpFsType: fs.statfsSync(os.tmpdir()).type });
    return vm;
  } catch (err) {
    await vm.close();
    throw err;
  }
}

export async function protectedHashes(vm, label) {
  const result = await run(vm, label, "find /init /usr/local/bin/dropcap /usr/local/libexec /etc/corb /usr/bin/bindfs /etc/apk/keys -type f -exec sha256sum '{}' ';' | sort");
  return result.stdout;
}

export async function checkpoint(vm, name, image = base) {
  const filename = path.join(runtime, "layers", "dar-15", name + ".qcow2");
  const start = performance.now();
  const value = await vm.checkpoint(filename);
  const result = { path: filename, ms: performance.now() - start, bytes: fs.statSync(filename).size, sha256: sha256(filename), checkpoint: value.toJSON(), base: image };
  save(name, result);
  log(name + "-checkpoint", result);
  return result;
}

export function diskInfo(filename) {
  return JSON.parse(execFileSync("qemu-img", ["info", "--output=json", filename], { encoding: "utf8" }));
}
