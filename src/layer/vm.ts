import { verifyVm, withImageVm } from "../image/verify.ts";
import { VM, VmCheckpoint, createHttpHooks, type VMOptions } from "@earendil-works/gondolin";
import { configureTrustedTls } from "../vm/tls.ts";
import { buildGateConfigMount, GATE_CONFIG_RAW_ROOT } from "../vm/session.ts";
import { requireLayerExecution, type LayerBase } from "./local-base.ts";
import { fail } from "./validate.ts";
import type { ApkKeys } from "./apk.ts";
import type { InstalledIdentity } from "./plan.ts";

export const BASE_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";
export const VERIFIER_HOSTS = ["api.anthropic.com", "github.com"];

export interface Verification { ok: boolean; gates: Array<{ name: string; ok: boolean; detail: string }> }
export interface BaseSnapshot {
  os: string; arch: string; alpineVersion: string; world: string; database: string; packages: InstalledIdentity[]; keys: ApkKeys;
  accounts: { users: Array<{ name: string; id: number; gid: number; home: string; shell: string }>; groups: Array<{ name: string; id: number }> };
  protected: Array<Record<string, unknown>>; native: Array<Record<string, unknown>>;
}
export { guestLayerSource, layerGuest } from "./guest.ts";
import { layerGuest } from "./guest.ts";
export async function layerExec(vm: VM, argv: string[], timeout = 120_000) {
  const result = await vm.exec(argv, { env: { PATH: BASE_PATH }, cwd: "/", stdout: "buffer", stderr: "buffer", signal: AbortSignal.timeout(timeout) });
  if (Buffer.byteLength(result.stdout) + Buffer.byteLength(result.stderr) > 8 * 1024 ** 2) fail("guest command diagnostics exceed 8 MiB");
  return result;
}
export async function verifyProductionVm(vm: VM): Promise<Verification> {
  const result = await verifyVm(vm);
  const required = ["user", "privilege-drop", "suid", "removals", "ca-trust", "git-gh-shimmed", "pi"];
  for (const gate of result.gates) process.stderr.write(`corb image: [${gate.ok ? "PASS" : "FAIL"}] ${gate.name}: ${gate.detail}\n`);
  if (!result.ok || result.gates.length !== 7 || required.some((name) => result.gates.filter((gate) => gate.name === name && gate.ok).length !== 1)) fail("production image verification requires all seven gates");
  return result;
}
export async function withLayerVm<T>(base: LayerBase, label: string, hosts: string[], callback: (vm: VM) => Promise<T>, options: { mounts?: NonNullable<VMOptions["vfs"]>["mounts"]; checkpoint?: VmCheckpoint; verifier?: boolean } = {}): Promise<T> {
  requireLayerExecution(base);
  const { httpHooks, env } = createHttpHooks({ allowedHosts: hosts, allowedInternalHosts: [] });
  const vmOptions: VMOptions = {
    sandbox: { imagePath: base.directory, vmm: "qemu" }, memory: "1G", cpus: 2, startTimeoutMs: 45_000,
    dns: { mode: "synthetic", syntheticHostMapping: "per-host" }, httpHooks, env,
    ssh: { allowedHosts: [] }, allowWebSockets: false,
    vfs: { mounts: { ...(options.verifier ? { [GATE_CONFIG_RAW_ROOT]: buildGateConfigMount() } : {}), ...options.mounts } }, sessionLabel: label,
  };
  let vm: VM | undefined;
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    vm = options.checkpoint === undefined ? await VM.create(vmOptions) : await options.checkpoint.resume<VM>(vmOptions);
    configureTrustedTls(vm);
    const active = vm;
    const timeout = new Promise<never>((_resolve, reject) => { timer = setTimeout(() => { void active.close(); reject(new Error("layer VM exceeded 15 minute overall limit")); }, 15 * 60_000); });
    const result = await Promise.race([callback(vm), timeout]);
    return result;
  } finally {
    if (timer !== undefined) clearTimeout(timer);
    if (vm !== undefined) {
      const pid = vm.getHostPid();
      process.stderr.write(`corb image: closing ${label}${pid === undefined || pid === null ? "" : ` (host PID ${pid})`}\n`);
      await vm.close();
    }
  }
}
export async function verifyLayerBase(base: LayerBase): Promise<{ baseline: BaseSnapshot; verification: Verification }> {
  return withLayerVm(base, "corb-layer-base-verifier", VERIFIER_HOSTS, async (vm) => {
    const coherent = await layerExec(vm, ["/usr/bin/node", "/usr/local/libexec/corb-package-coherence.mjs", "--validate-report"]);
    if (!coherent.ok) fail(`base package coherence failed: ${(coherent.stderr || coherent.stdout).slice(-8000)}`);
    const baseline = await layerGuest<BaseSnapshot>(vm, "snapshot");
    if (baseline.os !== "linux" || baseline.arch !== base.manifest.config.arch || `v${baseline.alpineVersion.split(".").slice(0, 2).join(".")}` !== base.branch) fail("base guest OS, architecture or Alpine branch differs from its manifest");
    const verification = await verifyProductionVm(vm);
    return { baseline, verification };
  }, { verifier: true });
}

/** Base distribution uses the SDK's normal native image behavior. Layer execution has its own narrower backend check. */
export async function verifyLocalBase(base: LayerBase): Promise<Verification> {
  return withImageVm(base.directory, { sessionLabel: "corb-base-verify" }, async (vm) => {
    const marker = await layerGuest<BaseSnapshot>(vm, "snapshot");
    if (marker.os !== "linux" || marker.arch !== base.manifest.config.arch || `v${marker.alpineVersion.split(".").slice(0, 2).join(".")}` !== base.branch) fail("base guest OS, architecture or Alpine branch differs from its manifest");
    if (marker.packages.length === 0) fail("base has no coherent package identities");
    const coherent = await layerExec(vm, ["/usr/bin/node", "/usr/local/libexec/corb-package-coherence.mjs", "--validate-report"]);
    if (!coherent.ok) fail(`base package coherence failed: ${(coherent.stderr || coherent.stdout).slice(-8000)}`);
    return verifyProductionVm(vm);
  });
}
