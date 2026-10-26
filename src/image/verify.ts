import { withBoundedVm } from "../vm/bounded.ts";
// Run the seven production gates before Corb publishes an image or a composition.
// The compiled CLI and source checkout use this same implementation.
// image/verify.ts keeps the historical source checkout import path.

import { configureTrustedTls } from "../vm/tls.ts";
import { createHttpHooks, VM } from "@earendil-works/gondolin";
import { buildGateConfigMount, GATE_CONFIG_GUEST_PATH, GATE_CONFIG_RAW_ROOT } from "../vm/session.ts";

export interface GateResult {
  name: string;
  ok: boolean;
  detail: string;
}

export interface VerifyReport {
  ok: boolean;
  gates: GateResult[];
}

export interface VerifyImageOptions {
  /**
   * Hosts the throwaway verification VM's egress is allowed to reach.
   * Needed for the "ca-trust" gate, which must complete a real TLS
   * handshake from inside the guest. Defaults cover exactly the hosts the
   * gates below actually use.
   */
  allowedHosts?: string[];
  sessionLabel?: string;
}

const DEFAULT_ALLOWED_HOSTS = ["api.anthropic.com", "github.com"];

// Supply the base PATH explicitly for every gate command.
const BASE_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";

function pass(name: string, detail: string): GateResult {
  return { name, ok: true, detail };
}

function fail(name: string, detail: string): GateResult {
  return { name, ok: false, detail };
}

async function run(vm: VM, argv: string[], env: Record<string, string> = {}) {
  return vm.exec(argv, {
    env: { PATH: BASE_PATH, ...env },
    stdout: "buffer",
    stderr: "buffer",
    signal: AbortSignal.timeout(30_000),
  });
}

function firstMatch(text: string, re: RegExp): string | undefined {
  return re.exec(text)?.[1];
}

// --- Gates ------------------------------------------------------------

async function gateUser(vm: VM): Promise<GateResult> {
  const name = "user";
  const idResult = await run(vm, ["/usr/bin/id", "-u", "agent"]);
  const uid = idResult.stdout.trim();
  if (!idResult.ok || uid !== "1000") {
    return fail(name, `'id -u agent' printed '${uid}' (exit ${idResult.exitCode}), expected '1000'`);
  }

  // `-n` on BusyBox ls prints numeric uid/gid instead of resolved names,
  // which is more portable across images than a GNU-`stat`-format string.
  const ownerResult = await run(vm, ["/bin/sh", "-lc", "ls -ldn /home/agent | awk '{print $3, $4}'"]);
  const [ownerUid, ownerGid] = ownerResult.stdout.trim().split(/\s+/);
  if (!ownerResult.ok || ownerUid !== "1000" || ownerGid !== "1000") {
    return fail(
      name,
      `/home/agent is owned by uid:gid '${ownerUid ?? "?"}:${ownerGid ?? "?"}' (exit ${ownerResult.exitCode}), expected '1000:1000'`,
    );
  }

  return pass(name, "id -u agent = 1000; /home/agent owned by 1000:1000");
}

async function gatePrivilegeDrop(vm: VM): Promise<GateResult> {
  const name = "privilege-drop";
  const result = await run(vm, ["/usr/local/bin/dropcap", "1000", "1000", "/bin/sh", "-c", "cat /proc/self/status"]);
  if (!result.ok) {
    return fail(name, `dropcap exited ${result.exitCode}: ${result.stderr.trim() || result.stdout.trim()}`);
  }

  const status = result.stdout;
  // Match spaces and tabs without consuming the next status line.
  // An empty Groups field must stay empty.
  const noNewPrivs = firstMatch(status, /^NoNewPrivs:[ \t]*(\d+)/m);
  const capEff = firstMatch(status, /^CapEff:[ \t]*([0-9a-fA-F]+)/m);
  const groups = firstMatch(status, /^Groups:[ \t]*(.*)$/m)?.trim();
  const uidLine = firstMatch(status, /^Uid:[ \t]*(.*)$/m)?.trim();

  const problems: string[] = [];
  if (noNewPrivs !== "1") {
    problems.push(`NoNewPrivs='${noNewPrivs ?? "(missing)"}' (expected '1')`);
  }
  if (capEff === undefined || !/^0+$/.test(capEff)) {
    problems.push(`CapEff='${capEff ?? "(missing)"}' (expected all zeros)`);
  }
  if (groups !== "") {
    problems.push(`Groups='${groups ?? "(missing)"}' (expected empty)`);
  }
  const uidFields = uidLine?.split(/\s+/) ?? [];
  if (uidFields[0] !== "1000" || uidFields[1] !== "1000" || uidFields[2] !== "1000") {
    problems.push(`Uid='${uidLine ?? "(missing)"}' (expected '1000 1000 1000 ...')`);
  }

  if (problems.length > 0) {
    return fail(name, `dropcap did not fully drop privilege: ${problems.join("; ")}`);
  }
  return pass(name, "dropcap 1000 1000 -> NoNewPrivs=1, CapEff=0, Groups empty, Uid=1000/1000/1000");
}

async function gateSuid(vm: VM): Promise<GateResult> {
  const name = "suid";
  const allowlistResult = await run(vm, ["/bin/cat", "/etc/corb/suid-allowlist.txt"]);
  if (!allowlistResult.ok) {
    return fail(name, `could not read /etc/corb/suid-allowlist.txt: exit ${allowlistResult.exitCode}`);
  }
  const allowlist = new Set(
    allowlistResult.stdout
      .split("\n")
      .map((line) => line.trim())
      .filter((line) => line.length > 0 && !line.startsWith("#")),
  );

  const sweepResult = await run(vm, [
    "/bin/sh",
    "-lc",
    "find / -xdev \\( -perm -4000 -o -perm -2000 \\) -type f 2>/dev/null | sort",
  ]);
  if (!sweepResult.ok) {
    return fail(name, `SUID/SGID sweep failed: exit ${sweepResult.exitCode}: ${sweepResult.stderr.trim()}`);
  }
  const live = new Set(
    sweepResult.stdout
      .split("\n")
      .map((line) => line.trim())
      .filter((line) => line.length > 0),
  );

  const unexpected = [...live].filter((p) => !allowlist.has(p));
  const missingExpected = [...allowlist].filter((p) => !live.has(p));
  if (unexpected.length > 0 || missingExpected.length > 0) {
    const parts: string[] = [];
    if (unexpected.length > 0) parts.push(`unexpected=[${unexpected.join(", ")}]`);
    if (missingExpected.length > 0) parts.push(`missing=[${missingExpected.join(", ")}]`);
    return fail(name, `live SUID/SGID set does not match /etc/corb/suid-allowlist.txt: ${parts.join(" ")}`);
  }

  return pass(name, `live SUID/SGID set matches /etc/corb/suid-allowlist.txt (${live.size} entries)`);
}

async function gateRemovals(vm: VM): Promise<GateResult> {
  const name = "removals";
  const candidates = ["npm", "npx", "su", "sudo", "doas", "apk", "apk.static"];
  const script = candidates.map((c) => `command -v ${c} >/dev/null 2>&1 && echo "PRESENT:${c}"`).join("; ");
  const result = await run(vm, ["/bin/sh", "-lc", script]);
  const present = result.stdout
    .split("\n")
    .filter((line) => line.startsWith("PRESENT:"))
    .map((line) => line.slice("PRESENT:".length).trim());

  if (present.length > 0) {
    return fail(name, `still reachable on PATH: ${present.join(", ")}`);
  }
  return pass(name, `absent from PATH: ${candidates.join(", ")}`);
}

async function gateCaTrust(vm: VM): Promise<GateResult> {
  const name = "ca-trust";
  const bundleResult = await run(vm, [
    "/bin/sh",
    "-lc",
    "test -f /run/gondolin/ca-certificates.crt && echo PRESENT || echo ABSENT",
  ]);
  if (!bundleResult.stdout.includes("PRESENT")) {
    return fail(name, "/run/gondolin/ca-certificates.crt is absent");
  }

  const problems: string[] = [];

  // Any HTTP response proves a completed Node TLS handshake. The request uses no API key.
  const nodeResult = await run(
    vm,
    [
      "/usr/bin/node",
      "-e",
      "fetch('https://api.anthropic.com/v1/messages',{method:'POST',body:'{}'})" +
        ".then(async r=>{console.log('STATUS',r.status)})" +
        ".catch(e=>{console.error('FETCH_ERROR',String(e&&e.stack||e));process.exitCode=1});",
    ],
    { HOME: "/root" },
  );
  if (nodeResult.exitCode !== 0 || !/STATUS \d+/.test(nodeResult.stdout)) {
    problems.push(
      `node: TLS handshake to api.anthropic.com did not complete (exit ${nodeResult.exitCode}): ${(nodeResult.stderr || nodeResult.stdout).trim()}`,
    );
  }

  // Curl reports TLS failures through its exit code. Any HTTP status can pass.
  const curlResult = await run(vm, [
    "/usr/bin/curl",
    "-s",
    "-o",
    "/dev/null",
    "-w",
    "%{http_code}",
    "--max-time",
    "20",
    "https://api.anthropic.com/v1/messages",
    "-X",
    "POST",
    "-d",
    "{}",
  ]);
  if (curlResult.exitCode !== 0) {
    problems.push(
      `curl: TLS handshake to api.anthropic.com did not complete, exit ${curlResult.exitCode}: ${curlResult.stderr.trim()}`,
    );
  }

  // Git invokes the policy shim again for its HTTPS helper. Both users
  // need the production gate mount and CA environment from the wrapper.
  for (const agent of [false, true]) {
    for (const executable of ["/usr/local/bin/git", "/usr/local/libexec/real-git"]) {
      const gitResult = await run(
        vm,
        [
          ...(agent ? ["/usr/local/bin/dropcap", "1000", "1000"] : []),
          executable, "ls-remote", "https://github.com/octocat/Hello-World.git",
        ],
        {
          HOME: agent ? "/home/agent" : "/root",
          CORB_GATE_CONFIG: GATE_CONFIG_GUEST_PATH,
          GIT_TERMINAL_PROMPT: "0",
          GIT_TRACE_CURL: "1",
          GIT_TRACE_CURL_NO_DATA: "1",
        },
      );
      const label = `${agent ? "agent" : "root"} ${executable}`;
      if (gitResult.exitCode !== 0 || !/^[a-f0-9]{40,64}\s+HEAD$/m.test(gitResult.stdout)) {
        problems.push(`${label}: HTTPS ls-remote failed (exit ${gitResult.exitCode}): ${gitResult.stderr.trim().slice(-4000)}`);
      } else if (!/SSL certificate (?:verify ok|verified via OpenSSL)/.test(gitResult.stderr)) {
        problems.push(`${label}: HTTPS trace did not confirm certificate verification`);
      }
    }
  }

  if (problems.length > 0) {
    return fail(name, problems.join(" | "));
  }
  return pass(name, "CA bundle present; Node, curl and root/agent git/real-git completed trusted HTTPS");
}

// Check the shipped policy shims. Behavioral policy tests also run in e2e.
async function gateGitGhShimmed(vm: VM): Promise<GateResult> {
  const name = "git-gh-shimmed";
  const result = await run(vm, [
    "/bin/sh",
    "-lc",
    "command -v git || echo GIT_ABSENT; " +
      "test -L /usr/local/bin/git && readlink /usr/local/bin/git || echo GIT_SHIM_NOT_SYMLINK; " +
      "test -L /usr/local/bin/gh && readlink /usr/local/bin/gh || echo GH_SHIM_NOT_SYMLINK; " +
      "test -x /usr/local/libexec/real-git && echo GIT_REAL_PRESENT || echo GIT_REAL_MISSING; " +
      "test -x /usr/local/libexec/real-gh && echo GH_REAL_PRESENT || echo GH_REAL_MISSING; " +
      "test -x /usr/local/libexec/policygate && echo POLICYGATE_PRESENT || echo POLICYGATE_MISSING; " +
      "test -e /usr/bin/git && echo OLD_GIT_ON_DISK || echo OLD_GIT_GONE; " +
      "test -e /usr/bin/gh && echo OLD_GH_ON_DISK || echo OLD_GH_GONE",
  ]);
  const lines = result.stdout
    .split("\n")
    .map((line) => line.trim())
    .filter(Boolean);
  const gitPath = lines[0];
  const gitSymlinkTarget = lines[1];
  const ghSymlinkTarget = lines[2];

  const problems: string[] = [];
  if (gitPath !== "/usr/local/bin/git") {
    problems.push(`git resolves to '${gitPath ?? "(nothing)"}', expected the policygate shim at /usr/local/bin/git`);
  }
  if (gitSymlinkTarget !== "/usr/local/libexec/policygate") {
    problems.push(`/usr/local/bin/git is not a symlink to /usr/local/libexec/policygate (readlink: '${gitSymlinkTarget ?? "(nothing)"}')`);
  }
  if (ghSymlinkTarget !== "/usr/local/libexec/policygate") {
    problems.push(`/usr/local/bin/gh is not a symlink to /usr/local/libexec/policygate (readlink: '${ghSymlinkTarget ?? "(nothing)"}')`);
  }
  if (!lines.includes("GIT_REAL_PRESENT")) {
    problems.push("/usr/local/libexec/real-git is missing or not executable");
  }
  if (!lines.includes("GH_REAL_PRESENT")) {
    problems.push("/usr/local/libexec/real-gh is missing or not executable");
  }
  if (!lines.includes("POLICYGATE_PRESENT")) {
    problems.push("/usr/local/libexec/policygate is missing or not executable");
  }
  if (lines.includes("OLD_GIT_ON_DISK")) {
    problems.push("/usr/bin/git is still directly reachable — the old unshadowed path should no longer be on PATH");
  }
  if (lines.includes("OLD_GH_ON_DISK")) {
    problems.push("/usr/bin/gh is still directly reachable — the old unshadowed path should no longer be on PATH");
  }

  if (problems.length > 0) {
    return fail(name, problems.join("; "));
  }
  return pass(
    name,
    "git/gh on PATH resolve to the policygate shim; real-git/real-gh/policygate all present and executable",
  );
}

async function gatePi(vm: VM): Promise<GateResult> {
  const name = "pi";
  const imageJsonResult = await run(vm, ["/bin/cat", "/etc/corb/image.json"]);
  if (!imageJsonResult.ok) {
    return fail(name, `could not read /etc/corb/image.json: exit ${imageJsonResult.exitCode}`);
  }

  let expected: unknown;
  try {
    expected = JSON.parse(imageJsonResult.stdout);
  } catch (err) {
    return fail(name, `/etc/corb/image.json is not valid JSON: ${String(err)}`);
  }
  const expectedVersion = (expected as { piVersion?: unknown }).piVersion;
  if (typeof expectedVersion !== "string" || expectedVersion.length === 0) {
    return fail(name, "/etc/corb/image.json has no string 'piVersion' field");
  }

  const versionResult = await run(vm, ["/bin/sh", "-lc", "pi --version"], { HOME: "/root" });
  if (!versionResult.ok) {
    return fail(name, `'pi --version' failed: exit ${versionResult.exitCode}: ${versionResult.stderr.trim()}`);
  }
  const actual = versionResult.stdout.trim();
  if (!actual.includes(expectedVersion)) {
    return fail(
      name,
      `'pi --version' printed '${actual}', expected it to contain the pinned piVersion '${expectedVersion}' recorded in /etc/corb/image.json`,
    );
  }

  return pass(name, `pi --version ('${actual}') matches /etc/corb/image.json's pinned piVersion '${expectedVersion}'`);
}

const GATES: Array<[string, (vm: VM) => Promise<GateResult>]> = [
  ["user", gateUser],
  ["privilege-drop", gatePrivilegeDrop],
  ["suid", gateSuid],
  ["removals", gateRemovals],
  ["ca-trust", gateCaTrust],
  ["git-gh-shimmed", gateGitGhShimmed],
  ["pi", gatePi],
];

/** Run all seven gates. The caller owns the VM and its network mounts. */
export async function verifyVm(vm: VM): Promise<VerifyReport> {
  const gates: GateResult[] = [];
  for (const [name, gate] of GATES) {
    try {
      gates.push(await gate(vm));
    } catch (error) {
      gates.push(fail(name, String(error)));
    }
  }
  return { ok: gates.every((gate) => gate.ok), gates };
}

/** Boot one verifier VM and close it after every result. */
export async function withImageVm<T>(
  assetDir: string,
  options: VerifyImageOptions,
  check: (vm: VM) => Promise<T>,
): Promise<T> {
  const allowedHosts = options.allowedHosts ?? DEFAULT_ALLOWED_HOSTS;
  const { httpHooks, env } = createHttpHooks({ allowedHosts, allowedInternalHosts: [] });

  return withBoundedVm(() => VM.create({
    sandbox: { imagePath: assetDir },
    memory: "1G",
    cpus: 2,
    startTimeoutMs: 45_000,
    ssh: { allowedHosts: [] },
    allowWebSockets: false,
    dns: { mode: "synthetic", syntheticHostMapping: "per-host" },
    httpHooks,
    env,
    // Git TLS checks need the same internal gate mount as ordinary sessions.
    vfs: { mounts: { [GATE_CONFIG_RAW_ROOT]: buildGateConfigMount() } },
    sessionLabel: options.sessionLabel ?? "corb-image-verify",
  }),
  async (vm) => { configureTrustedTls(vm); return check(vm); },
  (vm) => { process.stderr.write(`corb image: closing verifier host PID ${vm.getHostPid?.() ?? "unknown"}\n`); });
}

/** Boot an image, run the seven gates, and close the VM on every result. */
export async function verifyImage(assetDir: string, options: VerifyImageOptions = {}): Promise<VerifyReport> {
  return withImageVm(assetDir, options, verifyVm);
}
