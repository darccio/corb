// M1.4 — in-VM gate suite that boots a just-built (not yet tagged) guest
// image and asserts a fixed set of properties before `corb image build` is
// allowed to call `tagImage()`. This turns M1.3's one-off manual sanity
// check (`dropcap 1000 1000 /bin/sh -c 'cat /proc/self/status'`, run by
// hand in a throwaway VM and eyeballed) into a permanent, repeatable gate.
//
// Deliberately outside `src/`: this is invoked from `src/commands/image.ts`
// via a runtime dynamic import (see the comment there for why), not through
// tsc's normal module graph, so it is not subject to `tsconfig.json`'s
// `rootDir: "src"` restriction. It still type-checks on its own (run
// `npx tsc --noEmit image/verify.ts` or equivalent) and runs directly under
// Node's native TypeScript support (erasable syntax only), matching how
// `src/cli.ts` is run in dev mode.
//
// One VM is booted for the whole suite (a handful of `vm.exec` calls against
// the same session) rather than one VM per gate, mirroring M1.3's own smoke
// check and avoiding the ~seconds-of-boot cost per gate.
//
// Two of the gates from the plan's original table needed a decision rather
// than a blind port — see the "ca-trust" and "git-gh-current-state" gates
// below for what was decided and why.

import { createHttpHooks, VM } from "@earendil-works/gondolin";

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

// No login shell, so no reliance on /etc/profile; matches the array-exec
// convention used throughout the rest of Corb (see docs/design.md §5.4).
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
  // [ \t]*, not \s* — \s matches "\n" too, so on a value-less line like
  // "Groups:\t \n" a greedy \s* swallows the trailing space *and* the
  // newline and (.*)$ ends up capturing the *next* line instead of the
  // (correctly) empty Groups value. Caught by running this for real
  // against the built image, not a hypothetical.
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
  const candidates = ["npm", "npx", "su", "sudo", "doas", "apk"];
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

  // node — a completed handshake plus *any* HTTP response (even a 401) is
  // a pass; no API key is needed or used. Technique from M0.2's spike.
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

  // curl — exit 0 means the TLS handshake and HTTP round-trip both
  // completed, regardless of HTTP status; curl uses distinct nonzero exit
  // codes (35, 60, ...) specifically for TLS/certificate failures, so exit
  // code alone discriminates "trusted" from "not trusted" here.
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

  // git — ls-remote against a real public git-over-HTTPS host. Exit 0
  // means the TLS handshake was trusted and the smart-HTTP exchange
  // completed; no clone, no credentials.
  const gitResult = await run(
    vm,
    ["/usr/bin/git", "ls-remote", "https://github.com/octocat/Hello-World.git"],
    { HOME: "/root" },
  );
  if (gitResult.exitCode !== 0) {
    problems.push(`git: ls-remote over https to github.com failed, exit ${gitResult.exitCode}: ${gitResult.stderr.trim()}`);
  }

  if (problems.length > 0) {
    return fail(name, problems.join(" | "));
  }
  return pass(name, "CA bundle present; node, curl and git each completed a trusted TLS handshake to an allowed host");
}

// The plan's original gate table (written before M1 was split into
// milestones) asserted that `/usr/local/bin/git` is a `policygate` shim and
// that `/usr/bin/git` is absent. Before M7 shipped, that assertion was
// flipped to a *current-state* gate (git/gh still the real, unmodified
// Alpine binaries) so a premature regression toward the shimmed state would
// still be caught. M7 (`image/corb-image.json`'s `postBuild.commands`) now
// actually installs the shim, so this gate is flipped back to asserting the
// shimmed state the plan originally called for — this is the gate that
// stays in place going forward.
//
// This is static image structure only: `command -v`/symlink target/`test -x`
// checks against the *built image*, not `policygate`'s actual runtime
// gating behavior. This throwaway build-time verify VM has no `gate.json`
// mounted (that's a runtime, per-session artifact `src/vm/session.ts`
// generates, not something baked into the image) and no `CORB_GATE_CONFIG`
// pointing anywhere, so no gated subcommand can be meaningfully exercised
// here. Full behavioral verification against a real session (M7.4) is a
// separate, later item.
async function gateGitGhShimmed(vm: VM): Promise<GateResult> {
  const name = "git-gh-shimmed";
  const result = await run(vm, [
    "/bin/sh",
    "-lc",
    "command -v git || echo GIT_ABSENT; " +
      "test -L /usr/local/bin/git && readlink /usr/local/bin/git || echo GIT_SHIM_NOT_SYMLINK; " +
      "test -L /usr/local/bin/gh && readlink /usr/local/bin/gh || echo GH_SHIM_NOT_SYMLINK; " +
      "test -x /usr/local/libexec/git-real && echo GIT_REAL_PRESENT || echo GIT_REAL_MISSING; " +
      "test -x /usr/local/libexec/gh-real && echo GH_REAL_PRESENT || echo GH_REAL_MISSING; " +
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
    problems.push("/usr/local/libexec/git-real is missing or not executable");
  }
  if (!lines.includes("GH_REAL_PRESENT")) {
    problems.push("/usr/local/libexec/gh-real is missing or not executable");
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
    "git/gh on PATH resolve to the policygate shim; git-real/gh-real/policygate all present and executable",
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

const GATES: Array<(vm: VM) => Promise<GateResult>> = [
  gateUser,
  gatePrivilegeDrop,
  gateSuid,
  gateRemovals,
  gateCaTrust,
  gateGitGhShimmed,
  gatePi,
];

/**
 * Boot the guest image at `assetDir` (a `buildAssets()` output directory, an
 * imported build id, or an image selector — anything `SandboxServerOptions.imagePath`
 * accepts) in a throwaway VM and run every gate against it. Always closes the
 * VM, including when a gate throws or fails.
 */
export async function verifyImage(assetDir: string, options: VerifyImageOptions = {}): Promise<VerifyReport> {
  const allowedHosts = options.allowedHosts ?? DEFAULT_ALLOWED_HOSTS;
  const { httpHooks, env } = createHttpHooks({ allowedHosts, allowedInternalHosts: [] });

  const vm = await VM.create({
    sandbox: { imagePath: assetDir },
    dns: { mode: "synthetic", syntheticHostMapping: "per-host" },
    httpHooks,
    env,
    sessionLabel: options.sessionLabel ?? "corb-image-verify",
  });

  try {
    const gates: GateResult[] = [];
    for (const gate of GATES) {
      gates.push(await gate(vm));
    }
    return { ok: gates.every((g) => g.ok), gates };
  } finally {
    await vm.close();
  }
}
