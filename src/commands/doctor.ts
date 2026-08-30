// `corb doctor` — M3.5: host-side environment inspection. No VM is ever
// booted here; every check below is a file-existence test, a PATH/fallback
// binary lookup, a cheap subprocess version query, or a cgroup file read.
// `corb doctor` also takes no directory/workspace argument — see
// `src/config/paths.ts`'s own note that named-workspace-file resolution is
// a later milestone; this item only ever reads the single global
// `~/.config/corb/config.toml`, if present, the same way `corbConfigDir()`/
// `configTomlPath()` already default.
//
// Structured as a list of independent checks (`DoctorCheckResult`) rather
// than one large imperative function, so each check's classification logic
// can be unit-tested against an injectable input (an on-disk layout, a
// fabricated env object, a parsed version tuple) without mocking the real
// OS out from under it. `runDoctorChecks()` is the only place that touches
// real global state (`process.env`, the real filesystem, a real
// subprocess) — everything it calls is a small, pure, independently
// testable function.
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { corbConfigDir, configTomlPath } from "../config/paths.ts";
import { ConfigParseError, parseConfigLayer, type ConfigLayer } from "../config/schema.ts";
import { ImageNotFoundError, resolveRuntimeImage } from "../vm/image.ts";
import { readCgroupControllersText } from "../vm/cgroup.ts";

export type DoctorStatus = "ok" | "warn" | "fail";

export interface DoctorCheckResult {
  name: string;
  status: DoctorStatus;
  detail: string;
}

export interface DoctorReport {
  checks: DoctorCheckResult[];
  /** `false` if any check is `"fail"`. A `"warn"` alone does not fail the report. */
  ok: boolean;
}

function ok(name: string, detail: string): DoctorCheckResult {
  return { name, status: "ok", detail };
}

function warn(name: string, detail: string): DoctorCheckResult {
  return { name, status: "warn", detail };
}

function fail(name: string, detail: string): DoctorCheckResult {
  return { name, status: "fail", detail };
}

/** Pure aggregation: a report `ok`s exactly when no check `fail`ed. Exported separately so the roll-up logic is testable against a fabricated check list, without exercising any real check. */
export function buildDoctorReport(checks: DoctorCheckResult[]): DoctorReport {
  return { checks, ok: checks.every((c) => c.status !== "fail") };
}

function errorMessage(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

function isEnoent(err: unknown): boolean {
  return err instanceof Error && "code" in err && (err as NodeJS.ErrnoException).code === "ENOENT";
}

// src/commands/doctor.ts -> repo root is two levels up, same depth as
// src/commands/image.ts / src/vm/image.ts (see readPackageVersion there for
// the full reasoning — duplicated rather than factored into a shared
// helper for the same reason those two don't share one either: a five-line
// function with a couple of call sites doesn't earn a new module).
function moduleDir(): string {
  return path.dirname(fileURLToPath(import.meta.url));
}

function packageRoot(): string {
  return path.resolve(moduleDir(), "..", "..");
}

// ---------------------------------------------------------------------------
// /dev/kvm
// ---------------------------------------------------------------------------

const KVM_DEVICE_PATH = "/dev/kvm";

function checkKvm(kvmPath: string = KVM_DEVICE_PATH): DoctorCheckResult {
  if (!fs.existsSync(kvmPath)) {
    return fail(
      "kvm",
      `${kvmPath} does not exist. corb boots a KVM-accelerated micro-VM and cannot run without it — ` +
        `enable virtualization in firmware/BIOS and load the 'kvm' plus 'kvm_intel'/'kvm_amd' kernel modules.`,
    );
  }
  try {
    fs.accessSync(kvmPath, fs.constants.R_OK | fs.constants.W_OK);
  } catch {
    return fail(
      "kvm",
      `${kvmPath} exists but is not readable/writable by this process. ` +
        `Add your user to the group that owns it (commonly 'kvm') and start a new login session.`,
    );
  }
  return ok("kvm", `${kvmPath} present and accessible.`);
}

// ---------------------------------------------------------------------------
// PATH / fallback-directory binary lookup — shared by several checks below.
// ---------------------------------------------------------------------------

export type ToolLocation = "path" | "fallback" | "missing";

function isExecutableFile(candidate: string): boolean {
  try {
    const stat = fs.statSync(candidate);
    if (!stat.isFile()) {
      return false;
    }
    fs.accessSync(candidate, fs.constants.X_OK);
    return true;
  } catch {
    return false;
  }
}

export function splitPath(pathEnv: string | undefined): string[] {
  if (pathEnv === undefined || pathEnv === "") {
    return [];
  }
  return pathEnv.split(path.delimiter).filter((dir) => dir.length > 0);
}

/** Where `name` was found: on one of `pathDirs`, on one of `fallbackDirs` only, or nowhere. */
export function locateTool(name: string, pathDirs: readonly string[], fallbackDirs: readonly string[] = []): ToolLocation {
  for (const dir of pathDirs) {
    if (isExecutableFile(path.join(dir, name))) {
      return "path";
    }
  }
  for (const dir of fallbackDirs) {
    if (isExecutableFile(path.join(dir, name))) {
      return "fallback";
    }
  }
  return "missing";
}

// ---------------------------------------------------------------------------
// qemu-system-*
// ---------------------------------------------------------------------------

/** Maps `os.arch()` to the `qemu-system-<arch>` binary name QEMU itself uses. Unrecognised arches fall through to `qemu-system-<os.arch()>` as a best-effort guess rather than throwing — a check that can't be sure still shouldn't crash the whole command. */
export function qemuBinaryName(arch: string): string {
  switch (arch) {
    case "x64":
      return "qemu-system-x86_64";
    case "arm64":
      return "qemu-system-aarch64";
    case "ia32":
      return "qemu-system-i386";
    default:
      return `qemu-system-${arch}`;
  }
}

function checkQemu(pathDirs: readonly string[]): DoctorCheckResult {
  const binary = qemuBinaryName(os.arch());
  const location = locateTool(binary, pathDirs);
  if (location === "missing") {
    return fail(
      "qemu",
      `'${binary}' was not found on PATH. Install QEMU (the package is usually 'qemu-system-x86' / 'qemu' / 'qemu-full' ` +
        `depending on distro) — corb cannot boot a guest VM without it.`,
    );
  }
  return ok("qemu", `'${binary}' found on PATH.`);
}

// ---------------------------------------------------------------------------
// Docker
// ---------------------------------------------------------------------------

function checkDocker(pathDirs: readonly string[]): DoctorCheckResult {
  const location = locateTool("docker", pathDirs);
  if (location === "missing") {
    return fail(
      "docker",
      "'docker' was not found on PATH. corb image build needs a container runtime " +
        "(image/corb-image.json sets container.force: true, runtime: \"docker\") — install Docker.",
    );
  }
  try {
    execFileSync("docker", ["info"], { stdio: "ignore", timeout: 5000 });
  } catch (err) {
    return fail(
      "docker",
      `'docker' is installed but its daemon is not reachable ('docker info' failed: ${errorMessage(err)}). ` +
        "Start the Docker daemon (e.g. 'sudo systemctl start docker', or open Docker Desktop).",
    );
  }
  return ok("docker", "'docker' found on PATH and its daemon is reachable.");
}

// ---------------------------------------------------------------------------
// Node version
// ---------------------------------------------------------------------------

export type VersionTuple = [number, number, number];

export function parseVersionTuple(version: string): VersionTuple | undefined {
  const match = /(\d+)\.(\d+)\.(\d+)/.exec(version);
  if (match === null) {
    return undefined;
  }
  return [Number(match[1]), Number(match[2]), Number(match[3])];
}

/** -1 / 0 / 1, comparing tuples lexicographically (major, then minor, then patch). */
export function compareVersionTuples(a: VersionTuple, b: VersionTuple): number {
  for (let i = 0; i < 3; i++) {
    const diff = (a[i] ?? 0) - (b[i] ?? 0);
    if (diff !== 0) {
      return Math.sign(diff);
    }
  }
  return 0;
}

/** Pure classification: is `runningVersion` at or above `floorRange` (an `engines.node`-style `">=X.Y.Z"` string)? Exported separately from `checkNodeVersion` so the comparison logic is testable without touching `process.version` or `package.json`. */
export function classifyNodeVersion(runningVersion: string, floorRange: string): DoctorCheckResult {
  const running = parseVersionTuple(runningVersion);
  const floor = parseVersionTuple(floorRange);
  if (running === undefined) {
    return fail("node", `could not parse a version out of '${runningVersion}'.`);
  }
  if (floor === undefined) {
    return fail("node", `could not parse a version floor out of package.json's engines.node ('${floorRange}').`);
  }
  if (compareVersionTuples(running, floor) < 0) {
    return fail(
      "node",
      `running Node ${running.join(".")}, but corb requires >= ${floor.join(".")} (package.json's engines.node). ` +
        "Upgrade Node before running corb.",
    );
  }
  return ok("node", `running Node ${running.join(".")} (>= ${floor.join(".")} required).`);
}

function readEnginesNodeFloor(): string {
  const pkgPath = path.join(packageRoot(), "package.json");
  const pkg = JSON.parse(fs.readFileSync(pkgPath, "utf8")) as { engines?: { node?: unknown } };
  const floor = pkg.engines?.node;
  if (typeof floor !== "string" || floor.length === 0) {
    throw new Error(`package.json at ${pkgPath} has no "engines.node" string field`);
  }
  return floor;
}

// ---------------------------------------------------------------------------
// Go
// ---------------------------------------------------------------------------

export type MinorVersion = [number, number];

/** Extracts the `go 1.26`-style directive from a `go.mod` file's text. `undefined` if the file has no such line (never expected in this repo's own `guest/go.mod`, but a check that can't find it should degrade, not throw). */
export function parseGoModFloor(goModText: string): MinorVersion | undefined {
  const match = /^go\s+(\d+)\.(\d+)/m.exec(goModText);
  if (match === null) {
    return undefined;
  }
  return [Number(match[1]), Number(match[2])];
}

/** Extracts the `go1.26.5`-style version out of `go version`'s stdout. */
export function parseGoVersionOutput(output: string): MinorVersion | undefined {
  const match = /go(\d+)\.(\d+)/.exec(output);
  if (match === null) {
    return undefined;
  }
  return [Number(match[1]), Number(match[2])];
}

/**
 * Pure classification. Presence of `go` is the hard requirement (image
 * builds need it for the guest binaries); a version floor is only a
 * `warn`, never a `fail` — only `dropcap`'s own build (a `make guest` step,
 * not something `corb doctor` gatekeeps) actually needs a specific Go
 * version, and being confidently wrong about that floor is worse than not
 * checking it at all.
 */
export function classifyGoInstall(installed: MinorVersion | undefined, pinned: MinorVersion | undefined): DoctorCheckResult {
  if (installed === undefined) {
    return fail(
      "go",
      "'go' binary not found on PATH. Image builds need it to build the guest binaries (dropcap) — install Go.",
    );
  }
  if (pinned !== undefined && (installed[0] < pinned[0] || (installed[0] === pinned[0] && installed[1] < pinned[1]))) {
    return warn(
      "go",
      `go ${installed.join(".")} found, older than guest/go.mod's pinned floor (go ${pinned.join(".")}). ` +
        "Only the guest build (make guest) needs the pinned version — corb doctor itself does not require it, but the guest build may fail.",
    );
  }
  return ok("go", `go ${installed.join(".")} found on PATH.`);
}

// ---------------------------------------------------------------------------
// cpio / lz4
// ---------------------------------------------------------------------------

function checkCpioLz4(pathDirs: readonly string[]): DoctorCheckResult {
  const missing = ["cpio", "lz4"].filter((name) => locateTool(name, pathDirs) === "missing");
  if (missing.length > 0) {
    return fail(
      "cpio-lz4",
      `missing on PATH: ${missing.join(", ")}. Image builds need both to assemble the initramfs — install them.`,
    );
  }
  return ok("cpio-lz4", "'cpio' and 'lz4' both found on PATH.");
}

// ---------------------------------------------------------------------------
// e2fsprogs — the check docs/design.md calls out by name for needing the
// three-way "on PATH" / "reachable but not on PATH" / "genuinely missing"
// distinction.
// ---------------------------------------------------------------------------

const E2FSPROGS_TOOLS = ["mkfs.ext4", "resize2fs", "e2fsck"] as const;
const E2FSPROGS_FALLBACK_DIRS = ["/sbin", "/usr/sbin"];

/**
 * Pure classification over an already-computed `{tool -> ToolLocation}` map
 * — this is the one piece of logic docs/design.md calls out as needing to
 * be right, so it is factored out and unit-testable against a fabricated
 * map rather than only ever exercised against this machine's real
 * filesystem. All three on PATH -> ok. All three found (PATH or fallback)
 * but at least one only via fallback -> warn (image builds already handle
 * this themselves; a script/manual invocation might not). Any genuinely
 * missing -> fail.
 */
export function classifyE2fsprogs(locations: Readonly<Record<string, ToolLocation>>): DoctorCheckResult {
  const tools = Object.keys(locations);
  const missing = tools.filter((t) => locations[t] === "missing");
  if (missing.length > 0) {
    return fail(
      "e2fsprogs",
      `missing entirely: ${missing.join(", ")} (checked PATH, /sbin, /usr/sbin). ` +
        "Install e2fsprogs — image builds need mkfs.ext4/resize2fs/e2fsck to assemble the rootfs.",
    );
  }
  const fallbackOnly = tools.filter((t) => locations[t] === "fallback");
  if (fallbackOnly.length > 0) {
    return warn(
      "e2fsprogs",
      `reachable, but not on PATH: ${fallbackOnly.join(", ")} (found in /sbin or /usr/sbin instead). ` +
        "corb image build already accounts for this internally, so builds are unaffected; " +
        "a script or manual invocation of these tools may still fail unless it also checks /sbin:/usr/sbin.",
    );
  }
  return ok("e2fsprogs", `${tools.join(", ")} all found on PATH.`);
}

function checkE2fsprogs(pathDirs: readonly string[]): DoctorCheckResult {
  const locations: Record<string, ToolLocation> = {};
  for (const tool of E2FSPROGS_TOOLS) {
    locations[tool] = locateTool(tool, pathDirs, E2FSPROGS_FALLBACK_DIRS);
  }
  return classifyE2fsprogs(locations);
}

// ---------------------------------------------------------------------------
// SSH_AUTH_SOCK
// ---------------------------------------------------------------------------

/**
 * Pure classification given the env var's value and (if set) whether the
 * socket path exists. `socketExists` is only consulted when `sockPath` is
 * set, so a caller checking the unset case can pass anything for it.
 */
export function classifySshAuthSock(sockPath: string | undefined, socketExists: boolean): DoctorCheckResult {
  if (sockPath === undefined || sockPath === "") {
    return warn(
      "ssh-auth-sock",
      "SSH_AUTH_SOCK is not set. git-over-SSH inside the guest needs some auth mechanism; " +
        "this is not required for corb run to boot.",
    );
  }
  if (!socketExists) {
    return warn(
      "ssh-auth-sock",
      `SSH_AUTH_SOCK is set to '${sockPath}', but that path does not exist. The agent socket looks stale; ` +
        "git-over-SSH will likely fail until it points at a live agent.",
    );
  }
  // Heuristic only, per docs/design.md §5.2: 1Password's agent prompts
  // per-signature in a way that can look like a hang behind Pi's full-screen
  // TUI. Not a guarantee — just a distinct, more actionable warn when it's
  // cheaply detectable.
  if (sockPath.toLowerCase().includes("1password")) {
    return warn(
      "ssh-auth-sock",
      `SSH_AUTH_SOCK points at what looks like a 1Password agent socket ('${sockPath}'). ` +
        "1Password prompts per-signature, which can look like a hang behind Pi's full-screen TUI — " +
        "approve the prompt (it may be off-screen or in another window) rather than assuming corb has frozen.",
    );
  }
  return ok("ssh-auth-sock", `SSH_AUTH_SOCK is set ('${sockPath}') and the socket exists.`);
}

// ---------------------------------------------------------------------------
// config.toml loading — shared by the two secrets-related checks below.
// ---------------------------------------------------------------------------

export type DoctorConfigLoad =
  | { kind: "absent" }
  | { kind: "parsed"; layer: ConfigLayer }
  | { kind: "parse-error"; error: ConfigParseError };

function loadDoctorConfigLayer(configPath: string): DoctorConfigLoad {
  let text: string;
  try {
    text = fs.readFileSync(configPath, "utf8");
  } catch (err) {
    if (isEnoent(err)) {
      return { kind: "absent" };
    }
    throw err;
  }
  try {
    return { kind: "parsed", layer: parseConfigLayer(text, configPath) };
  } catch (err) {
    if (err instanceof ConfigParseError) {
      return { kind: "parse-error", error: err };
    }
    throw err;
  }
}

// ---------------------------------------------------------------------------
// Required secret env vars (config.toml says a secret is required; is the
// env var actually set?)
// ---------------------------------------------------------------------------

/**
 * Pure: given an already-loaded config (or parse failure) and an env
 * object, which non-`optional` `[secrets.NAME]` entries have no usable
 * (non-empty) `process.env[NAME]`? A malformed config.toml fails this
 * specific check with the parse error rather than throwing — `corb doctor`
 * should never crash outright over a bad config file, that is exactly the
 * kind of thing it exists to report.
 */
export function checkRequiredSecrets(configResult: DoctorConfigLoad, env: NodeJS.ProcessEnv): DoctorCheckResult {
  if (configResult.kind === "parse-error") {
    return fail("required-secrets", `config.toml could not be parsed: ${configResult.error.message}`);
  }
  if (configResult.kind === "absent") {
    return ok("required-secrets", "no config.toml present, so nothing to check.");
  }
  const secrets = configResult.layer.secrets ?? {};
  const missing: string[] = [];
  for (const [name, entry] of Object.entries(secrets)) {
    if (entry.optional === true) {
      continue;
    }
    // Empty-string counts as unset — matches src/vm/egress.ts's own
    // buildSecretBindings convention: FOO= in a shell is almost always a
    // mistake, not an intentionally empty secret.
    const value = env[name];
    if (value === undefined || value === "") {
      missing.push(name);
    }
  }
  if (missing.length > 0) {
    return fail(
      "required-secrets",
      `required secret env var(s) not set: ${missing.join(", ")}. ` +
        `Set them before running corb (e.g. \`${missing[0]}=... corb run\`), ` +
        "or mark the entry optional = true in config.toml if that's acceptable.",
    );
  }
  return ok("required-secrets", "every non-optional [secrets.*] entry in config.toml has its env var set.");
}

// ---------------------------------------------------------------------------
// Provider-neutral "no secrets configured at all" warning (docs/design.md
// §8). A separate, softer check from the one above: this fires when *no*
// secrets are configured at all, not when configured secrets are missing
// their env vars.
// ---------------------------------------------------------------------------

export function checkSecretsConfigured(configResult: DoctorConfigLoad): DoctorCheckResult {
  if (configResult.kind === "parse-error") {
    // Already reported by checkRequiredSecrets; avoid a second, redundant
    // fail for the same root cause under a different check name.
    return warn("secrets-configured", `config.toml could not be parsed (see the required-secrets check): ${configResult.error.message}`);
  }
  const hasAny = configResult.kind === "parsed" && Object.keys(configResult.layer.secrets ?? {}).length > 0;
  if (hasAny) {
    return ok("secrets-configured", "at least one [secrets.*] entry is configured.");
  }
  return warn(
    "secrets-configured",
    "no [secrets.*] entries are configured (config.toml is " +
      (configResult.kind === "absent" ? "absent" : "present but has none") +
      "). corb run needs at least a model API key to do anything useful. " +
      "Run 'corb explain' to see the current effective config, and see Pi's own provider docs for the env var " +
      "table it supports — corb does not assume any one provider.",
  );
}

// ---------------------------------------------------------------------------
// Pinned image resolvable
// ---------------------------------------------------------------------------

function checkImageResolvable(): DoctorCheckResult {
  try {
    const resolved = resolveRuntimeImage();
    return ok(
      "image-resolvable",
      `'${resolved.selector}' resolves to ${resolved.assetDir}${resolved.buildId !== undefined ? ` (buildId ${resolved.buildId})` : ""}.`,
    );
  } catch (err) {
    if (err instanceof ImageNotFoundError) {
      return warn("image-resolvable", `${err.message} (a fresh checkout legitimately has not built one yet.)`);
    }
    throw err;
  }
}

// ---------------------------------------------------------------------------
// Delegated systemd user cgroup controllers (Linux only; macOS has no
// equivalent primitive at all, per docs/design.md §7).
// ---------------------------------------------------------------------------

const REQUIRED_CGROUP_CONTROLLERS = ["memory", "pids", "cpu"];

/** Pure: given the raw text of `cgroup.controllers` (or `undefined` if the file doesn't exist), does it delegate everything M8's resource limits will need? */
export function classifyCgroupControllers(controllersText: string | undefined): DoctorCheckResult {
  if (controllersText === undefined) {
    return warn(
      "cgroup-controllers",
      "delegated cgroup.controllers file not found. This only matters for M8's (not-yet-built) resource limits — " +
        "corb run works fine without it today, unlimited.",
    );
  }
  const controllers = new Set(controllersText.split(/\s+/).filter((s) => s.length > 0));
  const missing = REQUIRED_CGROUP_CONTROLLERS.filter((c) => !controllers.has(c));
  if (missing.length > 0) {
    return warn(
      "cgroup-controllers",
      `user cgroup is missing delegated controller(s): ${missing.join(", ")} (has: ${[...controllers].join(", ") || "none"}). ` +
        "This only matters for M8's (not-yet-built) resource limits — corb run works fine without it today, unlimited.",
    );
  }
  return ok("cgroup-controllers", `user cgroup delegates all required controllers (${REQUIRED_CGROUP_CONTROLLERS.join(", ")}).`);
}

function checkCgroupControllers(platform: NodeJS.Platform): DoctorCheckResult {
  if (platform !== "linux") {
    return ok("cgroup-controllers", `not applicable on ${platform} — cgroups are a Linux-only primitive (docs/design.md §7).`);
  }
  const uid = process.getuid?.();
  if (uid === undefined) {
    return warn("cgroup-controllers", "could not determine the current uid (process.getuid is unavailable); skipping this check.");
  }
  // Raw read (fs.readFileSync + ENOENT-as-"missing") lives in
  // `src/vm/cgroup.ts` now, shared with `src/vm/scope.ts` (M8.3) — this
  // check's own classification policy (`classifyCgroupControllers`,
  // `REQUIRED_CGROUP_CONTROLLERS`, below) is unchanged.
  return classifyCgroupControllers(readCgroupControllersText(uid));
}

// ---------------------------------------------------------------------------
// Orchestration
// ---------------------------------------------------------------------------

/**
 * Runs every check against real host state (`process.env`, the real
 * filesystem, real subprocesses) and returns the aggregated report. Takes
 * no arguments, matching `corb doctor`'s own no-argument CLI surface —
 * every check's actual classification logic lives in the small pure
 * functions above, which is where injectable-input testing happens.
 */
export async function runDoctorChecks(): Promise<DoctorReport> {
  const pathDirs = splitPath(process.env.PATH);
  const configPath = configTomlPath(corbConfigDir());
  const configResult = loadDoctorConfigLayer(configPath);

  const checks: DoctorCheckResult[] = [checkKvm(), checkQemu(pathDirs), checkDocker(pathDirs)];

  checks.push(classifyNodeVersion(process.version, readEnginesNodeFloor()));

  {
    const goLocation = locateTool("go", pathDirs);
    if (goLocation === "missing") {
      checks.push(classifyGoInstall(undefined, undefined));
    } else {
      let installed: MinorVersion | undefined;
      try {
        installed = parseGoVersionOutput(execFileSync("go", ["version"], { encoding: "utf8", timeout: 5000 }));
      } catch {
        installed = undefined;
      }
      let pinned: MinorVersion | undefined;
      try {
        pinned = parseGoModFloor(fs.readFileSync(path.join(packageRoot(), "guest", "go.mod"), "utf8"));
      } catch {
        pinned = undefined;
      }
      checks.push(installed === undefined ? warn("go", "'go' found on PATH, but 'go version' could not be parsed.") : classifyGoInstall(installed, pinned));
    }
  }

  checks.push(checkCpioLz4(pathDirs));
  checks.push(checkE2fsprogs(pathDirs));

  {
    const sockPath = process.env.SSH_AUTH_SOCK;
    const socketExists = sockPath !== undefined && sockPath !== "" && fs.existsSync(sockPath);
    checks.push(classifySshAuthSock(sockPath, socketExists));
  }

  checks.push(checkRequiredSecrets(configResult, process.env));
  checks.push(checkSecretsConfigured(configResult));
  checks.push(checkImageResolvable());
  checks.push(checkCgroupControllers(process.platform));

  return buildDoctorReport(checks);
}

function statusLabel(status: DoctorStatus): string {
  switch (status) {
    case "ok":
      return "OK";
    case "warn":
      return "WARN";
    case "fail":
      return "FAIL";
  }
}

export async function runDoctorCommand(): Promise<void> {
  const report = await runDoctorChecks();
  for (const check of report.checks) {
    console.log(`[${statusLabel(check.status)}] ${check.name}: ${check.detail}`);
  }
  const failCount = report.checks.filter((c) => c.status === "fail").length;
  const warnCount = report.checks.filter((c) => c.status === "warn").length;
  console.log(`corb doctor: ${report.checks.length} check(s), ${failCount} failed, ${warnCount} warning(s).`);
  if (!report.ok) {
    process.exitCode = 1;
  }
}
