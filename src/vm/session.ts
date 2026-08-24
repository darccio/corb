// `src/vm/session.ts` — M1.6 built the one host program that assembles a
// single `VMOptions`, boots the already-tagged guest image (M1.3/M1.4), and
// runs Pi's interactive TUI inside it via `dropcap`, with the model API key
// bound as a host secret that never enters the guest. M2.4 generalizes the
// workspace piece of that from exactly one host directory to N, each with
// its own guest-visible name and independent `ro`/`rw` mode — the mechanism
// `docs/design.md` §3 describes (`/work/<name>` per directory) — while
// leaving everything else (image resolution, secret binding, guest identity
// read, `dropcap`/`pi` exec, shutdown, tty handling) conceptually unchanged.
//
// Partially decoupled from the config system: `dirs`/`primary` still use
// this file's own minimal `WorkspaceDirSpec` shape rather than importing
// `src/config/load.ts`'s `DirConfig` (unchanged since M2.4/M2.6). M3.4
// narrowed that decoupling for `egress`/`secrets` specifically — see the
// import comment below for why those two consume `src/config/` types
// directly instead of getting their own parallel shape.
//
// Composes M1.5's three modules rather than rebuilding any part of them:
// `resolveRuntimeImage` (src/vm/image.ts) for image resolution, `acquire` /
// `canRequestPty` (src/vm/tty.ts) for raw-mode terminal handling, and
// `ShutdownController` (src/vm/shutdown.ts) as the only real kill switch —
// `docs/gondolin-notes.md` §3 and §12 record that `ExecProcess` has no
// `kill`/`sendSignal` and no exec timeout, so `vm.close()` reachable from
// every exit path (a clean Ctrl-C, a killed terminal, an unexpected throw,
// and the exec's own normal completion) is the only reliable termination
// primitive available.
import fs from "node:fs";
import path from "node:path";
import { ReadonlyProvider, RealFSProvider, VM, type VirtualProvider } from "@earendil-works/gondolin";
import { acquire, canRequestPty, type TtyHandle } from "./tty.ts";
import { ShutdownController, type ExitFn, type ProcessLike } from "./shutdown.ts";
import { resolveRuntimeImage } from "./image.ts";
import { buildEgressConfig } from "./egress.ts";
import { buildGitSshOptions } from "./gitssh.ts";
// `egress.ts` (M3.2/M3.3) already imports these same config types directly
// rather than inventing its own decoupled shape, because it exists
// specifically to consume `EffectiveConfig.egress`/`.secrets` and hand the
// result straight to `createHttpHooks()`. `RunSessionOptions.egress`/
// `.secrets` below are passed straight through to `buildEgressConfig()`
// unchanged, so a redundant parallel type here would only be converted back
// into these exact types immediately before that call — no decoupling
// benefit, just an extra conversion step. M4.3 adds `RunSessionOptions.git`
// to this same group for the identical reason: `buildGitSshOptions()`
// (`./gitssh.ts`) already takes `EffectiveGitConfig` directly and hands its
// result straight to `VM.create({ ssh })`, so `git` is passed through
// unconverted exactly like `egress`/`secrets` are. This is different from
// `dirs`/`primary` (this module's own `WorkspaceDirSpec`, deliberately not
// `src/config/load.ts`'s `DirConfig` — see the module comment): those are
// shaped and validated by this module itself (name safety, mount roots),
// not merely forwarded to another module that already takes the config
// type directly.
import type { EffectiveEgressConfig, EffectiveGitConfig } from "../config/load.ts";
import type { PartialSecretConfig } from "../config/schema.ts";
import type { AuditWriter } from "../policy/audit.ts";

/**
 * Root all workspace directories are publicly visible under in the guest.
 * A dir named `name` lands at `` `${WORKSPACE_PUBLIC_ROOT}/${name}` ``, e.g.
 * `/work/corb` for a dir named `corb` — matching `docs/design.md` §3's
 * `[[dir]] name = "corb" -> guest /work/corb` scheme. This is a *public*
 * path, not where the underlying `RealFSProvider`/`ReadonlyProvider` mount
 * actually lands — see `WORKSPACE_RAW_ROOT`.
 */
export const WORKSPACE_PUBLIC_ROOT = "/work";

/**
 * Root all workspace directories' raw, internal-only, root-only mounts land
 * under in the guest. A dir named `name` is actually mounted (via
 * `vfs.mounts`) at `` `${WORKSPACE_RAW_ROOT}/${name}` ``, never referenced
 * again by anything but the boot-time re-export script below.
 *
 * Gondolin's own `sandboxfs` mounts every `vfs.mounts` guest path with a
 * compile-time-literal FUSE option string —
 * `fd={d},rootmode=40000,user_id=0,group_id=0,default_permissions` (see
 * `node_modules/@earendil-works/gondolin/dist/guest/src/sandboxfs/main.zig`'s
 * `mountFuse`) — with no `allow_other` and no config surface to add it. Per
 * plain Linux FUSE semantics that means only the mounting uid (0 — Gondolin's
 * own `/init` performs the mount before any of Corb's own code runs) can
 * touch a path mounted here at all, which left `dropcap`'s drop to a
 * non-root uid with no filesystem access whatsoever if a workspace directory
 * were mounted directly at its public `/work/<name>` path
 * (`docs/gondolin-notes.md` R5/R12, closed by this fix).
 *
 * The fix is `image/overlay/init-extra.sh`, wired via `image/corb-image.json`'s
 * `init.rootfsInitExtra`, which runs after `sandboxfs` has mounted (and bound
 * every `vfs.mounts` path, including every raw entry here) and before
 * `sandboxd` starts: it re-exports each raw mount at its public
 * `/work/<name>` path through `bindfs` (built from source at image-build
 * time — not packaged for any current Alpine stable branch), whose
 * `--force-user`/`--force-group` squash the workspace uid/gid (read from
 * `/etc/corb/image.json`) onto every path seen through the re-export, with
 * `allow_other` on by bindfs's own default. Nothing in this process — nor
 * Pi, nor `dropcap` — ever talks to a raw path directly; only the boot-time
 * re-export script does. `ReadonlyProvider`-wrapped (`ro`) dirs are mounted
 * the same way as `rw` ones at this layer: read-only enforcement is this
 * host-side provider's job, not the guest FUSE re-export's (see
 * `WorkspaceDirSpec.mode` below and `image/overlay/init-extra.sh`'s own
 * comment for why no read-only-specific `bindfs` flag is used).
 */
export const WORKSPACE_RAW_ROOT = "/mnt/corb-raw";

// No login shell for any exec here (array-form `exec` does not run one —
// `docs/design.md` §5.4), so nothing can come from `/etc/profile`; PATH is
// set explicitly everywhere, matching `image/verify.ts`'s own convention.
const GUEST_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";

// Confirmed against the real, locally-built `corb:0.1.0` image (M1.3/M1.4):
// `npm i -g` on Alpine's stock nodejs/npm installs with prefix `/usr/local`,
// so `pi`'s bin symlink lands at `/usr/local/bin/pi`, matching the literal
// path `docs/design.md` §2 already uses in its own exec example. Not
// recorded in `/etc/corb/image.json` (unlike uid/gid/dropcapPath/home,
// which are, and are read from there below instead of hardcoded).
const PI_PATH = "/usr/local/bin/pi";

/** Thrown before any VM is created when a requested workspace directory is unusable. */
export class WorkspaceDirectoryError extends Error {
  constructor(dir: string, reason: string) {
    super(`corb run: workspace directory '${dir}' ${reason}`);
    this.name = "WorkspaceDirectoryError";
  }
}

/**
 * Thrown before any VM is created when a workspace directory's guest-visible
 * `name` is unsafe to use in a guest path — a second, independent check from
 * `src/config/guestpaths.ts`'s `assertPlainSegment` (not called from here,
 * per this module's deliberate decoupling from the config system), applying
 * the same discipline: an unchecked `name` must never reach path
 * construction for either the raw (`WORKSPACE_RAW_ROOT`) or public
 * (`WORKSPACE_PUBLIC_ROOT`) mount point.
 */
export class InvalidWorkspaceNameError extends Error {
  constructor(name: string, reason: string) {
    super(`corb run: workspace directory name '${name}' ${reason}`);
    this.name = "InvalidWorkspaceNameError";
  }
}

/** The subset of `/etc/corb/image.json` (image/overlay/etc/corb/image.json) this session needs. */
interface CorbImageJson {
  user: string;
  uid: number;
  gid: number;
  paths: {
    dropcapPath: string;
    home: string;
    sessionsDir: string;
  };
}

function parseCorbImageJson(text: string): CorbImageJson {
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch (err) {
    throw new Error(`corb run: /etc/corb/image.json is not valid JSON: ${String(err)}`);
  }
  if (typeof parsed !== "object" || parsed === null) {
    throw new Error("corb run: /etc/corb/image.json did not parse to an object");
  }
  const obj = parsed as Record<string, unknown>;
  const paths = obj.paths;
  if (
    typeof obj.user !== "string" ||
    typeof obj.uid !== "number" ||
    typeof obj.gid !== "number" ||
    typeof paths !== "object" ||
    paths === null
  ) {
    throw new Error(
      "corb run: /etc/corb/image.json is missing one of the required fields 'user', 'uid', 'gid', 'paths'",
    );
  }
  const p = paths as Record<string, unknown>;
  if (
    typeof p.dropcapPath !== "string" ||
    typeof p.home !== "string" ||
    typeof p.sessionsDir !== "string"
  ) {
    throw new Error(
      "corb run: /etc/corb/image.json's 'paths' is missing one of the required string fields " +
        "'dropcapPath', 'home', 'sessionsDir'",
    );
  }
  return {
    user: obj.user,
    uid: obj.uid,
    gid: obj.gid,
    paths: { dropcapPath: p.dropcapPath, home: p.home, sessionsDir: p.sessionsDir },
  };
}

/**
 * Reads uid/gid (and the other baked-in paths) from `/etc/corb/image.json`
 * inside the *booted* guest, the same way `image/verify.ts`'s `gatePi` gate
 * does — the file's content on disk inside `rootfs.ext4` isn't directly
 * host-readable without mounting the image, so this is a `vm.exec` read
 * after boot, not a host filesystem read of the asset directory.
 */
async function readGuestIdentity(vm: VM): Promise<CorbImageJson> {
  const result = await vm.exec(["/bin/cat", "/etc/corb/image.json"], {
    env: { PATH: GUEST_PATH },
    stdout: "buffer",
    stderr: "buffer",
  });
  if (!result.ok) {
    throw new Error(
      `corb run: could not read /etc/corb/image.json from the guest (exit ${result.exitCode}): ` +
        (result.stderr.trim() || result.stdout.trim()),
    );
  }
  return parseCorbImageJson(result.stdout);
}

function resolveHostDir(dir: string): string {
  const resolved = path.resolve(dir);
  let stat: fs.Stats;
  try {
    stat = fs.statSync(resolved);
  } catch {
    throw new WorkspaceDirectoryError(resolved, "does not exist");
  }
  if (!stat.isDirectory()) {
    throw new WorkspaceDirectoryError(resolved, "is not a directory");
  }
  return resolved;
}

// Mirrors `src/config/guestpaths.ts`'s `assertPlainSegment` exactly (name
// must be a single, literal path segment — no separator, no `.`/`..`) but
// is not that same function: this module deliberately does not import the
// config system (see the module comment), and a bad `name` here would
// otherwise construct an unsafe raw (`WORKSPACE_RAW_ROOT`) or public
// (`WORKSPACE_PUBLIC_ROOT`) guest path independently of anything
// `src/config/` validates.
function assertValidWorkspaceName(name: string): void {
  if (name.length === 0) {
    throw new InvalidWorkspaceNameError(name, "must not be empty");
  }
  if (name === "." || name === "..") {
    throw new InvalidWorkspaceNameError(name, "is not a valid directory name");
  }
  if (name.includes("/") || name.includes("\\")) {
    throw new InvalidWorkspaceNameError(name, "must not contain a path separator");
  }
}

function assertNoDuplicateNames(dirs: readonly WorkspaceDirSpec[]): void {
  const seen = new Set<string>();
  for (const dir of dirs) {
    if (seen.has(dir.name)) {
      throw new InvalidWorkspaceNameError(dir.name, "is used by more than one 'dirs' entry");
    }
    seen.add(dir.name);
  }
}

/** Public guest mount point for a workspace directory named `name` — see `WORKSPACE_PUBLIC_ROOT`. */
export function publicWorkspacePath(name: string): string {
  return `${WORKSPACE_PUBLIC_ROOT}/${name}`;
}

/** Internal, root-only raw guest mount point for a workspace directory named `name` — see `WORKSPACE_RAW_ROOT`. */
export function rawWorkspacePath(name: string): string {
  return `${WORKSPACE_RAW_ROOT}/${name}`;
}

/**
 * Guest environment for the `dropcap`/`pi` exec. None of this can come from
 * `/etc/profile` (`docs/design.md` §5.4) — array-form `exec` runs no login
 * shell — so everything the guest process needs is listed explicitly here.
 * `NODE_EXTRA_CA_CERTS`/`SSL_CERT_FILE`/etc. are deliberately *not* set:
 * `docs/gondolin-notes.md` R3 records that Gondolin's own guest init exports
 * them unconditionally for every guest process regardless of `VM.create()`/
 * `vm.exec()` config, so setting them again here would be redundant.
 */
function buildGuestEnv(
  secretEnv: Record<string, string>,
  hostEnv: NodeJS.ProcessEnv,
  identity: CorbImageJson,
): Record<string, string> {
  return {
    ...secretEnv,
    HOME: identity.paths.home,
    USER: identity.user,
    PATH: GUEST_PATH,
    ...(hostEnv.TERM !== undefined ? { TERM: hostEnv.TERM } : {}),
    // Nice-to-have, not a host mount — see the M1.6 report's "sessions
    // mount" note. Points Pi at the sessions directory the image already
    // creates and chowns to `agent` (recorded in /etc/corb/image.json, not
    // hardcoded here), so it has somewhere writable of its own without a
    // second VFS mount. Its contents do not survive `vm.close()`.
    PI_CODING_AGENT_SESSION_DIR: identity.paths.sessionsDir,
  };
}

/**
 * One workspace directory to mount for a `runSession` call. Deliberately
 * this module's own minimal shape, not `src/config/load.ts`'s `DirConfig` —
 * see the module comment for why `session.ts` stays decoupled from the
 * config system.
 */
export interface WorkspaceDirSpec {
  /**
   * Guest-visible name. The directory is publicly mounted at
   * `` `/work/${name}` `` (`publicWorkspacePath`). Must be a plain path
   * segment: non-empty, no `/` or `\`, not `.` or `..`.
   */
  name: string;
  /** Host path to mount. Relative paths are resolved against `process.cwd()`, like the current single-dir behavior. */
  hostPath: string;
  /** `"rw"` mounts a plain `RealFSProvider`; `"ro"` wraps it in `ReadonlyProvider`. */
  mode: "ro" | "rw";
  /** If true and `hostPath` doesn't exist, create it (`mkdir -p`) before validating/mounting. */
  create?: boolean;
}

export interface RunSessionOptions {
  /** Workspace directories to mount. Every entry's `name` must be unique. */
  dirs: WorkspaceDirSpec[];
  /** Which `dirs[].name` becomes Pi's cwd (`` `/work/${primary}` ``). Must match one entry in `dirs`. */
  primary: string;
  /** Args forwarded to `pi` after `dropcap` has dropped privilege. */
  piArgs: string[];
  /** Image selector override. Defaults to `resolveRuntimeImage()`'s own default (`corb:<pkgVersion>`). */
  image?: string;
  /** `VM.create()`'s `sessionLabel`. Defaults to a name derived from the primary directory. */
  sessionLabel?: string;
  /**
   * A session's full effective egress config (`EffectiveConfig.egress`,
   * always present — see `src/config/load.ts`), passed straight through to
   * `buildEgressConfig()`. See the module-level import comment for why this
   * module imports this config type directly rather than defining its own
   * decoupled shape, unlike `dirs`/`primary` above.
   */
  egress: EffectiveEgressConfig;
  /**
   * A session's configured secrets (`EffectiveConfig.secrets`), optional to
   * match that field's own optionality. Passed straight through to
   * `buildEgressConfig()` — see the module-level import comment.
   */
  secrets?: Record<string, PartialSecretConfig>;
  /**
   * A session's full effective git config (`EffectiveConfig.git`, always
   * present — see `src/config/load.ts`), passed straight through to
   * `buildGitSshOptions()`. See the module-level import comment for why this
   * module imports this config type directly rather than defining its own
   * decoupled shape, unlike `dirs`/`primary` above.
   */
  git: EffectiveGitConfig;
  /**
   * Where policy decisions for this session are recorded. Constructed by the
   * caller (`src/commands/run.ts`) — this module does not resolve an audit
   * path itself, matching its existing convention of taking already-resolved
   * inputs rather than doing its own config-adjacent path resolution (see
   * `dirs: WorkspaceDirSpec[]`, which is likewise never resolved from config
   * by this module).
   */
  audit: AuditWriter;
  /**
   * Identifier correlating this session's audit events. Defaults to whatever
   * this call computes for `sessionLabel` (see below) — there is no real
   * session-id infrastructure yet (M8 builds that). Reusing `sessionLabel`'s
   * value for both is a reasonable, explicitly *temporary* choice for this
   * item; do not treat it as a permanent design decision.
   */
  sessionId?: string;
  /** Host process environment to read configured secrets'/`TERM` from. Defaults to `process.env` — injectable for tests. */
  env?: NodeJS.ProcessEnv;
  /** Streams to attach the interactive exec to. Default `process.stdin/stdout/stderr`. */
  stdin?: NodeJS.ReadStream;
  stdout?: NodeJS.WriteStream;
  stderr?: NodeJS.WriteStream;
  /** Passed through to `ShutdownController` — injectable for tests, per `src/vm/shutdown.ts`'s own convention. */
  shutdownProcess?: ProcessLike;
  exit?: ExitFn;
}

interface ResolvedWorkspaceDir {
  name: string;
  hostPath: string;
  mode: "ro" | "rw";
}

/**
 * Validates and resolves every `dirs` entry: name safety, no duplicate
 * names, `create`-if-missing, then existence/directory-ness — in that order,
 * so a bad name is caught before any path arithmetic or filesystem mutation,
 * and `create` runs before the existence check it would otherwise fail.
 */
function resolveWorkspaceDirs(dirs: WorkspaceDirSpec[]): ResolvedWorkspaceDir[] {
  for (const dir of dirs) {
    assertValidWorkspaceName(dir.name);
  }
  assertNoDuplicateNames(dirs);

  return dirs.map((dir) => {
    if (dir.create) {
      const resolved = path.resolve(dir.hostPath);
      if (!fs.existsSync(resolved)) {
        fs.mkdirSync(resolved, { recursive: true });
      }
    }
    const hostPath = resolveHostDir(dir.hostPath);
    return { name: dir.name, hostPath, mode: dir.mode };
  });
}

function findPrimaryEntry(dirs: ResolvedWorkspaceDir[], primary: string): ResolvedWorkspaceDir {
  const found = dirs.find((d) => d.name === primary);
  if (!found) {
    throw new WorkspaceDirectoryError(primary, "is not one of the configured 'dirs' entries (check 'primary')");
  }
  return found;
}

/**
 * Boots the guest image, mounts every entry in `options.dirs` at its own
 * `` `/work/${name}` ``, and runs Pi's TUI inside `` `/work/${options.primary}` ``
 * via `dropcap`, following the pattern in `docs/design.md` §5.5. Under
 * normal operation this does not return: the guest's own exit code (or an
 * error) is propagated through `ShutdownController`'s `exit` function, which
 * defaults to the real `process.exit`.
 */
export async function runSession(options: RunSessionOptions): Promise<void> {
  const hostEnv = options.env ?? process.env;

  // Resolution and validation above all happen before any VM is created —
  // "error clearly and immediately... before attempting to boot anything".
  const resolvedDirs = resolveWorkspaceDirs(options.dirs);
  const primaryEntry = findPrimaryEntry(resolvedDirs, options.primary);
  const resolvedImage = resolveRuntimeImage(options.image);

  const sessionLabel = options.sessionLabel ?? `corb-run:${path.basename(primaryEntry.hostPath)}`;
  // See `RunSessionOptions.sessionId`'s own doc comment: no real session-id
  // infrastructure exists yet (M8), so this reuses `sessionLabel` as a
  // temporary stand-in rather than minting anything new here.
  const sessionId = options.sessionId ?? sessionLabel;

  const stdin = options.stdin ?? process.stdin;
  const stdout = options.stdout ?? process.stdout;
  const stderr = options.stderr ?? process.stderr;

  const vfsMounts: Record<string, VirtualProvider> = {};
  for (const dir of resolvedDirs) {
    const base = new RealFSProvider(dir.hostPath);
    vfsMounts[rawWorkspacePath(dir.name)] = dir.mode === "ro" ? new ReadonlyProvider(base) : base;
  }

  let vm: VM | undefined;
  let ttyHandle: TtyHandle | undefined;

  // Installed before the VM even exists: a signal during boot must still
  // lead to a clean close of whatever got started, not just of a fully
  // running session. Each step independently no-ops until there is
  // something to restore/close.
  const controller = new ShutdownController({
    steps: [
      { name: "restore-tty", run: () => ttyHandle?.restore() },
      {
        name: "close-vm",
        run: async () => {
          if (vm) {
            await vm.close();
          }
        },
      },
      {
        name: "flush-audit",
        // Independent of the other two steps, same discipline (a flush
        // failure — e.g. a full disk — must not prevent the VM from
        // closing, and a VM-close failure must not prevent whatever's
        // already buffered from reaching disk). Runs last, after the VM is
        // closed: closing the VM is the time-sensitive cleanup (an
        // un-closed VM leaves a real QEMU process running), while flushing
        // the audit log is not, so there's no reason to risk delaying it.
        run: () => options.audit.flush(),
      },
    ],
    ...(options.shutdownProcess ? { process: options.shutdownProcess } : {}),
    ...(options.exit ? { exit: options.exit } : {}),
  });
  controller.install();

  try {
    // The `session` channel (`docs/design.md` §6/§8) has had no producer
    // until this item — recorded here since the audit writer is already
    // being threaded through this function for `buildEgressConfig()`'s own
    // `http`-channel events. "start" is recorded before `buildEgressConfig`
    // so a pre-boot validation failure (a `MissingSecretError`/
    // `SecretHostsMissingError`) still lands in the buffer and, via the
    // `catch` below, still reaches disk through the `flush-audit` step.
    options.audit.record({
      channel: "session",
      decision: "allow",
      subject: sessionLabel,
      reason: "start",
      sessionId,
    });

    const egressConfig = buildEgressConfig(options.egress, options.secrets, hostEnv, options.audit, sessionId);
    // `ssh` is always passed, never conditionally omitted: `SshOptions.allowedHosts`
    // is a required `string[]`, and `buildGitSshOptions` itself already
    // normalizes an absent `git["allow-hosts"]` to `[]` — which, per that
    // function's own doc comment (verified against
    // `node_modules/@earendil-works/gondolin/dist/src/qemu/ssh.js`), cleanly
    // disables SSH egress entirely rather than requiring `ssh` to be left
    // unset for the same effect.
    const gitSshOptions = buildGitSshOptions(options.git, hostEnv, options.audit, sessionId);

    vm = await VM.create({
      sandbox: { imagePath: resolvedImage.assetDir },
      dns: { mode: "synthetic", syntheticHostMapping: "per-host" },
      httpHooks: egressConfig.httpHooks,
      env: egressConfig.env,
      allowWebSockets: egressConfig.allowWebSockets,
      vfs: { mounts: vfsMounts },
      ssh: gitSshOptions,
      sessionLabel,
    });

    const identity = await readGuestIdentity(vm);
    const guestEnv = buildGuestEnv(egressConfig.env, hostEnv, identity);

    const requestPty = canRequestPty(stdin, stdout);
    if (requestPty) {
      ttyHandle = acquire(stdin, stdout);
    }

    const proc = vm.exec(
      [identity.paths.dropcapPath, String(identity.uid), String(identity.gid), PI_PATH, ...options.piArgs],
      {
        cwd: publicWorkspacePath(options.primary),
        env: guestEnv,
        stdin: true,
        pty: requestPty,
        stdout: "pipe",
        stderr: "pipe",
      },
    );
    proc.attach(stdin, stdout, stderr);

    const result = await proc;
    options.audit.record({
      channel: "session",
      decision: "allow",
      subject: sessionLabel,
      reason: `exit:${result.exitCode}`,
      sessionId,
    });
    await controller.trigger("exit", result.exitCode);
  } catch (err) {
    options.audit.record({
      channel: "session",
      decision: "allow",
      subject: sessionLabel,
      reason: "error",
      sessionId,
    });
    await controller.trigger("error", 1, err);
    throw err;
  }
}
