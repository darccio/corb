// `src/vm/session.ts` — M1.6: the one host program that assembles a single
// `VMOptions`, boots the already-tagged guest image (M1.3/M1.4), mounts one
// host directory, and runs Pi's interactive TUI inside it via `dropcap`,
// with the model API key bound as a host secret that never enters the
// guest. This is M1's own accept criterion (`docs/design.md` §10 /
// `plans/.../` §7): the TUI is interactive, resize reflows, Ctrl-C exits
// clean and restores the terminal, guest edits appear on the host, and the
// real key is absent from guest env, `/proc/*/environ` and disk.
//
// Deliberately minimal, per the M1.6 brief: no config system (M2), no
// general-purpose multi-host egress/audit module (M3), no git/SSH policy
// (M4), no glob-based VFS policy (M5), no Pi settings synthesis, no session
// registry/watchdog (M8). Everything here is inlined exactly as far as this
// one session needs it — one `RealFSProvider` mount, one `createHttpHooks`
// call binding exactly `ANTHROPIC_API_KEY`, nothing configurable beyond the
// couple of fields `src/commands/run.ts` passes in. The general, pluggable
// versions of these pieces belong to later milestones, once there is an
// actual config system to drive them.
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
//
// Two judgment calls made here are flagged in the M1.6 report rather than
// treated as settled, per the brief's instruction to surface real forks
// instead of quietly resolving them:
//
//   - The guest mount path (`WORKSPACE_GUEST_PATH` below, chosen as `/work`
//     because `image/corb-image.json`'s postBuild already creates and
//     chowns it to `agent:agent`, and it matches the future multi-directory
//     mount root `/work/<name>` the full plan describes in §5.3) — the
//     M1.6 brief separately suggested "something under /home/agent/" as
//     the more image-consistent choice, and both are defensible.
//   - The sessions mount: deferred. Pi is pointed at the image's own
//     baked-in, chowned-to-agent `/home/agent/sessions` directory via
//     `PI_CODING_AGENT_SESSION_DIR` (from `/etc/corb/image.json`, not
//     hardcoded), but that directory is *not* backed by a host `RealFSProvider`
//     mount — its contents do not survive `vm.close()`. Adding a host-backed
//     mount is cheap in isolation but pulls in a second host-path decision
//     (where do session transcripts live on the host?) that the brief left
//     open; deferring it keeps this milestone to the one mount the accept
//     criterion actually requires.
import fs from "node:fs";
import path from "node:path";
import { createHttpHooks, RealFSProvider, VM } from "@earendil-works/gondolin";
import { acquire, canRequestPty, type TtyHandle } from "./tty.ts";
import { ShutdownController, type ExitFn, type ProcessLike } from "./shutdown.ts";
import { resolveRuntimeImage } from "./image.ts";

/**
 * Guest mount point the rest of Corb (and Pi, via `dropcap`) sees the one
 * host workspace directory at. This is a *public* path, not where the
 * `RealFSProvider` is actually mounted — see `WORKSPACE_RAW_GUEST_PATH`.
 */
export const WORKSPACE_GUEST_PATH = "/work";

/**
 * Internal, root-only guest path where the raw `RealFSProvider` mount
 * actually lands.
 *
 * Gondolin's own `sandboxfs` mounts every `vfs.mounts` guest path with a
 * compile-time-literal FUSE option string —
 * `fd={d},rootmode=40000,user_id=0,group_id=0,default_permissions` (see
 * `node_modules/@earendil-works/gondolin/dist/guest/src/sandboxfs/main.zig`'s
 * `mountFuse`) — with no `allow_other` and no config surface to add it. Per
 * plain Linux FUSE semantics that means only the mounting uid (0 — Gondolin's
 * own `/init` performs the mount before any of Corb's own code runs) can
 * touch a path mounted here at all, which left `dropcap`'s drop to uid 1000
 * with no filesystem access whatsoever if the workspace were mounted
 * directly at `WORKSPACE_GUEST_PATH` (`docs/gondolin-notes.md` R5/R12,
 * closed by this fix).
 *
 * The fix is `image/overlay/init-extra.sh`, wired via `image/corb-image.json`'s
 * `init.rootfsInitExtra`, which runs after `sandboxfs` has mounted (and bound
 * every `vfs.mounts` path, including this one) and before `sandboxd` starts:
 * it re-exports this raw mount at `WORKSPACE_GUEST_PATH` through `bindfs`
 * (built from source at image-build time — not packaged for any current
 * Alpine stable branch), whose `--force-user`/`--force-group` squash the
 * workspace uid/gid (read from `/etc/corb/image.json`) onto every path seen
 * through the re-export, with `allow_other` on by bindfs's own default.
 * Nothing in this process — nor Pi, nor `dropcap` — ever talks to this path
 * directly; only the boot-time re-export script does.
 */
export const WORKSPACE_RAW_GUEST_PATH = "/mnt/corb-raw/work";

/** The only host this session's egress is allowed to reach. */
const ANTHROPIC_HOST = "api.anthropic.com";

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

/**
 * Thrown before any VM is created when the host process environment has no
 * `ANTHROPIC_API_KEY` — never silently proceeds with an empty secret.
 */
export class MissingApiKeyError extends Error {
  constructor() {
    super(
      "corb run: ANTHROPIC_API_KEY is not set in the host environment.\n" +
        "  Set it before running corb, e.g. `ANTHROPIC_API_KEY=sk-... corb run`.\n" +
        "  The key is bound as a host-side secret (see docs/design.md §5) and never enters the guest.",
    );
    this.name = "MissingApiKeyError";
  }
}

/** Thrown before any VM is created when the requested workspace directory is unusable. */
export class WorkspaceDirectoryError extends Error {
  constructor(dir: string, reason: string) {
    super(`corb run: workspace directory '${dir}' ${reason}`);
    this.name = "WorkspaceDirectoryError";
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
    piConfigDir: string;
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
    typeof p.piConfigDir !== "string" ||
    typeof p.sessionsDir !== "string"
  ) {
    throw new Error(
      "corb run: /etc/corb/image.json's 'paths' is missing one of the required string fields " +
        "'dropcapPath', 'home', 'piConfigDir', 'sessionsDir'",
    );
  }
  return {
    user: obj.user,
    uid: obj.uid,
    gid: obj.gid,
    paths: { dropcapPath: p.dropcapPath, home: p.home, piConfigDir: p.piConfigDir, sessionsDir: p.sessionsDir },
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

function requireApiKey(env: NodeJS.ProcessEnv): string {
  const key = env.ANTHROPIC_API_KEY;
  if (!key) {
    throw new MissingApiKeyError();
  }
  return key;
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
    // Nice-to-have, not a host mount — see the module comment's "sessions
    // mount" note. Points Pi at the sessions directory the image already
    // creates and chowns to `agent` (recorded in /etc/corb/image.json, not
    // hardcoded here), so it has somewhere writable of its own without a
    // second VFS mount in this milestone. Its contents do not survive
    // `vm.close()`.
    PI_CODING_AGENT_SESSION_DIR: identity.paths.sessionsDir,
  };
}

export interface RunSessionOptions {
  /** Host directory to mount at `WORKSPACE_GUEST_PATH` and run Pi against. */
  dir: string;
  /** Args forwarded to `pi` after `dropcap` has dropped privilege. */
  piArgs: string[];
  /** Image selector override. Defaults to `resolveRuntimeImage()`'s own default (`corb:<pkgVersion>`). */
  image?: string;
  /** `VM.create()`'s `sessionLabel`. Defaults to a name derived from the workspace directory. */
  sessionLabel?: string;
  /** Host process environment to read `ANTHROPIC_API_KEY`/`TERM` from. Defaults to `process.env` — injectable for tests. */
  env?: NodeJS.ProcessEnv;
  /** Streams to attach the interactive exec to. Default `process.stdin/stdout/stderr`. */
  stdin?: NodeJS.ReadStream;
  stdout?: NodeJS.WriteStream;
  stderr?: NodeJS.WriteStream;
  /** Passed through to `ShutdownController` — injectable for tests, per `src/vm/shutdown.ts`'s own convention. */
  shutdownProcess?: ProcessLike;
  exit?: ExitFn;
}

/**
 * Boots the guest image, mounts `options.dir` at `WORKSPACE_GUEST_PATH`,
 * and runs Pi's TUI inside it via `dropcap`, following the pattern in
 * `docs/design.md` §5.5. Under normal operation this does not return: the
 * guest's own exit code (or an error) is propagated through
 * `ShutdownController`'s `exit` function, which defaults to the real
 * `process.exit`.
 */
export async function runSession(options: RunSessionOptions): Promise<void> {
  const hostEnv = options.env ?? process.env;
  const apiKey = requireApiKey(hostEnv);
  const hostDir = resolveHostDir(options.dir);

  // Resolution and validation above all happen before any VM is created —
  // "error clearly and immediately... before attempting to boot anything".
  const resolvedImage = resolveRuntimeImage(options.image);

  const { httpHooks, env: secretEnv } = createHttpHooks({
    allowedHosts: [ANTHROPIC_HOST],
    allowedInternalHosts: [],
    secrets: { ANTHROPIC_API_KEY: { hosts: [ANTHROPIC_HOST], value: apiKey } },
  });

  const stdin = options.stdin ?? process.stdin;
  const stdout = options.stdout ?? process.stdout;
  const stderr = options.stderr ?? process.stderr;

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
    ],
    ...(options.shutdownProcess ? { process: options.shutdownProcess } : {}),
    ...(options.exit ? { exit: options.exit } : {}),
  });
  controller.install();

  try {
    vm = await VM.create({
      sandbox: { imagePath: resolvedImage.assetDir },
      dns: { mode: "synthetic", syntheticHostMapping: "per-host" },
      httpHooks,
      env: secretEnv,
      vfs: { mounts: { [WORKSPACE_RAW_GUEST_PATH]: new RealFSProvider(hostDir) } },
      sessionLabel: options.sessionLabel ?? `corb-run:${path.basename(hostDir)}`,
    });

    const identity = await readGuestIdentity(vm);
    const guestEnv = buildGuestEnv(secretEnv, hostEnv, identity);

    const requestPty = canRequestPty(stdin, stdout);
    if (requestPty) {
      ttyHandle = acquire(stdin, stdout);
    }

    const proc = vm.exec(
      [identity.paths.dropcapPath, String(identity.uid), String(identity.gid), PI_PATH, ...options.piArgs],
      {
        cwd: WORKSPACE_GUEST_PATH,
        env: guestEnv,
        stdin: true,
        pty: requestPty,
        stdout: "pipe",
        stderr: "pipe",
      },
    );
    proc.attach(stdin, stdout, stderr);

    const result = await proc;
    await controller.trigger("exit", result.exitCode);
  } catch (err) {
    await controller.trigger("error", 1, err);
    throw err;
  }
}
