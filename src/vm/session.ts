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
import { MemoryProvider, ReadonlyProvider, RealFSProvider, VM, type VirtualProvider } from "@earendil-works/gondolin";
import { acquire, canRequestPty, type TtyHandle } from "./tty.ts";
import { ShutdownController, type ExitFn, type ProcessLike } from "./shutdown.ts";
import { resolveRuntimeImage } from "./image.ts";
import { buildEgressConfig } from "./egress.ts";
import { buildGitSshOptions } from "./gitssh.ts";
import { POLICY_HOST } from "../policy/sentinel.ts";
// M5.4: the outermost VFS layer for every mount (see the mount-building loop
// inside `runSession`). `GlobRule` (`src/vfs/policy.ts`, M5.2) is the fully-
// required rule shape `withGlobPolicy` (`src/vfs/glob-policy.ts`, M5.3)
// consumes; `toGlobRules` below is this module's own conversion from the
// config system's still-partial `DirRuleConfig` into that shape.
import { withGlobPolicy, type GlobPolicyDenyEvent } from "../vfs/glob-policy.ts";
import type { GlobRule } from "../vfs/policy.ts";
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
import type { DirConfig, DirRuleConfig, EffectiveEgressConfig, EffectiveGitConfig, EffectivePolicyConfig } from "../config/load.ts";
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

/**
 * Guest mount point (and, spelled out via `GATE_CONFIG_MOUNT_ROOT` below, the
 * `CORB_GATE_CONFIG` env var value) for `policygate`'s (`guest/internal/gate/
 * policy.go`) per-tool shim config, generated fresh every `runSession` call
 * (see `GATE_CONFIG` and the `vfsMounts` construction below) — a *runtime*
 * artifact, unlike `/etc/corb/image.json`, which is baked into the rootfs at
 * image-build time.
 *
 * Deliberately **not** `/etc/corb` (the plan's own early sketch): `/etc/corb`
 * already holds `image.json`, baked into `rootfs.ext4` by `image/corb-image.json`'s
 * `postBuild.copy`. Gondolin's `vfs.mounts` are directory-level FUSE mounts
 * that fully shadow whatever the underlying rootfs had at that guest path
 * (the same mechanism `docs/gondolin-notes.md` R5/R12/R18 document for
 * `/work`), so mounting anything at `/etc/corb` would make `image.json`
 * invisible to `readGuestIdentity()`'s post-boot `cat` — and the host has no
 * way to re-synthesize an identical `image.json` ahead of `VM.create()`
 * (that's the whole reason `readGuestIdentity()` reads it post-boot in the
 * first place). `/run` already hosts Gondolin's own runtime-injected
 * `/run/gondolin/ca-certificates.crt` (a different mechanism, not a
 * `vfs.mounts` entry Corb controls, but establishing `/run` as the right
 * *kind* of location for runtime-generated state); nothing in
 * `corb-image.json`'s `postBuild` touches `/run`, so this mounts a path that
 * doesn't pre-exist in the rootfs at all — the same situation
 * `WORKSPACE_RAW_ROOT` is already in, which is already proven to work.
 */
const GATE_CONFIG_MOUNT_ROOT = "/run/corb";

/** Guest-visible path to the generated `gate.json` — see `GATE_CONFIG_MOUNT_ROOT`. Matches `CORB_GATE_CONFIG` in `buildGuestEnv()`. */
const GATE_CONFIG_GUEST_PATH = `${GATE_CONFIG_MOUNT_ROOT}/gate.json`;

/**
 * Fixed, host-authored `policygate` shim config (`guest/internal/gate/policy.go`'s
 * `Config`/`ToolPolicy`), not derived from any workspace config — there is no
 * config-schema surface for per-tool blocked-subcommand/flag lists.
 * `blockedSubcommands`/`blockedFlags` values match `docs/design.md` §4's
 * table; `real` paths match `image/corb-image.json`'s `postBuild.commands`
 * shim installation exactly (`git`/`gh` moved to `git-real`/`gh-real` under
 * `/usr/local/libexec`) — keeping image wiring and this content consistent
 * with each other is entirely this module's own responsibility, nothing
 * upstream enforces it.
 */
const GATE_CONFIG = {
  tools: {
    git: {
      real: "/usr/local/libexec/git-real",
      blockedSubcommands: ["config", "credential", "filter-branch", "init"],
      blockedFlags: ["-c", "--config-env", "--exec-path", "--upload-pack", "--receive-pack", "--no-gpg-sign"],
    },
    gh: {
      real: "/usr/local/libexec/gh-real",
      blockedSubcommands: ["auth", "secret", "ssh-key", "gpg-key", "config"],
      blockedFlags: ["--with-token"],
    },
  },
};

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

/**
 * Thrown before any VM is created when a workspace directory's `rules[]`
 * entry (`src/config/load.ts`'s `DirRuleConfig`, itself `src/config/
 * schema.ts`'s `PartialDirRuleConfig` — `glob`/`mode`/`reason` all optional
 * at that parse/merge layer) is missing `glob` or `mode`. This is the first
 * place in the codebase that ever converts a parsed rule into `src/vfs/
 * policy.ts`'s fully-required `GlobRule` shape (see `toGlobRules` below),
 * and nothing before this item validated that the conversion is actually
 * possible — a rule table entry that names neither a pattern nor a mode is
 * meaningless (there is nothing to match, or nothing to do once matched), so
 * this fails the same way `WorkspaceDirectoryError`/`InvalidWorkspaceNameError`
 * already do for their own "config entry is missing a field it needs" cases:
 * a dedicated `Error` subclass, thrown eagerly, before any VM is created.
 * `reason` is deliberately not one of these hard-error cases — see
 * `toGlobRules`'s own doc comment for why a missing `reason` gets a fallback
 * string instead.
 */
export class InvalidDirRuleError extends Error {
  constructor(dirName: string, index: number, missingField: "glob" | "mode") {
    super(
      `corb run: workspace directory '${dirName}' rules[${index}] is missing required field '${missingField}' ` +
        "(both 'glob' and 'mode' must be set for a rule to have any effect)",
    );
    this.name = "InvalidDirRuleError";
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

/**
 * Placeholder `reason` substituted for a `rules[]` entry that omits it.
 * Unlike `glob`/`mode` (see `InvalidDirRuleError`), an absent `reason` does
 * not make a rule meaningless — it still has a pattern to match and a mode
 * to apply — so this is a defensible default rather than a third hard-error
 * case. Deliberately worded so it reads as obviously synthetic wherever it
 * surfaces (a denial error message, an audit log `reason` field): an
 * operator who left `reason` unset should see that plainly, not a blank
 * string or a value that looks like it was actually configured.
 */
const DEFAULT_RULE_REASON = "no reason configured for this rule";

/**
 * Converts one workspace directory's parsed `rules[]`
 * (`src/config/load.ts`'s `DirConfig.rules`, always an array — possibly
 * empty, never `undefined`, per that module's own comment — of still-partial
 * `DirRuleConfig` entries) into `src/vfs/policy.ts`'s fully-required
 * `GlobRule[]`, throwing `InvalidDirRuleError` for any entry missing `glob`
 * or `mode`. See `InvalidDirRuleError`'s own doc comment for why those two
 * fields are hard errors and `DEFAULT_RULE_REASON`'s for why a missing
 * `reason` is not.
 *
 * Exported (unlike this module's other internal `resolveWorkspaceDirs`
 * helpers) so `src/commands/run.ts`'s `toWorkspaceDirSpec` can call it
 * eagerly too, purely for its validating side effect (discarding the
 * result), so a malformed `rules[]` entry fails before `runSession` is ever
 * invoked — see that call site's own comment. `resolveWorkspaceDirs` below
 * still performs the authoritative, non-discarded conversion again on every
 * `runSession` call, for any caller that reaches this module directly
 * without going through `run.ts` first.
 */
export function toGlobRules(dirName: string, rules: readonly DirRuleConfig[]): GlobRule[] {
  return rules.map((rule, index): GlobRule => {
    if (rule.glob === undefined) {
      throw new InvalidDirRuleError(dirName, index, "glob");
    }
    if (rule.mode === undefined) {
      throw new InvalidDirRuleError(dirName, index, "mode");
    }
    return { glob: rule.glob, mode: rule.mode, reason: rule.reason ?? DEFAULT_RULE_REASON };
  });
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
    // M7.3: `policygate`'s two env vars (`guest/internal/gate/policy.go`
    // never hardcodes either, by design, exactly so this decision could be
    // made independently here). Plain HTTP, not HTTPS — docs/design.md §5:
    // "plain HTTP (no CA handling needed)". Built from `POLICY_HOST`
    // (`src/policy/sentinel.ts`) rather than re-spelling the hostname a
    // third time, matching that module's own stated reasoning for exporting
    // the constant in the first place.
    CORB_POLICY_URL: `http://${POLICY_HOST}/check`,
    CORB_GATE_CONFIG: GATE_CONFIG_GUEST_PATH,
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
  /**
   * This directory's configured `[[dir]].rules[]`, straight from
   * `src/config/load.ts`'s `DirConfig.rules` (still partial — `glob`/`mode`/
   * `reason` all optional at that layer). `resolveWorkspaceDirs` converts
   * this into `src/vfs/policy.ts`'s fully-required `GlobRule[]` via
   * `toGlobRules`, throwing `InvalidDirRuleError` for any entry missing
   * `glob` or `mode`. Reusing `DirRuleConfig` here (rather than this
   * module inventing a fourth, parallel copy of the same three optional
   * fields) matches this module's own `mode`/`hostPath` precedent of taking
   * an already-shaped-elsewhere input and validating it itself, not
   * re-deriving its shape from scratch — see the module comment's
   * `dirs`/`primary` discussion. Defaults to `[]` (no rules configured) when
   * omitted.
   */
  rules?: DirRuleConfig[];
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
   * A session's full effective policy config (`EffectiveConfig.policy`,
   * always present — see `src/config/load.ts`), passed straight through to
   * `buildEgressConfig()`, which threads it into `sentinel()`
   * (`src/policy/sentinel.ts`, M7.2/M7.3). See the module-level import
   * comment for why this module imports this config type directly rather
   * than defining its own decoupled shape, unlike `dirs`/`primary` above —
   * mirrors `egress`/`git`'s own "always present, passed straight through"
   * precedent (`runSession` has exactly one real caller, `src/commands/run.ts`,
   * which already has `resolved.fullConfig.policy` on hand).
   */
  policy: EffectivePolicyConfig;
  /**
   * The real, already-merged `EffectiveConfig.dir` (`src/config/load.ts`'s
   * `DirConfig[]`) — **not** the same thing as `dirs: WorkspaceDirSpec[]`
   * above. `dirs` is this module's own deliberately decoupled shape for its
   * *own* mounting logic (name safety, mount roots, `GlobRule[]`-shaped
   * rules); `dirConfigs` is the un-decoupled config-system type that
   * `sentinel()`'s content-check (`checkDuplicatedPathRules`, `src/policy/
   * checks.ts`) needs instead, since it wants the raw `DirRuleConfig[]` with
   * its optional fields, not `dirs`'s fully-validated `GlobRule[]`. Passed
   * straight through to `buildEgressConfig()`, exactly mirroring the
   * `egress`/`git`/`policy` "passed straight through, imported directly from
   * config/load.ts" precedent. Do not confuse the two `dirs`-shaped fields on
   * this interface — this one is never used for mounting.
   */
  dirConfigs: DirConfig[];
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
  /** Fully validated, `GlobRule`-shaped form of `WorkspaceDirSpec.rules` — see `toGlobRules`. */
  rules: GlobRule[];
}

/**
 * Validates and resolves every `dirs` entry: name safety, no duplicate
 * names, `create`-if-missing, existence/directory-ness, then rule-table
 * validation — in that order, so a bad name is caught before any path
 * arithmetic or filesystem mutation, `create` runs before the existence
 * check it would otherwise fail, and an invalid `rules[]` entry
 * (`InvalidDirRuleError`, via `toGlobRules`) is still caught before any VM
 * is created even though it has no bearing on the host-path checks above it.
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
    const rules = toGlobRules(dir.name, dir.rules ?? []);
    return { name: dir.name, hostPath, mode: dir.mode, rules };
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

  // The `vfs` channel (`docs/design.md` §6/§8) has had no producer until this
  // item, same gap `ssh`/`http`/`session` each had before their own wiring
  // items (M4.3/M3.2-3/this function's own "start"/"exit"/"error" events
  // above). `event.path` is already mount-relative (`src/vfs/glob-policy.ts`'s
  // own doc comment on `GlobPolicyDenyEvent.path` — never a raw host path or
  // guest absolute path), so it is safe to fold directly into `subject`
  // alongside `event.op`, matching `buildGitSshOptions`'s own
  // `` `${info.service} ${repo}` `` precedent for building a safe subject
  // from two already-safe pieces. A `"shadowed"` outcome is still recorded as
  // `decision: "deny"` (`AuditEvent.decision` is a fixed `"allow" | "deny"`
  // union — adding a third value for one caller is out of scope for this
  // item) because it is still a policy intervention, not a plain pass-through;
  // `reason` is prefixed to tell a human reading the log that this call was
  // silently redirected rather than refused outright.
  const onVfsDeny = (event: GlobPolicyDenyEvent): void => {
    const subject = event.path === "" ? event.op : `${event.op} ${event.path}`;
    const reason =
      event.outcome.kind === "shadowed"
        ? `shadowed (redirected to ephemeral storage): ${event.reason}`
        : event.reason;
    options.audit.record({ channel: "vfs", decision: "deny", subject, reason, sessionId });
  };

  const vfsMounts: Record<string, VirtualProvider> = {};
  for (const dir of resolvedDirs) {
    const base = new RealFSProvider(dir.hostPath);
    // `withGlobPolicy` is layered *outermost* regardless of `ro`/`rw`
    // (`docs/design.md` §3, the top-level plan's §5.3 sketch): a `hidden`
    // rule must yield `ENOENT` on a `ro` mount exactly as it would on `rw`,
    // which only holds if the glob policy wrapper sees every call first.
    // `ReadonlyProvider`'s own write-rejection for `ro` dirs still applies
    // underneath, independently of anything the rule table says — a `ro` dir
    // with a `shadow-write` rule still shadows (the glob policy layer
    // intercepts before the call ever reaches `ReadonlyProvider`), matching
    // that plan sketch's own wording exactly.
    const roOrRw: VirtualProvider = dir.mode === "ro" ? new ReadonlyProvider(base) : base;
    vfsMounts[rawWorkspacePath(dir.name)] = withGlobPolicy(roOrRw, { rules: dir.rules, onDeny: onVfsDeny });
  }

  // `gate.json` — see `GATE_CONFIG_MOUNT_ROOT`'s doc comment for why this
  // lands at `/run/corb` rather than `/etc/corb`. Populated synchronously
  // before `VM.create()`, then `setReadOnly()`'d: this is fixed, host-authored
  // config the guest's `policygate` only ever reads, never writes.
  // `ReadonlyProvider`-wrapped too, matching this function's own convention
  // just above for every other read-only guest-visible mount.
  const gateConfigStore = new MemoryProvider();
  // `writeFileSync` is typed optional on the shared `VirtualProvider`
  // interface (some providers, e.g. `ReadonlyProvider`, don't implement it),
  // but `MemoryProvider`'s own base class always provides it — confirmed by
  // reading `.../vendored-node-vfs/lib/internal/vfs/provider.js`, which
  // implements it generically via `open`/`write`. Non-null assertion, not a
  // narrower cast: this is a real, always-present method on this concrete
  // type, not an `unknown`-shaped escape hatch.
  gateConfigStore.writeFileSync!("/gate.json", JSON.stringify(GATE_CONFIG));
  gateConfigStore.setReadOnly();
  vfsMounts[GATE_CONFIG_MOUNT_ROOT] = new ReadonlyProvider(gateConfigStore);

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

    const egressConfig = buildEgressConfig(
      options.egress,
      options.secrets,
      hostEnv,
      options.audit,
      sessionId,
      options.policy,
      options.dirConfigs,
    );
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
