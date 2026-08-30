// `src/vm/sockpath.ts` — a small shared primitive for one latent environment
// trap: Gondolin's per-session unix domain socket path can silently exceed
// the kernel's `sockaddr_un.sun_path` limit, which permanently and invisibly
// breaks Corb's whole session-management surface (`corb ls`, `corb kill`, and
// the not-yet-built `corb gc`/`corb attach`) for sessions that are otherwise
// running perfectly.
//
// Extracted here rather than inlined into either consumer for the same reason
// `src/vm/cgroup.ts` exists: two callers need the identical primitive —
// `src/commands/doctor.ts` (a reported health check) and `src/commands/run.ts`
// (a pre-boot warning) — and duplicating the derivation in both is exactly how
// the two would drift.
//
// ## The trap
//
// Gondolin creates one unix socket per session and derives its path from a
// *module-level* constant in `node_modules/@earendil-works/gondolin/dist/src/
// session-registry.js`:
//
//     const CACHE_BASE = process.env.XDG_CACHE_HOME ?? path.join(os.homedir(), ".cache");
//     const SESSIONS_DIR = process.env.GONDOLIN_SESSIONS_DIR ?? path.join(CACHE_BASE, "gondolin", "sessions");
//
// with the socket at `` `${SESSIONS_DIR}/${id}.sock` ``, `id` being the
// 36-character v4 UUID that is also `vm.id`. If that path exceeds the
// `sun_path` budget, the bind fails — and the failure is swallowed whole.
// `SessionIpcServer.start()` in the same file installs `server.on("error",
// () => { /* ignore */ })` before `server.listen(this.sockPath)`, and
// `registerSession()` has *already* written the session's `<id>.json`
// metadata by then. So the observable end state of an overflowing path is:
// metadata file present, `.sock` file never created, no error printed
// anywhere, `VM.create()` resolves successfully, and the session runs
// completely normally.
//
// The consequence is entirely Corb's problem, not the VM's. Gondolin's
// `listSessions()` computes liveness as `isPidAlive(pid) &&
// isSocketAlive(socketPath)`, and `isSocketAlive` short-circuits on
// `fs.existsSync(sockPath)`. A genuinely running, healthy session therefore
// reports `alive: false` forever: `corb ls` shows it as `stale`, and `corb
// kill` correctly-but-uselessly refuses to signal it (its PID-reuse guard
// requires `alive` — see `src/commands/kill.ts`), leaving a live session the
// user cannot manage through Corb at all.
//
// This is SDK behaviour and is deliberately **not** fixed here: no patching,
// no vendoring, no monkey-patching `node_modules`. Corb's job is to detect the
// condition and report it in terms a user can act on.
//
// ## Not Corb's own sessions directory
//
// The directory this module reasons about is **Gondolin's** socket directory
// (`~/.cache/gondolin/sessions`, `GONDOLIN_SESSIONS_DIR`). It is *not*
// `src/config/paths.ts`'s `sessionsStateDir()` (`~/.local/state/corb/
// sessions`, `CORB_STATE_DIR`), which holds Corb's own `<id>.json` sidecars
// (`src/vm/registry.ts`) — plain files, no sockets, no length limit
// whatsoever. The two directories hold same-named `<id>.json` files for the
// same sessions, which makes them very easy to confuse; checking the wrong one
// would make this entire check meaningless.
//
// ## Deliberately no runtime probe
//
// Nothing here binds a socket. The check is a pure length computation:
// deterministic, free, and side-effect-free, which is what lets it sit on the
// `corb run` hot path and inside `corb doctor` alike.
import os from "node:os";
import path from "node:path";

/**
 * The maximum length, in characters, of a bindable unix domain socket path.
 *
 * Capped by `sockaddr_un.sun_path`, which is a fixed 108-byte array on Linux
 * (`man 7 unix`), one byte of which the kernel needs for the NUL terminator on
 * the pathname form — leaving 107 usable *bytes* by a naive reading of the
 * header. The real, measured figure is 108: verified empirically on Linux with
 * a Node `net.createServer().listen(p)` probe over a range of exact path
 * lengths, which binds successfully (and creates the `.sock` file) at 108
 * characters and fails at 109.
 *
 * The failure Node/libuv reports for the overflow is **`EINVAL`**, not the
 * `ENAMETOOLONG` a reader would reasonably expect and grep for
 * (`listen EINVAL: invalid argument /path/...`). Recorded here because that
 * mismatch is precisely why this condition is hard to recognise from a log.
 *
 * Counted in characters rather than bytes, which matches how the two
 * consumers actually reason about a path. The two diverge only for a
 * non-ASCII directory path; erring by treating a multi-byte path as shorter
 * than the kernel sees it can only under-report, never produce a false alarm.
 */
export const MAX_UNIX_SOCKET_PATH_LENGTH = 108;

/** The 36 characters of a v4 UUID (`8-4-4-4-12` hex groups plus four dashes) — Gondolin's session `id`, minted by `randomUUID()` in `VM.create()` and used verbatim as the socket's filename stem. */
const SESSION_ID_LENGTH = 36;

/**
 * What Gondolin appends to its sessions directory for one session's socket:
 * the `path.join` separator, the 36-character session UUID, and the `.sock`
 * extension — i.e. the `` `${SESSIONS_DIR}/${id}.sock` `` template in
 * `session-registry.js`'s `socketPath()`. Derived rather than written as a
 * literal 42 so the arithmetic stays legible if any piece of that template
 * ever changes.
 */
export const SESSION_SOCKET_SUFFIX_LENGTH = "/".length + SESSION_ID_LENGTH + ".sock".length;

/** The longest sessions directory whose session sockets still fit: `108 - 42 = 66`. A directory of exactly this length yields a 108-character socket path (the last one that binds); one character more yields 109 (the first that does not). */
export const MAX_SESSIONS_DIR_LENGTH = MAX_UNIX_SOCKET_PATH_LENGTH - SESSION_SOCKET_SUFFIX_LENGTH;

/**
 * Replicates Gondolin's own `SESSIONS_DIR` derivation:
 * `GONDOLIN_SESSIONS_DIR`, else `${XDG_CACHE_HOME ?? ~/.cache}/gondolin/
 * sessions`.
 *
 * **This is a deliberate duplication of an SDK internal that is not
 * exported.** `SESSIONS_DIR` is a module-level `const` in
 * `node_modules/@earendil-works/gondolin/dist/src/session-registry.js` with no
 * export and no accessor, so there is no way to ask the SDK where it put its
 * sockets — the value has to be re-derived. Checked against the exact pinned
 * version in `package.json`, **`@earendil-works/gondolin` 0.12.0**. If
 * Gondolin changes how it derives that directory, this function must be
 * updated to match or the check silently starts measuring the wrong path;
 * re-read `session-registry.js` on any version bump.
 *
 * Note the derivation is evaluated *at module load* inside the SDK, so
 * mutating `process.env.GONDOLIN_SESSIONS_DIR` after importing Gondolin has no
 * effect there. That is irrelevant to this pure function, but it is why both
 * consumers read the environment as it stands at process start.
 *
 * `env` is injectable and defaults to `process.env`, per this repo's
 * established convention for environment-reading helpers (`src/vm/scope.ts`'s
 * `ReExecOptions.env`, `src/commands/doctor.ts`'s `checkRequiredSecrets(
 * configResult, env)`).
 */
export function gondolinSessionsDir(env: NodeJS.ProcessEnv = process.env): string {
  const override = env.GONDOLIN_SESSIONS_DIR;
  if (override !== undefined) {
    return override;
  }
  const cacheBase = env.XDG_CACHE_HOME ?? path.join(os.homedir(), ".cache");
  return path.join(cacheBase, "gondolin", "sessions");
}

/** Everything a caller needs to render an actionable message about whether a session socket will fit — see `classifySessionSocketPath`. */
export interface SessionSocketPathFit {
  /** The Gondolin sessions directory this was computed for — Gondolin's socket directory, never Corb's own sidecar directory (see the module comment). */
  sessionsDir: string;
  /** Length of the socket path a session in `sessionsDir` would get: `sessionsDir.length + SESSION_SOCKET_SUFFIX_LENGTH`. */
  socketPathLength: number;
  /** The budget `socketPathLength` is measured against — `MAX_UNIX_SOCKET_PATH_LENGTH`, carried in the result so a caller never has to import the constant just to print it. */
  budget: number;
  /** `true` when `socketPathLength <= budget`, i.e. the bind will succeed and the session stays manageable. */
  fits: boolean;
}

/**
 * Pure classification: would a Gondolin session socket created in
 * `sessionsDir` fit inside the `sun_path` budget?
 *
 * Takes the directory as an argument rather than deriving it, so a caller can
 * classify a hypothetical directory (and a test can classify a fabricated one)
 * without touching the environment. Pair it with `gondolinSessionsDir()` for
 * the real one.
 */
export function classifySessionSocketPath(sessionsDir: string): SessionSocketPathFit {
  const socketPathLength = sessionsDir.length + SESSION_SOCKET_SUFFIX_LENGTH;
  return {
    sessionsDir,
    socketPathLength,
    budget: MAX_UNIX_SOCKET_PATH_LENGTH,
    fits: socketPathLength <= MAX_UNIX_SOCKET_PATH_LENGTH,
  };
}

/**
 * The one-line-ish warning both consumers print for an overflowing directory,
 * shared so `corb doctor`'s check detail and `corb run`'s pre-boot stderr
 * warning cannot drift into describing the same condition two different ways.
 * Names the actual directory, states precisely what silently breaks, and gives
 * the actionable remedy.
 */
export function describeSessionSocketOverflow(fit: SessionSocketPathFit): string {
  return (
    `Gondolin's session socket directory is too long: '${fit.sessionsDir}' (${fit.sessionsDir.length} chars) ` +
    `yields a ${fit.socketPathLength}-character socket path, over the ${fit.budget}-character unix-socket limit. ` +
    "Gondolin swallows the resulting bind error, so sessions will still boot and run normally, but their IPC socket " +
    "is never created — 'corb ls' will report a live session as 'stale' and 'corb kill' will refuse to signal it. " +
    `Set GONDOLIN_SESSIONS_DIR to a shorter path (at most ${MAX_SESSIONS_DIR_LENGTH} chars), e.g. ` +
    "GONDOLIN_SESSIONS_DIR=/tmp/gondolin-sessions."
  );
}
