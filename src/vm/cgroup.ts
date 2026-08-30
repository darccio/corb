// `src/vm/cgroup.ts` — M8.3: the one place that reads a uid's delegated
// systemd user-manager cgroup controllers off disk.
//
// `corb doctor`'s `checkCgroupControllers` (`src/commands/doctor.ts`, M3.5)
// already reads `/sys/fs/cgroup/user.slice/user-<uid>.slice/user@<uid>.service/
// cgroup.controllers` for a general, forward-looking health check: it
// classifies against a fixed `REQUIRED_CGROUP_CONTROLLERS` list
// (`memory`/`pids`/`cpu`) unconditionally, regardless of what any particular
// `corb run` actually configures. That is the right policy for `doctor` and
// is untouched here — `classifyCgroupControllers`, `REQUIRED_CGROUP_
// CONTROLLERS`, and the blanket check-all-three behavior all stay exactly
// where they are, in `doctor.ts`.
//
// M8.3's `src/vm/scope.ts` needs the same raw read, but for a narrower,
// per-run question: "for the specific `vm.limits` keys *this run* actually
// configured, are their controllers delegated?" Rather than duplicate the
// `fs.readFileSync(...)` + ENOENT-as-"nothing delegated" logic in both
// places, it lives here once; `doctor.ts` and `scope.ts` both import it.
import fs from "node:fs";

function isEnoent(err: unknown): boolean {
  return err instanceof Error && "code" in err && (err as NodeJS.ErrnoException).code === "ENOENT";
}

/** Path to the delegated-controllers file for `uid`'s systemd user manager. */
export function cgroupControllersPath(uid: number): string {
  return `/sys/fs/cgroup/user.slice/user-${uid}.slice/user@${uid}.service/cgroup.controllers`;
}

/**
 * Raw contents of `uid`'s `cgroup.controllers` file, or `undefined` if it
 * doesn't exist (ENOENT) — no systemd user manager, a uid whose
 * `user@<uid>.service` hasn't started, or (relevant to M8.3, not just
 * `doctor`) a non-Linux platform where `/sys/fs/cgroup` doesn't exist at
 * all. Any other read error (e.g. permission denied) propagates rather than
 * being swallowed — that is a real, surprising failure, not the routine
 * "nothing delegated" case.
 */
export function readCgroupControllersText(uid: number): string | undefined {
  try {
    return fs.readFileSync(cgroupControllersPath(uid), "utf8");
  } catch (err) {
    if (isEnoent(err)) {
      return undefined;
    }
    throw err;
  }
}

/** Parses `cgroup.controllers`' whitespace-separated contents into a set. `undefined` (missing file, see `readCgroupControllersText`) parses to an empty set — "nothing delegated", not an error. */
export function parseCgroupControllers(text: string | undefined): Set<string> {
  if (text === undefined) {
    return new Set();
  }
  return new Set(text.split(/\s+/).filter((s) => s.length > 0));
}

/** `uid`'s delegated cgroup controllers as a set (e.g. `{"pids"}`). Combines `readCgroupControllersText` + `parseCgroupControllers` — the "read the controllers set for a uid" primitive `src/vm/scope.ts` needs. */
export function readDelegatedControllers(uid: number): Set<string> {
  return parseCgroupControllers(readCgroupControllersText(uid));
}

/**
 * Same as `readDelegatedControllers`, but resolves the current process's own
 * uid via `process.getuid?.()` — the convenience shape `src/vm/scope.ts`'s
 * real (non-test) call sites use. `process.getuid` is undefined on
 * platforms with no POSIX uid concept (not a concern for Corb's actual
 * Linux/macOS support matrix, but still defensive here); that case is
 * treated the same as "nothing delegated", the same fallback-safe posture
 * `readDelegatedControllers` already takes for a missing controllers file.
 */
export function readDelegatedControllersForCurrentUser(): Set<string> {
  const uid = process.getuid?.();
  if (uid === undefined) {
    return new Set();
  }
  return readDelegatedControllers(uid);
}
