// `src/config/guestpaths.ts` — M2.2: validates that the guest mount targets
// derived from a merged `dir` list (`/work/<name>`, per `docs/design.md` §3)
// are safe to actually mount. Pure and side-effect-free other than throwing;
// does not know about `ConfigLayer`, layering, or merge order — that is
// `load.ts`, which calls this once, as the last step of
// `mergeConfigLayers`, on the fully-merged `dir` list.
import path from "node:path";

/** Root all workspace directories mount under in the guest. */
const WORK_ROOT = "/work";

/**
 * Guest paths that must never be a mount target: `/` (hides the distro CA
 * bundle), `/etc/gondolin` (breaks CA injection and `enableIngress()`), and
 * the other top-level system dirs a workspace mount could otherwise shadow.
 * Matches the plan's own §3 list exactly.
 */
const RESERVED_GUEST_PATHS: readonly string[] = [
  "/",
  "/etc",
  "/etc/gondolin",
  "/run",
  "/proc",
  "/sys",
  "/dev",
  "/usr",
  "/bin",
  "/lib",
];

/**
 * Thrown for any unsafe guest mount target: a reserved system path, or two
 * dirs whose targets collide (equal, or one a path-component prefix of the
 * other).
 */
export class GuestPathError extends Error {
  constructor(message: string) {
    super(`corb config: ${message}`);
    this.name = "GuestPathError";
  }
}

interface MountableDir {
  name: string;
}

// Primary defense: `name` must be a single, literal path segment — no
// separator, no `.`/`..`. Checked before any path arithmetic, so a
// traversal-shaped name never reaches `path.posix.normalize` below. This is
// what actually keeps a mount target inside `/work/`; see `assertNotReserved`
// for why the second check downstream is a redundant backstop, not an
// independent line of defense, given this one.
function assertPlainSegment(name: string): void {
  if (name.length === 0) {
    throw new GuestPathError("a directory name must not be empty");
  }
  if (name === "." || name === "..") {
    throw new GuestPathError(`directory name '${name}' is not a valid mount name`);
  }
  if (name.includes("/") || name.includes("\\")) {
    throw new GuestPathError(`directory name '${name}' must not contain a path separator`);
  }
}

// Second, independent-in-spirit check, matching design.md §1's "check the
// resolved path, not just what was typed" discipline applied one level up
// (§3's own realpath discussion). Honestly: given `assertPlainSegment`
// above, this can never actually fire. Every reserved path is either one
// segment (`/etc`, `/run`, ...) or, for `/etc/gondolin`, two segments whose
// first component is `etc`, not `work`; `assertPlainSegment` guarantees any
// `name` that reaches here has no `.`/`..` component for `normalize` to
// collapse, so the result is always literally `/work/<name>` — which cannot
// equal any entry in `RESERVED_GUEST_PATHS`. Kept anyway because it is cheap,
// it is what the project's stated discipline calls for, and it stops being
// vacuous the moment `assertPlainSegment` is ever loosened or `WORK_ROOT`
// changes without this file being revisited.
function assertNotReserved(name: string, target: string): void {
  if (RESERVED_GUEST_PATHS.includes(target)) {
    throw new GuestPathError(`directory '${name}' would mount at reserved guest path '${target}'`);
  }
}

function guestMountTarget(name: string): string {
  assertPlainSegment(name);
  const target = path.posix.normalize(`${WORK_ROOT}/${name}`);
  assertNotReserved(name, target);
  return target;
}

function pathSegments(target: string): string[] {
  return target.split("/").filter((segment) => segment.length > 0);
}

function isProperPrefix(shorter: string[], longer: string[]): boolean {
  return shorter.length < longer.length && shorter.every((segment, i) => segment === longer[i]);
}

/**
 * Validates every dir's guest mount target (`/work/<name>`): rejects a
 * reserved system path, and rejects any pair of dirs whose targets collide
 * — equal, or one a path-component prefix of the other (`/work/foo` vs
 * `/work/foo/bar`, not `/work/foo` vs `/work/foobar`). Throws
 * `GuestPathError` on the first violation; otherwise returns nothing.
 *
 * A duplicate `name` is structurally impossible reaching here from
 * `load.ts`'s name-keyed dir merge, but this function does not assume that:
 * two dirs sharing a `name` produce equal targets, which the equal-target
 * check below catches directly, so no separate duplicate-name check is
 * needed.
 *
 * Given the `/work/<name>` scheme, every target is exactly two path
 * components (`work`, `<name>`), and `name` is restricted (see
 * `assertPlainSegment`) to a single component. Two distinct names can
 * therefore never produce a genuine *proper*-prefix collision — only the
 * equal case is reachable in practice. The prefix check is kept regardless:
 * it is cheap, it matches the general property `docs/design.md` describes,
 * and it stays correct if a later milestone ever mounts something nested
 * under `/work/<name>` itself.
 */
export function validateMountTargets(dirs: MountableDir[]): void {
  const resolved = dirs.map((dir) => ({ name: dir.name, target: guestMountTarget(dir.name) }));

  for (let i = 0; i < resolved.length; i++) {
    for (let j = i + 1; j < resolved.length; j++) {
      const a = resolved[i]!;
      const b = resolved[j]!;
      const segA = pathSegments(a.target);
      const segB = pathSegments(b.target);
      const collides = a.target === b.target || isProperPrefix(segA, segB) || isProperPrefix(segB, segA);
      if (collides) {
        throw new GuestPathError(
          `directories '${a.name}' and '${b.name}' have colliding guest mount targets ('${a.target}' and '${b.target}')`,
        );
      }
    }
  }
}
