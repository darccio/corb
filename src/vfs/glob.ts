// `src/vfs/glob.ts` — M5.1 builds the general-purpose glob engine
// `docs/design.md` §3's `GlobRule.glob` field and the top-level plan's
// §6.2 both need and neither the SDK nor this codebase had yet:
// `createShadowPathPredicate` (`@earendil-works/gondolin`) supports only
// exact-path and prefix matching (`docs/gondolin-notes.md` §7, "Sharp
// edges"), and the two glob matchers that already exist in this codebase —
// `src/vm/gitssh.ts`'s private `globToRegExp` (single-segment `*` only, no
// `**`, scoped to `git.allow-repos` repo-name matching) and
// `src/policy/github.ts`'s private `pathGlobToRegExp` (cross-segment `**`
// only, no single-segment `*`, scoped to `deny-paths` matching) — are each
// deliberately narrow to their own call site, per their own module
// comments. Neither is imported or extended here, and this module does not
// touch either file: this is the third, general-purpose matcher the plan
// names as `src/vfs/glob.ts`, for `GlobRule.glob` patterns that need both
// wildcard shapes at once (`**/*_test.go` needs cross-segment `**` *and*
// single-segment `*` in the same pattern; neither existing matcher can
// express that).
//
// This module is used only by *future* VFS policy code
// (`src/vfs/policy.ts`, M5.2, and `src/vfs/glob-policy.ts`'s
// `withGlobPolicy`, M5.3 — neither exists yet, confirmed by `find src/vfs`
// coming up empty before this item). It exports two independent pieces:
//
//   - `globToRegExp` — converts one `GlobRule.glob` pattern into an anchored
//     `RegExp`.
//   - `normalizeGuestPath` — canonicalizes a raw VFS-provider-received path
//     into the form a future caller should run both rule-matching *and*
//     `globToRegExp`'s regexes against.
//
// Neither function talks to the SDK or to a real filesystem — this file has
// zero runtime dependency on `@earendil-works/gondolin`, matching the plan's
// own §1 requirement that `src/vfs/glob.ts` and `src/vfs/policy.ts` "import
// nothing from Gondolin" so the whole policy semantics table stays
// unit-testable with zero VM boot.

// ---------------------------------------------------------------------------
// globToRegExp
// ---------------------------------------------------------------------------

/**
 * Escapes one literal path segment's regex-special characters and turns any
 * `*` in it into `[^/]*` (matches any run of characters *within* this
 * segment, never a `/`). Every other character — including the other
 * regex metacharacters `. + ? ( ) | [ ] ^ $ { } \` — is escaped so it is
 * matched literally: `go.sum` must match the literal path `go.sum` and must
 * not match `goXsum`.
 *
 * Not exported: a bare per-segment converter is not useful on its own
 * (`globToRegExp` is the unit callers need — a whole pattern, not one
 * segment of it), and exporting it would invite a caller to reimplement
 * `**` handling around it.
 */
function segmentToRegexSource(segment: string): string {
  return segment.replace(/[.*+?^${}()|[\]\\]/g, (matched) => (matched === "*" ? "[^/]*" : `\\${matched}`));
}

/**
 * Converts one `GlobRule.glob` pattern (`docs/design.md` §3) into an
 * anchored `RegExp` that performs a *whole-string* match (`^...$`) against a
 * candidate path.
 *
 * Wildcard semantics — deliberately minimal, covering exactly what every
 * real pattern in `docs/design.md` §3 and the top-level plan's `corb.toml`
 * spec uses (a leading `**` before `/*_test.go`, before `/.env`, before
 * `/.env.*`, and before `/secrets` followed by a trailing `**`; plus the
 * `**`-free `go.sum`, `.git/hooks` followed by a trailing `**`, and
 * `.git/config`) and nothing more:
 *
 *   - `**` stands for zero or more *entire* path segments. It must appear as
 *     its own `/`-delimited segment (a leading `**`, a trailing `**`, or a
 *     `**` in the middle between two literal segments) — this module does
 *     not support gluing `**` to literal characters within the same segment
 *     (e.g. `key**`), unlike `src/policy/github.ts`'s narrower
 *     `pathGlobToRegExp`, because no real pattern anywhere in this
 *     codebase's docs needs that shape for the general VFS-policy alphabet.
 *     A leading `**` segment matches zero segments too — a pattern like a
 *     leading `**` before `.env` matches the bare path `.env`, not only
 *     `foo/.env` — which is why "zero or more", not "one or more".
 *   - `*` matches within a single path segment only; it never matches `/`.
 *   - Every other character is a literal, including the other regex
 *     metacharacters (escaped — see `segmentToRegexSource`).
 *   - No `?` and no character classes (`[...]`): nothing in
 *     `docs/design.md`'s or the plan's example rules needs either, and
 *     adding them would be scope creep for the syntax `corb.toml` actually
 *     exposes.
 *
 * A pattern with no leading `/` (every real example) is matched against a
 * candidate with no leading `/` — i.e. this function has no opinion on
 * mount roots or path aliasing; it just matches strings. A pattern with no
 * `**` in it at all is implicitly anchored to the *whole* candidate path,
 * not just its final segment: `go.sum` matches only the path `go.sum`, not
 * `vendor/go.sum` — a rule author who wants "anywhere in the tree" writes a
 * leading `**` before `go.sum` explicitly, the same way a leading `**`
 * before `.env` is spelled out explicitly in `docs/design.md`'s own example
 * rule list rather than relying on an implicit leading `**` segment. Turning
 * a future caller's per-mount relative path into the string this regex is
 * tested against (and deciding whether that string carries a leading `/`)
 * is `src/vfs/policy.ts`'s job (M5.2), not this function's.
 *
 * Construction: the pattern is split on `/` into segments. Each `**`
 * segment becomes one of four fragments depending on whether it has a
 * literal neighbor on each side (not on its position in the *whole*
 * pattern, so this generalizes correctly even to patterns with more than
 * two `**` tokens, though none of the real examples need more than two):
 *
 *   - no neighbors at all (the whole pattern is just `**`) → `.*`
 *   - a right neighbor only (leading `**`) → `(?:[^/]+/)*`, placed with no
 *     separator before the following literal — each iteration already ends
 *     in `/`, and zero iterations leaves nothing, so a leading `**` before
 *     `.env` becomes `^(?:[^/]+/)*\.env$` and matches `.env`, `a/.env`, and
 *     `a/b/.env` alike.
 *   - a left neighbor only (trailing `**`) → `(?:/[^/]+)*`, placed with no
 *     separator after the preceding literal, symmetric to the above.
 *   - both neighbors (a `**` segment sandwiched between two literals) →
 *     `/(?:[^/]+/)*`, which owns the separating `/` itself so that zero
 *     matched segments still produces exactly one `/` between the two
 *     literals (a middle `**` in a pattern like `a`, `**`, `b` joined by
 *     slashes matches the path `a/b`) while one or more matched segments
 *     produces the expected `a/x/b`, `a/x/y/b`, etc. This shape (rather than
 *     naively concatenating a plain `(?:[^/]+/)*` between two literals with
 *     no anchoring slash) matters: without the leading `/` baked into the
 *     fragment, that same middle-`**` pattern would wrongly match a path
 *     like `a/xb`, because nothing would force the final literal `b` to
 *     start at a segment boundary.
 *
 * A literal segment gets a plain `/` separator before it, but only when the
 * *previous* segment exists and was not itself a `**` — a `**` fragment
 * always supplies whatever separating `/` its neighbors need internally
 * (see above), so adding a second one would double it up.
 */
export function globToRegExp(pattern: string): RegExp {
  const segments = pattern.split("/");
  let source = "";
  for (let i = 0; i < segments.length; i++) {
    const segment = segments[i] as string;
    const hasLeft = i > 0;
    const hasRight = i < segments.length - 1;
    if (segment === "**") {
      if (!hasLeft && !hasRight) {
        source += ".*";
      } else if (!hasLeft) {
        source += "(?:[^/]+/)*";
      } else if (!hasRight) {
        source += "(?:/[^/]+)*";
      } else {
        source += "/(?:[^/]+/)*";
      }
      continue;
    }
    const previous = hasLeft ? (segments[i - 1] as string) : undefined;
    if (hasLeft && previous !== "**") {
      source += "/";
    }
    source += segmentToRegexSource(segment);
  }
  return new RegExp(`^${source}$`);
}

// ---------------------------------------------------------------------------
// normalizeGuestPath
// ---------------------------------------------------------------------------

/**
 * The SDK's own `fuseMount` default (`docs/gondolin-notes.md` §7:
 * `fuseMount: "/data", // default`). Hardcoded here rather than sourced from
 * `src/config/`, because nothing in this codebase currently exposes
 * `vfs.fuseMount` as a configurable value — `VM.create()` is always called
 * with the SDK's own default. If a future item ever makes `fuseMount`
 * configurable (passed through to `VM.create({ vfs: { fuseMount } })`),
 * `normalizeGuestPath`'s call sites must start passing that configured
 * value in explicitly instead of relying on this constant, and this
 * constant should stop being treated as anything other than "the SDK's
 * factory default" — it must track `VM.create()`'s own default, not the
 * other way around.
 */
export const DEFAULT_FUSE_MOUNT = "/data";

/**
 * Thrown by `normalizeGuestPath` when the raw path contains a `..` path
 * segment. See `normalizeGuestPath`'s own doc comment for why this fails
 * closed instead of resolving `..` away.
 */
export class GuestPathTraversalError extends Error {
  constructor(rawPath: string) {
    super(`corb vfs: path '${rawPath}' contains a '..' segment, which is never valid in a guest-supplied VFS path.`);
    this.name = "GuestPathTraversalError";
  }
}

/**
 * Canonicalizes a raw path as received by a `VirtualProvider` method (or
 * built by one, e.g. `readdir`'s per-entry join) into the form a future
 * caller (`withGlobPolicy`, M5.3) should run both rule-matching and
 * `globToRegExp`'s regexes against. Three things, in order:
 *
 *   1. **Strip the `fuseMount` alias prefix.** `docs/design.md` §3's "Path
 *      aliasing" subsection: every VFS path is also reachable under the
 *      SDK's `fuseMount` (default `/data`), so `/work/repo/.env` is also
 *      `/data/work/repo/.env` — "path normalisation must strip the alias
 *      prefix before rule matching, or every rule has a trivial second
 *      spelling that misses." The canonical (post-strip) form this function
 *      produces is the `/work/...`-style spelling, i.e. `/data` itself
 *      normalizes to the bare mount root `/`. The prefix is matched at a
 *      `/`-boundary (`fuseMount` itself, or `fuseMount` followed by `/`) so
 *      that an unrelated path which merely starts with the same characters
 *      (e.g. `/database/foo` against a `/data` `fuseMount`) is left alone.
 *   2. **Collapse redundant `/` separators.** The top-level plan's §6.2
 *      calls this out directly: `readdir` joins with the raw template
 *      `` `${path}/${name}` ``, which produces a `//` whenever `path` is the
 *      root path `/` itself. Any run of two or more consecutive `/`
 *      characters collapses to one.
 *   3. **Fail closed on `..`.** Every guest-supplied path that reaches host
 *      code must be "normalised first and then re-checked for containment
 *      in its mount root" (`docs/design.md` §1); a naive
 *      normalize-by-resolving-`..` step is exactly the kind of thing that
 *      principle warns about; `path.posix.normalize` — which is *all* the
 *      SDK's own exported `normalizeVfsPath` does, see below — resolves
 *      `..` lexically and would turn
 *      `/work/repo/../../../../etc` into `/etc` without ever raising a
 *      flag, silently producing a well-formed-looking path that has escaped
 *      the mount root entirely. This function instead rejects any path
 *      containing a `..` segment outright, mirroring `src/vm/gitssh.ts`'s
 *      `normalizeRepo` — its `RepoTraversalError` doc comment lays out the
 *      same reasoning for the same class of problem: failing closed before
 *      any comparison happens is simpler to reason about and audit than
 *      normalizing `..` away and trusting every future caller to treat
 *      "still contains .." as "obviously never matches anything" — where
 *      this function *deliberately diverges from `normalizeRepo`'s exact
 *      test* is that `normalizeRepo` uses a blunt `repo.includes("..")`
 *      substring check, which is precise enough for `owner/repo`-shaped
 *      strings (a real repo path never legitimately contains a literal
 *      `..` substring). A general filesystem path is a different input
 *      domain: a filename can legitimately contain `..` as a substring
 *      without it being a traversal segment at all (an unusual but valid
 *      name like `..bashrc.bak` contains `..` as its first two characters,
 *      yet is a single ordinary segment, not a parent-directory reference).
 *      So this function checks with segment-level precision — splitting on
 *      `/` and testing whether any segment is *exactly* `..` — which still
 *      rejects every real traversal shape (including `/a/../../etc`) while
 *      not rejecting a same-substring-but-different-shape legitimate
 *      filename that `normalizeRepo`'s cruder check would not have had to
 *      worry about in its own, narrower domain.
 *
 * **What the SDK's own `normalizeVfsPath` does, verified by reading
 * `node_modules/@earendil-works/gondolin/dist/src/vfs/utils.js` (not just
 * the `.d.ts`) — its entire body is:**
 *
 * ```js
 * export function normalizeVfsPath(inputPath) {
 *     let normalized = path.posix.normalize(inputPath);
 *     if (!normalized.startsWith("/")) {
 *         normalized = `/${normalized}`;
 *     }
 *     if (normalized.length > 1 && normalized.endsWith("/")) {
 *         normalized = normalized.slice(0, -1);
 *     }
 *     return normalized;
 * }
 * ```
 *
 * So `normalizeVfsPath`: (a) delegates entirely to Node's
 * `path.posix.normalize`, which *does* collapse repeated `/` (covers the
 * `readdir`-join bug) and *does* lexically resolve `..` and `.` segments
 * (`path.posix.normalize("/work/repo/../../../../etc")` is `"/etc"` —
 * verified interactively against Node's own `path` module); (b) ensures a
 * leading `/`; (c) strips one trailing `/` (except for the root path
 * itself). It does **not** know anything about `fuseMount` — there is no
 * alias-prefix stripping anywhere in it, unsurprising since `fuseMount` is a
 * Corb/VM-instance-level configuration concept the shared `vfs/utils.js`
 * module has no access to. And critically for this module's own `..`
 * decision: it resolves `..` *silently*, with no signal to the caller that
 * anything unusual happened — exactly the "translating a guest path to a
 * host path... without re-checking containment on the result" failure mode
 * `docs/gondolin-notes.md` §1 warns about, except here it is the SDK's own
 * general-purpose path helper doing the resolving, not a hand-rolled one.
 *
 * Conclusion: `normalizeVfsPath` is not reusable as-is for this module's
 * purpose. It is the right tool for *slash*-shaped normalization (and a
 * future caller of *this* module that also needs `.`-segment collapsing —
 * something this function deliberately does not attempt, see below — could
 * reasonably compose with it), but composing with it here would mean this
 * function's `..`-rejection either runs *after* `normalizeVfsPath` has
 * already resolved the traversal away (too late — the dangerous substring
 * is gone by the time this function's own check would see it) or *before*
 * it (redundant with this function's own `/`-collapsing, since
 * `normalizeVfsPath` would just do that part again). Reimplementing the
 * `/`-collapsing and leading/trailing-slash handling directly here, and
 * doing the `..`-rejection first against the raw input, is more correct
 * for this module's actual requirement (reject, don't resolve) than
 * wrapping the SDK function would be.
 *
 * Deliberately not attempted: collapsing `.` (single-dot) segments. Unlike
 * `..`, a lone `.` segment is not a safety concern (it never escapes
 * anything), so it is out of scope for what this function's three
 * documented jobs above require, and no realistic guest-supplied VFS path
 * reaching a `VirtualProvider` method actually contains one — FUSE resolves
 * `.` components in the guest kernel before a path ever reaches host code
 * over the VFS RPC channel, unlike the `readdir`-join `//` bug (which is
 * produced by *this codebase's own future join code*, not the guest, and so
 * is exactly the kind of thing this function must handle).
 */
export function normalizeGuestPath(rawPath: string, fuseMount: string = DEFAULT_FUSE_MOUNT): string {
  if (rawPath.split("/").includes("..")) {
    throw new GuestPathTraversalError(rawPath);
  }

  let normalized = rawPath.startsWith("/") ? rawPath : `/${rawPath}`;
  normalized = normalized.replace(/\/{2,}/g, "/");

  if (fuseMount !== "/" && (normalized === fuseMount || normalized.startsWith(`${fuseMount}/`))) {
    normalized = normalized.slice(fuseMount.length);
    if (normalized === "") {
      normalized = "/";
    }
  }

  if (normalized.length > 1 && normalized.endsWith("/")) {
    normalized = normalized.slice(0, -1);
  }

  return normalized;
}
