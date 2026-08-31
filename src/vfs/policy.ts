// `src/vfs/policy.ts` — M5.2 builds the pure decision table for `docs/design.md`
// §3's filesystem policy: given a workspace directory's configured glob rules
// and a specific filesystem operation against a specific path, what should
// happen? This module answers exactly that question and nothing else. The
// live `VirtualProvider` wrapper that intercepts real Gondolin VFS calls and
// actually enforces these decisions (`withGlobPolicy`, `src/vfs/glob-policy.ts`)
// is a later item (M5.3) — this file contains no such wrapper, and
// `test/fakes/provider.ts` / `src/vm/session.ts` (M5.3/M5.4's own files) are
// untouched here.
//
// Zero Gondolin dependency, by design and by the top-level plan's own §1
// requirement: "`src/vfs/glob.ts`, `src/vfs/policy.ts` and `src/config/`
// import nothing from Gondolin — the whole policy semantics table stays
// unit-testable with zero VM boot." Grepping this file for the SDK's npm
// package specifier must produce nothing — verified as part of this item,
// not just asserted (deliberately not spelling that specifier out in this
// comment either, so the check itself doesn't produce a false positive
// against its own documentation). The real `VirtualProvider` interface
// (found under the installed SDK package's own `dist/src/vfs/node/`
// directory) was read for research only, to make sure the operation
// vocabulary below lines up cleanly with what M5.3 will eventually need to
// translate its real intercepted calls onto — it is never imported.
//
// Consequence of the "open takes a flags string, not a resolved intent" gap
// noted in the top-level plan's §9 ("`isWriteFlag(flags: string)` is declared
// for strings; verify the RPC layer isn't handing down numeric `O_*` flags
// before relying on it... relevant when M5 builds `GlobPolicyProvider`"): this
// module's operation vocabulary (`FsOpKind` below) takes "this is a
// read-shaped open" or "this is a write-shaped open" as an *already-decided*
// fact, never a raw `flags` string or number. Classifying a real, possibly-
// numeric `flags` value into one of those two buckets — including actually
// answering the still-open `isWriteFlag` question — is entirely M5.3's job.
// This module has no opinion on how that classification happens.
//
// Rule model: reuses `RuleMode` from `src/config/schema.ts` (M2.1) directly,
// per that module's own comment: "the current, authoritative set" of four
// modes (`deny-write`, `deny-read`, `hidden`, `shadow-write`) — not a fourth,
// redeclared copy of the same union, and not `docs/design.md` §3's own
// `GlobRuleMode`, which named only three and is now stale (fixed by this item
// — see the diff to that file's semantics matrix). `GlobRule` below is
// otherwise the same shape `docs/design.md` §3 already sketches
// (`{ glob, mode, reason }`), just fully required rather than the partial,
// still-optional shape `src/config/load.ts`'s own `DirRuleConfig` carries
// (that module deliberately leaves `glob`/`mode`/`reason` optional at the
// config layer; something between there and this module's callers is
// responsible for having a fully-populated `GlobRule` by the time policy
// decisions are made — not this milestone's concern).
import type { RuleMode } from "../config/schema.ts";
import { globToRegExp } from "./glob.ts";

// ---------------------------------------------------------------------------
// Rule model
// ---------------------------------------------------------------------------

/**
 * One fully-resolved `[[dir]].rules[]` entry (`docs/design.md` §3,
 * `src/config/schema.ts`'s `RuleMode`). All three fields are required here,
 * unlike `src/config/schema.ts`'s `PartialDirRuleConfig` / `src/config/
 * load.ts`'s `DirRuleConfig` — this module operates only on rules that have
 * already been fully validated, which is some future caller's job, not this
 * one's.
 */
export interface GlobRule {
  /** A `src/vfs/glob.ts` `globToRegExp` pattern, e.g. `"**\/*_test.go"`. */
  readonly glob: string;
  readonly mode: RuleMode;
  /** Surfaced in the denial error and in the audit log — never consulted by this module's own logic. */
  readonly reason: string;
}

// ---------------------------------------------------------------------------
// Operations vocabulary
// ---------------------------------------------------------------------------

/**
 * Every filesystem operation this module has an opinion about, expressed as
 * this module's own vocabulary rather than any real `VirtualProvider` method
 * name — a later, Gondolin-importing module (M5.3) maps its real intercepted
 * calls onto these. Several real methods share one category below because
 * `docs/design.md` §3's own matrix already gives them identical outcomes in
 * every mode (confirmed row by row while building the table in this file);
 * merging them here is not a loss of precision, it is recognizing that the
 * design doc itself never needed to distinguish them.
 *
 * - `"read"` — open for read, `readFile`. Content-disclosing, gated by
 *   `deny-read`.
 * - `"write"` — open for write/create/truncate/append, `writeFile`,
 *   `appendFile`, and `truncate` (folded in here because `docs/design.md`
 *   §3's own "open for write / create / truncate / append" row already
 *   names `truncate` explicitly as part of this same row, not a separate
 *   one). Mutating, gated by `deny-write` (and therefore `deny-read`, which
 *   implies it).
 * - `"stat"` — `stat` / `lstat`. Existence + metadata only, no content.
 * - `"mutate"` — `mkdir`, `rmdir`, `unlink`.
 * - `"rename"` — `rename`, either endpoint, **non-directory source case
 *   only**. Renaming a directory needs `ruleMayMatchUnderDirectory` (below)
 *   as well — see that function's own doc comment for why a single-path
 *   lookup is insufficient there.
 * - `"copy-source"` / `"copy-dest"` — `copyFile`'s two paths, which
 *   `docs/design.md` §3 already treats asymmetrically: the source is
 *   read-shaped (a copy doesn't mutate what it reads from), the destination
 *   is write-shaped.
 * - `"link"` — `link`'s two paths and `symlink`'s one checked path
 *   (`symlink(target, path, type)`'s `target` argument is an arbitrary
 *   string, not a VFS path this provider ever resolves or checks — only
 *   `path`, where the new entry is actually created, is). `docs/design.md`
 *   §3 groups `link`/`symlink` as one row with one outcome per mode
 *   ("either endpoint") rather than splitting source vs. destination
 *   semantics, and this module follows that grouping rather than
 *   introducing an asymmetry the design doc itself doesn't draw — see
 *   `decideFsAccess`'s doc comment for why `shadow-write`'s value for this
 *   category is not a simple "allow the read side" despite `link`'s existing-
 *   path argument being nominally read-shaped.
 * - `"access-exists"` / `"access-read"` / `"access-write"` — the three
 *   meaningfully different questions the real `access(path, mode?)` can be
 *   asked (`F_OK`, `R_OK`, `W_OK` — see the module comment on `access` for
 *   why `X_OK` isn't a fourth category here).
 * - `"readlink"` — reading a symlink's own target text. Content-disclosing
 *   (the target string is the symlink's "content"), so gated like `"read"`,
 *   not like `"stat"` — see `decideFsAccess`'s doc comment.
 * - `"exists"` — a boolean existence probe (e.g. `VirtualProvider.exists()`),
 *   distinct from `access-exists` only in which real guest-facing method
 *   asks the question; the two share identical outcomes in every mode.
 * - `"realpath"` — canonicalizes a path, guest-facing (see that function's
 *   own note distinguishing this from `withGlobPolicy`'s internal, M5.3-only
 *   defensive resolved-path re-check).
 *
 * Deliberately absent, with reasoning instead of a silent omission:
 *
 * - **`statfs`** — reports aggregate, mount-wide filesystem statistics
 *   (block/inode counts, per `VfsStatfs`), never anything about one path's
 *   own policy. There is nothing for a per-path rule to gate; M5.3 should
 *   let `statfs` calls reach the backend directly without consulting this
 *   module at all.
 * - **The `watch*` family** (`watch`, `watchAsync`, `watchFile`,
 *   `unwatchFile`) — no dedicated category, by design, not oversight. Their
 *   guest-visible effect ("get notified when this path changes") is
 *   read-adjacent: no content or mutation happens through a watch call
 *   itself. `decideFsAccess(mode, "read")` already has the right shape for
 *   this — `allow` under `deny-write`, `EACCES` under `deny-read` (a path
 *   the guest cannot read should not let it infer content changes via
 *   change-notification timing either), `ENOENT` under `hidden`, and `allow`
 *   under `shadow-write` (watching doesn't touch the redirect). M5.3 should
 *   call `decideFsAccess(mode, "read")` directly for the whole `watch*`
 *   family rather than this module growing a same-shaped duplicate category.
 */
export type FsOpKind =
  | "read"
  | "write"
  | "stat"
  | "mutate"
  | "rename"
  | "copy-source"
  | "copy-dest"
  | "link"
  | "access-exists"
  | "access-read"
  | "access-write"
  | "readlink"
  | "exists"
  | "realpath";

// ---------------------------------------------------------------------------
// Outcome vocabulary
// ---------------------------------------------------------------------------

/** The two errno-shaped denial reasons this module ever produces, matching `docs/gondolin-notes.md`'s `ERRNO` export by name only — that export itself is Gondolin-owned and never imported here. */
export type FsErrno = "ENOENT" | "EACCES";

/**
 * The result of one `decideFsAccess` call. Three shapes, not two — `shadow-write`
 * needs an outcome that is neither a plain allow nor a plain deny:
 *
 * - `{ kind: "allow" }` — proceed against the real backend.
 * - `{ kind: "deny", errno }` — refuse, surfaced to the guest as `errno`.
 * - `{ kind: "shadowed" }` — appears to succeed from the guest's perspective,
 *   but M5.3 must route the operation through shadow storage
 *   (`ShadowProvider(writeMode: "tmpfs")`, per the top-level plan's §6.2)
 *   rather than the real backend. Never a `deny`: `shadow-write`'s entire
 *   point is that the guest is not told no.
 */
export type FsAccessOutcome = { readonly kind: "allow" } | { readonly kind: "deny"; readonly errno: FsErrno } | { readonly kind: "shadowed" };

const ALLOW: FsAccessOutcome = { kind: "allow" };
const SHADOWED: FsAccessOutcome = { kind: "shadowed" };
const DENY_ENOENT: FsAccessOutcome = { kind: "deny", errno: "ENOENT" };
const DENY_EACCES: FsAccessOutcome = { kind: "deny", errno: "EACCES" };

// ---------------------------------------------------------------------------
// The semantics table
// ---------------------------------------------------------------------------

/**
 * One row per `FsOpKind`, one column per `RuleMode`. This *is*
 * `docs/design.md` §3's semantics matrix (now with `shadow-write` filled in
 * — see the diff to that file made alongside this module) plus the
 * categories that matrix never covered, laid out so each cell's
 * justification can be read directly out of the source rather than
 * reconstructed:
 *
 * - `read`, `write`, `stat`, `mutate`, `rename`, `copy-source`, `copy-dest`,
 *   `link` for `deny-write`/`deny-read`/`hidden`: taken directly from
 *   `docs/design.md` §3's existing three-mode matrix, unchanged.
 * - The same rows' `shadow-write` column: taken from the top-level plan's
 *   §6.2 coarse table (`open read: allow`, `open write: discarded`,
 *   `stat/lstat: allow`, `readdir: listed`, `mutations: via
 *   ShadowProvider(writeMode:"tmpfs")`) for `read`/`write`/`stat` directly,
 *   and by reasoned extension for `mutate`/`rename`/`copy-dest`/`link`: each
 *   of those is exactly the kind of real-backend mutation the plan's
 *   "mutations" bucket describes, so each gets `shadowed` rather than
 *   `allow` or `deny`. `copy-source` gets `allow` by the same read/write
 *   asymmetry `docs/design.md` already applies to `deny-write`/`deny-read`:
 *   reading *from* a shadow-write path doesn't touch the redirect, so it
 *   passes straight through to whatever the backend actually has.
 * - `link`'s `shadow-write` value is `shadowed`, not `allow`, even though
 *   `link`'s existing-path argument is nominally a read: `docs/design.md`
 *   §3's own reasoning for gating *both* endpoints of `link`/`symlink` under
 *   `deny-write` is "the only place to stop [hard-link aliasing] is at
 *   creation" — letting `link(shadowWritePath, elsewhere)` through to the
 *   real backend would create a second, real name for the same inode that
 *   is not itself covered by any shadow-write rule, and a write through
 *   *that* name would land on the real backend for real, defeating the
 *   redirect entirely. `shadowed` (route the whole `link`/`symlink` call
 *   through shadow storage, same as any other mutation) is the only value
 *   consistent with that reasoning, extended to this mode.
 * - `access-exists` / `exists`: reasoned extension. Both ask "does this path
 *   exist", nothing more — exactly what `stat`'s row already answers in
 *   every mode, so both columns are copied from the `stat` row verbatim
 *   (`allow` everywhere except `hidden`'s `ENOENT`). The top-level plan's
 *   own caution ("`access` disagreeing with `open` gives an incoherent
 *   filesystem") is respected in the opposite direction from a literal
 *   reading: `F_OK` must agree with what `stat` reports (existence), not
 *   with what `open` reports (readability/writability) — those are
 *   `access-read`/`access-write`'s job below, not `access-exists`'s.
 * - `access-read`: reasoned extension, made to agree with `read`'s row
 *   exactly, per the same "access disagreeing with open" caution — this
 *   time read the way it's usually meant: `R_OK` must predict what `open`
 *   for read will actually do. `X_OK` (execute permission) is deliberately
 *   folded into this same category rather than given its own: none of the
 *   four `RuleMode`s models an execute bit distinct from read/write, and no
 *   rule anywhere in this codebase's own examples targets execute
 *   permission specifically, so "can this be read" is the closest available
 *   proxy for "can this be executed" and treating them identically is a
 *   reasoned simplification, not an oversight.
 * - `access-write`: reasoned extension, made to agree with `write`'s row for
 *   `deny-write`/`deny-read`/`hidden`/no-rule (`W_OK` must predict what
 *   `open` for write will do) — but **not** for `shadow-write`, where
 *   `write` itself is `shadowed`, not `allow`. `access` has no operation
 *   payload for a future caller to redirect — it is a pure permission
 *   query, not an attempt — so the truthful answer under `shadow-write` is
 *   `allow`: a write *will* be accepted (the guest-visible contract
 *   `write`'s own `shadowed` outcome promises), it just will not persist to
 *   the real backend. This is the one place in the table where `shadowed`
 *   collapses to `allow` rather than being copied straight across, and it
 *   is deliberate, not an inconsistency.
 * - `readlink`: reasoned extension, made to agree with `read`'s row, not
 *   `stat`'s. A symlink's target string is content it discloses (where a
 *   `secrets`-hidden name points to might itself be sensitive), unlike
 *   `stat`, which discloses only existence and metadata — so `readlink` is
 *   gated by `deny-read` the same way file content is, not exempted from it
 *   the way mere existence-checks are.
 * - `realpath`: reasoned extension — see `decideFsAccess`'s own callers and
 *   the module comment on this operation for the full reasoning; copied
 *   from the `stat` row because canonicalizing a path's spelling discloses
 *   existence and shape, not content.
 *
 * `mode: undefined` (no rule matched) is handled separately in
 * `decideFsAccess`, not as a fifth column here — every real column in
 * `docs/design.md` §3's own matrix agrees it is always `allow`, so there is
 * no per-operation variation to tabulate for it.
 */
const TABLE: Record<FsOpKind, Record<RuleMode, FsAccessOutcome>> = {
  read: { "deny-write": ALLOW, "deny-read": DENY_EACCES, hidden: DENY_ENOENT, "shadow-write": ALLOW },
  write: { "deny-write": DENY_EACCES, "deny-read": DENY_EACCES, hidden: DENY_ENOENT, "shadow-write": SHADOWED },
  stat: { "deny-write": ALLOW, "deny-read": ALLOW, hidden: DENY_ENOENT, "shadow-write": ALLOW },
  mutate: { "deny-write": DENY_EACCES, "deny-read": DENY_EACCES, hidden: DENY_ENOENT, "shadow-write": SHADOWED },
  rename: { "deny-write": DENY_EACCES, "deny-read": DENY_EACCES, hidden: DENY_ENOENT, "shadow-write": SHADOWED },
  "copy-source": { "deny-write": ALLOW, "deny-read": DENY_EACCES, hidden: DENY_ENOENT, "shadow-write": ALLOW },
  "copy-dest": { "deny-write": DENY_EACCES, "deny-read": DENY_EACCES, hidden: DENY_ENOENT, "shadow-write": SHADOWED },
  link: { "deny-write": DENY_EACCES, "deny-read": DENY_EACCES, hidden: DENY_ENOENT, "shadow-write": SHADOWED },
  "access-exists": { "deny-write": ALLOW, "deny-read": ALLOW, hidden: DENY_ENOENT, "shadow-write": ALLOW },
  "access-read": { "deny-write": ALLOW, "deny-read": DENY_EACCES, hidden: DENY_ENOENT, "shadow-write": ALLOW },
  "access-write": { "deny-write": DENY_EACCES, "deny-read": DENY_EACCES, hidden: DENY_ENOENT, "shadow-write": ALLOW },
  readlink: { "deny-write": ALLOW, "deny-read": DENY_EACCES, hidden: DENY_ENOENT, "shadow-write": ALLOW },
  exists: { "deny-write": ALLOW, "deny-read": ALLOW, hidden: DENY_ENOENT, "shadow-write": ALLOW },
  realpath: { "deny-write": ALLOW, "deny-read": ALLOW, hidden: DENY_ENOENT, "shadow-write": ALLOW },
};

/**
 * The single place the mode × operation matrix lives. `mode: undefined`
 * means no configured rule matched this path at all — always `allow`,
 * regardless of `op`, matching every "no rule" column in both
 * `docs/design.md` §3's matrix and the top-level plan's §6.2 table. A
 * defined `mode` looks up `TABLE[op][mode]`.
 *
 * Note on `exists`/`access-exists`'s `deny`: a `deny`'s `errno` is always
 * `"ENOENT"` for those two categories (see `TABLE`), but `exists()`'s real
 * guest-facing contract (`docs/gondolin-notes.md` §7) never throws — it
 * returns a boolean. Translating this function's `{ kind: "deny", errno:
 * "ENOENT" }` into `exists()` returning `false` (rather than into a thrown
 * error, which is the right translation for every other category) is M5.3's
 * job, not this module's; this function only ever reasons in terms of the
 * abstract three-outcome vocabulary above, never in terms of any one real
 * method's calling convention.
 */
export function decideFsAccess(mode: RuleMode | undefined, op: FsOpKind): FsAccessOutcome {
  if (mode === undefined) {
    return ALLOW;
  }
  return TABLE[op][mode];
}

// ---------------------------------------------------------------------------
// Rule matching
// ---------------------------------------------------------------------------

/**
 * Finds the first rule in `rules` whose glob matches `path`, or `undefined`
 * if none do — first-match-wins, per `docs/design.md` §3: "Rules are
 * evaluated in order and first match wins."
 *
 * `path` must already be in the form `src/vfs/glob.ts`'s `globToRegExp`
 * expects: relative to the *directory's own root* (no leading `/`, no
 * mount-point prefix) — exactly the convention every real pattern in
 * `docs/design.md` §3's example rule list uses (`"go.sum"`,
 * `".git/config"`, a leading `"**\/"` for "anywhere in the tree"). Stripping
 * a real VFS-received absolute path down to that form — normalizing it via
 * `normalizeGuestPath` *and* stripping the specific directory's own
 * mount-root prefix (`/work/<name>`) — is `src/vfs/glob-policy.ts`'s job
 * (M5.3), not this function's: this module has no concept of mount points
 * at all, matching `src/vfs/glob.ts`'s own module comment ("this function
 * has no opinion on mount roots or path aliasing").
 */
export function matchRule(rules: readonly GlobRule[], path: string): GlobRule | undefined {
  for (const rule of rules) {
    if (globToRegExp(rule.glob).test(path)) {
      return rule;
    }
  }
  return undefined;
}

/**
 * The convenience, fully "per-path, per-operation" entry point: resolves
 * which rule (if any) governs `path` and looks up that rule's mode in
 * `decideFsAccess`, in one call. Also returns the matched `rule` itself
 * (`undefined` when none matched) alongside the outcome, so a caller doesn't
 * need a second `matchRule` call just to get at `rule.reason` for an error
 * message or an audit-log entry — `docs/design.md` §3's own `GlobRule.reason`
 * field exists specifically "to be surfaced in the error and in the audit
 * log," and both of those happen at the call site that already has (or
 * needs) the matched rule, not inside this pure decision table.
 *
 * See `matchRule`'s own doc comment for the required shape of `path`.
 */
export function decideFsAccessForPath(
  rules: readonly GlobRule[],
  path: string,
  op: FsOpKind,
): { readonly outcome: FsAccessOutcome; readonly rule: GlobRule | undefined } {
  const rule = matchRule(rules, path);
  return { outcome: decideFsAccess(rule?.mode, op), rule };
}

// ---------------------------------------------------------------------------
// Directory-listing visibility
// ---------------------------------------------------------------------------

/**
 * Answers "should this specific entry be filtered out of its parent
 * directory's listing" — the `readdir` row of `docs/design.md` §3's matrix,
 * but deliberately a different shape from `decideFsAccess`: that row's
 * values are `yes`/`yes`/`yes`/`no`/`yes` (listed for every mode except
 * `hidden`), a plain boolean question, not a three-outcome one — `shadowed`
 * has no meaning for "is this name in the listing", since a shadow-write
 * entry's mutations are redirected but its *presence* in the directory is
 * exactly what the real backend (or, once written to, the tmpfs upper
 * layer — an M5.3 concern) already says it is.
 *
 * Takes one already-fully-qualified `entryPath` (the parent directory's own
 * path joined with the child's name) rather than a `(parentDir, name)` pair:
 * this module has no opinion on how that join should be done (`path.posix.
 * join`, or something aware of the `readdir`-`//`-join bug `src/vfs/
 * glob.ts`'s `normalizeGuestPath` already fixes) — a caller iterating a raw
 * directory listing one entry at a time builds the joined path however it
 * already needs to for other reasons, then asks this function about it.
 */
export function isEntryHidden(rules: readonly GlobRule[], entryPath: string): boolean {
  return matchRule(rules, entryPath)?.mode === "hidden";
}

// ---------------------------------------------------------------------------
// Directory-rename subtree coverage
// ---------------------------------------------------------------------------

/**
 * Matches one already-split glob pattern segment (never `"**"` — the caller
 * handles that case itself) against one already-split candidate path
 * segment, with the same `*`-within-a-segment, everything-else-literal
 * semantics `src/vfs/glob.ts`'s private (unexported, and this module does
 * not modify that file) `segmentToRegexSource` uses. Reimplemented here in
 * miniature — a single segment, not a whole pattern — because that
 * function isn't exported and duplicating five lines of regex-escaping is
 * simpler and more honest than trying to repurpose `globToRegExp` (which
 * only ever produces a whole-*pattern*, whole-string-anchored regex) for a
 * single-segment comparison.
 */
function segmentMatches(patternSegment: string, candidateSegment: string): boolean {
  const escaped = patternSegment.replace(/[.*+?^${}()|[\]\\]/g, (matched) => (matched === "*" ? "[^/]*" : `\\${matched}`));
  return new RegExp(`^${escaped}$`).test(candidateSegment);
}

/**
 * Splits an already-relative (see `matchRule`'s doc comment for what
 * "relative" means here) directory path into its `/`-delimited segments,
 * with the bare root path (`""`, or a lone `"/"` should one ever reach this
 * function) normalized to an empty segment array rather than `[""]`. An
 * empty segment array is the conservative extreme of `patternMayMatchAtOrUnder`
 * below: with zero directory segments to consume, every call immediately
 * hits that function's base case and returns `true` for *any* pattern — the
 * correct, conservative answer for "could anything match at or under the
 * mount root", even though renaming the root itself is not an operation
 * this codebase's own mount model ever actually exposes to a guest.
 */
function splitDirSegments(dirPath: string): string[] {
  if (dirPath === "" || dirPath === "/") {
    return [];
  }
  return dirPath.split("/").filter((segment) => segment.length > 0);
}

/**
 * Decides whether `pattern` could match `dirPath` itself, or any path that
 * has `dirPath` as a proper prefix (i.e., anything that would move if the
 * directory at `dirPath` were renamed as a whole). Conservative by
 * construction, per the top-level plan's own words for this exact check:
 * "cheap and correct... a precise one requires walking the subtree" — this
 * function never inspects real directory contents, only the shapes of
 * `dirPath` and `pattern`.
 *
 * Why a plain `globToRegExp(pattern).test(dirPath)` (or a prefix test
 * against its source) does not work: `globToRegExp` produces a whole-string
 * *anchored* regex (`^...$`), built specifically to answer "does this exact
 * candidate match", not "could some longer candidate sharing this prefix
 * match". A pattern like `"a/**\/b"` must match `"a/b"`, `"a/x/b"`,
 * `"a/x/y/b"`, and so on — infinitely many candidate lengths — and no
 * single anchored regex built for exact matching can be turned into a
 * prefix test by truncation or by stripping the trailing `$`, because a
 * literal segment appearing *after* a `**` (like the trailing `b` above)
 * still has to be accounted for somewhere in the middle of an
 * unboundedly-long real match. So this function reasons directly against
 * the pattern's own `/`-split segments instead of compiling anything.
 *
 * The key insight that makes this tractable: once `dirPath`'s segments are
 * fully consumed against a prefix of `pattern`'s segments (respecting `**`'s
 * "zero or more segments" and `*`'s "anything within one segment"
 * semantics), *any* remaining pattern segments — literal, `*`, or `**` —
 * can always be satisfied by some hypothetical file or directory structure
 * underneath `dirPath`, because this function is asking about *possible*
 * matches, not existing ones, and nothing constrains what could exist below
 * a renamed directory. So "`pattern` may match at or under `dirPath`"
 * reduces to "`dirPath`'s segments can be fully consumed by a prefix of
 * `pattern`'s segments" — a small recursive match, structurally the same
 * shape as ordinary glob matching but relaxed to stop as soon as the
 * candidate (here, `dirPath`) runs out, rather than requiring the pattern to
 * run out at the same time too.
 *
 * Two worked examples (both exercised in this module's own tests):
 *   - `pattern = "secrets"` (no `**`, so it only ever matches an exact
 *     top-level entry named `secrets`), `dirPath = "secrets/sub"`: the
 *     pattern is exhausted after matching `dirPath`'s first segment, but
 *     `dirPath` still has a second segment left over — `false`. Renaming
 *     `secrets/sub` cannot relocate anything this pattern would ever have
 *     matched, because the pattern could never have matched anything nested
 *     inside a directory *named* `secrets` in the first place.
 *   - `pattern = "**\/secrets/**"`, `dirPath = "a/b"`: the leading `**`
 *     absorbs both of `dirPath`'s segments, `dirPath` is now fully consumed,
 *     and the answer is `true` — a hypothetical `a/b/secrets` (or deeper)
 *     would match, so renaming `a/b` must be denied.
 */
function patternMayMatchAtOrUnder(pattern: string, dirSegments: readonly string[]): boolean {
  const patternSegments = pattern.split("/");
  const memo = new Map<string, boolean>();

  function canConsumeDir(patternIndex: number, dirIndex: number): boolean {
    if (dirIndex === dirSegments.length) {
      // `dirPath` fully consumed. Whatever (if anything) remains of the
      // pattern is always satisfiable by some hypothetical content below
      // `dirPath` — see this function's own doc comment.
      return true;
    }
    if (patternIndex === patternSegments.length) {
      // Pattern exhausted, but `dirPath` still has real segments left to
      // account for — a fixed-length pattern can never match a longer path.
      return false;
    }
    const key = `${patternIndex},${dirIndex}`;
    const cached = memo.get(key);
    if (cached !== undefined) {
      return cached;
    }
    const segment = patternSegments[patternIndex] as string;
    let result: boolean;
    if (segment === "**") {
      // Zero or more directory segments consumed by this one `**`.
      result = canConsumeDir(patternIndex + 1, dirIndex) || canConsumeDir(patternIndex, dirIndex + 1);
    } else {
      const dirSegment = dirSegments[dirIndex] as string;
      result = segmentMatches(segment, dirSegment) && canConsumeDir(patternIndex + 1, dirIndex + 1);
    }
    memo.set(key, result);
    return result;
  }

  return canConsumeDir(0, 0);
}

/**
 * Answers "if the directory at `dirPath` were renamed as a whole, could any
 * rule in `rules` match something that would move as a result" —
 * `docs/design.md` §3's "rename of a directory containing a matched path"
 * row, and the top-level plan's own called-out gap: "Directory `rename`
 * relocates rule-matched subtrees out of scope (`mv secrets/ ok/`)... this
 * needs a dedicated check, not just a per-path mode lookup, since it has to
 * ask 'could any configured rule match something under this directory being
 * renamed' against the *whole rule list*, not just 'what mode applies to
 * this exact path'."
 *
 * A `true` result must be surfaced as `EACCES` regardless of which rule (or
 * which of its four modes) would be relocated — matching `docs/design.md`
 * §3's matrix, which uses a single `EACCES` value across every mode's column
 * for this row, including `hidden` (notably *not* `ENOENT`: the directory
 * being renamed is not itself necessarily hidden, so denying it as
 * "forbidden" rather than "doesn't exist" is the honest answer — see that
 * row's own values). `shadow-write` gets the same `EACCES` treatment for a
 * reason `docs/design.md`'s original three-mode matrix didn't need to
 * consider: relocating a directory that contains a shadow-write-covered
 * path would move that path out from under its own rule, so a *future*
 * write to it would no longer be shadowed at all and would land on the real
 * backend for real — exactly the same "protection relocated out of scope"
 * failure the other three modes are denied for, just discovered one step
 * later (at the next write, not at the rename itself) if this weren't
 * denied up front.
 *
 * `rules.length === 0` never denies (`Array.prototype.some` on an empty
 * array is `false`), matching "no configured rules" being equivalent to "no
 * rule can possibly match anything" everywhere else in this module.
 *
 * See `matchRule`'s doc comment for the required (mount-root-relative)
 * shape of `dirPath`.
 */
export function ruleMayMatchUnderDirectory(rules: readonly GlobRule[], dirPath: string): boolean {
  const dirSegments = splitDirSegments(dirPath);
  return rules.some((rule) => patternMayMatchAtOrUnder(rule.glob, dirSegments));
}
