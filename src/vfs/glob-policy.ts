// `src/vfs/glob-policy.ts` — M5.3: `withGlobPolicy`, the live `VirtualProvider`
// wrapper that actually enforces `src/vfs/policy.ts`'s decisions against real
// Gondolin VFS calls. `src/vfs/glob.ts` (M5.1) and `src/vfs/policy.ts` (M5.2)
// are pure decision tables with zero Gondolin dependency; this module is
// where that decision table meets the real, importing-from-Gondolin world —
// it is the one place in the `vfs/` family that is allowed to `import` from
// `@earendil-works/gondolin`, and it does so only for `ERRNO`, `isWriteFlag`
// and `MemoryProvider`, three small, already-shipped primitives, never a
// bespoke enforcement primitive of the SDK's own (see "Why not
// `ShadowProvider`" below for the one place that distinction matters).
//
// This item is the largest, most security-critical item in the project so
// far (per the dispatching item's own framing) precisely because a
// partially-hardened wrapper is not a safe intermediate state: gating plain
// reads/writes but not yet symlink indirection is *more* dangerous than no
// wrapper at all, because it looks safe. Every design decision below is
// documented with the reasoning that justifies it, not just the choice
// itself, because a security-relevant module like this one is read far more
// often than it is written.
//
// ---------------------------------------------------------------------------
// Investigation findings that shaped this file (verified independently, not
// taken on faith from the dispatching item's own notes)
// ---------------------------------------------------------------------------
//
// 1. **`isWriteFlag(flags: string)` always receives a string, never a
//    numeric `O_*` bitmask, by the time a call reaches a mounted
//    `VirtualProvider`'s `open`/`openSync`.** Verified by reading
//    `node_modules/@earendil-works/gondolin/dist/src/vfs/rpc-service.js`:
//    the guest kernel's FUSE `open` request carries numeric Linux `O_*`
//    flags, but the RPC service converts them to a Node-style flag string
//    (`'r'`, `'r+'`, `'w'`, `'w+'`, `'a'`, `'a+'`) via its own
//    `openFlagsToString`/`parseOpenFlagsForOpen` helpers *before* ever
//    calling `this.provider.open(entryPath, <string>, mode)`. The top-level
//    plan's §9 "still unverified" flag is resolved: `isWriteFlag` is safe to
//    rely on exactly as typed.
//
// 2. **`readFile`/`writeFile`/`appendFile`/`exists`/`copyFile` are real,
//    callable methods on a `RealFSProvider` instance, but for the first four
//    of those five, only via *inherited base-class defaults*, not
//    `RealFSProvider`'s own overrides.** Verified by reading
//    `.../lib/internal/vfs/provider.js` (the base `VirtualProvider` class:
//    `readFile`/`writeFile`/`appendFile`/`exists`/`realpath`/`access` all
//    have working default implementations built on `open`/`stat`) against
//    `.../lib/internal/vfs/providers/real.js` (`RealFSProvider`, which
//    overrides `access`, `realpath`, `copyFile` and their sync twins with
//    fs-native implementations, but never `readFile`/`writeFile`/
//    `appendFile`/`exists` — those five fall through to the base class).
//
//    This has one sharp, security-relevant consequence for how this wrapper
//    must be built: the base class's `readFile` default is
//    `{ const handle = await this.open(path, 'r'); ... }` — it calls
//    `this.open`, where `this` is whatever object the method was invoked on.
//    If this wrapper ever delegated `readFile` by doing something like
//    `return backend.readFile(path)` and trusted that to be safe because
//    `open` is separately gated, it would be **wrong**: `backend.readFile`'s
//    internal `this.open` call resolves against the *raw, unwrapped*
//    `backend` object, never back through this module's own `Proxy`, so
//    that internal `open` call would completely bypass every check this
//    file exists to perform. The fix is structural, not a special case:
//    every operation this wrapper exposes — including `readFile`,
//    `writeFile`, `appendFile`, `exists` and `copyFile` — gets its own
//    top-level policy decision made by *this* module before ever touching
//    `backend`, and only ever calls `backend.<sameMethod>(...)` (or the
//    shadow store's) after that decision is already made — never relies on
//    a real provider's own internal cross-method delegation to stay inside
//    the gate.
//
// 3. **File-handle wrapping is unnecessary — confirmed, not assumed — for
//    the real backend, and inconsequential for the private shadow store.**
//    `RealFileHandle` (`.../providers/real.js`) wraps a genuine OS file
//    descriptor opened with the real, negotiated flags; its `write`/
//    `writeSync` call straight through to `fs.write`/`fs.writeSync` on that
//    fd with no additional flag check of their own — meaning the enforcement
//    is happening one layer down, in the kernel itself: a fd opened
//    `O_RDONLY` cannot succeed a `write(2)` no matter what JavaScript code
//    calls `write()` on the wrapping object. That is exactly the same
//    kernel-level guarantee a real POSIX process gets, and it holds
//    regardless of what this wrapper does after `open()` returns. So gating
//    is only needed at `open()`-time (deciding *which* backend's `open` to
//    call, and rejecting outright before any handle is created for a denied
//    path) — the returned handle is passed straight to the guest untouched.
//
//    The one nuance worth recording rather than silently assuming away:
//    `MemoryFileHandle` (`.../lib/internal/vfs/file_handle.js`, used by this
//    module's own private shadow store) does *not* self-enforce the same
//    way — its `writeSync` never consults `this.flags` before mutating
//    content. This sounds like a gap, but it is inconsequential here: this
//    wrapper only ever routes a call to the shadow store when the *original
//    request* was already write-shaped (every read-shaped operation on a
//    `shadow-write` path is routed to the real backend, per
//    `src/vfs/policy.ts`'s own table — see the `TABLE.read["shadow-write"]
//    === ALLOW` cell), so a read-shaped handle into the shadow store is
//    never actually created by this wrapper's own routing logic in the
//    first place, and the shadow store never holds anything more sensitive
//    than what the guest itself already wrote there. There is no
//    confidentiality or integrity property riding on `MemoryFileHandle`'s
//    own internal flag discipline.
//
// 4. **`RealFSProvider` genuinely implements both `realpath` and
//    `realpathSync`**, confirmed directly in `.../providers/real.js` (they
//    convert the resolved real path back to a VFS-relative path). The
//    symlink-bypass defense this module builds (see below) can therefore
//    function for real against the actual backend Corb mounts — this was a
//    real, not rhetorical, risk to check before relying on it, since the
//    defense is a no-op (and this module refuses to silently degrade into
//    one — see the constructor guard below) against any backend that lacks
//    both methods.
//
// 5. **The real RPC dispatch (`rpc-service.js`) never calls a mounted
//    provider's own top-level `truncate(path, length)` method unless the
//    provider happens to implement one** — it *probes* for it
//    (`if (provider.truncate) { await provider.truncate(...) } else { open
//    'r+', handle.truncate(size), close }`) — and `RealFSProvider` does
//    **not** implement a top-level `truncate`, only `RealFileHandle`'s own
//    per-handle `truncate(len)`. So for the real backend Corb actually uses,
//    top-level `truncate` is never invoked at all; the RPC layer's own
//    fallback opens the file (`'r+'`) through whatever `open` it was given
//    — which, once this wrapper is in place, is *this module's own gated
//    `open`* — and truncates the returned handle directly. This wrapper
//    still implements gating for a top-level `truncate`, because the
//    `VirtualProvider` surface allows a *future* or *different* backend to
//    supply one, and "defaults unknown method names to a thrown EPERM" would
//    otherwise silently start denying `truncate` outright the day some
//    backend adds it — but it correctly exposes `truncate`/`truncateSync` as
//    `undefined` (matching real absence) when the wrapped backend doesn't
//    have one itself, exactly like every other optional `VirtualProvider`
//    member (see "Optional-method exposure" below).
//
// ---------------------------------------------------------------------------
// Why not `ShadowProvider` — the shadow store is a private `MemoryProvider`
// ---------------------------------------------------------------------------
//
// The top-level plan's own sketch names `ShadowProvider(writeMode: "tmpfs")`
// for `shadow-write` mode. Reading `dist/src/vfs/shadow.js` in full turns up
// two findings that make composing with it the wrong choice here:
//
//   - `ShadowProvider` only actually overrides `open`, `stat`, `lstat`,
//     `readdir`, `mkdir`, `rmdir`, `unlink`, `readlink`, `symlink`,
//     `realpath` and `access` (confirmed by grepping every `shadowedFor(...)`
//     call site) — it has **no override at all** for `rename`, `link`,
//     `writeFile`, `appendFile`, `truncate` or `copyFile`. `writeFile` would
//     fall back through its own base-class default, which calls `this.open`
//     — and since `ShadowProvider` *does* override `open`, that particular
//     gap self-heals. `rename` and `link`, however, have dedicated overrides
//     in `ShadowProvider` that behave differently from what
//     `src/vfs/policy.ts`'s own table requires: `ShadowProvider.rename`
//     throws `EXDEV` unless *both* endpoints resolve to shadowed, where this
//     codebase's table treats "either endpoint" as sufficient (matching
//     `docs/design.md` §3's single "either endpoint" row) — composing with
//     the real class would silently reintroduce a narrower policy than the
//     one this codebase has already decided on and tested (M5.2).
//   - `ShadowProvider`'s constructor requires a `shouldShadow` predicate
//     keyed on `(path, op, flags)`, which is a strictly coarser vocabulary
//     than `src/vfs/policy.ts`'s already-built `FsOpKind` categories and
//     four-mode table — bridging the two would mean re-deriving most of
//     M5.2's own logic *again*, inside a predicate, just to hand it to a
//     class whose per-method behavior still doesn't match in the two cases
//     above.
//
// So this module does not use `ShadowProvider` at all. Instead, it holds one
// private `MemoryProvider` instance per `withGlobPolicy()` call (a real,
// fully-implemented `VirtualProvider`, exported from `@earendil-works/
// gondolin` and used elsewhere in the SDK's own `ShadowProvider` as exactly
// this kind of upper layer) as its shadow store, and for any operation
// `decideFsAccess`/`decideFsAccessForPath` resolves to `{ kind: "shadowed" }`,
// delegates the call to that instance's own matching method instead of the
// real backend. This is a real, consequential departure from the plan's
// literal wording, not a cosmetic one, and it is the one place this module
// disagrees with the plan's own sketch outright rather than merely filling
// in a gap the plan left open.
//
// One shadow store per `withGlobPolicy()` call means one per mounted
// directory (`session.ts`, M5.4, is expected to call this once per
// configured `[[dir]]`), not one shared, VM-session-wide store. That is a
// slightly *more* isolated scoping than "session-scoped" strictly requires,
// and is a defensible reading of "ephemeral, session-scoped storage": a
// shadow-write in one directory's tree can never leak into another
// directory's shadow namespace, and since `GlobRule`s and mount roots are
// already per-directory concepts, nothing needs cross-directory shadow
// visibility.
//
// **Read-after-write decision (a genuine behavioral choice this item is
// responsible for resolving, not merely modeling abstractly):** a
// shadow-written path is *never* visible to a subsequent read, even within
// the same session, even immediately after the write. This follows directly
// from `docs/design.md` §3's own words, taken literally: "Reads, `stat`, and
// directory listings keep reflecting the real backend unchanged" — not
// "unchanged until the guest writes to them locally." `src/vfs/policy.ts`'s
// own table already encodes the mechanism that makes this true without any
// extra bookkeeping here: `TABLE.read["shadow-write"]` is `ALLOW`, never
// `SHADOWED`, so a read-shaped operation against a `shadow-write` path is
// *always* routed to the real backend by construction — the shadow store is
// consulted only by write-shaped operations, and only to let them "succeed"
// without ever touching the real file, not to serve as an upper layer reads
// can see through. `test/unit/vfs/glob-policy.test.ts` proves this
// (write-then-read round-trip against a `shadow-write` path returns the
// pre-write real content, not the shadow-written content), because a
// property this consequential should be demonstrated, not just asserted in
// a comment.
//
// A second consequence of using a real (rather than a no-op/"discard
// everything") `MemoryProvider` as the shadow store: `mkdir`/`writeFile`
// there always succeed (missing ancestor directories are auto-created,
// verified by reading `MemoryProvider._ensureParent`'s `create` parameter),
// but `rmdir`/`unlink`/`rename`/`link` targeting a path that was *never
// previously shadow-written* will throw `ENOENT` from the empty shadow
// store, even though the operation must "appear to succeed" per
// `docs/design.md` §3 ("anything that would mutate the real backend... is
// redirected... and never reaches the real file" — never "and may then fail
// for a reason having nothing to do with the real backend's own state").
// The real `ShadowProvider`'s own `rmdir`/`unlink` implementations hit this
// exact problem and solve it the same way this module does: catch `ENOENT`
// specifically and swallow it (`isNoEntryError` in `shadow.js`). This module
// copies that precedent (`tolerateMissingShadowEntry` below) because it is a
// verified, working answer to the same problem, not a novel guess.
import { constants as fsConstants } from "node:fs";
import path from "node:path";
import { ERRNO, isWriteFlag, MemoryProvider } from "@earendil-works/gondolin";
import { normalizeGuestPath } from "./glob.ts";
import { decideFsAccessForPath, isEntryHidden, ruleMayMatchUnderDirectory, type FsAccessOutcome, type FsErrno, type FsOpKind, type GlobRule } from "./policy.ts";

// ---------------------------------------------------------------------------
// Public option / event shapes
// ---------------------------------------------------------------------------

/**
 * Everything a future audit call (`src/policy/audit.ts`'s `AuditWriter`,
 * wired in by M5.4 — this module takes no `AuditWriter` dependency itself,
 * matching how `src/vm/gitssh.ts`'s M4.1 stage took no `AuditWriter`
 * parameter and M4.3 added one a full item later) needs to record one
 * non-allow policy decision:
 *
 *   - `path` — the rule-relative path the decision was made against (no
 *     leading `/`, no mount prefix — the same shape
 *     `src/vfs/policy.ts`'s `matchRule` expects, e.g. `".env"` or
 *     `"a/b/secret"`, with the bare mount root spelled `""`). Never a raw
 *     absolute guest path or a real host path — this module never learns a
 *     real host path at all, only ever talks to `backend` in mount-relative
 *     VFS-path terms.
 *   - `op` — the `FsOpKind` category the decision was made under, or the
 *     literal string `"unknown-operation"` for the fail-closed default this
 *     module applies to any `VirtualProvider` member it does not recognize
 *     (see `withGlobPolicy`'s `get` trap) — a case with no natural
 *     `FsOpKind`, since it exists precisely because some future operation
 *     wasn't anticipated when this module's operation vocabulary was built.
 *   - `outcome` — never `{ kind: "allow" }`: `onDeny` is only ever invoked
 *     for a `"deny"` or a `"shadowed"` outcome, per the dispatching item's
 *     own instruction that shadowed operations are audit-worthy too (a
 *     silently-redirected mutation is exactly the kind of thing an operator
 *     watching the audit log wants visibility into, not just outright
 *     denials).
 *   - `rule` — the `GlobRule` whose `mode` produced this outcome, for its
 *     `reason` field. `undefined` for the two cases that have no single
 *     originating rule: the directory-rename subtree check (denies based on
 *     the whole rule list's shape against a directory's descendants, not
 *     one matched rule) and the unknown-operation fail-closed default (there
 *     is no rule to blame — the wrapper itself declined to proceed).
 *   - `reason` — always populated: `rule.reason` when `rule` is defined,
 *     otherwise a synthesized human-readable description of why the
 *     rule-less case fired. Saves a future audit call from having to handle
 *     `rule === undefined` as a special case just to get a displayable
 *     string.
 */
export interface GlobPolicyDenyEvent {
  readonly path: string;
  readonly op: FsOpKind | "unknown-operation";
  readonly outcome: Extract<FsAccessOutcome, { kind: "deny" } | { kind: "shadowed" }>;
  readonly rule: GlobRule | undefined;
  readonly reason: string;
}

/**
 * Options for `withGlobPolicy`. `rules` is `src/vfs/policy.ts`'s own
 * `GlobRule[]` — evaluated in order, first match wins, exactly as
 * `matchRule` already implements. `onDeny` is a plain callback, deliberately
 * not typed against `AuditWriter` — see `GlobPolicyDenyEvent`'s own doc
 * comment for why that wiring is left to a later item.
 */
export interface GlobPolicyOptions {
  readonly rules: readonly GlobRule[];
  readonly onDeny: (event: GlobPolicyDenyEvent) => void;
}

// ---------------------------------------------------------------------------
// errno-shaped error construction
// ---------------------------------------------------------------------------

/**
 * Builds a `NodeJS.ErrnoException` in exactly the shape
 * `@earendil-works/gondolin`'s own internal `createErrnoError`
 * (`dist/src/vfs/errors.js`) does — `code` as a platform-neutral string,
 * `errno` as the host-specific numeric constant, `syscall`, and `path` when
 * known — so that the RPC layer's own errno-to-Linux-numeric translation
 * (`dist/src/vfs/linux-errno.js`, which keys off `error.code`, not
 * `error.errno`, specifically because host errno numbers are platform-
 * specific while `code` strings are not) treats an error thrown by this
 * module identically to one thrown by the SDK's own code. Not itself
 * reusable from the package: `createErrnoError` is used internally by
 * `shadow.js`/`mounts.js` but is not part of the public export list in
 * `dist/src/index.d.ts` (only `ERRNO`, `isWriteFlag`, `normalizeVfsPath` and
 * a handful of others are), so it is reimplemented here rather than reached
 * for via an unsupported internal import path.
 */
function makeErrnoError(errno: number, code: string, syscall: string, targetPath: string): NodeJS.ErrnoException {
  const message = `${code}: ${syscall} '${targetPath}'`;
  const error = new Error(message) as NodeJS.ErrnoException;
  error.code = code;
  error.errno = errno;
  error.syscall = syscall;
  error.path = targetPath;
  return error;
}

function errnoNumber(code: FsErrno): number {
  return code === "ENOENT" ? ERRNO.ENOENT : ERRNO.EACCES;
}

function isNoEntryError(err: unknown): boolean {
  if (!err || typeof err !== "object") {
    return false;
  }
  const e = err as { code?: unknown; errno?: unknown };
  return e.code === "ENOENT" || e.errno === ERRNO.ENOENT;
}

// ---------------------------------------------------------------------------
// Path helpers
// ---------------------------------------------------------------------------

/**
 * Strips the leading `/` a `normalizeGuestPath`-normalized absolute path
 * always carries, producing the mount-root-relative shape
 * `src/vfs/policy.ts`'s `matchRule`/`decideFsAccessForPath`/
 * `ruleMayMatchUnderDirectory`/`isEntryHidden` all require (root itself
 * becomes `""`, matching `matchRule`'s doc comment).
 */
function toRulePath(normalizedAbs: string): string {
  return normalizedAbs === "/" ? "" : normalizedAbs.slice(1);
}

/**
 * Joins a rule-relative parent directory path with one child entry name,
 * without ever producing the `//`-shaped join `src/vfs/glob.ts`'s own module
 * comment documents (the top-level plan's §6.2: `readdir` joining with the
 * raw template `${path}/${name}` produces `//` whenever `path` is the root).
 * Avoided by construction here — no `/` separator is ever inserted when
 * `parentRulePath` is the empty (root) string — rather than produced and
 * then cleaned up by a second `normalizeGuestPath` pass.
 */
function joinRulePath(parentRulePath: string, name: string): string {
  return parentRulePath === "" ? name : `${parentRulePath}/${name}`;
}

/** Splits a `normalizeGuestPath`-normalized absolute path into its parent directory and final segment, both still in normalized-absolute form. */
function splitAbs(normalizedAbs: string): { parent: string; base: string } {
  if (normalizedAbs === "/") {
    return { parent: "/", base: "" };
  }
  return { parent: path.posix.dirname(normalizedAbs), base: path.posix.basename(normalizedAbs) };
}

/** Rejoins a resolved parent directory (normalized-absolute) with a literal final segment, again without a `//`-producing join at the root. */
function joinAbs(normalizedParent: string, base: string): string {
  return normalizedParent === "/" ? `/${base}` : `${normalizedParent}/${base}`;
}

// ---------------------------------------------------------------------------
// Minimal structural types for dynamic dispatch
// ---------------------------------------------------------------------------

// `withGlobPolicy<P extends object>` accepts *any* object as `backend` (the
// plan's own signature), so this module cannot statically type every method
// call against the real `VirtualProvider` type without narrowing `P` in a
// way the plan's signature doesn't ask for. Internally, it works against a
// small structural view instead, dispatching by property name at runtime —
// exactly what the fail-closed `get`-trap default (see `withGlobPolicy`
// below) exists to make safe: any property this module doesn't explicitly
// know about never reaches `backend` at all.
// eslint-disable-next-line @typescript-eslint/no-explicit-any -- deliberate: see the module comment above.
type AnyFn = (...args: any[]) => any;
type ProviderLike = Record<string, unknown>;

interface FileHandleLike {
  truncate(len?: number): Promise<void>;
  truncateSync(len?: number): void;
  close(): Promise<void>;
  closeSync(): void;
}

// ---------------------------------------------------------------------------
// withGlobPolicy
// ---------------------------------------------------------------------------

/**
 * Wraps `backend` (a `VirtualProvider` for one mounted directory) in a
 * `Proxy` that enforces `opts.rules` against every real VFS call before it
 * reaches `backend`, per `docs/design.md` §3. See the top of this file for
 * the investigation findings and design departures that shaped the
 * implementation below.
 *
 * Structured as a `Proxy` rather than a `VirtualProviderClass` subclass —
 * per the top-level plan's own reasoning, this sidesteps `gondolin-notes.md`
 * R13 ("confirm `VirtualProviderClass` delegates unoverridden methods
 * correctly") entirely for *this* module's own code: an explicit `get`-trap
 * table with a fail-closed default has no "did I forget to override
 * something" failure mode the way a partial subclass override would.
 */
export function withGlobPolicy<P extends object>(backend: P, opts: GlobPolicyOptions): P {
  const rules = opts.rules;
  const onDeny = opts.onDeny;
  const backendAny = backend as ProviderLike;

  // The symlink-bypass defense (`resolveForRecheck`/`resolveForRecheckSync`
  // below) has no way to function without a real `realpath`/`realpathSync`
  // on the backend — finding #4 above confirms `RealFSProvider` (the real
  // backend Corb mounts) has both. Failing loudly here, once, at
  // construction time, is a stronger and more debuggable guarantee than
  // failing per-call: a backend missing either method would otherwise make
  // *every single operation* deny (since "the resolver cannot answer" must
  // fail closed, per `docs/design.md` §3), which would look like a policy
  // bug rather than what it actually is — a backend that cannot support
  // this wrapper's core security property at all.
  if (typeof backendAny.realpath !== "function" || typeof backendAny.realpathSync !== "function") {
    throw new Error(
      "withGlobPolicy: backend must implement both realpath and realpathSync. " +
        "The symlink-bypass defense (docs/design.md §3, 'Check the resolved " +
        "path, not just the requested one') has no way to function without " +
        "them — RealFSProvider (the real backend Corb mounts) implements both.",
    );
  }
  // Deliberately *not* extracted into standalone `const` bindings
  // (`const backendRealpath = backendAny.realpath`): doing so would drop
  // `this`, since `FakeVirtualProvider`/`RealFSProvider`'s own `realpath`
  // implementations close over instance state (`this.lookup`/`this.#rootPath`)
  // — calling a bare extracted function reference invokes it with
  // `this === undefined`, throwing a `TypeError` that this module's own
  // fail-closed `realpath`-error handling would then (correctly, but
  // needlessly) treat as "the resolver could not answer" and deny
  // everything. `(backendAny.realpath as AnyFn)(...)` at each call site
  // instead keeps the call in member-expression form (`obj.method(...)`),
  // which preserves `this` binding even through a parenthesized type
  // assertion — verified interactively: `(obj.method)()` keeps `this`,
  // extracting `const fn = obj.method; fn()` does not.

  const shadowStore = new MemoryProvider();
  const shadowAny = shadowStore as unknown as ProviderLike;

  // ---------------------------------------------------------------------
  // Core decision pipeline
  // ---------------------------------------------------------------------

  type Mode = "allow" | "shadowed";

  function auditAndThrow(op: FsOpKind | "unknown-operation", syscall: string, rulePath: string, outcome: FsAccessOutcome & { kind: "deny" }, rule: GlobRule | undefined, reason: string): never {
    onDeny({ path: rulePath, op, outcome, rule, reason });
    throw makeErrnoError(errnoNumber(outcome.errno), outcome.errno, syscall, rulePath);
  }

  /**
   * Resolves the rule-relative path to re-check the same operation against,
   * per `docs/design.md` §3's "Check the resolved path, not just the
   * requested one." `createPath` selects which of the two documented shapes
   * applies: a non-create-path operation resolves the path itself (it is
   * expected to already exist); a create-path operation resolves the
   * *parent* directory instead (the leaf legitimately does not exist yet)
   * and reattaches the literal final segment, per that section's own
   * parenthetical ("...or of its parent, for operations that create").
   *
   * Returns `undefined` when the recheck should be skipped outright: an
   * `ENOENT` from `realpath` here means either "this create-path's parent
   * doesn't exist either" (harmless — the real operation will fail on its
   * own, unrelated to policy) or "this non-create-path's target doesn't
   * exist" (equally harmless and equally not this module's job to report —
   * the backend's own real call will surface its own, correct `ENOENT`).
   * Any *other* `realpath` error fails closed by throwing directly (not
   * returning), per `docs/design.md` §3: "A resolver that cannot answer is
   * not evidence that the path is safe."
   */
  async function resolveForRecheck(normalizedAbs: string, createPath: boolean, op: FsOpKind, syscall: string): Promise<string | undefined> {
    const target = createPath ? splitAbs(normalizedAbs).parent : normalizedAbs;
    let resolved: string;
    try {
      resolved = await (backendAny.realpath as AnyFn)(target);
    } catch (err) {
      if (isNoEntryError(err)) {
        return undefined;
      }
      const rulePath = toRulePath(normalizedAbs);
      auditAndThrow(op, syscall, rulePath, { kind: "deny", errno: "EACCES" }, undefined, "realpath could not resolve this path while checking for symlink indirection; failing closed");
    }
    const resolvedNormalized = normalizeGuestPath(resolved);
    if (createPath) {
      const { base } = splitAbs(normalizedAbs);
      return toRulePath(joinAbs(resolvedNormalized, base));
    }
    return toRulePath(resolvedNormalized);
  }

  /** Synchronous twin of `resolveForRecheck`, using `realpathSync`. */
  function resolveForRecheckSync(normalizedAbs: string, createPath: boolean, op: FsOpKind, syscall: string): string | undefined {
    const target = createPath ? splitAbs(normalizedAbs).parent : normalizedAbs;
    let resolved: string;
    try {
      resolved = (backendAny.realpathSync as AnyFn)(target);
    } catch (err) {
      if (isNoEntryError(err)) {
        return undefined;
      }
      const rulePath = toRulePath(normalizedAbs);
      auditAndThrow(op, syscall, rulePath, { kind: "deny", errno: "EACCES" }, undefined, "realpath could not resolve this path while checking for symlink indirection; failing closed");
    }
    const resolvedNormalized = normalizeGuestPath(resolved);
    if (createPath) {
      const { base } = splitAbs(normalizedAbs);
      return toRulePath(joinAbs(resolvedNormalized, base));
    }
    return toRulePath(resolvedNormalized);
  }

  /**
   * The single entry point every gated operation funnels through: decides
   * against the requested path, then (if not already denied) against the
   * resolved path too, auditing and throwing on the first denial found —
   * requested path first, resolved path second. Returns `"allow"` or
   * `"shadowed"` — a plain-allow caller proceeds against `backend`, a
   * `"shadowed"` caller proceeds against the private shadow store instead.
   *
   * `createPath` must reflect whether the *specific* path passed here is
   * expected to already exist (`false`) or may not (`true`) — see
   * `resolveForRecheck`'s own doc comment. Each call site documents its own
   * choice inline.
   */
  async function decide(op: FsOpKind, syscall: string, normalizedAbs: string, createPath: boolean): Promise<Mode> {
    const rulePath = toRulePath(normalizedAbs);
    const primary = decideFsAccessForPath(rules, rulePath, op);
    if (primary.outcome.kind === "deny") {
      auditAndThrow(op, syscall, rulePath, primary.outcome, primary.rule, primary.rule?.reason ?? "denied by policy");
    }
    const resolvedRulePath = await resolveForRecheck(normalizedAbs, createPath, op, syscall);
    if (resolvedRulePath !== undefined) {
      const resolved = decideFsAccessForPath(rules, resolvedRulePath, op);
      if (resolved.outcome.kind === "deny") {
        auditAndThrow(op, syscall, rulePath, resolved.outcome, resolved.rule, `${resolved.rule?.reason ?? "denied by policy"} (via resolved path '${resolvedRulePath}')`);
      }
      if (resolved.outcome.kind === "shadowed") {
        onDeny({ path: rulePath, op, outcome: resolved.outcome, rule: resolved.rule, reason: resolved.rule?.reason ?? "shadowed" });
        return "shadowed";
      }
    }
    if (primary.outcome.kind === "shadowed") {
      onDeny({ path: rulePath, op, outcome: primary.outcome, rule: primary.rule, reason: primary.rule?.reason ?? "shadowed" });
      return "shadowed";
    }
    return "allow";
  }

  /** Synchronous twin of `decide`. */
  function decideSync(op: FsOpKind, syscall: string, normalizedAbs: string, createPath: boolean): Mode {
    const rulePath = toRulePath(normalizedAbs);
    const primary = decideFsAccessForPath(rules, rulePath, op);
    if (primary.outcome.kind === "deny") {
      auditAndThrow(op, syscall, rulePath, primary.outcome, primary.rule, primary.rule?.reason ?? "denied by policy");
    }
    const resolvedRulePath = resolveForRecheckSync(normalizedAbs, createPath, op, syscall);
    if (resolvedRulePath !== undefined) {
      const resolved = decideFsAccessForPath(rules, resolvedRulePath, op);
      if (resolved.outcome.kind === "deny") {
        auditAndThrow(op, syscall, rulePath, resolved.outcome, resolved.rule, `${resolved.rule?.reason ?? "denied by policy"} (via resolved path '${resolvedRulePath}')`);
      }
      if (resolved.outcome.kind === "shadowed") {
        onDeny({ path: rulePath, op, outcome: resolved.outcome, rule: resolved.rule, reason: resolved.rule?.reason ?? "shadowed" });
        return "shadowed";
      }
    }
    if (primary.outcome.kind === "shadowed") {
      onDeny({ path: rulePath, op, outcome: primary.outcome, rule: primary.rule, reason: primary.rule?.reason ?? "shadowed" });
      return "shadowed";
    }
    return "allow";
  }

  function denyUnknownOperation(propertyName: string): never {
    onDeny({
      path: "",
      op: "unknown-operation",
      outcome: { kind: "deny", errno: "EACCES" },
      rule: undefined,
      reason: `'${propertyName}' is not a VirtualProvider member this policy wrapper recognizes`,
    });
    throw makeErrnoError(ERRNO.EPERM, "EPERM", propertyName, "");
  }

  /**
   * Swallows an `ENOENT` from the shadow store specifically — the pattern
   * the SDK's own `ShadowProvider.rmdir`/`.unlink` use (`isNoEntryError` in
   * `shadow.js`) for the exact same problem: a mutation targeting a path
   * that was never previously shadow-written has nothing to remove from the
   * (real, but ephemeral and otherwise-empty) shadow store, yet must still
   * "appear to succeed" per `docs/design.md` §3. Any other error propagates.
   */
  async function tolerateMissingShadowEntry(fn: () => Promise<unknown>): Promise<void> {
    try {
      await fn();
    } catch (err) {
      if (!isNoEntryError(err)) {
        throw err;
      }
    }
  }

  function tolerateMissingShadowEntrySync(fn: () => unknown): void {
    try {
      fn();
    } catch (err) {
      if (!isNoEntryError(err)) {
        throw err;
      }
    }
  }

  // ---------------------------------------------------------------------
  // Shadow-store fallback for link() — see the module comment's "Why not
  // ShadowProvider" section for why hard-link identity is not preserved in
  // the fallback case, and why that is an acceptable, documented tradeoff:
  // the security property this row exists for (the call never reaches the
  // real backend and never creates a persistent, ungated alias to it) holds
  // either way.
  // ---------------------------------------------------------------------

  async function linkShadowed(existingNorm: string, newNorm: string): Promise<void> {
    try {
      await (shadowAny.link as AnyFn)(existingNorm, newNorm);
      return;
    } catch (err) {
      if (!isNoEntryError(err)) {
        throw err;
      }
    }
    let content: unknown;
    if (typeof backendAny.readFile === "function") {
      try {
        content = await (backendAny.readFile as AnyFn)(existingNorm);
      } catch {
        // fall through to the shadow-store read below
      }
    }
    if (content === undefined) {
      content = await (shadowAny.readFile as AnyFn)(existingNorm);
    }
    await (shadowAny.writeFile as AnyFn)(newNorm, content);
  }

  function linkShadowedSync(existingNorm: string, newNorm: string): void {
    try {
      (shadowAny.linkSync as AnyFn)(existingNorm, newNorm);
      return;
    } catch (err) {
      if (!isNoEntryError(err)) {
        throw err;
      }
    }
    let content: unknown;
    if (typeof backendAny.readFileSync === "function") {
      try {
        content = (backendAny.readFileSync as AnyFn)(existingNorm);
      } catch {
        // fall through to the shadow-store read below
      }
    }
    if (content === undefined) {
      content = (shadowAny.readFileSync as AnyFn)(existingNorm);
    }
    (shadowAny.writeFileSync as AnyFn)(newNorm, content);
  }

  // ---------------------------------------------------------------------
  // Directory-rename subtree coverage (`docs/design.md` §3, part 3)
  // ---------------------------------------------------------------------

  /**
   * `true` if `oldNorm` both (a) names a real directory on the backend and
   * (b) could contain a rule-matched descendant. A `stat`/`lstat` failure
   * other than `ENOENT` fails closed (cannot rule out the risk); `ENOENT`
   * means the source doesn't exist at all, in which case the real
   * `rename()` call below will fail on its own with the correct error, and
   * there is no subtree to protect.
   */
  async function isDeniedDirectoryRename(oldNorm: string, syscall: string): Promise<boolean> {
    const rulePath = toRulePath(oldNorm);
    let isDirectory: boolean;
    try {
      const st = (await (backendAny.lstat as AnyFn)(oldNorm)) as { isDirectory(): boolean };
      isDirectory = st.isDirectory();
    } catch (err) {
      if (isNoEntryError(err)) {
        return false;
      }
      auditAndThrow("rename", syscall, rulePath, { kind: "deny", errno: "EACCES" }, undefined, "could not stat the rename source to check for a rule-matched subtree; failing closed");
    }
    return isDirectory && ruleMayMatchUnderDirectory(rules, rulePath);
  }

  function isDeniedDirectoryRenameSync(oldNorm: string, syscall: string): boolean {
    const rulePath = toRulePath(oldNorm);
    let isDirectory: boolean;
    try {
      const st = (backendAny.lstatSync as AnyFn)(oldNorm) as { isDirectory(): boolean };
      isDirectory = st.isDirectory();
    } catch (err) {
      if (isNoEntryError(err)) {
        return false;
      }
      auditAndThrow("rename", syscall, rulePath, { kind: "deny", errno: "EACCES" }, undefined, "could not stat the rename source to check for a rule-matched subtree; failing closed");
    }
    return isDirectory && ruleMayMatchUnderDirectory(rules, rulePath);
  }

  function denyDirectoryRenameSubtree(oldNorm: string, syscall: string): never {
    const rulePath = toRulePath(oldNorm);
    auditAndThrow("rename", syscall, rulePath, { kind: "deny", errno: "EACCES" }, undefined, "renaming this directory would relocate a rule-matched subtree out from under its rule");
  }

  // ---------------------------------------------------------------------
  // access() bitmask decoding
  // ---------------------------------------------------------------------

  /**
   * Decodes a POSIX `access(2)`-style mode bitmask into the `FsOpKind`
   * categories it asks about, per `src/vfs/policy.ts`'s own documented
   * split (`access-exists`/`access-read`/`access-write`; `X_OK` folds into
   * `access-read`, per that module's own reasoning). `mode === undefined`
   * (or `F_OK`, numerically `0`) asks only about existence — Node's own
   * `fs.access` treats an omitted mode as `F_OK`.
   */
  function accessCategories(mode: number | undefined): FsOpKind[] {
    const m = mode ?? fsConstants.F_OK;
    if (m === fsConstants.F_OK) {
      return ["access-exists"];
    }
    const categories: FsOpKind[] = [];
    if ((m & fsConstants.R_OK) !== 0 || (m & fsConstants.X_OK) !== 0) {
      categories.push("access-read");
    }
    if ((m & fsConstants.W_OK) !== 0) {
      categories.push("access-write");
    }
    return categories.length > 0 ? categories : ["access-exists"];
  }

  // =======================================================================
  // Gated operations
  // =======================================================================

  async function open(rawPath: string, flags: string, mode?: number): Promise<unknown> {
    const normalized = normalizeGuestPath(rawPath);
    const op: FsOpKind = isWriteFlag(flags) ? "write" : "read";
    // 'w'/'a'-family flags always imply O_CREAT in Node's flag-string
    // convention (unlike 'r+', which requires the target to already exist)
    // — see the module comment on `isWriteFlag` vs. this create-path check.
    const createPath = /[wa]/.test(flags);
    const decision = await decide(op, "open", normalized, createPath);
    if (decision === "shadowed") {
      return (shadowAny.open as AnyFn)(normalized, flags, mode);
    }
    return (backendAny.open as AnyFn)(normalized, flags, mode);
  }

  function openSync(rawPath: string, flags: string, mode?: number): unknown {
    const normalized = normalizeGuestPath(rawPath);
    const op: FsOpKind = isWriteFlag(flags) ? "write" : "read";
    const createPath = /[wa]/.test(flags);
    const decision = decideSync(op, "open", normalized, createPath);
    if (decision === "shadowed") {
      return (shadowAny.openSync as AnyFn)(normalized, flags, mode);
    }
    return (backendAny.openSync as AnyFn)(normalized, flags, mode);
  }

  /** `stat`/`lstat` never shadow (`TABLE.stat` is `ALLOW` in every mode including `shadow-write`) — always routes to `backend` once `decide` doesn't throw. Kept generic (branches on `decision` anyway) so a future table change can't silently start leaking to the wrong backend. */
  function makeStatLike(methodName: "stat" | "lstat") {
    return async function statLike(rawPath: string, options?: object): Promise<unknown> {
      const normalized = normalizeGuestPath(rawPath);
      const decision = await decide("stat", methodName, normalized, false);
      const target = decision === "shadowed" ? shadowAny : backendAny;
      return (target[methodName] as AnyFn)(normalized, options);
    };
  }
  function makeStatLikeSync(methodName: "statSync" | "lstatSync") {
    return function statLikeSync(rawPath: string, options?: object): unknown {
      const normalized = normalizeGuestPath(rawPath);
      const decision = decideSync("stat", methodName, normalized, false);
      const target = decision === "shadowed" ? shadowAny : backendAny;
      return (target[methodName] as AnyFn)(normalized, options);
    };
  }

  async function readdir(rawPath: string, options?: object): Promise<unknown> {
    const normalized = normalizeGuestPath(rawPath);
    const decision = await decide("read", "readdir", normalized, false);
    const target = decision === "shadowed" ? shadowAny : backendAny;
    const entries = (await (target.readdir as AnyFn)(normalized, options)) as Array<string | { name: string }>;
    const dirRulePath = toRulePath(normalized);
    return entries.filter((entry) => {
      const name = typeof entry === "string" ? entry : entry.name;
      return !isEntryHidden(rules, joinRulePath(dirRulePath, name));
    });
  }

  function readdirSync(rawPath: string, options?: object): unknown {
    const normalized = normalizeGuestPath(rawPath);
    const decision = decideSync("read", "readdirSync", normalized, false);
    const target = decision === "shadowed" ? shadowAny : backendAny;
    const entries = (target.readdirSync as AnyFn)(normalized, options) as Array<string | { name: string }>;
    const dirRulePath = toRulePath(normalized);
    return entries.filter((entry) => {
      const name = typeof entry === "string" ? entry : entry.name;
      return !isEntryHidden(rules, joinRulePath(dirRulePath, name));
    });
  }

  function makeMutateLike(methodName: "mkdir" | "rmdir" | "unlink", createPath: boolean) {
    return async function mutateLike(rawPath: string, options?: object): Promise<unknown> {
      const normalized = normalizeGuestPath(rawPath);
      const decision = await decide("mutate", methodName, normalized, createPath);
      if (decision === "shadowed") {
        if (methodName === "mkdir") {
          return (shadowAny.mkdir as AnyFn)(normalized, options);
        }
        let result: unknown;
        await tolerateMissingShadowEntry(async () => {
          result = await (shadowAny[methodName] as AnyFn)(normalized);
        });
        return result;
      }
      return (backendAny[methodName] as AnyFn)(normalized, options);
    };
  }
  function makeMutateLikeSync(methodName: "mkdirSync" | "rmdirSync" | "unlinkSync", createPath: boolean) {
    return function mutateLikeSync(rawPath: string, options?: object): unknown {
      const normalized = normalizeGuestPath(rawPath);
      const decision = decideSync("mutate", methodName, normalized, createPath);
      if (decision === "shadowed") {
        if (methodName === "mkdirSync") {
          return (shadowAny.mkdirSync as AnyFn)(normalized, options);
        }
        let result: unknown;
        tolerateMissingShadowEntrySync(() => {
          result = (shadowAny[methodName] as AnyFn)(normalized);
        });
        return result;
      }
      return (backendAny[methodName] as AnyFn)(normalized, options);
    };
  }

  async function rename(rawOld: string, rawNew: string): Promise<void> {
    const oldNorm = normalizeGuestPath(rawOld);
    const newNorm = normalizeGuestPath(rawNew);
    // Source is expected to exist; destination may or may not (POSIX rename
    // permits overwriting an existing destination), so it is treated as a
    // create-path for the bypass recheck — the more conservative of the two
    // readings, since a symlinked ancestor redirecting the destination is
    // the concerning case regardless of whether the leaf itself pre-exists.
    const oldMode = await decide("rename", "rename", oldNorm, false);
    const newMode = await decide("rename", "rename", newNorm, true);
    if (await isDeniedDirectoryRename(oldNorm, "rename")) {
      denyDirectoryRenameSubtree(oldNorm, "rename");
    }
    if (oldMode === "shadowed" || newMode === "shadowed") {
      return tolerateMissingShadowEntry(() => (shadowAny.rename as AnyFn)(oldNorm, newNorm));
    }
    return (backendAny.rename as AnyFn)(oldNorm, newNorm);
  }

  function renameSync(rawOld: string, rawNew: string): void {
    const oldNorm = normalizeGuestPath(rawOld);
    const newNorm = normalizeGuestPath(rawNew);
    const oldMode = decideSync("rename", "renameSync", oldNorm, false);
    const newMode = decideSync("rename", "renameSync", newNorm, true);
    if (isDeniedDirectoryRenameSync(oldNorm, "renameSync")) {
      denyDirectoryRenameSubtree(oldNorm, "renameSync");
    }
    if (oldMode === "shadowed" || newMode === "shadowed") {
      tolerateMissingShadowEntrySync(() => (shadowAny.renameSync as AnyFn)(oldNorm, newNorm));
      return;
    }
    (backendAny.renameSync as AnyFn)(oldNorm, newNorm);
  }

  async function link(rawExisting: string, rawNew: string): Promise<void> {
    const existingNorm = normalizeGuestPath(rawExisting);
    const newNorm = normalizeGuestPath(rawNew);
    // Both endpoints are gated under the same "link" category, per
    // `docs/design.md` §3: "creating a new, unrestricted name for a
    // restricted inode is exactly the bypass to prevent" — the existing
    // path's own rule matters as much as the new path's.
    const existingMode = await decide("link", "link", existingNorm, false);
    const newMode = await decide("link", "link", newNorm, true);
    if (existingMode === "shadowed" || newMode === "shadowed") {
      return linkShadowed(existingNorm, newNorm);
    }
    return (backendAny.link as AnyFn)(existingNorm, newNorm);
  }

  function linkSync(rawExisting: string, rawNew: string): void {
    const existingNorm = normalizeGuestPath(rawExisting);
    const newNorm = normalizeGuestPath(rawNew);
    const existingMode = decideSync("link", "linkSync", existingNorm, false);
    const newMode = decideSync("link", "linkSync", newNorm, true);
    if (existingMode === "shadowed" || newMode === "shadowed") {
      linkShadowedSync(existingNorm, newNorm);
      return;
    }
    (backendAny.linkSync as AnyFn)(existingNorm, newNorm);
  }

  async function readlink(rawPath: string, options?: object): Promise<unknown> {
    const normalized = normalizeGuestPath(rawPath);
    const decision = await decide("readlink", "readlink", normalized, false);
    const target = decision === "shadowed" ? shadowAny : backendAny;
    return (target.readlink as AnyFn)(normalized, options);
  }
  function readlinkSync(rawPath: string, options?: object): unknown {
    const normalized = normalizeGuestPath(rawPath);
    const decision = decideSync("readlink", "readlinkSync", normalized, false);
    const target = decision === "shadowed" ? shadowAny : backendAny;
    return (target.readlinkSync as AnyFn)(normalized, options);
  }

  /**
   * Resolves a `symlink()` call's raw `target` argument into the normalized-
   * absolute VFS path it would point to, for `checkSymlinkTargetPolicy`
   * below. Deliberately *not* run through `normalizeGuestPath`: `target` is
   * not "a path as received by a `VirtualProvider` method" the way every
   * other raw argument in this file is (see the doc comment below on why
   * only `path` is gated) — a relative target legitimately containing `..`
   * (`ln -s ../shared/lib.so`) is ordinary POSIX symlink usage, not a
   * traversal attempt, so `normalizeGuestPath`'s fail-closed `..` rejection
   * does not apply here. `path.posix.normalize` resolves it the same way the
   * guest kernel's own dereference eventually would (and, like the guest
   * kernel, clamps a `..`-above-root target to the root rather than escaping
   * it).
   */
  function resolveSymlinkTargetAbs(normalizedSymlinkPath: string, target: string): string {
    const raw = target;
    const abs = raw.startsWith("/") ? raw : path.posix.join(path.posix.dirname(normalizedSymlinkPath), raw);
    return path.posix.normalize(abs);
  }

  /**
   * Verified empirically (a fresh scratch-VM boot, `onDeny` wired to
   * `console.log`) that leaving this to the RPC layer's own post-creation
   * `lstat` is not just a cosmetic gap: `rpc-service.js`'s `handleSymlink`
   * calls `provider.symlink()` first — which this module's own `decide()`
   * call below *allows* for a `hidden`-target case, since only the new
   * entry's own name (not what it points to) is checked there, so a real
   * symlink lands on the real backend — and only then calls
   * `this.provider.lstat(entryPath)` to build the FUSE reply, which is what
   * actually denies (via this module's own resolved-path recheck following
   * the now-real symlink to its hidden target). That throw happens *before*
   * `rpc-service.js`'s own `ensureIno()`/`invalidateReaddirCacheEntries()`
   * calls one line later, leaving a real, ino-less symlink on the backend
   * that the RPC service's own bookkeeping never learned about. Once that
   * directory's `readdirCache` entry naturally expires (`READDIR_CACHE_TTL_MS`,
   * 5s) and a fresh `readdir` re-enumerates it, this orphaned entry corrupts
   * the guest-visible `readdir`/`lookup` handshake: every subsequent `ls` of
   * that directory returns permanently empty (confirmed: 0 bytes, exit 0,
   * does not self-heal, survives a brand-new file being added directly on
   * the host) until the VM is recreated.
   *
   * The fix is to make the same decision `rpc-service.js`'s post-creation
   * `lstat` would make, but *before* ever calling `backend.symlink()`, so a
   * denied target never gets a real backend entry created for it at all —
   * exactly like `link()` already gates its existing endpoint before ever
   * creating a real hard link (see that function's own comment). Checked
   * against the `"stat"` category specifically, because that is the actual
   * operation the RPC layer's post-creation fetch performs — this is why a
   * `deny-read`-covered target (`TABLE.stat` is `ALLOW`) still creates
   * cleanly here, matching the already-documented, already-tested "creation
   * succeeds, the *read* is what's denied" behavior for that case; only a
   * `hidden` target (`TABLE.stat` is `ENOENT`) is caught by this check.
   * `resolveForRecheck` returning `undefined` (a dangling target, or a
   * target whose parent doesn't exist) means there is nothing to deny —
   * dangling symlinks are ordinary and harmless, matching every other
   * ENOENT-from-realpath case in this file.
   */
  async function checkSymlinkTargetPolicy(normalizedSymlinkPath: string, target: string, syscall: string): Promise<void> {
    const targetAbs = resolveSymlinkTargetAbs(normalizedSymlinkPath, target);
    const targetRulePath = await resolveForRecheck(targetAbs, false, "stat", syscall);
    if (targetRulePath === undefined) {
      return;
    }
    const targetDecision = decideFsAccessForPath(rules, targetRulePath, "stat");
    if (targetDecision.outcome.kind === "deny") {
      auditAndThrow(
        "stat",
        syscall,
        targetRulePath,
        targetDecision.outcome,
        targetDecision.rule,
        `${targetDecision.rule?.reason ?? "denied by policy"} (symlink target resolves into a policy-denied path)`,
      );
    }
  }
  function checkSymlinkTargetPolicySync(normalizedSymlinkPath: string, target: string, syscall: string): void {
    const targetAbs = resolveSymlinkTargetAbs(normalizedSymlinkPath, target);
    const targetRulePath = resolveForRecheckSync(targetAbs, false, "stat", syscall);
    if (targetRulePath === undefined) {
      return;
    }
    const targetDecision = decideFsAccessForPath(rules, targetRulePath, "stat");
    if (targetDecision.outcome.kind === "deny") {
      auditAndThrow(
        "stat",
        syscall,
        targetRulePath,
        targetDecision.outcome,
        targetDecision.rule,
        `${targetDecision.rule?.reason ?? "denied by policy"} (symlink target resolves into a policy-denied path)`,
      );
    }
  }

  async function symlink(target: string, rawPath: string, type?: string): Promise<unknown> {
    // `target` is an arbitrary string the provider never resolves as a VFS
    // path (`src/vfs/policy.ts`'s own doc comment on the `"link"` category)
    // — only `path`, where the new symlink entry is created, is gated
    // against its own name by `decide()` below. `checkSymlinkTargetPolicy`
    // additionally gates what `target` resolves *into* — see that function's
    // own doc comment for why this is not redundant with `decide()`.
    const normalized = normalizeGuestPath(rawPath);
    const decision = await decide("link", "symlink", normalized, true);
    await checkSymlinkTargetPolicy(normalized, target, "symlink");
    if (decision === "shadowed") {
      return (shadowAny.symlink as AnyFn)(target, normalized, type);
    }
    return (backendAny.symlink as AnyFn)(target, normalized, type);
  }
  function symlinkSync(target: string, rawPath: string, type?: string): unknown {
    const normalized = normalizeGuestPath(rawPath);
    const decision = decideSync("link", "symlinkSync", normalized, true);
    checkSymlinkTargetPolicySync(normalized, target, "symlinkSync");
    if (decision === "shadowed") {
      return (shadowAny.symlinkSync as AnyFn)(target, normalized, type);
    }
    return (backendAny.symlinkSync as AnyFn)(target, normalized, type);
  }

  /** Guest-facing `realpath`/`realpathSync` — distinct from this closure's own *internal* `resolveForRecheck`/`resolveForRecheckSync` defensive helpers above, which call `backendRealpath`/`backendRealpathSync` directly (unwrapped, no policy decision) purely to detect symlink indirection for every *other* operation. This pair is the actual guest-visible operation, gated like any other: `TABLE.realpath` never shadows (canonicalizing a path's spelling discloses existence and shape, not content — see `src/vfs/policy.ts`'s own reasoning), so it always ends up delegating to `backend` once `decide` doesn't throw. */
  async function realpath(rawPath: string, options?: object): Promise<unknown> {
    const normalized = normalizeGuestPath(rawPath);
    const decision = await decide("realpath", "realpath", normalized, false);
    const target = decision === "shadowed" ? shadowAny : backendAny;
    return (target.realpath as AnyFn)(normalized, options);
  }
  function realpathSync(rawPath: string, options?: object): unknown {
    const normalized = normalizeGuestPath(rawPath);
    const decision = decideSync("realpath", "realpathSync", normalized, false);
    const target = decision === "shadowed" ? shadowAny : backendAny;
    return (target.realpathSync as AnyFn)(normalized, options);
  }

  async function access(rawPath: string, mode?: number): Promise<void> {
    const normalized = normalizeGuestPath(rawPath);
    // None of the access-* categories ever yields "shadowed" (`W_OK`'s
    // shadow-write column is `ALLOW`, per `src/vfs/policy.ts`'s own
    // reasoning: "access is a pure permission query... the truthful answer
    // under shadow-write is allow"), so every category here only ever
    // contributes a possible deny (via `decide`'s own throw) or nothing.
    for (const category of accessCategories(mode)) {
      await decide(category, "access", normalized, false);
    }
    return (backendAny.access as AnyFn)(normalized, mode);
  }
  function accessSync(rawPath: string, mode?: number): void {
    const normalized = normalizeGuestPath(rawPath);
    for (const category of accessCategories(mode)) {
      decideSync(category, "accessSync", normalized, false);
    }
    (backendAny.accessSync as AnyFn)(normalized, mode);
  }

  async function copyFile(rawSrc: string, rawDest: string, mode?: number): Promise<void> {
    const srcNorm = normalizeGuestPath(rawSrc);
    const destNorm = normalizeGuestPath(rawDest);
    await decide("copy-source", "copyFile", srcNorm, false);
    const destMode = await decide("copy-dest", "copyFile", destNorm, true);
    if (destMode === "shadowed") {
      const content = await (backendAny.readFile as AnyFn)(srcNorm);
      await (shadowAny.writeFile as AnyFn)(destNorm, content);
      return;
    }
    return (backendAny.copyFile as AnyFn)(srcNorm, destNorm, mode);
  }
  function copyFileSync(rawSrc: string, rawDest: string, mode?: number): void {
    const srcNorm = normalizeGuestPath(rawSrc);
    const destNorm = normalizeGuestPath(rawDest);
    decideSync("copy-source", "copyFileSync", srcNorm, false);
    const destMode = decideSync("copy-dest", "copyFileSync", destNorm, true);
    if (destMode === "shadowed") {
      const content = (backendAny.readFileSync as AnyFn)(srcNorm);
      (shadowAny.writeFileSync as AnyFn)(destNorm, content);
      return;
    }
    (backendAny.copyFileSync as AnyFn)(srcNorm, destNorm, mode);
  }

  function makeReadFileLike(methodName: "readFile" | "readFileSync") {
    const isAsync = methodName === "readFile";
    return isAsync
      ? async function readFileLike(rawPath: string, options?: unknown): Promise<unknown> {
          const normalized = normalizeGuestPath(rawPath);
          const decision = await decide("read", methodName, normalized, false);
          const target = decision === "shadowed" ? shadowAny : backendAny;
          return (target[methodName] as AnyFn)(normalized, options);
        }
      : function readFileLikeSync(rawPath: string, options?: unknown): unknown {
          const normalized = normalizeGuestPath(rawPath);
          const decision = decideSync("read", methodName, normalized, false);
          const target = decision === "shadowed" ? shadowAny : backendAny;
          return (target[methodName] as AnyFn)(normalized, options);
        };
  }

  function makeWriteFileLike(methodName: "writeFile" | "appendFile" | "writeFileSync" | "appendFileSync") {
    const isAsync = methodName === "writeFile" || methodName === "appendFile";
    return isAsync
      ? async function writeFileLike(rawPath: string, data: unknown, options?: unknown): Promise<unknown> {
          const normalized = normalizeGuestPath(rawPath);
          // 'writeFile'/'appendFile' both create-if-missing (base-class
          // defaults open with 'w'/'a' respectively; RealFSProvider has no
          // override for either — see finding #2 above), so both are
          // create-path operations for the bypass recheck.
          const decision = await decide("write", methodName, normalized, true);
          const target = decision === "shadowed" ? shadowAny : backendAny;
          return (target[methodName] as AnyFn)(normalized, data, options);
        }
      : function writeFileLikeSync(rawPath: string, data: unknown, options?: unknown): unknown {
          const normalized = normalizeGuestPath(rawPath);
          const decision = decideSync("write", methodName, normalized, true);
          const target = decision === "shadowed" ? shadowAny : backendAny;
          return (target[methodName] as AnyFn)(normalized, data, options);
        };
  }

  async function existsOp(rawPath: string): Promise<boolean> {
    const normalized = normalizeGuestPath(rawPath);
    try {
      const decision = await decide("exists", "exists", normalized, false);
      const target = decision === "shadowed" ? shadowAny : backendAny;
      return (await (target.exists as AnyFn)(normalized)) as boolean;
    } catch {
      // `exists()`'s guest-facing contract never throws (`src/vfs/policy.ts`'s
      // own note on `decideFsAccess`) — any denial (always `ENOENT` for this
      // category per the table) or resolver failure translates to `false`.
      return false;
    }
  }
  function existsSyncOp(rawPath: string): boolean {
    const normalized = normalizeGuestPath(rawPath);
    try {
      const decision = decideSync("exists", "existsSync", normalized, false);
      const target = decision === "shadowed" ? shadowAny : backendAny;
      return (target.existsSync as AnyFn)(normalized) as boolean;
    } catch {
      return false;
    }
  }

  async function truncateOp(rawPath: string, length: number): Promise<void> {
    const normalized = normalizeGuestPath(rawPath);
    const decision = await decide("write", "truncate", normalized, false);
    if (decision === "shadowed") {
      let handle: FileHandleLike;
      try {
        handle = (await (shadowAny.open as AnyFn)(normalized, "r+")) as FileHandleLike;
      } catch {
        // Never previously shadow-written: approximate as a fresh,
        // zero-filled file of the requested size, then truncate/extend from
        // there — the shadow store has no real content to base this on.
        await (shadowAny.writeFile as AnyFn)(normalized, Buffer.alloc(0));
        handle = (await (shadowAny.open as AnyFn)(normalized, "r+")) as FileHandleLike;
      }
      try {
        await handle.truncate(length);
      } finally {
        await handle.close();
      }
      return;
    }
    return (backendAny.truncate as AnyFn)(normalized, length);
  }
  function truncateSyncOp(rawPath: string, length: number): void {
    const normalized = normalizeGuestPath(rawPath);
    const decision = decideSync("write", "truncateSync", normalized, false);
    if (decision === "shadowed") {
      let handle: FileHandleLike;
      try {
        handle = (shadowAny.openSync as AnyFn)(normalized, "r+") as FileHandleLike;
      } catch {
        (shadowAny.writeFileSync as AnyFn)(normalized, Buffer.alloc(0));
        handle = (shadowAny.openSync as AnyFn)(normalized, "r+") as FileHandleLike;
      }
      try {
        handle.truncateSync(length);
      } finally {
        handle.closeSync();
      }
      return;
    }
    (backendAny.truncateSync as AnyFn)(normalized, length);
  }

  function makeWatchLike(methodName: "watch" | "watchAsync" | "watchFile") {
    return function watchLike(rawPath: string, options?: object, listener?: (...args: unknown[]) => void): unknown {
      const normalized = normalizeGuestPath(rawPath);
      // The whole `watch*` family is read-adjacent, never content-disclosing
      // or mutating on its own — `src/vfs/policy.ts`'s own documented
      // conclusion is to reuse `decideFsAccess(mode, "read")` wholesale
      // rather than grow a dedicated category. All four members are
      // synchronous-returning per the `VirtualProvider` type (no `Promise`),
      // so this uses `decideSync`, not `decide`.
      const decision = decideSync("read", methodName, normalized, false);
      const target = decision === "shadowed" ? shadowAny : backendAny;
      return (target[methodName] as AnyFn)(normalized, options, listener);
    };
  }
  function unwatchFile(rawPath: string, listener?: (...args: unknown[]) => void): void {
    const normalized = normalizeGuestPath(rawPath);
    const decision = decideSync("read", "unwatchFile", normalized, false);
    const target = decision === "shadowed" ? shadowAny : backendAny;
    (target.unwatchFile as AnyFn)(normalized, listener);
  }

  // =======================================================================
  // Property table and Proxy
  // =======================================================================

  // Capability getters: passed straight through, untouched — these describe
  // the backend's own capabilities, not an operation to gate.
  const passthroughCapabilities = new Set(["readonly", "supportsSymlinks", "supportsWatch"]);

  // Required VirtualProvider members: always present on any conforming
  // backend, always wrapped.
  const requiredHandlers: ProviderLike = {
    open,
    openSync,
    stat: makeStatLike("stat"),
    statSync: makeStatLikeSync("statSync"),
    lstat: makeStatLike("lstat"),
    lstatSync: makeStatLikeSync("lstatSync"),
    readdir,
    readdirSync,
    mkdir: makeMutateLike("mkdir", true),
    mkdirSync: makeMutateLikeSync("mkdirSync", true),
    rmdir: makeMutateLike("rmdir", false),
    rmdirSync: makeMutateLikeSync("rmdirSync", false),
    unlink: makeMutateLike("unlink", false),
    unlinkSync: makeMutateLikeSync("unlinkSync", false),
    rename,
    renameSync,
  };

  // Optional VirtualProvider members: this wrapper only exposes a gated
  // version when `backend` itself implements the member — a `Proxy` that
  // fabricated a function for an optional member the backend lacks would
  // make `typeof provider.foo === "function"` feature-detection (used by
  // both `mounts.js` and `rpc-service.js`, verified by reading both) lie
  // about what the backend can actually do.
  const optionalFactories: Record<string, () => unknown> = {
    link: () => link,
    linkSync: () => linkSync,
    readFile: () => makeReadFileLike("readFile"),
    readFileSync: () => makeReadFileLike("readFileSync"),
    writeFile: () => makeWriteFileLike("writeFile"),
    writeFileSync: () => makeWriteFileLike("writeFileSync"),
    appendFile: () => makeWriteFileLike("appendFile"),
    appendFileSync: () => makeWriteFileLike("appendFileSync"),
    exists: () => existsOp,
    existsSync: () => existsSyncOp,
    copyFile: () => copyFile,
    copyFileSync: () => copyFileSync,
    readlink: () => readlink,
    readlinkSync: () => readlinkSync,
    symlink: () => symlink,
    symlinkSync: () => symlinkSync,
    access: () => access,
    accessSync: () => accessSync,
    truncate: () => truncateOp,
    truncateSync: () => truncateSyncOp,
    watch: () => makeWatchLike("watch"),
    watchAsync: () => makeWatchLike("watchAsync"),
    watchFile: () => makeWatchLike("watchFile"),
    unwatchFile: () => unwatchFile,
    // `realpath`/`realpathSync` are optional per the `VirtualProvider` type,
    // but this wrapper's own constructor guard above already asserts they
    // exist on `backend` before this point is ever reached, so they are
    // unconditionally present here rather than probed for again.
    realpath: () => realpath,
    realpathSync: () => realpathSync,
    // `statfs` and `internalModuleStat` are passed straight through,
    // unquestioned: `src/vfs/policy.ts`'s own documented conclusion for
    // `statfs` is "there is nothing for a per-path rule to gate", and
    // `internalModuleStat` is a host-side module-resolution convenience
    // never invoked by the guest-facing VFS RPC dispatch (absent from
    // `rpc-service.js`'s own operation-case list, confirmed by reading it) —
    // Corb only ever hands these provider objects into `vfs.mounts` for
    // `VM.create`, never into a host-side `VirtualFileSystem` that would
    // actually call `internalModuleStat`. Gating either would be inventing
    // an opinion about a code path this wrapper cannot actually reach.
    statfs: () => (...args: unknown[]) => (backendAny.statfs as AnyFn)(...args),
    internalModuleStat: () => (...args: unknown[]) => (backendAny.internalModuleStat as AnyFn)(...args),
  };

  const handlers: ProviderLike = { ...requiredHandlers };
  for (const [name, factory] of Object.entries(optionalFactories)) {
    if (typeof backendAny[name] === "function") {
      handlers[name] = factory();
    }
  }

  return new Proxy(backend, {
    get(target, prop, receiver) {
      // Symbols (e.g. `Symbol.toPrimitive`, `util.inspect.custom`) are not
      // part of the `VirtualProvider` operation vocabulary this module has
      // an opinion about; passing them straight through avoids this
      // wrapper breaking generic JS object protocols (`util.inspect`,
      // `JSON.stringify`, etc.) that were never a security-relevant surface
      // to begin with.
      if (typeof prop === "symbol") {
        return Reflect.get(target, prop, receiver);
      }
      if (passthroughCapabilities.has(prop)) {
        return Reflect.get(target, prop, target);
      }
      if (Object.hasOwn(handlers, prop)) {
        return handlers[prop];
      }
      // A `VirtualProvider` member this module recognizes but the wrapped
      // backend does not implement (an optional method it lacks): return
      // `undefined`, matching real absence — see the comment on
      // `optionalFactories` above for why this matters for feature
      // detection elsewhere in the SDK.
      if (prop in optionalFactories) {
        return undefined;
      }
      // Anything else is a property this module has never heard of — most
      // likely a future Gondolin release adding a new VirtualProvider
      // operation. Fail loudly rather than silently pass it through
      // ungated: "a Gondolin release that adds a VFS operation fails loudly
      // instead of leaking" (the plan's own words for this exact case).
      return () => denyUnknownOperation(prop);
    },
  }) as P;
}
