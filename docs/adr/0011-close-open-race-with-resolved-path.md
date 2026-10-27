# Route the already-resolved path to the backend call, for operations where that is safe

## Status

Accepted

## Context and Problem Statement

`src/vfs/glob-policy.ts`'s `withGlobPolicy` implements the resolved-path check
from `docs/design.md` §3. `decide()`/`decideSync()` call
`resolveForRecheck()`/`resolveForRecheckSync()`. These use real
`backendAny.realpath()`/`realpathSync()` calls to recheck policy against the
symlink-resolved target rather than the literal requested path.
Without this check, `ln -s .env decoy && cat decoy` defeats the rules because
`decoy` matches nothing.

That check was already correct. The gap was discarding `resolveForRecheck`'s
resolved path after the decision. Every backend operation, such as
`backendAny.open`, `backendAny.readFile`, or `backendAny.stat`, still received
`normalized`, the original unresolved path. The real backend's `open`/`stat`
calls independently resolve that path again through real filesystem calls in
production. The `await` between the policy check and backend call yields the
event loop. A concurrent guest operation can swap a symlink during that window.

For example, consider rule `{ glob: "**/.env", mode: "deny-read" }`.
Process A loops `cat decoy`. Process B flips `decoy` between a dummy target
and `.env`. The check can resolve `decoy` to the dummy and allow access.
Before the backend opens the file, `decoy` can instead point to `.env`.
The read succeeds because `decide()` allowed the earlier target and the backend
independently opened the later target.

`docs/design.md` §3 requires a resolved-path *decision*. It does not specify
which path the *operation* must use. Discarding the resolution and sending the
original string to the backend reopens the race the resolution intends to
close.

## Decision Drivers

- If the filesystem operation resolves the original path again, the decision and operation can act on different targets.
  They must use the same resolved target for the check to protect the operation.
- Redirecting *every* operation is unsafe because some POSIX/Node.js operations must act on the *literally named* entry.
  They must never follow a trailing symlink.
  `lstat` reports on the named entry, rather than its target.
  `unlink`/`rmdir` remove the named directory entry itself.
  Redirecting them causes a **correctness/data-loss bug**: deleting or moving a real file the guest never named.
  `rename`'s source and `link`'s existing-path endpoint must rename/link the named entry, whether it is a symlink or not.
  They must never relocate its resolved target.
- `checkSymlinkTargetPolicy`/`checkSymlinkTargetPolicySync` provide a separate, already-shipped `symlink()`-target pre-creation check.
  They fix an empirically verified RPC readdir-cache-corruption issue documented in this file's module comment.
  This change must not alter or conflate that mechanism.
- `VirtualProvider` exposes no atomic resolve-and-open primitive, such as Linux `openat2(2)` with `RESOLVE_NO_SYMLINKS`.
  Every option here leaves some gap between resolution and operation.
  The goal is to narrow the gap and make exploitation harder, rather than eliminate the race.

## Considered Options

- Keep discarding `resolveForRecheck`'s resolved path after the decision (the existing bug).
- Redirect every gated operation unconditionally to the resolved path.
- Classify operations by whether their filesystem semantics follow a trailing symlink.
  Redirect the backend call only for those operations. Keep the rest on the original unresolved path.

## Decision Outcome

Chosen option: "classify each gated operation".
Unconditional redirection is unsafe for the operations identified above.
Keeping every operation on the unresolved path preserves the bug.

If an operation's filesystem semantics already follow a trailing symlink,
redirect its backend call to the computed resolution. This changes *when*
resolution happens, before the race window, without changing *what* the
operation acts on. If an operation must act on the literal named entry,
redirection changes *which real filesystem entry* it acts on. That causes the
data-loss failure described above.

For **create-path** operations whose leaf does not exist, resolve only the
*parent* directory, then reattach the unchanged literal final segment.
Existing write and copy-destination targets also resolve the leaf and may pass
that resolved path to the backend. A `rename` destination, `link` new-name,
or `symlink`'s own name always keeps its leaf literal; only its parent is resolved.

### Mechanism

`resolveForRecheck`/`resolveForRecheckSync` previously returned only the
rule-relative path (`string | undefined`) for the second policy lookup.
They discarded the computed absolute path: `resolvedNormalized`, or
`joinAbs(resolvedNormalized, base)` for a create-path operation.
They now return `RecheckResult { rulePath, absPath }
| undefined`. The `undefined`-on-`ENOENT` and fail-closed throw on every other
error remain unchanged. The result now retains `absPath`.

`decide`/`decideSync` now return `DecideResult { mode, resolvedAbs }` rather
than a bare `Mode`. If the recheck resolves a target, `resolvedAbs` contains
the recheck's `absPath`, preferring the resolved leaf for existing write and
copy-destination targets. If no recheck resolves, it contains the unchanged
original `normalizedAbs`. That means the target, or a create-path operation's
parent, does not exist yet. A missing create parent may cause the backend to
report `ENOENT` for non-recursive `mkdir`, while recursive directory creation
can create the missing parents instead.

Every call site's `if (decision === "shadowed")` became
`if (decision.mode === "shadowed")`. Calls in the redirect classification
below also use `decision.resolvedAbs` for `backendAny.<method>` instead of the
original normalized path.

Every `shadowAny.<method>` call still uses the original normalized path,
never `resolvedAbs`. The private, in-process `MemoryProvider` shadow store
has no real filesystem or symlink exposure to race against.
Only calls that reach the real `backend` need `resolvedAbs`.

### Full classification

**Redirected to the resolved path**: these operations already follow a
trailing symlink under their own semantics. Earlier resolution changes only
*when* it happens, without changing *what* the operation acts on.

| Operation | Resolved argument |
|---|---|
| `open`/`openSync` (read- and write/create-shaped alike) | the path |
| `stat`/`statSync` | the path |
| `access`/`accessSync` | the path |
| `readFile`/`readFileSync`, `writeFile`/`writeFileSync`, `appendFile`/`appendFileSync` | the path |
| `copyFile`/`copyFileSync` | the *source* argument; the destination uses `destDecision.resolvedAbs`, including destination-parent resolution |
| `truncate`/`truncateSync` (the top-level, path-based operation) | the path. Unlike `ftruncate`, POSIX `truncate(path,...)` follows a trailing symlink. |
| `readdir`/`readdirSync` | the directory argument to the backend's own `readdir` call *only*. The requested directory's rule-relative path (`dirRulePath`, used by `isEntryHidden` to test each returned entry) stays unchanged. The rule-path basis for child-entry visibility is a separate design question outside this fix. |
| `mkdir`/`mkdirSync` | the (create-path) parent |
| `symlink`/`symlinkSync` | the new symlink's own (create-path) parent. The provider still never resolves `target` itself as a VFS path. |
| `rename`/`renameSync` | the *new*/destination (create-path) parent only. The source stays unresolved, as described below. |
| `link`/`linkSync` | the *new* (create-path) parent only. The existing endpoint stays unresolved, as described below. |

**Left on the original, unresolved path**: redirecting these operations is
meaningless or unsafe.

| Operation | Why |
|---|---|
| `lstat`/`lstatSync` | It must report on the named entry itself, never its target. This is `lstat`'s purpose. |
| `unlink`/`unlinkSync`, `rmdir`/`rmdirSync` | POSIX removes the named directory entry itself without following a trailing symlink. Redirection risks deleting a real file the guest never named. This is a correctness/data-loss bug. |
| `readlink`/`readlinkSync` | It must read the named symlink's own target text. Once resolved, there is nothing to "readlink". |
| `rename`'s *source* (old) path, `link`'s *existing* path | POSIX renames/links the named entry itself, rather than its resolved target. Renaming or linking a symlink must act on that symlink without relocating its target. |
| `isDeniedDirectoryRename`'s own `lstat` call | It already correctly uses `backendAny.lstat` with the unresolved path. It must identify whether the named source itself is a real directory, without following symlinks. |
| `checkSymlinkTargetPolicy`/`checkSymlinkTargetPolicySync` | This separate, already-shipped mechanism fixes RPC readdir-cache corruption, as documented elsewhere in this file. It stays unchanged. |
| `exists`/`existsSync` | It returns only a boolean, without data exposure or mutation. It stays unchanged because it is outside this finding. |
| the `watch*` family (`watch`, `watchAsync`, `watchFile`, `unwatchFile`) | The module already documents these as read-adjacent. They disclose no content and cause no mutation, so the added surface is not worthwhile. |
| guest-facing `realpath`/`realpathSync` | Its purpose is to ask the backend to resolve the path from scratch. Passing an already-resolved path closes no relevant window. The reported entry causes no downstream content disclosure or mutation, as with `exists`. |

### Consequences

- Good, because every redirected operation now requires an attacker to race against the resolved, already-known-safe absolute path.
  Racing against the originally requested, possibly symlinked path is no longer enough.
  The Context section's `decoy`/`.env` scenario no longer works.
  `open()`'s backend call receives the already-resolved `/real/.env`-shaped path computed at decision time, rather than resolving `decoy` again.
- Good, because the classification follows each operation's documented POSIX/Node.js semantics.
  Verification checked `test/fakes/provider.ts`'s `followSymlinks` argument at each relevant `getEntry`/`lookup` call.
  It deliberately treats `unlink`/`rmdir`/`lstat`/`readlink` and rename-and-link's existing endpoint conservatively to protect correctness.
- Bad (residual risk), because this narrows the race without eliminating it.
  An attacker can still theoretically rename or replace a *real* filesystem entry at the resolved absolute path.
  The attack must occur between `realpath()` inside `resolveForRecheck` and the backend call that reuses its result.
  This requires manipulating real backend structure at a specific resolved location under time pressure.
  It is narrower and harder than flipping a symlink at the requested name, but the risk remains nonzero.
  This ADR accepts that residual gap without solving it.
- Neutral, because this change does not pursue full elimination.
  `VirtualProvider`, the abstraction behind `withGlobPolicy`, exposes no atomic resolve-and-open primitive such as Linux `openat2(RESOLVE_NO_SYMLINKS)`.
  Closing the gap requires a backend capability the interface lacks, rather than more code in this file.
  That is future work, rather than a defect in this change.
- Neutral, because `resolveForRecheck`/`resolveForRecheckSync` and `decide`/`decideSync` changed their return shapes.
  They now return `RecheckResult`/`DecideResult` instead of bare `string`/`Mode`.
  None are exported, so this is internal only.
  Every call site inside `src/vfs/glob-policy.ts` required a mechanical update, which explains the wide diff for a narrow fix.
