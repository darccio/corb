# Route the already-resolved path to the backend call, for operations where that is safe

## Status

Accepted

## Context and Problem Statement

`src/vfs/glob-policy.ts`'s `withGlobPolicy` implements `docs/design.md` §3's
first hardening requirement, "check the resolved path, not just the requested
one": `decide()`/`decideSync()` call `resolveForRecheck()`/
`resolveForRecheckSync()` (a real `backendAny.realpath()`/`realpathSync()`
call) to re-run the policy decision against the symlink-resolved target, not
just the literal requested path. Without this, `ln -s .env decoy && cat decoy`
would defeat every rule in the table, because `decoy` itself matches nothing.

That much was already correct. The gap: `resolveForRecheck`'s resolved path
was used *only* to decide — every call site then issued the actual backend
operation (`backendAny.open`, `backendAny.readFile`, `backendAny.stat`, and so
on) against `normalized`, the original, unresolved path, exactly as if the
resolve had never happened. Since the real backend's own `open`/`stat`/etc.
independently re-resolve that path string from scratch (a real filesystem
call in production), there is a window — the `await` between the policy
check and the backend call yields the event loop — during which a concurrent
guest operation can swap a symlink along the requested path.

Concretely, with rule `{ glob: "**/.env", mode: "deny-read" }`: process A
loops `cat decoy`; process B loops flipping `decoy` between a dummy target and
`.env`. On an iteration where `decoy` resolves to the dummy at
`withGlobPolicy`'s check-time but to `.env` by the real backend's open-time,
the read goes through uninspected — `decide()` allowed the operation (having
resolved `decoy` → dummy and found no denial), and the backend then opened
whatever `decoy` pointed to *at that later moment*, independently.

`docs/design.md` §3's own words are "check the resolved path, not just the
requested one" — that phrase covers the *decision*. It says nothing about
which path the *operation* itself should run against, and the gap above is
exactly that silence turning into a real bug: resolving a path purely to
decide, then discarding the resolution and handing the backend call the
original string, re-opens exactly the window the resolve was meant to close.

## Decision Drivers

- The entire value of resolving a path before deciding is lost if the actual
  filesystem operation re-resolves the same path from scratch afterward —
  the decision and the operation must act on the same resolved target for the
  check to mean anything at the moment it matters.
- Blanket-redirecting *every* gated operation to the resolved path is itself
  dangerous, not merely imprecise: several operations' own POSIX/Node.js
  semantics require them to act on the *literally named* entry and never
  follow a trailing symlink. `lstat` exists specifically to report on the
  named entry, not what it points to. `unlink`/`rmdir` remove the named
  directory entry itself; redirecting them to a resolved target would be a
  **correctness/data-loss bug** — deleting or moving a real file the guest
  never named — not just a policy nuance. `rename`'s source and `link`'s
  existing-path endpoint must rename/link the named entry (symlink or not),
  never relocate what it resolves to.
- `checkSymlinkTargetPolicy`/`checkSymlinkTargetPolicySync` (the
  `symlink()`-target pre-creation check) is a separate, already-shipped
  mechanism for a different, already-fixed bug (an empirically-verified RPC
  readdir-cache-corruption issue documented in this file's own module
  comment) — it must not be touched or conflated with this fix.
- No atomic resolve-and-open primitive (e.g. Linux `openat2(2)` with
  `RESOLVE_NO_SYMLINKS`) is exposed through the `VirtualProvider` abstraction
  this module is built on, so a resolve-then-act sequence with *some* gap
  between the two steps is unavoidable at this layer regardless of which
  option below is chosen — the goal is narrowing that gap and what it takes
  to exploit it, not eliminating it outright.

## Considered Options

- Leave `resolveForRecheck`'s resolved path discarded after the decision
  (status quo — the bug this ADR fixes).
- Redirect every gated operation unconditionally to the resolved path.
- Classify each gated operation by whether its own real-filesystem semantics
  already imply following a trailing symlink, and redirect only the backend
  call for operations where that holds — leaving the rest on the original,
  unresolved path.

## Decision Outcome

Chosen option: "classify each gated operation," because the unconditional
redirect option is not just imprecise but actively unsafe for a subset of
operations (see Decision Drivers), while leaving every operation on the
unresolved path is the status quo bug. The dividing line is exactly whether
an operation's own real-filesystem semantics already resolve a trailing
symlink at the point the backend call names: if they do, routing the
already-computed resolution into that same call changes *when* the resolution
happens (earlier, before the race window) but not *what* gets acted on — a
pure narrowing. If they don't (an operation that must act on the literal
named entry), routing a resolved path into it would change *which real
filesystem entry* the operation acts on, which is the data-loss failure mode
above, not a security improvement.

For **create-path** operations (the target may not exist yet, so only the
*parent* directory is resolved and the literal final segment is reattached
unchanged), the same reasoning still applies: redirecting only ever changes
which already-resolved parent-directory chain is used, never the leaf name
itself, so an operation whose leaf must stay literal (a create-path `rename`
destination, a create-path `link` new-name, a create-path `symlink`'s own
name) is unaffected in that respect by also getting its parent pre-resolved.

### Mechanism

`resolveForRecheck`/`resolveForRecheckSync` used to return only the
rule-relative path (`string | undefined`) needed for the second policy
lookup, discarding the resolved *absolute* path they had already computed
internally (`resolvedNormalized`, or `joinAbs(resolvedNormalized, base)` for
the create-path case). They now return a `RecheckResult { rulePath, absPath }
| undefined` — same `undefined`-on-`ENOENT` and fail-closed-throw-on-any-other-error
behavior as before, just with `absPath` no longer thrown away.

`decide`/`decideSync` now return a `DecideResult { mode, resolvedAbs }`
instead of a bare `Mode`. `resolvedAbs` is the recheck's `absPath` when a
recheck ran and found something to resolve, or the original, unresolved
`normalizedAbs` unchanged when the recheck returned `undefined` (target, or
its parent for a create-path operation, doesn't exist yet — nothing to
resolve, and the backend's own call will surface its own correct `ENOENT`).
Every call site's `if (decision === "shadowed")` became
`if (decision.mode === "shadowed")`; call sites for operations in the
redirect classification below additionally use `decision.resolvedAbs` instead
of the original normalized path for the `backendAny.<method>` call.

The shadow store (a private, in-process `MemoryProvider`) is unaffected:
every `shadowAny.<method>` call keeps using the original, normalized path,
never `resolvedAbs`. There is no real filesystem or symlink exposure inside
the shadow store to narrow a race against — `resolvedAbs` only matters for
calls that reach the real `backend`.

### Full classification

**Redirected to the resolved path** (each already implies following a
trailing symlink by its own semantics, so resolving earlier changes only
*when* the resolution happens, not *what* is acted on):

| Operation | Resolved argument |
|---|---|
| `open`/`openSync` (read- and write/create-shaped alike) | the path |
| `stat`/`statSync` | the path |
| `access`/`accessSync` | the path |
| `readFile`/`readFileSync`, `writeFile`/`writeFileSync`, `appendFile`/`appendFileSync` | the path |
| `copyFile`/`copyFileSync` | the *source* argument |
| `truncate`/`truncateSync` (the top-level, path-based operation — unlike `ftruncate`, POSIX `truncate(path,...)` follows a trailing symlink) | the path |
| `readdir`/`readdirSync` | the directory argument passed to the backend's own `readdir` call *only* — the requested directory's own rule-relative path (`dirRulePath`, used by `isEntryHidden` to test each returned entry) is unchanged; which rule-path basis governs child-entry visibility is a separate, unrelated design question this fix does not touch |
| `mkdir`/`mkdirSync` | the (create-path) parent |
| `symlink`/`symlinkSync` | the new symlink's own (create-path) parent — `target` itself is never a VFS path this provider resolves, unchanged |
| `rename`/`renameSync` | the *new*/destination (create-path) parent only — the source stays unresolved, see below |
| `link`/`linkSync` | the *new* (create-path) parent only — the existing endpoint stays unresolved, see below |

**Left on the original, unresolved path** (redirecting would either be
meaningless or actively wrong):

| Operation | Why |
|---|---|
| `lstat`/`lstatSync` | must report on the named entry itself, never what it points to — that is `lstat`'s entire reason to exist |
| `unlink`/`unlinkSync`, `rmdir`/`rmdirSync` | POSIX removes the named directory entry itself, never follows a trailing symlink; redirecting is a correctness/data-loss bug (could delete a real file the guest never named), not a policy nuance |
| `readlink`/`readlinkSync` | must read the named symlink's own target text; there is nothing to "readlink" once resolved |
| `rename`'s *source* (old) path, `link`'s *existing* path | POSIX renames/links the named entry itself, not its resolved target — renaming or linking a symlink must act on the symlink, not relocate what it points to |
| `isDeniedDirectoryRename`'s own `lstat` call | already correctly uses `backendAny.lstat` unresolved — it specifically needs to know whether the *named* source, without following, is a real directory; no change |
| `checkSymlinkTargetPolicy`/`checkSymlinkTargetPolicySync` | a separate, already-shipped, unrelated mechanism (the RPC readdir-cache-corruption fix documented elsewhere in this file); not touched |
| `exists`/`existsSync` | low-stakes — a boolean only, no data exposure or mutation either way — and not part of this finding; left as-is rather than expanding scope |
| the `watch*` family (`watch`, `watchAsync`, `watchFile`, `unwatchFile`) | read-adjacent per this module's own already-documented reasoning; no content disclosure or mutation, not worth the added surface |
| guest-facing `realpath`/`realpathSync` | this operation's entire job is asking the backend to resolve the path from scratch; handing it an already-resolved path closes no window that matters, since there is no content disclosure or mutation downstream of *which* real entry it reports on — the same low-stakes shape as `exists` |

### Consequences

- Good, because the TOCTOU window this ADR closes now requires winning a
  race against the *resolved, already-known-safe* absolute path rather than
  against the originally-requested (possibly symlinked) one, for every
  operation in the redirect list — the concrete `decoy`/`.env` scenario in
  the Context section above no longer works, because `open()`'s backend call
  now receives the already-resolved `/real/.env`-shaped path computed at
  decision time, not the `decoy` string re-resolved fresh.
- Good, because the classification is derived from each operation's own
  documented POSIX/Node.js semantics (verified against
  `test/fakes/provider.ts`'s own `followSymlinks` argument at each relevant
  `getEntry`/`lookup` call), not guessed — the correctness-sensitive half
  (`unlink`/`rmdir`/`lstat`/`readlink`/rename-and-link's existing endpoint)
  is the one this ADR is most conservative about, on purpose.
- Bad (residual risk), because this narrows the race without eliminating it:
  an attacker who can rename or replace a *real* filesystem entry sitting
  exactly at the already-resolved absolute path, in the gap between the
  `realpath()` call inside `resolveForRecheck` and the backend call that
  reuses its result, could still theoretically win a race. This is a
  categorically narrower and harder attack than what existed before — it
  requires manipulating real backend structure at a specific resolved
  location under time pressure, not merely flipping a symlink at the
  originally-requested name — but it is not zero. This residual gap is
  accepted, not solved, by this ADR.
- Neutral, because full elimination is not pursued here: no atomic
  resolve-and-open primitive (e.g. Linux `openat2(RESOLVE_NO_SYMLINKS)`) is
  exposed through the `VirtualProvider` abstraction `withGlobPolicy` is built
  on. Closing the residual gap completely would require a capability the
  backend interface does not offer, not just more code in this file — a
  future item, not a defect in this one.
- Neutral, because `resolveForRecheck`/`resolveForRecheckSync` and
  `decide`/`decideSync` all changed their return shapes (`RecheckResult`/
  `DecideResult` instead of bare `string`/`Mode`) — an internal-only change
  (none of these are exported), but every call site inside
  `src/vfs/glob-policy.ts` had to be touched mechanically to match, which is
  why this is a wide diff for what is conceptually a narrow fix.
