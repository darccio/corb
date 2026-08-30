# Glob VFS policy as a `Proxy` wrapper, not a `VirtualProviderClass` subclass

## Status

Accepted

## Context and Problem Statement

Corb enforces per-path filesystem rules (deny-write, deny-read, hidden,
shadow-write) below the guest kernel's view of the filesystem, by decorating
Gondolin's real `VirtualProvider` with a policy layer. Gondolin's SDK offers
`VirtualProviderClass` as the intended extension point for building a custom
provider. How should the policy layer actually be implemented — as a subclass
of that base class, or some other wrapper shape?

See `docs/design.md` §3 ("Build it as a Proxy wrapper, not a subclass") and
`docs/gondolin-notes.md` R13.

## Decision Drivers

* `VirtualProviderClass` is declared as `{ new (...args: any[]): any }` in
  Gondolin's shipped types — extending it gives zero compile-time type
  checking on the resulting subclass.
* A subclass silently delegates any method it doesn't override to the base
  class's default implementation. A forgotten override is therefore a policy
  hole that compiles clean and produces no warning.
* `VirtualProvider` requires both async and `*Sync` variants of a fairly large
  method set (`open`, `stat`, `lstat`, `readdir`, `mkdir`, `rmdir`, `unlink`,
  `rename`, plus optional `link`, `readFile`, `writeFile`, `appendFile`,
  `exists`, `copyFile`, `realpath`, `access`, `readlink`, `symlink`, `statfs`,
  the `watch*` family) — a large surface to remember to cover exhaustively by
  hand.
* An SDK update could add a new `VirtualProvider` operation at any point,
  since Gondolin is an actively evolving, "early" SDK (0.12.0, breaking
  reshapes as recently as 0.6.0).

## Considered Options

* Extend `VirtualProviderClass` and override the methods that need policy
  enforcement
* Wrap the real provider in a `Proxy`, driven by an explicit method→access
  table, with every method the table doesn't recognize defaulting to a thrown
  `EPERM`

## Decision Outcome

Chosen option: "`Proxy` wrapper over an explicit method→access table", because
a subclass gives no type checking and silently leaks any method the
implementer forgets to override, while a `Proxy` defaults an unrecognized
method name to a thrown `EPERM` — so a future Gondolin release that adds a new
VFS operation fails loudly and immediately instead of leaking ungated access
through it. This also makes R13 (whether `VirtualProviderClass` correctly
delegates unoverridden methods) moot for the critical path, since nothing here
depends on that delegation behavior at all. Confirmed in implementation
(`src/vfs/glob-policy.ts`, commit `0b3fcc4`): every operation makes its own
top-level policy decision before ever touching the backend, rather than
inheriting `VirtualProviderClass`'s base-class defaults for `readFile`/
`writeFile`/`appendFile`/`exists` (verified these are built on `open`/`stat`
internally and would otherwise call `this.open` against the raw, unwrapped
backend, bypassing the wrapper entirely).

### Consequences

* Good, because an SDK update adding a new VFS operation is a fail-closed
  event (a thrown `EPERM` surfaces immediately) rather than a silent gap in
  policy coverage.
* Good, because the explicit method→access table is the single place the
  full set of gated operations is enumerated and reviewable, rather than being
  implicit in "whatever wasn't overridden."
* Bad, because every new `VirtualProvider` method the SDK ships still has to
  be explicitly added to the table before it can be used at all — the Proxy's
  safety is bought by initially refusing anything not yet accounted for, which
  is a deliberate cost, not a free win.
* Neutral, because this closes several bypasses beyond the subclass-vs-proxy
  question itself as part of the same implementation: symlink-indirection
  re-checking against `realpath()` with fail-closed behavior on resolver
  errors, gating both path arguments of `link()`/`symlink()`, and treating a
  directory `rename` as covering its whole matched subtree — none of which
  follow automatically from choosing a Proxy, but all of which the Proxy shape
  made it natural to enumerate and enforce in one place.
