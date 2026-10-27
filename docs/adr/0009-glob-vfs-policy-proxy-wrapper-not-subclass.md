# Glob VFS policy as a `Proxy` wrapper, not a `VirtualProviderClass` subclass

## Status

Accepted

## Context and Problem Statement

Corb enforces per-path filesystem rules below the guest kernel's view.
It decorates Gondolin's real `VirtualProvider` with deny-write, deny-read,
hidden, and shadow-write policies. Gondolin offers `VirtualProviderClass` as the
extension point for custom providers. Does the policy layer need a subclass
or another wrapper shape?

See `docs/design.md` §3 ("Build it as a Proxy wrapper, not a subclass") and
`docs/gondolin-notes.md` R13.

## Decision Drivers

* Gondolin declares `VirtualProviderClass` as `{ new (...args: any[]): any }` in its shipped types.
  Extending it provides no compile-time type checking on the subclass.
* A subclass silently delegates methods it does not override to the base class's defaults.
  A forgotten override creates a policy hole that compiles without warnings.
* `VirtualProvider` requires both async and `*Sync` variants of a large method set.
  Required methods are `open`, `stat`, `lstat`, `readdir`, `mkdir`, `rmdir`, `unlink`, and `rename`.
  Optional methods include `link`, `readFile`, `writeFile`, `appendFile`, `exists`, `copyFile`, `realpath`, `access`, `readlink`, `symlink`, `statfs`, and the `watch*` family.
  Manual coverage is easy to miss.
* An SDK update can add a new `VirtualProvider` operation at any point.
  Gondolin is an actively changing, "early" SDK (0.12.0), with breaking reshapes as recently as 0.6.0.

## Considered Options

* Extend `VirtualProviderClass` and override methods that need policy enforcement
* Wrap the real provider in a `Proxy` driven by an explicit method→access table.
  Throw `EPERM` for every method the table does not recognize.

## Decision Outcome

Chosen option: "`Proxy` wrapper over an explicit method→access table".
A subclass lacks type checking and silently leaks methods the implementer
forgets to override. A `Proxy` throws `EPERM` for an unrecognized method name.
If a future Gondolin release adds a VFS operation, it fails loudly and
immediately instead of allowing ungated access.

R13 asks whether `VirtualProviderClass` correctly delegates unoverridden
methods. That behavior is moot for the critical path because this design does
not depend on it.

The implementation in `src/vfs/glob-policy.ts` (commit `0b3fcc4`) confirmed that
every gated operation makes its own top-level policy decision before touching
the backend. `statfs` and `internalModuleStat` pass through without policy
checks. It does not inherit the base-class defaults for
`readFile`/`writeFile`/`appendFile`/`exists`. Those defaults use `open`/`stat`
internally. They call `this.open` against the raw backend and bypass the wrapper
entirely.

### Consequences

* Good, because an SDK update adding a VFS operation fails closed with an immediate `EPERM`.
  It cannot silently create a policy gap.
* Good, because the explicit method→access table lists all gated operations in one reviewable place.
  Coverage does not depend on implicitly finding missing overrides.
* Bad, because every new `VirtualProvider` method requires an explicit table entry before use.
  The `Proxy` initially refuses every operation the table does not cover. This safety has a deliberate maintenance cost.
* Neutral, because the same implementation closes additional bypasses beyond the subclass-versus-proxy choice.
  It rechecks symlink indirection against `realpath()` and fails closed on resolver errors.
  It gates both path arguments of `link()`/`symlink()` and treats directory `rename` as covering the whole matched subtree.
  A `Proxy` does not provide these checks automatically. Its shape helps list and enforce them in one place.
