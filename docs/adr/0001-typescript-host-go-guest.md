# TypeScript host, Go guest helpers

## Status

Accepted

## Context and Problem Statement

Corb needs a host-side program to drive the Gondolin micro-VM SDK (network egress
mediation, VFS providers, SSH policy, secret binding) and a small set of
in-guest helper binaries to drop privilege and gate `git`/`gh`. What language(s)
should each side be written in?

See `docs/design.md` §2 (privilege drop) and the "Decisions" table in the
project plan (`let-s-read-the-docs-nifty-russell.md`).

## Decision Drivers

* Gondolin (`@earendil-works/gondolin`) is a Node-only SDK — no Go bindings, no C ABI.
* The host program's job is almost entirely built on Gondolin SDK surface: the
  MITM egress proxy (`createHttpHooks`), secret substitution, VFS-over-RPC
  (`VirtualProvider`), and the SSH policy layer (`ssh.execPolicy`).
* The guest helper `dropcap` needs raw `prctl(PR_SET_NO_NEW_PRIVS)` and
  `setresuid`/`setresgid` syscalls, in a fixed order, with no room for a
  runtime or GC pause between steps.
* The guest image should carry as little runtime baggage as possible — every
  installed interpreter or dynamic library is attack surface and image size.

## Considered Options

* TypeScript/Node host + Go guest helpers (static binaries)
* Go host (reimplementing the Gondolin SDK's surface) + Go guest helpers
* TypeScript/Node for both host and guest helpers

## Decision Outcome

Chosen option: "TypeScript/Node host + Go guest helpers (static binaries)",
because Gondolin only ships a Node SDK, and a Go host would mean rebuilding the
MITM egress proxy, secret substitution, VFS-over-RPC, and SSH policy layer from
scratch — none of that is a small reimplementation. On the guest side, `dropcap`
needs direct, ordered syscalls (`prctl`, `setgroups`, `setresgid`, `setresuid`)
that Go's `syscall` package exposes cleanly and applies across every OS thread;
building it with `CGO_ENABLED=0` yields a single static binary with no runtime
dependency on the guest's libc or dynamic linker.

### Consequences

* Good, because the host gets Gondolin's full SDK surface (egress MITM, VFS
  providers, SSH policy, secrets) for free instead of reimplemented.
* Good, because guest helpers are dependency-free static binaries — nothing to
  install or link against inside the Alpine guest image.
* Bad, because the project now carries two toolchains (Node/TypeScript and Go)
  and two build steps (`tsc` and `go build`) instead of one.
* Neutral, because it rules out ever running the guest helpers under a
  different guest distro's libc — moot today since the image is Alpine-only,
  but a constraint to remember if that changes.
