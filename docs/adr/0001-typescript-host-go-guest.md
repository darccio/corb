# TypeScript host, Go guest helpers

## Status

Accepted

## Context and Problem Statement

Corb needs a host-side program to drive the Gondolin micro-VM SDK.
The SDK handles network egress mediation, VFS providers, SSH policy, and secret
binding. Corb also needs small in-guest helper binaries to drop privilege and
gate `git`/`gh`. Which languages fit these two roles?

See `docs/design.md` §2 (privilege drop) and the "Decisions" table in the
project plan (`let-s-read-the-docs-nifty-russell.md`).

## Decision Drivers

* Gondolin (`@earendil-works/gondolin`) is a Node-only SDK. It has no Go bindings or C ABI.
* The host program depends almost entirely on Gondolin's SDK surface.
  This includes the MITM egress proxy (`createHttpHooks`), secret substitution,
  VFS-over-RPC (`VirtualProvider`), and the SSH policy layer (`ssh.execPolicy`).
* The guest helper `dropcap` needs raw `prctl(PR_SET_NO_NEW_PRIVS)` and
  `setresuid`/`setresgid` syscalls in a fixed order.
  The sequence must stay on the same OS thread through exec, enforced by
  `runtime.LockOSThread()`.
* The guest image needs minimal runtime baggage.
  Every installed interpreter or dynamic library adds attack surface and image size.

## Considered Options

* TypeScript/Node host + Go guest helpers (static binaries)
* Go host (reimplementing the Gondolin SDK's surface) + Go guest helpers
* TypeScript/Node for both host and guest helpers

## Decision Outcome

Chosen option: "TypeScript/Node host + Go guest helpers (static binaries)".
Gondolin only ships a Node SDK. A Go host requires a substantial reimplementation
of the MITM egress proxy, secret substitution, VFS-over-RPC, and SSH policy layer.

On the guest side, `dropcap` needs direct, ordered syscalls
(`prctl`, `setgroups`, `setresgid`, `setresuid`). `unix.Prctl()` sets
`PR_SET_NO_NEW_PRIVS` only on the OS thread locked by `runtime.LockOSThread()`.
Go's `syscall.Setgroups`, `syscall.Setresgid`, and `syscall.Setresuid` apply
credential changes across every OS thread. Building with
`CGO_ENABLED=0` yields a single static binary with no runtime dependency on the
guest's libc or dynamic linker.

### Consequences

* Good, because the host gets Gondolin's full SDK surface without reimplementation.
  This covers egress MITM, VFS providers, SSH policy, and secrets.
* Good, because guest helpers are dependency-free static binaries.
  The Alpine guest image needs nothing extra to install or link against.
* Bad, because the project carries two toolchains (Node/TypeScript and Go).
  It also needs two build steps (`tsc` and `go build`) instead of one.
* Neutral, because `CGO_ENABLED=0` removes the guest libc dependency and does not restrict helpers to Alpine-based images.
  Changing the image requires review of kernel, architecture, and image integration assumptions.
