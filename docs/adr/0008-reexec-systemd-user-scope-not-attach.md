# Re-exec into a systemd user scope for resource limits, not attach-after-launch

## Status

Accepted

## Context and Problem Statement

Gondolin provides no in-guest resource governance at all — no cgroups, no
rlimits, nothing to stop a guest process from burning CPU, filling memory, or
forking without bound. Any resource limit on a session has to be applied to the
host-side hypervisor process from outside the SDK. `vm.getHostPid()` returns
the real QEMU process id, but only after `VM.create()` has already started the
VM. How should host-side resource limits (`[vm.limits]`: memory, task count,
CPU quota) actually be applied?

See `docs/design.md` §7 ("Host resource limits: re-exec, not attach") and
`docs/gondolin-notes.md` R15.

## Decision Drivers

* `vm.getHostPid()` only resolves once `VM.create()` has returned, so attaching
  a cgroup to that pid afterward leaves a window, of unknown length, during
  which the guest is already running completely unconstrained.
* There is nothing in the SDK to narrow that window or report when it closes —
  it isn't observable, only inferable.
* The limit needs to exist *before* the hypervisor does, not be retrofitted
  onto a process that's already running.

## Considered Options

* Attach a cgroup to the host pid after `VM.create()` returns, using
  `vm.getHostPid()`
* Re-exec `corb run` itself under a transient `systemd-run --user --scope`
  before `VM.create()` is ever reached, with the limit properties passed to
  `systemd-run` directly

## Decision Outcome

Chosen option: "Re-exec into a systemd user scope before `VM.create()`",
because it eliminates the timing race by construction rather than trying to
shrink it: when `[vm.limits]` is configured and `CORB_SCOPED` is unset, `corb
run` re-executes itself (`process.execPath`, `process.argv.slice(1)`, never a
reconstructed command string) under `systemd-run --user --scope --collect
--quiet -p MemoryMax=… -p TasksMax=… -p CPUQuota=…`, with `CORB_SCOPED=1` set in
the child's environment so it doesn't re-exec again. `stdio` is inherited, so
the agent's TUI and pty behave exactly as a direct run, and the parent process
exits with the child's exact exit code — this is a re-exec, not a supervisor.
The limit then covers the whole process tree (`corb`, QEMU, everything they
spawn) from before QEMU exists, and no pid observation is ever needed. Risk R15
("cgroup attach timing") is closed as moot, not answered, since the attach was
never attempted.

### Consequences

* Good, because there is no unconstrained window at all — the limit is in
  force before the hypervisor process exists, which is a stronger guarantee
  than any window-narrowing on the attach-after-launch approach could achieve.
* Good, because rebuilding the command from `process.execPath`/`argv` (not a
  textual `corb …` reconstruction) means the re-exec behaves identically under
  `node src/cli.ts run …` in development and under the installed bin shim.
* Bad, because this only works where a delegated systemd user scope with the
  needed controllers (`memory`, `pids`, `cpu`) exists — on a platform lacking
  `systemd-run`, or with a user session missing controller delegation, the
  mechanism is skipped entirely (never partially applied) and the session runs
  unlimited with only a stderr warning, matching the same fail-open-and-say-so
  posture used elsewhere. macOS gets no host-side resource limits at all under
  this design, and no polling-based equivalent is built to compensate.
* Bad, because a subtle mapping detail has to be maintained by hand: the pids
  controller's systemd property is spelled `TasksMax=`, not `PidsMax=` — using
  the latter fails outright with "Unknown assignment," confirmed only by
  testing against real `systemd-run` rather than assumed from the controller's
  own name.
* Neutral, because this is a re-exec, not a supervisor: the parent process
  exits with the child's exact code and does not stay around to manage it,
  which keeps signal handling and shutdown behavior simple but means there is
  no separate host-side process watching the constrained one.
