# Re-exec into a systemd user scope for resource limits, not attach-after-launch

## Status

Accepted

## Context and Problem Statement

Gondolin provides no in-guest resource governance: no cgroups or rlimits.
Nothing stops a guest process from exhausting CPU or memory, or forking without
bound. Session resource limits must apply to the host-side hypervisor process
from outside the SDK. `vm.getHostPid()` returns the real QEMU process id only
after `VM.create()` starts the VM. How can Corb apply host-side resource limits
(`[vm.limits]`: memory, task count, CPU quota)?

See `docs/design.md` §7 ("Host resource limits: re-exec, not attach") and
`docs/gondolin-notes.md` R15.

## Decision Drivers

* `vm.getHostPid()` only resolves after `VM.create()` returns.
  Attaching a cgroup afterward leaves an unknown window in which the guest runs without constraints.
* The SDK cannot narrow that window or report when it closes.
  Its duration is inferable, but not observable.
* The limit must exist *before* the hypervisor, rather than attach to a process that is already running.

## Considered Options

* Attach a cgroup to the host pid after `VM.create()` returns. Get the pid with `vm.getHostPid()`
* Re-exec `corb run` under a transient `systemd-run --user --scope` before reaching `VM.create()`.
  Pass the limit properties directly to `systemd-run`.

## Decision Outcome

Chosen option: "Re-exec into a systemd user scope before `VM.create()`".
It eliminates the timing race by construction.
Re-exec requires at least one configured `[vm.limits]` key and an unset
`CORB_SCOPED`. All controllers required by those keys must also be delegated.
When these conditions hold, `corb run` re-executes itself under
`systemd-run --user --scope --collect
--quiet -p MemoryMax=… -p TasksMax=… -p CPUQuota=…`.

It uses `process.execPath` and `process.argv.slice(1)`, never a reconstructed
command string. The child's environment sets `CORB_SCOPED=1` to prevent
another re-exec.

The child inherits `stdio`, so the agent's TUI and pty behave as in a direct
run. For a normal exit, the parent forwards the child's exact exit code.
For signal termination, it uses 128 plus the signal number.
For other results without an exit status, it returns 1.
This is a re-exec, rather than a supervisor.

The limit covers the whole process tree (`corb`, QEMU, and their children)
before QEMU exists. No pid observation is needed. R15 ("cgroup attach timing")
is moot because this design never attempts the attach.

### Consequences

* Good, because the limit takes effect before the hypervisor process exists.
  There is no unconstrained window. Attach-after-launch can only narrow that window.
* Good, because `process.execPath`/`argv` preserves behavior under both `node src/cli.ts run …` and the installed bin shim.
  It avoids textual `corb …` reconstruction.
* Bad, because this requires a delegated systemd user scope with the needed controllers (`memory`, `pids`, `cpu`).
  If `systemd-run` or user-session controller delegation is missing, Corb skips the mechanism entirely.
  It never applies limits partially. The session runs unlimited with a stderr warning, consistent with other fail-open-and-say-so behavior.
  macOS gets no host-side resource limits, and this design provides no polling equivalent.
* Bad, because the pids controller maps to `TasksMax=`, rather than `PidsMax=`.
  The latter fails with "Unknown assignment," as real `systemd-run` testing confirmed.
  This mapping requires manual maintenance. The controller's name alone does not establish the correct property.
* Neutral, because the parent forwards the child's exact code on normal exit.
  For signal termination, it uses 128 plus the signal number.
  For other results without an exit status, it returns 1.
  It does not stay to manage the child.
  This keeps signal handling and shutdown simple. No separate host-side process watches the constrained process.
