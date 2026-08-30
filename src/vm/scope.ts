// `src/vm/scope.ts` — M8.3: host resource limits on the VM process, applied
// by re-executing `corb run` itself under `systemd-run --user --scope` with
// `-p MemoryMax=…`/`-p TasksMax=…`/`-p CPUQuota=…`, rather than attaching a
// cgroup to `vm.getHostPid()` after the fact. Attach-after-the-fact is the
// naive alternative `docs/design.md` §7 itself shows and explicitly warns
// against ("Attach timing matters: confirm the PID is stable early enough to
// attach the cgroup before the guest can do meaningful work, not after") —
// re-exec sidesteps the whole timing problem by having the limit already in
// place, on the whole process tree, before `corb` (and therefore QEMU) ever
// starts.
//
// One correction to note for a future reader: the systemd property for the
// pids controller is `TasksMax=`, not `PidsMax=` — confirmed both by `man
// systemd.resource-control` and empirically (`systemd-run --user --scope -p
// PidsMax=100 -- true` fails with "Unknown assignment: PidsMax=100"; `-p
// TasksMax=100` succeeds). `MemoryMax=` and `CPUQuota=` take the raw
// `vm.limits` config strings unchanged (`man systemd.resource-control`
// confirms `MemoryMax=` accepts a `K`/`M`/`G`/`T`-suffixed size and
// `CPUQuota=` a `%`-suffixed percentage — the exact formats
// `src/config/schema.ts`'s `MEMORY_SIZE_RE`/`PERCENT_RE` already validate).
//
// Two independently unit-testable pieces, mirroring `src/vm/shutdown.ts`'s
// injectable-dependency convention (`ProcessLike`/`ExitFn`):
//
//   (a) `decideScope` — pure: given the configured `vm.limits` and the
//       uid's delegated cgroup controllers (`src/vm/cgroup.ts`), decide
//       whether to re-exec at all, and if so, exactly which `-p` properties
//       to pass. No re-exec is attempted for an unconfigured key (it
//       contributes no flag, regardless of delegation) — only *configured*
//       keys are examined. If any configured key's controller is missing,
//       the whole mechanism is skipped (never a partial re-exec with just
//       the deliverable subset) — this is deliberately narrower than
//       `doctor.ts`'s own blanket all-three check (which exists to warn
//       forward-looking about M8 in general, not to gate one specific run's
//       specific configured keys); do not "fix" this into matching
//       `doctor.ts`, the two checks answer different questions on purpose.
//
//   (b) `reExecUnderScope` — performs the actual re-exec: `process.execPath`
//       + `process.argv.slice(1)` (never a textual `corb ...`
//       reconstruction, so this works identically whether invoked via `node
//       src/cli.ts run ...` in dev or the installed `corb` bin shim) under
//       `systemd-run --user --scope --collect --quiet -p <prop>... --
//       <execPath> <args...>`, with `CORB_SCOPED=1` added to the child's
//       env and everything else inherited, `stdio: "inherit"` so the
//       re-exec'd process's TUI/pty behaves exactly as a direct run would,
//       and the parent exiting with the child's exact exit code once it
//       completes — a genuine re-exec, not a supervisor.
//
//       `--collect` (unload the transient scope unit once it completes,
//       even on failure, per `man systemd-run`) avoids a lingering
//       "failed"-looking unit entry; `--quiet` suppresses the "Running as
//       unit: run-xxxx.scope" line `systemd-run` otherwise prints to
//       stderr, which would otherwise look like unexpected `corb` output —
//       both confirmed empirically on this machine (`systemd-run --user
//       --scope -- true` prints the "Running as unit" line and nothing
//       else without the flags; `--collect --quiet` prints neither, and
//       exit codes/stdio still pass through correctly either way).
//
// `src/commands/run.ts` wires the two together: `decideScope` runs against
// `readDelegatedControllersForCurrentUser()` (`src/vm/cgroup.ts`); if it says
// to proceed, `reExecUnderScope` is called and (on a real systemd-run
// invocation) never returns — the process has already exited with the
// child's code. If `decideScope` says not to (nothing configured, or a
// configured key's controller isn't delegated), or if `reExecUnderScope`
// itself couldn't even spawn `systemd-run` (e.g. ENOENT — the "systemd-run
// itself is simply absent" case, indistinguishable in effect from "missing
// delegated controllers" per the M8.3 brief: warn and continue unlimited,
// nothing else attempted), `run.ts` prints a one-line warning and falls
// straight through to `runSession()` with no limits applied. Not this
// module's job: printing that warning (an `run.ts`-level concern, since it
// needs to know it's about to proceed unlimited) or deciding when in
// `runRunCommand`'s control flow this all happens (also `run.ts` — see that
// module's own comment for why it's after `--dry-run` and the trust gate,
// but before `runSession()`).
import { spawnSync } from "node:child_process";
import os from "node:os";
import type { PartialVmLimits } from "../config/schema.ts";

/** The three `vm.limits` keys `src/config/schema.ts` validates, and the systemd cgroup controller each one needs delegated. */
const CONTROLLER_FOR_LIMIT_KEY: Record<keyof PartialVmLimits, string> = {
  "memory-max": "memory",
  "pids-max": "pids",
  "cpu-quota": "cpu",
};

/** Which `-p` property each configured key contributes, and in what order (memory, pids, cpu — matches `PartialVmLimits`' own field order). `TasksMax=`, not `PidsMax=` — see the module comment for why. */
function propertyForLimitKey(key: keyof PartialVmLimits, limits: PartialVmLimits): string | undefined {
  switch (key) {
    case "memory-max":
      return limits["memory-max"] !== undefined ? `MemoryMax=${limits["memory-max"]}` : undefined;
    case "pids-max":
      return limits["pids-max"] !== undefined ? `TasksMax=${limits["pids-max"]}` : undefined;
    case "cpu-quota":
      return limits["cpu-quota"] !== undefined ? `CPUQuota=${limits["cpu-quota"]}` : undefined;
  }
}

/** What `decideScope` decided. */
export interface ScopeDecision {
  /** Whether `reExecUnderScope` should actually be called. */
  reExec: boolean;
  /** `-p` property strings to pass to `systemd-run`, built only for configured keys. Empty when `reExec` is `false`. */
  properties: string[];
  /**
   * Controller(s) a *configured* key needed but that aren't in
   * `delegatedControllers`. Non-empty exactly when `reExec` is `false`
   * because of a missing controller (as opposed to nothing being
   * configured at all, which also yields `reExec: false` but an empty
   * array here) — `run.ts` uses this to distinguish "nothing to do" from
   * "warn and continue unlimited".
   */
  missingControllers: string[];
}

/**
 * Pure decision logic: given the `vm.limits` a run actually configured and
 * the uid's delegated cgroup controllers, should `corb run` re-exec under a
 * systemd scope, and with which `-p` properties?
 *
 * - `limits` undefined, or present but with no keys set → nothing to do
 *   (`reExec: false`, both arrays empty).
 * - Every controller a *configured* key needs is delegated → `reExec: true`,
 *   with one `-p` property per configured key (an unconfigured key
 *   contributes nothing, regardless of delegation).
 * - Any configured key's controller is missing → `reExec: false`, with
 *   `missingControllers` naming exactly which controller(s) are missing —
 *   never a partial re-exec with just the deliverable subset (see the
 *   module comment for why).
 */
export function decideScope(limits: PartialVmLimits | undefined, delegatedControllers: ReadonlySet<string>): ScopeDecision {
  if (limits === undefined) {
    return { reExec: false, properties: [], missingControllers: [] };
  }

  const configuredKeys = (Object.keys(CONTROLLER_FOR_LIMIT_KEY) as (keyof PartialVmLimits)[]).filter(
    (key) => limits[key] !== undefined,
  );
  if (configuredKeys.length === 0) {
    return { reExec: false, properties: [], missingControllers: [] };
  }

  const missingControllers = [...new Set(configuredKeys.map((key) => CONTROLLER_FOR_LIMIT_KEY[key]).filter((c) => !delegatedControllers.has(c)))];
  if (missingControllers.length > 0) {
    return { reExec: false, properties: [], missingControllers };
  }

  const properties = configuredKeys
    .map((key) => propertyForLimitKey(key, limits))
    .filter((p): p is string => p !== undefined);
  return { reExec: true, properties, missingControllers: [] };
}

/** `systemd-run`'s full argv (everything after the binary name itself), given the `-p` properties and the command to re-exec. Exported so a unit test can assert the exact argv without invoking a real `systemd-run`. */
export function buildSystemdRunArgv(properties: readonly string[], execPath: string, execArgv: readonly string[]): string[] {
  const propertyArgs = properties.flatMap((p) => ["-p", p]);
  // `--collect`/`--quiet` — see the module comment for what each avoids and
  // how that was confirmed empirically.
  return ["--user", "--scope", "--collect", "--quiet", ...propertyArgs, "--", execPath, ...execArgv];
}

/** The subset of `child_process.spawnSync`'s return shape this module actually reads — injectable for tests (see `ReExecOptions.spawn`). */
export interface SpawnSyncResultLike {
  status: number | null;
  signal: NodeJS.Signals | null;
  error?: Error;
}

export type SpawnSyncLike = (
  command: string,
  args: string[],
  options: { stdio: "inherit"; env: NodeJS.ProcessEnv },
) => SpawnSyncResultLike;

export type ExitFn = (code: number) => void;

export interface ReExecOptions {
  /** `-p` property strings — normally `decideScope(...).properties`. */
  properties: readonly string[];
  /** Defaults to `process.execPath`. */
  execPath?: string;
  /** Defaults to `process.argv.slice(1)` — never a textual `corb ...` reconstruction, see the module comment. */
  execArgv?: readonly string[];
  /** Defaults to `process.env`. `CORB_SCOPED: "1"` is always added on top, regardless of what this contains. */
  env?: NodeJS.ProcessEnv;
  /** Defaults to `"systemd-run"` (resolved via `PATH`). */
  systemdRunPath?: string;
  /** Defaults to the real `child_process.spawnSync`. Override in tests so no real `systemd-run` is ever invoked. */
  spawn?: SpawnSyncLike;
  /** Defaults to the real `process.exit`. Override in tests so nothing exits the test worker. */
  exit?: ExitFn;
}

/** What happened when `reExecUnderScope` tried to spawn `systemd-run`. Only returned (rather than `exit` having already been called) when the spawn itself failed outright — e.g. `systemd-run` isn't installed. */
export interface ReExecOutcome {
  argv: string[];
  env: NodeJS.ProcessEnv;
  /**
   * Set when `systemd-run` could not be spawned at all (e.g. ENOENT). When
   * this is set, `exit` was never called — the caller (`run.ts`) should
   * treat this exactly like "missing delegated controllers": warn and
   * continue unlimited, nothing else attempted. Unset means `exit` *was*
   * called with the child's exit code — in real usage that already ended
   * the process, so there is nothing further for a caller to do; this
   * return value only matters to a test using an injected, non-terminating
   * `exit`.
   */
  spawnError?: Error;
}

function realSpawnSync(command: string, args: string[], options: { stdio: "inherit"; env: NodeJS.ProcessEnv }): SpawnSyncResultLike {
  return spawnSync(command, args, options);
}

/** Converts a `spawnSync` result into the exit code the parent process should propagate: the child's own status if it exited normally, or the conventional 128+signal number (matching `src/vm/shutdown.ts`'s `SIGNAL_EXIT_CODES` reasoning) if it was killed by a signal instead. */
export function exitCodeFromSpawnResult(result: Pick<SpawnSyncResultLike, "status" | "signal">): number {
  if (result.status !== null) {
    return result.status;
  }
  if (result.signal !== null) {
    const signalNumber = os.constants.signals[result.signal];
    return signalNumber !== undefined ? 128 + signalNumber : 1;
  }
  return 1;
}

/**
 * Re-execs `process.execPath`/`process.argv.slice(1)` under `systemd-run
 * --user --scope` with the given `-p` properties and `CORB_SCOPED=1`,
 * `stdio: "inherit"`. On a successful spawn, calls `exit` with the child's
 * exact exit code and returns `{ argv, env }` — in real usage (the default,
 * real `process.exit`) that call never returns control to this function's
 * caller. On a spawn failure (e.g. `systemd-run` not installed), `exit` is
 * never called; the error is returned instead so the caller can fall back
 * to running unlimited.
 */
export function reExecUnderScope(options: ReExecOptions): ReExecOutcome {
  const execPath = options.execPath ?? process.execPath;
  const execArgv = options.execArgv ?? process.argv.slice(1);
  const env: NodeJS.ProcessEnv = { ...(options.env ?? process.env), CORB_SCOPED: "1" };
  const systemdRunPath = options.systemdRunPath ?? "systemd-run";
  const spawn = options.spawn ?? realSpawnSync;
  const exit = options.exit ?? ((code: number) => process.exit(code));

  const argv = buildSystemdRunArgv(options.properties, execPath, execArgv);
  const result = spawn(systemdRunPath, argv, { stdio: "inherit", env });
  if (result.error) {
    return { argv, env, spawnError: result.error };
  }
  exit(exitCodeFromSpawnResult(result));
  return { argv, env };
}
