// `src/vm/shutdown.ts` — M1.5: one idempotent teardown funnel reachable from
// `SIGINT`/`SIGTERM`/`SIGHUP` and `uncaughtException`.
//
// Why this is the shape it is: `docs/gondolin-notes.md` §3 and
// `docs/design.md` §7 both land on the same fact — `ExecProcess` has no
// `kill`/`sendSignal` and no exec timeout, only an `AbortSignal` that
// rejects the local promise without guaranteeing the guest process actually
// dies. `vm.close()` (closing the VM) is the only real kill switch Corb has.
// That means teardown has to be reachable from *every* exit path — a clean
// Ctrl-C, a killed terminal, a bug that throws somewhere unexpected — and it
// has to be safe to trigger more than once, because a SIGTERM can easily
// arrive a second time (a user pressing Ctrl-C twice, an orchestrator
// sending SIGTERM then SIGKILL) while the first teardown is still running.
//
// The real cleanup targets this eventually orchestrates — closing a live
// `VM` (M1.6), flushing an audit log (M3), clearing a session watchdog (M8)
// — don't exist as modules yet, so this cannot hardcode "call vm.close()"
// today. Design landed on: an ordered list of named async steps, each one
// independent of the others' success. `ShutdownController` runs every step
// in order regardless of whether an earlier one threw, collects the
// failures rather than aborting the rest of teardown on the first one (a
// failure to flush the audit log must not skip closing the VM), and reports
// them all afterward. M1.6 constructs one with `[restoreTty, closeVm]`; M3
// and M8 append their own steps to that same list — this file does not need
// to change when they do.
//
// Testable without ever touching the test runner's own process: signal
// registration and the exit function are both injectable, defaulting to the
// real `process.on`/`process.exit`. A unit test builds a controller with a
// fake registrar (so no real "SIGINT" listener is ever attached to the
// actual process) and a fake exit function (so nothing calls the real
// `process.exit` and kills the test worker), then calls `trigger()` directly
// to simulate a signal. See `test/unit/vm/shutdown.test.ts`.
//
// A second, end-to-end test drives this against a real OS signal — but
// against a small *spawned child process*, never the test runner's own
// process, per the milestone's own hard requirement. See
// `test/unit/vm/shutdown.e2e-child.test.ts` and its child script.

/** One named, independent teardown action. */
export interface ShutdownStep {
  name: string;
  run(): Promise<void> | void;
}

/** One step's failure, collected rather than allowed to abort the rest of teardown. */
export interface ShutdownStepFailure {
  step: string;
  error: unknown;
}

/** What happened during one run of teardown. */
export interface ShutdownReport {
  reason: string;
  /** Present when `trigger()` was given a cause (e.g. an `uncaughtException`'s error). */
  cause?: unknown;
  failures: ShutdownStepFailure[];
}

/** The subset of `process` this module needs to register handlers — injectable for tests. */
export interface ProcessLike {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any -- matches Node's own `process.on` overload shape
  on(event: string, listener: (...args: any[]) => void): unknown;
}

export type ExitFn = (code: number) => void;
export type StepErrorReporter = (failure: ShutdownStepFailure) => void;

export interface ShutdownControllerOptions {
  /** Run in this order, every time, regardless of whether an earlier step threw. */
  steps: ShutdownStep[];
  /** Defaults to the real `process`. Override in tests so no real signal handler is attached. */
  process?: ProcessLike;
  /** Defaults to the real `process.exit`. Override in tests so nothing exits the test worker. */
  exit?: ExitFn;
  /** Defaults to `console.error`. Called once per failed step, in addition to it being in the report. */
  onStepError?: StepErrorReporter;
}

// Conventional shell exit codes for a process terminated by a signal
// (128 + signal number) — matches what a shell itself reports for the same
// signal, so a transcript or a `$?` check downstream sees the value it
// already knows how to interpret, the same reasoning `docs/design.md` §4
// applies to `policygate`'s own exit codes (86/87 chosen to be unambiguous
// in a transcript, not to be pretty).
const SIGNAL_EXIT_CODES: Record<string, number> = {
  SIGHUP: 129,
  SIGINT: 130,
  SIGTERM: 143,
};

const UNCAUGHT_EXCEPTION_EXIT_CODE = 1;

function defaultStepErrorReporter(failure: ShutdownStepFailure): void {
  console.error(`corb: shutdown step '${failure.step}' failed:`, failure.error);
}

/**
 * Runs a fixed, ordered list of named async cleanup steps exactly once, no
 * matter how many times (or from how many different signal handlers)
 * `trigger()` is called concurrently or in sequence.
 */
export class ShutdownController {
  private readonly steps: ShutdownStep[];
  private readonly processLike: ProcessLike;
  private readonly exitFn: ExitFn;
  private readonly onStepError: StepErrorReporter;
  private installed = false;
  private inFlight: Promise<ShutdownReport> | null = null;

  constructor(options: ShutdownControllerOptions) {
    this.steps = options.steps;
    this.processLike = options.process ?? process;
    this.exitFn = options.exit ?? ((code) => process.exit(code));
    this.onStepError = options.onStepError ?? defaultStepErrorReporter;
  }

  /** Whether `trigger()` has been called at least once (a shutdown is in progress or done). */
  get isTriggered(): boolean {
    return this.inFlight !== null;
  }

  /**
   * Registers `SIGINT`/`SIGTERM`/`SIGHUP` and `uncaughtException` handlers
   * that all funnel into `trigger()`. Safe to call more than once — only the
   * first call actually registers anything.
   */
  install(): void {
    if (this.installed) {
      return;
    }
    this.installed = true;

    for (const signal of ["SIGHUP", "SIGINT", "SIGTERM"] as const) {
      this.processLike.on(signal, () => {
        void this.trigger(signal, SIGNAL_EXIT_CODES[signal] ?? 1);
      });
    }

    this.processLike.on("uncaughtException", (err: unknown) => {
      void this.trigger("uncaughtException", UNCAUGHT_EXCEPTION_EXIT_CODE, err);
    });
  }

  /**
   * Runs every step in order and then exits. Idempotent: a second call
   * (from a second signal, or from an overlapping trigger while the first
   * is still running its steps) returns the exact same in-flight promise
   * instead of re-running any step or calling `exit` a second time.
   *
   * `cause` (e.g. the error from `uncaughtException`) is accepted for a
   * caller that wants to log it, but is not passed to steps — steps take no
   * arguments by design, since a step must be able to run regardless of
   * *why* teardown started.
   */
  trigger(reason: string, exitCode = 1, cause?: unknown): Promise<ShutdownReport> {
    if (this.inFlight) {
      return this.inFlight;
    }
    this.inFlight = this.runSteps(reason, cause).then((report) => {
      this.exitFn(exitCode);
      return report;
    });
    return this.inFlight;
  }

  private async runSteps(reason: string, cause: unknown): Promise<ShutdownReport> {
    const failures: ShutdownStepFailure[] = [];
    for (const step of this.steps) {
      try {
        await step.run();
      } catch (error) {
        const failure: ShutdownStepFailure = { step: step.name, error };
        failures.push(failure);
        this.onStepError(failure);
      }
    }
    return cause === undefined ? { reason, failures } : { reason, cause, failures };
  }
}
