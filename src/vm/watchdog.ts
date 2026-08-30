// `src/vm/watchdog.ts` — M8.2: a thin, unit-testable wrapper around the
// wall-clock session watchdog `docs/design.md` §7 describes:
//
//   const watchdog = setTimeout(() => vm.close(), maxSessionMs);
//
// Deliberately not inlined as a raw `setTimeout` call inside
// `src/vm/session.ts` — a dedicated module gives this one small piece of
// timing logic its own unit test (`test/unit/vm/watchdog.test.ts`, driven by
// `vi.useFakeTimers()`) independent of booting a real VM, the same reasoning
// `src/vm/tty.ts` and `src/vm/shutdown.ts` already apply to their own
// pieces of session lifecycle.

/** A running (or already-fired) watchdog timer. */
export interface WatchdogHandle {
  /**
   * Cancels the timer. Safe to call more than once, and safe to call after
   * the timer has already fired — both are standard `clearTimeout`
   * behavior: a second `clearTimeout` on an already-cleared (or already-
   * fired) timer id is simply a no-op, never a throw.
   */
  clear(): void;
}

/**
 * Starts a one-shot timer that calls `onExpire` after `ms` milliseconds
 * unless `clear()` is called first. `onExpire` is never called after
 * `clear()`, no matter how close to expiry `clear()` runs — a timer whose
 * callback has already been scheduled by the event loop but not yet
 * dispatched still has that dispatch cancelled by `clearTimeout` up until
 * the callback actually begins executing, which is the only case that
 * matters for this module's single-fire contract.
 */
export function startWatchdog(ms: number, onExpire: () => void): WatchdogHandle {
  const timer = setTimeout(onExpire, ms);
  return {
    clear(): void {
      clearTimeout(timer);
    },
  };
}
