// `src/vm/tty.ts` — M1.5: raw-mode terminal acquire/restore, plus the guard
// for whether it is even safe to ask Gondolin for a pty in the first place.
//
// Why this exists at all: `docs/gondolin-notes.md` §3 records that
// `ExecProcess` has no `kill`/`sendSignal` and no exec timeout, only an
// `AbortSignal` that rejects the local promise without guaranteeing the
// guest process actually dies. Closing the VM (`src/vm/shutdown.ts`) is
// therefore the only real kill switch, and it must run on every exit path —
// including ones the process didn't choose (an uncaught exception, a
// SIGKILL-adjacent situation). If any of those paths leave the host
// terminal in raw mode or stuck in an alternate-screen buffer with a hidden
// cursor, the user's shell is broken until they blindly type `reset` and
// hit enter. That is what this module exists to prevent.
//
// Genuinely unit-testable by construction: nothing here reaches for
// `process.stdin`/`process.stdout` itself. Every function takes the stream
// (or stream-shaped fake) it needs as a parameter, and the `process.on`
// registration used as an exit-time safety net is itself injectable so a
// test can assert the safety net was registered without touching the real
// process object's real "exit" listeners.
//
// What this buys real confidence in, versus what it cannot: everything here
// is exercised in `test/unit/vm/tty.test.ts` against fake streams — raw-mode
// save/restore, idempotency, the non-TTY pty guard, and that the escape
// sequence is written exactly once even across a real `process.emit("exit")`.
// What it cannot prove is that a *real* terminal actually leaves alternate-
// screen mode and shows the cursor again when handed these exact bytes —
// that needs an actual interactive terminal emulator to observe, which no
// unit test (or CI) has. The escape sequences themselves
// (`\x1b[?1049l` exit alt-screen, `\x1b[?25h` show cursor, `\x1b[0m` reset
// SGR) are standard and were not invented for this milestone; verifying them
// against a real terminal is M1.6/manual-QA territory, not this file's.

/**
 * The minimal shape of a readable stream this module needs from `stdin`.
 * Deliberately narrower than `NodeJS.ReadStream` so a plain object literal
 * satisfies it in tests without constructing a real stream.
 */
export interface RawModeCapableStream {
  readonly isTTY?: boolean;
  /** Node's `tty.ReadStream#isRaw`. Absent (non-tty stream) reads as `false`. */
  readonly isRaw?: boolean;
  /** Node's `tty.ReadStream#setRawMode`. Absent on a non-tty stream. */
  setRawMode?(mode: boolean): unknown;
}

/** The minimal shape this module needs from `stdout`. */
export interface WritableTtyStream {
  readonly isTTY?: boolean;
  write(chunk: string): unknown;
}

/** Registers a callback to run on process exit. Defaults to real `process.on("exit", ...)`. */
export type ExitHandlerRegistrar = (listener: () => void) => void;

export interface TtyHandle {
  /**
   * Restores raw mode to whatever it was before `acquire` and writes the
   * exit-alt-screen / show-cursor / reset-SGR escape sequence. Idempotent:
   * calling this more than once (including once explicitly and once via the
   * `process.on("exit")` safety net) has the same effect as calling it once.
   */
  restore(): void;
}

// Exit alternate-screen buffer, re-show the cursor, reset SGR attributes —
// in that order, so a TUI that left color/bold state set doesn't bleed into
// the shell prompt that follows.
export const TERMINAL_RESTORE_SEQUENCE = "\x1b[?1049l\x1b[?25h\x1b[0m";

const defaultRegisterExitHandler: ExitHandlerRegistrar = (listener) => {
  process.on("exit", listener);
};

/**
 * Puts `stdin` into raw mode, remembering whatever mode it was already in,
 * and returns a handle whose `restore()` puts it back — including writing
 * the terminal back out of any alternate-screen buffer with its cursor
 * shown, regardless of why the process is exiting.
 *
 * `restore()` is also registered against `process.on("exit")` (or the
 * injected equivalent) as a safety net, on top of whatever explicit call
 * sites do — the point of this module is that even an exit path nobody
 * anticipated still leaves the terminal usable.
 */
export function acquire(
  stdin: RawModeCapableStream,
  stdout: WritableTtyStream,
  options: { registerExitHandler?: ExitHandlerRegistrar } = {},
): TtyHandle {
  const registerExitHandler = options.registerExitHandler ?? defaultRegisterExitHandler;

  // Not `false` unconditionally — a caller that was already in raw mode for
  // some other reason (an outer harness, a nested acquire) must get that
  // state back, not "off".
  const wasRaw = stdin.isRaw ?? false;
  stdin.setRawMode?.(true);

  let restored = false;
  const restore = (): void => {
    if (restored) {
      return;
    }
    restored = true;
    stdin.setRawMode?.(wasRaw);
    stdout.write(TERMINAL_RESTORE_SEQUENCE);
  };

  registerExitHandler(restore);

  return { restore };
}

/**
 * Whether it is safe to request a pty (`ExecOptions.pty: true`) for this
 * pair of streams at all. `pty: true` must never be requested when either
 * stream is not a real TTY — piped input, a redirected file, or a test
 * harness all report `isTTY !== true`, and asking for a pty in that
 * situation is a corb bug waiting to confuse whoever piped something into
 * `corb run`, not a corner case to special-case later.
 */
export function canRequestPty(
  stdin: Pick<RawModeCapableStream, "isTTY">,
  stdout: Pick<WritableTtyStream, "isTTY">,
): boolean {
  return stdin.isTTY === true && stdout.isTTY === true;
}
