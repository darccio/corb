// Unit tests for `src/vm/tty.ts`. Every stream here is a plain object
// literal, never a real terminal — that is the whole point of the module's
// design (accept stream-shaped parameters instead of reaching for
// `process.stdin`/`process.stdout`). One test at the bottom deliberately
// checks the *default* wiring against the real `process.on`, but only via a
// spy that is torn down before the test ends — nothing here ever emits a
// real "exit" event or touches real terminal state.
import { describe, expect, it, vi } from "vitest";
import { acquire, canRequestPty, TERMINAL_RESTORE_SEQUENCE } from "../../../src/vm/tty.ts";

interface FakeStdin {
  isTTY?: boolean;
  isRaw?: boolean;
  setRawMode: ReturnType<typeof vi.fn>;
}

interface FakeStdout {
  isTTY?: boolean;
  write: ReturnType<typeof vi.fn>;
}

function makeStdin(opts: { isTTY?: boolean; isRaw?: boolean } = {}): FakeStdin {
  return { isTTY: opts.isTTY, isRaw: opts.isRaw, setRawMode: vi.fn() };
}

function makeStdout(opts: { isTTY?: boolean } = {}): FakeStdout {
  return { isTTY: opts.isTTY, write: vi.fn() };
}

describe("vm/tty acquire/restore", () => {
  it("puts stdin into raw mode immediately", () => {
    const stdin = makeStdin({ isTTY: true, isRaw: false });
    const stdout = makeStdout({ isTTY: true });

    acquire(stdin, stdout, { registerExitHandler: vi.fn() });

    expect(stdin.setRawMode).toHaveBeenNthCalledWith(1, true);
  });

  it("restore() sets raw mode back to what it was before, not unconditionally false", () => {
    // The caller was already in raw mode for some other reason before acquiring.
    const stdin = makeStdin({ isTTY: true, isRaw: true });
    const stdout = makeStdout({ isTTY: true });

    const handle = acquire(stdin, stdout, { registerExitHandler: vi.fn() });
    handle.restore();

    expect(stdin.setRawMode).toHaveBeenNthCalledWith(1, true); // acquire's own entry
    expect(stdin.setRawMode).toHaveBeenNthCalledWith(2, true); // restored to true, not false
  });

  it("restore() sets raw mode to false when the caller was not already raw", () => {
    const stdin = makeStdin({ isTTY: true, isRaw: false });
    const stdout = makeStdout({ isTTY: true });

    const handle = acquire(stdin, stdout, { registerExitHandler: vi.fn() });
    handle.restore();

    expect(stdin.setRawMode).toHaveBeenNthCalledWith(2, false);
  });

  it("treats a missing isRaw (non-tty stdin) as 'was not raw'", () => {
    const stdin = makeStdin({ isTTY: false, isRaw: undefined });
    const stdout = makeStdout({ isTTY: true });

    const handle = acquire(stdin, stdout, { registerExitHandler: vi.fn() });
    handle.restore();

    expect(stdin.setRawMode).toHaveBeenNthCalledWith(2, false);
  });

  it("restore() writes exactly the exit-alt-screen/show-cursor/reset-SGR escape sequence", () => {
    const stdin = makeStdin({ isTTY: true, isRaw: false });
    const stdout = makeStdout({ isTTY: true });

    expect(TERMINAL_RESTORE_SEQUENCE).toBe("\x1b[?1049l\x1b[?25h\x1b[0m");

    const handle = acquire(stdin, stdout, { registerExitHandler: vi.fn() });
    handle.restore();

    expect(stdout.write).toHaveBeenCalledExactlyOnceWith(TERMINAL_RESTORE_SEQUENCE);
  });

  it("restore() is idempotent: repeated calls do not re-run setRawMode or re-write the escape sequence", () => {
    const stdin = makeStdin({ isTTY: true, isRaw: false });
    const stdout = makeStdout({ isTTY: true });

    const handle = acquire(stdin, stdout, { registerExitHandler: vi.fn() });
    handle.restore();
    handle.restore();
    handle.restore();

    // Once for acquire()'s own setRawMode(true), once for the first restore()'s setRawMode(false).
    expect(stdin.setRawMode).toHaveBeenCalledTimes(2);
    expect(stdout.write).toHaveBeenCalledTimes(1);
  });

  it("registers restore against the injected exit handler as a safety net, and that path is idempotent too", () => {
    const stdin = makeStdin({ isTTY: true, isRaw: false });
    const stdout = makeStdout({ isTTY: true });
    const registerExitHandler = vi.fn();

    const handle = acquire(stdin, stdout, { registerExitHandler });

    expect(registerExitHandler).toHaveBeenCalledExactlyOnceWith(expect.any(Function));

    // Simulate the process exiting unexpectedly, without any explicit
    // restore() call from the caller — this is the scenario the safety net
    // exists for.
    const [registeredListener] = registerExitHandler.mock.calls[0] as [() => void];
    registeredListener();
    expect(stdout.write).toHaveBeenCalledExactlyOnceWith(TERMINAL_RESTORE_SEQUENCE);

    // An explicit restore() after the safety net already fired must still be
    // a no-op, not a second write.
    handle.restore();
    expect(stdout.write).toHaveBeenCalledTimes(1);
  });

  it("registers against the real process.on('exit', ...) by default", () => {
    const stdin = makeStdin({ isTTY: true, isRaw: false });
    const stdout = makeStdout({ isTTY: true });
    const onSpy = vi.spyOn(process, "on");

    try {
      acquire(stdin, stdout);
      expect(onSpy).toHaveBeenCalledWith("exit", expect.any(Function));
    } finally {
      // Never let the listener acquire() just installed on the *real*
      // process outlive this test — this suite must not leak an "exit"
      // listener (or a raw-mode restore against a fake stdin) into whatever
      // runs after it in the same process.
      const call = onSpy.mock.calls.find(([event]) => event === "exit");
      if (call) {
        process.off("exit", call[1] as () => void);
      }
      onSpy.mockRestore();
    }
  });
});

describe("vm/tty canRequestPty", () => {
  it("is true when both stdin and stdout are real TTYs", () => {
    expect(canRequestPty({ isTTY: true }, { isTTY: true })).toBe(true);
  });

  it("is false when stdin is not a TTY (piped input)", () => {
    expect(canRequestPty({ isTTY: undefined }, { isTTY: true })).toBe(false);
    expect(canRequestPty({ isTTY: false }, { isTTY: true })).toBe(false);
  });

  it("is false when stdout is not a TTY (redirected to a file)", () => {
    expect(canRequestPty({ isTTY: true }, { isTTY: undefined })).toBe(false);
    expect(canRequestPty({ isTTY: true }, { isTTY: false })).toBe(false);
  });

  it("is false when neither stream is a TTY (e.g. a test harness or CI)", () => {
    expect(canRequestPty({}, {})).toBe(false);
  });
});
