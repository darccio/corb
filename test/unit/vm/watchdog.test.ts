// Unit tests for `src/vm/watchdog.ts`. Uses `vi.useFakeTimers()` (vitest's
// own documented API — no other test in this repo's `test/unit/vm/` uses
// fake timers, so there is no established in-repo pattern to match beyond
// the general `describe`/`it` style `shutdown.test.ts`/`tty.test.ts` use).
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { startWatchdog } from "../../../src/vm/watchdog.ts";

describe("vm/watchdog startWatchdog", () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it("does not fire onExpire before ms has elapsed", () => {
    const onExpire = vi.fn();
    startWatchdog(1000, onExpire);

    vi.advanceTimersByTime(999);

    expect(onExpire).not.toHaveBeenCalled();
  });

  it("fires onExpire once ms has elapsed", () => {
    const onExpire = vi.fn();
    startWatchdog(1000, onExpire);

    vi.advanceTimersByTime(1000);

    expect(onExpire).toHaveBeenCalledExactlyOnceWith();
  });

  it("clear() before expiry prevents onExpire from ever firing", () => {
    const onExpire = vi.fn();
    const handle = startWatchdog(1000, onExpire);

    handle.clear();
    vi.advanceTimersByTime(10_000);

    expect(onExpire).not.toHaveBeenCalled();
  });

  it("clear() after expiry is a safe no-op", () => {
    const onExpire = vi.fn();
    const handle = startWatchdog(1000, onExpire);

    vi.advanceTimersByTime(1000);
    expect(onExpire).toHaveBeenCalledExactlyOnceWith();

    expect(() => handle.clear()).not.toThrow();
    // Still exactly once — clearing an already-fired timer must not somehow
    // cause a second invocation, and there's nothing left to cancel either.
    expect(onExpire).toHaveBeenCalledExactlyOnceWith();
  });

  it("clear() called twice before expiry is a safe no-op", () => {
    const onExpire = vi.fn();
    const handle = startWatchdog(1000, onExpire);

    handle.clear();
    expect(() => handle.clear()).not.toThrow();
    vi.advanceTimersByTime(10_000);

    expect(onExpire).not.toHaveBeenCalled();
  });
});
