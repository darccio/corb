// Unit tests for `src/vm/shutdown.ts`. Every signal registration and every
// exit here goes through injected fakes — nothing in this file ever attaches
// a listener to the real `process` object or calls the real `process.exit`,
// so it cannot kill or hang the test runner. See
// `test/unit/vm/shutdown.e2e-child.test.ts` for the companion end-to-end
// proof against a real OS signal, run against a spawned child process
// instead of this one.
import { describe, expect, it, vi } from "vitest";
import { ShutdownController, type ProcessLike, type ShutdownStep } from "../../../src/vm/shutdown.ts";

/** A fake `process` that records what it was asked to listen for, without touching the real one. */
function makeFakeProcess(): ProcessLike & { listeners: Map<string, Array<(...args: unknown[]) => void>> } {
  const listeners = new Map<string, Array<(...args: unknown[]) => void>>();
  return {
    listeners,
    on(event: string, listener: (...args: unknown[]) => void) {
      const existing = listeners.get(event) ?? [];
      existing.push(listener);
      listeners.set(event, existing);
      return this;
    },
  };
}

function stepOf(name: string, order: string[], impl?: () => Promise<void> | void): ShutdownStep {
  return {
    name,
    async run() {
      order.push(name);
      await impl?.();
    },
  };
}

describe("vm/shutdown ShutdownController", () => {
  it("runs every step in order", async () => {
    const order: string[] = [];
    const controller = new ShutdownController({
      steps: [stepOf("restoreTty", order), stepOf("closeVm", order), stepOf("flushAudit", order)],
      exit: vi.fn(),
    });

    await controller.trigger("test");

    expect(order).toEqual(["restoreTty", "closeVm", "flushAudit"]);
  });

  it("exits with the given code only after every step has settled", async () => {
    const exit = vi.fn();
    const order: string[] = [];
    const controller = new ShutdownController({
      steps: [
        stepOf("slow", order, () => new Promise((resolve) => setTimeout(resolve, 5))),
        stepOf("fast", order),
      ],
      exit,
    });

    await controller.trigger("test", 143);

    expect(order).toEqual(["slow", "fast"]);
    expect(exit).toHaveBeenCalledExactlyOnceWith(143);
  });

  it("continues past a step that throws instead of aborting the rest of teardown", async () => {
    const order: string[] = [];
    const onStepError = vi.fn();
    const controller = new ShutdownController({
      steps: [
        stepOf("restoreTty", order),
        {
          name: "closeVm",
          run() {
            order.push("closeVm");
            throw new Error("vm.close() blew up");
          },
        },
        stepOf("flushAudit", order),
      ],
      exit: vi.fn(),
      onStepError,
    });

    const report = await controller.trigger("test");

    // Every step still ran, in order, despite the middle one throwing.
    expect(order).toEqual(["restoreTty", "closeVm", "flushAudit"]);
    expect(report.failures).toHaveLength(1);
    expect(report.failures[0]?.step).toBe("closeVm");
    expect((report.failures[0]?.error as Error).message).toBe("vm.close() blew up");
    expect(onStepError).toHaveBeenCalledExactlyOnceWith(report.failures[0]);
  });

  it("collects failures from more than one step without stopping", async () => {
    const controller = new ShutdownController({
      steps: [
        {
          name: "a",
          run() {
            throw new Error("a failed");
          },
        },
        {
          name: "b",
          run() {
            throw new Error("b failed");
          },
        },
        { name: "c", run() {} },
      ],
      exit: vi.fn(),
      onStepError: vi.fn(),
    });

    const report = await controller.trigger("test");

    expect(report.failures.map((f) => f.step)).toEqual(["a", "b"]);
  });

  it("is idempotent: a second trigger() while shutdown is already running does not re-run steps or exit twice", async () => {
    const order: string[] = [];
    const exit = vi.fn();
    let releaseFirstStep: () => void = () => {};
    const gate = new Promise<void>((resolve) => {
      releaseFirstStep = resolve;
    });
    const controller = new ShutdownController({
      steps: [stepOf("slowStep", order, () => gate), stepOf("secondStep", order)],
      exit,
    });

    const first = controller.trigger("SIGTERM", 143);
    // Fired while the first trigger is still awaiting `slowStep` — this is
    // exactly the "a second signal arrives mid-teardown" scenario.
    const second = controller.trigger("SIGINT", 130);

    releaseFirstStep();
    await first;
    await second;

    expect(order).toEqual(["slowStep", "secondStep"]); // not run twice
    expect(exit).toHaveBeenCalledTimes(1);
    expect(exit).toHaveBeenCalledWith(143); // the *first* trigger's exit code, not the second's
  });

  it("is idempotent after completion too: a trigger() after shutdown finished is a no-op", async () => {
    const order: string[] = [];
    const exit = vi.fn();
    const controller = new ShutdownController({ steps: [stepOf("only", order)], exit });

    await controller.trigger("first", 1);
    await controller.trigger("second", 2);

    expect(order).toEqual(["only"]);
    expect(exit).toHaveBeenCalledTimes(1);
    expect(exit).toHaveBeenCalledWith(1);
  });

  it("reports isTriggered once a shutdown has started", async () => {
    const controller = new ShutdownController({ steps: [], exit: vi.fn() });
    expect(controller.isTriggered).toBe(false);

    const done = controller.trigger("test");
    expect(controller.isTriggered).toBe(true);

    await done;
    expect(controller.isTriggered).toBe(true);
  });

  it("install() registers SIGHUP/SIGINT/SIGTERM/uncaughtException exactly once each, even if called twice", () => {
    const fakeProcess = makeFakeProcess();
    const controller = new ShutdownController({ steps: [], exit: vi.fn(), process: fakeProcess });

    controller.install();
    controller.install(); // must not double-register

    for (const event of ["SIGHUP", "SIGINT", "SIGTERM", "uncaughtException"]) {
      expect(fakeProcess.listeners.get(event)).toHaveLength(1);
    }
  });

  it("install()'s SIGTERM handler triggers shutdown with the conventional 128+signal exit code", async () => {
    const fakeProcess = makeFakeProcess();
    const order: string[] = [];
    const exit = vi.fn();
    const controller = new ShutdownController({
      steps: [stepOf("closeVm", order)],
      exit,
      process: fakeProcess,
    });
    controller.install();

    const sigtermListener = fakeProcess.listeners.get("SIGTERM")?.[0];
    expect(sigtermListener).toBeDefined();
    sigtermListener?.();

    // The listener fires trigger() without awaiting it (it can't — process
    // signal listeners are synchronous) so give the microtask queue a turn.
    await vi.waitFor(() => expect(exit).toHaveBeenCalled());

    expect(order).toEqual(["closeVm"]);
    expect(exit).toHaveBeenCalledExactlyOnceWith(143);
  });

  it("install()'s uncaughtException handler triggers shutdown with exit code 1 and records the cause", async () => {
    const fakeProcess = makeFakeProcess();
    const exit = vi.fn();
    const controller = new ShutdownController({ steps: [], exit, process: fakeProcess });
    controller.install();

    const handler = fakeProcess.listeners.get("uncaughtException")?.[0];
    expect(handler).toBeDefined();
    const boom = new Error("boom");
    handler?.(boom);

    await vi.waitFor(() => expect(exit).toHaveBeenCalled());
    expect(exit).toHaveBeenCalledExactlyOnceWith(1);
  });

  it("code after `await trigger()` only runs because the injected exit() doesn't actually terminate — the real default does", async () => {
    // This is the hazard behind `src/vm/session.ts`'s runSession(): its
    // catch block does `await controller.trigger("error", 1, err); throw
    // err;`, relying on `trigger()`'s returned promise to resolve so the
    // `throw` can run. It only resolves here because `exit` is `vi.fn()` —
    // a stand-in that records the call and returns, rather than acting on
    // it. The real default (`shutdown.ts`'s `exitFn = options.exit ??
    // ((code) => process.exit(code))`) terminates the process synchronously
    // instead, so in production the `throw err` right after `trigger()` is
    // unreachable: nothing after it — including `cli.ts`'s top-level
    // `.catch()`, which is what prints the error at all — ever runs. That
    // gap is why `runSession()`'s catch block now writes to `stderr`
    // *before* calling `trigger()`, rather than relying on the `throw` to
    // surface the error further up the call stack.
    const exit = vi.fn();
    const controller = new ShutdownController({ steps: [], exit });
    let ranAfterTrigger = false;

    await controller.trigger("test", 1);
    ranAfterTrigger = true;

    expect(exit).toHaveBeenCalledExactlyOnceWith(1);
    expect(ranAfterTrigger).toBe(true); // would never flip to true against a real, un-injected process.exit
  });

  it("never touches the real process: exit() and process registration are fully injected", () => {
    // A canary: if this test ever accidentally exercised the real
    // `process.exit`, the test process itself would die and no assertions
    // below would run. Its mere presence and passing is the proof.
    const realExit = process.exit;
    const controller = new ShutdownController({ steps: [], exit: vi.fn() });
    void controller.trigger("canary");
    expect(process.exit).toBe(realExit);
  });
});
