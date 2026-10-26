import { afterEach, expect, it, vi } from "vitest";
import { withBoundedVm } from "../../../src/vm/bounded.ts";
afterEach(() => vi.useRealTimers());
it("closes and drains failed work before returning", async () => {
  const events: string[] = []; const vm = { close: async () => { events.push("close"); } };
  await expect(withBoundedVm(async () => vm, async () => { throw Error("work"); }, () => events.push("closing"))).rejects.toThrow("work");
  expect(events).toEqual(["closing", "close"]);
});
it("closes a VM created after cancellation without running work", async () => {
  let created!: (vm: { close(): Promise<void> }) => void; const close = vi.fn(async () => {}); const work = vi.fn();
  const pending = withBoundedVm(() => new Promise((resolve) => { created = resolve; }), work, () => {});
  const listener = process.listeners("SIGTERM").at(-1)!; listener("SIGTERM"); created({ close });
  await expect(pending).rejects.toThrow("SIGTERM"); expect(close).toHaveBeenCalledOnce(); expect(work).not.toHaveBeenCalled(); expect(process.listeners("SIGTERM")).not.toContain(listener);
});
it("awaits work cleanup after its overall deadline", async () => {
  vi.useFakeTimers(); const events: string[] = []; let fail!: (error: Error) => void;
  const vm = { close: async () => { events.push("close"); fail(Error("closed")); } };
  const pending = withBoundedVm(async () => vm, async () => { try { await new Promise((_resolve, reject) => { fail = reject; }); } finally { await Promise.resolve(); events.push("drained"); } }, () => {}, 1000);
  const result = expect(pending).rejects.toThrow("overall limit"); await vi.advanceTimersByTimeAsync(1000); await result;
  expect(events.at(-1)).toBe("drained");
});
it("closes the VM even when reporting cleanup fails", async () => {
  const close = vi.fn(async () => {});
  await expect(withBoundedVm(async () => ({ close }), async () => 1, () => { throw Error("output"); })).rejects.toThrow("output");
  expect(close).toHaveBeenCalledOnce();
});
