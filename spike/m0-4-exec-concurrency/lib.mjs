// Shared helpers for the M0.4 exec-concurrency spike (throwaway).
//
// Every wait in this spike is bounded. If Gondolin's exec really does
// serialise, a naive `await` would hang forever and the spike would produce
// no evidence at all; `withTimeout` turns "still pending after N ms" into a
// recorded *result* instead.
import { randomBytes } from "node:crypto";

const T0 = Date.now();

/** Milliseconds since process start, for a rough but consistent timeline in every log line. */
export function elapsed() {
  return Date.now() - T0;
}

// Absolute wall-clock time as well as the relative one: the cross-process
// leg produces two independent logs (holder and attach client) that have to
// be correlated against each other, which a t+ offset alone cannot do.
export function log(...parts) {
  const wall = new Date().toISOString().slice(11, 23);
  console.log(`[${wall} t+${String(elapsed()).padStart(6, " ")}ms]`, ...parts);
}

export function nonce(label) {
  return `${label}_${randomBytes(4).toString("hex").toUpperCase()}`;
}

/**
 * Await `promise` for at most `ms`. Never throws for the timeout case — a
 * timeout is data, not an error.
 *
 * Returns `{ outcome: "resolved" | "rejected" | "timeout", value?, error?, ms }`.
 */
export async function withTimeout(promise, ms, label) {
  const started = Date.now();
  let timer;
  const timeout = new Promise((resolve) => {
    timer = setTimeout(() => resolve({ outcome: "timeout" }), ms);
    timer.unref?.();
  });
  const settled = Promise.resolve(promise).then(
    (value) => ({ outcome: "resolved", value }),
    (error) => ({ outcome: "rejected", error }),
  );
  const result = await Promise.race([settled, timeout]);
  clearTimeout(timer);
  const took = Date.now() - started;
  const detail =
    result.outcome === "rejected" ? ` err=${result.error?.message ?? String(result.error)}` : "";
  log(`  ${label}: ${result.outcome} after ${took}ms${detail}`);
  return { ...result, ms: took, label };
}

/** A growing capture of one exec's output, so cross-talk can be checked after the fact. */
export function captureOutput(proc, tag) {
  const chunks = [];
  const record = (stream) => (buf) => {
    const text = buf.toString("utf8");
    chunks.push({ at: elapsed(), stream, text });
  };
  proc.stdout?.on("data", record("stdout"));
  proc.stderr?.on("data", record("stderr"));
  return {
    tag,
    chunks,
    text() {
      return chunks.map((c) => c.text).join("");
    },
    /** Resolve once `marker` shows up in the accumulated output, or time out. */
    async waitFor(marker, ms) {
      const deadline = Date.now() + ms;
      while (Date.now() < deadline) {
        if (this.text().includes(marker)) return { found: true, ms: ms - (deadline - Date.now()) };
        await new Promise((r) => {
          const t = setTimeout(r, 50);
          t.unref?.();
        });
      }
      return { found: false, ms };
    },
  };
}

/**
 * `execPressure()` and `waitForExecIdle()` live on `SandboxServerOps`, which
 * `VM` holds in a **private** field (`private server` in
 * `dist/src/vm/core.d.ts`) and never re-exposes. TypeScript `private` is
 * compile-time only, so a `.mjs` spike can reach it; production code cannot
 * (and this is itself part of the finding — see the write-up).
 */
export function serverOps(vm) {
  return vm.server ?? null;
}

export function pressure(vm) {
  const ops = serverOps(vm);
  return ops ? ops.execPressure() : "<no server>";
}

/** Print a labelled `execPressure()` sample. */
export function samplePressure(vm, label) {
  const p = pressure(vm);
  log(`  execPressure(${label}) = ${p}`);
  return p;
}
