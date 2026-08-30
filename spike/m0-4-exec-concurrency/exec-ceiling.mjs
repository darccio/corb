// M0.4 / R2 — how many concurrent execs are actually allowed?
//
// Concurrency is real (evidence-01/02), but it is not unbounded:
// `handleExec` rejects with `queue_full` once `execPressure() >=
// options.maxQueuedExecs`, whose default is 64
// (`dist/src/sandbox/server-options.js`). That ceiling is shared by every
// client of the session — the session owner's own execs and every attach
// client's execs land in the same counter — so it is the real bound on how
// many `corb attach` sessions could coexist. Measured here rather than
// trusted from the constant.
//
// One long-lived pty exec (production's shape) is started first, then
// concurrent `sleep 60` execs are issued until the server starts refusing.
import { createHttpHooks, VM } from "@earendil-works/gondolin";
import { resolveRuntimeImage } from "../../src/vm/image.ts";
import { captureOutput, log, nonce, samplePressure, withTimeout } from "./lib.mjs";

const BASE_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";
const BOOT = 180_000;
const ATTEMPTS = 80;

async function main() {
  const image = resolveRuntimeImage();
  log(`image: selector=${image.selector} buildId=${image.buildId}`);
  const { httpHooks, env } = createHttpHooks({ allowedHosts: [] });
  const vm = await VM.create({
    sandbox: { imagePath: image.assetDir },
    dns: { mode: "synthetic", syntheticHostMapping: "per-host" },
    httpHooks,
    env,
    sessionLabel: "corb-spike-m0-4-exec-ceiling",
  });
  log(`VM.create() returned id=${vm.id}`);

  try {
    const warm = await withTimeout(
      vm.exec(["/bin/echo", "boot-warmup"], { stdout: "buffer", stderr: "buffer" }),
      BOOT,
      "boot warm-up exec",
    );
    if (warm.outcome !== "resolved") throw new Error("guest never came up");
    log(`guest up; hostPid=${vm.getHostPid()}`);

    const long = vm.exec(["/bin/sh"], {
      env: { PATH: BASE_PATH, TERM: "xterm-256color", PS1: "# " },
      stdin: true,
      pty: true,
      stdout: "pipe",
      stderr: "pipe",
    });
    const out = captureOutput(long, "long");
    // Required, not cosmetic. `vm.close()` rejects EVERY still-live exec with
    // `server_shutdown` (server-ops.js `failInflight` -> core.js
    // `handleError` -> `rejectExecSession`). Node's default
    // `--unhandled-rejections=throw` turns any such rejection with no handler
    // attached into an uncaught exception that kills the host process *after*
    // the run has already produced its results. The first version of this
    // script omitted this line and died exactly that way — see the write-up.
    void Promise.resolve(long).then(
      (r) => log(`  long exec settled: exit=${r.exitCode}`),
      (e) => log(`  long exec settled: rejected ${e?.message}`),
    );
    const marker = nonce("CEILING_LONG_UP");
    long.write(`echo ${marker}\n`);
    if (!(await out.waitFor(marker, 20_000)).found) throw new Error("long exec never came up");
    log("long pty exec confirmed alive");
    samplePressure(vm, "long exec only");

    log(`issuing ${ATTEMPTS} concurrent 'sleep 60' execs alongside it`);
    const outcomes = [];
    const procs = [];
    for (let i = 0; i < ATTEMPTS; i += 1) {
      const p = vm.exec(["/bin/sleep", "60"], { stdout: "ignore", stderr: "ignore" });
      procs.push(p);
      outcomes.push(
        Promise.resolve(p).then(
          (r) => ({ i, outcome: "resolved", exitCode: r.exitCode }),
          (e) => ({ i, outcome: "rejected", error: e?.message }),
        ),
      );
      // Small stagger so the server's async admission path keeps up and the
      // pressure counter is a true running total rather than a burst race.
      await new Promise((r) => setTimeout(r, 25));
    }

    // Give rejections a moment to arrive, then read the state. Nothing here
    // waits on the sleeps themselves — they take 60s by construction.
    await new Promise((r) => setTimeout(r, 3000));
    const settled = await Promise.all(
      outcomes.map((o) => Promise.race([o, new Promise((r) => setTimeout(() => r(null), 10))])),
    );
    const rejected = settled.filter((s) => s && s.outcome === "rejected");
    const stillRunning = settled.filter((s) => s === null).length;
    log(`still running: ${stillRunning}, rejected: ${rejected.length}`);
    if (rejected.length > 0) {
      log(`first rejection at index ${rejected[0].i}: ${rejected[0].error}`);
      log(`last  rejection at index ${rejected[rejected.length - 1].i}`);
    }
    const pCeiling = samplePressure(vm, "at the ceiling");

    // The long exec must be unharmed by the flood.
    const after = nonce("CEILING_LONG_STILL_ALIVE");
    long.write(`echo ${after}\n`);
    const stillAlive = await out.waitFor(after, 20_000);
    log(`long pty exec still answering after the flood: ${stillAlive.found}`);

    log("");
    log("================ SUMMARY ================");
    console.log(
      JSON.stringify(
        {
          attempts: ATTEMPTS,
          accepted: stillRunning,
          rejected: rejected.length,
          firstRejectionIndex: rejected[0]?.i ?? null,
          rejectionMessage: rejected[0]?.error ?? null,
          execPressureAtCeiling: pCeiling,
          longExecSurvived: stillAlive.found,
        },
        null,
        2,
      ),
    );
  } finally {
    log("closing VM (this abandons the sleeps; vm.close() is the only kill primitive)");
    await vm.close();
    log("VM closed");
  }
}

await main();
