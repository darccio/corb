// M0.4 / R2 — measurement 1, 3, 4 and 5, in a single host process.
//
// With a long-lived `pty: true, stdin: true` exec running (production's
// shape, `src/vm/session.ts`), issue a *second* `vm.exec()` from the same
// process and measure: does it run, does it return promptly, does the first
// exec survive, and is there any cross-talk between the two output streams?
// Also samples `execPressure()` throughout and probes `waitForExecIdle()` and
// `vm.fs` (which internally awaits `waitForExecIdle()`).
//
// Drives `VM.create()` directly rather than `runSession()`, the established
// convention in this repo for narrow SDK-behaviour checks — see
// `test/e2e/policygate-content.e2e.ts` and `test/e2e/dropcap-status.e2e.ts`.
// No `vfs.mounts`: nothing here touches a workspace.
//
// Two long-exec shapes are measured in the same VM boot, because a simple
// stand-in and production's `dropcap`-wrapped shape could plausibly differ
// (dropcap re-execs after dropping privilege, so the pty's controlling
// process is not the process sandboxd started):
//
//   A. `/bin/sh` with a pty            — the simple stand-in
//   B. `dropcap 1000 1000 /bin/sh`     — production's wrapper, same as
//                                        `session.ts`'s `dropcap -> pi`
//                                        modulo which binary is on the end
import { createHttpHooks, VM } from "@earendil-works/gondolin";
import { resolveRuntimeImage } from "../../src/vm/image.ts";
import { captureOutput, log, nonce, samplePressure, serverOps, withTimeout } from "./lib.mjs";

// Matches `image/corb-image.json`'s postBuild and every e2e suite's own
// hardcoded convention for these values.
const AGENT_UID = 1000;
const AGENT_GID = 1000;
const DROPCAP_PATH = "/usr/local/bin/dropcap";
const BASE_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";

const SHORT = 20_000;
const IDLE_PROBE = 6_000;
const BOOT = 180_000;

async function runShape(vm, { name, argv }) {
  log("");
  log(`================ SHAPE ${name}: ${JSON.stringify(argv)} ================`);

  const aliveMarker = nonce("LONG_ALIVE");
  samplePressure(vm, "before any exec");

  // ---- the long-lived exec, in production's shape -------------------------
  const long = vm.exec(argv, {
    env: { PATH: BASE_PATH, TERM: "xterm-256color", PS1: "# " },
    stdin: true,
    pty: true,
    stdout: "pipe",
    stderr: "pipe",
  });
  const longOut = captureOutput(long, "long");
  let longSettled = null;
  void Promise.resolve(long).then(
    (r) => {
      longSettled = { outcome: "resolved", exitCode: r.exitCode };
    },
    (e) => {
      longSettled = { outcome: "rejected", error: e?.message };
    },
  );

  log(`long exec issued (id=${long.id}); proving it is alive before anything else`);
  long.write(`echo ${aliveMarker}\n`);
  const aliveHit = await longOut.waitFor(aliveMarker, SHORT);
  log(`  long exec alive: ${aliveHit.found}`);
  if (!aliveHit.found) {
    log(`  !! long exec never produced its marker; captured so far: ${JSON.stringify(longOut.text())}`);
    return { name, fatal: "long exec never came up" };
  }
  const pLong = samplePressure(vm, "long exec running");

  // ---- MEASUREMENT 1: a second, one-shot exec from the same process -------
  log("MEASUREMENT 1 — second one-shot vm.exec() while the long exec runs");
  const echoMarker = nonce("SECOND_ONESHOT");
  const second = vm.exec(["/bin/echo", echoMarker], { stdout: "buffer", stderr: "buffer" });
  const pDuring = samplePressure(vm, "immediately after issuing the second exec");
  const secondRes = await withTimeout(Promise.resolve(second), SHORT, "second one-shot exec");
  if (secondRes.outcome === "resolved") {
    log(`  exitCode=${secondRes.value.exitCode} stdout=${JSON.stringify(secondRes.value.stdout)}`);
  }
  const pAfterSecond = samplePressure(vm, "after the second exec finished");

  // ---- MEASUREMENT 1b: are they genuinely *parallel*, or just accepted? ---
  // `vm.exec()` returns synchronously but `VM.startExec` is async, so a
  // pressure sample taken on the line right after `vm.exec()` can still read
  // the pre-exec value. Everything below samples only after the exec has
  // demonstrably started, and uses wall-clock time as the independent check:
  // four concurrent 3s sleeps take ~3s if parallel, ~12s if serialised.
  log("MEASUREMENT 1b — four concurrent 3s sleeps alongside the long exec: parallel or serialised?");
  const sleepStarted = Date.now();
  const sleeps = Array.from({ length: 4 }, () =>
    vm.exec(["/bin/sleep", "3"], { stdout: "buffer", stderr: "buffer" }),
  );
  await new Promise((r) => setTimeout(r, 750));
  const pSleeps = samplePressure(vm, "long exec + 4 sleeps, sampled 750ms in");
  const sleepRes = await withTimeout(
    Promise.all(sleeps.map((s) => Promise.resolve(s))),
    30_000,
    "four concurrent 3s sleeps",
  );
  const sleepWall = Date.now() - sleepStarted;
  log(`  wall clock for 4x 'sleep 3': ${sleepWall}ms (parallel ~3000ms, serialised ~12000ms)`);
  if (sleepRes.outcome === "resolved") {
    log(`  exit codes: ${JSON.stringify(sleepRes.value.map((r) => r.exitCode))}`);
  }

  // ---- MEASUREMENT 5: waitForExecIdle() / vm.fs while an exec is live -----
  log("MEASUREMENT 5 — waitForExecIdle() and vm.fs while the long exec is still running");
  const ops = serverOps(vm);
  const idleWhileBusy = await withTimeout(
    ops.waitForExecIdle(),
    IDLE_PROBE,
    "waitForExecIdle() with the long exec running",
  );
  const fsWhileBusy = await withTimeout(
    vm.fs.readFile("/etc/hostname", { encoding: "utf8" }),
    IDLE_PROBE,
    "vm.fs.readFile() with the long exec running",
  );
  const fsStatWhileBusy = await withTimeout(
    vm.fs.stat("/etc/hostname"),
    IDLE_PROBE,
    "vm.fs.stat() with the long exec running (exec-backed, not file-op-backed)",
  );
  if (fsStatWhileBusy.outcome === "resolved") {
    log(`    stat -> ${JSON.stringify(fsStatWhileBusy.value)}`);
  }

  // ---- MEASUREMENT 4: an *interactive* (pty) second exec ------------------
  log("MEASUREMENT 4 — second exec with pty: true + stdin: true (what `corb attach` wants)");
  const ptyMarker = nonce("SECOND_PTY");
  const secondPty = vm.exec(["/bin/sh"], {
    env: { PATH: BASE_PATH, TERM: "xterm-256color", PS1: "$ " },
    stdin: true,
    pty: true,
    stdout: "pipe",
    stderr: "pipe",
  });
  const ptyOut = captureOutput(secondPty, "second-pty");
  const pTwoPty = samplePressure(vm, "two interactive execs live");
  secondPty.write(`echo ${ptyMarker}\n`);
  const ptyHit = await ptyOut.waitFor(ptyMarker, SHORT);
  log(`  second pty exec produced its own marker: ${ptyHit.found}`);
  log(`  second pty exec captured output: ${JSON.stringify(ptyOut.text())}`);

  // Two extra round-trips through the second shell, to be sure it is a real
  // interactive session and not a one-shot fluke.
  const ptyMarker2 = nonce("SECOND_PTY_TURN2");
  secondPty.write(`id -u; echo ${ptyMarker2}\n`);
  const ptyHit2 = await ptyOut.waitFor(ptyMarker2, SHORT);
  log(`  second pty exec second round-trip: ${ptyHit2.found}`);
  // Sampled only now, once *both* interactive execs have provably answered a
  // command — the earlier sample raced `VM.startExec`'s async send.
  const pTwoPtyLive = samplePressure(vm, "two interactive execs, both confirmed live");

  // ---- MEASUREMENT 3: is the FIRST exec still alive and functioning? ------
  log("MEASUREMENT 3 — first exec still alive while the second interactive exec is live");
  const stillMarker = nonce("LONG_STILL_ALIVE");
  const longTextBeforeProbe = longOut.text();
  long.write(`echo ${stillMarker}\n`);
  const stillHit = await longOut.waitFor(stillMarker, SHORT);
  log(`  first exec answered a fresh command while the second was live: ${stillHit.found}`);
  log(`  first exec settled? ${longSettled ? JSON.stringify(longSettled) : "no — still running"}`);

  // ---- cross-talk check ---------------------------------------------------
  const longText = longOut.text();
  const ptyText = ptyOut.text();
  const crossTalk = {
    secondPtyMarkerLeakedIntoFirst: longText.includes(ptyMarker) || longText.includes(ptyMarker2),
    oneShotMarkerLeakedIntoFirst: longText.includes(echoMarker),
    firstMarkersLeakedIntoSecond:
      ptyText.includes(aliveMarker) || ptyText.includes(stillMarker),
  };
  log(`  CROSS-TALK: ${JSON.stringify(crossTalk)}`);
  log(`  first exec output since the probe started: ${JSON.stringify(longText.slice(longTextBeforeProbe.length))}`);

  // ---- tear the second interactive exec down, keep the first ---------------
  secondPty.write("exit\n");
  const ptyResult = await withTimeout(Promise.resolve(secondPty), SHORT, "second pty exec exit");
  if (ptyResult.outcome === "resolved") {
    log(`  second pty exec exitCode=${ptyResult.value.exitCode}`);
  }
  const pAfterPty = samplePressure(vm, "after the second pty exec exited");

  const afterMarker = nonce("LONG_AFTER_SECOND_EXITED");
  long.write(`echo ${afterMarker}\n`);
  const afterHit = await longOut.waitFor(afterMarker, SHORT);
  log(`  first exec still answering after the second exec exited: ${afterHit.found}`);

  // ---- tear the long exec down, then re-probe idle/fs ----------------------
  long.write("exit\n");
  const longResult = await withTimeout(Promise.resolve(long), SHORT, "long exec exit");
  if (longResult.outcome === "resolved") {
    log(`  long exec exitCode=${longResult.value.exitCode}`);
  }
  const pIdle = samplePressure(vm, "no execs running");
  const idleWhenIdle = await withTimeout(
    ops.waitForExecIdle(),
    IDLE_PROBE,
    "waitForExecIdle() with nothing running",
  );
  const fsWhenIdle = await withTimeout(
    vm.fs.readFile("/etc/hostname", { encoding: "utf8" }),
    IDLE_PROBE,
    "vm.fs.readFile() with nothing running",
  );
  if (fsWhenIdle.outcome === "resolved") {
    log(`    readFile -> ${JSON.stringify(fsWhenIdle.value)}`);
  }

  return {
    name,
    longAlive: aliveHit.found,
    secondOneShot: {
      outcome: secondRes.outcome,
      ms: secondRes.ms,
      exitCode: secondRes.value?.exitCode,
      stdout: secondRes.value?.stdout?.trim(),
    },
    secondPty: {
      firstMarker: ptyHit.found,
      secondMarker: ptyHit2.found,
      exit: ptyResult.outcome,
      exitCode: ptyResult.value?.exitCode,
    },
    firstSurvives: {
      whileSecondLive: stillHit.found,
      afterSecondExited: afterHit.found,
      settledEarly: longSettled,
    },
    crossTalk,
    parallelism: {
      wallMsForFourConcurrent3sSleeps: sleepWall,
      pressureDuringSleeps: pSleeps,
      outcome: sleepRes.outcome,
    },
    execPressure: {
      longRunning: pLong,
      sampledRaceyRightAfterIssuingSecond: pDuring,
      afterSecond: pAfterSecond,
      longPlusFourSleeps: pSleeps,
      twoInteractiveSampledRacey: pTwoPty,
      twoInteractiveBothConfirmedLive: pTwoPtyLive,
      afterPtyExit: pAfterPty,
      idle: pIdle,
    },
    waitForExecIdle: { whileBusy: idleWhileBusy.outcome, whenIdle: idleWhenIdle.outcome },
    vmFs: {
      readFileWhileBusy: fsWhileBusy.outcome,
      statWhileBusy: fsStatWhileBusy.outcome,
      readFileWhenIdle: fsWhenIdle.outcome,
    },
  };
}

async function main() {
  log(`GONDOLIN_SESSIONS_DIR=${process.env.GONDOLIN_SESSIONS_DIR}`);
  log(`CORB_STATE_DIR=${process.env.CORB_STATE_DIR}`);
  const image = resolveRuntimeImage();
  log(`image: selector=${image.selector} buildId=${image.buildId} arch=${image.arch}`);
  log(`assetDir=${image.assetDir}`);

  const { httpHooks, env } = createHttpHooks({ allowedHosts: [] });

  const vm = await VM.create({
    sandbox: { imagePath: image.assetDir },
    dns: { mode: "synthetic", syntheticHostMapping: "per-host" },
    httpHooks,
    env,
    sessionLabel: "corb-spike-m0-4-same-process",
  });
  log(`VM.create() returned, id=${vm.id} hostPid=${vm.getHostPid()}`);

  // `VM.create()` resolves before the guest is actually up (it returned in
  // ~90ms on the first run of this spike, with `getHostPid()` still null) —
  // the boot is lazy and happens on the first exec. Force it with a
  // throwaway exec and a boot-sized timeout, so that no later measurement's
  // timeout is really just measuring boot time.
  //
  // `--no-warmup` reproduces the trap this spike fell into first time round:
  // without it, every per-measurement timeout is competing with a ~33s boot
  // and the long exec looks dead. Kept as a runnable negative control, since
  // "the second exec timed out" and "the guest wasn't up yet" are the two
  // readings this whole spike has to be able to tell apart.
  if (process.argv.includes("--no-warmup")) {
    log("--no-warmup: skipping the boot warm-up (negative control)");
  } else {
  const warm = await withTimeout(
    vm.exec(["/bin/echo", "boot-warmup"], { stdout: "buffer", stderr: "buffer" }),
    BOOT,
    "boot warm-up exec",
  );
  if (warm.outcome !== "resolved") {
    throw new Error(`guest never came up: ${warm.outcome}`);
  }
  log(`guest is up; warm-up stdout=${JSON.stringify(warm.value.stdout)} hostPid=${vm.getHostPid()}`);
  }

  const summary = [];
  try {
    summary.push(await runShape(vm, { name: "A (plain /bin/sh + pty)", argv: ["/bin/sh"] }));
    summary.push(
      await runShape(vm, {
        name: "B (dropcap 1000 1000 /bin/sh + pty — production's wrapper)",
        argv: [DROPCAP_PATH, String(AGENT_UID), String(AGENT_GID), "/bin/sh"],
      }),
    );
  } finally {
    log("");
    log("closing VM");
    await vm.close();
    log("VM closed");
  }

  log("");
  log("================ SUMMARY ================");
  console.log(JSON.stringify(summary, null, 2));
}

await main();
