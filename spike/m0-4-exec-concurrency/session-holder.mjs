// M0.4 / R2 — the "corb run" side of the cross-process test.
//
// Boots a real `corb:0.1.0` VM, starts ONE long-lived interactive exec in
// production's exact shape (`dropcap <uid> <gid> /bin/sh`, `pty: true`,
// `stdin: true`, `stdout: "pipe"` — `src/vm/session.ts`'s `dropcap -> pi`
// exec with `pi` swapped for a shell), and then just sits there logging:
//
//   - every byte the long exec emits, timestamped
//   - `execPressure()` every 2s
//
// while accepting commands from the host so that a *separate* process
// (`attach-client.mjs`) can be run against the same session and this side
// can independently confirm the long exec is still alive and uncorrupted.
//
// Commands arrive by appending a line to the file named by `--cmd` (a plain
// append-and-poll channel rather than a FIFO: a FIFO's writer closing gives
// the reader EOF, which would need reopen bookkeeping for no benefit here):
//
//   send <text>   write `<text>\n` into the long exec's stdin
//   pressure      log an execPressure() sample now
//   quit          close the VM and exit 0
//
// The state file named by `--state` is written once the long exec has proven
// itself alive, and carries `vm.id` and the Gondolin session socket path.
import fs from "node:fs";
import { createHttpHooks, VM } from "@earendil-works/gondolin";
import { resolveRuntimeImage } from "../../src/vm/image.ts";
import { gondolinSessionsDir } from "../../src/vm/sockpath.ts";
import { captureOutput, log, nonce, samplePressure, withTimeout } from "./lib.mjs";

const AGENT_UID = 1000;
const AGENT_GID = 1000;
const DROPCAP_PATH = "/usr/local/bin/dropcap";
const BASE_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";
const BOOT = 180_000;

function arg(name) {
  const i = process.argv.indexOf(`--${name}`);
  if (i < 0 || i + 1 >= process.argv.length) throw new Error(`missing --${name}`);
  return process.argv[i + 1];
}

const statePath = arg("state");
const cmdPath = arg("cmd");

async function main() {
  log(`holder pid=${process.pid}`);
  log(`GONDOLIN_SESSIONS_DIR=${process.env.GONDOLIN_SESSIONS_DIR} (derived: ${gondolinSessionsDir()})`);
  const image = resolveRuntimeImage();
  log(`image: selector=${image.selector} buildId=${image.buildId}`);

  const { httpHooks, env } = createHttpHooks({ allowedHosts: [] });
  const vm = await VM.create({
    sandbox: { imagePath: image.assetDir },
    dns: { mode: "synthetic", syntheticHostMapping: "per-host" },
    httpHooks,
    env,
    sessionLabel: "corb-spike-m0-4-session-holder",
  });
  log(`VM.create() returned id=${vm.id}`);

  let exitCode = 0;
  try {
    const warm = await withTimeout(
      vm.exec(["/bin/echo", "boot-warmup"], { stdout: "buffer", stderr: "buffer" }),
      BOOT,
      "boot warm-up exec",
    );
    if (warm.outcome !== "resolved") throw new Error("guest never came up");
    log(`guest up; hostPid=${vm.getHostPid()}`);

    const long = vm.exec([DROPCAP_PATH, String(AGENT_UID), String(AGENT_GID), "/bin/sh"], {
      env: { PATH: BASE_PATH, TERM: "xterm-256color", PS1: "corb-long# " },
      stdin: true,
      pty: true,
      stdout: "pipe",
      stderr: "pipe",
    });
    const out = captureOutput(long, "long");
    // Everything the long exec emits is echoed into this process's log as it
    // arrives, so cross-talk from an attach client's exec would be visible
    // here, in this stream, at the moment it happened.
    long.stdout?.on("data", (b) => log(`  LONG-STDOUT ${JSON.stringify(b.toString("utf8"))}`));
    long.stderr?.on("data", (b) => log(`  LONG-STDERR ${JSON.stringify(b.toString("utf8"))}`));
    let settled = null;
    void Promise.resolve(long).then(
      (r) => {
        settled = `resolved exit=${r.exitCode}`;
        log(`  LONG EXEC SETTLED: ${settled}`);
      },
      (e) => {
        settled = `rejected ${e?.message}`;
        log(`  LONG EXEC SETTLED: ${settled}`);
      },
    );

    const boot = nonce("HOLDER_LONG_UP");
    long.write(`echo ${boot}\n`);
    const hit = await out.waitFor(boot, 20_000);
    if (!hit.found) throw new Error("long exec never came up");
    log(`long exec confirmed alive (id=${long.id})`);
    samplePressure(vm, "long exec only");

    const sockPath = `${gondolinSessionsDir()}/${vm.id}.sock`;
    const state = {
      pid: process.pid,
      vmId: vm.id,
      socketPath: sockPath,
      socketExists: fs.existsSync(sockPath),
      socketPathLength: sockPath.length,
      longExecId: long.id,
    };
    fs.writeFileSync(statePath, JSON.stringify(state, null, 2) + "\n");
    log(`state written: ${JSON.stringify(state)}`);
    if (!state.socketExists) {
      log("!! session socket does not exist — cross-process attach cannot be tested");
    }

    // ---- command loop ------------------------------------------------------
    fs.writeFileSync(cmdPath, "");
    let offset = 0;
    let pending = "";
    const pressureTimer = setInterval(() => samplePressure(vm, "periodic"), 2000);
    pressureTimer.unref?.();

    let quit = false;
    while (!quit) {
      await new Promise((r) => setTimeout(r, 200));
      const size = fs.statSync(cmdPath).size;
      if (size > offset) {
        const fd = fs.openSync(cmdPath, "r");
        const buf = Buffer.alloc(size - offset);
        fs.readSync(fd, buf, 0, buf.length, offset);
        fs.closeSync(fd);
        offset = size;
        pending += buf.toString("utf8");
        let idx;
        while ((idx = pending.indexOf("\n")) >= 0) {
          const line = pending.slice(0, idx);
          pending = pending.slice(idx + 1);
          if (!line.trim()) continue;
          log(`CMD: ${line}`);
          if (line === "quit") {
            quit = true;
            break;
          } else if (line === "pressure") {
            samplePressure(vm, "on demand");
          } else if (line.startsWith("send ")) {
            const text = line.slice("send ".length);
            log(`  writing to long exec stdin: ${JSON.stringify(text)}`);
            long.write(`${text}\n`);
          } else if (line.startsWith("expect ")) {
            const marker = line.slice("expect ".length);
            const found = await out.waitFor(marker, 20_000);
            log(`  EXPECT ${marker} -> ${found.found ? "FOUND in the long exec's own stream" : "NOT FOUND"}`);
          } else if (line.startsWith("assert-absent ")) {
            const marker = line.slice("assert-absent ".length);
            const present = out.text().includes(marker);
            log(`  ASSERT-ABSENT ${marker} -> ${present ? "!! PRESENT (cross-talk)" : "absent (no cross-talk)"}`);
          } else if (line === "status") {
            log(`  long exec settled? ${settled ?? "no — still running"}`);
          } else {
            log(`  unknown command`);
          }
        }
      }
    }
    clearInterval(pressureTimer);
    log(`long exec settled? ${settled ?? "no — still running"}`);
    log(`total long-exec output captured: ${JSON.stringify(out.text())}`);
  } catch (err) {
    log(`holder error: ${err?.stack ?? err}`);
    exitCode = 1;
  } finally {
    log("closing VM");
    await vm.close();
    log("VM closed");
  }
  process.exit(exitCode);
}

await main();
