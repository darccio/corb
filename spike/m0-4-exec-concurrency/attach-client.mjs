// M0.4 / R2 — measurement 2: the actual `corb attach` mechanism.
//
// A SEPARATE host process from `session-holder.mjs`. It has no `VM` object
// and no handle on the running session other than the unix socket Gondolin's
// own `registerSession()` created for it. It speaks the raw sandbox control
// protocol over `connectToSession()`:
//
//   client -> server : u32 BE length, then the JSON message
//                      (`connectToSession().send()` does this framing)
//   server -> client : u8 type, u32 BE length, then payload
//                      type 0 = JSON control message
//                      type 1 = binary output frame
//   binary output frame payload: u8 tag (1 stdout / 2 stderr),
//                                u32 BE request id, then the data bytes
//
// (`dist/src/sandbox/control-protocol.d.ts` for the message shapes and the
// frame layout; `dist/src/session-registry.js` for the outer framing and for
// `SessionIpcServer`'s per-client external->internal request-id remapping.)
//
// Three exec shapes are issued, each independently bounded by a timeout:
//
//   1. a one-shot `/bin/echo`                    — does anything run at all?
//   2. an interactive `pty: true` `/bin/sh`      — what `corb attach` wants
//   3. `dropcap 1000 1000 /bin/sh`, `pty: true`  — what `corb attach` would
//                                                  actually have to run
import fs from "node:fs";
import { connectToSession } from "@earendil-works/gondolin";
import { log, nonce } from "./lib.mjs";

const AGENT_UID = 1000;
const AGENT_GID = 1000;
const DROPCAP_PATH = "/usr/local/bin/dropcap";
const BASE_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";

const STEP_TIMEOUT = 20_000;

function arg(name) {
  const i = process.argv.indexOf(`--${name}`);
  if (i < 0 || i + 1 >= process.argv.length) throw new Error(`missing --${name}`);
  return process.argv[i + 1];
}

/** Decode a binary output frame payload: u8 tag, u32 BE id, data. */
function decodeFrame(buf) {
  const tag = buf.readUInt8(0);
  const id = buf.readUInt32BE(1);
  return { id, stream: tag === 2 ? "stderr" : "stdout", data: buf.subarray(5) };
}

function delay(ms) {
  return new Promise((r) => {
    const t = setTimeout(r, ms);
    t.unref?.();
  });
}

async function main() {
  const state = JSON.parse(fs.readFileSync(arg("state"), "utf8"));
  log(`attach client pid=${process.pid}, target session ${state.vmId}`);
  log(`socket: ${state.socketPath} (exists=${fs.existsSync(state.socketPath)}, len=${state.socketPath.length})`);
  if (!fs.existsSync(state.socketPath)) {
    log("!! socket missing — aborting (this would otherwise look like a concurrency failure)");
    process.exit(2);
  }

  /** id -> { out: string[], done: promise handle, response: msg } */
  const execs = new Map();
  const unexpectedFrames = [];
  const jsonLog = [];
  let closedReason = null;

  const conn = connectToSession(state.socketPath, {
    onJson(message) {
      jsonLog.push({ at: Date.now(), message });
      log(`  <- JSON ${JSON.stringify(message)}`);
      if (message.type === "exec_response" || (message.type === "error" && message.id !== undefined)) {
        const rec = execs.get(message.id);
        if (rec) {
          rec.response = message;
          rec.resolve?.(message);
        } else {
          unexpectedFrames.push({ kind: "json-unknown-id", message });
        }
      }
    },
    onBinary(frame) {
      const { id, stream, data } = decodeFrame(frame);
      const rec = execs.get(id);
      if (!rec) {
        unexpectedFrames.push({ kind: "binary-unknown-id", id, stream, text: data.toString("utf8") });
        log(`  <- !! BINARY frame for an id this client never issued: id=${id} ${JSON.stringify(data.toString("utf8"))}`);
        return;
      }
      rec.out.push({ stream, text: data.toString("utf8") });
      log(`  <- ${stream} (id=${id}) ${JSON.stringify(data.toString("utf8"))}`);
    },
    onClose(err) {
      closedReason = err ? err.message : "closed";
      log(`  connection closed: ${closedReason}`);
    },
  });

  let nextId = 1;
  function startExec(spec) {
    const id = nextId++;
    let resolve;
    const done = new Promise((r) => {
      resolve = r;
    });
    const rec = { id, out: [], response: null, resolve, done, started: Date.now() };
    execs.set(id, rec);
    const message = { type: "exec", id, ...spec };
    log(`  -> ${JSON.stringify(message)}`);
    conn.send(message);
    rec.text = () => rec.out.map((c) => c.text).join("");
    rec.waitForMarker = async (marker, ms) => {
      const deadline = Date.now() + ms;
      while (Date.now() < deadline) {
        if (rec.text().includes(marker)) return true;
        await delay(50);
      }
      return false;
    };
    rec.waitForExit = async (ms) => {
      const r = await Promise.race([done, delay(ms).then(() => null)]);
      return r;
    };
    rec.writeStdin = (text) =>
      conn.send({ type: "stdin", id, data: Buffer.from(text, "utf8").toString("base64") });
    return rec;
  }

  const results = {};

  // ---- 1. one-shot exec over the attach socket ----------------------------
  log("");
  log("ATTACH CHECK 1 — one-shot /bin/echo over connectToSession()");
  const m1 = nonce("ATTACH_ONESHOT");
  const e1 = startExec({
    cmd: "/bin/echo",
    argv: [m1],
    env: [`PATH=${BASE_PATH}`],
  });
  const e1Exit = await e1.waitForExit(STEP_TIMEOUT);
  results.oneShot = {
    exited: e1Exit !== null,
    response: e1.response,
    stdout: e1.text(),
    markerEchoedBack: e1.text().includes(m1),
    ms: Date.now() - e1.started,
  };
  log(`  result: ${JSON.stringify(results.oneShot)}`);

  // ---- 2. interactive pty exec over the attach socket ---------------------
  log("");
  log("ATTACH CHECK 2 — interactive pty:true /bin/sh over connectToSession()");
  const e2 = startExec({
    cmd: "/bin/sh",
    env: [`PATH=${BASE_PATH}`, "TERM=xterm-256color", "PS1=attach$ "],
    stdin: true,
    pty: true,
  });
  const m2a = nonce("ATTACH_PTY_TURN1");
  await delay(300);
  conn.send({ type: "pty_resize", id: e2.id, rows: 40, cols: 120 });
  e2.writeStdin(`echo ${m2a}\n`);
  const got2a = await e2.waitForMarker(m2a, STEP_TIMEOUT);
  const m2b = nonce("ATTACH_PTY_TURN2");
  e2.writeStdin(`stty size; id -u; echo ${m2b}\n`);
  const got2b = await e2.waitForMarker(m2b, STEP_TIMEOUT);
  const e2TextBeforeExit = e2.text();
  e2.writeStdin("exit\n");
  const e2Exit = await e2.waitForExit(STEP_TIMEOUT);
  results.interactivePty = {
    turn1: got2a,
    turn2: got2b,
    exited: e2Exit !== null,
    response: e2.response,
    transcript: e2TextBeforeExit,
  };
  log(`  result: ${JSON.stringify(results.interactivePty)}`);

  // ---- 3. the real `corb attach` shape: dropcap + pty shell ---------------
  log("");
  log("ATTACH CHECK 3 — dropcap 1000 1000 /bin/sh, pty:true (what `corb attach` would actually run)");
  const e3 = startExec({
    cmd: DROPCAP_PATH,
    argv: [String(AGENT_UID), String(AGENT_GID), "/bin/sh"],
    env: [`PATH=${BASE_PATH}`, "TERM=xterm-256color", "PS1=attach-agent$ "],
    stdin: true,
    pty: true,
  });
  const m3 = nonce("ATTACH_DROPCAP");
  await delay(300);
  e3.writeStdin(`id -u; id -g; echo ${m3}\n`);
  const got3 = await e3.waitForMarker(m3, STEP_TIMEOUT);

  // While THIS interactive shell is still open, drive the holder's own long
  // exec from here, so both processes' logs show the two interactive execs
  // being used in the same wall-clock window. Without this the attach
  // client's execs are all sub-second and the holder's periodic
  // `execPressure()` sampler would never happen to catch two live at once.
  const cmdPath = process.argv.includes("--cmd") ? arg("cmd") : null;
  let duringMarker = null;
  if (cmdPath) {
    duringMarker = nonce("DURING_ATTACH_LONG_EXEC");
    log(`  holding this attach shell open; driving the holder's long exec concurrently (${duringMarker})`);
    fs.appendFileSync(
      cmdPath,
      ["pressure", "status", `send echo ${duringMarker}`, `expect ${duringMarker}`, "pressure", "status", ""].join("\n"),
    );
    // Long enough for the holder's 2s periodic sampler to fire at least twice
    // with both interactive execs live, and for its `expect` to complete.
    await delay(8000);
    e3.writeStdin(`echo STILL_HERE_${duringMarker}\n`);
    await e3.waitForMarker(`STILL_HERE_${duringMarker}`, STEP_TIMEOUT);
  }

  const e3TextBeforeExit = e3.text();
  e3.writeStdin("exit\n");
  const e3Exit = await e3.waitForExit(STEP_TIMEOUT);
  results.dropcapPty = {
    answered: got3,
    exited: e3Exit !== null,
    response: e3.response,
    heldOpenWhileDrivingHoldersLongExec: duringMarker,
    transcript: e3TextBeforeExit,
  };
  log(`  result: ${JSON.stringify(results.dropcapPty)}`);

  // ---- 4. can the attach client reach the long exec at all? ---------------
  // The control protocol has no "list execs" and no "join exec N" message, so
  // the only thing that can be tried is addressing an id directly. The
  // holder's long exec has a small VM-internal id; SessionIpcServer maps ids
  // per client, so this should be rejected as unknown rather than hijack it.
  log("");
  log("ATTACH CHECK 4 — try to address the holder's long exec by id (stdin to it)");
  log(`  holder's long exec has VM-internal id=${state.longExecId}`);
  const hijackMarker = nonce("ATTACH_HIJACK_ATTEMPT");
  conn.send({
    type: "stdin",
    id: state.longExecId,
    data: Buffer.from(`echo ${hijackMarker}\n`, "utf8").toString("base64"),
  });
  conn.send({ type: "pty_resize", id: state.longExecId, rows: 1, cols: 1 });
  await delay(1500);
  results.hijackAttempt = {
    marker: hijackMarker,
    jsonSinceAttempt: jsonLog.slice(-4).map((e) => e.message),
  };
  log(`  result: ${JSON.stringify(results.hijackAttempt)}`);

  log("");
  log(`unexpected frames (would be cross-talk): ${JSON.stringify(unexpectedFrames)}`);
  log(`connection state at end: ${closedReason ?? "still open"}`);
  conn.close();

  log("");
  log("================ ATTACH SUMMARY ================");
  console.log(JSON.stringify({ ...results, unexpectedFrames, closedReason }, null, 2));
}

await main();
