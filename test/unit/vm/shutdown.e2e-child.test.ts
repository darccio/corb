// End-to-end proof of `ShutdownController` against a *real* OS signal —
// deliberately run against a spawned child process, never against this
// (the vitest worker's own) process, so a bug here cannot kill or hang the
// test run itself. Everything else in `shutdown.test.ts` uses injected
// fakes for the process object and the exit function; this file is the one
// place a real `SIGTERM` is actually sent to a real process.
//
// Despite the ".e2e-" in the filename this is a plain, fast vitest test —
// it boots no VM and needs no `CORB_E2E=1` gate (that gate, per
// `plans/let-s-read-the-docs-nifty-russell.md` §7/§8, is for the real-VM
// suite under `test/e2e/`). The name is just an honest label for "this one
// spawns an OS process and sends it a real signal," so a reader scanning
// `test/unit/` for anything unusual finds it immediately.
import { spawn } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const childScript = fileURLToPath(new URL("./fixtures/shutdown-child.ts", import.meta.url));

describe("vm/shutdown end-to-end (real SIGTERM, spawned child process)", () => {
  it("runs the shutdown step and exits with the conventional 128+signal code", async () => {
    const markerPath = path.join(fs.mkdtempSync(path.join(os.tmpdir(), "corb-shutdown-e2e-")), "marker.txt");

    const child = spawn(process.execPath, [childScript, markerPath], {
      stdio: ["ignore", "pipe", "pipe"],
    });
    let stderr = "";
    child.stderr.on("data", (chunk: Buffer) => {
      stderr += chunk.toString("utf8");
    });

    const ready = new Promise<void>((resolve, reject) => {
      let buffered = "";
      child.stdout.on("data", (chunk: Buffer) => {
        buffered += chunk.toString("utf8");
        if (buffered.includes("READY")) {
          resolve();
        }
      });
      child.once("error", reject);
    });
    await ready;

    const exited = new Promise<{ code: number | null; signal: NodeJS.Signals | null }>((resolve) => {
      child.once("exit", (code, signal) => resolve({ code, signal }));
    });

    child.kill("SIGTERM");
    const { code } = await exited;

    expect(code, `child exited with code=${String(code)}; stderr:\n${stderr}`).toBe(143);
    expect(fs.readFileSync(markerPath, "utf8")).toBe("step-ran\n");

    fs.rmSync(path.dirname(markerPath), { recursive: true, force: true });
  }, 15_000);
});
