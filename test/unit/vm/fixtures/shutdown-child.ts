// A tiny standalone child process used only by
// `test/unit/vm/shutdown.e2e-child.test.ts` to prove `ShutdownController`'s
// teardown against a *real* OS signal. Deliberately never run against the
// test runner's own process — the M1.5 brief requires that a real-signal
// proof, if attempted at all, targets a spawned child, precisely so a bug in
// this file (or in `ShutdownController` itself) cannot kill or hang the
// vitest worker running the suite.
import fs from "node:fs";
import { ShutdownController } from "../../../../src/vm/shutdown.ts";

const markerPath = process.argv[2];
if (!markerPath) {
  console.error("usage: shutdown-child.ts <marker-file-path>");
  process.exit(2);
}

const controller = new ShutdownController({
  steps: [
    {
      name: "write-marker",
      run() {
        // Proof, checked by the parent test, that the step actually ran
        // (and ran before the process exited) rather than the exit code
        // alone, which a process could produce by accident.
        fs.writeFileSync(markerPath, "step-ran\n");
      },
    },
  ],
  // No injected `exit`/`process` here on purpose: this process *is* the
  // thing under test for the real-signal proof, so it uses the real
  // `process.exit` and the real `process.on`.
});
controller.install();

// A registered signal listener does not, by itself, keep the event loop
// alive — without something else scheduled, Node would exit on its own the
// moment this script finishes running, before any signal ever arrives.
setInterval(() => {}, 1000);

process.stdout.write("READY\n");
