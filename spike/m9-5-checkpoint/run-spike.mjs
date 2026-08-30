// Throwaway spike for M9.5: does `vm.checkpoint()` + `VmCheckpoint.resume()`
// actually skip any boot cost versus a cold `VM.create()`, or does the guest
// reboot from scratch (kernel, initramfs, init, sandboxd, sandboxfs,
// bindfs re-export) every time regardless, with checkpoint/resume only
// forking the *disk contents* rather than any execution/memory state?
//
// gondolin-notes.md §2 already states "Checkpoints are disk only. There are
// no memory snapshots." This spike measures whether that has a real, timed
// consequence for corb run's actual startup cost, rather than trusting that
// sentence's implication without checking.
import { VM, VmCheckpoint, createHttpHooks } from "@earendil-works/gondolin";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { resolveRuntimeImage } from "../../src/vm/image.ts";

// Matches M0.4's own precedent (spike/m0-4-exec-concurrency/*.mjs): resolve
// the real, already-tagged runtime image the exact way `corb run` does,
// rather than hand-building a selector string, so what's measured is the
// guest Corb actually ships.
const IMAGE_SELECTOR = resolveRuntimeImage().selector;

function guestBaseEnv() {
  const { httpHooks, env } = createHttpHooks({ allowedHosts: [], allowedInternalHosts: [] });
  return { httpHooks, env };
}

async function timeBoot(label, factory) {
  const t0 = performance.now();
  const vm = await factory();
  const bootMs = performance.now() - t0;
  // Prove the guest is actually usable post-boot, not just that VM.create()'s
  // promise resolved — read /etc/corb/image.json the same way session.ts does.
  const t1 = performance.now();
  const result = await vm.exec(["/bin/cat", "/etc/corb/image.json"], {
    env: { PATH: "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" },
    stdout: "buffer",
    stderr: "buffer",
  });
  const execMs = performance.now() - t1;
  console.log(`[${label}] VM.create() resolved in ${bootMs.toFixed(0)}ms; first exec (cat image.json) in ${execMs.toFixed(0)}ms; ok=${result.ok}`);
  return vm;
}

async function main() {
  const { httpHooks, env } = guestBaseEnv();

  console.log("--- Phase 1: cold boot #1 (baseline) ---");
  const vm1 = await timeBoot("cold-1", () =>
    VM.create({ sandbox: { imagePath: IMAGE_SELECTOR }, dns: { mode: "synthetic", syntheticHostMapping: "per-host" }, httpHooks, env, sessionLabel: "corb-spike-cold-1" }),
  );

  console.log("--- Phase 2: cold boot #2 (baseline, same image, fresh VM.create()) ---");
  const vm2 = await timeBoot("cold-2", () =>
    VM.create({ sandbox: { imagePath: IMAGE_SELECTOR }, dns: { mode: "synthetic", syntheticHostMapping: "per-host" }, httpHooks, env, sessionLabel: "corb-spike-cold-2" }),
  );

  console.log("--- Phase 3: checkpoint vm1, then close it ---");
  const checkpointPath = path.join(os.tmpdir(), `corb-spike-checkpoint-${Date.now()}.qcow2`);
  const t2 = performance.now();
  const checkpoint = await vm1.checkpoint(checkpointPath);
  const checkpointMs = performance.now() - t2;
  console.log(`checkpoint() took ${checkpointMs.toFixed(0)}ms, wrote ${checkpointPath}`);
  console.log(`checkpoint metadata: ${JSON.stringify(checkpoint.toJSON())}`);
  await vm2.close();

  console.log("--- Phase 4: resume from checkpoint, fresh VMOptions (different sessionLabel, own httpHooks) ---");
  const loaded = VmCheckpoint.load(checkpointPath);
  const vm3 = await timeBoot("resume", () =>
    loaded.resume({ dns: { mode: "synthetic", syntheticHostMapping: "per-host" }, httpHooks, env, sessionLabel: "corb-spike-resume" }),
  );

  console.log("--- Phase 5: cold boot #3 (baseline, run again after the resume, for a fair same-run comparison) ---");
  const vm4 = await timeBoot("cold-3", () =>
    VM.create({ sandbox: { imagePath: IMAGE_SELECTOR }, dns: { mode: "synthetic", syntheticHostMapping: "per-host" }, httpHooks, env, sessionLabel: "corb-spike-cold-3" }),
  );

  await vm1.close().catch(() => {});
  await vm3.close();
  await vm4.close();
  fs.rmSync(checkpointPath, { force: true });
  console.log("--- done ---");
}

main().catch((err) => {
  console.error(err);
  process.exitCode = 1;
});
