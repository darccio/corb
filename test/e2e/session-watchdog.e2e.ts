// M8.2 — real-VM proof for the wall-clock session watchdog
// (`src/vm/watchdog.ts`) and its wiring into `runSession()`
// (`src/vm/session.ts`): the sessionLabel format fix, the sidecar
// write/remove around a real session, and (independently) the one SDK
// behavior claim the whole watchdog design is built on.
//
// Gating and layout matches every other suite in this directory exactly:
// `vitest.config.ts` never matches `test/e2e/**`, so a plain `npm test`
// never touches this file, and `describe.skipIf` below additionally gates
// the whole suite on `CORB_E2E=1`. Run via `CORB_E2E=1 npx vitest run
// --config vitest.e2e.config.ts test/e2e/session-watchdog.e2e.ts`,
// `npm run test:e2e`, or `make e2e`.
//
// ## Three independent real-VM proofs, three independent boots
//
// Unlike most suites in this directory, the three `it()` blocks below don't
// share one `beforeAll`-booted VM — each proves something different enough
// (a raw SDK behavior claim vs. two different `runSession()` call shapes)
// that sharing a VM across them would only make failures harder to
// attribute. Each is fully self-contained: boot, assert, close/clean up.
//
// ## Proof 1 — the core SDK claim: does `vm.close()` reject a pending
//    `vm.exec()`, independent of `runSession()`?
//
// This is the load-bearing behavior the entire watchdog design depends on:
// `onExpire` only calls `controller.trigger("watchdog", 124)`, which runs
// `close-vm` (`vm.close()`) as one of its steps — if a pending `await proc`
// inside `runSession()` didn't actually settle when the VM underneath it
// closes, the watchdog would fire but the session would never actually
// unblock. Reading the installed SDK source
// (`node_modules/@earendil-works/gondolin/dist/src/vm/core.js`) says it
// does: `closeInternal()` → `server.close()`/`disconnect()` →
// `handleDisconnect()` → `rejectAll()` → `rejectExecSession()` on every
// still-pending exec session (`dist/src/exec.js`). This test proves it for
// real, against this exact pinned Gondolin version, independent of trusting
// that source read — matching `policygate-content.e2e.ts`'s own stated
// reasoning for driving `VM.create()`/`vm.exec()` directly rather than
// through `runSession()` for a narrow SDK-behavior check.
//
// ## Proofs 2 and 3 — `runSession()` itself
//
// Proof 2 exercises the sidecar/label wiring with no watchdog configured
// (`maxSession` unset), using `pi --version` as the cheap fast-exit path
// (`image/verify.ts`'s own `gatePi` gate uses the identical invocation).
//
// Proof 3 exercises the watchdog forcibly interrupting a real, in-progress
// **production** `pi` exec — not just the low-level `vm.exec()` of Proof 1 —
// using `pi --mode rpc` (`docs/` from the installed
// `@earendil-works/pi-coding-agent` package: RPC mode reads JSONL commands
// from stdin and only starts talking to a model provider once a `prompt`
// command arrives). With nothing ever written to the attached stdin, this
// blocks indefinitely without needing any credential — confirmed
// empirically before writing this test (a throwaway probe script booted a
// real VM, ran `dropcap ... pi --mode rpc` with `pty: false` and an
// unfulfilled stdin, and observed it still running 5 seconds later with no
// error output, then rejecting cleanly on `AbortSignal`). This is the "real,
// safe way to make `pi` block" the M8.2 task brief asked for, using only
// `pi`'s own documented, supported CLI surface — no test-only escape hatch
// added to `session.ts`.
//
// Both `runSession()` proofs pass a fake `shutdownProcess` (`ProcessLike`,
// matching `shutdown.test.ts`'s own `makeFakeProcess()` precedent) so
// `ShutdownController.install()` never attaches a real `SIGINT`/`SIGTERM`/
// `SIGHUP`/`uncaughtException` listener to *this* test process, and a fake
// `exit` (`vi.fn()`) so nothing calls the real `process.exit` and kills the
// test worker — the same discipline `shutdown.test.ts` documents for itself.
// Real `process.stdin`/`stdout` are passed straight through to `runSession()`
// in both proofs (proven safe by the same probe script above: `attachTty`
// only touches `setRawMode`/`resize` when the stream is actually a TTY,
// which a vitest worker's stdio is not), matching production usage exactly
// rather than inventing fake stream objects whose behavior under `attach()`
// would itself be unproven. `stderr` follows the same real-stream default in
// Proof 2; Proof 3 instead passes `makeCapturingStderr()`'s fake — needed
// there, unlike everywhere else in this suite, because that test's whole
// point is asserting on what a normal watchdog-triggered shutdown does *not*
// write to stderr (D2), which a real `process.stderr` can't be observed
// doing. That fake is built on a real `stream.Writable`, not a bare object,
// specifically so it remains a valid `Readable.pipe()` destination under
// `attachTty()` — see its own doc comment.
//
// `CORB_STATE_DIR` is overridden per-proof to an isolated `mkdtemp`
// directory so `writeSessionSidecar`/`removeSessionSidecar`'s default
// `sessionsStateDir()` (`src/vm/session.ts` never passes an explicit
// `sessionsDir`, matching the M8.2 task brief's "no clock/dir injection
// needed here" call) lands somewhere this test controls and can assert
// against, and is restored in a `finally` so it never leaks into any other
// suite run in the same `vitest` process (`fileParallelism: false` makes
// this safe either way, but restoring is cheap and removes any doubt).
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { Writable } from "node:stream";
import { afterEach, describe, expect, it, vi } from "vitest";
import { createHttpHooks, VM } from "@earendil-works/gondolin";
import { resolveRuntimeImage } from "../../src/vm/image.ts";
import { runSession } from "../../src/vm/session.ts";
import { createAuditWriter, type AuditEvent } from "../../src/policy/audit.ts";
import { listSessionSidecars, readSessionSidecar } from "../../src/vm/registry.ts";
import type { ProcessLike } from "../../src/vm/shutdown.ts";
import type { EffectiveEgressConfig, EffectiveGitConfig, EffectivePolicyConfig } from "../../src/config/load.ts";

const EGRESS: EffectiveEgressConfig = {
  "block-internal-ranges": true,
  websockets: false,
  allow: [],
};

const GIT: EffectiveGitConfig = {
  "ssh-agent": false,
  "allow-push": false,
};

// Content checks are irrelevant to this suite (no git/gh use at all), so
// disabled outright rather than left to fail open — matches the reasoning
// `dropcap-status.e2e.ts` applies for features orthogonal to what it tests.
const POLICY: EffectivePolicyConfig = { enabled: false, "secret-scan": true, "fail-open": true };

/** A fake `process` that records nothing and does nothing — matches `shutdown.test.ts`'s own `makeFakeProcess()`, just without the bookkeeping this suite doesn't need. */
function makeFakeProcess(): ProcessLike {
  return { on: () => undefined };
}

/**
 * A capturing stand-in for `runSession()`'s `stderr` option
 * (`RunSessionOptions.stderr`, typed `NodeJS.WriteStream`) — lets a test
 * assert on what would otherwise go straight to the real process's stderr
 * (which a test can't observe). Built on a real `stream.Writable`, not a
 * bare `{ write() {} }` object: `runSession()` passes this stream straight
 * into the SDK's `ExecProcess.attach()`
 * (`node_modules/@earendil-works/gondolin/dist/src/exec.js`), which pipes
 * the guest's own stderr channel into it (`stderrPipe.pipe(stderrOut, {
 * end: false })` in `attachTty()`) any time `vm.exec()` was called with
 * `stderr: "pipe"` — which `runSession()` always does — regardless of
 * whether the guest process ever actually writes anything. `Readable.pipe()`
 * needs a real `EventEmitter`-shaped destination (`on`/`once`/`emit`, not
 * just `write`) to attach itself, which a bare object lacks. Cast to
 * `NodeJS.WriteStream` because a plain `Writable` doesn't structurally match
 * that type (`isTTY`/`columns`/`rows`, etc.) — `session.ts` itself never
 * reads any of those on `stderr`, only `.write()`.
 */
function makeCapturingStderr(): NodeJS.WriteStream & { chunks: Buffer[] } {
  const chunks: Buffer[] = [];
  const writable = new Writable({
    write(chunk: Buffer | string, _encoding, callback) {
      chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
      callback();
    },
  });
  return Object.assign(writable, { chunks }) as unknown as NodeJS.WriteStream & { chunks: Buffer[] };
}

/** Polls `check` every `intervalMs` until it returns a truthy value or `timeoutMs` elapses, returning that value (or throwing on timeout). */
async function pollUntil<T>(check: () => T | undefined, timeoutMs: number, intervalMs = 50): Promise<T> {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    const result = check();
    if (result !== undefined) {
      return result;
    }
    if (Date.now() > deadline) {
      throw new Error(`pollUntil: timed out after ${timeoutMs}ms`);
    }
    await new Promise((resolve) => setTimeout(resolve, intervalMs));
  }
}

const cleanupDirs: string[] = [];
const savedStateDir = process.env.CORB_STATE_DIR;

afterEach(() => {
  process.env.CORB_STATE_DIR = savedStateDir;
  for (const dir of cleanupDirs.splice(0)) {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

describe.skipIf(!process.env.CORB_E2E)("session-watchdog e2e (real VM boot)", () => {
  it(
    "SDK behavior proof: vm.close() rejects a pending vm.exec(), not hangs or resolves",
    async () => {
      const resolvedImage = resolveRuntimeImage();
      const { httpHooks, env } = createHttpHooks({ allowedHosts: [], allowedInternalHosts: [] });
      const vm = await VM.create({
        sandbox: { imagePath: resolvedImage.assetDir },
        dns: { mode: "synthetic", syntheticHostMapping: "per-host" },
        httpHooks,
        env,
        sessionLabel: "corb-e2e-session-watchdog-sdk-proof",
      });

      const proc = vm.exec(["/bin/sleep", "30"], { stdout: "buffer", stderr: "buffer" });

      let settled: "pending" | "resolved" | "rejected" = "pending";
      const observed = proc.then(
        () => {
          settled = "resolved";
        },
        () => {
          settled = "rejected";
        },
      );

      // Give the exec a real moment to actually start running inside the
      // guest before closing out from under it — this is testing "closed
      // while genuinely in flight", not "closed before it ever started".
      await new Promise((resolve) => setTimeout(resolve, 1500));
      expect(settled, "the exec settled on its own before vm.close() was ever called").toBe("pending");

      await vm.close();
      // `vm.close()` itself already awaited every teardown step internally
      // (per the source read), so the exec's promise should already be
      // settled by the time `close()` returns — no extra tick needed, but
      // awaiting `observed` (not a fixed sleep) is the honest way to confirm
      // it either way.
      await observed;

      expect(settled, "vm.close() left the pending exec neither rejected nor resolved (i.e. it hung)").toBe("rejected");
      await expect(proc).rejects.toThrow();
    },
    120_000,
  );

  it(
    "runSession(): sidecar appears with the right id while the session is up, sessionLabel matches corb:<name>:<shortid>, and the sidecar is gone after clean teardown",
    async () => {
      const hostDir = fs.mkdtempSync(path.join(os.tmpdir(), "corb-e2e-session-watchdog-sidecar-"));
      cleanupDirs.push(hostDir);
      const auditDir = fs.mkdtempSync(path.join(os.tmpdir(), "corb-e2e-session-watchdog-sidecar-audit-"));
      cleanupDirs.push(auditDir);
      const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "corb-e2e-session-watchdog-sidecar-state-"));
      cleanupDirs.push(stateDir);
      process.env.CORB_STATE_DIR = stateDir;
      const sessionsDir = path.join(stateDir, "sessions");

      const auditPath = path.join(auditDir, "audit.jsonl");
      const audit = createAuditWriter({ path: auditPath });
      const dirName = path.basename(hostDir);

      const sessionPromise = runSession({
        dirs: [{ name: dirName, hostPath: hostDir, mode: "rw" }],
        primary: dirName,
        // `--version` is `image/verify.ts`'s own `gatePi` gate's exact
        // invocation for "the cheapest real `pi` exec that exits fast".
        piArgs: ["--version"],
        egress: EGRESS,
        git: GIT,
        policy: POLICY,
        dirConfigs: [{ name: dirName, host: hostDir, mode: "rw", rules: [] }],
        audit,
        auditPath,
        stdin: process.stdin,
        stdout: process.stdout,
        stderr: process.stderr,
        shutdownProcess: makeFakeProcess(),
        exit: vi.fn(),
      });

      // The sidecar is written right after `VM.create()` resolves, well
      // before the (fast but not instant) `pi --version` exec completes —
      // poll rather than assume a fixed delay.
      const sidecars = await pollUntil(() => {
        const found = listSessionSidecars(sessionsDir);
        return found.length > 0 ? found : undefined;
      }, 60_000);

      expect(sidecars, `expected exactly one sidecar, found: ${JSON.stringify(sidecars)}`).toHaveLength(1);
      const sidecar = sidecars[0]!;
      // A real UUID — matches `vm.id` (`randomUUID()` internally, per
      // `src/vm/registry.ts`'s own module comment).
      expect(sidecar.id).toMatch(/^[0-9a-f-]{36}$/);
      expect(sidecar.sessionLabel).toMatch(new RegExp(`^corb:${dirName}:[0-9a-f]{8}$`));
      expect(sidecar.dirs).toEqual([{ name: dirName, hostPath: hostDir, mode: "rw" }]);
      expect(sidecar.auditPath).toBe(auditPath);
      expect(sidecar.pid).toBe(process.pid);

      await sessionPromise;

      expect(readSessionSidecar(sidecar.id, sessionsDir), "sidecar was not removed after clean teardown").toBeUndefined();
      expect(listSessionSidecars(sessionsDir)).toEqual([]);
    },
    120_000,
  );

  it(
    "runSession(): a short maxSession forcibly interrupts a real, in-progress pi exec — one watchdog-expired audit line, no spurious error line or stderr output, sidecar still cleaned up",
    async () => {
      const hostDir = fs.mkdtempSync(path.join(os.tmpdir(), "corb-e2e-session-watchdog-fire-"));
      cleanupDirs.push(hostDir);
      const auditDir = fs.mkdtempSync(path.join(os.tmpdir(), "corb-e2e-session-watchdog-fire-audit-"));
      cleanupDirs.push(auditDir);
      const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "corb-e2e-session-watchdog-fire-state-"));
      cleanupDirs.push(stateDir);
      process.env.CORB_STATE_DIR = stateDir;
      const sessionsDir = path.join(stateDir, "sessions");

      const auditPath = path.join(auditDir, "audit.jsonl");
      const audit = createAuditWriter({ path: auditPath });
      const dirName = path.basename(hostDir);

      let vmId: string | undefined;
      // Injectable in place of `process.stderr` specifically so this test can
      // observe it — a real `process.stderr` write can't be asserted on. This
      // is the literal gap the spurious-stack-trace bug (D2) lived in: the
      // sibling audit-log assertion below already covered "no spurious error
      // *record*", but nothing previously covered "no spurious error *stderr
      // output*" for this exact watchdog-fired scenario.
      const fakeStderr = makeCapturingStderr();

      const sessionPromise = runSession({
        dirs: [{ name: dirName, hostPath: hostDir, mode: "rw" }],
        primary: dirName,
        // RPC mode blocks on stdin without ever needing a model credential
        // (see the module comment) — the real, production exec path this
        // proof needs, not a low-level `vm.exec()` stand-in.
        piArgs: ["--mode", "rpc"],
        maxSession: "2s",
        egress: EGRESS,
        git: GIT,
        policy: POLICY,
        dirConfigs: [{ name: dirName, host: hostDir, mode: "rw", rules: [] }],
        audit,
        auditPath,
        stdin: process.stdin,
        stdout: process.stdout,
        stderr: fakeStderr,
        shutdownProcess: makeFakeProcess(),
        exit: vi.fn(),
      });
      // `runSession()`'s catch block always rethrows — a watchdog-triggered
      // close rejects the pending `await proc`, which propagates out here.
      // This is the expected, documented shape of a watchdog firing, not a
      // test failure.
      const observedRejection = sessionPromise.catch((err) => err);

      const sidecar = await pollUntil(() => listSessionSidecars(sessionsDir)[0], 60_000);
      vmId = sidecar.id;

      const err = await observedRejection;
      expect(err, "runSession() resolved instead of rejecting when the watchdog fired").toBeDefined();

      audit.flush();
      const lines = fs
        .readFileSync(auditPath, "utf8")
        .trim()
        .split("\n")
        .map((line) => JSON.parse(line) as AuditEvent);

      const watchdogLines = lines.filter((e) => e.channel === "session" && e.reason === "watchdog-expired");
      expect(watchdogLines, `expected exactly one watchdog-expired line in: ${JSON.stringify(lines)}`).toHaveLength(1);
      expect(watchdogLines[0]?.subject).toBe(sidecar.sessionLabel);

      const errorLines = lines.filter((e) => e.channel === "session" && e.reason === "error");
      expect(errorLines, `expected no spurious error line, found: ${JSON.stringify(errorLines)}`).toHaveLength(0);

      // The D2 fix itself: a watchdog-triggered rejection of the pending
      // `await proc` must not dump `err.stack` to the user's terminal — that
      // stderr write is only for a *genuine, first-cause* error
      // (`!controller.isTriggered`), and this rejection is a side effect of
      // the watchdog's own `close-vm` step, not a first cause.
      const stderrText = Buffer.concat(fakeStderr.chunks).toString("utf8");
      expect(stderrText, `expected nothing written to stderr for a watchdog-triggered shutdown, got: ${JSON.stringify(stderrText)}`).toBe("");

      expect(vmId, "sidecar never appeared before the watchdog should have fired").toBeDefined();
      expect(readSessionSidecar(vmId!, sessionsDir), "sidecar was not removed after the watchdog-triggered teardown").toBeUndefined();
    },
    120_000,
  );
});
