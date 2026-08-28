// M6.1 — independent, non-root e2e proof of the privilege-drop and
// exit-code properties `guest/cmd/dropcap` is supposed to guarantee,
// against the actual pinned runtime image `corb run` boots from — not the
// build pipeline's own throwaway image, and not a root-gated host process.
//
// Two things already assert overlapping properties, and neither counts for
// M6's acceptance criterion ("a test — not a doc — asserts NoNewPrivs=1,
// CapEff=0, empty Groups, uid 1000"):
//
//   - `image/verify.ts`'s `gatePrivilegeDrop` gate asserts exactly this,
//     but only as a precondition of `tagImage()` during `corb image build`
//     (docs/design.md §8: "image gates are not tests — they block
//     tagImage()"), and only against a just-built, not-yet-tagged image —
//     never the pinned image `resolveRuntimeImage()` actually resolves for
//     `corb run`.
//   - `guest/cmd/dropcap/integration_test.go`'s `TestDropcapIntegration`
//     asserts the identical table, but skips itself unless
//     `os.Getuid() == 0`, so it never actually runs its assertions on a
//     normal (non-root) dev machine or CI runner. It also drives the raw
//     binary directly on the host kernel, not inside the real Alpine guest
//     image.
//
// This suite closes both gaps: it boots a real VM from the
// `resolveRuntimeImage()`-resolved runtime image (the exact selector
// `corb run` uses, per `src/vm/image.ts`), execs the real
// `/usr/local/bin/dropcap` inside the booted guest, and asserts against its
// actual output — independent of both the build-gate pipeline and root.
//
// Gating and layout matches the other `test/e2e/**` suites exactly:
// `vitest.config.ts` never matches `test/e2e/**`, so a plain `npm test`
// never touches this file, and `describe.skipIf` below additionally gates
// the whole suite on `CORB_E2E=1`. Run via `CORB_E2E=1 npx vitest run
// --config vitest.e2e.config.ts test/e2e/dropcap-status.e2e.ts`,
// `npm run test:e2e`, or `make e2e`.
//
// Why this drives `VM.create()` directly instead of `runSession()`:
// `runSession()` launches Pi's *interactive* TUI (`dropcap` -> `pi`)
// attached to real stdio and requires a real `ANTHROPIC_API_KEY` — neither
// of which this suite needs or wants. What's under test here is `dropcap`
// itself, wrapping a synthetic `/bin/sh -c 'cat /proc/self/status'` target
// exactly like `image/verify.ts`'s own `gatePrivilegeDrop` technique, never
// the real `pi` binary — every other e2e suite in this repo deliberately
// avoids exec'ing real `pi` for the same reason.
//
// No `vfs.mounts`: this suite never touches a workspace directory, only
// `/proc/self/status` inside the guest. Guest identity (uid/gid 1000,
// `/usr/local/bin/dropcap`, `BASE_PATH`) is hardcoded rather than read from
// `/etc/corb/image.json` at runtime, matching every other e2e suite's own
// documented convention (see `workspace-mounts.e2e.ts`'s module comment) —
// that dynamic read is exercised elsewhere and is orthogonal to what this
// suite tests.
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createHttpHooks, VM } from "@earendil-works/gondolin";
import { resolveRuntimeImage } from "../../src/vm/image.ts";

// Matches `image/corb-image.json`'s `postBuild.commands`
// (`addgroup -g 1000 agent && adduser -D -u 1000 ...`) and `image/verify.ts`'s
// own hardcoded convention for the same values — not read dynamically from
// `/etc/corb/image.json` here, see the module comment for why.
const AGENT_UID = 1000;
const AGENT_GID = 1000;
const DROPCAP_PATH = "/usr/local/bin/dropcap";

// No login shell for any exec (array-form `exec` runs none), matching
// `image/verify.ts`'s own `BASE_PATH` convention.
const BASE_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";

// A path guaranteed to not exist in the guest image — used only to drive
// `dropcap`'s `exec.LookPath` failure path
// (`guest/cmd/dropcap/main.go`'s `execNotFoundExitCode`, 127).
const NONEXISTENT_TARGET = "/usr/local/bin/corb-e2e-does-not-exist";

describe.skipIf(!process.env.CORB_E2E)("dropcap-status e2e (real VM boot)", () => {
  let vm: VM | undefined;

  beforeAll(async () => {
    const resolvedImage = resolveRuntimeImage();
    const { httpHooks, env } = createHttpHooks({ allowedHosts: [], allowedInternalHosts: [] });

    vm = await VM.create({
      sandbox: { imagePath: resolvedImage.assetDir },
      dns: { mode: "synthetic", syntheticHostMapping: "per-host" },
      httpHooks,
      env,
      sessionLabel: "corb-e2e-dropcap-status",
    });
  }, 180_000);

  afterAll(async () => {
    if (vm) {
      await vm.close();
    }
  }, 180_000);

  function requireVm(): VM {
    if (!vm) {
      throw new Error("dropcap-status e2e: VM was not booted (beforeAll must have failed)");
    }
    return vm;
  }

  /** Runs a shell script as the dropped-privilege `agent` uid via `dropcap`, mirroring `image/verify.ts`'s `run` helper and `workspace-mounts.e2e.ts`'s `guestShell`. */
  async function guestShell(script: string) {
    return requireVm().exec([DROPCAP_PATH, String(AGENT_UID), String(AGENT_GID), "/bin/sh", "-c", script], {
      env: { PATH: BASE_PATH },
      stdout: "buffer",
      stderr: "buffer",
    });
  }

  it("drops root privilege before exec: NoNewPrivs=1, CapEff=0, Groups empty, Uid/Gid=1000/1000/1000/1000", async () => {
    const result = await guestShell("cat /proc/self/status");
    expect(result.ok, `exit ${result.exitCode}: ${result.stderr}`).toBe(true);

    const status = result.stdout;
    // [ \t]*, not \s* — mirrors `image/verify.ts`'s `gatePrivilegeDrop`
    // comment exactly: \s* matches "\n" too, so on a value-less line like
    // "Groups:\t \n" a greedy \s* swallows the trailing space *and* the
    // newline, and (.*)$ ends up capturing the *next* line instead of the
    // (correctly) empty Groups value.
    const noNewPrivs = /^NoNewPrivs:[ \t]*(\d+)/m.exec(status)?.[1];
    const capEff = /^CapEff:[ \t]*([0-9a-fA-F]+)/m.exec(status)?.[1];
    const groups = /^Groups:[ \t]*(.*)$/m.exec(status)?.[1]?.trim();
    const uidLine = /^Uid:[ \t]*(.*)$/m.exec(status)?.[1]?.trim();
    const gidLine = /^Gid:[ \t]*(.*)$/m.exec(status)?.[1]?.trim();

    expect(noNewPrivs, status).toBe("1");
    expect(capEff, status).toMatch(/^0+$/);
    expect(groups, status).toBe("");
    expect(uidLine?.split(/\s+/), status).toEqual(["1000", "1000", "1000", "1000"]);
    expect(gidLine?.split(/\s+/), status).toEqual(["1000", "1000", "1000", "1000"]);
  });

  it("targeting a nonexistent binary exits 127, not 0", async () => {
    const result = await requireVm().exec([DROPCAP_PATH, String(AGENT_UID), String(AGENT_GID), NONEXISTENT_TARGET], {
      env: { PATH: BASE_PATH },
      stdout: "buffer",
      stderr: "buffer",
    });

    expect(result.exitCode, `stdout: ${result.stdout}\nstderr: ${result.stderr}`).toBe(127);
  });
});
