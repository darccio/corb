// M2.4 — real-VM proof that `src/vm/session.ts`'s generalization from one
// workspace directory to N actually holds up against a booted guest: two
// directories (one `rw`, one `ro`) mounted in a single session, exercised
// from the dropped-privilege guest uid, not assumed to work because the
// host-side types compile.
//
// Gating (belt and suspenders, per the milestone brief): `vitest.config.ts`
// (the config `npm test` uses) only ever matches `test/unit/**/*.test.ts`,
// so this file — under `test/e2e/`, suffixed `.e2e.ts` — is never picked up
// by a plain `npm test` regardless of this file's own content. On top of
// that, `describe.skipIf` below gates the whole suite on `CORB_E2E=1`, so
// even a direct `vitest run --config vitest.e2e.config.ts` without the env
// var reports a clean skip instead of trying to boot a VM. Run for real via
// `npm run test:e2e` (with `CORB_E2E=1` set) or `make e2e` (which also
// rebuilds the guest binary and the image first — see the Makefile).
//
// Why this drives `VM.create()` directly instead of `runSession()`:
// `runSession()` launches Pi's *interactive* TUI (`dropcap` -> `pi`) attached
// to real stdio and requires a real `ANTHROPIC_API_KEY` — neither of which
// this suite needs or wants, since what's under test here is the mount
// mechanism (`WORKSPACE_RAW_ROOT`/`WORKSPACE_PUBLIC_ROOT` and the per-dir
// `RealFSProvider`/`ReadonlyProvider` + `bindfs` re-export), not the agent
// session itself. Importing `session.ts`'s own exported constants and path
// helpers (`rawWorkspacePath`, `publicWorkspacePath`) rather than
// re-deriving `/mnt/corb-raw/<name>` / `/work/<name>` locally means this
// suite exercises the *exact* scheme the production code uses — a drift
// between the two would fail this suite, not silently diverge. Guest
// identity (uid/gid 1000, `/usr/local/bin/dropcap`) is hardcoded rather than
// read from `/etc/corb/image.json` at runtime, matching `image/verify.ts`'s
// own convention (its `gateUser`/`gatePrivilegeDrop` gates do the same) —
// `session.ts`'s dynamic read of that file is itself untested by this suite
// on purpose, since it is already exercised every time `corb run` actually
// runs and is orthogonal to what this milestone changed.
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createHttpHooks, ReadonlyProvider, RealFSProvider, VM, type VirtualProvider } from "@earendil-works/gondolin";
import { resolveRuntimeImage } from "../../src/vm/image.ts";
import { publicWorkspacePath, rawWorkspacePath } from "../../src/vm/session.ts";

const RW_NAME = "rw";
const RO_NAME = "ro";

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

const HOST_RW_MARKER_NAME = "host-rw-marker.txt";
const HOST_RW_MARKER_CONTENT = "host-rw-marker\n";
const HOST_RO_MARKER_NAME = "host-ro-marker.txt";
const HOST_RO_MARKER_CONTENT = "host-ro-marker\n";
const GUEST_WRITTEN_NAME = "guest-written.txt";
const GUEST_WRITTEN_CONTENT = "written-from-guest\n";

describe.skipIf(!process.env.CORB_E2E)("workspace mounts e2e (real VM boot)", () => {
  let rwHostDir: string;
  let roHostDir: string;
  let vm: VM | undefined;

  beforeAll(async () => {
    rwHostDir = fs.mkdtempSync(path.join(os.tmpdir(), "corb-e2e-rw-"));
    roHostDir = fs.mkdtempSync(path.join(os.tmpdir(), "corb-e2e-ro-"));
    fs.writeFileSync(path.join(rwHostDir, HOST_RW_MARKER_NAME), HOST_RW_MARKER_CONTENT);
    fs.writeFileSync(path.join(roHostDir, HOST_RO_MARKER_NAME), HOST_RO_MARKER_CONTENT);

    const resolvedImage = resolveRuntimeImage();
    const { httpHooks, env } = createHttpHooks({ allowedHosts: [], allowedInternalHosts: [] });

    // Exactly the shape `runSession()` builds, generalized to two entries:
    // one plain `RealFSProvider` (`rw`), one `ReadonlyProvider`-wrapped
    // (`ro`), each mounted at its own raw guest path.
    const vfsMounts: Record<string, VirtualProvider> = {
      [rawWorkspacePath(RW_NAME)]: new RealFSProvider(rwHostDir),
      [rawWorkspacePath(RO_NAME)]: new ReadonlyProvider(new RealFSProvider(roHostDir)),
    };

    vm = await VM.create({
      sandbox: { imagePath: resolvedImage.assetDir },
      dns: { mode: "synthetic", syntheticHostMapping: "per-host" },
      httpHooks,
      env,
      vfs: { mounts: vfsMounts },
      sessionLabel: "corb-e2e-workspace-mounts",
    });
  }, 180_000);

  afterAll(async () => {
    try {
      if (vm) {
        await vm.close();
      }
    } finally {
      fs.rmSync(rwHostDir, { recursive: true, force: true });
      fs.rmSync(roHostDir, { recursive: true, force: true });
    }
  }, 180_000);

  function requireVm(): VM {
    if (!vm) {
      throw new Error("workspace-mounts e2e: VM was not booted (beforeAll must have failed)");
    }
    return vm;
  }

  /** Runs a shell script as the dropped-privilege `agent` uid via `dropcap`, mirroring `image/verify.ts`'s `run` helper. */
  async function guestShell(script: string) {
    return requireVm().exec([DROPCAP_PATH, String(AGENT_UID), String(AGENT_GID), "/bin/sh", "-c", script], {
      env: { PATH: BASE_PATH },
      stdout: "buffer",
      stderr: "buffer",
    });
  }

  it("mounts both directories at their public /work/<name> paths", async () => {
    const result = await guestShell(
      `test -d ${publicWorkspacePath(RW_NAME)} && test -d ${publicWorkspacePath(RO_NAME)} && echo BOTH_OK`,
    );
    expect(result.ok, `exit ${result.exitCode}: ${result.stderr}`).toBe(true);
    expect(result.stdout).toContain("BOTH_OK");
  });

  it("rw: a host-created file is visible and readable from the guest", async () => {
    const result = await guestShell(`cat ${publicWorkspacePath(RW_NAME)}/${HOST_RW_MARKER_NAME}`);
    expect(result.ok, `exit ${result.exitCode}: ${result.stderr}`).toBe(true);
    expect(result.stdout).toBe(HOST_RW_MARKER_CONTENT);
  });

  it("rw: a file written from the guest round-trips back to the host directory", async () => {
    const writeResult = await guestShell(
      `printf '%s' '${GUEST_WRITTEN_CONTENT}' > ${publicWorkspacePath(RW_NAME)}/${GUEST_WRITTEN_NAME}`,
    );
    expect(writeResult.ok, `exit ${writeResult.exitCode}: ${writeResult.stderr}`).toBe(true);

    const hostPath = path.join(rwHostDir, GUEST_WRITTEN_NAME);
    expect(fs.existsSync(hostPath), `${hostPath} does not exist on the host after a guest write`).toBe(true);
    expect(fs.readFileSync(hostPath, "utf8")).toBe(GUEST_WRITTEN_CONTENT);
  });

  it("rw: files appear owned by the configured uid/gid from the guest (bindfs squash)", async () => {
    // `-n` (BusyBox `ls`) prints numeric uid/gid instead of resolved names —
    // more portable than a GNU-`stat`-format string, matching
    // `image/verify.ts`'s `gateUser` convention.
    const result = await guestShell(`ls -ln ${publicWorkspacePath(RW_NAME)}/${HOST_RW_MARKER_NAME} | awk '{print $3, $4}'`);
    expect(result.ok, `exit ${result.exitCode}: ${result.stderr}`).toBe(true);
    expect(result.stdout.trim()).toBe(`${AGENT_UID} ${AGENT_GID}`);
  });

  it("ro: a host-created file is readable from the guest", async () => {
    const result = await guestShell(`cat ${publicWorkspacePath(RO_NAME)}/${HOST_RO_MARKER_NAME}`);
    expect(result.ok, `exit ${result.exitCode}: ${result.stderr}`).toBe(true);
    expect(result.stdout).toBe(HOST_RO_MARKER_CONTENT);
  });

  it("ro: files appear owned by the configured uid/gid from the guest (bindfs squash)", async () => {
    const result = await guestShell(`ls -ln ${publicWorkspacePath(RO_NAME)}/${HOST_RO_MARKER_NAME} | awk '{print $3, $4}'`);
    expect(result.ok, `exit ${result.exitCode}: ${result.stderr}`).toBe(true);
    expect(result.stdout.trim()).toBe(`${AGENT_UID} ${AGENT_GID}`);
  });

  // The empirically-required check: the brief is explicit that the
  // host-side `ReadonlyProvider`'s write denial must be observed actually
  // propagating through bindfs -> the raw sandboxfs mount -> the virtio VFS
  // RPC -> the host, not assumed to work because it "should" on paper — the
  // same discipline that caught the FUSE non-root-mount blocker itself
  // (docs/gondolin-notes.md R5/R12) rather than trusting a design doc.
  it("ro: a write attempt from the guest fails", async () => {
    const result = await guestShell(`echo nope > ${publicWorkspacePath(RO_NAME)}/should-not-exist.txt`);
    expect(result.ok, "a write through a ro-mode directory unexpectedly succeeded").toBe(false);
    expect(fs.existsSync(path.join(roHostDir, "should-not-exist.txt"))).toBe(false);
  });
});
