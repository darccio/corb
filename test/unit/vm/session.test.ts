// Unit tests for `src/vm/session.ts` — the largest file in `src/vm/`, and
// (before this file) covered only indirectly: e2e tests that boot real VMs
// (`test/e2e/session-watchdog.e2e.ts`, `test/e2e/policygate-content.e2e.ts`),
// plus `test/unit/commands/run.test.ts`'s own coverage of `toGlobRules`/
// `InvalidDirRuleError` specifically (that coverage stays where it is — not
// duplicated here).
//
// Two tiers, matching how little of this module is actually VM-shaped:
//
// Tier 1 — every pure/near-pure piece `runSession` is built from
// (`buildGateConfigMount`, `parseCorbImageJson`, workspace-dir validation
// and resolution, path joining), called directly, no VM and no mocked SDK
// anywhere in sight. `resolveHostDir`/`assertValidWorkspaceName`/
// `assertNoDuplicateNames`/`resolveWorkspaceDirs`/`findPrimaryEntry` were
// module-private until this file needed to call them directly — each now
// carries an `export` (and nothing else changed) with a comment pointing
// here; see their own comments in `../../../src/vm/session.ts`.
//
// Tier 2 — `runSession`'s catch-block error reporting. `RunSessionOptions`
// already injects most of `runSession`'s side-effect surface directly
// (stdin/stdout/stderr, shutdownProcess, exit, audit — same as
// `session-watchdog.e2e.ts` already relies on). The one piece that isn't
// injectable is `VM.create` itself, imported directly from
// `@earendil-works/gondolin`. Nothing in this codebase mocks that SDK module
// before this file (`attach.test.ts` only imports a *type* from it) — the
// `vi.mock` below establishes that pattern fresh, scoped to this file only.
//
// The concrete target is the D2 fix ("vm: stop dumping a stack trace on
// every normal shutdown"): `runSession`'s catch block gates both its audit
// "error" record and its `stderr.write` on `!controller.isTriggered`, so an
// *ordinary* shutdown (Ctrl-C, `corb kill`, watchdog expiry) — which also
// rejects the pending exec/VM-create call, just not as a first cause —
// reports nothing. `session-watchdog.e2e.ts`'s own watchdog-fire proof
// covers that *suppressed* case for real. What it explicitly could not
// cover is the mirror image: a genuine, first-cause error (nothing else
// triggered shutdown) still has to reach the user, on stderr and in the
// audit log — proving that requires exactly the VM.create mocking built
// here. Both directions are covered below, the second one reusing the
// mocking scaffold plus a fake `shutdownProcess` (no new SDK surface) to
// simulate a signal racing an in-flight `VM.create()`.
//
// Deliberately NOT attempted: comprehensive coverage of `runSession`'s full
// ~350-line body (resource-limit wiring, watchdog wiring, ingress/expose
// handling, TTY attach, the clean-success exit path). That would need a
// full fake `VM` instance (`.id`, `.exec()` returning both an awaitable
// result and an `.attach()` method, `.close()`, ...) standing in for
// mechanics `session-watchdog.e2e.ts` and `policygate-content.e2e.ts`
// already exercise for real — a substantially larger undertaking than the
// catch-block gap this file exists to close.
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { randomUUID } from "node:crypto";
import { Writable } from "node:stream";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const { vmCreateMock } = vi.hoisted(() => ({ vmCreateMock: vi.fn() }));

// Only `VM` is replaced (with a bare `{ create }` stand-in, not a spread of
// the real class — static class methods are non-enumerable, so `{
// ...actual.VM }` would silently drop `create`). Everything else this
// module and its dependencies pull from `@earendil-works/gondolin`
// (`MemoryProvider`/`ReadonlyProvider`/`RealFSProvider`, `createHttpHooks`,
// `resolveImageSelector`, `setImageRef`, ...) stays the real implementation
// via `importOriginal`, matching `test/unit/commands/run.test.ts`'s own
// partial-mock convention. Confirmed by grep (`grep -rn "\bVM\b" src/`):
// `VM.create` is the only runtime use of this binding anywhere in `src/` —
// everywhere else it's a type annotation (`vm: VM | undefined`), erased at
// compile time — so nothing else in the dependency graph calls a different
// static method or does `new VM()`/`instanceof VM`.
vi.mock("@earendil-works/gondolin", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@earendil-works/gondolin")>();
  return { ...actual, VM: { create: vmCreateMock } };
});

import { setImageRef } from "@earendil-works/gondolin";
import {
  GATE_CONFIG,
  InvalidWorkspaceNameError,
  WORKSPACE_PUBLIC_ROOT,
  WORKSPACE_RAW_ROOT,
  WorkspaceDirectoryError,
  assertNoDuplicateNames,
  assertValidWorkspaceName,
  buildGateConfigMount,
  findPrimaryEntry,
  parseCorbImageJson,
  publicWorkspacePath,
  rawWorkspacePath,
  resolveHostDir,
  resolveWorkspaceDirs,
  runSession,
  type CorbImageJson,
  type RunSessionOptions,
  type WorkspaceDirSpec,
} from "../../../src/vm/session.ts";
import type { EffectiveEgressConfig, EffectiveGitConfig, EffectivePolicyConfig } from "../../../src/config/load.ts";
import type { AuditWriter } from "../../../src/policy/audit.ts";
import type { ProcessLike } from "../../../src/vm/shutdown.ts";

describe("vm/session: buildGateConfigMount", () => {
  it("returns a read-only provider exposing GATE_CONFIG as JSON at its own /gate.json path", () => {
    const provider = buildGateConfigMount();
    expect(provider.readonly).toBe(true);

    const handle = provider.openSync("/gate.json", "r");
    try {
      // `readFileSync`'s declared return type is `Buffer | string` regardless
      // of the encoding argument's literal value — passing "utf8" always
      // yields a real string at runtime, so this cast is narrowing a type
      // the SDK itself leaves imprecise, not asserting past a genuine
      // ambiguity.
      const content = handle.readFileSync("utf8") as string;
      expect(JSON.parse(content)).toEqual(GATE_CONFIG);
    } finally {
      handle.closeSync();
    }
  });

  it("rejects a write attempt (EROFS) — genuinely read-only, not just labeled so", () => {
    const provider = buildGateConfigMount();
    expect(() => provider.openSync("/gate.json", "w")).toThrow();
  });

  it("builds a fresh, independent provider on every call, matching 'generated fresh every runSession call'", () => {
    expect(buildGateConfigMount()).not.toBe(buildGateConfigMount());
  });
});

describe("vm/session: parseCorbImageJson", () => {
  const VALID: CorbImageJson = {
    user: "agent",
    uid: 1000,
    gid: 1000,
    paths: {
      dropcapPath: "/usr/local/bin/dropcap",
      home: "/home/agent",
      sessionsDir: "/home/agent/.pi/sessions",
    },
  };

  it("round-trips a valid CorbImageJson through JSON.stringify/parseCorbImageJson", () => {
    expect(parseCorbImageJson(JSON.stringify(VALID))).toEqual(VALID);
  });

  it("throws a clear error for invalid JSON", () => {
    expect(() => parseCorbImageJson("{ not valid json")).toThrow(/not valid JSON/);
  });

  it("throws when the parsed JSON is not an object (e.g. a bare number)", () => {
    // Not "[1,2,3]": arrays are `typeof "object"` too and would instead fall
    // through to the "missing required fields" branch below — a genuinely
    // different (still-correct) error this case isn't testing.
    expect(() => parseCorbImageJson("42")).toThrow(/did not parse to an object/);
  });

  it.each(["user", "uid", "gid", "paths"] as const)(
    "throws when the top-level field '%s' is missing",
    (field) => {
      const broken = { ...VALID } as Record<string, unknown>;
      delete broken[field];
      expect(() => parseCorbImageJson(JSON.stringify(broken))).toThrow(
        "missing one of the required fields 'user', 'uid', 'gid', 'paths'",
      );
    },
  );

  it.each(["dropcapPath", "home", "sessionsDir"] as const)(
    "throws when the nested paths field '%s' is missing",
    (field) => {
      const broken = { ...VALID, paths: { ...VALID.paths } as Record<string, unknown> };
      delete broken.paths[field];
      expect(() => parseCorbImageJson(JSON.stringify(broken))).toThrow(
        "'paths' is missing one of the required string fields",
      );
    },
  );

  // `src/vm/attach.ts` imports and calls `parseCorbImageJson` directly (its
  // own doc comment says so); confirmed by reading `attach.ts` — it does —
  // but `test/unit/vm/attach.test.ts` only imports the *type* `CorbImageJson`
  // from `session.ts`, never `parseCorbImageJson` itself, so there is no
  // existing coverage of this function to duplicate.
});

describe("vm/session: assertValidWorkspaceName", () => {
  it("throws InvalidWorkspaceNameError with the expected message for an empty name", () => {
    expect(() => assertValidWorkspaceName("")).toThrow(InvalidWorkspaceNameError);
    expect(() => assertValidWorkspaceName("")).toThrow("corb run: workspace directory name '' must not be empty");
  });

  it.each([".", ".."])("throws InvalidWorkspaceNameError for '%s'", (name) => {
    expect(() => assertValidWorkspaceName(name)).toThrow(InvalidWorkspaceNameError);
    expect(() => assertValidWorkspaceName(name)).toThrow("is not a valid directory name");
  });

  it.each(["a/b", "a\\b"])("throws InvalidWorkspaceNameError for a name containing a path separator ('%s')", (name) => {
    expect(() => assertValidWorkspaceName(name)).toThrow(InvalidWorkspaceNameError);
    expect(() => assertValidWorkspaceName(name)).toThrow("must not contain a path separator");
  });

  it("does not throw for an ordinary name", () => {
    expect(() => assertValidWorkspaceName("corb")).not.toThrow();
  });
});

describe("vm/session: assertNoDuplicateNames", () => {
  function spec(name: string): WorkspaceDirSpec {
    return { name, hostPath: "/irrelevant", mode: "rw" };
  }

  it("throws InvalidWorkspaceNameError with the expected message for a genuine duplicate", () => {
    expect(() => assertNoDuplicateNames([spec("a"), spec("a")])).toThrow(InvalidWorkspaceNameError);
    expect(() => assertNoDuplicateNames([spec("a"), spec("a")])).toThrow(
      "corb run: workspace directory name 'a' is used by more than one 'dirs' entry",
    );
  });

  it("does not throw when every name is distinct", () => {
    expect(() => assertNoDuplicateNames([spec("a"), spec("b"), spec("c")])).not.toThrow();
  });

  it("does not throw for an empty list", () => {
    expect(() => assertNoDuplicateNames([])).not.toThrow();
  });
});

describe("vm/session: resolveHostDir", () => {
  let dir: string;

  beforeEach(() => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), "corb-session-hostdir-"));
  });

  afterEach(() => {
    fs.rmSync(dir, { recursive: true, force: true });
  });

  it("resolves a real, existing directory to its absolute path", () => {
    expect(resolveHostDir(dir)).toBe(path.resolve(dir));
  });

  it("throws WorkspaceDirectoryError with reason 'does not exist' for a nonexistent path", () => {
    const missing = path.join(dir, "does-not-exist");
    expect(() => resolveHostDir(missing)).toThrow(WorkspaceDirectoryError);
    expect(() => resolveHostDir(missing)).toThrow(`corb run: workspace directory '${missing}' does not exist`);
  });

  it("throws WorkspaceDirectoryError with reason 'is not a directory' for a path that is a file", () => {
    const filePath = path.join(dir, "a-file");
    fs.writeFileSync(filePath, "hello");
    expect(() => resolveHostDir(filePath)).toThrow(WorkspaceDirectoryError);
    expect(() => resolveHostDir(filePath)).toThrow(`corb run: workspace directory '${filePath}' is not a directory`);
  });
});

describe("vm/session: resolveWorkspaceDirs", () => {
  let dirA: string;
  let dirB: string;

  beforeEach(() => {
    dirA = fs.mkdtempSync(path.join(os.tmpdir(), "corb-session-wsdirs-a-"));
    dirB = fs.mkdtempSync(path.join(os.tmpdir(), "corb-session-wsdirs-b-"));
  });

  afterEach(() => {
    fs.rmSync(dirA, { recursive: true, force: true });
    fs.rmSync(dirB, { recursive: true, force: true });
  });

  it("resolves multiple real directories together, preserving name/hostPath/mode and converting rules", () => {
    const resolved = resolveWorkspaceDirs([
      { name: "a", hostPath: dirA, mode: "rw" },
      {
        name: "b",
        hostPath: dirB,
        mode: "ro",
        rules: [{ glob: "secrets/**", mode: "hidden", reason: "keep secrets out of view" }],
      },
    ]);

    expect(resolved).toEqual([
      { name: "a", hostPath: path.resolve(dirA), mode: "rw", rules: [] },
      {
        name: "b",
        hostPath: path.resolve(dirB),
        mode: "ro",
        rules: [{ glob: "secrets/**", mode: "hidden", reason: "keep secrets out of view" }],
      },
    ]);
  });

  it("creates a missing directory first (mkdir -p) when create is true, then resolves it", () => {
    const notYetThere = path.join(dirA, "nested", "child");
    const resolved = resolveWorkspaceDirs([{ name: "a", hostPath: notYetThere, mode: "rw", create: true }]);

    expect(fs.existsSync(notYetThere)).toBe(true);
    expect(resolved[0]?.hostPath).toBe(path.resolve(notYetThere));
  });

  it("propagates InvalidWorkspaceNameError for a bad name before touching the filesystem", () => {
    expect(() => resolveWorkspaceDirs([{ name: "..", hostPath: dirA, mode: "rw" }])).toThrow(InvalidWorkspaceNameError);
  });

  it("propagates InvalidWorkspaceNameError for duplicate names across entries", () => {
    expect(() =>
      resolveWorkspaceDirs([
        { name: "dup", hostPath: dirA, mode: "rw" },
        { name: "dup", hostPath: dirB, mode: "rw" },
      ]),
    ).toThrow(InvalidWorkspaceNameError);
  });

  it("propagates WorkspaceDirectoryError for a nonexistent directory (create not set)", () => {
    const missing = path.join(dirA, "does-not-exist");
    expect(() => resolveWorkspaceDirs([{ name: "a", hostPath: missing, mode: "rw" }])).toThrow(WorkspaceDirectoryError);
  });
});

describe("vm/session: findPrimaryEntry", () => {
  let dir: string;

  beforeEach(() => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), "corb-session-primary-"));
  });

  afterEach(() => {
    fs.rmSync(dir, { recursive: true, force: true });
  });

  it("returns the matching entry when primary matches a resolved dir's name", () => {
    const resolved = resolveWorkspaceDirs([{ name: "corb", hostPath: dir, mode: "rw" }]);
    expect(findPrimaryEntry(resolved, "corb")).toEqual(resolved[0]);
  });

  it("throws WorkspaceDirectoryError with the expected message when primary matches nothing", () => {
    const resolved = resolveWorkspaceDirs([{ name: "corb", hostPath: dir, mode: "rw" }]);
    expect(() => findPrimaryEntry(resolved, "nope")).toThrow(WorkspaceDirectoryError);
    expect(() => findPrimaryEntry(resolved, "nope")).toThrow(
      "corb run: workspace directory 'nope' is not one of the configured 'dirs' entries (check 'primary')",
    );
  });
});

describe("vm/session: publicWorkspacePath / rawWorkspacePath", () => {
  it("publicWorkspacePath joins WORKSPACE_PUBLIC_ROOT with the given name", () => {
    expect(publicWorkspacePath("corb")).toBe(`${WORKSPACE_PUBLIC_ROOT}/corb`);
  });

  it("rawWorkspacePath joins WORKSPACE_RAW_ROOT with the given name", () => {
    expect(rawWorkspacePath("corb")).toBe(`${WORKSPACE_RAW_ROOT}/corb`);
  });
});

describe("vm/session: runSession catch-block error reporting (mocked VM.create)", () => {
  // The one piece of runSession's pre-VM side-effect surface that isn't
  // injectable through RunSessionOptions: resolveRuntimeImage() runs before
  // the try/catch this suite is testing, so it still needs a real, locally
  // resolvable image selector — planted the same hermetic way
  // `test/unit/vm/image.test.ts` does (an isolated GONDOLIN_IMAGE_STORE +
  // the real setImageRef) — or every test below would fail on
  // ImageNotFoundError before vmCreateMock is ever called, never mind what
  // it's actually testing.
  const IMAGE_SELECTOR = "corb-session-test:1.0.0";

  const EGRESS: EffectiveEgressConfig = { "block-internal-ranges": true, websockets: false, allow: [] };
  const GIT: EffectiveGitConfig = { "ssh-agent": false, "allow-push": false };
  // Content checks are irrelevant to this suite (no git/gh use at all, no
  // VM ever actually boots) — disabled outright, matching
  // `session-watchdog.e2e.ts`'s own reasoning for the identical config.
  const POLICY: EffectivePolicyConfig = { enabled: false, "secret-scan": true, "fail-open": true };

  let hostDir: string;
  let imageStoreDir: string;
  let previousImageStore: string | undefined;

  /** Mirrors `test/unit/vm/image.test.ts`'s own `plantFakeImage` — enough for `resolveImageSelector` to resolve it for real, without needing an actual bootable kernel/rootfs. */
  function plantFakeImage(storeDir: string, reference: string): void {
    const buildId = randomUUID();
    const objectDir = path.join(storeDir, "objects", buildId);
    fs.mkdirSync(objectDir, { recursive: true });
    fs.writeFileSync(
      path.join(objectDir, "manifest.json"),
      JSON.stringify({
        buildId,
        config: { arch: "x86_64" },
        assets: { kernel: "vmlinuz-virt", initramfs: "initramfs.cpio.lz4", rootfs: "rootfs.ext4" },
      }),
    );
    for (const name of ["vmlinuz-virt", "initramfs.cpio.lz4", "rootfs.ext4"]) {
      fs.writeFileSync(path.join(objectDir, name), "");
    }
    setImageRef(reference, buildId, "x86_64");
  }

  /** Matches `test/unit/vm/gitssh.test.ts`/`egress.test.ts`'s own `fakeAudit()` convention. */
  function fakeAudit(): AuditWriter & { record: ReturnType<typeof vi.fn> } {
    return { record: vi.fn(), addRedactedSecrets: vi.fn(), flush: vi.fn() };
  }

  /** Matches `test/unit/vm/shutdown.test.ts`'s own `makeFakeProcess()` — records what it was asked to listen for, without touching the real process. */
  function makeFakeProcess(): ProcessLike & { listeners: Map<string, Array<(...args: unknown[]) => void>> } {
    const listeners = new Map<string, Array<(...args: unknown[]) => void>>();
    return {
      listeners,
      on(event: string, listener: (...args: unknown[]) => void) {
        const existing = listeners.get(event) ?? [];
        existing.push(listener);
        listeners.set(event, existing);
        return this;
      },
    };
  }

  /**
   * Matches `test/e2e/session-watchdog.e2e.ts`'s own `makeCapturingStderr()`:
   * built on a real `stream.Writable` (not a bare `{write(){}}` object) so it
   * would remain a valid `Readable.pipe()` destination if `runSession` ever
   * reached `ExecProcess.attach()` — it doesn't, in either scenario below,
   * but matching the established helper exactly costs nothing and avoids a
   * second, subtly-different stderr fake in this codebase.
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

  function makeOptions(over: {
    audit: AuditWriter;
    stderr: NodeJS.WriteStream;
    shutdownProcess: ProcessLike;
    exit: ReturnType<typeof vi.fn>;
    sessionLabel: string;
  }): RunSessionOptions {
    const dirName = path.basename(hostDir);
    return {
      dirs: [{ name: dirName, hostPath: hostDir, mode: "rw" }],
      primary: dirName,
      piArgs: ["--version"],
      image: IMAGE_SELECTOR,
      egress: EGRESS,
      git: GIT,
      policy: POLICY,
      dirConfigs: [{ name: dirName, host: hostDir, mode: "rw", rules: [] }],
      audit: over.audit,
      auditPath: path.join(hostDir, "audit.jsonl"),
      sessionLabel: over.sessionLabel,
      sessionId: over.sessionLabel,
      env: {},
      stdin: {} as NodeJS.ReadStream,
      stdout: {} as NodeJS.WriteStream,
      stderr: over.stderr,
      shutdownProcess: over.shutdownProcess,
      exit: over.exit,
    };
  }

  beforeEach(() => {
    hostDir = fs.mkdtempSync(path.join(os.tmpdir(), "corb-session-test-work-"));
    imageStoreDir = fs.mkdtempSync(path.join(os.tmpdir(), "corb-session-test-images-"));
    previousImageStore = process.env.GONDOLIN_IMAGE_STORE;
    process.env.GONDOLIN_IMAGE_STORE = imageStoreDir;
    plantFakeImage(imageStoreDir, IMAGE_SELECTOR);
    vmCreateMock.mockReset();
  });

  afterEach(() => {
    if (previousImageStore === undefined) {
      delete process.env.GONDOLIN_IMAGE_STORE;
    } else {
      process.env.GONDOLIN_IMAGE_STORE = previousImageStore;
    }
    fs.rmSync(hostDir, { recursive: true, force: true });
    fs.rmSync(imageStoreDir, { recursive: true, force: true });
  });

  it("a genuine, first-cause VM.create() rejection propagates out of runSession(), writes the error to stderr, and records a channel:session reason:error audit line", async () => {
    const audit = fakeAudit();
    const stderr = makeCapturingStderr();
    const exit = vi.fn();
    const boom = new Error("boom: VM.create failed");
    vmCreateMock.mockRejectedValueOnce(boom);

    const options = makeOptions({
      audit,
      stderr,
      shutdownProcess: makeFakeProcess(),
      exit,
      sessionLabel: "first-cause-session",
    });

    await expect(runSession(options)).rejects.toBe(boom);

    expect(vmCreateMock).toHaveBeenCalledTimes(1);
    expect(audit.record).toHaveBeenCalledWith({
      channel: "session",
      decision: "allow",
      subject: "first-cause-session",
      reason: "error",
      sessionId: "first-cause-session",
    });
    const stderrText = Buffer.concat(stderr.chunks).toString("utf8");
    expect(stderrText).toContain("corb run:");
    expect(stderrText).toContain("boom: VM.create failed");
    expect(exit).toHaveBeenCalledExactlyOnceWith(1);
  });

  it("a rejection arriving after some other trigger (e.g. a signal) already started shutdown suppresses both the audit error line and the stderr write — D2's own e2e proof, at the unit level", async () => {
    const audit = fakeAudit();
    const stderr = makeCapturingStderr();
    const exit = vi.fn();
    const shutdownProcess = makeFakeProcess();
    const boom = new Error("boom: VM.create failed after a signal");
    vmCreateMock.mockRejectedValueOnce(boom);

    const options = makeOptions({ audit, stderr, shutdownProcess, exit, sessionLabel: "triggered-session" });

    const sessionPromise = runSession(options);
    // Fired synchronously, before the pending `await VM.create()` inside
    // runSession has any chance to settle — an `await` always yields at
    // least one microtask turn, even for an already-rejected promise, and
    // everything from `controller.install()` through the `VM.create()` call
    // itself runs synchronously before that first `await` suspends. This
    // simulates a SIGTERM arriving while VM.create() is still in flight —
    // exactly the case runSession's own "Installed before the VM even
    // exists: a signal during boot must still lead to a clean close of
    // whatever got started" comment anticipates.
    const sigtermListener = shutdownProcess.listeners.get("SIGTERM")?.[0];
    expect(sigtermListener, "ShutdownController.install() did not register a SIGTERM listener").toBeDefined();
    sigtermListener?.();

    await expect(sessionPromise).rejects.toBe(boom);

    expect(audit.record).not.toHaveBeenCalledWith(expect.objectContaining({ reason: "error" }));
    const stderrText = Buffer.concat(stderr.chunks).toString("utf8");
    expect(stderrText, `expected nothing written to stderr, got: ${JSON.stringify(stderrText)}`).toBe("");
    // The *first* trigger (SIGTERM, 143) wins — the later, idempotent
    // `controller.trigger("error", 1, err)` call inside the catch block must
    // not re-run steps or call exit a second time with its own code (1).
    expect(exit).toHaveBeenCalledExactlyOnceWith(143);
  });
});
