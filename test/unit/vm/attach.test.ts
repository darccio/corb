// Unit tests for `src/vm/attach.ts` — M8.7.
//
// Same split every other M8 command test file uses: `resolveAttachTarget`
// and `renderAttachRefusal` are tested against fabricated `SessionEntry`/
// `SessionSidecar` values (mirroring `kill.test.ts`'s own fabrication
// style), the pure exec-message-building helpers are asserted directly, and
// `runAttachSession` is driven through a fully fake `connect` (never a real
// socket) that lets a test script exactly what the "server" side of the raw
// protocol does and when — including, critically, closing the connection
// mid-session, which is the single scenario the M8.7 brief calls out as the
// most important thing to get right (a closed connection must resolve
// `runAttachSession` cleanly, never throw and never leave anything
// unhandled).
import { describe, expect, it, vi } from "vitest";
import type { SessionEntry } from "@earendil-works/gondolin";
import {
  ATTACH_CONNECTION_ENDED_EXIT_CODE,
  IDENTITY_EXEC_ID,
  SHELL_EXEC_ID,
  buildAttachEnv,
  buildAttachShellExecMessage,
  buildIdentityExecMessage,
  renderAttachRefusal,
  resolveAttachTarget,
  runAttachSession,
  type AttachPlan,
  type AttachStdin,
  type AttachStdout,
  type ConnectFn,
} from "../../../src/vm/attach.ts";
import type { KillLookup } from "../../../src/commands/kill.ts";
import type { CorbImageJson } from "../../../src/vm/session.ts";
import type { SessionSidecar } from "../../../src/vm/registry.ts";
import type { AuditWriter } from "../../../src/policy/audit.ts";

const ID_A = "aaaaaaaa-1111-4111-8111-000000000001";
const ID_B = "bbbbbbbb-2222-4222-8222-000000000002";
const ID_B2 = "bbbbbbbb-2222-4999-8999-000000000099";

function entry(id: string, overrides: Partial<SessionEntry> = {}): SessionEntry {
  return {
    id,
    pid: 4242,
    socketPath: `/tmp/gondolin/${id}.sock`,
    createdAt: "2026-08-30T12:00:00.000Z",
    label: `corb:proj:${id.slice(0, 8)}`,
    alive: true,
    ...overrides,
  };
}

function sidecar(id: string, overrides: Partial<SessionSidecar> = {}): SessionSidecar {
  return {
    id,
    sessionLabel: `corb:proj:${id.slice(0, 8)}`,
    dirs: [{ name: "proj", hostPath: "/home/u/proj", mode: "rw" }],
    image: { selector: "corb:0.1.0", buildId: "abc123" },
    auditPath: "/home/u/.local/state/corb/audit.jsonl",
    pid: 4242,
    startedAt: "2026-08-30T12:00:00.000Z",
    ...overrides,
  };
}

/** The exact message shape Gondolin's `findSession` throws for an ambiguous prefix (mirrors `kill.test.ts`'s own helper). */
function sdkAmbiguousMessage(query: string, ids: string[]): string {
  return `ambiguous session prefix '${query}' matches ${ids.length} sessions:\n` + ids.map((id) => `  ${id}`).join("\n");
}

describe("vm/attach: resolveAttachTarget", () => {
  it("plans a connect for an alive entry, carrying its socket path", () => {
    const plan = resolveAttachTarget(ID_A, { entry: entry(ID_A), sidecars: [] });
    expect(plan).toEqual({ kind: "connect", id: ID_A, socketPath: `/tmp/gondolin/${ID_A}.sock`, label: `corb:proj:${ID_A.slice(0, 8)}` });
  });

  it("refuses a resolved session that is not alive", () => {
    const plan = resolveAttachTarget(ID_A, { entry: entry(ID_A, { alive: false }), sidecars: [] });
    expect(plan).toEqual({ kind: "not-alive", id: ID_A, pid: 4242, label: `corb:proj:${ID_A.slice(0, 8)}` });
  });

  it("reports an ambiguous prefix from the message findSession threw", () => {
    const plan = resolveAttachTarget("bbbb", { entry: null, ambiguousMessage: sdkAmbiguousMessage("bbbb", [ID_B, ID_B2]), sidecars: [] });
    expect(plan).toEqual({ kind: "ambiguous", candidates: [ID_B, ID_B2], rawMessage: sdkAmbiguousMessage("bbbb", [ID_B, ID_B2]) });
  });

  it("reports not-found when neither registry knows the query", () => {
    expect(resolveAttachTarget("zzzz", { entry: null, sidecars: [sidecar(ID_A)] })).toEqual({ kind: "not-found" });
  });

  it("falls back to corb's own sidecars when Gondolin has no entry", () => {
    const plan = resolveAttachTarget(ID_A, { entry: null, sidecars: [sidecar(ID_A)] });
    expect(plan).toEqual({ kind: "sidecar-only", id: ID_A, pid: 4242, label: `corb:proj:${ID_A.slice(0, 8)}` });
  });

  it("reports an ambiguous sidecar prefix rather than picking one to connect to", () => {
    const plan = resolveAttachTarget("bbbb", { entry: null, sidecars: [sidecar(ID_B), sidecar(ID_B2)] });
    expect(plan.kind).toBe("ambiguous");
  });

  it("never plans a connect from a sidecar alone, however alive its recorded pid looks", () => {
    const plan = resolveAttachTarget(ID_A, { entry: null, sidecars: [sidecar(ID_A, { pid: process.pid })] });
    expect(plan.kind).not.toBe("connect");
  });
});

describe("vm/attach: renderAttachRefusal", () => {
  it("points a no-match at corb ls", () => {
    const text = renderAttachRefusal("zzzz", { kind: "not-found" });
    expect(text).toContain("no session matches 'zzzz'");
    expect(text).toContain("corb ls");
  });

  it("lists every candidate for an ambiguous query and says nothing was attached", () => {
    const text = renderAttachRefusal("bbbb", { kind: "ambiguous", candidates: [ID_B, ID_B2], rawMessage: "" });
    expect(text).toContain(ID_B);
    expect(text).toContain(ID_B2);
    expect(text).toContain("Nothing was attached");
  });

  it("explains a stale registry entry in terms of no live socket", () => {
    const text = renderAttachRefusal(ID_A, { kind: "not-alive", id: ID_A, pid: 4242, label: "corb:proj:aaaa" });
    expect(text).toContain("is not running");
    expect(text).toContain("Nothing was attached");
  });

  it("explains a sidecar-only session, names the leftover file, and mentions corb gc", () => {
    const text = renderAttachRefusal(ID_A, { kind: "sidecar-only", id: ID_A, pid: 4242, label: "corb:proj:aaaa" }, "/state/sessions/a.json");
    expect(text).toContain("no live Gondolin session entry");
    expect(text).toContain("/state/sessions/a.json");
    expect(text).toContain("corb gc");
    expect(text).toContain("Nothing was attached");
  });
});

const IDENTITY: CorbImageJson = {
  user: "agent",
  uid: 1000,
  gid: 1000,
  paths: { dropcapPath: "/usr/local/bin/dropcap", home: "/home/agent", sessionsDir: "/home/agent/.pi-sessions" },
};

describe("vm/attach: exec-message-construction helpers", () => {
  it("buildIdentityExecMessage: cats /etc/corb/image.json with an explicit PATH, nothing else", () => {
    expect(buildIdentityExecMessage(7)).toEqual({
      type: "exec",
      id: 7,
      cmd: "/bin/cat",
      argv: ["/etc/corb/image.json"],
      env: ["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"],
    });
  });

  it("buildAttachEnv: HOME/USER/PATH from identity, TERM passed through when set", () => {
    expect(buildAttachEnv(IDENTITY, { TERM: "xterm-256color" })).toEqual([
      "HOME=/home/agent",
      "USER=agent",
      "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
      "TERM=xterm-256color",
    ]);
  });

  it("buildAttachEnv: no TERM entry at all when the host has none", () => {
    const env = buildAttachEnv(IDENTITY, {});
    expect(env).toHaveLength(3);
    expect(env.some((e) => e.startsWith("TERM="))).toBe(false);
  });

  it("buildAttachShellExecMessage: dropcap <uid> <gid> /bin/sh, cwd /work, stdin+pty true — the exact shape the M0.4 spike proved interactive-capable", () => {
    expect(buildAttachShellExecMessage(SHELL_EXEC_ID, IDENTITY, { TERM: "xterm" })).toEqual({
      type: "exec",
      id: SHELL_EXEC_ID,
      cmd: "/usr/local/bin/dropcap",
      argv: ["1000", "1000", "/bin/sh"],
      cwd: "/work",
      env: ["HOME=/home/agent", "USER=agent", "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "TERM=xterm"],
      stdin: true,
      pty: true,
    });
  });
});

// ---------------------------------------------------------------------------
// runAttachSession, driven entirely through a fake `connect` — no real socket
// is ever opened anywhere in this file.
// ---------------------------------------------------------------------------

/** Encodes a binary output frame exactly like the real protocol: `u8 tag, u32 BE id, data`. */
function makeFrame(id: number, stream: "stdout" | "stderr", text: string): Buffer {
  const data = Buffer.from(text, "utf8");
  const frame = Buffer.alloc(5 + data.length);
  frame.writeUInt8(stream === "stderr" ? 2 : 1, 0);
  frame.writeUInt32BE(id, 1);
  data.copy(frame, 5);
  return frame;
}

/**
 * A fully scriptable fake of `connectToSession()`'s return value. Every sent
 * message is logged verbatim in `sent` (what the exec-message-construction
 * assertions check against), and the test drives the "server" side by
 * calling `emitBinary`/`emitExecResponse`/`emitError`/`emitClose` whenever it
 * chooses — nothing here auto-responds, so a test can assert exactly what
 * was sent *before* deciding how (or whether) to answer it.
 */
function makeFakeConnect() {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any -- these are the raw `ClientMessage` union's members; see attach.ts's own module comment on why that type isn't importable by name.
  const sent: any[] = [];
  let callbacks: Parameters<ConnectFn>[1] | undefined;
  let closedByClient = false;

  const connect: ConnectFn = (_sockPath, cb) => {
    callbacks = cb;
    return {
      send(message) {
        sent.push(message);
      },
      close() {
        closedByClient = true;
      },
    };
  };

  return {
    connect,
    sent,
    isClosedByClient: () => closedByClient,
    emitBinary(id: number, stream: "stdout" | "stderr", text: string) {
      callbacks!.onBinary(makeFrame(id, stream, text));
    },
    emitExecResponse(id: number, exitCode: number) {
      callbacks!.onJson({ type: "exec_response", id, exit_code: exitCode });
    },
    emitError(id: number | undefined, code: string, message: string) {
      callbacks!.onJson(id === undefined ? { type: "error", code, message } : { type: "error", id, code, message });
    },
    emitClose(err?: Error) {
      callbacks!.onClose(err);
    },
  };
}

/** Flushes pending microtasks, i.e. lets already-resolved promise chains inside `runAttachSession` continue up to (but not past) the next thing this test needs to control. */
async function tick(times = 8): Promise<void> {
  for (let i = 0; i < times; i++) {
    await Promise.resolve();
  }
}

function makeStdin(overrides: Partial<AttachStdin> = {}): AttachStdin & { emit(event: "data", chunk: Buffer): void } {
  const listeners: Array<(chunk: Buffer) => void> = [];
  return {
    isTTY: true,
    isRaw: false,
    setRawMode: vi.fn(),
    on(event, listener) {
      if (event === "data") listeners.push(listener);
      return this;
    },
    off(event, listener) {
      if (event === "data") {
        const i = listeners.indexOf(listener);
        if (i >= 0) listeners.splice(i, 1);
      }
      return this;
    },
    emit(_event, chunk) {
      for (const l of [...listeners]) l(chunk);
    },
    ...overrides,
  };
}

function makeStdout(overrides: Partial<AttachStdout> = {}): AttachStdout & { emit(event: "resize"): void; writes: Buffer[] } {
  const listeners: Array<() => void> = [];
  const writes: Buffer[] = [];
  return {
    isTTY: true,
    rows: 40,
    columns: 120,
    write(chunk) {
      writes.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
      return true;
    },
    on(event, listener) {
      if (event === "resize") listeners.push(listener);
      return this;
    },
    off(event, listener) {
      if (event === "resize") {
        const i = listeners.indexOf(listener);
        if (i >= 0) listeners.splice(i, 1);
      }
      return this;
    },
    emit(_event) {
      for (const l of [...listeners]) l();
    },
    writes,
    ...overrides,
  };
}

const CONNECT_PLAN: Extract<AttachPlan, { kind: "connect" }> = {
  kind: "connect",
  id: ID_A,
  socketPath: "/tmp/gondolin/aaaa.sock",
  label: "corb:proj:aaaaaaaa",
};

describe("vm/attach: runAttachSession", () => {
  it("refuses outright when stdin/stdout are not real TTYs, without ever connecting", async () => {
    const fake = makeFakeConnect();
    const connectSpy = vi.fn(fake.connect);
    const outcome = await runAttachSession(CONNECT_PLAN, {
      connect: connectSpy,
      stdin: makeStdin({ isTTY: false }),
      stdout: makeStdout(),
    });
    expect(outcome.exitCode).not.toBe(0);
    expect(outcome.message).toContain("must both be a real terminal");
    expect(connectSpy).not.toHaveBeenCalled();
  });

  it("sends the exact identity exec, then the exact dropcap shell exec, forwards live stdin/resize, and propagates the shell's own exit code", async () => {
    const fake = makeFakeConnect();
    const stdin = makeStdin();
    const stdout = makeStdout();
    const restore = vi.fn();
    const report = vi.fn();

    const outcomePromise = runAttachSession(CONNECT_PLAN, {
      connect: fake.connect,
      stdin,
      stdout,
      env: { TERM: "xterm-256color" },
      acquireTty: (() => ({ restore })) as never,
      report,
    });

    // The identity exec is issued synchronously, before this function's
    // first real `await` suspends it.
    await tick(1);
    expect(fake.sent[0]).toEqual(buildIdentityExecMessage(IDENTITY_EXEC_ID));

    fake.emitBinary(IDENTITY_EXEC_ID, "stdout", JSON.stringify(IDENTITY));
    fake.emitExecResponse(IDENTITY_EXEC_ID, 0);
    await tick();

    // The shell exec, and its immediate initial resize, both fired before
    // this test does anything further.
    expect(fake.sent[1]).toEqual(buildAttachShellExecMessage(SHELL_EXEC_ID, IDENTITY, { TERM: "xterm-256color" }));
    expect(fake.sent).toContainEqual({ type: "pty_resize", id: SHELL_EXEC_ID, rows: 40, cols: 120 });
    expect(report).toHaveBeenCalledTimes(1);
    expect(report.mock.calls[0]?.[0]).toContain("NEW shell");

    // Live stdin forwarding, base64-encoded.
    stdin.emit("data", Buffer.from("echo hi\n", "utf8"));
    expect(fake.sent.at(-1)).toEqual({ type: "stdin", id: SHELL_EXEC_ID, data: Buffer.from("echo hi\n", "utf8").toString("base64") });

    // Live resize forwarding — not just the one fixed resize the spike sent.
    Object.assign(stdout, { rows: 50, columns: 200 });
    stdout.emit("resize");
    expect(fake.sent.at(-1)).toEqual({ type: "pty_resize", id: SHELL_EXEC_ID, rows: 50, cols: 200 });

    // Output frames land on the local stdout.
    fake.emitBinary(SHELL_EXEC_ID, "stdout", "hi\n");
    expect(Buffer.concat(stdout.writes).toString("utf8")).toBe("hi\n");

    fake.emitExecResponse(SHELL_EXEC_ID, 42);
    const outcome = await outcomePromise;

    expect(outcome.exitCode).toBe(42);
    expect(outcome.message).toContain("42");
    expect(restore).toHaveBeenCalledTimes(1);
    expect(fake.isClosedByClient()).toBe(true);
  });

  it("records exactly one attach audit event, right after the identity read succeeds, and flushes it", async () => {
    const fake = makeFakeConnect();
    const audit: AuditWriter = { record: vi.fn(), addRedactedSecrets: vi.fn(), flush: vi.fn() };

    const outcomePromise = runAttachSession(CONNECT_PLAN, {
      connect: fake.connect,
      stdin: makeStdin(),
      stdout: makeStdout(),
      acquireTty: (() => ({ restore: vi.fn() })) as never,
      report: vi.fn(),
      audit,
    });

    await tick(1);
    fake.emitBinary(IDENTITY_EXEC_ID, "stdout", JSON.stringify(IDENTITY));
    fake.emitExecResponse(IDENTITY_EXEC_ID, 0);
    await tick();

    expect(audit.record).toHaveBeenCalledTimes(1);
    expect(audit.record).toHaveBeenCalledWith({ channel: "session", decision: "allow", subject: "corb:proj:aaaaaaaa", reason: "attach", sessionId: ID_A });
    expect(audit.flush).toHaveBeenCalledTimes(1);

    fake.emitExecResponse(SHELL_EXEC_ID, 0);
    await outcomePromise;
  });

  it("reports a queue_full (or any other) exec-start error plainly rather than hanging", async () => {
    const fake = makeFakeConnect();
    const outcomePromise = runAttachSession(CONNECT_PLAN, {
      connect: fake.connect,
      stdin: makeStdin(),
      stdout: makeStdout(),
      acquireTty: (() => ({ restore: vi.fn() })) as never,
      report: vi.fn(),
    });

    await tick(1);
    fake.emitBinary(IDENTITY_EXEC_ID, "stdout", JSON.stringify(IDENTITY));
    fake.emitExecResponse(IDENTITY_EXEC_ID, 0);
    await tick();

    fake.emitError(SHELL_EXEC_ID, "queue_full", "too many pending execs");
    const outcome = await outcomePromise;

    expect(outcome.exitCode).not.toBe(0);
    expect(outcome.exitCode).not.toBe(ATTACH_CONNECTION_ENDED_EXIT_CODE);
    expect(outcome.message).toContain("queue_full");
  });

  it("resolves cleanly — never throws, never hangs — when the connection closes mid-attach (the vm.close()-adjacent trap)", async () => {
    const fake = makeFakeConnect();
    const restore = vi.fn();
    const outcomePromise = runAttachSession(CONNECT_PLAN, {
      connect: fake.connect,
      stdin: makeStdin(),
      stdout: makeStdout(),
      acquireTty: (() => ({ restore })) as never,
      report: vi.fn(),
    });

    await tick(1);
    fake.emitBinary(IDENTITY_EXEC_ID, "stdout", JSON.stringify(IDENTITY));
    fake.emitExecResponse(IDENTITY_EXEC_ID, 0);
    await tick();

    // The underlying session ends (a corb kill, a watchdog firing, a crash)
    // while the shell exec is still live.
    fake.emitClose(new Error("ECONNRESET"));

    await expect(outcomePromise).resolves.toMatchObject({ exitCode: ATTACH_CONNECTION_ENDED_EXIT_CODE });
    const outcome = await outcomePromise;
    expect(outcome.message).toContain("session ended");
    expect(restore).toHaveBeenCalledTimes(1);
  });

  it("resolves cleanly when the connection closes before the identity read even completes", async () => {
    const fake = makeFakeConnect();
    const outcomePromise = runAttachSession(CONNECT_PLAN, {
      connect: fake.connect,
      stdin: makeStdin(),
      stdout: makeStdout(),
      acquireTty: (() => ({ restore: vi.fn() })) as never,
      report: vi.fn(),
    });

    await tick(1);
    fake.emitClose(new Error("ECONNREFUSED"));

    const outcome = await outcomePromise;
    expect(outcome.exitCode).toBe(ATTACH_CONNECTION_ENDED_EXIT_CODE);
    expect(outcome.message).not.toMatch(/undefined/);
  });

  it("times out rather than hanging forever when the guest never answers the identity read", async () => {
    const fake = makeFakeConnect();
    const outcome = await runAttachSession(CONNECT_PLAN, {
      connect: fake.connect,
      stdin: makeStdin(),
      stdout: makeStdout(),
      acquireTty: (() => ({ restore: vi.fn() })) as never,
      report: vi.fn(),
      identityTimeoutMs: 20,
    });

    expect(outcome.exitCode).not.toBe(0);
    expect(outcome.message).toContain("timed out");
  });
});
