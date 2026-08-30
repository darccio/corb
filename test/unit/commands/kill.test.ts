// Unit tests for `src/commands/kill.ts` — M8.5. Same split `ls.test.ts`
// documents for itself: the pure resolution/decision/formatting functions are
// tested against fabricated `SessionEntry`/`SessionSidecar` values, and
// `executeKillPlan` is tested through its injected `sendSignal`/`isAlive`/
// `sleep`/`now` seams so nothing here ever signals a real process or waits
// real time. `runKillCommand` (the one function that calls the real
// `findSession()`, the real sidecar directory and the real `process.kill`) is
// deliberately not mocked — it is verified by hand against real running
// sessions, see the M8.5 report.
//
// The single most important test in this file is "refuses to signal a
// resolved-but-not-alive session": that is the PID-reuse guard, and its
// assertion is that the injected signal function was never called at all.
import { describe, expect, it, vi } from "vitest";
import type { SessionEntry } from "@earendil-works/gondolin";
import {
  DEFAULT_WAIT_TIMEOUT_MS,
  decideKill,
  executeKillPlan,
  matchSidecarsByQuery,
  parseAmbiguousSessionIds,
  parseKillArgs,
  renderKillRefusal,
  waitForProcessExit,
  type KillPlan,
} from "../../../src/commands/kill.ts";
import type { SessionSidecar } from "../../../src/vm/registry.ts";

const T0 = "2026-08-30T12:00:00.000Z";

function entry(id: string, overrides: Partial<SessionEntry> = {}): SessionEntry {
  return {
    id,
    pid: 4242,
    socketPath: `/tmp/gondolin/${id}.sock`,
    createdAt: T0,
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
    startedAt: T0,
    ...overrides,
  };
}

const ID_A = "aaaaaaaa-1111-4111-8111-000000000001";
const ID_B = "bbbbbbbb-2222-4222-8222-000000000002";
// Shares a 12-character prefix with ID_B, so a short prefix is ambiguous
// between the two but the full id is not.
const ID_B2 = "bbbbbbbb-2222-4999-8999-000000000099";

/** The exact message shape Gondolin's `findSession` throws for an ambiguous prefix (`session-registry.js`). */
function sdkAmbiguousMessage(query: string, ids: string[]): string {
  return `ambiguous session prefix '${query}' matches ${ids.length} sessions:\n` + ids.map((id) => `  ${id}`).join("\n");
}

describe("commands/kill: matchSidecarsByQuery", () => {
  it("matches an exact id", () => {
    expect(matchSidecarsByQuery([sidecar(ID_A), sidecar(ID_B)], ID_A).map((s) => s.id)).toEqual([ID_A]);
  });

  it("matches a unique prefix", () => {
    expect(matchSidecarsByQuery([sidecar(ID_A), sidecar(ID_B)], "aaaa").map((s) => s.id)).toEqual([ID_A]);
  });

  it("returns every candidate for an ambiguous prefix rather than picking one", () => {
    expect(matchSidecarsByQuery([sidecar(ID_B), sidecar(ID_B2)], "bbbb").map((s) => s.id).sort()).toEqual([ID_B, ID_B2].sort());
  });

  it("prefers an exact id over the prefix matches it also has", () => {
    // ID_B is itself a prefix of nothing else, but an exact hit must never be
    // reported as ambiguous alongside longer ids sharing its prefix.
    const shortId = "bbbb";
    expect(matchSidecarsByQuery([sidecar(shortId), sidecar(ID_B)], shortId).map((s) => s.id)).toEqual([shortId]);
  });

  it("normalises the query to lowercase, matching findSession's own behaviour", () => {
    expect(matchSidecarsByQuery([sidecar(ID_A)], ID_A.toUpperCase()).map((s) => s.id)).toEqual([ID_A]);
  });

  it("matches nothing when nothing shares the prefix", () => {
    expect(matchSidecarsByQuery([sidecar(ID_A)], "zzzz")).toEqual([]);
  });
});

describe("commands/kill: parseAmbiguousSessionIds", () => {
  it("extracts the ids the SDK's own ambiguity message lists", () => {
    expect(parseAmbiguousSessionIds(sdkAmbiguousMessage("bbbb", [ID_B, ID_B2]))).toEqual([ID_B, ID_B2]);
  });

  it("returns nothing for a message with no listed ids, rather than inventing any", () => {
    expect(parseAmbiguousSessionIds("something else entirely")).toEqual([]);
  });
});

describe("commands/kill: decideKill", () => {
  it("plans a signal for an exact-id match that is alive", () => {
    const plan = decideKill(ID_A, { entry: entry(ID_A), sidecars: [] });
    expect(plan).toEqual({ kind: "signal", id: ID_A, pid: 4242, label: `corb:proj:${ID_A.slice(0, 8)}` });
  });

  it("plans a signal for a prefix match that is alive (findSession resolved the prefix itself)", () => {
    const plan = decideKill("aaaa", { entry: entry(ID_A), sidecars: [] });
    expect(plan.kind).toBe("signal");
    expect(plan).toMatchObject({ id: ID_A, pid: 4242 });
  });

  it("refuses a resolved session that is not alive", () => {
    const plan = decideKill(ID_A, { entry: entry(ID_A, { alive: false }), sidecars: [sidecar(ID_A)] });
    expect(plan).toEqual({ kind: "not-alive", id: ID_A, pid: 4242, label: `corb:proj:${ID_A.slice(0, 8)}` });
  });

  it("reports an ambiguous prefix from the message findSession threw", () => {
    const plan = decideKill("bbbb", { entry: null, ambiguousMessage: sdkAmbiguousMessage("bbbb", [ID_B, ID_B2]), sidecars: [] });
    expect(plan).toEqual({
      kind: "ambiguous",
      candidates: [ID_B, ID_B2],
      rawMessage: sdkAmbiguousMessage("bbbb", [ID_B, ID_B2]),
    });
  });

  it("reports not-found when neither registry knows the query", () => {
    expect(decideKill("zzzz", { entry: null, sidecars: [sidecar(ID_A)] })).toEqual({ kind: "not-found" });
  });

  it("falls back to corb's own sidecars when Gondolin has no entry", () => {
    const plan = decideKill(ID_A, { entry: null, sidecars: [sidecar(ID_A)] });
    expect(plan).toEqual({ kind: "sidecar-only", id: ID_A, pid: 4242, label: `corb:proj:${ID_A.slice(0, 8)}` });
  });

  it("resolves a sidecar-only session by prefix too", () => {
    const plan = decideKill("aaaa", { entry: null, sidecars: [sidecar(ID_A), sidecar(ID_B)] });
    expect(plan).toMatchObject({ kind: "sidecar-only", id: ID_A });
  });

  it("reports an ambiguous sidecar prefix rather than picking one to kill", () => {
    const plan = decideKill("bbbb", { entry: null, sidecars: [sidecar(ID_B), sidecar(ID_B2)] });
    expect(plan.kind).toBe("ambiguous");
    expect((plan as Extract<KillPlan, { kind: "ambiguous" }>).candidates.sort()).toEqual([ID_B, ID_B2].sort());
  });

  it("never plans a signal from a sidecar, however alive its recorded pid looks", () => {
    // A sidecar carries a pid but no liveness at all, so trusting it would be
    // exactly the pid-reuse bug this command exists to avoid.
    const plan = decideKill(ID_A, { entry: null, sidecars: [sidecar(ID_A, { pid: process.pid })] });
    expect(plan.kind).not.toBe("signal");
  });

  it("prefers Gondolin's entry over a sidecar for the same id", () => {
    const plan = decideKill(ID_A, { entry: entry(ID_A, { pid: 99 }), sidecars: [sidecar(ID_A, { pid: 4242 })] });
    expect(plan).toMatchObject({ kind: "signal", pid: 99 });
  });

  it("carries an undefined label through when Gondolin recorded none", () => {
    const noLabel = entry(ID_A);
    delete noLabel.label;
    expect(decideKill(ID_A, { entry: noLabel, sidecars: [] })).toMatchObject({ kind: "signal", label: undefined });
  });
});

describe("commands/kill: renderKillRefusal", () => {
  it("points a no-match at corb ls", () => {
    const text = renderKillRefusal("zzzz", { kind: "not-found" });
    expect(text).toContain("no session matches 'zzzz'");
    expect(text).toContain("corb ls");
  });

  it("lists every candidate for an ambiguous query and says nothing was signalled", () => {
    const text = renderKillRefusal("bbbb", { kind: "ambiguous", candidates: [ID_B, ID_B2], rawMessage: "" });
    expect(text).toContain(ID_B);
    expect(text).toContain(ID_B2);
    expect(text).toContain("Nothing was signalled");
  });

  it("falls back to the SDK's raw message when its ids could not be parsed", () => {
    const text = renderKillRefusal("bbbb", { kind: "ambiguous", candidates: [], rawMessage: "some unparsed sdk wording" });
    expect(text).toContain("some unparsed sdk wording");
  });

  it("explains a stale registry entry in terms of pid reuse", () => {
    const text = renderKillRefusal(ID_A, { kind: "not-alive", id: ID_A, pid: 4242, label: "corb:proj:aaaa" });
    expect(text).toContain("is not running");
    expect(text).toContain("stale registry entry");
    expect(text).toContain("Nothing was signalled");
    expect(text).toContain("4242");
  });

  it("explains a sidecar-only session and names the leftover file", () => {
    const text = renderKillRefusal(ID_A, { kind: "sidecar-only", id: ID_A, pid: 4242, label: "corb:proj:aaaa" }, "/state/sessions/a.json");
    expect(text).toContain("no live Gondolin session entry");
    expect(text).toContain("Nothing was signalled");
    expect(text).toContain("/state/sessions/a.json");
    expect(text).toContain("corb gc");
  });

  it("renders an unlabelled session as a bare id, with no empty parentheses", () => {
    const text = renderKillRefusal(ID_A, { kind: "not-alive", id: ID_A, pid: 4242, label: undefined });
    expect(text).toContain(ID_A);
    expect(text).not.toContain("()");
  });
});

describe("commands/kill: waitForProcessExit", () => {
  it("returns immediately when the process is already gone", async () => {
    const sleep = vi.fn(async () => {});
    const exited = await waitForProcessExit(1234, { isAlive: () => false, sleep, now: () => 0, timeoutMs: 1000, pollIntervalMs: 10 });
    expect(exited).toBe(true);
    expect(sleep).not.toHaveBeenCalled();
  });

  it("polls until the process disappears", async () => {
    let calls = 0;
    const exited = await waitForProcessExit(1234, {
      isAlive: () => ++calls < 3,
      sleep: async () => {},
      now: () => 0,
      timeoutMs: 1000,
      pollIntervalMs: 10,
    });
    expect(exited).toBe(true);
    expect(calls).toBe(3);
  });

  it("gives up at the deadline instead of hanging forever", async () => {
    let clock = 0;
    const exited = await waitForProcessExit(1234, {
      isAlive: () => true,
      sleep: async (ms) => {
        clock += ms;
      },
      now: () => clock,
      timeoutMs: 100,
      pollIntervalMs: 10,
    });
    expect(exited).toBe(false);
    expect(clock).toBeGreaterThanOrEqual(100);
  });
});

describe("commands/kill: executeKillPlan", () => {
  /** Injected dependencies that make a signalled process look like it exits on the first poll. */
  function fastDeps(sendSignal: ReturnType<typeof vi.fn>) {
    return {
      sendSignal: sendSignal as unknown as (pid: number, signal: NodeJS.Signals) => void,
      isAlive: () => false,
      sleep: async () => {},
      now: () => 0,
      report: () => {},
    };
  }

  it("sends exactly one SIGTERM to the recorded host pid and reports success", async () => {
    const sendSignal = vi.fn();
    const reported: string[] = [];
    const outcome = await executeKillPlan(
      ID_A,
      { kind: "signal", id: ID_A, pid: 4242, label: "corb:proj:aaaa" },
      { ...fastDeps(sendSignal), report: (line) => reported.push(line) },
    );

    expect(sendSignal).toHaveBeenCalledTimes(1);
    expect(sendSignal).toHaveBeenCalledWith(4242, "SIGTERM");
    expect(outcome).toMatchObject({ signalled: true, exited: true, exitCode: 0 });
    expect(outcome.message).toContain("teardown complete");
    expect(reported[0]).toContain("sent SIGTERM");
    expect(reported[0]).toContain("4242");
  });

  // The PID-reuse guard. If this ever regresses, `corb kill` can SIGTERM an
  // unrelated process that happened to inherit a dead session's pid.
  it("refuses to signal a resolved-but-not-alive session", async () => {
    const sendSignal = vi.fn();
    const outcome = await executeKillPlan(ID_A, { kind: "not-alive", id: ID_A, pid: 4242, label: "corb:proj:aaaa" }, fastDeps(sendSignal));

    expect(sendSignal).not.toHaveBeenCalled();
    expect(outcome.signalled).toBe(false);
    expect(outcome.exitCode).not.toBe(0);
    expect(outcome.message).toContain("Nothing was signalled");
  });

  it("signals nothing for a sidecar-only session, and names the sidecar file", async () => {
    const sendSignal = vi.fn();
    const outcome = await executeKillPlan(ID_A, { kind: "sidecar-only", id: ID_A, pid: 4242, label: "corb:proj:aaaa" }, {
      ...fastDeps(sendSignal),
      sidecarPathFor: (id) => `/fake/state/sessions/${id}.json`,
    });

    expect(sendSignal).not.toHaveBeenCalled();
    expect(outcome.signalled).toBe(false);
    expect(outcome.exitCode).not.toBe(0);
    expect(outcome.message).toContain(`/fake/state/sessions/${ID_A}.json`);
  });

  it("signals nothing for a not-found or ambiguous query", async () => {
    const sendSignal = vi.fn();
    for (const plan of [{ kind: "not-found" }, { kind: "ambiguous", candidates: [ID_B, ID_B2], rawMessage: "" }] as KillPlan[]) {
      const outcome = await executeKillPlan("q", plan, fastDeps(sendSignal));
      expect(outcome.signalled).toBe(false);
      expect(outcome.exitCode).not.toBe(0);
    }
    expect(sendSignal).not.toHaveBeenCalled();
  });

  it("waits for the host process to exit before reporting success", async () => {
    const sendSignal = vi.fn();
    let alive = 3;
    const outcome = await executeKillPlan(
      ID_A,
      { kind: "signal", id: ID_A, pid: 4242, label: "corb:proj:aaaa" },
      { ...fastDeps(sendSignal), isAlive: () => alive-- > 0 },
    );
    expect(alive).toBeLessThan(0);
    expect(outcome).toMatchObject({ exited: true, exitCode: 0 });
  });

  it("fails, rather than hanging or claiming success, when teardown outlasts the timeout", async () => {
    const sendSignal = vi.fn();
    let clock = 0;
    const outcome = await executeKillPlan(
      ID_A,
      { kind: "signal", id: ID_A, pid: 4242, label: "corb:proj:aaaa" },
      {
        ...fastDeps(sendSignal),
        isAlive: () => true,
        sleep: async (ms) => {
          clock += ms;
        },
        now: () => clock,
        timeoutMs: 1000,
        pollIntervalMs: 100,
      },
    );

    expect(sendSignal).toHaveBeenCalledWith(4242, "SIGTERM");
    expect(outcome).toMatchObject({ signalled: true, exited: false });
    expect(outcome.exitCode).not.toBe(0);
    expect(outcome.message).toContain("had not exited after 1s");
    expect(outcome.message).toContain("qemu-system");
  });

  it("reports honestly when the session exits in the window between the liveness check and the signal", async () => {
    const sendSignal = vi.fn(() => {
      const err = new Error("kill ESRCH") as NodeJS.ErrnoException;
      err.code = "ESRCH";
      throw err;
    });
    const outcome = await executeKillPlan(ID_A, { kind: "signal", id: ID_A, pid: 4242, label: "corb:proj:aaaa" }, fastDeps(sendSignal));

    expect(outcome.signalled).toBe(false);
    expect(outcome.exitCode).not.toBe(0);
    expect(outcome.message).toContain("already exited");
  });

  it("uses a bounded default timeout rather than waiting forever", () => {
    expect(DEFAULT_WAIT_TIMEOUT_MS).toBeGreaterThan(0);
    expect(Number.isFinite(DEFAULT_WAIT_TIMEOUT_MS)).toBe(true);
  });
});

describe("commands/kill: parseKillArgs", () => {
  it("takes exactly one session id", () => {
    expect(parseKillArgs([ID_A])).toEqual({ session: ID_A });
  });

  it("accepts a prefix", () => {
    expect(parseKillArgs(["aaaa"])).toEqual({ session: "aaaa" });
  });

  it("requires a session argument", () => {
    expect(() => parseKillArgs([])).toThrow(/missing required argument <session>/);
  });

  it("rejects a second positional by name", () => {
    expect(() => parseKillArgs([ID_A, ID_B])).toThrow(new RegExp(`unexpected argument '${ID_B}'`));
  });

  it("rejects an empty session, which would otherwise be a prefix of every id", () => {
    expect(() => parseKillArgs([""])).toThrow(/must not be empty/);
    expect(() => parseKillArgs(["   "])).toThrow(/must not be empty/);
  });

  it("explains why there is no --force rather than reporting an unknown option", () => {
    expect(() => parseKillArgs([ID_A, "--force"])).toThrow(/no --force option, by design/);
    expect(() => parseKillArgs([ID_A, "-f"])).toThrow(/SIGKILL cannot be caught/);
  });

  it("rejects any other unknown flag", () => {
    expect(() => parseKillArgs([ID_A, "--nope"])).toThrow();
  });
});
