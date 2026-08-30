// Unit tests for `src/commands/gc.ts` — M8.6. Same split `ls.test.ts` and
// `kill.test.ts` document for themselves: the pure decision/rendering
// functions are tested against fabricated `SessionSidecar` values, and
// `executeSidecarGc` is tested through its injected `removeSidecar` seam, so
// nothing here ever deletes a real file or probes a real process.
// `runGcCommand` (the one function that calls the real `gcSessions()`, the
// real sidecar directory and the real `process.kill`) is deliberately not
// mocked — it is verified by hand against real running and real orphaned
// sessions, see the M8.6 report.
//
// The single most important test in this file is "does NOT remove a sidecar
// whose recorded pid is still alive": that is the mandatory guard, and its
// assertion is that the injected removal function was never called with that
// id at all. It is the mirror of `kill.test.ts`'s "refuses to signal a
// resolved-but-not-alive session".
import { describe, expect, it, vi } from "vitest";
import {
  DEFAULT_MIN_AGE_MS,
  decideSidecarGc,
  executeSidecarGc,
  parseGcArgs,
  renderGcReport,
  type GcReport,
  type GcSidecarDecision,
} from "../../../src/commands/gc.ts";
import type { SessionSidecar } from "../../../src/vm/registry.ts";

const T0 = "2026-08-30T12:00:00.000Z";
const NOW = Date.parse("2026-08-30T13:00:00.000Z");

const HOUR_MS = 3_600_000;
const MINUTE_MS = 60_000;

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
const ID_C = "cccccccc-3333-4333-8333-000000000003";

/** A sidecar started `ageMs` before `NOW`. */
function aged(id: string, ageMs: number, overrides: Partial<SessionSidecar> = {}): SessionSidecar {
  return sidecar(id, { startedAt: new Date(NOW - ageMs).toISOString(), ...overrides });
}

/** Liveness probe reporting exactly the listed pids alive and nothing else. */
function alivePids(...pids: number[]): (pid: number) => boolean {
  return (pid) => pids.includes(pid);
}

const NOTHING_ALIVE = () => false;

function decide(sidecars: SessionSidecar[], opts: { isAlive?: (pid: number) => boolean; minAgeMs?: number } = {}): GcSidecarDecision[] {
  return decideSidecarGc(sidecars, {
    isAlive: opts.isAlive ?? NOTHING_ALIVE,
    now: NOW,
    minAgeMs: opts.minAgeMs ?? DEFAULT_MIN_AGE_MS,
  });
}

describe("commands/gc: decideSidecarGc", () => {
  it("decides nothing for an empty sidecar directory", () => {
    expect(decide([])).toEqual([]);
  });

  it("prunes a sidecar whose recorded host pid is gone", () => {
    const decisions = decide([sidecar(ID_A, { pid: 4242 })]);
    expect(decisions).toHaveLength(1);
    expect(decisions[0]).toMatchObject({ prune: true, reason: "dead" });
    expect(decisions[0]?.sidecar.id).toBe(ID_A);
  });

  // THE guard. If this ever regresses, `corb gc` deletes the sidecar of a
  // running session and makes it unmanageable through corb entirely.
  it("never prunes a sidecar whose recorded host pid is still alive", () => {
    const decisions = decide([sidecar(ID_A, { pid: 9001 })], { isAlive: alivePids(9001) });
    expect(decisions[0]).toMatchObject({ prune: false, reason: "alive" });
  });

  it("checks liveness before age, so a very old sidecar with a live pid is still kept", () => {
    const decisions = decide([aged(ID_A, 30 * 24 * HOUR_MS, { pid: 9001 })], {
      isAlive: alivePids(9001),
      minAgeMs: HOUR_MS,
    });
    expect(decisions[0]).toMatchObject({ prune: false, reason: "alive" });
  });

  // The startup window: `runSession()` writes the sidecar as soon as
  // `VM.create()` resolves, but Gondolin registers the session later. A
  // seconds-old, perfectly healthy session therefore has a sidecar, no
  // Gondolin entry, and a live pid — observed presenting as `orphaned` to
  // `corb ls` for ~12s. Note this decision consults no Gondolin state at all,
  // which is exactly why the absent registry entry cannot mislead it.
  it("keeps a booting session's sidecar: no gondolin entry, seconds old, pid alive", () => {
    const decisions = decide([aged(ID_A, 3000, { pid: 9001 })], { isAlive: alivePids(9001) });
    expect(decisions[0]).toMatchObject({ prune: false, reason: "alive" });
  });

  // The socket-overflow trap (`src/vm/sockpath.ts`): a genuinely running
  // session whose `.sock` was never created reads `alive: false` to Gondolin
  // forever, so `gcSessions()` deletes its metadata and leaves it
  // sidecar-only. The pid guard is the only thing that then saves it.
  it("keeps a live-but-socketless session's sidecar after gcSessions() removed its gondolin metadata", () => {
    const decisions = decide([aged(ID_A, 2 * HOUR_MS, { pid: 9001 })], {
      isAlive: alivePids(9001),
      minAgeMs: HOUR_MS,
    });
    expect(decisions[0]).toMatchObject({ prune: false, reason: "alive" });
  });

  it("judges each sidecar independently, mixing prune and keep in one batch", () => {
    const decisions = decide([sidecar(ID_A, { pid: 4242 }), sidecar(ID_B, { pid: 9001 }), sidecar(ID_C, { pid: 4243 })], {
      isAlive: alivePids(9001),
    });
    expect(decisions.map((d) => [d.sidecar.id, d.prune])).toEqual([
      [ID_A, true],
      [ID_B, false],
      [ID_C, true],
    ]);
  });

  it("computes an age for every decision, clamping a future timestamp to zero", () => {
    expect(decide([aged(ID_A, 5 * MINUTE_MS)])[0]?.ageMs).toBe(5 * MINUTE_MS);
    expect(decide([sidecar(ID_A, { startedAt: new Date(NOW + 10_000).toISOString() })])[0]?.ageMs).toBe(0);
  });

  describe("--older-than", () => {
    it("keeps a dead sidecar that is younger than the cutoff", () => {
      const decisions = decide([aged(ID_A, 5 * MINUTE_MS)], { minAgeMs: HOUR_MS });
      expect(decisions[0]).toMatchObject({ prune: false, reason: "too-recent" });
    });

    it("prunes a dead sidecar that is older than the cutoff", () => {
      const decisions = decide([aged(ID_A, 2 * HOUR_MS)], { minAgeMs: HOUR_MS });
      expect(decisions[0]).toMatchObject({ prune: true, reason: "dead" });
    });

    it("prunes at exactly the age threshold, and keeps one millisecond under it", () => {
      expect(decide([aged(ID_A, HOUR_MS)], { minAgeMs: HOUR_MS })[0]).toMatchObject({ prune: true, reason: "dead" });
      expect(decide([aged(ID_A, HOUR_MS - 1)], { minAgeMs: HOUR_MS })[0]).toMatchObject({ prune: false, reason: "too-recent" });
    });

    it("splits a batch by age, pruning only the old dead ones", () => {
      const decisions = decide([aged(ID_A, 3 * HOUR_MS), aged(ID_B, 1 * MINUTE_MS)], { minAgeMs: HOUR_MS });
      expect(decisions.map((d) => [d.sidecar.id, d.prune, d.reason])).toEqual([
        [ID_A, true, "dead"],
        [ID_B, false, "too-recent"],
      ]);
    });

    it("refuses to prune a dead sidecar whose startedAt is unparseable, rather than assuming it is old enough", () => {
      const decisions = decide([sidecar(ID_A, { startedAt: "not-a-date" })], { minAgeMs: HOUR_MS });
      expect(decisions[0]).toMatchObject({ prune: false, reason: "unknown-age", ageMs: undefined });
    });

    it("prunes a dead sidecar with an unparseable startedAt when no age filter was asked for", () => {
      const decisions = decide([sidecar(ID_A, { startedAt: "not-a-date" })]);
      expect(decisions[0]).toMatchObject({ prune: true, reason: "dead" });
    });

    it("applies no age filter by default, pruning even a seconds-old dead sidecar", () => {
      expect(DEFAULT_MIN_AGE_MS).toBe(0);
      expect(decide([aged(ID_A, 1000)])[0]).toMatchObject({ prune: true, reason: "dead" });
    });
  });
});

describe("commands/gc: executeSidecarGc", () => {
  it("removes exactly the sidecars decided prunable", () => {
    const removeSidecar = vi.fn();
    const decisions = decide([sidecar(ID_A, { pid: 4242 }), sidecar(ID_B, { pid: 4243 })]);
    const result = executeSidecarGc(decisions, { removeSidecar });

    expect(removeSidecar).toHaveBeenCalledTimes(2);
    expect(result.prunedIds).toEqual([ID_A, ID_B]);
    expect(result.failures).toEqual([]);
  });

  // The most important test in this file — the mirror of kill.test.ts's
  // "refuses to signal a resolved-but-not-alive session".
  it("does NOT call remove for a sidecar whose pid is alive", () => {
    const removeSidecar = vi.fn();
    const decisions = decide([sidecar(ID_A, { pid: 9001 }), sidecar(ID_B, { pid: 4242 })], { isAlive: alivePids(9001) });
    const result = executeSidecarGc(decisions, { removeSidecar });

    expect(removeSidecar).toHaveBeenCalledTimes(1);
    expect(removeSidecar).toHaveBeenCalledWith(ID_B);
    expect(removeSidecar).not.toHaveBeenCalledWith(ID_A);
    expect(result.prunedIds).toEqual([ID_B]);
  });

  it("removes nothing at all when every sidecar belongs to a live pid", () => {
    const removeSidecar = vi.fn();
    const decisions = decide([sidecar(ID_A, { pid: 9001 }), sidecar(ID_B, { pid: 9002 })], { isAlive: alivePids(9001, 9002) });
    const result = executeSidecarGc(decisions, { removeSidecar });

    expect(removeSidecar).not.toHaveBeenCalled();
    expect(result.prunedIds).toEqual([]);
  });

  it("removes nothing under --dry-run, but reports what it would have removed", () => {
    const removeSidecar = vi.fn();
    const decisions = decide([sidecar(ID_A, { pid: 4242 })]);
    const result = executeSidecarGc(decisions, { removeSidecar, dryRun: true });

    expect(removeSidecar).not.toHaveBeenCalled();
    expect(result.prunedIds).toEqual([ID_A]);
  });

  it("keeps going after a failed removal and reports it, rather than aborting the batch", () => {
    const removeSidecar = vi.fn((id: string) => {
      if (id === ID_A) {
        throw new Error("EACCES: permission denied");
      }
    });
    const decisions = decide([sidecar(ID_A, { pid: 4242 }), sidecar(ID_B, { pid: 4243 })]);
    const result = executeSidecarGc(decisions, { removeSidecar });

    expect(result.prunedIds).toEqual([ID_B]);
    expect(result.failures).toEqual([{ id: ID_A, error: "EACCES: permission denied" }]);
  });
});

describe("commands/gc: renderGcReport", () => {
  function report(overrides: Partial<GcReport> = {}): GcReport {
    return {
      gondolinCollected: 0,
      decisions: [],
      prune: { prunedIds: [], failures: [] },
      dryRun: false,
      olderThan: undefined,
      now: NOW,
      ...overrides,
    };
  }

  it("says plainly that a clean state is not a failure", () => {
    const text = renderGcReport(report());
    expect(text).toContain("gondolin collected 0 stale registry entries");
    expect(text).toContain("examined 0 corb sidecars");
    expect(text).toContain("not a failure");
  });

  it("does not claim there was nothing to collect when sidecars were examined and kept", () => {
    const decisions = decide([sidecar(ID_A, { pid: 9001 })], { isAlive: alivePids(9001) });
    const text = renderGcReport(report({ decisions }));
    expect(text).toContain("pruned 0, kept 1");
    expect(text).not.toContain("nothing to collect");
  });

  it("reports what gondolin itself collected, with singular wording for one", () => {
    expect(renderGcReport(report({ gondolinCollected: 1 }))).toContain("collected 1 stale registry entry");
    expect(renderGcReport(report({ gondolinCollected: 3 }))).toContain("collected 3 stale registry entries");
  });

  it("names each pruned sidecar and why it qualified", () => {
    const decisions = decide([aged(ID_A, 3 * HOUR_MS, { pid: 4242 })]);
    const text = renderGcReport(report({ decisions, prune: { prunedIds: [ID_A], failures: [] } }));
    expect(text).toContain("pruned 1, kept 0");
    expect(text).toContain(ID_A.slice(0, 12));
    expect(text).toContain("age 3h");
    expect(text).toContain("host pid 4242 is gone");
  });

  it("names each kept sidecar and why it was skipped", () => {
    const decisions = decide([sidecar(ID_A, { pid: 9001 }), aged(ID_B, MINUTE_MS, { pid: 4242 })], {
      isAlive: alivePids(9001),
      minAgeMs: HOUR_MS,
    });
    const text = renderGcReport(report({ decisions, olderThan: "1h" }));
    expect(text).toContain("pruned 0, kept 2");
    expect(text).toContain("host pid 9001 is still alive");
    expect(text).toContain("--older-than 1h window");
  });

  it("explains the live-pid guard whenever anything was kept for being alive", () => {
    const decisions = decide([sidecar(ID_A, { pid: 9001 })], { isAlive: alivePids(9001) });
    const text = renderGcReport(report({ decisions }));
    expect(text).toContain("still alive is never pruned");
    expect(text).toContain("corb ls");
  });

  it("does not print the live-pid note when nothing was kept for that reason", () => {
    const decisions = decide([sidecar(ID_A, { pid: 4242 })]);
    const text = renderGcReport(report({ decisions, prune: { prunedIds: [ID_A], failures: [] } }));
    expect(text).not.toContain("never pruned");
  });

  it("states which age filter was in force, either way", () => {
    expect(renderGcReport(report())).toContain("no --older-than filter");
    expect(renderGcReport(report({ olderThan: "2h" }))).toContain("--older-than 2h: only sidecars started more than 2h ago qualify");
  });

  it("says 'would prune' under --dry-run, and that gondolin's own gc was not run", () => {
    const decisions = decide([sidecar(ID_A, { pid: 4242 })]);
    const text = renderGcReport(report({ gondolinCollected: undefined, dryRun: true, decisions, prune: { prunedIds: [ID_A], failures: [] } }));
    expect(text).toContain("would prune 1, would keep 0");
    expect(text).toContain("gcSessions() was NOT run");
    expect(text).not.toContain("gondolin collected");
  });

  it("reports a gcSessions() failure without hiding the sidecar half's result", () => {
    const decisions = decide([sidecar(ID_A, { pid: 4242 })]);
    const text = renderGcReport(report({ gondolinCollected: undefined, gondolinError: "EACCES", decisions, prune: { prunedIds: [ID_A], failures: [] } }));
    expect(text).toContain("gcSessions() failed: EACCES");
    expect(text).toContain("pruned 1");
  });

  it("reports a removal failure by id", () => {
    const decisions = decide([sidecar(ID_A, { pid: 4242 })]);
    const text = renderGcReport(report({ decisions, prune: { prunedIds: [], failures: [{ id: ID_A, error: "EACCES" }] } }));
    expect(text).toContain(`failed to remove the sidecar for ${ID_A}`);
    expect(text).toContain("EACCES");
  });

  it("lists the oldest garbage first, deterministically", () => {
    const decisions = decide([aged(ID_B, MINUTE_MS), aged(ID_C, 5 * HOUR_MS), aged(ID_A, 2 * HOUR_MS)]);
    const lines = renderGcReport(report({ decisions })).split("\n").filter((line) => line.startsWith("  "));
    expect(lines.map((line) => line.trim().slice(0, 12))).toEqual([ID_C.slice(0, 12), ID_A.slice(0, 12), ID_B.slice(0, 12)]);
  });
});

describe("commands/gc: parseGcArgs", () => {
  it("defaults to no age filter and no dry run", () => {
    expect(parseGcArgs([])).toEqual({ olderThan: undefined, minAgeMs: 0, dryRun: false });
  });

  it("parses --older-than with src/util/duration.ts's own format", () => {
    expect(parseGcArgs(["--older-than", "1h"])).toEqual({ olderThan: "1h", minAgeMs: HOUR_MS, dryRun: false });
    expect(parseGcArgs(["--older-than", "30s"]).minAgeMs).toBe(30_000);
    expect(parseGcArgs(["--older-than", "5m"]).minAgeMs).toBe(5 * MINUTE_MS);
    expect(parseGcArgs(["--older-than", "2d"]).minAgeMs).toBe(2 * 86_400_000);
  });

  it("rejects a malformed duration, naming the flag it came from", () => {
    expect(() => parseGcArgs(["--older-than", "soon"])).toThrow(/corb gc: invalid --older-than 'soon'/);
    expect(() => parseGcArgs(["--older-than", "1"])).toThrow(/expected a duration like/);
    expect(() => parseGcArgs(["--older-than", "1w"])).toThrow(/corb gc: invalid --older-than '1w'/);
    expect(() => parseGcArgs(["--older-than", ""])).toThrow(/corb gc: invalid --older-than/);
  });

  it("accepts --dry-run and its -n short form", () => {
    expect(parseGcArgs(["--dry-run"]).dryRun).toBe(true);
    expect(parseGcArgs(["-n"]).dryRun).toBe(true);
  });

  it("rejects a positional argument by name", () => {
    expect(() => parseGcArgs(["nope"])).toThrow(/corb gc: unexpected argument 'nope'/);
  });

  it("rejects an unknown flag", () => {
    expect(() => parseGcArgs(["--nope"])).toThrow();
  });
});
