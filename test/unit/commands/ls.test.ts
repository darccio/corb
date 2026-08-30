// Unit tests for `src/commands/ls.ts` — M8.4. Everything meaningful in
// `corb ls` is the pure join between two registries plus the rendering of its
// result, so that is what is tested here, against fabricated `SessionEntry`/
// `SessionSidecar` values — the same split `doctor.test.ts` documents for
// itself. `runLsCommand` (the one function that touches the real Gondolin
// registry, the real sidecar directory, and the real clock) is deliberately
// not mocked: mocking `listSessions()` would prove only that a mock returns
// what it was told to. The real two-registry join is verified end to end by
// hand against real running/killed sessions (see the M8.4 report).
import { describe, expect, it } from "vitest";
import type { SessionEntry } from "@earendil-works/gondolin";
import {
  formatAge,
  idColumnWidth,
  joinSessions,
  parseLsArgs,
  renderLsJson,
  renderLsText,
  type LsJson,
} from "../../../src/commands/ls.ts";
import type { SessionSidecar } from "../../../src/vm/registry.ts";

const T0 = "2026-08-30T12:00:00.000Z";
const NOW = Date.parse("2026-08-30T12:05:00.000Z");

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
const ID_C = "cccccccc-3333-4333-8333-000000000003";

describe("commands/ls: joinSessions", () => {
  it("returns nothing for two empty registries", () => {
    expect(joinSessions([], [])).toEqual([]);
  });

  it("joins a matched pair by exact id", () => {
    const rows = joinSessions([entry(ID_A)], [sidecar(ID_A)]);
    expect(rows).toHaveLength(1);
    expect(rows[0]?.join).toBe("both");
    expect(rows[0]?.status).toBe("running");
    expect(rows[0]?.gondolin?.id).toBe(ID_A);
    expect(rows[0]?.sidecar?.id).toBe(ID_A);
  });

  it("a matched pair whose Gondolin entry is not alive is stale, not running", () => {
    const rows = joinSessions([entry(ID_A, { alive: false })], [sidecar(ID_A)]);
    expect(rows[0]?.join).toBe("both");
    expect(rows[0]?.status).toBe("stale");
  });

  it("lists a Gondolin entry with no sidecar, carrying no fabricated sidecar data", () => {
    const rows = joinSessions([entry(ID_A)], []);
    expect(rows).toHaveLength(1);
    expect(rows[0]?.join).toBe("gondolin-only");
    expect(rows[0]?.status).toBe("running");
    expect(rows[0]?.sidecar).toBeUndefined();
    expect(rows[0]?.gondolin?.id).toBe(ID_A);
  });

  it("surfaces an orphaned sidecar with no Gondolin entry, marked not running", () => {
    const rows = joinSessions([], [sidecar(ID_A)]);
    expect(rows).toHaveLength(1);
    expect(rows[0]?.join).toBe("sidecar-only");
    expect(rows[0]?.status).toBe("orphaned");
    expect(rows[0]?.gondolin).toBeUndefined();
    expect(rows[0]?.sidecar?.id).toBe(ID_A);
  });

  it("handles all three cases together, dropping nothing from either side", () => {
    const rows = joinSessions([entry(ID_A), entry(ID_B)], [sidecar(ID_A), sidecar(ID_C)]);
    expect(rows.map((r) => [r.id, r.join, r.status])).toEqual(
      expect.arrayContaining([
        [ID_A, "both", "running"],
        [ID_B, "gondolin-only", "running"],
        [ID_C, "sidecar-only", "orphaned"],
      ]),
    );
    expect(rows).toHaveLength(3);
  });

  it("takes startedAt from Gondolin's createdAt when present, and the sidecar's startedAt otherwise", () => {
    const rows = joinSessions([entry(ID_A, { createdAt: "2026-08-30T09:00:00.000Z" })], [sidecar(ID_A, { startedAt: "2026-08-30T08:00:00.000Z" }), sidecar(ID_B, { startedAt: "2026-08-30T07:00:00.000Z" })]);
    expect(rows.find((r) => r.id === ID_A)?.startedAt).toBe("2026-08-30T09:00:00.000Z");
    expect(rows.find((r) => r.id === ID_B)?.startedAt).toBe("2026-08-30T07:00:00.000Z");
  });

  it("sorts newest first across both sides, tie-breaking on id", () => {
    const rows = joinSessions(
      [entry(ID_B, { createdAt: "2026-08-30T10:00:00.000Z" })],
      [sidecar(ID_C, { startedAt: "2026-08-30T11:00:00.000Z" }), sidecar(ID_A, { startedAt: "2026-08-30T11:00:00.000Z" })],
    );
    expect(rows.map((r) => r.id)).toEqual([ID_A, ID_C, ID_B]);
  });

  it("does not drop a row whose timestamp is unparseable", () => {
    const rows = joinSessions([entry(ID_A, { createdAt: "not-a-date" })], []);
    expect(rows).toHaveLength(1);
    expect(rows[0]?.startedAt).toBe("not-a-date");
  });
});

describe("commands/ls: formatAge", () => {
  const base = Date.parse(T0);

  it("renders seconds, minutes, hours, and days as the largest whole unit", () => {
    expect(formatAge(T0, base)).toBe("0s");
    expect(formatAge(T0, base + 45_000)).toBe("45s");
    expect(formatAge(T0, base + 59_999)).toBe("59s");
    expect(formatAge(T0, base + 60_000)).toBe("1m");
    expect(formatAge(T0, base + 59 * 60_000)).toBe("59m");
    expect(formatAge(T0, base + 2 * 3_600_000)).toBe("2h");
    expect(formatAge(T0, base + 23 * 3_600_000)).toBe("23h");
    expect(formatAge(T0, base + 5 * 86_400_000)).toBe("5d");
  });

  it("clamps a future timestamp to 0s rather than going negative", () => {
    expect(formatAge(T0, base - 10_000)).toBe("0s");
  });

  it("renders an unparseable timestamp as '?', never NaN", () => {
    expect(formatAge("not-a-date", base)).toBe("?");
  });
});

describe("commands/ls: idColumnWidth", () => {
  it("uses the minimum width when it already separates every id", () => {
    expect(idColumnWidth([ID_A, ID_B, ID_C])).toBe(12);
  });

  it("grows only as far as needed to keep colliding prefixes distinct", () => {
    // Identical through character 15, differing only at the very last one.
    expect(idColumnWidth(["a".repeat(15) + "X", "a".repeat(15) + "Y"])).toBe(16);
    // Identical through character 12, differing at the 13th.
    expect(idColumnWidth(["a".repeat(12) + "Xzzz", "a".repeat(12) + "Yzzz"])).toBe(13);
  });

  it("never exceeds the ids' own length", () => {
    expect(idColumnWidth(["abc", "abd"])).toBe(3);
    expect(idColumnWidth([])).toBe(0);
  });
});

describe("commands/ls: renderLsText", () => {
  it("says so plainly when there are no sessions, instead of printing an empty table", () => {
    const text = renderLsText([], NOW);
    expect(text).toBe("corb ls: no sessions.");
    expect(text).not.toContain("ID");
  });

  it("renders a header and one aligned row per session", () => {
    const text = renderLsText(joinSessions([entry(ID_A)], [sidecar(ID_A)]), NOW);
    const lines = text.split("\n");
    expect(lines[0]).toMatch(/^ID\s+STATUS\s+AGE\s+WORKSPACE\s+IMAGE\s+EXPOSED\s+LABEL$/);
    expect(lines[1]).toContain(ID_A.slice(0, 12));
    expect(lines[1]).toContain("running");
    expect(lines[1]).toContain("5m");
    expect(lines[1]).toContain("proj");
    expect(lines[1]).toContain("corb:0.1.0");
    // Column alignment: header and row share the same column offsets.
    expect(lines[0]?.indexOf("STATUS")).toBe(lines[1]?.indexOf("running"));
  });

  it("shows '-' in the EXPOSED column when the sidecar has no exposed field", () => {
    const text = renderLsText(joinSessions([entry(ID_A)], [sidecar(ID_A)]), NOW);
    const lines = text.split("\n");
    const exposedCol = lines[0]?.indexOf("EXPOSED") ?? -1;
    expect(exposedCol).toBeGreaterThanOrEqual(0);
    expect(lines[1]?.slice(exposedCol)).toMatch(/^-\s/);
  });

  it("shows the exposed URL in the EXPOSED column when the sidecar has one", () => {
    const withExposed = sidecar(ID_A, { exposed: { port: 8080, url: "http://127.0.0.1:54321" } });
    const text = renderLsText(joinSessions([entry(ID_A)], [withExposed]), NOW);
    expect(text.split("\n")[1]).toContain("http://127.0.0.1:54321");
  });

  it("leaves workspace and image empty for a Gondolin entry with no sidecar, but still shows its label", () => {
    const text = renderLsText(joinSessions([entry(ID_A)], []), NOW);
    const row = text.split("\n")[1] ?? "";
    expect(row).toContain("-");
    expect(row).not.toContain("corb:0.1.0");
    expect(row).toContain(`corb:proj:${ID_A.slice(0, 8)}`);
  });

  it("marks an orphaned sidecar and notes that nothing was deleted", () => {
    const text = renderLsText(joinSessions([], [sidecar(ID_A)]), NOW);
    expect(text).toContain("orphaned");
    expect(text).toContain("Nothing was deleted");
    expect(text).toContain("only reads");
  });

  it("adds no not-running note when every session is running", () => {
    const text = renderLsText(joinSessions([entry(ID_A)], [sidecar(ID_A)]), NOW);
    expect(text).not.toContain("Nothing was deleted");
    expect(text.split("\n")).toHaveLength(2);
  });

  it("emits no trailing whitespace on any line", () => {
    const text = renderLsText(joinSessions([entry(ID_A), entry(ID_B, { label: "x" })], [sidecar(ID_A)]), NOW);
    for (const line of text.split("\n")) {
      expect(line).toBe(line.trimEnd());
    }
  });
});

describe("commands/ls: renderLsJson", () => {
  it("is an empty sessions array for no sessions", () => {
    expect(JSON.parse(renderLsJson([])) as LsJson).toEqual({ sessions: [] });
  });

  it("carries the full sidecar and the full Gondolin entry alongside the join status", () => {
    const payload = JSON.parse(renderLsJson(joinSessions([entry(ID_A)], [sidecar(ID_A)]))) as LsJson;
    expect(payload.sessions).toHaveLength(1);
    const session = payload.sessions[0]!;
    expect(session).toMatchObject({ id: ID_A, join: "both", status: "running", startedAt: T0 });
    expect(session.sidecar).toEqual(sidecar(ID_A));
    expect(session.gondolin).toEqual(entry(ID_A));
  });

  it("uses null (not a missing key) for the side that has no entry", () => {
    const gondolinOnly = (JSON.parse(renderLsJson(joinSessions([entry(ID_A)], []))) as LsJson).sessions[0]!;
    expect(gondolinOnly.sidecar).toBeNull();
    expect(gondolinOnly.gondolin).not.toBeNull();

    const sidecarOnly = (JSON.parse(renderLsJson(joinSessions([], [sidecar(ID_A)]))) as LsJson).sessions[0]!;
    expect(sidecarOnly.gondolin).toBeNull();
    expect(sidecarOnly.sidecar).not.toBeNull();
    expect(sidecarOnly.status).toBe("orphaned");
  });

  it("is pretty-printed, matching src/config/render.ts's renderJson convention", () => {
    expect(renderLsJson([])).toBe(JSON.stringify({ sessions: [] }, null, 2));
  });
});

describe("commands/ls: parseLsArgs", () => {
  it("defaults json to false", () => {
    expect(parseLsArgs([])).toEqual({ json: false });
  });

  it("accepts --json", () => {
    expect(parseLsArgs(["--json"])).toEqual({ json: true });
  });

  it("rejects a positional argument by name", () => {
    expect(() => parseLsArgs(["nope"])).toThrow(/corb ls: unexpected argument 'nope'/);
  });

  it("rejects an unknown flag", () => {
    expect(() => parseLsArgs(["--nope"])).toThrow();
  });
});
