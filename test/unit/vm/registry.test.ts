// Unit tests for `src/vm/registry.ts` — M8.1. Covers: write-then-read round
// trip, `readSessionSidecar` returning `undefined` for a missing file,
// `MalformedSessionSidecarError` for a corrupt/incomplete file,
// `listSessionSidecars` skipping a corrupt sidecar among otherwise-valid ones
// and returning `[]` for a missing directory, and `removeSessionSidecar`
// idempotency. Uses a temp directory per test (`fs.mkdtempSync` +
// `fs.rmSync` in `beforeEach`/`afterEach`), matching
// `test/unit/policy/audit.test.ts`'s own pattern for the same reason: never
// touch the real `~/.local/state/corb`.
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  MalformedSessionSidecarError,
  listSessionSidecars,
  readSessionSidecar,
  removeSessionSidecar,
  sessionSidecarPath,
  writeSessionSidecar,
  type SessionSidecar,
} from "../../../src/vm/registry.ts";

function makeSidecar(overrides: Partial<SessionSidecar> = {}): SessionSidecar {
  return {
    id: "11111111-1111-4111-8111-111111111111",
    sessionLabel: "corb-run:corb",
    dirs: [{ name: "corb", hostPath: "/home/dario/Code/corb", mode: "rw" }],
    image: { selector: "corb:0.1.0", buildId: "abcdef01" },
    auditPath: "/home/dario/.local/state/corb/audit.jsonl",
    pid: 12345,
    startedAt: "2026-08-30T12:00:00.000Z",
    ...overrides,
  };
}

describe("vm/registry session sidecars", () => {
  let dir: string;

  beforeEach(() => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), "corb-registry-"));
  });

  afterEach(() => {
    fs.rmSync(dir, { recursive: true, force: true });
  });

  it("write-then-read round trip returns an equal sidecar", () => {
    const sidecar = makeSidecar();
    writeSessionSidecar(sidecar, dir);

    const read = readSessionSidecar(sidecar.id, dir);
    expect(read).toEqual(sidecar);
  });

  it("writeSessionSidecar creates sessionsDir (mkdir -p) if it doesn't exist yet", () => {
    const nested = path.join(dir, "does", "not", "exist", "yet");
    const sidecar = makeSidecar();
    writeSessionSidecar(sidecar, nested);

    expect(fs.existsSync(nested)).toBe(true);
    expect(readSessionSidecar(sidecar.id, nested)).toEqual(sidecar);
  });

  it("writes pretty JSON with a trailing newline, filename <id>.json", () => {
    const sidecar = makeSidecar();
    writeSessionSidecar(sidecar, dir);

    const raw = fs.readFileSync(sessionSidecarPath(sidecar.id, dir), "utf8");
    expect(raw.endsWith("\n")).toBe(true);
    expect(raw).toBe(JSON.stringify(sidecar, null, 2) + "\n");
  });

  it("readSessionSidecar returns undefined for a missing file", () => {
    expect(readSessionSidecar("does-not-exist", dir)).toBeUndefined();
  });

  it("readSessionSidecar throws MalformedSessionSidecarError for invalid JSON", () => {
    fs.writeFileSync(path.join(dir, "bad-json.json"), "{ not valid json");
    expect(() => readSessionSidecar("bad-json", dir)).toThrow(MalformedSessionSidecarError);
  });

  it("readSessionSidecar throws MalformedSessionSidecarError for JSON missing required fields", () => {
    fs.writeFileSync(path.join(dir, "incomplete.json"), JSON.stringify({ id: "incomplete" }));
    expect(() => readSessionSidecar("incomplete", dir)).toThrow(MalformedSessionSidecarError);
  });

  it("readSessionSidecar throws MalformedSessionSidecarError for a wrongly-typed field (dirs[].mode)", () => {
    const bad = { ...makeSidecar(), dirs: [{ name: "corb", hostPath: "/x", mode: "rwx" }] };
    fs.writeFileSync(path.join(dir, "bad-mode.json"), JSON.stringify(bad));
    expect(() => readSessionSidecar("bad-mode", dir)).toThrow(MalformedSessionSidecarError);
  });

  it("listSessionSidecars skips a corrupt sidecar among otherwise-valid ones", () => {
    const good1 = makeSidecar({ id: "aaaaaaaa-1111-4111-8111-111111111111" });
    const good2 = makeSidecar({ id: "bbbbbbbb-1111-4111-8111-111111111111", sessionLabel: "corb-run:other" });
    writeSessionSidecar(good1, dir);
    writeSessionSidecar(good2, dir);
    fs.writeFileSync(path.join(dir, "corrupt.json"), "not json at all");
    // A non-.json file must be ignored entirely, not attempted.
    fs.writeFileSync(path.join(dir, "notes.txt"), "hello");

    const listed = listSessionSidecars(dir);
    expect(listed).toHaveLength(2);
    expect(listed.map((s) => s.id).sort()).toEqual([good1.id, good2.id].sort());
  });

  it("listSessionSidecars returns [] for a missing directory, without creating it", () => {
    const missing = path.join(dir, "never-created");
    expect(listSessionSidecars(missing)).toEqual([]);
    expect(fs.existsSync(missing)).toBe(false);
  });

  it("removeSessionSidecar removes an existing sidecar", () => {
    const sidecar = makeSidecar();
    writeSessionSidecar(sidecar, dir);
    expect(fs.existsSync(sessionSidecarPath(sidecar.id, dir))).toBe(true);

    removeSessionSidecar(sidecar.id, dir);
    expect(fs.existsSync(sessionSidecarPath(sidecar.id, dir))).toBe(false);
    expect(readSessionSidecar(sidecar.id, dir)).toBeUndefined();
  });

  it("removeSessionSidecar is idempotent (no-op, not an error) when the file is already gone", () => {
    expect(() => removeSessionSidecar("never-existed", dir)).not.toThrow();
    // Calling it a second time on the same (still-nonexistent) id is still fine.
    expect(() => removeSessionSidecar("never-existed", dir)).not.toThrow();
  });

  it("image.buildId being undefined round-trips correctly (JSON.stringify drops undefined fields)", () => {
    const sidecar = makeSidecar({ image: { selector: "corb:0.1.0", buildId: undefined } });
    writeSessionSidecar(sidecar, dir);

    const read = readSessionSidecar(sidecar.id, dir);
    expect(read?.image).toEqual({ selector: "corb:0.1.0", buildId: undefined });
  });
});
