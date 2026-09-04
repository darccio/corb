// Unit tests for `src/policy/audit.ts` — M3.1. Covers the "write-through,
// not written-until-flush()" contract, JSONL shape, multi-record batching,
// append-not-clobber across two flush cycles, directory/file creation and
// their permissions, subject/reason truncation, the injected clock, and the
// end-to-end redaction pass (the concrete version of `docs/design.md` §6's
// "plant a known secret, assert its absence").
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { createAuditWriter, MAX_REASON_BYTES, MAX_SUBJECT_BYTES, type AuditEvent } from "../../../src/policy/audit.ts";

describe("policy/audit AuditWriter", () => {
  let dir: string;
  let logPath: string;

  beforeEach(() => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), "corb-audit-"));
    logPath = path.join(dir, "audit.jsonl");
  });

  afterEach(() => {
    fs.rmSync(dir, { recursive: true, force: true });
  });

  function readLines(): unknown[] {
    const content = fs.readFileSync(logPath, "utf8");
    return content
      .split("\n")
      .filter((line) => line.length > 0)
      .map((line) => JSON.parse(line));
  }

  it("record() writes to disk immediately, before flush() is ever called", () => {
    const writer = createAuditWriter({ path: logPath, now: () => 1000 });
    writer.record({ channel: "http", decision: "allow", subject: "GET example.com/", sessionId: "s1" });
    expect(fs.existsSync(logPath)).toBe(true);
    expect(readLines()).toEqual([{ ts: 1000, channel: "http", decision: "allow", subject: "GET example.com/", sessionId: "s1" }]);
  });

  it("nothing touches disk until the first record() call — construction alone opens no file", () => {
    createAuditWriter({ path: logPath, now: () => 1000 });
    expect(fs.existsSync(logPath)).toBe(false);
  });

  it("flush() is a safe no-op when nothing was ever recorded (no fd was ever opened)", () => {
    const writer = createAuditWriter({ path: logPath, now: () => 1000 });
    expect(() => writer.flush()).not.toThrow();
    expect(fs.existsSync(logPath)).toBe(false);
  });

  it("flush() is idempotent — calling it twice does not throw", () => {
    const writer = createAuditWriter({ path: logPath, now: () => 1000 });
    writer.record({ channel: "http", decision: "allow", subject: "GET example.com/", sessionId: "s1" });
    writer.flush();
    expect(() => writer.flush()).not.toThrow();
  });

  it("record() after flush() reopens the file and appends, rather than losing further events", () => {
    const writer = createAuditWriter({ path: logPath, now: () => 1 });
    writer.record({ channel: "session", decision: "allow", subject: "start", sessionId: "s1" });
    writer.flush();
    writer.record({ channel: "session", decision: "allow", subject: "after-flush", sessionId: "s1" });
    expect((readLines() as AuditEvent[]).map((e) => e.subject)).toEqual(["start", "after-flush"]);
  });

  it("creates the log file with 0600 permissions", () => {
    const writer = createAuditWriter({ path: logPath, now: () => 1 });
    writer.record({ channel: "gate", decision: "allow", subject: "op", sessionId: "s1" });
    const mode = fs.statSync(logPath).mode & 0o777;
    expect(mode).toBe(0o600);
  });

  it("tightens an existing, more permissive log file to 0600 on first use", () => {
    fs.writeFileSync(logPath, "", { mode: 0o644 });
    expect(fs.statSync(logPath).mode & 0o777).toBe(0o644);
    const writer = createAuditWriter({ path: logPath, now: () => 1 });
    writer.record({ channel: "gate", decision: "allow", subject: "op", sessionId: "s1" });
    expect(fs.statSync(logPath).mode & 0o777).toBe(0o600);
  });

  it("refuses to open when the log path is already a symlink, rather than silently following it (O_NOFOLLOW)", () => {
    const target = path.join(dir, "target.txt");
    fs.writeFileSync(target, "pre-existing content");
    fs.symlinkSync(target, logPath);

    const writer = createAuditWriter({ path: logPath, now: () => 1 });
    let caught: unknown;
    try {
      writer.record({ channel: "gate", decision: "allow", subject: "op", sessionId: "s1" });
    } catch (err) {
      caught = err;
    }
    // Observed directly against this Node/Linux combination (see the audit
    // module's `ensureOpen` comment): opening a path that already exists as
    // a symlink with `O_NOFOLLOW` in the flags fails with ELOOP rather than
    // silently following it.
    expect(caught).toBeInstanceOf(Error);
    expect((caught as NodeJS.ErrnoException).code).toBe("ELOOP");
  });

  it("a symlink at the log path leaves its target file untouched by the failed open — not written, and not chmod'd", () => {
    const target = path.join(dir, "target.txt");
    fs.writeFileSync(target, "pre-existing content", { mode: 0o644 });
    fs.symlinkSync(target, logPath);
    const modeBefore = fs.statSync(target).mode & 0o777;
    const mtimeBefore = fs.statSync(target).mtimeMs;

    const writer = createAuditWriter({ path: logPath, now: () => 1 });
    expect(() => writer.record({ channel: "gate", decision: "allow", subject: "op", sessionId: "s1" })).toThrow();

    // This is the actual proof the arbitrary-host-file-write primitive is
    // closed: not merely that *some* error was thrown, but that the
    // symlink's target was never opened, appended to, or chmod'd as a side
    // effect of the attempt.
    expect(fs.readFileSync(target, "utf8")).toBe("pre-existing content");
    expect(fs.statSync(target).mode & 0o777).toBe(modeBefore);
    expect(fs.statSync(target).mtimeMs).toBe(mtimeBefore);
  });

  it("creates a newly-created target directory with 0700 permissions", () => {
    const nestedDir = path.join(dir, "nested-perms");
    const nestedPath = path.join(nestedDir, "audit.jsonl");
    const writer = createAuditWriter({ path: nestedPath, now: () => 1 });
    writer.record({ channel: "gate", decision: "allow", subject: "op", sessionId: "s1" });
    expect(fs.statSync(nestedDir).mode & 0o777).toBe(0o700);
  });

  it("truncates an oversized subject to MAX_SUBJECT_BYTES, marking that it happened", () => {
    const writer = createAuditWriter({ path: logPath, now: () => 1 });
    const oversized = "x".repeat(MAX_SUBJECT_BYTES + 500);
    writer.record({ channel: "vfs", decision: "deny", subject: oversized, sessionId: "s1" });

    const lines = readLines() as AuditEvent[];
    expect(Buffer.byteLength(lines[0]?.subject ?? "", "utf8")).toBeLessThanOrEqual(MAX_SUBJECT_BYTES);
    expect(lines[0]?.subject).toContain("[truncated]");
  });

  it("truncates an oversized reason to MAX_REASON_BYTES, marking that it happened", () => {
    const writer = createAuditWriter({ path: logPath, now: () => 1 });
    const oversized = "y".repeat(MAX_REASON_BYTES + 500);
    writer.record({ channel: "vfs", decision: "deny", subject: "op", reason: oversized, sessionId: "s1" });

    const lines = readLines() as AuditEvent[];
    expect(Buffer.byteLength(lines[0]?.reason ?? "", "utf8")).toBeLessThanOrEqual(MAX_REASON_BYTES);
    expect(lines[0]?.reason).toContain("[truncated]");
  });

  it("a subject under the byte cap is left untouched", () => {
    const writer = createAuditWriter({ path: logPath, now: () => 1 });
    writer.record({ channel: "vfs", decision: "deny", subject: "/work/repo/.env", sessionId: "s1" });
    const lines = readLines() as AuditEvent[];
    expect(lines[0]?.subject).toBe("/work/repo/.env");
  });

  it("flush() writes one valid JSON object per line, matching the recorded event", () => {
    const writer = createAuditWriter({ path: logPath, now: () => 42 });
    writer.record({ channel: "vfs", decision: "deny", subject: "/work/repo/.env", reason: "blocked path", sessionId: "s1" });
    writer.flush();

    const lines = readLines();
    expect(lines).toEqual([
      { ts: 42, channel: "vfs", decision: "deny", subject: "/work/repo/.env", reason: "blocked path", sessionId: "s1" },
    ]);
  });

  it("multiple record() calls followed by one flush() produce multiple lines in one call", () => {
    const writer = createAuditWriter({ path: logPath, now: () => 1 });
    writer.record({ channel: "http", decision: "allow", subject: "GET a.example/", sessionId: "s1" });
    writer.record({ channel: "ssh", decision: "allow", subject: "git.example:repo", sessionId: "s1" });
    writer.record({ channel: "gate", decision: "deny", subject: "op1", sessionId: "s1" });
    writer.flush();

    expect(readLines()).toHaveLength(3);
  });

  it("a second round of record()+flush() appends rather than overwrites", () => {
    const writer = createAuditWriter({ path: logPath, now: () => 1 });
    writer.record({ channel: "session", decision: "allow", subject: "start", sessionId: "s1" });
    writer.record({ channel: "session", decision: "allow", subject: "tick", sessionId: "s1" });
    writer.flush();

    writer.record({ channel: "session", decision: "allow", subject: "end", sessionId: "s1" });
    writer.flush();

    const lines = readLines() as AuditEvent[];
    expect(lines.map((e) => e.subject)).toEqual(["start", "tick", "end"]);
  });

  it("creates the target directory automatically if it doesn't exist", () => {
    const nestedPath = path.join(dir, "nested", "state", "audit.jsonl");
    const writer = createAuditWriter({ path: nestedPath, now: () => 1 });
    writer.record({ channel: "gate", decision: "allow", subject: "op", sessionId: "s1" });
    writer.flush();

    expect(fs.existsSync(nestedPath)).toBe(true);
  });

  it("the injected clock function controls the recorded ts value", () => {
    let current = 1000;
    const writer = createAuditWriter({ path: logPath, now: () => current });
    writer.record({ channel: "gate", decision: "allow", subject: "first", sessionId: "s1" });
    current = 2000;
    writer.record({ channel: "gate", decision: "allow", subject: "second", sessionId: "s1" });
    writer.flush();

    const lines = readLines() as AuditEvent[];
    expect(lines.map((e) => e.ts)).toEqual([1000, 2000]);
  });

  it("applies redaction end-to-end: the written file contains the placeholder, not the raw secret", () => {
    const secret = "ghp_supersecrettoken123";
    const writer = createAuditWriter({ path: logPath, now: () => 1, redactSecrets: [secret] });
    writer.record({
      channel: "gate",
      decision: "deny",
      subject: "op",
      reason: `denied: value contained ${secret}`,
      sessionId: "s1",
    });
    writer.flush();

    const raw = fs.readFileSync(logPath, "utf8");
    expect(raw).not.toContain(secret);
    expect(raw).toContain("[REDACTED]");

    const lines = readLines() as AuditEvent[];
    expect(lines[0]?.reason).toBe("denied: value contained [REDACTED]");
  });

  it("a writer with no redaction list configured passes text through unchanged", () => {
    const writer = createAuditWriter({ path: logPath, now: () => 1 });
    const reason = "this looks like a secret but isn't redacted: ghp_notconfigured";
    writer.record({ channel: "gate", decision: "deny", subject: "op", reason, sessionId: "s1" });
    writer.flush();

    const lines = readLines() as AuditEvent[];
    expect(lines[0]?.reason).toBe(reason);
  });

  it("addRedactedSecrets() registers values a caller learns after construction, applied to later record() calls", () => {
    const secret = "sk-late-bound-secret";
    const writer = createAuditWriter({ path: logPath, now: () => 1 });
    writer.addRedactedSecrets([secret]);
    writer.record({ channel: "http", decision: "allow", subject: "op", reason: `bearer ${secret}`, sessionId: "s1" });
    writer.flush();

    const lines = readLines() as AuditEvent[];
    expect(lines[0]?.reason).toBe("bearer [REDACTED]");
  });

  it("addRedactedSecrets() adds to, rather than replaces, values passed at construction time", () => {
    const constructorSecret = "ctor-secret";
    const laterSecret = "later-secret";
    const writer = createAuditWriter({ path: logPath, now: () => 1, redactSecrets: [constructorSecret] });
    writer.addRedactedSecrets([laterSecret]);
    writer.record({
      channel: "gate",
      decision: "deny",
      subject: "op",
      reason: `${constructorSecret} and ${laterSecret}`,
      sessionId: "s1",
    });
    writer.flush();

    const lines = readLines() as AuditEvent[];
    expect(lines[0]?.reason).toBe("[REDACTED] and [REDACTED]");
  });

  it("addRedactedSecrets() does not retroactively redact events already recorded before it was called", () => {
    const secret = "not-yet-registered";
    const writer = createAuditWriter({ path: logPath, now: () => 1 });
    writer.record({ channel: "gate", decision: "deny", subject: "op", reason: secret, sessionId: "s1" });
    writer.addRedactedSecrets([secret]);
    writer.flush();

    const lines = readLines() as AuditEvent[];
    expect(lines[0]?.reason).toBe(secret);
  });
});
