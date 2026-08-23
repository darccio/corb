// Unit tests for `src/policy/audit.ts` — M3.1. Covers the "buffered, not
// written until flush()" contract, JSONL shape, multi-record batching,
// append-not-clobber across two flush cycles, directory auto-creation, the
// injected clock, and the end-to-end redaction pass (the concrete version
// of `docs/design.md` §6's "plant a known secret, assert its absence").
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { createAuditWriter, type AuditEvent } from "../../../src/policy/audit.ts";

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

  it("does not write anything to disk until flush() is called", () => {
    const writer = createAuditWriter({ path: logPath, now: () => 1000 });
    writer.record({ channel: "http", decision: "allow", subject: "GET example.com/", sessionId: "s1" });
    expect(fs.existsSync(logPath)).toBe(false);
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
