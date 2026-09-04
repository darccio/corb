// Unit tests for `src/util/secure-write.ts`. Covers: the basic write (exact
// content, 0600 file mode), directory creation (0700 for a directory this
// call creates, left alone for one that already existed), the two
// atomicity guarantees (a failed write never leaves `filePath` torn — it's
// either the old complete content/absence, or the new complete content, and
// never leaves a temp file behind), and the "rename replaces permissions
// too" property that makes a separate retroactive `chmodSync` unnecessary,
// unlike `src/policy/audit.ts`'s own append-mode hardening.
//
// The two failure-path tests use real filesystem permission errors rather
// than mocking `node:fs` (matching `resolve.test.ts`'s own precedent of
// creating a directory where a file is expected to force a real EISDIR),
// since this module's whole job is filesystem I/O behavior under failure —
// a real, uncontrived error is more convincing than a mocked one.
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { writeFileSecure } from "../../../src/util/secure-write.ts";

describe("util/secure-write writeFileSecure", () => {
  let dir: string;

  beforeEach(() => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), "corb-securewrite-"));
  });

  afterEach(() => {
    fs.rmSync(dir, { recursive: true, force: true });
  });

  it("writes the given content to filePath verbatim", () => {
    const filePath = path.join(dir, "target.json");
    writeFileSecure(filePath, "hello world");
    expect(fs.readFileSync(filePath, "utf8")).toBe("hello world");
  });

  it("creates the file with 0600 permissions", () => {
    const filePath = path.join(dir, "target.json");
    writeFileSecure(filePath, "hello world");
    expect(fs.statSync(filePath).mode & 0o777).toBe(0o600);
  });

  it("creates a missing target directory with 0700 permissions", () => {
    const nestedDir = path.join(dir, "nested-perms");
    const filePath = path.join(nestedDir, "target.json");
    writeFileSecure(filePath, "hello world");
    expect(fs.statSync(nestedDir).mode & 0o777).toBe(0o700);
  });

  it("does not retroactively tighten an already-existing, more permissive directory", () => {
    const existingDir = path.join(dir, "existing");
    fs.mkdirSync(existingDir, { mode: 0o755 });
    const filePath = path.join(existingDir, "target.json");
    writeFileSecure(filePath, "hello world");
    expect(fs.statSync(existingDir).mode & 0o777).toBe(0o755);
  });

  it("replaces an existing file's looser permissions with 0600 (no separate chmod needed — rename carries the temp file's own permissions)", () => {
    const filePath = path.join(dir, "target.json");
    fs.writeFileSync(filePath, "old content", { mode: 0o644 });
    expect(fs.statSync(filePath).mode & 0o777).toBe(0o644);

    writeFileSecure(filePath, "new content");

    expect(fs.statSync(filePath).mode & 0o777).toBe(0o600);
    expect(fs.readFileSync(filePath, "utf8")).toBe("new content");
  });

  it("leaves a pre-existing file's content completely untouched when the write fails before the rename", () => {
    const filePath = path.join(dir, "target.json");
    fs.writeFileSync(filePath, "original content");
    // No write permission on `dir` itself: mkdirSync's recursive no-op on an
    // already-existing directory still succeeds, but creating the new temp
    // file inside it cannot -- a real EACCES, not a simulated one.
    fs.chmodSync(dir, 0o500);
    try {
      expect(() => writeFileSecure(filePath, "new content")).toThrow();
    } finally {
      fs.chmodSync(dir, 0o700);
    }

    expect(fs.readFileSync(filePath, "utf8")).toBe("original content");
    expect(fs.readdirSync(dir)).toEqual(["target.json"]);
  });

  it("leaves filePath absent when a write that never existed before fails", () => {
    const filePath = path.join(dir, "target.json");
    fs.chmodSync(dir, 0o500);
    try {
      expect(() => writeFileSecure(filePath, "new content")).toThrow();
    } finally {
      fs.chmodSync(dir, 0o700);
    }

    expect(fs.existsSync(filePath)).toBe(false);
    expect(fs.readdirSync(dir)).toEqual([]);
  });

  it("cleans up the temp file when the write succeeds but the rename fails, leaving the original target and no leftover temp file", () => {
    const filePath = path.join(dir, "target");
    // A rename can never land a file on top of an existing, non-empty-proof
    // directory (EISDIR) -- forces a real failure strictly after the temp
    // file write has already succeeded, unlike the EACCES tests above.
    fs.mkdirSync(filePath);

    expect(() => writeFileSecure(filePath, "new content")).toThrow();

    expect(fs.statSync(filePath).isDirectory()).toBe(true);
    expect(fs.readdirSync(dir)).toEqual(["target"]);
  });
});
