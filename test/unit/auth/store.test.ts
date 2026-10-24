// Unit tests for `src/auth/store.ts`: file and directory permissions, atomic
// replacement, validation of what is read back, deletion, and the
// cross-process refresh lock. Real temp directories throughout, matching
// `test/unit/util/secure-write.test.ts`: this module's whole job is
// filesystem behaviour.
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  CREDENTIAL_FILE_VERSION,
  CredentialFileError,
  CredentialLockTimeoutError,
  credentialFilePath,
  deleteStoredCredential,
  InvalidProviderIdError,
  readStoredCredential,
  withCredentialLock,
  writeStoredCredential,
  type StoredCredential,
} from "../../../src/auth/store.ts";

function sampleCredential(overrides: Partial<StoredCredential> = {}): StoredCredential {
  return {
    version: CREDENTIAL_FILE_VERSION,
    provider: "openai-codex",
    type: "oauth",
    access: "access-token",
    refresh: "refresh-token",
    expires: 1_900_000_000_000,
    accountId: "acct-123",
    updatedAt: "2026-10-24T00:00:00.000Z",
    ...overrides,
  };
}

describe("auth/store credential files", () => {
  let root: string;
  let dir: string;

  beforeEach(() => {
    root = fs.mkdtempSync(path.join(os.tmpdir(), "corb-auth-store-"));
    dir = path.join(root, "credentials");
  });

  afterEach(() => {
    fs.rmSync(root, { recursive: true, force: true });
  });

  it("reads back exactly what was written", () => {
    const credential = sampleCredential();
    writeStoredCredential(dir, credential);
    expect(readStoredCredential(dir, "openai-codex")).toEqual(credential);
  });

  it("returns undefined when no login is stored", () => {
    expect(readStoredCredential(dir, "openai-codex")).toBeUndefined();
  });

  it("writes the file 0600 and creates the directory 0700", () => {
    writeStoredCredential(dir, sampleCredential());
    expect(fs.statSync(credentialFilePath(dir, "openai-codex")).mode & 0o777).toBe(0o600);
    expect(fs.statSync(dir).mode & 0o777).toBe(0o700);
  });

  it("tightens an existing, looser credentials directory to 0700", () => {
    fs.mkdirSync(dir, { mode: 0o755 });
    fs.chmodSync(dir, 0o755);
    writeStoredCredential(dir, sampleCredential());
    expect(fs.statSync(dir).mode & 0o777).toBe(0o700);
  });

  it("replaces a looser existing file with a 0600 one", () => {
    fs.mkdirSync(dir, { recursive: true });
    const filePath = credentialFilePath(dir, "openai-codex");
    fs.writeFileSync(filePath, "{}", { mode: 0o644 });
    writeStoredCredential(dir, sampleCredential());
    expect(fs.statSync(filePath).mode & 0o777).toBe(0o600);
  });

  it("replaces atomically and leaves no temp file behind", () => {
    writeStoredCredential(dir, sampleCredential({ access: "first" }));
    writeStoredCredential(dir, sampleCredential({ access: "second" }));
    expect(readStoredCredential(dir, "openai-codex")?.access).toBe("second");
    expect(fs.readdirSync(dir)).toEqual(["openai-codex.json"]);
  });

  it("throws CredentialFileError for invalid JSON, without treating it as logged out", () => {
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(credentialFilePath(dir, "openai-codex"), "{not json");
    expect(() => readStoredCredential(dir, "openai-codex")).toThrow(CredentialFileError);
    expect(() => readStoredCredential(dir, "openai-codex")).toThrow(/corb logout openai-codex/);
  });

  it.each([
    ["a missing refresh token", { refresh: "" }],
    ["a non-numeric expires", { expires: "soon" }],
    ["a provider mismatch", { provider: "other" }],
    ["an unknown version", { version: 99 }],
  ])("throws CredentialFileError for %s, without echoing token values", (_label, patch) => {
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(credentialFilePath(dir, "openai-codex"), JSON.stringify({ ...sampleCredential({ access: "SECRET-ACCESS" }), ...patch }));
    let message = "";
    try {
      readStoredCredential(dir, "openai-codex");
    } catch (err) {
      expect(err).toBeInstanceOf(CredentialFileError);
      message = (err as Error).message;
    }
    expect(message).not.toBe("");
    expect(message).not.toContain("SECRET-ACCESS");
  });

  it.each(["../escape", "Upper", "", "a/b", "."])("rejects the unsafe provider id %j", (id) => {
    expect(() => credentialFilePath(dir, id)).toThrow(InvalidProviderIdError);
  });

  it("deletes a stored login and reports whether anything was removed", () => {
    writeStoredCredential(dir, sampleCredential());
    expect(deleteStoredCredential(dir, "openai-codex")).toBe(true);
    expect(readStoredCredential(dir, "openai-codex")).toBeUndefined();
    expect(deleteStoredCredential(dir, "openai-codex")).toBe(false);
  });
});

describe("auth/store withCredentialLock", () => {
  let root: string;
  let dir: string;

  beforeEach(() => {
    root = fs.mkdtempSync(path.join(os.tmpdir(), "corb-auth-lock-"));
    dir = path.join(root, "credentials");
  });

  afterEach(() => {
    fs.rmSync(root, { recursive: true, force: true });
  });

  const lockPath = (): string => `${credentialFilePath(dir, "openai-codex")}.lock`;

  it("runs fn, returns its result, and removes the lock afterwards", async () => {
    const result = await withCredentialLock(dir, "openai-codex", async () => {
      expect(fs.existsSync(lockPath())).toBe(true);
      return 42;
    });
    expect(result).toBe(42);
    expect(fs.existsSync(lockPath())).toBe(false);
  });

  it("releases the lock when fn throws", async () => {
    await expect(
      withCredentialLock(dir, "openai-codex", async () => {
        throw new Error("boom");
      }),
    ).rejects.toThrow("boom");
    expect(fs.existsSync(lockPath())).toBe(false);
  });

  it("serialises concurrent holders: critical sections never overlap", async () => {
    const events: string[] = [];
    const section = (name: string) =>
      withCredentialLock(dir, "openai-codex", async () => {
        events.push(`${name}:start`);
        await new Promise((resolve) => setTimeout(resolve, 30));
        events.push(`${name}:end`);
      });
    await Promise.all([section("a"), section("b"), section("c")]);
    for (let i = 0; i < events.length; i += 2) {
      const name = events[i]!.split(":")[0];
      expect(events[i]).toBe(`${name}:start`);
      expect(events[i + 1]).toBe(`${name}:end`);
    }
    expect(events).toHaveLength(6);
  });

  it("takes over a lock whose holder pid is no longer alive", async () => {
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(lockPath(), JSON.stringify({ pid: 999_999, token: "old", createdAt: Date.now() }));
    const result = await withCredentialLock(dir, "openai-codex", async () => "ok", {
      isProcessAlive: (pid) => pid !== 999_999,
    });
    expect(result).toBe("ok");
    expect(fs.readdirSync(dir)).toEqual([]);
  });

  it("takes over a lock older than staleMs even if its pid looks alive", async () => {
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(lockPath(), JSON.stringify({ pid: process.pid, token: "old", createdAt: Date.now() - 10_000 }));
    const result = await withCredentialLock(dir, "openai-codex", async () => "ok", { staleMs: 1_000 });
    expect(result).toBe("ok");
  });

  it("times out while a live, fresh holder keeps the lock", async () => {
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(lockPath(), JSON.stringify({ pid: process.pid, token: "other", createdAt: Date.now() }));
    await expect(
      withCredentialLock(dir, "openai-codex", async () => "never", { timeoutMs: 100, sleep: () => new Promise((r) => setTimeout(r, 10)) }),
    ).rejects.toBeInstanceOf(CredentialLockTimeoutError);
    // The other holder's lock is left untouched.
    expect(JSON.parse(fs.readFileSync(lockPath(), "utf8")).token).toBe("other");
  });

  it("does not delete a lock that another holder took over in the meantime", async () => {
    await withCredentialLock(dir, "openai-codex", async () => {
      fs.writeFileSync(lockPath(), JSON.stringify({ pid: process.pid, token: "usurper", createdAt: Date.now() }));
    });
    expect(JSON.parse(fs.readFileSync(lockPath(), "utf8")).token).toBe("usurper");
  });
});
