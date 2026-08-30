// Unit tests for `src/vm/sockpath.ts` — the shared "would a Gondolin session
// socket created in this directory actually bind?" primitive.
//
// Two kinds of test here, mirroring `test/unit/vm/cgroup.test.ts`'s own split:
//
//   (a) Pure logic against fabricated directory paths. The boundary cases are
//       the entire point of the module — an off-by-one in `MAX_UNIX_SOCKET_
//       PATH_LENGTH` or `SESSION_SOCKET_SUFFIX_LENGTH` reintroduces exactly
//       the bug class this exists to detect — so the directory lengths below
//       are computed from the constants rather than hardcoded, *and*
//       separately asserted to be the specific numbers derived by hand (66/67
//       for the directory, 108/109 for the socket path) so a wrong constant
//       cannot make a self-consistently wrong test pass.
//
//   (b) `gondolinSessionsDir`'s three-way env chain, exercised against
//       fabricated `NodeJS.ProcessEnv` objects via its injectable `env`
//       parameter — no mutation of the real `process.env` required.
//
// Deliberately absent: any test that binds a real socket. Shipped code does a
// pure length computation and never probes (see the module comment); the
// 108-binds/109-fails figure itself was verified out-of-band with a one-off
// `net.createServer().listen()` probe, and baking that probe into the suite
// would make it slow, filesystem-dependent, and no more truthful.
import os from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import {
  classifySessionSocketPath,
  describeSessionSocketOverflow,
  gondolinSessionsDir,
  MAX_SESSIONS_DIR_LENGTH,
  MAX_UNIX_SOCKET_PATH_LENGTH,
  SESSION_SOCKET_SUFFIX_LENGTH,
} from "../../../src/vm/sockpath.ts";

/** A directory path of exactly `length` characters, absolute and plausible-looking. */
function dirOfLength(length: number): string {
  const prefix = "/tmp/";
  return prefix + "d".repeat(length - prefix.length);
}

describe("vm/sockpath: the constants themselves", () => {
  it("the socket path budget is the empirically measured 108 (108 binds, 109 fails with EINVAL on Linux)", () => {
    expect(MAX_UNIX_SOCKET_PATH_LENGTH).toBe(108);
  });

  it("the per-session overhead is 42: '/' + a 36-char UUID + '.sock'", () => {
    expect(SESSION_SOCKET_SUFFIX_LENGTH).toBe(42);
    // Cross-check against a real-shaped Gondolin socket filename rather than
    // trusting the arithmetic alone.
    expect(`/${"0d1c2b3a-4567-4890-abcd-ef0123456789"}.sock`.length).toBe(SESSION_SOCKET_SUFFIX_LENGTH);
  });

  it("the derived sessions-directory budget is 66 (108 - 42)", () => {
    expect(MAX_SESSIONS_DIR_LENGTH).toBe(66);
  });
});

describe("vm/sockpath: classifySessionSocketPath", () => {
  it("a comfortably short directory fits", () => {
    const fit = classifySessionSocketPath("/home/u/.cache/gondolin/sessions");
    expect(fit.fits).toBe(true);
    expect(fit.sessionsDir).toBe("/home/u/.cache/gondolin/sessions");
    expect(fit.socketPathLength).toBe("/home/u/.cache/gondolin/sessions".length + 42);
    expect(fit.budget).toBe(108);
  });

  it("a directory exactly at the boundary (66 chars) still fits — its socket path is exactly 108", () => {
    const dir = dirOfLength(MAX_SESSIONS_DIR_LENGTH);
    expect(dir.length).toBe(66);

    const fit = classifySessionSocketPath(dir);
    expect(fit.socketPathLength).toBe(108);
    expect(fit.fits).toBe(true);
  });

  it("one character over the boundary (67 chars) does not fit — its socket path is 109, the first length that fails to bind", () => {
    const dir = dirOfLength(MAX_SESSIONS_DIR_LENGTH + 1);
    expect(dir.length).toBe(67);

    const fit = classifySessionSocketPath(dir);
    expect(fit.socketPathLength).toBe(109);
    expect(fit.fits).toBe(false);
  });

  it("a wildly over-long directory does not fit either (the check is not boundary-only)", () => {
    const fit = classifySessionSocketPath(dirOfLength(400));
    expect(fit.fits).toBe(false);
    expect(fit.socketPathLength).toBe(442);
  });

  it("an empty directory string is measured as just the suffix, and fits", () => {
    const fit = classifySessionSocketPath("");
    expect(fit.socketPathLength).toBe(42);
    expect(fit.fits).toBe(true);
  });
});

describe("vm/sockpath: describeSessionSocketOverflow", () => {
  it("names the offending directory, both numbers, what breaks, and the remedy", () => {
    const dir = dirOfLength(MAX_SESSIONS_DIR_LENGTH + 1);
    const message = describeSessionSocketOverflow(classifySessionSocketPath(dir));

    expect(message).toContain(dir);
    expect(message).toContain("109");
    expect(message).toContain("108");
    // The actual user-visible symptom, not just "path too long".
    expect(message).toContain("corb ls");
    expect(message).toContain("corb kill");
    // An actionable remedy, naming the env var that fixes it.
    expect(message).toContain("GONDOLIN_SESSIONS_DIR");
    expect(message).toContain("66");
  });
});

describe("vm/sockpath: gondolinSessionsDir env chain", () => {
  it("GONDOLIN_SESSIONS_DIR wins outright, even when XDG_CACHE_HOME is also set", () => {
    const env = { GONDOLIN_SESSIONS_DIR: "/tmp/gsd", XDG_CACHE_HOME: "/tmp/xdg", HOME: "/home/u" };
    expect(gondolinSessionsDir(env)).toBe("/tmp/gsd");
  });

  it("XDG_CACHE_HOME is used when GONDOLIN_SESSIONS_DIR is absent", () => {
    const env = { XDG_CACHE_HOME: "/tmp/xdg" };
    expect(gondolinSessionsDir(env)).toBe(path.join("/tmp/xdg", "gondolin", "sessions"));
  });

  it("falls back to ~/.cache/gondolin/sessions when neither is set", () => {
    expect(gondolinSessionsDir({})).toBe(path.join(os.homedir(), ".cache", "gondolin", "sessions"));
  });

  it("an empty-string GONDOLIN_SESSIONS_DIR still wins, matching Gondolin's own '??' (nullish, not falsy) semantics", () => {
    // `session-registry.js` uses `??`, so an explicitly-empty override is
    // honoured there rather than falling through to the cache path. This
    // duplication must match that behavior exactly, however odd the value.
    expect(gondolinSessionsDir({ GONDOLIN_SESSIONS_DIR: "", XDG_CACHE_HOME: "/tmp/xdg" })).toBe("");
    expect(gondolinSessionsDir({ XDG_CACHE_HOME: "" })).toBe(path.join("gondolin", "sessions"));
  });

  it("defaults to the real process.env when no env is passed", () => {
    expect(gondolinSessionsDir()).toBe(gondolinSessionsDir(process.env));
  });
});
