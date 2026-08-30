// Unit tests for `src/vm/cgroup.ts` — M8.3's shared "read a uid's delegated
// cgroup controllers" primitive (factored out of `src/commands/doctor.ts`'s
// `checkCgroupControllers`, see that module's own comment for why only the
// raw read moved, not the classification policy).
//
// `cgroupControllersPath`/`parseCgroupControllers` are pure and tested as
// such below. `readCgroupControllersText`/`readDelegatedControllers` read a
// *hardcoded* `/sys/fs/cgroup/...` path derived from a uid argument — there
// is no injectable path to fabricate a fixture against (matching
// `doctor.ts`'s own precedent: its `checkCgroupControllers` was never
// path-injectable either, only its pure `classifyCgroupControllers`
// classifier was unit-tested against fabricated text, with the real read
// left to that module's own e2e smoke test). So this file does the same
// split: pure logic gets fabricated-input tests; the real read gets exactly
// two checks against this machine's actual, real state — the current
// process's own real uid (whatever this machine's environment happens to
// delegate, not asserted against a hardcoded controller list) and a uid
// essentially guaranteed to have no such cgroup path at all, proving the
// ENOENT-as-"nothing delegated" fallback for real, not just in theory.
import fs from "node:fs";
import { describe, expect, it } from "vitest";
import {
  cgroupControllersPath,
  parseCgroupControllers,
  readCgroupControllersText,
  readDelegatedControllers,
  readDelegatedControllersForCurrentUser,
} from "../../../src/vm/cgroup.ts";

describe("vm/cgroup: cgroupControllersPath", () => {
  it("builds the systemd user-manager cgroup.controllers path for a uid", () => {
    expect(cgroupControllersPath(1000)).toBe("/sys/fs/cgroup/user.slice/user-1000.slice/user@1000.service/cgroup.controllers");
  });
});

describe("vm/cgroup: parseCgroupControllers", () => {
  it("undefined (missing file) parses to an empty set", () => {
    expect(parseCgroupControllers(undefined)).toEqual(new Set());
  });

  it("splits whitespace-separated controller names into a set", () => {
    expect(parseCgroupControllers("cpuset cpu io memory pids\n")).toEqual(new Set(["cpuset", "cpu", "io", "memory", "pids"]));
  });

  it("a single controller with no surrounding whitespace parses correctly", () => {
    expect(parseCgroupControllers("pids")).toEqual(new Set(["pids"]));
  });

  it("empty string parses to an empty set (no stray empty-string member)", () => {
    expect(parseCgroupControllers("")).toEqual(new Set());
  });
});

describe.skipIf(process.platform !== "linux")("vm/cgroup: real filesystem (Linux)", () => {
  it("readCgroupControllersText/readDelegatedControllers agree with a direct read of this machine's own real cgroup.controllers file", () => {
    const uid = process.getuid?.();
    expect(uid, "process.getuid() unavailable — cannot run this real-environment check").toBeDefined();

    const path = cgroupControllersPath(uid!);
    let expectedText: string | undefined;
    try {
      expectedText = fs.readFileSync(path, "utf8");
    } catch (err) {
      if (!(err instanceof Error) || (err as NodeJS.ErrnoException).code !== "ENOENT") {
        throw err;
      }
      expectedText = undefined;
    }

    expect(readCgroupControllersText(uid!)).toBe(expectedText);
    expect(readDelegatedControllers(uid!)).toEqual(parseCgroupControllers(expectedText));
    expect(readDelegatedControllersForCurrentUser()).toEqual(parseCgroupControllers(expectedText));
  });

  it("a uid with no real cgroup.controllers file reads back as 'nothing delegated' (empty set), not a thrown error", () => {
    // Not a real uid on any sane system — no `/sys/fs/cgroup/user.slice/
    // user-999999999.slice/...` path exists, exercising the ENOENT branch
    // for real rather than mocking `fs.readFileSync`.
    const bogusUid = 999_999_999;
    expect(fs.existsSync(cgroupControllersPath(bogusUid)), "test assumption broken: this uid actually has a real cgroup path").toBe(false);

    expect(readCgroupControllersText(bogusUid)).toBeUndefined();
    expect(readDelegatedControllers(bogusUid)).toEqual(new Set());
  });
});
