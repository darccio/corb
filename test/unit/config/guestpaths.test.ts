// Unit tests for `src/config/guestpaths.ts` — M2.2. Covers the primary
// name-shape defense (empty, `.`, `..`, a path separator), the reserved-path
// rejection list, and mount-target collision (equal/duplicate, and the
// near-miss that must NOT be flagged as a collision).
//
// Two things this file deliberately does *not* pad out with a misleading
// test, and says why instead:
//
//   - The resolved-path reserved-check (`assertNotReserved` in
//     guestpaths.ts) cannot be exercised independently of the primary
//     name-shape check (`assertPlainSegment`): every `name` that would make
//     `/work/<name>` normalize to a reserved path (e.g. `"../etc"` ->
//     `/etc`, `".."` -> `/`) necessarily contains a `/` or *is* `..`, so the
//     primary check throws first. The "rejects each reserved path" tests
//     below prove the reserved-path scenarios are all rejected end-to-end;
//     they do not prove the second check specifically fired, because the
//     first one always does. See guestpaths.ts's own comment on
//     `assertNotReserved` for the full reasoning.
//   - A genuine *proper*-prefix collision between two different dirs (e.g.
//     `/work/foo` vs `/work/foo/bar`) is unreachable through this module's
//     public API: every dir's target is exactly `/work/<name>` with `name`
//     restricted to one path component, so two distinct names can only ever
//     produce equal-depth targets that differ at that one component (never a
//     prefix of one another). The "equal targets" tests below (which
//     subsume the duplicate-name case) and the "near-miss" test are what's
//     actually reachable and are what's tested.
import { describe, expect, it } from "vitest";
import { GuestPathError, validateMountTargets } from "../../../src/config/guestpaths.ts";

const RESERVED_PATHS = ["/", "/etc", "/etc/gondolin", "/run", "/proc", "/sys", "/dev", "/usr", "/bin", "/lib"];

describe("config/guestpaths", () => {
  it("accepts a normal set of plain single-segment names", () => {
    expect(() => validateMountTargets([{ name: "corb" }, { name: "reference" }, { name: "scratch" }])).not.toThrow();
  });

  describe("rejects a name that isn't a plain path segment (primary defense)", () => {
    it("empty name", () => {
      expect(() => validateMountTargets([{ name: "" }])).toThrow(GuestPathError);
    });

    it("name '.'", () => {
      expect(() => validateMountTargets([{ name: "." }])).toThrow(GuestPathError);
    });

    it("name '..'", () => {
      expect(() => validateMountTargets([{ name: ".." }])).toThrow(GuestPathError);
    });

    it("name containing a forward slash", () => {
      expect(() => validateMountTargets([{ name: "foo/bar" }])).toThrow(GuestPathError);
    });

    it("name containing a leading slash (absolute-looking)", () => {
      expect(() => validateMountTargets([{ name: "/etc" }])).toThrow(GuestPathError);
    });

    it("name containing a backslash", () => {
      expect(() => validateMountTargets([{ name: "foo\\bar" }])).toThrow(GuestPathError);
    });
  });

  describe("rejects every reserved guest path (reached via a traversal-shaped name, so the primary check fires first)", () => {
    for (const reserved of RESERVED_PATHS) {
      it(`resolves-to '${reserved}'`, () => {
        // "/work/.." + the reserved path's own remaining segments normalizes
        // to the reserved path itself; constructing it this way is exactly
        // what makes the name fail the primary shape check (it contains
        // '..' and, for anything but '/', a '/' too).
        const suffix = reserved === "/" ? "" : reserved.slice(1);
        const name = suffix === "" ? ".." : `../${suffix}`;
        expect(() => validateMountTargets([{ name }])).toThrow(GuestPathError);
      });
    }
  });

  describe("mount-target collision", () => {
    it("rejects two dirs with the same name (equal targets, and the duplicate-name case in one)", () => {
      expect(() => validateMountTargets([{ name: "corb" }, { name: "corb" }])).toThrow(GuestPathError);
    });

    it("does NOT reject a near-miss where one name is a superstring, not a path-component prefix, of another", () => {
      expect(() => validateMountTargets([{ name: "foo" }, { name: "foobar" }])).not.toThrow();
    });

    it("does not reject three distinct, unrelated names", () => {
      expect(() => validateMountTargets([{ name: "corb" }, { name: "reference" }, { name: "scratch" }])).not.toThrow();
    });
  });

  it("validateMountTargets([]) does not throw", () => {
    expect(() => validateMountTargets([])).not.toThrow();
  });
});
