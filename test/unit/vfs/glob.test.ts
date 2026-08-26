// Unit tests for `src/vfs/glob.ts` — M5.1. Table-driven for `globToRegExp`,
// per the top-level plan's §8 verification list ("`globToRegExp`
// table-driven"), plus dedicated tests for `normalizeGuestPath`'s three
// documented behaviors (alias-prefix stripping, `//`-collapsing, `..`
// rejection).
import { describe, expect, it } from "vitest";
import { DEFAULT_FUSE_MOUNT, globToRegExp, GuestPathTraversalError, normalizeGuestPath } from "../../../src/vfs/glob.ts";

describe("vfs/glob globToRegExp", () => {
  // Every real pattern from `docs/design.md` §3's example rule list and the
  // top-level plan's `corb.toml` spec, each with a path that should match
  // and a close near-miss that shouldn't.
  const table: Array<{ pattern: string; match: string[]; noMatch: string[] }> = [
    {
      pattern: "**/.env",
      match: [".env", "foo/.env", "a/b/.env"],
      noMatch: [".env.local", "foo/.env.local", "envfile", "foo/.environment"],
    },
    {
      pattern: "**/.env.*",
      match: [".env.local", "foo/.env.local", "a/b/.env.production"],
      noMatch: [".env", "foo/.env", ".environment"],
    },
    {
      pattern: "**/secrets/**",
      match: ["secrets", "secrets/key.pem", "a/secrets/b/c", "x/y/secrets"],
      noMatch: ["secretsxyz", "a/secretsxyz/b", "xsecrets/y"],
    },
    {
      pattern: "**/*_test.go",
      match: ["foo_test.go", "pkg/foo_test.go", "a/b/foo_test.go"],
      noMatch: ["footest.go", "foo_test.go.bak", "pkg/foo_test.go/nested"],
    },
    {
      pattern: "go.sum",
      match: ["go.sum"],
      noMatch: ["goXsum", "vendor/go.sum", "go.sum.bak", "go_sum"],
    },
    {
      pattern: ".git/hooks/**",
      match: [".git/hooks", ".git/hooks/pre-commit", ".git/hooks/sub/dir"],
      noMatch: [".git/hooksfoo", "sub/.git/hooks/pre-commit", ".githooks/pre-commit"],
    },
    {
      pattern: ".git/config",
      match: [".git/config"],
      noMatch: [".git/config.bak", "sub/.git/config", ".git/configx"],
    },
  ];

  for (const { pattern, match, noMatch } of table) {
    describe(`pattern ${JSON.stringify(pattern)}`, () => {
      for (const candidate of match) {
        it(`matches ${JSON.stringify(candidate)}`, () => {
          expect(globToRegExp(pattern).test(candidate)).toBe(true);
        });
      }
      for (const candidate of noMatch) {
        it(`does not match ${JSON.stringify(candidate)}`, () => {
          expect(globToRegExp(pattern).test(candidate)).toBe(false);
        });
      }
    });
  }

  describe("** segment counts", () => {
    it("a leading **/ matches zero segments (bare filename at the root)", () => {
      expect(globToRegExp("**/x").test("x")).toBe(true);
    });

    it("a leading **/ matches exactly one segment", () => {
      expect(globToRegExp("**/x").test("a/x")).toBe(true);
    });

    it("a leading **/ matches several segments", () => {
      expect(globToRegExp("**/x").test("a/b/c/x")).toBe(true);
    });

    it("a trailing /** matches zero segments (bare directory itself)", () => {
      expect(globToRegExp("x/**").test("x")).toBe(true);
    });

    it("a trailing /** matches exactly one segment", () => {
      expect(globToRegExp("x/**").test("x/a")).toBe(true);
    });

    it("a trailing /** matches several segments", () => {
      expect(globToRegExp("x/**").test("x/a/b/c")).toBe(true);
    });

    it("a middle /**/ matches zero segments", () => {
      expect(globToRegExp("a/**/b").test("a/b")).toBe(true);
    });

    it("a middle /**/ matches exactly one segment", () => {
      expect(globToRegExp("a/**/b").test("a/x/b")).toBe(true);
    });

    it("a middle /**/ matches several segments", () => {
      expect(globToRegExp("a/**/b").test("a/x/y/b")).toBe(true);
    });

    it("a middle /**/ does not let the final literal match mid-segment", () => {
      // Regression case for the naive "no anchoring slash" construction:
      // without `**`'s own fragment owning the separating `/`, `a/**/b`
      // could wrongly match `a/xb` by treating the trailing `b` of the
      // `xb` segment as the pattern's final literal `b`.
      expect(globToRegExp("a/**/b").test("a/xb")).toBe(false);
    });

    it("a bare ** matches everything, including nested paths", () => {
      const re = globToRegExp("**");
      expect(re.test("")).toBe(true);
      expect(re.test("x")).toBe(true);
      expect(re.test("a/b/c")).toBe(true);
    });
  });

  describe("* never crosses a / boundary", () => {
    it("* matches within a single segment", () => {
      expect(globToRegExp("*.env").test("foo.env")).toBe(true);
    });

    it("* does not match across a /", () => {
      expect(globToRegExp("*.env").test("a/foo.env")).toBe(false);
    });

    it("multiple * in one segment each stay within that segment", () => {
      const re = globToRegExp("*_test.*");
      expect(re.test("foo_test.go")).toBe(true);
      expect(re.test("a/foo_test.go")).toBe(false);
    });
  });

  describe("regex-special literal characters are escaped, not interpreted", () => {
    it("a literal . does not act as a wildcard", () => {
      expect(globToRegExp("go.sum").test("goXsum")).toBe(false);
    });

    it("literal + ? ( ) are matched literally", () => {
      const pattern = "a+b?(c).txt";
      expect(globToRegExp(pattern).test("a+b?(c).txt")).toBe(true);
      expect(globToRegExp(pattern).test("aabc.txt")).toBe(false);
    });

    it("literal [ ] { } and backslash are matched literally", () => {
      const pattern = "a[1]{2}\\b";
      expect(globToRegExp(pattern).test("a[1]{2}\\b")).toBe(true);
    });
  });
});

describe("vfs/glob normalizeGuestPath", () => {
  it("strips the default /data fuseMount alias prefix", () => {
    expect(normalizeGuestPath("/data/work/repo/.env")).toBe("/work/repo/.env");
  });

  it("normalizes the fuseMount root itself to the bare root path", () => {
    expect(normalizeGuestPath(DEFAULT_FUSE_MOUNT)).toBe("/");
  });

  it("leaves an already-canonical /work/... path untouched", () => {
    expect(normalizeGuestPath("/work/repo/.env")).toBe("/work/repo/.env");
  });

  it("does not strip a path that merely starts with the same characters as fuseMount", () => {
    expect(normalizeGuestPath("/database/foo")).toBe("/database/foo");
  });

  it("collapses the readdir `${path}/${name}` // join bug", () => {
    expect(normalizeGuestPath("//foo")).toBe("/foo");
    expect(normalizeGuestPath("/work///repo//.env")).toBe("/work/repo/.env");
  });

  it("adds a leading / to a path that lacks one", () => {
    expect(normalizeGuestPath("work/repo/.env")).toBe("/work/repo/.env");
  });

  it("strips a trailing / except for the bare root", () => {
    expect(normalizeGuestPath("/work/repo/")).toBe("/work/repo");
    expect(normalizeGuestPath("/")).toBe("/");
  });

  it("combines alias-stripping and // collapsing in one call", () => {
    expect(normalizeGuestPath("/data//work/repo//.env")).toBe("/work/repo/.env");
  });

  it("respects a custom fuseMount argument instead of the default", () => {
    expect(normalizeGuestPath("/custom/work/repo/.env", "/custom")).toBe("/work/repo/.env");
  });

  it("rejects a path containing a .. segment", () => {
    expect(() => normalizeGuestPath("/work/repo/../../../../etc")).toThrow(GuestPathTraversalError);
  });

  it("rejects a .. segment anywhere in the path, not just at the start", () => {
    expect(() => normalizeGuestPath("/work/repo/foo/../bar")).toThrow(GuestPathTraversalError);
  });

  it("does not reject a filename that merely contains .. as a substring within one segment", () => {
    expect(normalizeGuestPath("/work/repo/..bashrc.bak")).toBe("/work/repo/..bashrc.bak");
  });

  it("the .. rejection error message names the offending raw path", () => {
    expect(() => normalizeGuestPath("/a/../b")).toThrow(/a\/\.\.\/b/);
  });
});
