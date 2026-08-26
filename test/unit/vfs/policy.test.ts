// Unit tests for `src/vfs/policy.ts` — M5.2. Table-driven for `decideFsAccess`,
// covering the complete four-mode ("no rule" plus all of `RULE_MODES`) ×
// every-`FsOpKind` matrix per the top-level plan's §8 requirement ("the full
// mode × access matrix from §6.2"), one explicit assertion per cell — not
// spot checks, matching `test/unit/vfs/glob.test.ts`'s own table-driven
// style. Plus dedicated tests for `matchRule`, `decideFsAccessForPath`,
// `isEntryHidden`, and `ruleMayMatchUnderDirectory`.
import { describe, expect, it } from "vitest";
import type { RuleMode } from "../../../src/config/schema.ts";
import { RULE_MODES } from "../../../src/config/schema.ts";
import {
  decideFsAccess,
  decideFsAccessForPath,
  type FsAccessOutcome,
  type FsOpKind,
  type GlobRule,
  isEntryHidden,
  matchRule,
  ruleMayMatchUnderDirectory,
} from "../../../src/vfs/policy.ts";

const ALLOW: FsAccessOutcome = { kind: "allow" };
const SHADOWED: FsAccessOutcome = { kind: "shadowed" };
const ENOENT: FsAccessOutcome = { kind: "deny", errno: "ENOENT" };
const EACCES: FsAccessOutcome = { kind: "deny", errno: "EACCES" };

/**
 * The full mode × op matrix, transcribed independently from `docs/design.md`
 * §3's matrix (as amended by this item) and the top-level plan's §6.2 table
 * — not copy-pasted from `src/vfs/policy.ts`'s own `TABLE` object, so this
 * test actually catches a transcription error in either place rather than
 * validating the implementation against itself. Columns: no rule (always
 * `allow`, tested separately below since it's `mode: undefined`, not a
 * `RuleMode`), `deny-write`, `deny-read`, `hidden`, `shadow-write`.
 */
const MATRIX: Record<FsOpKind, Record<RuleMode, FsAccessOutcome>> = {
  read: { "deny-write": ALLOW, "deny-read": EACCES, hidden: ENOENT, "shadow-write": ALLOW },
  write: { "deny-write": EACCES, "deny-read": EACCES, hidden: ENOENT, "shadow-write": SHADOWED },
  stat: { "deny-write": ALLOW, "deny-read": ALLOW, hidden: ENOENT, "shadow-write": ALLOW },
  mutate: { "deny-write": EACCES, "deny-read": EACCES, hidden: ENOENT, "shadow-write": SHADOWED },
  rename: { "deny-write": EACCES, "deny-read": EACCES, hidden: ENOENT, "shadow-write": SHADOWED },
  "copy-source": { "deny-write": ALLOW, "deny-read": EACCES, hidden: ENOENT, "shadow-write": ALLOW },
  "copy-dest": { "deny-write": EACCES, "deny-read": EACCES, hidden: ENOENT, "shadow-write": SHADOWED },
  link: { "deny-write": EACCES, "deny-read": EACCES, hidden: ENOENT, "shadow-write": SHADOWED },
  "access-exists": { "deny-write": ALLOW, "deny-read": ALLOW, hidden: ENOENT, "shadow-write": ALLOW },
  "access-read": { "deny-write": ALLOW, "deny-read": EACCES, hidden: ENOENT, "shadow-write": ALLOW },
  "access-write": { "deny-write": EACCES, "deny-read": EACCES, hidden: ENOENT, "shadow-write": ALLOW },
  readlink: { "deny-write": ALLOW, "deny-read": EACCES, hidden: ENOENT, "shadow-write": ALLOW },
  exists: { "deny-write": ALLOW, "deny-read": ALLOW, hidden: ENOENT, "shadow-write": ALLOW },
  realpath: { "deny-write": ALLOW, "deny-read": ALLOW, hidden: ENOENT, "shadow-write": ALLOW },
};

const OP_KINDS = Object.keys(MATRIX) as FsOpKind[];

describe("vfs/policy decideFsAccess", () => {
  describe("no rule (mode: undefined) always allows, for every operation", () => {
    for (const op of OP_KINDS) {
      it(`${op}: allow`, () => {
        expect(decideFsAccess(undefined, op)).toEqual(ALLOW);
      });
    }
  });

  for (const op of OP_KINDS) {
    describe(`operation ${JSON.stringify(op)}`, () => {
      for (const mode of RULE_MODES) {
        const expected = MATRIX[op][mode];
        it(`${mode}: ${JSON.stringify(expected)}`, () => {
          expect(decideFsAccess(mode, op)).toEqual(expected);
        });
      }
    });
  }

  it("deny-read implies deny-write: every write-shaped category denies under deny-read, never a lesser restriction than deny-write", () => {
    // `docs/design.md` §3: "There is no mode that denies reads while
    // permitting writes." Checked structurally here: for every op whose
    // `deny-write` outcome is a denial, `deny-read`'s outcome must also be a
    // denial (never `allow`).
    for (const op of OP_KINDS) {
      const denyWriteOutcome = MATRIX[op]["deny-write"];
      if (denyWriteOutcome.kind === "deny" || denyWriteOutcome.kind === "shadowed") {
        const denyReadOutcome = MATRIX[op]["deny-read"];
        expect(denyReadOutcome.kind).not.toBe("allow");
      }
    }
  });

  it("hidden reports ENOENT for every operation, never EACCES", () => {
    // `docs/design.md` §3: "`hidden` reports `ENOENT` rather than `EACCES`
    // everywhere... so the path does not merely fail to open — it does not
    // appear to exist."
    for (const op of OP_KINDS) {
      expect(MATRIX[op].hidden).toEqual(ENOENT);
    }
  });

  it("shadow-write never denies outright: no cell in its column is a deny", () => {
    // `shadow-write`'s whole point is that the guest is never told no.
    for (const op of OP_KINDS) {
      expect(MATRIX[op]["shadow-write"].kind).not.toBe("deny");
    }
  });
});

describe("vfs/policy matchRule", () => {
  const rules: GlobRule[] = [
    { glob: "**/.env", mode: "hidden", reason: "local secrets file" },
    { glob: "**/*_test.go", mode: "deny-write", reason: "tests are frozen" },
    { glob: "go.sum", mode: "deny-write", reason: "lockfile" },
  ];

  it("returns the first matching rule", () => {
    expect(matchRule(rules, ".env")).toBe(rules[0]);
    expect(matchRule(rules, "pkg/foo_test.go")).toBe(rules[1]);
    expect(matchRule(rules, "go.sum")).toBe(rules[2]);
  });

  it("returns undefined when no rule matches", () => {
    expect(matchRule(rules, "main.go")).toBeUndefined();
  });

  it("first-match-wins: an earlier rule shadows a later one that would also match", () => {
    const overlapping: GlobRule[] = [
      { glob: "**/secrets/**", mode: "hidden", reason: "first" },
      { glob: "**/secrets/key.pem", mode: "deny-write", reason: "second, never reached" },
    ];
    expect(matchRule(overlapping, "a/secrets/key.pem")?.reason).toBe("first");
  });

  it("returns undefined for an empty rule list", () => {
    expect(matchRule([], "anything")).toBeUndefined();
  });
});

describe("vfs/policy decideFsAccessForPath", () => {
  const rules: GlobRule[] = [{ glob: "**/.env", mode: "hidden", reason: "local secrets file" }];

  it("combines matchRule and decideFsAccess, and surfaces the matched rule", () => {
    const result = decideFsAccessForPath(rules, ".env", "read");
    expect(result.outcome).toEqual(ENOENT);
    expect(result.rule).toBe(rules[0]);
  });

  it("allows and reports no matched rule when nothing matches", () => {
    const result = decideFsAccessForPath(rules, "main.go", "write");
    expect(result.outcome).toEqual(ALLOW);
    expect(result.rule).toBeUndefined();
  });
});

describe("vfs/policy isEntryHidden", () => {
  const rules: GlobRule[] = [
    { glob: "**/.env", mode: "hidden", reason: "local secrets file" },
    { glob: "**/*_test.go", mode: "deny-write", reason: "tests are frozen" },
    { glob: ".git/hooks/**", mode: "shadow-write", reason: "keep hooks inert" },
  ];

  it("hides an entry matched by a hidden-mode rule", () => {
    expect(isEntryHidden(rules, ".env")).toBe(true);
    expect(isEntryHidden(rules, "sub/.env")).toBe(true);
  });

  it("does not hide an entry matched by a non-hidden-mode rule", () => {
    expect(isEntryHidden(rules, "pkg/foo_test.go")).toBe(false);
    expect(isEntryHidden(rules, ".git/hooks/pre-commit")).toBe(false);
  });

  it("does not hide an entry matched by no rule at all", () => {
    expect(isEntryHidden(rules, "main.go")).toBe(false);
  });

  it("never hides anything for an empty rule list", () => {
    expect(isEntryHidden([], ".env")).toBe(false);
  });
});

describe("vfs/policy ruleMayMatchUnderDirectory", () => {
  it("denies renaming a directory when a rule could match something directly inside it", () => {
    const rules: GlobRule[] = [{ glob: "secrets/key.pem", mode: "hidden", reason: "secret file" }];
    expect(ruleMayMatchUnderDirectory(rules, "secrets")).toBe(true);
  });

  it("denies renaming a directory when a rule could match something nested arbitrarily deep inside it", () => {
    const rules: GlobRule[] = [{ glob: "**/secrets/**", mode: "hidden", reason: "secrets anywhere" }];
    expect(ruleMayMatchUnderDirectory(rules, "a/b")).toBe(true);
  });

  it("denies renaming the directory itself when a rule matches it exactly with a trailing **", () => {
    const rules: GlobRule[] = [{ glob: "secrets/**", mode: "hidden", reason: "secrets dir" }];
    expect(ruleMayMatchUnderDirectory(rules, "secrets")).toBe(true);
  });

  it("does not deny when a fixed-length pattern names an unrelated top-level entry", () => {
    const rules: GlobRule[] = [{ glob: "go.sum", mode: "deny-write", reason: "lockfile" }];
    expect(ruleMayMatchUnderDirectory(rules, "vendor")).toBe(false);
  });

  it("does not deny a fixed-length pattern against a directory nested below a same-named segment", () => {
    // `secrets` (no **) matches only the exact top-level entry `secrets`,
    // never anything nested inside a directory literally named `secrets`.
    const rules: GlobRule[] = [{ glob: "secrets", mode: "hidden", reason: "exact literal only" }];
    expect(ruleMayMatchUnderDirectory(rules, "secrets/sub")).toBe(false);
  });

  it("does not deny when the pattern names a sibling, not an ancestor or descendant", () => {
    const rules: GlobRule[] = [{ glob: "a/**/b", mode: "deny-write", reason: "middle wildcard" }];
    expect(ruleMayMatchUnderDirectory(rules, "x")).toBe(false);
  });

  it("denies when a middle-** pattern could reach into the renamed directory", () => {
    const rules: GlobRule[] = [{ glob: "a/**/b", mode: "deny-write", reason: "middle wildcard" }];
    expect(ruleMayMatchUnderDirectory(rules, "a")).toBe(true);
  });

  it("never denies for an empty rule list", () => {
    expect(ruleMayMatchUnderDirectory([], "secrets")).toBe(false);
  });

  it("is conservative for a rename of the mount root itself (empty directory path)", () => {
    const rules: GlobRule[] = [{ glob: "**/*_test.go", mode: "deny-write", reason: "tests" }];
    expect(ruleMayMatchUnderDirectory(rules, "")).toBe(true);
  });

  it("respects * within a single segment when consuming the directory path", () => {
    const rules: GlobRule[] = [{ glob: "*.secret/inner", mode: "hidden", reason: "star segment" }];
    expect(ruleMayMatchUnderDirectory(rules, "a.secret")).toBe(true);
    expect(ruleMayMatchUnderDirectory(rules, "asecret")).toBe(false);
  });
});
