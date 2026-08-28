// Unit tests for `src/policy/checks.ts` — M7.2. Table-driven per function:
// `scanForSecrets` against real AKIA/ASIA-shaped, PEM, and GitHub-token
// strings plus non-shaped strings; `checkChangedFileCeiling`'s boundary
// cases; `checkDuplicatedPathRules` against a small fake `DirConfig[]`; and
// `runChecks`'s composition, including the `secret-scan` toggle.
import { describe, expect, it } from "vitest";
import type { DirConfig, EffectivePolicyConfig } from "../../../src/config/load.ts";
import {
  checkChangedFileCeiling,
  checkDuplicatedPathRules,
  runChecks,
  scanForSecrets,
  type PolicyCheckRequest,
} from "../../../src/policy/checks.ts";

function fakePolicy(overrides: Partial<EffectivePolicyConfig> = {}): EffectivePolicyConfig {
  return {
    enabled: true,
    "secret-scan": true,
    "fail-open": true,
    ...overrides,
  };
}

describe("policy/checks scanForSecrets", () => {
  it("catches an AWS access key ID shape (AKIA + 16 uppercase-alnum)", () => {
    const violations = scanForSecrets("aws_key = AKIAABCDEFGHIJKLMNOP");
    expect(violations).toHaveLength(1);
    expect(violations[0]).toMatchObject({ rule: "secret-in-diff" });
    expect(violations[0]?.message).toContain("AWS access key ID");
  });

  it("catches the ASIA (temporary/STS) variant too", () => {
    const violations = scanForSecrets("aws_key = ASIAABCDEFGHIJKLMNOP");
    expect(violations).toHaveLength(1);
    expect(violations[0]?.message).toContain("AWS access key ID");
  });

  it("does not match an AKIA-prefixed string of the wrong length", () => {
    expect(scanForSecrets("AKIASHORT")).toHaveLength(0);
    expect(scanForSecrets("AKIAABCDEFGHIJKLMNOPEXTRA")).toHaveLength(0);
  });

  it("catches a PEM private-key header", () => {
    const violations = scanForSecrets("-----BEGIN RSA PRIVATE KEY-----\nMIIB...\n-----END RSA PRIVATE KEY-----");
    expect(violations).toHaveLength(1);
    expect(violations[0]?.message).toContain("PEM private key");
  });

  it("catches an unqualified PEM private-key header too", () => {
    const violations = scanForSecrets("-----BEGIN PRIVATE KEY-----\nMIIB...\n-----END PRIVATE KEY-----");
    expect(violations).toHaveLength(1);
  });

  it("catches a GitHub personal access token prefix", () => {
    const violations = scanForSecrets("token: ghp_abcdefghijklmnopqrstuvwxyzABCDEFGH");
    expect(violations).toHaveLength(1);
    expect(violations[0]?.message).toContain("GitHub token");
  });

  it("catches a github_pat_ fine-grained token prefix", () => {
    const violations = scanForSecrets("token: github_pat_abcdefghijklmnopqrstuvwxyzABCDEFGH");
    expect(violations).toHaveLength(1);
  });

  it("does not match a short ghp_-prefixed identifier (below the length floor)", () => {
    expect(scanForSecrets("ghp_test")).toHaveLength(0);
  });

  it("plain, non-secret-shaped diff text produces no violations", () => {
    expect(scanForSecrets("+function add(a, b) {\n+  return a + b;\n+}\n")).toHaveLength(0);
  });

  it("never echoes the matched substring into the violation message", () => {
    const secret = "AKIAABCDEFGHIJKLMNOP";
    const violations = scanForSecrets(`key = ${secret}`);
    expect(violations[0]?.message).not.toContain(secret);
  });

  it("reports one violation per distinct match, including multiple kinds in one diff", () => {
    const diff = ["AKIAABCDEFGHIJKLMNOP", "ASIAABCDEFGHIJKLMNOP", "ghp_abcdefghijklmnopqrstuvwxyzABCDEFGH"].join(
      "\n",
    );
    const violations = scanForSecrets(diff);
    expect(violations).toHaveLength(3);
    expect(violations.every((v) => v.rule === "secret-in-diff")).toBe(true);
  });
});

describe("policy/checks checkChangedFileCeiling", () => {
  it("ceiling undefined never denies, regardless of count", () => {
    expect(checkChangedFileCeiling(["a", "b", "c"], undefined)).toBeUndefined();
    expect(checkChangedFileCeiling([], undefined)).toBeUndefined();
  });

  it("count exactly at the ceiling does not deny", () => {
    expect(checkChangedFileCeiling(["a", "b", "c"], 3)).toBeUndefined();
  });

  it("count one over the ceiling denies, naming the count and the ceiling", () => {
    const violation = checkChangedFileCeiling(["a", "b", "c", "d"], 3);
    expect(violation).toMatchObject({ rule: "max-changed-files" });
    expect(violation?.message).toContain("4");
    expect(violation?.message).toContain("3");
  });

  it("zero changed files never denies", () => {
    expect(checkChangedFileCeiling([], 0)).toBeUndefined();
  });
});

describe("policy/checks checkDuplicatedPathRules", () => {
  function dir(name: string, rules: DirConfig["rules"]): DirConfig {
    return { name, rules };
  }

  it("flags a changed file matching a hidden rule in some configured directory", () => {
    const dirs = [dir("repo", [{ glob: "**/.env", mode: "hidden", reason: "local secrets file" }])];
    const violations = checkDuplicatedPathRules([".env", "src/index.ts"], dirs);
    expect(violations).toHaveLength(1);
    expect(violations[0]).toMatchObject({ rule: "path-rule-duplicate", file: ".env" });
    expect(violations[0]?.message).toContain(".env");
    expect(violations[0]?.message).toContain("local secrets file");
  });

  it("flags a changed file matching a deny-write rule", () => {
    const dirs = [dir("repo", [{ glob: "**/*_test.go", mode: "deny-write", reason: "tests are not editable" }])];
    const violations = checkDuplicatedPathRules(["internal/foo_test.go"], dirs);
    expect(violations).toHaveLength(1);
    expect(violations[0]?.file).toBe("internal/foo_test.go");
  });

  it("does not flag a rule mode outside hidden/deny-write (deny-read, shadow-write)", () => {
    const dirs = [
      dir("repo", [
        { glob: "**/*.secret", mode: "deny-read", reason: "sensitive" },
        { glob: "**/*.cache", mode: "shadow-write", reason: "ephemeral" },
      ]),
    ];
    expect(checkDuplicatedPathRules(["a.secret", "a.cache"], dirs)).toHaveLength(0);
  });

  it("checks the union of rules across every configured directory, not just one", () => {
    const dirs = [
      dir("repo-a", [{ glob: "**/.env", mode: "hidden", reason: "local secrets file" }]),
      dir("repo-b", [{ glob: "go.sum", mode: "deny-write", reason: "lockfile" }]),
    ];
    const violations = checkDuplicatedPathRules([".env", "go.sum", "README.md"], dirs);
    expect(violations).toHaveLength(2);
    const files = violations.map((v) => v.file).sort();
    expect(files).toEqual(["go.sum", ".env"].sort());
  });

  it("a file matching no configured rule produces no violation", () => {
    const dirs = [dir("repo", [{ glob: "**/.env", mode: "hidden", reason: "local secrets file" }])];
    expect(checkDuplicatedPathRules(["src/index.ts"], dirs)).toHaveLength(0);
  });

  it("a rule with no reason still produces a violation, without a dangling separator in the message", () => {
    const dirs = [dir("repo", [{ glob: "**/.env", mode: "hidden" }])];
    const violations = checkDuplicatedPathRules([".env"], dirs);
    expect(violations).toHaveLength(1);
    expect(violations[0]?.message).not.toContain("undefined");
  });

  it("empty dirs list never flags anything", () => {
    expect(checkDuplicatedPathRules([".env", "go.sum"], [])).toHaveLength(0);
  });

  it("reports at most one violation per file even if multiple rules match it", () => {
    const dirs = [
      dir("repo", [
        { glob: "**/secrets/**", mode: "hidden", reason: "secrets directory" },
        { glob: "**/*.env", mode: "deny-write", reason: "also matches" },
      ]),
    ];
    const violations = checkDuplicatedPathRules(["secrets/a.env"], dirs);
    expect(violations).toHaveLength(1);
  });
});

describe("policy/checks runChecks", () => {
  function baseRequest(overrides: Partial<PolicyCheckRequest> = {}): PolicyCheckRequest {
    return { op: "git.commit", changedFiles: [], diff: "", ...overrides };
  }

  it("a clean request with no config restrictions produces no violations", () => {
    const violations = runChecks(baseRequest({ diff: "+ordinary diff content" }), fakePolicy(), []);
    expect(violations).toHaveLength(0);
  });

  it("secret-scan=true runs scanForSecrets and surfaces its violation", () => {
    const violations = runChecks(
      baseRequest({ diff: "AKIAABCDEFGHIJKLMNOP" }),
      fakePolicy({ "secret-scan": true }),
      [],
    );
    expect(violations.some((v) => v.rule === "secret-in-diff")).toBe(true);
  });

  it("secret-scan=false skips scanForSecrets entirely, even for an obvious secret-shaped diff", () => {
    const violations = runChecks(
      baseRequest({ diff: "AKIAABCDEFGHIJKLMNOP" }),
      fakePolicy({ "secret-scan": false }),
      [],
    );
    expect(violations.some((v) => v.rule === "secret-in-diff")).toBe(false);
  });

  it("max-changed-files runs regardless of secret-scan, and is not gated by any toggle", () => {
    const violations = runChecks(
      baseRequest({ changedFiles: ["a", "b", "c"] }),
      fakePolicy({ "secret-scan": false, "max-changed-files": 2 }),
      [],
    );
    expect(violations.some((v) => v.rule === "max-changed-files")).toBe(true);
  });

  it("checkDuplicatedPathRules runs regardless of secret-scan", () => {
    const dirs: DirConfig[] = [{ name: "repo", rules: [{ glob: "**/.env", mode: "hidden", reason: "secrets" }] }];
    const violations = runChecks(
      baseRequest({ changedFiles: [".env"] }),
      fakePolicy({ "secret-scan": false }),
      dirs,
    );
    expect(violations.some((v) => v.rule === "path-rule-duplicate")).toBe(true);
  });

  it("concatenates violations from every check that fires", () => {
    const dirs: DirConfig[] = [{ name: "repo", rules: [{ glob: "**/.env", mode: "hidden", reason: "secrets" }] }];
    const violations = runChecks(
      baseRequest({
        changedFiles: [".env", "a", "b"],
        diff: "AKIAABCDEFGHIJKLMNOP",
      }),
      fakePolicy({ "secret-scan": true, "max-changed-files": 1 }),
      dirs,
    );
    const rules = violations.map((v) => v.rule).sort();
    expect(rules).toEqual(["max-changed-files", "path-rule-duplicate", "secret-in-diff"].sort());
  });
});
