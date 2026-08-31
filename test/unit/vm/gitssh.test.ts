// Unit tests for `src/vm/gitssh.ts`. Structured like
// `test/unit/vm/egress.test.ts`: one `describe` per exported function, no
// mocking of `@earendil-works/gondolin` needed here (unlike egress.test.ts's
// `createHttpHooks` mock) since `getInfoFromSshExecRequest` is a pure parser
// this module calls directly and is safe to exercise for real.
//
// M4.3 extends `buildGitSshOptions` with `(audit, sessionId)`. `fakeAudit()`
// below mirrors `test/unit/policy/github.test.ts`'s own fake-audit helper
// shape exactly (same three `vi.fn()` stubs), not a different pattern.
import { describe, expect, it, vi } from "vitest";
import type { SshExecDecision, SshExecRequest, SshOptions } from "@earendil-works/gondolin";
import { buildGitSshOptions, matchAnyGlob, normalizeRepo, RepoTraversalError } from "../../../src/vm/gitssh.ts";
import type { EffectiveGitConfig } from "../../../src/config/load.ts";
import type { AuditWriter } from "../../../src/policy/audit.ts";

function fakeAudit(): AuditWriter & { record: ReturnType<typeof vi.fn> } {
  return { record: vi.fn(), addRedactedSecrets: vi.fn(), flush: vi.fn() };
}

describe("vm/gitssh normalizeRepo", () => {
  it("lowercases a plain owner/repo string", () => {
    expect(normalizeRepo("Owner/Repo")).toBe("owner/repo");
  });

  it("strips a trailing .git", () => {
    expect(normalizeRepo("owner/repo.git")).toBe("owner/repo");
  });

  it("strips a single leading slash", () => {
    expect(normalizeRepo("/owner/repo")).toBe("owner/repo");
  });

  it("leaves a ~user/repo form as an ordinary lowercase path segment, tilde and all", () => {
    expect(normalizeRepo("~user/repo")).toBe("~user/repo");
  });

  it("combines leading slash, trailing .git and mixed case in one call", () => {
    expect(normalizeRepo("/Dario/Corb.git")).toBe("dario/corb");
  });

  it("throws RepoTraversalError for a repo string containing '..', failing closed", () => {
    expect(() => normalizeRepo("dario/../../etc")).toThrow(RepoTraversalError);
    expect(() => normalizeRepo("../secrets")).toThrow(/\.\./);
  });
});

describe("vm/gitssh matchAnyGlob", () => {
  it("denies everything when patterns is undefined", () => {
    expect(matchAnyGlob(undefined, "dario/corb")).toBe(false);
  });

  it("denies everything when patterns is an empty array", () => {
    expect(matchAnyGlob([], "dario/corb")).toBe(false);
  });

  it("matches a literal pattern exactly", () => {
    expect(matchAnyGlob(["dario/corb"], "dario/corb")).toBe(true);
  });

  it("matches a '*' glob within a path segment, per the design.md example config", () => {
    expect(matchAnyGlob(["dario/*-docs"], "dario/design-docs")).toBe(true);
  });

  it("does not match a near-miss that only differs outside the wildcard segment", () => {
    expect(matchAnyGlob(["dario/*-docs"], "other/design-docs")).toBe(false);
  });

  it("does not match when the glob segment doesn't cross a '/' boundary", () => {
    expect(matchAnyGlob(["dario/*-docs"], "dario/team/design-docs")).toBe(false);
  });

  it("matches case-insensitively against a differently-cased pattern", () => {
    expect(matchAnyGlob(["Dario/Corb"], "dario/corb")).toBe(true);
  });

  it("treats a literal '?' in a pattern as a literal character, not a regex quantifier", () => {
    // A pattern like "dario/repos?" means the literal string "dario/repos?"
    // — it must not be interpreted as "the 's' is optional" (which would
    // also match "dario/repo", a different, unintended repo).
    expect(matchAnyGlob(["dario/repos?"], "dario/repos?")).toBe(true);
    expect(matchAnyGlob(["dario/repos?"], "dario/repos")).toBe(false);
    expect(matchAnyGlob(["dario/repos?"], "dario/reposx")).toBe(false);
  });
});

function fakeGit(overrides: Partial<EffectiveGitConfig> = {}): EffectiveGitConfig {
  return {
    "ssh-agent": true,
    "allow-push": false,
    ...overrides,
  };
}

function fakeExecRequest(command: string): SshExecRequest {
  return {
    hostname: "github.com",
    port: 22,
    guestUsername: "git",
    command,
    src: { ip: "192.168.127.3", port: 54321 },
  };
}

function decisionFor(options: SshOptions, command: string): SshExecDecision {
  const execPolicy = options.execPolicy;
  if (!execPolicy) {
    throw new Error("execPolicy was not set on the built SshOptions");
  }
  const decision = execPolicy(fakeExecRequest(command));
  if (decision instanceof Promise) {
    throw new Error("execPolicy unexpectedly returned a Promise; tests here assume it is synchronous");
  }
  return decision;
}

describe("vm/gitssh buildGitSshOptions", () => {
  it("allow-hosts undefined produces allowedHosts: [], never undefined", () => {
    const options = buildGitSshOptions(fakeGit(), {}, fakeAudit(), "s");
    expect(options.allowedHosts).toEqual([]);
  });

  it("allow-hosts set is passed through unchanged", () => {
    const options = buildGitSshOptions(fakeGit({ "allow-hosts": ["github.com"] }), {}, fakeAudit(), "s");
    expect(options.allowedHosts).toEqual(["github.com"]);
  });

  it("ssh-agent true with SSH_AUTH_SOCK set in the injected env sets agent to that value", () => {
    const options = buildGitSshOptions(
      fakeGit({ "ssh-agent": true }),
      { SSH_AUTH_SOCK: "/tmp/agent.sock" },
      fakeAudit(),
      "s",
    );
    expect(options.agent).toBe("/tmp/agent.sock");
  });

  it("ssh-agent true with SSH_AUTH_SOCK unset in env leaves agent absent (no throw)", () => {
    const options = buildGitSshOptions(fakeGit({ "ssh-agent": true }), {}, fakeAudit(), "s");
    expect("agent" in options).toBe(false);
  });

  it("ssh-agent false leaves agent absent regardless of env", () => {
    const options = buildGitSshOptions(
      fakeGit({ "ssh-agent": false }),
      { SSH_AUTH_SOCK: "/tmp/agent.sock" },
      fakeAudit(),
      "s",
    );
    expect("agent" in options).toBe(false);
  });

  it("does not set knownHostsFile, deferring to the SDK's own broader default", () => {
    const options = buildGitSshOptions(fakeGit(), {}, fakeAudit(), "s");
    expect("knownHostsFile" in options).toBe(false);
  });

  describe("execPolicy", () => {
    const allowRepos = ["dario/corb"];

    it("denies a non-git ssh command", () => {
      const audit = fakeAudit();
      const options = buildGitSshOptions(fakeGit({ "allow-repos": allowRepos }), {}, audit, "s");
      const decision = decisionFor(options, "id");
      expect(decision.allow).toBe(false);
      expect((decision as { message?: string }).message).toMatch(/not a recognized git-over-ssh command/);
    });

    it("denies a recognized-but-unsupported git service", () => {
      const audit = fakeAudit();
      const options = buildGitSshOptions(fakeGit({ "allow-repos": allowRepos }), {}, audit, "s");
      const decision = decisionFor(options, "git-upload-archive 'dario/corb.git'");
      expect(decision.allow).toBe(false);
      expect((decision as { message?: string }).message).toMatch(/ssh service 'git-upload-archive' is not permitted/);
    });

    it("allows git-upload-pack (fetch/clone) for an allowlisted repo", () => {
      const audit = fakeAudit();
      const options = buildGitSshOptions(fakeGit({ "allow-repos": allowRepos }), {}, audit, "s");
      const decision = decisionFor(options, "git-upload-pack 'dario/corb.git'");
      expect(decision.allow).toBe(true);
    });

    it("denies git-upload-pack for a repo outside the allowlist", () => {
      const audit = fakeAudit();
      const options = buildGitSshOptions(fakeGit({ "allow-repos": allowRepos }), {}, audit, "s");
      const decision = decisionFor(options, "git-upload-pack 'someone-else/other.git'");
      expect(decision.allow).toBe(false);
      expect((decision as { message?: string }).message).toMatch(/not in git\.allow-repos/);
    });

    it("denies git-receive-pack (push) for an allowlisted repo when allow-push is false", () => {
      const audit = fakeAudit();
      const options = buildGitSshOptions(fakeGit({ "allow-repos": allowRepos, "allow-push": false }), {}, audit, "s");
      const decision = decisionFor(options, "git-receive-pack 'dario/corb.git'");
      expect(decision.allow).toBe(false);
      expect((decision as { message?: string }).message).toMatch(/push is disabled/);
    });

    it("allows git-receive-pack (push) for an allowlisted repo when allow-push is true", () => {
      const audit = fakeAudit();
      const options = buildGitSshOptions(fakeGit({ "allow-repos": allowRepos, "allow-push": true }), {}, audit, "s");
      const decision = decisionFor(options, "git-receive-pack 'dario/corb.git'");
      expect(decision.allow).toBe(true);
    });

    it("denies every service, including push, when allow-repos is undefined at all", () => {
      const audit = fakeAudit();
      const options = buildGitSshOptions(fakeGit({ "allow-push": true }), {}, audit, "s");
      const fetchDecision = decisionFor(options, "git-upload-pack 'dario/corb.git'");
      const pushDecision = decisionFor(options, "git-receive-pack 'dario/corb.git'");
      expect(fetchDecision.allow).toBe(false);
      expect(pushDecision.allow).toBe(false);
    });
  });

  describe("execPolicy audit wiring", () => {
    const allowRepos = ["dario/corb"];

    it("records one channel: ssh, decision: allow event with the expected subject shape", () => {
      const audit = fakeAudit();
      const options = buildGitSshOptions(fakeGit({ "allow-repos": allowRepos }), {}, audit, "session-1");
      decisionFor(options, "git-upload-pack 'dario/corb.git'");

      expect(audit.record).toHaveBeenCalledTimes(1);
      expect(audit.record).toHaveBeenCalledWith({
        channel: "ssh",
        decision: "allow",
        subject: "git-upload-pack dario/corb",
        sessionId: "session-1",
      });
    });

    it("not-a-git-command: records a deny event with the generic unparseable subject and the guest-facing message as reason", () => {
      const audit = fakeAudit();
      const options = buildGitSshOptions(fakeGit({ "allow-repos": allowRepos }), {}, audit, "session-2");
      decisionFor(options, "id");

      expect(audit.record).toHaveBeenCalledTimes(1);
      expect(audit.record).toHaveBeenCalledWith({
        channel: "ssh",
        decision: "deny",
        subject: "unparseable ssh command",
        reason: expect.stringMatching(/not a recognized git-over-ssh command/),
        sessionId: "session-2",
      });
    });

    it("unsupported-service: records a deny event with the parsed subject and matching reason", () => {
      const audit = fakeAudit();
      const options = buildGitSshOptions(fakeGit({ "allow-repos": allowRepos }), {}, audit, "session-3");
      decisionFor(options, "git-upload-archive 'dario/corb.git'");

      expect(audit.record).toHaveBeenCalledWith({
        channel: "ssh",
        decision: "deny",
        subject: "git-upload-archive dario/corb",
        reason: expect.stringMatching(/ssh service 'git-upload-archive' is not permitted/),
        sessionId: "session-3",
      });
    });

    it("not-in-allowlist: records a deny event with the parsed subject and matching reason", () => {
      const audit = fakeAudit();
      const options = buildGitSshOptions(fakeGit({ "allow-repos": allowRepos }), {}, audit, "session-4");
      decisionFor(options, "git-upload-pack 'someone-else/other.git'");

      expect(audit.record).toHaveBeenCalledWith({
        channel: "ssh",
        decision: "deny",
        subject: "git-upload-pack someone-else/other",
        reason: expect.stringMatching(/not in git\.allow-repos/),
        sessionId: "session-4",
      });
    });

    it("push-disabled: records a deny event with the parsed subject and matching reason", () => {
      const audit = fakeAudit();
      const options = buildGitSshOptions(
        fakeGit({ "allow-repos": allowRepos, "allow-push": false }),
        {},
        audit,
        "session-5",
      );
      decisionFor(options, "git-receive-pack 'dario/corb.git'");

      expect(audit.record).toHaveBeenCalledWith({
        channel: "ssh",
        decision: "deny",
        subject: "git-receive-pack dario/corb",
        reason: expect.stringMatching(/push is disabled/),
        sessionId: "session-5",
      });
    });

    it("the unparseable-command audit subject never contains the raw command string fed in", () => {
      const audit = fakeAudit();
      const options = buildGitSshOptions(fakeGit({ "allow-repos": allowRepos }), {}, audit, "session-6");
      const rawCommand = "totally-bogus-command --with-a-flag=SECRETVALUE";
      decisionFor(options, rawCommand);

      expect(audit.record).toHaveBeenCalledTimes(1);
      const recordedEvent = audit.record.mock.calls[0]?.[0] as { subject: string; reason?: string };
      expect(recordedEvent.subject).not.toContain(rawCommand);
      expect(recordedEvent.subject).not.toContain("SECRETVALUE");
      expect(recordedEvent.subject).toBe("unparseable ssh command");
    });

    it("a pass-through allow is not double-recorded — exactly one event for one execPolicy call", () => {
      const audit = fakeAudit();
      const options = buildGitSshOptions(fakeGit({ "allow-repos": allowRepos, "allow-push": true }), {}, audit, "s");
      decisionFor(options, "git-receive-pack 'dario/corb.git'");
      expect(audit.record).toHaveBeenCalledTimes(1);
      expect(audit.record).toHaveBeenCalledWith(
        expect.objectContaining({ channel: "ssh", decision: "allow" }),
      );
    });
  });
});
