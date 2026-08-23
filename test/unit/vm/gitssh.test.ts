// Unit tests for `src/vm/gitssh.ts`. Structured like
// `test/unit/vm/egress.test.ts`: one `describe` per exported function, no
// mocking of `@earendil-works/gondolin` needed here (unlike egress.test.ts's
// `createHttpHooks` mock) since `getInfoFromSshExecRequest` is a pure parser
// this module calls directly and is safe to exercise for real.
import { describe, expect, it } from "vitest";
import type { SshExecDecision, SshExecRequest, SshOptions } from "@earendil-works/gondolin";
import { buildGitSshOptions, matchAnyGlob, normalizeRepo, RepoTraversalError } from "../../../src/vm/gitssh.ts";
import type { EffectiveGitConfig } from "../../../src/config/load.ts";

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
    const options = buildGitSshOptions(fakeGit(), {});
    expect(options.allowedHosts).toEqual([]);
  });

  it("allow-hosts set is passed through unchanged", () => {
    const options = buildGitSshOptions(fakeGit({ "allow-hosts": ["github.com"] }), {});
    expect(options.allowedHosts).toEqual(["github.com"]);
  });

  it("ssh-agent true with SSH_AUTH_SOCK set in the injected env sets agent to that value", () => {
    const options = buildGitSshOptions(fakeGit({ "ssh-agent": true }), { SSH_AUTH_SOCK: "/tmp/agent.sock" });
    expect(options.agent).toBe("/tmp/agent.sock");
  });

  it("ssh-agent true with SSH_AUTH_SOCK unset in env leaves agent absent (no throw)", () => {
    const options = buildGitSshOptions(fakeGit({ "ssh-agent": true }), {});
    expect("agent" in options).toBe(false);
  });

  it("ssh-agent false leaves agent absent regardless of env", () => {
    const options = buildGitSshOptions(fakeGit({ "ssh-agent": false }), { SSH_AUTH_SOCK: "/tmp/agent.sock" });
    expect("agent" in options).toBe(false);
  });

  it("does not set knownHostsFile, deferring to the SDK's own broader default", () => {
    const options = buildGitSshOptions(fakeGit(), {});
    expect("knownHostsFile" in options).toBe(false);
  });

  describe("execPolicy", () => {
    const allowRepos = ["dario/corb"];

    it("denies a non-git ssh command", () => {
      const options = buildGitSshOptions(fakeGit({ "allow-repos": allowRepos }), {});
      const decision = decisionFor(options, "id");
      expect(decision.allow).toBe(false);
      expect((decision as { message?: string }).message).toMatch(/not a recognized git-over-ssh command/);
    });

    it("denies a recognized-but-unsupported git service", () => {
      const options = buildGitSshOptions(fakeGit({ "allow-repos": allowRepos }), {});
      const decision = decisionFor(options, "git-upload-archive 'dario/corb.git'");
      expect(decision.allow).toBe(false);
      expect((decision as { message?: string }).message).toMatch(/ssh service 'git-upload-archive' is not permitted/);
    });

    it("allows git-upload-pack (fetch/clone) for an allowlisted repo", () => {
      const options = buildGitSshOptions(fakeGit({ "allow-repos": allowRepos }), {});
      const decision = decisionFor(options, "git-upload-pack 'dario/corb.git'");
      expect(decision.allow).toBe(true);
    });

    it("denies git-upload-pack for a repo outside the allowlist", () => {
      const options = buildGitSshOptions(fakeGit({ "allow-repos": allowRepos }), {});
      const decision = decisionFor(options, "git-upload-pack 'someone-else/other.git'");
      expect(decision.allow).toBe(false);
      expect((decision as { message?: string }).message).toMatch(/not in git\.allow-repos/);
    });

    it("denies git-receive-pack (push) for an allowlisted repo when allow-push is false", () => {
      const options = buildGitSshOptions(fakeGit({ "allow-repos": allowRepos, "allow-push": false }), {});
      const decision = decisionFor(options, "git-receive-pack 'dario/corb.git'");
      expect(decision.allow).toBe(false);
      expect((decision as { message?: string }).message).toMatch(/push is disabled/);
    });

    it("allows git-receive-pack (push) for an allowlisted repo when allow-push is true", () => {
      const options = buildGitSshOptions(fakeGit({ "allow-repos": allowRepos, "allow-push": true }), {});
      const decision = decisionFor(options, "git-receive-pack 'dario/corb.git'");
      expect(decision.allow).toBe(true);
    });

    it("denies every service, including push, when allow-repos is undefined at all", () => {
      const options = buildGitSshOptions(fakeGit({ "allow-push": true }), {});
      const fetchDecision = decisionFor(options, "git-upload-pack 'dario/corb.git'");
      const pushDecision = decisionFor(options, "git-receive-pack 'dario/corb.git'");
      expect(fetchDecision.allow).toBe(false);
      expect(pushDecision.allow).toBe(false);
    });
  });
});
