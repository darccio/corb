// Unit tests for `src/vm/githttp.ts`. Structured like
// `test/unit/vm/gitssh.test.ts` (same `fakeAudit()`/`fakeGit(overrides)`
// helper shapes) for the git-domain pieces, and like
// `test/unit/policy/github.test.ts` (plain `Request` objects in,
// `Response | undefined` out, no SDK mocking) for the HTTP-gate pieces —
// neither `parseGitHttpRequest` nor `gitHttpGate` touch
// `@earendil-works/gondolin` at all.
import { describe, expect, it, vi } from "vitest";
import { gitHttpGate, parseGitHttpRequest } from "../../../src/vm/githttp.ts";
import { GIT_RECEIVE_PACK, GIT_UPLOAD_PACK, RepoTraversalError } from "../../../src/vm/gitssh.ts";
import type { EffectiveGitConfig } from "../../../src/config/load.ts";
import type { AuditWriter } from "../../../src/policy/audit.ts";

function fakeAudit(): AuditWriter & { record: ReturnType<typeof vi.fn> } {
  return { record: vi.fn(), addRedactedSecrets: vi.fn(), flush: vi.fn() };
}

function fakeGit(overrides: Partial<EffectiveGitConfig> = {}): EffectiveGitConfig {
  return {
    "ssh-agent": true,
    "allow-push": false,
    ...overrides,
  };
}

function req(url: string, method = "GET"): Request {
  return new Request(url, { method });
}

describe("vm/githttp parseGitHttpRequest", () => {
  it("GET .../info/refs matches as discovery", () => {
    expect(parseGitHttpRequest("GET", "/dario/corb/info/refs")).toEqual({
      repo: "dario/corb",
      kind: "discovery",
    });
  });

  it("POST .../git-upload-pack matches as fetch", () => {
    expect(parseGitHttpRequest("POST", "/dario/corb/git-upload-pack")).toEqual({
      repo: "dario/corb",
      kind: GIT_UPLOAD_PACK,
    });
  });

  it("POST .../git-receive-pack matches as push", () => {
    expect(parseGitHttpRequest("POST", "/dario/corb/git-receive-pack")).toEqual({
      repo: "dario/corb",
      kind: GIT_RECEIVE_PACK,
    });
  });

  it("POST to .../info/refs (wrong method for that shape) does not match", () => {
    expect(parseGitHttpRequest("POST", "/dario/corb/info/refs")).toBeUndefined();
  });

  it("GET to .../git-upload-pack (wrong method for that shape) does not match", () => {
    expect(parseGitHttpRequest("GET", "/dario/corb/git-upload-pack")).toBeUndefined();
  });

  it("GET to .../git-receive-pack (wrong method for that shape) does not match", () => {
    expect(parseGitHttpRequest("GET", "/dario/corb/git-receive-pack")).toBeUndefined();
  });

  it("a path with only one segment before the suffix (no repo) does not match", () => {
    expect(parseGitHttpRequest("POST", "/dario/git-upload-pack")).toBeUndefined();
  });

  it("a path with three-plus segments before the suffix (GitLab/self-hosted-style nesting) does not match", () => {
    expect(parseGitHttpRequest("POST", "/group/subgroup/repo/git-upload-pack")).toBeUndefined();
  });

  it("an unrecognized suffix does not match", () => {
    expect(parseGitHttpRequest("GET", "/dario/corb/HEAD")).toBeUndefined();
  });

  it("a path unrelated to git-smart-HTTP entirely does not match", () => {
    expect(parseGitHttpRequest("GET", "/")).toBeUndefined();
  });

  it("a bare (no .git) and a .git-suffixed repo segment both parse to the same matched shape, .git preserved raw in `repo`", () => {
    const bare = parseGitHttpRequest("POST", "/dario/corb/git-upload-pack");
    const suffixed = parseGitHttpRequest("POST", "/dario/corb.git/git-upload-pack");
    expect(bare).toEqual({ repo: "dario/corb", kind: GIT_UPLOAD_PACK });
    expect(suffixed).toEqual({ repo: "dario/corb.git", kind: GIT_UPLOAD_PACK });
  });
});

describe("vm/githttp gitHttpGate", () => {
  describe("host scope (both directions)", () => {
    it("allow-hosts undefined: a push-shaped request to ANY host passes through untouched, no audit event", () => {
      const audit = fakeAudit();
      const gate = gitHttpGate(fakeGit({ "allow-repos": ["dario/corb"], "allow-push": true }), audit, "s");
      const result = gate(req("https://github.com/dario/corb/git-receive-pack", "POST"));
      expect(result).toBeUndefined();
      expect(audit.record).not.toHaveBeenCalled();
    });

    it("allow-hosts empty array: same as undefined — passes through untouched, no audit event", () => {
      const audit = fakeAudit();
      const gate = gitHttpGate(
        fakeGit({ "allow-hosts": [], "allow-repos": ["dario/corb"], "allow-push": true }),
        audit,
        "s",
      );
      const result = gate(req("https://github.com/dario/corb/git-receive-pack", "POST"));
      expect(result).toBeUndefined();
      expect(audit.record).not.toHaveBeenCalled();
    });

    it("allow-hosts set to a different host: a request to a non-matching host passes through untouched", () => {
      const audit = fakeAudit();
      const gate = gitHttpGate(fakeGit({ "allow-hosts": ["github.com"], "allow-repos": ["dario/corb"] }), audit, "s");
      const result = gate(req("https://gitlab.com/dario/corb/git-upload-pack", "POST"));
      expect(result).toBeUndefined();
      expect(audit.record).not.toHaveBeenCalled();
    });

    it("allow-hosts set and matching: the gate actually engages (denies a non-allowlisted repo on that host)", () => {
      const audit = fakeAudit();
      const gate = gitHttpGate(fakeGit({ "allow-hosts": ["github.com"], "allow-repos": ["dario/corb"] }), audit, "s");
      const result = gate(req("https://github.com/someone-else/other/git-upload-pack", "POST"));
      expect(result).toBeInstanceOf(Response);
      expect(audit.record).toHaveBeenCalledTimes(1);
    });
  });

  describe("repo allowlist and push gating", () => {
    function git(overrides: Partial<EffectiveGitConfig> = {}): EffectiveGitConfig {
      return fakeGit({ "allow-hosts": ["github.com"], "allow-repos": ["dario/corb"], ...overrides });
    }

    it("fetch (git-upload-pack) is allowed for an allowlisted repo regardless of allow-push", () => {
      const audit = fakeAudit();
      const gate = gitHttpGate(git({ "allow-push": false }), audit, "s");
      expect(gate(req("https://github.com/dario/corb/git-upload-pack", "POST"))).toBeUndefined();
      expect(audit.record).not.toHaveBeenCalled();
    });

    it("push (git-receive-pack) is denied when allow-push is false, even for an allowlisted repo", () => {
      const audit = fakeAudit();
      const gate = gitHttpGate(git({ "allow-push": false }), audit, "s");
      const result = gate(req("https://github.com/dario/corb/git-receive-pack", "POST"));
      expect(result).toBeInstanceOf(Response);
      expect(audit.record).toHaveBeenCalledWith(
        expect.objectContaining({ decision: "deny", reason: expect.stringMatching(/push is disabled/) }),
      );
    });

    it("push (git-receive-pack) is allowed when allow-push is true, for an allowlisted repo", () => {
      const audit = fakeAudit();
      const gate = gitHttpGate(git({ "allow-push": true }), audit, "s");
      expect(gate(req("https://github.com/dario/corb/git-receive-pack", "POST"))).toBeUndefined();
      expect(audit.record).not.toHaveBeenCalled();
    });

    it("a non-allowlisted repo is denied for fetch", () => {
      const audit = fakeAudit();
      const gate = gitHttpGate(git(), audit, "s");
      const result = gate(req("https://github.com/someone-else/other/git-upload-pack", "POST"));
      expect(result).toBeInstanceOf(Response);
      expect(audit.record).toHaveBeenCalledWith(
        expect.objectContaining({ decision: "deny", reason: expect.stringMatching(/not in git\.allow-repos/) }),
      );
    });

    it("a non-allowlisted repo is denied for push too, even when allow-push is true", () => {
      const audit = fakeAudit();
      const gate = gitHttpGate(git({ "allow-push": true }), audit, "s");
      const result = gate(req("https://github.com/someone-else/other/git-receive-pack", "POST"));
      expect(result).toBeInstanceOf(Response);
      expect(audit.record).toHaveBeenCalledWith(
        expect.objectContaining({ decision: "deny", reason: expect.stringMatching(/not in git\.allow-repos/) }),
      );
    });

    it("discovery (info/refs) is allowed for an allowlisted repo regardless of allow-push, including a ?service=git-receive-pack query string", () => {
      const audit = fakeAudit();
      const gate = gitHttpGate(git({ "allow-push": false }), audit, "s");
      // The query string is never read at all — this proves it by using the
      // most push-suggestive query value possible on a request that must
      // still be treated as mere (repo-scoped, not push-scoped) discovery.
      const result = gate(req("https://github.com/dario/corb/info/refs?service=git-receive-pack", "GET"));
      expect(result).toBeUndefined();
      expect(audit.record).not.toHaveBeenCalled();
    });

    it("discovery (info/refs) is denied for a non-allowlisted repo", () => {
      const audit = fakeAudit();
      const gate = gitHttpGate(git(), audit, "s");
      const result = gate(req("https://github.com/someone-else/other/info/refs", "GET"));
      expect(result).toBeInstanceOf(Response);
    });
  });

  describe("percent-encoding and traversal", () => {
    it("a percent-encoded owner segment that decodes to a legitimate allowlisted repo still matches (proves decoding happens before comparison)", () => {
      const audit = fakeAudit();
      const gate = gitHttpGate(fakeGit({ "allow-hosts": ["github.com"], "allow-repos": ["dario/corb"] }), audit, "s");
      // %64 = 'd': "%64ario/corb" decodes to "dario/corb".
      const result = gate(req("https://github.com/%64ario/corb/git-upload-pack", "POST"));
      expect(result).toBeUndefined();
      expect(audit.record).not.toHaveBeenCalled();
    });

    it("a malformed percent-escape anywhere in the path is denied outright with the exact documented reason", () => {
      const audit = fakeAudit();
      const gate = gitHttpGate(fakeGit({ "allow-hosts": ["github.com"], "allow-repos": ["dario/corb"] }), audit, "s");
      const result = gate(req("https://github.com/dario/corb/%ZZ", "GET")) as Response;
      expect(result).toBeInstanceOf(Response);
      expect(result.status).toBe(403);
      expect(audit.record).toHaveBeenCalledWith(
        expect.objectContaining({ decision: "deny", reason: "malformed percent-encoding in request path" }),
      );
    });

    it("a double-percent-encoded '..' segment, which only becomes literal after decodeToFixpoint runs, is denied via RepoTraversalError", () => {
      const audit = fakeAudit();
      const gate = gitHttpGate(fakeGit({ "allow-hosts": ["github.com"], "allow-repos": ["dario/corb"] }), audit, "s");
      // "%252e%252e" is not one of the WHATWG URL spec's own recognized
      // dot-segment forms (those require each dot slot to be exactly "." or
      // "%2e"/"%2E", not "%25xx"), so it survives URL parsing as a literal
      // path segment untouched. Only gitHttpGate's own decodeToFixpoint turns
      // it into a real ".." — one decode: %252e -> %2e; a second: %2e -> "."
      // — reaching normalizeRepo's traversal check for real, unlike
      // gitssh.ts's own SSH-side version of this same check.
      const result = gate(req("https://github.com/dario/%252e%252e/git-upload-pack", "POST")) as Response;
      expect(result).toBeInstanceOf(Response);
      expect(result.status).toBe(403);
      const expectedMessage = new RepoTraversalError("dario/..").message;
      expect(audit.record).toHaveBeenCalledWith(
        expect.objectContaining({ decision: "deny", reason: expectedMessage }),
      );
    });
  });

  describe(".git suffix is optional — the core fix over the plan's original 'mandatory .git' scope", () => {
    it("the same owner/repo, with and without a .git suffix, are both recognized and allowed identically for fetch", () => {
      const gitConfig = fakeGit({ "allow-hosts": ["github.com"], "allow-repos": ["dario/corb"] });
      const auditBare = fakeAudit();
      const auditSuffixed = fakeAudit();

      const bareResult = gitHttpGate(gitConfig, auditBare, "s")(
        req("https://github.com/dario/corb/git-upload-pack", "POST"),
      );
      const suffixedResult = gitHttpGate(gitConfig, auditSuffixed, "s")(
        req("https://github.com/dario/corb.git/git-upload-pack", "POST"),
      );

      expect(bareResult).toBeUndefined();
      expect(suffixedResult).toBeUndefined();
      expect(auditBare.record).not.toHaveBeenCalled();
      expect(auditSuffixed.record).not.toHaveBeenCalled();
    });

    it("the same owner/repo, with and without a .git suffix, are both denied identically for push when allow-push is false", () => {
      const gitConfig = fakeGit({
        "allow-hosts": ["github.com"],
        "allow-repos": ["dario/corb"],
        "allow-push": false,
      });

      const bareResult = gitHttpGate(gitConfig, fakeAudit(), "s")(
        req("https://github.com/dario/corb/git-receive-pack", "POST"),
      ) as Response;
      const suffixedResult = gitHttpGate(gitConfig, fakeAudit(), "s")(
        req("https://github.com/dario/corb.git/git-receive-pack", "POST"),
      ) as Response;

      expect(bareResult.status).toBe(403);
      expect(suffixedResult.status).toBe(403);
    });
  });

  describe("audit shape and no-double-counting", () => {
    it("an allow (pass-through) records nothing — onResponse elsewhere handles the eventual real allow", () => {
      const audit = fakeAudit();
      const gate = gitHttpGate(fakeGit({ "allow-hosts": ["github.com"], "allow-repos": ["dario/corb"] }), audit, "s");
      gate(req("https://github.com/dario/corb/git-upload-pack", "POST"));
      expect(audit.record).not.toHaveBeenCalled();
    });

    it("a deny records exactly one channel: http, decision: deny event with the documented subject shape", () => {
      const audit = fakeAudit();
      const gate = gitHttpGate(
        fakeGit({ "allow-hosts": ["github.com"], "allow-repos": ["dario/corb"] }),
        audit,
        "session-1",
      );
      gate(req("https://github.com/someone-else/other/git-upload-pack", "POST"));

      expect(audit.record).toHaveBeenCalledTimes(1);
      expect(audit.record).toHaveBeenCalledWith({
        channel: "http",
        decision: "deny",
        subject: "POST github.com/someone-else/other/git-upload-pack",
        reason: expect.stringMatching(/not in git\.allow-repos/),
        sessionId: "session-1",
      });
    });

    it("a denial response body never echoes the raw request URL, method, or query string", async () => {
      const audit = fakeAudit();
      const gate = gitHttpGate(fakeGit({ "allow-hosts": ["github.com"], "allow-repos": ["dario/corb"] }), audit, "s");
      // A malformed percent-escape denial has a fully generic, fixed reason
      // string (unlike the allow-repos denial, which by design embeds the
      // requested repo name in its message, mirroring gitssh.ts) — the right
      // scenario to prove nothing request-specific leaks into the body.
      const result = gate(
        req("https://github.com/dario/corb/%ZZ?token=totally-a-secret-value", "DELETE"),
      ) as Response;
      const body = await result.text();
      expect(body).not.toContain("totally-a-secret-value");
      expect(body).not.toContain("/dario/corb/%ZZ");
      expect(body).not.toContain("DELETE");
    });
  });
});
