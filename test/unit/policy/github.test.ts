// Unit tests for `src/policy/github.ts` — M4.2. Covers every branch of
// `githubApiGate`'s semantics: the config-driven-only no-op when
// `[egress.github-api]` is entirely absent, the hostname-scoping that keeps
// this gate from ever touching an unrelated request, the `hosts` default and
// override, the `methods` allowlist, the `deny-paths` glob blocklist against
// all three of `docs/design.md`'s own example patterns, the "neither
// restriction violated" pass-through, and the audit event shape/content for
// a denial (with no double-audit on allow).
import { describe, expect, it, vi } from "vitest";
import type { PartialEgressGithubApiConfig } from "../../../src/config/schema.ts";
import type { AuditWriter } from "../../../src/policy/audit.ts";
import { githubApiGate } from "../../../src/policy/github.ts";

function fakeAudit(): AuditWriter & { record: ReturnType<typeof vi.fn> } {
  return { record: vi.fn(), addRedactedSecrets: vi.fn(), flush: vi.fn() };
}

function req(url: string, method = "GET"): Request {
  return new Request(url, { method });
}

describe("policy/github githubApiGate", () => {
  it("undefined config passes every request through untouched (no audit event)", () => {
    const audit = fakeAudit();
    const gate = githubApiGate(undefined, audit, "s");
    expect(gate(req("https://api.github.com/repos/dario/corb", "DELETE"))).toBeUndefined();
    expect(audit.record).not.toHaveBeenCalled();
  });

  it("a request to a hostname outside the (defaulted) target list passes through untouched", () => {
    const audit = fakeAudit();
    const gate = githubApiGate({ methods: ["GET"] }, audit, "s");
    expect(gate(req("https://api.anthropic.com/v1/messages", "DELETE"))).toBeUndefined();
    expect(audit.record).not.toHaveBeenCalled();
  });

  it("hosts unset defaults the target to api.github.com", () => {
    const audit = fakeAudit();
    const gate = githubApiGate({ methods: ["GET"] }, audit, "s");
    const result = gate(req("https://api.github.com/repos/dario/corb", "DELETE"));
    expect(result).toBeInstanceOf(Response);
  });

  it("hosts explicitly set changes the target — the default host is no longer gated", () => {
    const audit = fakeAudit();
    const gate = githubApiGate({ hosts: ["ghe.example.com"], methods: ["GET"] }, audit, "s");
    expect(gate(req("https://api.github.com/repos/dario/corb", "DELETE"))).toBeUndefined();
    expect(gate(req("https://ghe.example.com/repos/dario/corb", "DELETE"))).toBeInstanceOf(Response);
    expect(audit.record).toHaveBeenCalledTimes(1);
  });

  it("hostname matches and neither methods nor deny-paths is configured — denies nothing", () => {
    const audit = fakeAudit();
    const gate = githubApiGate({}, audit, "s");
    expect(gate(req("https://api.github.com/repos/dario/corb", "DELETE"))).toBeUndefined();
    expect(audit.record).not.toHaveBeenCalled();
  });

  it("methods allowlist denies a method not in the list", () => {
    const audit = fakeAudit();
    const gate = githubApiGate({ methods: ["GET", "POST", "PATCH"] }, audit, "s");
    const result = gate(req("https://api.github.com/repos/dario/corb", "DELETE"));
    expect(result).toBeInstanceOf(Response);
    expect((result as Response).status).toBe(403);
  });

  it("methods allowlist allows a method that is in the list", () => {
    const audit = fakeAudit();
    const gate = githubApiGate({ methods: ["GET", "POST", "PATCH"] }, audit, "s");
    expect(gate(req("https://api.github.com/repos/dario/corb", "GET"))).toBeUndefined();
    expect(audit.record).not.toHaveBeenCalled();
  });

  it("this is the concrete gate that makes `gh api -X DELETE` refusable: DELETE denied when methods = [GET, POST, PATCH]", () => {
    const audit = fakeAudit();
    const gate = githubApiGate({ methods: ["GET", "POST", "PATCH"] }, audit, "s");
    const result = gate(req("https://api.github.com/repos/dario/corb", "DELETE"));
    expect(result).toBeInstanceOf(Response);
    expect((result as Response).status).toBe(403);
  });

  describe("deny-paths — design.md's own three example patterns", () => {
    const denyPaths = ["**/actions/secrets/**", "**/actions/variables/**", "/user/keys**"];

    it("**/actions/secrets/** denies regardless of an otherwise-allowed method", () => {
      const audit = fakeAudit();
      const gate = githubApiGate({ methods: ["GET"], "deny-paths": denyPaths }, audit, "s");
      const result = gate(req("https://api.github.com/repos/dario/corb/actions/secrets/FOO", "GET"));
      expect(result).toBeInstanceOf(Response);
      expect((result as Response).status).toBe(403);
    });

    it("**/actions/variables/** denies", () => {
      const audit = fakeAudit();
      const gate = githubApiGate({ "deny-paths": denyPaths }, audit, "s");
      const result = gate(req("https://api.github.com/repos/dario/corb/actions/variables/FOO", "GET"));
      expect(result).toBeInstanceOf(Response);
      expect((result as Response).status).toBe(403);
    });

    it("/user/keys** denies", () => {
      const audit = fakeAudit();
      const gate = githubApiGate({ "deny-paths": denyPaths }, audit, "s");
      const result = gate(req("https://api.github.com/user/keys/123", "GET"));
      expect(result).toBeInstanceOf(Response);
      expect((result as Response).status).toBe(403);
    });

    it("a path matching none of the configured deny-paths passes through", () => {
      const audit = fakeAudit();
      const gate = githubApiGate({ "deny-paths": denyPaths }, audit, "s");
      expect(gate(req("https://api.github.com/repos/dario/corb/issues", "GET"))).toBeUndefined();
      expect(audit.record).not.toHaveBeenCalled();
    });
  });

  describe("percent-encoding cannot be used to smuggle a path past deny-paths", () => {
    it("a single percent-encoded path segment is still denied (URL.pathname never decodes on its own)", () => {
      const audit = fakeAudit();
      const gate = githubApiGate({ "deny-paths": ["**/actions/secrets/**"] }, audit, "s");
      // %73 = 's': "actions/%73ecrets/FOO" decodes to "actions/secrets/FOO".
      const result = gate(req("https://api.github.com/repos/dario/corb/actions/%73ecrets/FOO", "GET"));
      expect(result).toBeInstanceOf(Response);
      expect((result as Response).status).toBe(403);
    });

    it("a double percent-encoded path segment is still denied (decoding runs to a fixpoint)", () => {
      const audit = fakeAudit();
      const gate = githubApiGate({ "deny-paths": ["**/actions/secrets/**"] }, audit, "s");
      // %2573 decodes to %73 decodes to 's'.
      const result = gate(req("https://api.github.com/repos/dario/corb/actions/%2573ecrets/FOO", "GET"));
      expect(result).toBeInstanceOf(Response);
      expect((result as Response).status).toBe(403);
    });

    it("/user/keys** still denies a percent-encoded spelling", () => {
      const audit = fakeAudit();
      const gate = githubApiGate({ "deny-paths": ["/user/keys**"] }, audit, "s");
      const result = gate(req("https://api.github.com/%75ser/keys/123", "GET"));
      expect(result).toBeInstanceOf(Response);
      expect((result as Response).status).toBe(403);
    });

    it("a malformed percent-escape in the path is denied outright, fail-closed", () => {
      const audit = fakeAudit();
      const gate = githubApiGate({ "deny-paths": ["**/actions/secrets/**"] }, audit, "s");
      const result = gate(req("https://api.github.com/repos/dario/corb/%ZZ", "GET")) as Response;
      expect(result).toBeInstanceOf(Response);
      expect(result.status).toBe(403);
      expect(audit.record).toHaveBeenCalledWith(
        expect.objectContaining({ decision: "deny", reason: "malformed percent-encoding in request path" }),
      );
    });

    it("a legitimate percent-encoded path matching no deny-paths pattern still passes through", () => {
      const audit = fakeAudit();
      const gate = githubApiGate(
        { "deny-paths": ["**/actions/secrets/**", "**/actions/variables/**", "/user/keys**"] },
        audit,
        "s",
      );
      // %20 = space, in an issue title-ish path segment unrelated to any deny pattern.
      expect(gate(req("https://api.github.com/repos/dario/corb/issues/my%20issue", "GET"))).toBeUndefined();
      expect(audit.record).not.toHaveBeenCalled();
    });

    it("malformed percent-encoding does not cause a deny when deny-paths is not configured at all", () => {
      const audit = fakeAudit();
      const gate = githubApiGate({ methods: ["GET"] }, audit, "s");
      expect(gate(req("https://api.github.com/repos/dario/corb/%ZZ", "GET"))).toBeUndefined();
      expect(audit.record).not.toHaveBeenCalled();
    });
  });

  it("a request violating neither methods nor deny-paths (both configured) passes through", () => {
    const audit = fakeAudit();
    const gate = githubApiGate(
      { methods: ["GET", "POST"], "deny-paths": ["**/actions/secrets/**"] },
      audit,
      "s",
    );
    expect(gate(req("https://api.github.com/repos/dario/corb/issues", "POST"))).toBeUndefined();
    expect(audit.record).not.toHaveBeenCalled();
  });

  it("deny-paths denies even when method is not restricted at all (methods unset)", () => {
    const audit = fakeAudit();
    const gate = githubApiGate({ "deny-paths": ["**/actions/secrets/**"] }, audit, "s");
    const result = gate(req("https://api.github.com/repos/dario/corb/actions/secrets/FOO", "DELETE"));
    expect(result).toBeInstanceOf(Response);
  });

  it("records exactly one deny audit event with the documented subject/reason shape, and no allow event", () => {
    const audit = fakeAudit();
    const gate = githubApiGate({ methods: ["GET"] }, audit, "session-1");
    gate(req("https://api.github.com/repos/dario/corb", "DELETE"));

    expect(audit.record).toHaveBeenCalledTimes(1);
    expect(audit.record).toHaveBeenCalledWith({
      channel: "http",
      decision: "deny",
      subject: "DELETE api.github.com/repos/dario/corb",
      reason: "method not allowed",
      sessionId: "session-1",
    });
  });

  it("a deny-paths denial names the exact pattern that fired in its audit reason", () => {
    const audit = fakeAudit();
    const gate = githubApiGate({ "deny-paths": ["/user/keys**"] }, audit, "session-2");
    gate(req("https://api.github.com/user/keys/123", "GET"));

    expect(audit.record).toHaveBeenCalledWith({
      channel: "http",
      decision: "deny",
      subject: "GET api.github.com/user/keys/123",
      reason: "path denied: /user/keys**",
      sessionId: "session-2",
    });
  });

  it("a denial response never echoes the request URL, method, or headers into the body", async () => {
    const audit = fakeAudit();
    const gate = githubApiGate({ methods: ["GET"] }, audit, "s");
    const result = gate(
      req("https://api.github.com/repos/dario/corb?secret=totally-a-secret-value", "DELETE"),
    ) as Response;
    const body = await result.text();
    expect(body).not.toContain("totally-a-secret-value");
    expect(body).not.toContain("/repos/dario/corb");
    expect(body).not.toContain("DELETE");
  });

  it("a pass-through never calls audit.record — onResponse elsewhere records the eventual real allow", () => {
    const audit = fakeAudit();
    const gate = githubApiGate({ methods: ["GET", "DELETE"] }, audit, "s");
    expect(gate(req("https://api.github.com/repos/dario/corb", "DELETE"))).toBeUndefined();
    expect(audit.record).not.toHaveBeenCalled();
  });
});
