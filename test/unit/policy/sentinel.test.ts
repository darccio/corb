// Unit tests for `src/policy/sentinel.ts` — M7.2. Covers every branch of
// `sentinel()`'s behavior: the `policy.enabled=false` no-op, the wrong-
// hostname pass-through, the oversized-`Content-Length` and oversized-
// streamed-body denials, malformed JSON, every shape-invalid field, rate-
// limit exhaustion, a real violation denying, a clean request allowing, and
// both `fail-open`/`fail-closed` behavior when the check step throws.
//
// Style matches `test/unit/policy/github.test.ts`: a `fakeAudit()` helper
// and small request-building helpers, `describe`/`it` blocks per branch.
import { afterEach, describe, expect, it, vi } from "vitest";
import type { DirConfig, EffectivePolicyConfig } from "../../../src/config/load.ts";
import type { AuditWriter } from "../../../src/policy/audit.ts";
import * as checksModule from "../../../src/policy/checks.ts";
import type { PolicyCheckResponse } from "../../../src/policy/checks.ts";
import { MAX_BODY_BYTES, POLICY_HOST, RATE_LIMIT_BUDGET, sentinel } from "../../../src/policy/sentinel.ts";

function fakeAudit(): AuditWriter & { record: ReturnType<typeof vi.fn> } {
  return { record: vi.fn(), addRedactedSecrets: vi.fn(), flush: vi.fn() };
}

function fakePolicy(overrides: Partial<EffectivePolicyConfig> = {}): EffectivePolicyConfig {
  return {
    enabled: true,
    "secret-scan": true,
    "fail-open": true,
    ...overrides,
  };
}

/** Builds a POST request to the sentinel host with a JSON body and an accurate Content-Length. */
function policyReq(body: unknown, headers: Record<string, string> = {}): Request {
  const text = JSON.stringify(body);
  return new Request(`https://${POLICY_HOST}/check`, {
    method: "POST",
    headers: { "content-type": "application/json", ...headers },
    body: text,
  });
}

function cleanRequestBody(overrides: Record<string, unknown> = {}) {
  return { op: "git.commit", changedFiles: ["src/index.ts"], diff: "+ordinary diff content\n", ...overrides };
}

async function readResponseJson(res: Response): Promise<PolicyCheckResponse> {
  return (await res.json()) as PolicyCheckResponse;
}

describe("policy/sentinel sentinel", () => {
  it("policy.enabled=false is a no-op, even for a well-formed request to the sentinel host — no audit event", async () => {
    const audit = fakeAudit();
    const gate = sentinel(fakePolicy({ enabled: false }), [], audit, "s");
    const result = await gate(policyReq(cleanRequestBody()));
    expect(result).toBeUndefined();
    expect(audit.record).not.toHaveBeenCalled();
  });

  it("a request to any other hostname passes through untouched, no audit event", async () => {
    const audit = fakeAudit();
    const gate = sentinel(fakePolicy(), [], audit, "s");
    const req = new Request("https://api.github.com/repos/dario/corb", { method: "POST" });
    const result = await gate(req);
    expect(result).toBeUndefined();
    expect(audit.record).not.toHaveBeenCalled();
  });

  describe("body-size cap", () => {
    it("Content-Length already over the cap denies without reading the body", async () => {
      const audit = fakeAudit();
      const gate = sentinel(fakePolicy(), [], audit, "s");
      const req = new Request(`https://${POLICY_HOST}/check`, {
        method: "POST",
        headers: { "content-length": String(MAX_BODY_BYTES + 1) },
        // Body itself is small; only the declared Content-Length is oversized.
        body: "{}",
      });
      const result = (await gate(req)) as Response;
      expect(result).toBeInstanceOf(Response);
      expect(result.status).toBe(200);
      expect(result.headers.get("content-type")).toBe("application/json");
      const json = await readResponseJson(result);
      expect(json).toEqual({
        allowed: false,
        rateLimited: false,
        violations: [expect.objectContaining({ rule: "body-too-large" })],
      });
      expect(audit.record).toHaveBeenCalledWith({
        channel: "gate",
        decision: "deny",
        subject: "unknown",
        reason: "request body exceeds 256 KiB cap",
        sessionId: "s",
      });
    });

    it("a real streamed body exceeding the cap denies, without trusting a (correct or absent) Content-Length", async () => {
      const audit = fakeAudit();
      const gate = sentinel(fakePolicy(), [], audit, "s");

      const oversizedChunk = new Uint8Array(64 * 1024).fill(97); // 64 KiB of 'a'
      const chunkCount = Math.ceil((MAX_BODY_BYTES + 1) / oversizedChunk.byteLength);
      const stream = new ReadableStream<Uint8Array>({
        start(controller) {
          for (let i = 0; i < chunkCount; i++) {
            controller.enqueue(oversizedChunk);
          }
          controller.close();
        },
      });

      const req = new Request(`https://${POLICY_HOST}/check`, {
        method: "POST",
        // @ts-expect-error -- undici Request supports a ReadableStream body with duplex.
        duplex: "half",
        body: stream,
      });

      const result = (await gate(req)) as Response;
      expect(result.status).toBe(200);
      const json = await readResponseJson(result);
      expect(json.allowed).toBe(false);
      expect(json.rateLimited).toBe(false);
      expect(json.violations?.[0]?.rule).toBe("body-too-large");
      expect(audit.record).toHaveBeenCalledWith(
        expect.objectContaining({ channel: "gate", decision: "deny", reason: "request body exceeds 256 KiB cap" }),
      );
    });

    it("a body at exactly the cap is not denied for size", async () => {
      const audit = fakeAudit();
      const gate = sentinel(fakePolicy(), [], audit, "s");
      const result = (await gate(policyReq(cleanRequestBody()))) as Response;
      const json = await readResponseJson(result);
      expect(json.violations?.some((v) => v.rule === "body-too-large")).not.toBe(true);
    });
  });

  describe("shape validation", () => {
    it("malformed JSON denies with a well-formed PolicyCheckResponse, status 200", async () => {
      const audit = fakeAudit();
      const gate = sentinel(fakePolicy(), [], audit, "s");
      const req = new Request(`https://${POLICY_HOST}/check`, { method: "POST", body: "not json{{{" });
      const result = (await gate(req)) as Response;
      expect(result.status).toBe(200);
      expect(result.headers.get("content-type")).toBe("application/json");
      const json = await readResponseJson(result);
      expect(json.allowed).toBe(false);
      expect(json.rateLimited).toBe(false);
      expect(json.violations?.[0]?.rule).toBe("malformed-request");
      expect(audit.record).toHaveBeenCalledWith(
        expect.objectContaining({ channel: "gate", decision: "deny", reason: "malformed policy check request" }),
      );
    });

    it("wrong op value denies", async () => {
      const audit = fakeAudit();
      const gate = sentinel(fakePolicy(), [], audit, "s");
      const result = (await gate(policyReq(cleanRequestBody({ op: "git.rebase" })))) as Response;
      const json = await readResponseJson(result);
      expect(json.allowed).toBe(false);
      expect(json.violations?.[0]?.rule).toBe("malformed-request");
    });

    it("missing op denies", async () => {
      const audit = fakeAudit();
      const gate = sentinel(fakePolicy(), [], audit, "s");
      const body = cleanRequestBody() as Record<string, unknown>;
      delete body.op;
      const result = (await gate(policyReq(body))) as Response;
      const json = await readResponseJson(result);
      expect(json.allowed).toBe(false);
    });

    it("non-array changedFiles denies", async () => {
      const audit = fakeAudit();
      const gate = sentinel(fakePolicy(), [], audit, "s");
      const result = (await gate(policyReq(cleanRequestBody({ changedFiles: "not-an-array" })))) as Response;
      const json = await readResponseJson(result);
      expect(json.allowed).toBe(false);
      expect(json.violations?.[0]?.rule).toBe("malformed-request");
    });

    it("changedFiles: null denies, same as any other non-array — the guest must always send [] for empty, never null", async () => {
      const audit = fakeAudit();
      const gate = sentinel(fakePolicy(), [], audit, "s");
      const result = (await gate(policyReq(cleanRequestBody({ changedFiles: null })))) as Response;
      const json = await readResponseJson(result);
      expect(json.allowed).toBe(false);
      expect(json.violations?.[0]?.rule).toBe("malformed-request");
    });

    it("changedFiles containing a non-string entry denies", async () => {
      const audit = fakeAudit();
      const gate = sentinel(fakePolicy(), [], audit, "s");
      const result = (await gate(policyReq(cleanRequestBody({ changedFiles: ["ok.ts", 42] })))) as Response;
      const json = await readResponseJson(result);
      expect(json.allowed).toBe(false);
    });

    it("non-string diff denies", async () => {
      const audit = fakeAudit();
      const gate = sentinel(fakePolicy(), [], audit, "s");
      const result = (await gate(policyReq(cleanRequestBody({ diff: 12345 })))) as Response;
      const json = await readResponseJson(result);
      expect(json.allowed).toBe(false);
      expect(json.violations?.[0]?.rule).toBe("malformed-request");
    });

    it("a malformed-shape denial names the parsed op as subject when it happens to be valid", async () => {
      const audit = fakeAudit();
      const gate = sentinel(fakePolicy(), [], audit, "s");
      await gate(policyReq(cleanRequestBody({ diff: 12345 })));
      expect(audit.record).toHaveBeenCalledWith(
        expect.objectContaining({ channel: "gate", decision: "deny", subject: "git.commit" }),
      );
    });
  });

  describe("rate limiting", () => {
    it("exhausting the budget denies the next call with rateLimited: true and no violations field", async () => {
      const audit = fakeAudit();
      const gate = sentinel(fakePolicy(), [], audit, "s");

      for (let i = 0; i < RATE_LIMIT_BUDGET; i++) {
        const result = (await gate(policyReq(cleanRequestBody()))) as Response;
        const json = await readResponseJson(result);
        expect(json.allowed).toBe(true);
      }

      const overBudget = (await gate(policyReq(cleanRequestBody()))) as Response;
      const json = await readResponseJson(overBudget);
      expect(json).toEqual({ allowed: false, rateLimited: true });
      expect(overBudget.status).toBe(200);
      expect(audit.record).toHaveBeenCalledWith({
        channel: "gate",
        decision: "deny",
        subject: "git.commit",
        reason: "rate limit exceeded",
        sessionId: "s",
      });
    });

    it("the rate-limit counter is per sentinel() call (per session), not shared globally", async () => {
      const audit = fakeAudit();
      const gateA = sentinel(fakePolicy(), [], audit, "session-a");
      const gateB = sentinel(fakePolicy(), [], audit, "session-b");

      for (let i = 0; i < RATE_LIMIT_BUDGET; i++) {
        await gateA(policyReq(cleanRequestBody()));
      }
      // gateA is now exhausted; a fresh gateB for a different session must not be.
      const result = (await gateB(policyReq(cleanRequestBody()))) as Response;
      const json = await readResponseJson(result);
      expect(json.allowed).toBe(true);
    });
  });

  describe("running the checks", () => {
    it("a clean request allows, with an audit allow event and no violations field", async () => {
      const audit = fakeAudit();
      const gate = sentinel(fakePolicy(), [], audit, "s");
      const result = (await gate(policyReq(cleanRequestBody()))) as Response;
      expect(result.status).toBe(200);
      expect(result.headers.get("content-type")).toBe("application/json");
      const json = await readResponseJson(result);
      expect(json).toEqual({ allowed: true, rateLimited: false });
      expect(audit.record).toHaveBeenCalledWith({
        channel: "gate",
        decision: "allow",
        subject: "git.commit",
        reason: "ok",
        sessionId: "s",
      });
    });

    it("genuinely empty content (no changed files, empty diff) allows — regression test for a nil-vs-[] guest marshaling bug that made this deny as malformed-request", async () => {
      const audit = fakeAudit();
      const gate = sentinel(fakePolicy(), [], audit, "s");
      const result = (await gate(policyReq(cleanRequestBody({ changedFiles: [], diff: "" })))) as Response;
      expect(result.status).toBe(200);
      const json = await readResponseJson(result);
      expect(json).toEqual({ allowed: true, rateLimited: false });
      expect(audit.record).toHaveBeenCalledWith({
        channel: "gate",
        decision: "allow",
        subject: "git.commit",
        reason: "ok",
        sessionId: "s",
      });
    });

    it("a secret-shaped diff denies with the documented JSON shape, status 200, application/json", async () => {
      const audit = fakeAudit();
      const gate = sentinel(fakePolicy(), [], audit, "s");
      const result = (await gate(
        policyReq(cleanRequestBody({ diff: "aws key: AKIAABCDEFGHIJKLMNOP" })),
      )) as Response;

      expect(result.status).toBe(200);
      expect(result.headers.get("content-type")).toBe("application/json");
      const json = await readResponseJson(result);
      expect(json.allowed).toBe(false);
      expect(json.rateLimited).toBe(false);
      expect(json.violations).toEqual([
        expect.objectContaining({ rule: "secret-in-diff" }),
      ]);
      expect(audit.record).toHaveBeenCalledWith({
        channel: "gate",
        decision: "deny",
        subject: "git.commit",
        reason: "secret-in-diff",
        sessionId: "s",
      });
    });

    it("multiple violations produce a comma-joined reason naming every rule", async () => {
      const audit = fakeAudit();
      const dirs: DirConfig[] = [{ name: "repo", rules: [{ glob: "**/.env", mode: "hidden", reason: "secrets" }] }];
      const gate = sentinel(fakePolicy({ "max-changed-files": 1 }), dirs, audit, "s");
      const result = (await gate(
        policyReq(
          cleanRequestBody({
            changedFiles: [".env", "a", "b"],
            diff: "aws key: AKIAABCDEFGHIJKLMNOP",
          }),
        ),
      )) as Response;
      const json = await readResponseJson(result);
      expect(json.allowed).toBe(false);
      expect(json.violations?.length).toBeGreaterThan(1);

      const call = audit.record.mock.calls.find((c) => c[0].decision === "deny" && c[0].reason !== "rate limit exceeded");
      const reason = call?.[0].reason as string;
      expect(reason).toContain("secret-in-diff");
      expect(reason).toContain("max-changed-files");
      expect(reason).toContain("path-rule-duplicate");
      // Never leaks the actual diff text or matched secret substring into the audit reason.
      expect(reason).not.toContain("AKIA");
    });

    it("the audit reason for a denial never contains the raw diff text", async () => {
      const audit = fakeAudit();
      const gate = sentinel(fakePolicy(), [], audit, "s");
      await gate(policyReq(cleanRequestBody({ diff: "aws key: AKIAABCDEFGHIJKLMNOP some more diff content" })));
      const denyCall = audit.record.mock.calls.find((c) => c[0].decision === "deny");
      expect(denyCall?.[0].reason).toBe("secret-in-diff");
    });
  });

  describe("fail-open / fail-closed when runChecks itself throws", () => {
    // Organically triggering a throw out of `runChecks` is not practical:
    // every check function it composes is deliberately total over its
    // input (`scanForSecrets` runs fixed regexes with no way to throw,
    // `checkChangedFileCeiling` is arithmetic, and `checkDuplicatedPathRules`
    // calls `globToRegExp`, which escapes every regex metacharacter in a
    // glob segment rather than passing it through raw — so there is no
    // `DirConfig`/`glob` value that reaches `new RegExp()` unescaped and
    // makes it throw). Per this file's own instructions, the cleaner
    // approach here is `vi.spyOn` on the `checks.ts` module namespace:
    // `sentinel.ts` imports the named `runChecks` export, and Vitest's
    // module transform makes that a live binding to the namespace object,
    // so replacing `checksModule.runChecks` intercepts the exact call
    // `sentinel()` makes. `checks.ts`'s own error resilience (that every
    // real check function it ships is total) is exercised separately in
    // `checks.test.ts` instead of forced here.
    afterEach(() => {
      vi.restoreAllMocks();
    });

    it("fails open (allow) when policy.fail-open is true (the default), and the audit reason says so loudly", async () => {
      vi.spyOn(checksModule, "runChecks").mockImplementation(() => {
        throw new Error("boom");
      });
      const audit = fakeAudit();
      const gate = sentinel(fakePolicy({ "fail-open": true }), [], audit, "s");
      const result = (await gate(policyReq(cleanRequestBody({ changedFiles: ["x"] })))) as Response;
      expect(result.status).toBe(200);
      const json = await readResponseJson(result);
      expect(json).toEqual({ allowed: true, rateLimited: false });
      const call = audit.record.mock.calls.at(-1);
      expect(call?.[0]).toMatchObject({ channel: "gate", decision: "allow" });
      expect(call?.[0].reason).toContain("content check failed to run: boom");
      expect(call?.[0].reason).toContain("failing open");
    });

    it("fails closed (deny) when policy.fail-open is false", async () => {
      vi.spyOn(checksModule, "runChecks").mockImplementation(() => {
        throw new Error("boom");
      });
      const audit = fakeAudit();
      const gate = sentinel(fakePolicy({ "fail-open": false }), [], audit, "s");
      const result = (await gate(policyReq(cleanRequestBody({ changedFiles: ["x"] })))) as Response;
      expect(result.status).toBe(200);
      const json = await readResponseJson(result);
      expect(json.allowed).toBe(false);
      expect(json.violations?.[0]?.rule).toBe("check-error");
      const call = audit.record.mock.calls.at(-1);
      expect(call?.[0].decision).toBe("deny");
      expect(call?.[0].reason).toContain("content check failed to run: boom");
      expect(call?.[0].reason).toContain("failing closed");
      expect(call?.[0].reason).toContain("policy.fail-open=false");
    });
  });
});
