// Unit tests for `src/vm/egress.ts`. `env` is always a plain injected object
// literal here, never `process.env` itself — this module's whole contract is
// "no I/O beyond the `env` object it's handed", and mutating the real
// environment in tests would both violate that and risk leaking state across
// tests.
//
// The `buildSecretBindings` suite below is unchanged from M3.2. M3.3 adds
// `createHttpHooks` mocking (`vi.hoisted`, matching
// `test/unit/commands/run.test.ts`'s house style for mocking an SDK/module
// boundary) plus suites for `safeSubject` and `buildEgressConfig`.
import { beforeEach, describe, expect, it, vi } from "vitest";
import type { PartialSecretConfig } from "../../../src/config/schema.ts";
import type { AuditEvent, AuditWriter } from "../../../src/policy/audit.ts";

const { createHttpHooksMock } = vi.hoisted(() => ({
  createHttpHooksMock: vi.fn(),
}));
vi.mock("@earendil-works/gondolin", () => ({
  createHttpHooks: createHttpHooksMock,
}));

import {
  buildEgressConfig,
  buildSecretBindings,
  MissingSecretError,
  safeSubject,
  SecretHostsMissingError,
} from "../../../src/vm/egress.ts";
import type { EffectiveEgressConfig, EffectiveGitConfig } from "../../../src/config/load.ts";
import { POLICY_HOST } from "../../../src/policy/sentinel.ts";

describe("vm/egress buildSecretBindings", () => {
  it("returns {} without error when secrets is undefined", () => {
    expect(buildSecretBindings(undefined, {})).toEqual({});
  });

  it("returns {} without error when secrets is {}", () => {
    expect(buildSecretBindings({}, { SOMETHING: "value" })).toEqual({});
  });

  it("includes a single required secret present in env with the right hosts/value", () => {
    const secrets: Record<string, PartialSecretConfig> = {
      ANTHROPIC_API_KEY: { hosts: ["api.anthropic.com"] },
    };
    const result = buildSecretBindings(secrets, { ANTHROPIC_API_KEY: "sk-real-value" });
    expect(result).toEqual({
      ANTHROPIC_API_KEY: { hosts: ["api.anthropic.com"], value: "sk-real-value" },
    });
  });

  it("throws MissingSecretError when a single required secret is missing from env, naming the secret", () => {
    const secrets: Record<string, PartialSecretConfig> = {
      ANTHROPIC_API_KEY: { hosts: ["api.anthropic.com"] },
    };
    expect(() => buildSecretBindings(secrets, {})).toThrow(MissingSecretError);
    expect(() => buildSecretBindings(secrets, {})).toThrow(/ANTHROPIC_API_KEY/);
  });

  it("omits an optional secret missing from env, with no error", () => {
    const secrets: Record<string, PartialSecretConfig> = {
      OPTIONAL_TOKEN: { hosts: ["example.com"], optional: true },
    };
    expect(buildSecretBindings(secrets, {})).toEqual({});
  });

  it("includes an optional secret that IS present in env — optional only means 'don't require it'", () => {
    const secrets: Record<string, PartialSecretConfig> = {
      OPTIONAL_TOKEN: { hosts: ["example.com"], optional: true },
    };
    const result = buildSecretBindings(secrets, { OPTIONAL_TOKEN: "present-value" });
    expect(result).toEqual({
      OPTIONAL_TOKEN: { hosts: ["example.com"], value: "present-value" },
    });
  });

  it("treats an empty-string env var as unset for a required secret (throws)", () => {
    const secrets: Record<string, PartialSecretConfig> = {
      ANTHROPIC_API_KEY: { hosts: ["api.anthropic.com"] },
    };
    expect(() => buildSecretBindings(secrets, { ANTHROPIC_API_KEY: "" })).toThrow(MissingSecretError);
  });

  it("treats an empty-string env var as unset for an optional secret (omits, no throw)", () => {
    const secrets: Record<string, PartialSecretConfig> = {
      OPTIONAL_TOKEN: { hosts: ["example.com"], optional: true },
    };
    expect(buildSecretBindings(secrets, { OPTIONAL_TOKEN: "" })).toEqual({});
  });

  it("throws SecretHostsMissingError for hosts: [], distinguishable from the missing-value error", () => {
    const secrets: Record<string, PartialSecretConfig> = {
      ANTHROPIC_API_KEY: { hosts: [] },
    };
    expect(() => buildSecretBindings(secrets, { ANTHROPIC_API_KEY: "sk-real-value" })).toThrow(
      SecretHostsMissingError,
    );
    expect(() => buildSecretBindings(secrets, { ANTHROPIC_API_KEY: "sk-real-value" })).toThrow(/ANTHROPIC_API_KEY/);
  });

  it("throws SecretHostsMissingError when hosts is entirely absent (undefined)", () => {
    const secrets: Record<string, PartialSecretConfig> = {
      ANTHROPIC_API_KEY: {},
    };
    expect(() => buildSecretBindings(secrets, { ANTHROPIC_API_KEY: "sk-real-value" })).toThrow(
      SecretHostsMissingError,
    );
  });

  it("handles multiple secrets in one call with a mix of present/missing/optional/required, asserting the exact object", () => {
    const secrets: Record<string, PartialSecretConfig> = {
      REQUIRED_PRESENT: { hosts: ["a.example.com"] },
      OPTIONAL_PRESENT: { hosts: ["b.example.com"], optional: true },
      OPTIONAL_MISSING: { hosts: ["c.example.com"], optional: true },
    };
    const env = {
      REQUIRED_PRESENT: "value-a",
      OPTIONAL_PRESENT: "value-b",
      // OPTIONAL_MISSING deliberately absent.
    };
    const result = buildSecretBindings(secrets, env);
    expect(result).toEqual({
      REQUIRED_PRESENT: { hosts: ["a.example.com"], value: "value-a" },
      OPTIONAL_PRESENT: { hosts: ["b.example.com"], value: "value-b" },
    });
  });

  it("multiple secrets: a required-and-missing secret throws even if others in the same call are fine", () => {
    const secrets: Record<string, PartialSecretConfig> = {
      REQUIRED_PRESENT: { hosts: ["a.example.com"] },
      REQUIRED_MISSING: { hosts: ["d.example.com"] },
    };
    const env = { REQUIRED_PRESENT: "value-a" };
    expect(() => buildSecretBindings(secrets, env)).toThrow(MissingSecretError);
    expect(() => buildSecretBindings(secrets, env)).toThrow(/REQUIRED_MISSING/);
  });
});

describe("vm/egress safeSubject", () => {
  it("returns exactly `${method} ${hostname}${pathname}`, nothing else", () => {
    const req = new Request("https://api.example.com/v1/widgets", { method: "POST" });
    expect(safeSubject(req)).toBe("POST api.example.com/v1/widgets");
  });

  it("a fake secret planted in the query string and in a header never appears in the result", () => {
    const req = new Request("https://api.example.com/v1/widgets?token=totally-a-secret-value", {
      method: "GET",
      headers: { "X-My-Header": "totally-a-secret-value" },
    });
    const subject = safeSubject(req);
    expect(subject).toBe("GET api.example.com/v1/widgets");
    expect(subject).not.toContain("totally-a-secret-value");
    expect(subject).not.toContain("?");
    expect(subject).not.toContain("token");
  });

  it("root path renders as an empty pathname suffix (no trailing garbage)", () => {
    const req = new Request("https://example.com", { method: "GET" });
    expect(safeSubject(req)).toBe("GET example.com/");
  });
});

describe("vm/egress buildEgressConfig", () => {
  function egress(overrides: Partial<EffectiveEgressConfig> = {}): EffectiveEgressConfig {
    return {
      "block-internal-ranges": true,
      websockets: false,
      ...overrides,
    };
  }

  function fakeAudit(): AuditWriter & { record: ReturnType<typeof vi.fn>; addRedactedSecrets: ReturnType<typeof vi.fn> } {
    return { record: vi.fn(), addRedactedSecrets: vi.fn(), flush: vi.fn() };
  }

  beforeEach(() => {
    createHttpHooksMock.mockReset();
    createHttpHooksMock.mockReturnValue({
      httpHooks: { onResponse: undefined },
      env: { SOME_SECRET: "placeholder-value" },
      allowedHosts: [],
      secretManager: {},
    });
  });

  it("egress.allow unset produces allowedHosts: [POLICY_HOST] passed to createHttpHooks — never undefined, never omitted", () => {
    buildEgressConfig(egress(), undefined, {}, fakeAudit(), "session-1");
    expect(createHttpHooksMock).toHaveBeenCalledTimes(1);
    const callArgs = createHttpHooksMock.mock.calls[0]?.[0] as Record<string, unknown>;
    expect("allowedHosts" in callArgs).toBe(true);
    // M7.3: POLICY_HOST is always appended (docs/design.md §5) — see
    // src/vm/egress.ts's buildEgressConfig doc comment for why.
    expect(callArgs.allowedHosts).toEqual([POLICY_HOST]);
    expect(callArgs.allowedHosts).not.toBeUndefined();
  });

  it("egress.allow with real hosts passes them through unchanged, plus POLICY_HOST appended", () => {
    buildEgressConfig(egress({ allow: ["api.anthropic.com", "*.github.com"] }), undefined, {}, fakeAudit(), "s");
    const callArgs = createHttpHooksMock.mock.calls[0]?.[0] as Record<string, unknown>;
    expect(callArgs.allowedHosts).toEqual(["api.anthropic.com", "*.github.com", POLICY_HOST]);
  });

  it("egress['allow-internal'] unset produces [] the same way", () => {
    buildEgressConfig(egress(), undefined, {}, fakeAudit(), "s");
    const callArgs = createHttpHooksMock.mock.calls[0]?.[0] as Record<string, unknown>;
    expect(callArgs.allowedInternalHosts).toEqual([]);
  });

  it("egress['allow-internal'] with real hosts passes them through unchanged", () => {
    buildEgressConfig(egress({ "allow-internal": ["internal.example.com"] }), undefined, {}, fakeAudit(), "s");
    const callArgs = createHttpHooksMock.mock.calls[0]?.[0] as Record<string, unknown>;
    expect(callArgs.allowedInternalHosts).toEqual(["internal.example.com"]);
  });

  it("passes block-internal-ranges through unchanged (true)", () => {
    buildEgressConfig(egress({ "block-internal-ranges": true }), undefined, {}, fakeAudit(), "s");
    const callArgs = createHttpHooksMock.mock.calls[0]?.[0] as Record<string, unknown>;
    expect(callArgs.blockInternalRanges).toBe(true);
  });

  it("passes block-internal-ranges through unchanged (false)", () => {
    buildEgressConfig(egress({ "block-internal-ranges": false }), undefined, {}, fakeAudit(), "s");
    const callArgs = createHttpHooksMock.mock.calls[0]?.[0] as Record<string, unknown>;
    expect(callArgs.blockInternalRanges).toBe(false);
  });

  it("delegates secrets to buildSecretBindings and passes the resulting map through as 'secrets'", () => {
    const secrets: Record<string, PartialSecretConfig> = {
      ANTHROPIC_API_KEY: { hosts: ["api.anthropic.com"] },
    };
    buildEgressConfig(egress(), secrets, { ANTHROPIC_API_KEY: "sk-real" }, fakeAudit(), "s");
    const callArgs = createHttpHooksMock.mock.calls[0]?.[0] as Record<string, unknown>;
    expect(callArgs.secrets).toEqual({
      ANTHROPIC_API_KEY: { hosts: ["api.anthropic.com"], value: "sk-real" },
    });
  });

  it("propagates a MissingSecretError thrown by buildSecretBindings rather than swallowing it", () => {
    const secrets: Record<string, PartialSecretConfig> = {
      ANTHROPIC_API_KEY: { hosts: ["api.anthropic.com"] },
    };
    expect(() => buildEgressConfig(egress(), secrets, {}, fakeAudit(), "s")).toThrow(MissingSecretError);
    expect(createHttpHooksMock).not.toHaveBeenCalled();
  });

  it("registers every bound secret's real value with audit.addRedactedSecrets before returning", () => {
    const secrets: Record<string, PartialSecretConfig> = {
      ANTHROPIC_API_KEY: { hosts: ["api.anthropic.com"] },
      OTHER_TOKEN: { hosts: ["example.com"] },
    };
    const audit = fakeAudit();
    buildEgressConfig(egress(), secrets, { ANTHROPIC_API_KEY: "sk-real", OTHER_TOKEN: "tok-real" }, audit, "s");

    expect(audit.addRedactedSecrets).toHaveBeenCalledTimes(1);
    const registered = audit.addRedactedSecrets.mock.calls[0]?.[0] as string[];
    expect(registered.sort()).toEqual(["sk-real", "tok-real"]);
  });

  it("calls audit.addRedactedSecrets with an empty list when no secrets are configured, rather than skipping the call", () => {
    const audit = fakeAudit();
    buildEgressConfig(egress(), undefined, {}, audit, "s");
    expect(audit.addRedactedSecrets).toHaveBeenCalledWith([]);
  });

  it("allowWebSockets in the return value reflects egress.websockets (true) and is not passed to createHttpHooks", () => {
    const result = buildEgressConfig(egress({ websockets: true }), undefined, {}, fakeAudit(), "s");
    expect(result.allowWebSockets).toBe(true);
    const callArgs = createHttpHooksMock.mock.calls[0]?.[0] as Record<string, unknown>;
    expect("websockets" in callArgs).toBe(false);
    expect("allowWebSockets" in callArgs).toBe(false);
  });

  it("allowWebSockets in the return value reflects egress.websockets (false)", () => {
    const result = buildEgressConfig(egress({ websockets: false }), undefined, {}, fakeAudit(), "s");
    expect(result.allowWebSockets).toBe(false);
  });

  it("returns the httpHooks/env createHttpHooks produced, unmodified", () => {
    const httpHooksSentinel = { onResponse: undefined };
    createHttpHooksMock.mockReturnValue({
      httpHooks: httpHooksSentinel,
      env: { PLACEHOLDER: "abc" },
      allowedHosts: [],
      secretManager: {},
    });
    const result = buildEgressConfig(egress(), undefined, {}, fakeAudit(), "s");
    expect(result.httpHooks).toBe(httpHooksSentinel);
    expect(result.env).toEqual({ PLACEHOLDER: "abc" });
  });

  it("does not pass isRequestAllowed or isIpAllowed — no dead-code hooks for the still-out-of-scope M7 sentinel", () => {
    buildEgressConfig(egress(), undefined, {}, fakeAudit(), "s");
    const callArgs = createHttpHooksMock.mock.calls[0]?.[0] as Record<string, unknown>;
    expect("isRequestAllowed" in callArgs).toBe(false);
    expect("isIpAllowed" in callArgs).toBe(false);
  });

  it("passes onRequest as composeOnRequest([sentinel, githubApiGate]) — a request the gate denies is short-circuited with a 403", async () => {
    const audit = fakeAudit();
    buildEgressConfig(egress({ "github-api": { methods: ["GET"] } }), undefined, {}, audit, "session-gh");
    const callArgs = createHttpHooksMock.mock.calls[0]?.[0] as {
      onRequest: (req: Request) => Promise<Response | undefined> | Response | undefined;
    };
    expect(typeof callArgs.onRequest).toBe("function");

    // M7.3: onRequest is now `composeOnRequest([sentinel(...), githubApiGate(...)])`,
    // always async (sentinel() itself is async) — see src/vm/egress.ts.
    const req = new Request("https://api.github.com/repos/dario/corb", { method: "DELETE" });
    const result = await callArgs.onRequest(req);

    expect(result).toBeInstanceOf(Response);
    expect((result as Response).status).toBe(403);
    expect(audit.record).toHaveBeenCalledWith({
      channel: "http",
      decision: "deny",
      subject: "DELETE api.github.com/repos/dario/corb",
      reason: "method not allowed",
      sessionId: "session-gh",
    });
  });

  it("onRequest passes a request through (resolves undefined) when egress['github-api'] is undefined and the host isn't POLICY_HOST", async () => {
    buildEgressConfig(egress(), undefined, {}, fakeAudit(), "s");
    const callArgs = createHttpHooksMock.mock.calls[0]?.[0] as {
      onRequest: (req: Request) => Promise<Response | undefined> | Response | undefined;
    };
    const req = new Request("https://api.github.com/repos/dario/corb", { method: "DELETE" });
    await expect(callArgs.onRequest(req)).resolves.toBeUndefined();
  });

  it("wires onResponse to record an 'allow' AuditEvent with the exact expected shape, including sessionId", async () => {
    const audit = fakeAudit();
    buildEgressConfig(egress(), undefined, {}, audit, "session-42");
    const callArgs = createHttpHooksMock.mock.calls[0]?.[0] as {
      onResponse: (res: Response, req: Request) => unknown;
    };

    const req = new Request("https://api.anthropic.com/v1/messages?leak=totally-a-secret-value", {
      method: "POST",
      headers: { Authorization: "totally-a-secret-value" },
    });
    const res = new Response(null, { status: 200 });

    await callArgs.onResponse(res, req);

    expect(audit.record).toHaveBeenCalledTimes(1);
    const recorded = audit.record.mock.calls[0]?.[0] as Omit<AuditEvent, "ts">;
    expect(recorded).toEqual({
      channel: "http",
      decision: "allow",
      subject: "POST api.anthropic.com/v1/messages",
      reason: "200",
      sessionId: "session-42",
    });
  });

  it("onResponse's reason reflects the actual response status", async () => {
    const audit = fakeAudit();
    buildEgressConfig(egress(), undefined, {}, audit, "s");
    const callArgs = createHttpHooksMock.mock.calls[0]?.[0] as {
      onResponse: (res: Response, req: Request) => unknown;
    };
    const req = new Request("https://example.com/", { method: "GET" });
    const res = new Response(null, { status: 404 });

    await callArgs.onResponse(res, req);

    const recorded = audit.record.mock.calls[0]?.[0] as Omit<AuditEvent, "ts">;
    expect(recorded.reason).toBe("404");
  });

  it("wires gitHttpGate into onRequest too: a push-shaped request to an allow-hosted, allow-repos-scoped host is denied when allow-push is false", async () => {
    const audit = fakeAudit();
    const git: EffectiveGitConfig = {
      "ssh-agent": true,
      "allow-push": false,
      "allow-hosts": ["github.com"],
      "allow-repos": ["dario/corb"],
    };
    // `policy` (6th) and `dirs` (7th) must be filled in to reach `git` (8th)
    // positionally; `undefined` for `policy` falls back to this module's own
    // `INERT_POLICY` default, same as every other trailing-default parameter
    // in this file.
    buildEgressConfig(egress(), undefined, {}, audit, "session-git", undefined, [], git);
    const callArgs = createHttpHooksMock.mock.calls[0]?.[0] as {
      onRequest: (req: Request) => Promise<Response | undefined> | Response | undefined;
    };

    const req = new Request("https://github.com/dario/corb/git-receive-pack", { method: "POST" });
    const result = await callArgs.onRequest(req);

    expect(result).toBeInstanceOf(Response);
    expect((result as Response).status).toBe(403);
    expect(audit.record).toHaveBeenCalledWith(
      expect.objectContaining({
        channel: "http",
        decision: "deny",
        subject: "POST github.com/dario/corb/git-receive-pack",
        reason: expect.stringMatching(/push is disabled/),
        sessionId: "session-git",
      }),
    );
  });

  it("regression guard: omitting the git parameter entirely (INERT_GIT default) leaves a git-push-shaped request passing through untouched, same as every pre-existing call site in this file", async () => {
    buildEgressConfig(egress(), undefined, {}, fakeAudit(), "s");
    const callArgs = createHttpHooksMock.mock.calls[0]?.[0] as {
      onRequest: (req: Request) => Promise<Response | undefined> | Response | undefined;
    };

    const req = new Request("https://github.com/dario/corb/git-receive-pack", { method: "POST" });
    await expect(callArgs.onRequest(req)).resolves.toBeUndefined();
  });
});
