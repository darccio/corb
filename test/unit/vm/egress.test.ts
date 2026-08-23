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
import type { EffectiveEgressConfig } from "../../../src/config/load.ts";

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

  function fakeAudit(): AuditWriter & { record: ReturnType<typeof vi.fn> } {
    return { record: vi.fn(), flush: vi.fn() };
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

  it("egress.allow unset produces allowedHosts: [] passed to createHttpHooks — never undefined, never omitted", () => {
    buildEgressConfig(egress(), undefined, {}, fakeAudit(), "session-1");
    expect(createHttpHooksMock).toHaveBeenCalledTimes(1);
    const callArgs = createHttpHooksMock.mock.calls[0]?.[0] as Record<string, unknown>;
    expect("allowedHosts" in callArgs).toBe(true);
    expect(callArgs.allowedHosts).toEqual([]);
    expect(callArgs.allowedHosts).not.toBeUndefined();
  });

  it("egress.allow with real hosts passes them through unchanged", () => {
    buildEgressConfig(egress({ allow: ["api.anthropic.com", "*.github.com"] }), undefined, {}, fakeAudit(), "s");
    const callArgs = createHttpHooksMock.mock.calls[0]?.[0] as Record<string, unknown>;
    expect(callArgs.allowedHosts).toEqual(["api.anthropic.com", "*.github.com"]);
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

  it("does not pass onRequest, isRequestAllowed, or isIpAllowed — no dead-code hooks for out-of-scope M4/M7 gates", () => {
    buildEgressConfig(egress(), undefined, {}, fakeAudit(), "s");
    const callArgs = createHttpHooksMock.mock.calls[0]?.[0] as Record<string, unknown>;
    expect("onRequest" in callArgs).toBe(false);
    expect("isRequestAllowed" in callArgs).toBe(false);
    expect("isIpAllowed" in callArgs).toBe(false);
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
});
