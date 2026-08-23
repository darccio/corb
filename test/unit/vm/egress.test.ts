// Unit tests for `src/vm/egress.ts`'s `buildSecretBindings`. `env` is always
// a plain injected object literal here, never `process.env` itself — this
// module's whole contract is "no I/O beyond the `env` object it's handed",
// and mutating the real environment in tests would both violate that and
// risk leaking state across tests.
import { describe, expect, it } from "vitest";
import { buildSecretBindings, MissingSecretError, SecretHostsMissingError } from "../../../src/vm/egress.ts";
import type { PartialSecretConfig } from "../../../src/config/schema.ts";

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
