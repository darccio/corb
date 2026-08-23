// Unit tests for `src/util/redact.ts` — M3.1. Covers the scrub itself
// (single/multiple/repeated occurrences, multiple distinct secrets), the
// two "must not corrupt the text" guards (empty secrets list, an
// empty-string entry inside the list), and the no-false-positive case.
import { describe, expect, it } from "vitest";
import { redactKnownSecrets } from "../../../src/util/redact.ts";

describe("util/redact redactKnownSecrets", () => {
  it("scrubs a single occurrence of a known secret", () => {
    expect(redactKnownSecrets("token=ghp_abc123 sent", ["ghp_abc123"])).toBe("token=[REDACTED] sent");
  });

  it("scrubs multiple occurrences of the same secret", () => {
    expect(redactKnownSecrets("ghp_abc123 and again ghp_abc123", ["ghp_abc123"])).toBe(
      "[REDACTED] and again [REDACTED]",
    );
  });

  it("scrubs multiple different secrets from the same text", () => {
    expect(redactKnownSecrets("user=alice token=ghp_abc123 key=sk-xyz", ["ghp_abc123", "sk-xyz"])).toBe(
      "user=alice token=[REDACTED] key=[REDACTED]",
    );
  });

  it("does nothing when the secrets list is empty", () => {
    const text = "nothing sensitive here at all";
    expect(redactKnownSecrets(text, [])).toBe(text);
  });

  it("ignores an empty-string entry in the secrets list without corrupting the text", () => {
    const text = "hello world, this stays intact";
    expect(redactKnownSecrets(text, ["", "not-present"])).toBe(text);
  });

  it("does not false-positive on text that merely resembles but doesn't contain any listed secret", () => {
    const text = "token=ghp_abc124 is a different value";
    expect(redactKnownSecrets(text, ["ghp_abc123"])).toBe(text);
  });
});
