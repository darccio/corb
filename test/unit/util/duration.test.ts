// Unit tests for `src/util/duration.ts`. Mirrors `test/unit/util/
// redact.test.ts`'s style: a plain `describe`/`it` block, one focused
// assertion (or small group) per `it`, no fakes or injected dependencies
// needed since `parseDuration` is a pure function.
import { describe, expect, it } from "vitest";
import { DurationParseError, parseDuration } from "../../../src/util/duration.ts";

describe("util/duration parseDuration", () => {
  it("parses a seconds value", () => {
    expect(parseDuration("30s")).toBe(30_000);
  });

  it("parses a minutes value", () => {
    expect(parseDuration("5m")).toBe(300_000);
  });

  it("parses an hours value", () => {
    expect(parseDuration("4h")).toBe(14_400_000);
  });

  it("parses a days value", () => {
    expect(parseDuration("1d")).toBe(86_400_000);
  });

  it("parses multi-digit values", () => {
    expect(parseDuration("120s")).toBe(120_000);
    expect(parseDuration("90m")).toBe(5_400_000);
  });

  it("rejects a value with no suffix", () => {
    expect(() => parseDuration("30")).toThrow(DurationParseError);
  });

  it("rejects a value with an unrecognized suffix", () => {
    expect(() => parseDuration("30w")).toThrow(DurationParseError);
    expect(() => parseDuration("30x")).toThrow(DurationParseError);
  });

  it("rejects a negative value", () => {
    expect(() => parseDuration("-30s")).toThrow(DurationParseError);
  });

  it("rejects an empty string", () => {
    expect(() => parseDuration("")).toThrow(DurationParseError);
  });

  it("rejects a non-numeric value", () => {
    expect(() => parseDuration("abcs")).toThrow(DurationParseError);
  });

  it("rejects a value with trailing/leading whitespace or extra characters", () => {
    expect(() => parseDuration(" 30s")).toThrow(DurationParseError);
    expect(() => parseDuration("30s ")).toThrow(DurationParseError);
    expect(() => parseDuration("30ss")).toThrow(DurationParseError);
  });

  it("error message names the invalid input", () => {
    expect(() => parseDuration("nope")).toThrow(/nope/);
  });
});
