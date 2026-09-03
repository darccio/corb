// Unit tests for `src/util/duration.ts`. Mirrors `test/unit/util/
// redact.test.ts`'s style: a plain `describe`/`it` block, one focused
// assertion (or small group) per `it`, no fakes or injected dependencies
// needed since `parseDuration` is a pure function.
import { describe, expect, it } from "vitest";
import { DurationOverflowError, DurationParseError, MAX_SETTIMEOUT_MS, parseDuration } from "../../../src/util/duration.ts";

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

  // D1 regression: Node's `setTimeout` delay is a signed 32-bit integer
  // internally. A delay past `MAX_SETTIMEOUT_MS` (2**31 - 1 ms, ≈24.8 days)
  // doesn't error in Node -- it silently clamps to a ~1ms timer instead of
  // honoring the requested delay. `parseDuration` must reject it outright
  // rather than hand a consumer (the watchdog wiring in `src/vm/session.ts`,
  // or `corb gc --older-than` in `src/commands/gc.ts`) a value that would
  // silently misbehave three layers downstream.
  describe("overflow guard (MAX_SETTIMEOUT_MS)", () => {
    it("accepts a value safely under the bound", () => {
      expect(parseDuration("24d")).toBe(2_073_600_000);
    });

    it("rejects a value just over the bound -- the original bug's exact repro case", () => {
      expect(() => parseDuration("25d")).toThrow(DurationOverflowError);
    });

    it("rejects an over-bound value regardless of which unit produced it", () => {
      expect(() => parseDuration("600h")).toThrow(DurationOverflowError);
      expect(() => parseDuration("36000m")).toThrow(DurationOverflowError);
    });

    it("treats the bound itself as inclusive: the largest exactly-representable safe value succeeds, the next one overflows", () => {
      expect(parseDuration("2147483s")).toBe(MAX_SETTIMEOUT_MS - 647);
      expect(() => parseDuration("2147484s")).toThrow(DurationOverflowError);
    });

    it("overflow error message states the actual reason and both the precise bound and a human-friendly approximation", () => {
      expect(() => parseDuration("25d")).toThrow(/setTimeout/);
      expect(() => parseDuration("25d")).toThrow(new RegExp(String(MAX_SETTIMEOUT_MS)));
      expect(() => parseDuration("25d")).toThrow(/24\.8 days/);
    });

    it("overflow error carries the offending input and computed ms on the error instance", () => {
      let thrown: unknown;
      try {
        parseDuration("25d");
      } catch (err) {
        thrown = err;
      }
      expect(thrown).toBeInstanceOf(DurationOverflowError);
      expect((thrown as DurationOverflowError).input).toBe("25d");
      expect((thrown as DurationOverflowError).ms).toBe(2_160_000_000);
    });
  });
});
