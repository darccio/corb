import { describe, expect, it } from "vitest";
import { run, STUB_MESSAGE } from "../../src/cli.ts";

describe("cli", () => {
  it("returns the not-yet-implemented stub message", () => {
    expect(run([])).toBe(STUB_MESSAGE);
    expect(STUB_MESSAGE).toContain("corb");
  });
});
