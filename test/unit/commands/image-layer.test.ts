import { expect, it } from "vitest";
import { parseLayerCommandArgs } from "../../../src/commands/image-layer.ts";
it("accepts explicit workspace without a positional directory", () => { expect(parseLayerCommandArgs(["--workspace", "named"]).workspace).toBe("named"); });
it.each([["extra"], ["--unknown"], ["--workspace"], ["--dir", "x"]])("rejects unknown pin input %j", (args) => { expect(() => parseLayerCommandArgs(args)).toThrow(); });
it("permits only the declared transport options and one push destination", () => {
  expect(parseLayerCommandArgs(["registry.example/repo:tag", "--ca-file", "ca", "--registry-config", "auth"], { transport: true, destination: true })).toMatchObject({ destination: "registry.example/repo:tag", caFile: "ca", registryConfig: "auth" });
  expect(() => parseLayerCommandArgs(["one", "two"], { transport: true, destination: true })).toThrow();
  expect(() => parseLayerCommandArgs(["--ca-file", "ca"])).toThrow();
});
