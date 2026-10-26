import { expect, it } from "vitest";
import { cleanVmOptions, observeOptionsCall } from "../../../e2e/helpers/vm-options.ts";

it("detects an injected marker in provider fields, maps and byte views without printing it", () => {
  const marker = "synthetic-private-registry-marker";
  for (const value of [{ env: { SECRET: marker } }, { provider: new Map([["entry", marker]]) }, { provider: new Set([Buffer.from(marker)]) }, { [marker]: true }]) expect(cleanVmOptions(value, [marker])).toBe(false);
  const provider: { values: Map<string, Buffer>; self?: unknown } = { values: new Map([["large", Buffer.alloc(1024 * 1024)]]) }; provider.self = provider;
  expect(cleanVmOptions({ vfs: { provider }, memory: "1G" }, [marker])).toBe(true);
});
it("bounds traversal and refuses accessors without invoking them", () => {
  let invoked = false; const options = { get env() { invoked = true; return "hidden"; } };
  expect(() => cleanVmOptions(options, ["marker"])).toThrow("accessor"); expect(invoked).toBe(false);
  expect(() => cleanVmOptions(Buffer.alloc(20), ["marker"], { nodes: 10, depth: 10, text: 100, bytes: 10 })).toThrow("bounds");
});
it("preserves the receiver, argument identities and return value at the observed boundary", () => {
  const receiver = {}; const options = {}; const second = {}; const result = Promise.resolve("unchanged"); let observed: unknown;
  const original = function (this: unknown, first: object, next: object) { expect(this).toBe(receiver); expect(first).toBe(options); expect(next).toBe(second); return result; };
  const wrapped = observeOptionsCall(original, (value) => { observed = value; });
  expect(wrapped.call(receiver, options, second)).toBe(result); expect(observed).toBe(options);
});
