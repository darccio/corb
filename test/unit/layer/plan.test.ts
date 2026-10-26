import { expect, it } from "vitest";
import { assertPackageIdentities, parseInstalledIdentities, parsePackagePlan } from "../../../src/layer/plan.ts";
import { pins } from "./fixtures.ts";
const existing = parseInstalledIdentities(`P:musl\nV:1.2.4-r0\nA:x86_64\nC:base\nD:so:libc\np:so:libc=1\n`);
it("allows a smaller actual addition set with an existing compatible provider", () => {
  const additions = parsePackagePlan("(1/1) Installing go (1.26.0-r0)\nOK: 500 MiB in 2 packages", existing, pins());
  expect(additions.map((pkg) => pkg.name)).toEqual(["go"]); expect(pins().package).toHaveLength(2);
  const after = parseInstalledIdentities(`P:musl\nV:1.2.4-r0\nA:x86_64\nC:base\nD:so:libc\np:so:libc=1\nF:lib\nR:new-owner\n\nP:go\nV:1.26.0-r0\nA:x86_64\nC:${additions[0]!["apkindex-checksum"]}\n`);
  expect(() => assertPackageIdentities(existing, after, additions)).not.toThrow();
});
it.each(["Upgrading", "Downgrading", "Reinstalling", "Purging", "Replacing", "Unknown"])("rejects %s operations", (operation) => {
  expect(() => parsePackagePlan(`(1/1) ${operation} musl (1.2.5-r0)`, existing, pins())).toThrow();
});
it.each(["(1/1) Installing unknown (1-r0)", "(1/1) Installing go (2-r0)", "(1/2) Installing go (1.26.0-r0)", "(2/2) Installing go (1.26.0-r0)", "warning: ignored operation", "(1/1) Installing go (1.26.0-r0) trailing"])("rejects incomplete or unknown plan %s", (output) => {
  expect(() => parsePackagePlan(output, existing, pins())).toThrow();
});
it("permits an already installed exact request and no transaction", () => { expect(parsePackagePlan("OK: 100 MiB in 1 packages", existing, pins())).toEqual([]); });
it("rejects changed base dependency and provider identities", () => {
  expect(() => assertPackageIdentities(existing, [{ ...existing[0]!, D: "changed" }], [])).toThrow("base package");
  expect(() => assertPackageIdentities(existing, [], [])).toThrow("missing or extra");
});
