// Unit tests for `src/commands/attach.ts` — M8.7. Only `parseAttachArgs` is
// pure and unit-tested here, mirroring `kill.test.ts`'s own
// `parseKillArgs` tests minus the `--force` special case (this command has
// no flags at all — see the M8.7 brief's "explicitly out of scope" list).
// `runAttachCommand` (the one function that touches the real Gondolin
// registry, the real sidecar directory, and — via `runAttachSession` — the
// real socket and terminal) is deliberately not mocked here: it is verified
// by hand against a real running session, see the M8.7 report.
import { describe, expect, it } from "vitest";
import { parseAttachArgs } from "../../../src/commands/attach.ts";

const ID_A = "aaaaaaaa-1111-4111-8111-000000000001";
const ID_B = "bbbbbbbb-2222-4222-8222-000000000002";

describe("commands/attach: parseAttachArgs", () => {
  it("takes exactly one session id", () => {
    expect(parseAttachArgs([ID_A])).toEqual({ session: ID_A });
  });

  it("accepts a prefix", () => {
    expect(parseAttachArgs(["aaaa"])).toEqual({ session: "aaaa" });
  });

  it("requires a session argument", () => {
    expect(() => parseAttachArgs([])).toThrow(/missing required argument <session>/);
  });

  it("rejects a second positional by name", () => {
    expect(() => parseAttachArgs([ID_A, ID_B])).toThrow(new RegExp(`unexpected argument '${ID_B}'`));
  });

  it("rejects an empty session, which would otherwise be a prefix of every id", () => {
    expect(() => parseAttachArgs([""])).toThrow(/must not be empty/);
    expect(() => parseAttachArgs(["   "])).toThrow(/must not be empty/);
  });

  it("rejects an unknown flag", () => {
    expect(() => parseAttachArgs([ID_A, "--nope"])).toThrow();
  });
});
