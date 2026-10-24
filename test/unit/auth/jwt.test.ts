// Unit tests for `src/auth/jwt.ts`. The load-bearing property is that a
// stand-in built here decodes the way Pi 1.4.0 decodes an access token
// (`extractAccountId` in pi-ai's `openai-codex-responses.js`:
// `JSON.parse(atob(token.split(".")[1]))`), so `piExtractAccountId` below
// copies that expression rather than reusing corb's own decoder.
import { describe, expect, it } from "vitest";
import { buildUnsignedJwt, decodeJwtPayload } from "../../../src/auth/jwt.ts";

const CLAIM = "https://api.openai.com/auth";

function piExtractAccountId(token: string): unknown {
  const parts = token.split(".");
  if (parts.length !== 3) {
    throw new Error("Invalid token");
  }
  const payload = JSON.parse(atob(parts[1]!)) as Record<string, { chatgpt_account_id?: unknown } | undefined>;
  return payload[CLAIM]?.chatgpt_account_id;
}

function base64url(value: unknown): string {
  return Buffer.from(JSON.stringify(value)).toString("base64url");
}

describe("auth/jwt", () => {
  it("decodes a base64url payload, as real providers issue", () => {
    const token = `${base64url({ alg: "RS256" })}.${base64url({ sub: "u", n: "~~~???" })}.sig`;
    expect(decodeJwtPayload(token)).toEqual({ sub: "u", n: "~~~???" });
  });

  it("returns undefined for anything that is not a three-part token with an object payload", () => {
    expect(decodeJwtPayload("")).toBeUndefined();
    expect(decodeJwtPayload("a.b")).toBeUndefined();
    expect(decodeJwtPayload("a..c")).toBeUndefined();
    expect(decodeJwtPayload("a.!!!.c")).toBeUndefined();
    expect(decodeJwtPayload(`a.${base64url([1, 2])}.c`)).toBeUndefined();
    expect(decodeJwtPayload(`a.${base64url("text")}.c`)).toBeUndefined();
  });

  it("builds an unsigned token that corb's decoder reads back", () => {
    const token = buildUnsignedJwt({ hello: "world" }, "sig");
    const [header, , signature] = token.split(".");
    expect(JSON.parse(Buffer.from(header!, "base64").toString())).toEqual({ alg: "none", typ: "JWT" });
    expect(signature).toBe("sig");
    expect(decodeJwtPayload(token)).toEqual({ hello: "world" });
  });

  it("builds a token that Pi's atob-based decoder reads, even where base64url would differ", () => {
    // Values chosen so the standard-base64 payload contains '+' and '/',
    // the characters base64url would turn into '-' and '_' (which atob rejects).
    for (const accountId of ["acct-~~~>>>???", "a?b>c~d", "12345678-aaaa-bbbb-cccc-1234567890ab"]) {
      const token = buildUnsignedJwt({ [CLAIM]: { chatgpt_account_id: accountId } }, "x");
      expect(piExtractAccountId(token)).toBe(accountId);
    }
  });

  it("emits no '=' padding in the encoded segments", () => {
    const token = buildUnsignedJwt({ a: 1 }, "s");
    expect(token.split(".").slice(0, 2).join("")).not.toContain("=");
  });
});
