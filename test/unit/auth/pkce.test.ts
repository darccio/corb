// Unit tests for `src/auth/pkce.ts`.
import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import { createOAuthState, generatePkce, pkceChallenge } from "../../../src/auth/pkce.ts";

describe("auth/pkce", () => {
  it("computes the RFC 7636 appendix B S256 challenge", () => {
    expect(pkceChallenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk")).toBe("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM");
  });

  it("generates a 43-character base64url verifier whose challenge matches", () => {
    const { verifier, challenge } = generatePkce();
    expect(verifier).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(challenge).toBe(createHash("sha256").update(verifier).digest("base64url"));
  });

  it("generates fresh values each time", () => {
    expect(generatePkce().verifier).not.toBe(generatePkce().verifier);
    expect(createOAuthState()).not.toBe(createOAuthState());
  });

  it("generates a 32-character hex state", () => {
    expect(createOAuthState()).toMatch(/^[0-9a-f]{32}$/);
  });
});
