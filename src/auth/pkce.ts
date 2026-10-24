// `src/auth/pkce.ts` — PKCE (RFC 7636) and OAuth `state` helpers for the
// host-side login flows in `src/auth/providers/` (ADR 0012). Written for
// corb rather than imported from Pi's `pi-ai` package, which is not a corb
// dependency; the shape matches Pi's own `pkce.js` (32 random bytes,
// base64url verifier, S256 challenge) so a provider sees the same kind of
// request from either client.
import { createHash, randomBytes } from "node:crypto";

export interface Pkce {
  verifier: string;
  challenge: string;
}

/** The S256 code challenge for `verifier`: base64url(SHA-256(verifier)), no padding. */
export function pkceChallenge(verifier: string): string {
  return createHash("sha256").update(verifier).digest("base64url");
}

/** A fresh PKCE pair: a 43-character base64url verifier (32 random bytes) and its S256 challenge. */
export function generatePkce(): Pkce {
  const verifier = randomBytes(32).toString("base64url");
  return { verifier, challenge: pkceChallenge(verifier) };
}

/** A fresh OAuth `state` value: 16 random bytes, hex-encoded. */
export function createOAuthState(): string {
  return randomBytes(16).toString("hex");
}
