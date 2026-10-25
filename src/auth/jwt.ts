// `src/auth/jwt.ts` — the two JWT operations host-brokered OAuth needs
// (ADR 0012): reading claims out of a provider's real access token on the
// host, and building the unsigned, JWT-shaped stand-in token the guest gets
// in its place. Neither verifies or creates a signature. Corb never trusts a
// claim for an access decision: the only claim read is an account id that the
// provider's own client (Pi) also reads without verification and sends in a
// plain header.

/** Decodes base64 or base64url text, with or without padding. */
function decodeBase64Any(text: string): Buffer {
  return Buffer.from(text.replace(/-/g, "+").replace(/_/g, "/"), "base64");
}

/**
 * Returns a JWT's payload as a plain object, or `undefined` when `token` is
 * not three dot-separated segments with a JSON-object payload. Accepts both
 * base64url (what real providers issue) and plain base64 (what
 * `buildUnsignedJwt` emits — see there for why).
 */
export function decodeJwtPayload(token: string): Record<string, unknown> | undefined {
  const parts = token.split(".");
  if (parts.length !== 3 || parts[1] === undefined || parts[1] === "") {
    return undefined;
  }
  try {
    const payload: unknown = JSON.parse(decodeBase64Any(parts[1]).toString("utf8"));
    if (typeof payload !== "object" || payload === null || Array.isArray(payload)) {
      return undefined;
    }
    return payload as Record<string, unknown>;
  } catch {
    return undefined;
  }
}

/**
 * Builds an unsigned, JWT-shaped string: `base64(header).base64(payload).signature`,
 * with header `{"alg":"none","typ":"JWT"}` and `signature` used verbatim as
 * the third segment.
 *
 * The first two segments use **standard base64 without padding**, not the
 * base64url that RFC 7519 specifies. Pi 1.4.0 decodes the payload with
 * `atob()` (`extractAccountId` in pi-ai's `openai-codex-responses.js`), and
 * Node's `atob` rejects base64url's `-` and `_` with `InvalidCharacterError`
 * while accepting standard base64 with or without padding. Standard base64
 * is the encoding that always decodes on Pi's side; `decodeJwtPayload` above
 * reads both.
 */
export function buildUnsignedJwt(payload: Record<string, unknown>, signature: string): string {
  const encode = (value: unknown): string => Buffer.from(JSON.stringify(value), "utf8").toString("base64").replace(/=+$/, "");
  return `${encode({ alg: "none", typ: "JWT" })}.${encode(payload)}.${signature}`;
}
