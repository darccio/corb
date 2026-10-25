// Unit tests for `src/auth/providers/openai-codex.ts`: the authorize URL,
// token exchange and refresh (mocked `fetch`), account-id extraction, the
// device-code flow, and the guest stand-in credential. No network.
import { describe, expect, it } from "vitest";
import { buildUnsignedJwt } from "../../../../src/auth/jwt.ts";
import type { LoginIO } from "../../../../src/auth/provider.ts";
import {
  AUTHORIZE_URL,
  CLIENT_ID,
  CodexTokenError,
  DEVICE_REDIRECT_URI,
  DEVICE_TOKEN_URL,
  DEVICE_USER_CODE_URL,
  JWT_CLAIM_PATH,
  REDIRECT_URI,
  SCOPE,
  STAND_IN_EXPIRES,
  STAND_IN_REFRESH,
  TOKEN_URL,
  buildAuthorizeUrl,
  buildStandInAccessToken,
  exchangeAuthorizationCode,
  extractAccountId,
  openaiCodexProvider,
  pollDeviceAuth,
  refreshAccessToken,
  startDeviceAuth,
} from "../../../../src/auth/providers/openai-codex.ts";
import { CREDENTIAL_FILE_VERSION, type StoredCredential } from "../../../../src/auth/store.ts";

/** A real-looking (base64url, signed-shaped) access token carrying `accountId`. */
function accessToken(accountId: string | undefined): string {
  const enc = (value: unknown): string => Buffer.from(JSON.stringify(value)).toString("base64url");
  const claims = accountId === undefined ? {} : { [JWT_CLAIM_PATH]: { chatgpt_account_id: accountId } };
  return `${enc({ alg: "RS256" })}.${enc({ sub: "user", ...claims })}.signature`;
}

interface Call {
  url: string;
  init: RequestInit | undefined;
}

/** A `fetch` that answers each call with the next response in `responses` and records the calls. */
function scriptedFetch(responses: Response[]): { fetch: typeof fetch; calls: Call[] } {
  const calls: Call[] = [];
  const queue = [...responses];
  const fetchImpl = (async (input: string | URL | Request, init?: RequestInit) => {
    calls.push({ url: String(input), init });
    const next = queue.shift();
    if (next === undefined) {
      throw new Error("unexpected fetch");
    }
    return next;
  }) as typeof fetch;
  return { fetch: fetchImpl, calls };
}

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
}

function formBody(call: Call): URLSearchParams {
  return new URLSearchParams(String(call.init?.body));
}

function storedCredential(overrides: Partial<StoredCredential> = {}): StoredCredential {
  return {
    version: CREDENTIAL_FILE_VERSION,
    provider: "openai-codex",
    type: "oauth",
    access: accessToken("acct-1"),
    refresh: "refresh-1",
    expires: 1_900_000_000_000,
    accountId: "acct-1",
    updatedAt: "2026-10-24T00:00:00.000Z",
    ...overrides,
  };
}

describe("openai-codex authorize URL", () => {
  it("carries the same parameters Pi sends", () => {
    const url = new URL(buildAuthorizeUrl("challenge-1", "state-1"));
    expect(`${url.origin}${url.pathname}`).toBe(AUTHORIZE_URL);
    expect(Object.fromEntries(url.searchParams)).toEqual({
      response_type: "code",
      client_id: CLIENT_ID,
      redirect_uri: REDIRECT_URI,
      scope: SCOPE,
      code_challenge: "challenge-1",
      code_challenge_method: "S256",
      state: "state-1",
      id_token_add_organizations: "true",
      codex_cli_simplified_flow: "true",
      originator: "pi",
    });
  });
});

describe("openai-codex extractAccountId", () => {
  it("reads the ChatGPT account id claim", () => {
    expect(extractAccountId(accessToken("acct-9"))).toBe("acct-9");
  });

  it("returns undefined when the claim or the token shape is missing", () => {
    expect(extractAccountId(accessToken(undefined))).toBeUndefined();
    expect(extractAccountId("not-a-jwt")).toBeUndefined();
  });
});

describe("openai-codex token requests", () => {
  it("exchanges an authorization code", async () => {
    const access = accessToken("acct-1");
    const { fetch, calls } = scriptedFetch([json({ access_token: access, refresh_token: "r1", expires_in: 3600 })]);
    const before = Date.now();
    const tokens = await exchangeAuthorizationCode(fetch, "code-1", "verifier-1", REDIRECT_URI);
    expect(tokens).toMatchObject({ access, refresh: "r1", accountId: "acct-1" });
    expect(tokens.expires).toBeGreaterThanOrEqual(before + 3_600_000);
    expect(calls[0]?.url).toBe(TOKEN_URL);
    expect(calls[0]?.init?.method).toBe("POST");
    expect(Object.fromEntries(formBody(calls[0]!))).toEqual({
      grant_type: "authorization_code",
      client_id: CLIENT_ID,
      code: "code-1",
      code_verifier: "verifier-1",
      redirect_uri: REDIRECT_URI,
    });
  });

  it("refreshes, keeping the old refresh token when none is returned", async () => {
    const { fetch, calls } = scriptedFetch([json({ access_token: accessToken("acct-1"), expires_in: 60 })]);
    const tokens = await refreshAccessToken(fetch, "old-refresh");
    expect(tokens.refresh).toBe("old-refresh");
    expect(Object.fromEntries(formBody(calls[0]!))).toEqual({ grant_type: "refresh_token", refresh_token: "old-refresh", client_id: CLIENT_ID });
  });

  it("uses a rotated refresh token when one is returned", async () => {
    const { fetch } = scriptedFetch([json({ access_token: accessToken("acct-1"), refresh_token: "new-refresh", expires_in: 60 })]);
    expect((await refreshAccessToken(fetch, "old-refresh")).refresh).toBe("new-refresh");
  });

  it("reports an HTTP error without echoing any token", async () => {
    const { fetch } = scriptedFetch([json({ error: "invalid_grant" }, 400)]);
    const error = await refreshAccessToken(fetch, "secret-refresh").catch((err: unknown) => err);
    expect(error).toBeInstanceOf(CodexTokenError);
    expect(String(error)).toMatch(/HTTP 400/);
    expect(String(error)).toMatch(/invalid_grant/);
    expect(String(error)).not.toContain("secret-refresh");
  });

  it("wraps a network failure", async () => {
    const failing = (async () => {
      throw new Error("ECONNRESET");
    }) as typeof fetch;
    await expect(refreshAccessToken(failing, "r")).rejects.toThrow(/refresh request failed: ECONNRESET/);
  });

  it("rejects a success response with missing fields, without echoing the body", async () => {
    const { fetch } = scriptedFetch([json({ access_token: "secret-access" })]);
    const error = await exchangeAuthorizationCode(fetch, "c", "v", REDIRECT_URI).catch((err: unknown) => err);
    expect(String(error)).toMatch(/missing access_token, refresh_token or expires_in/);
    expect(String(error)).not.toContain("secret-access");
  });

  it("rejects an access token without a ChatGPT account id", async () => {
    const { fetch } = scriptedFetch([json({ access_token: accessToken(undefined), refresh_token: "r", expires_in: 60 })]);
    await expect(exchangeAuthorizationCode(fetch, "c", "v", REDIRECT_URI)).rejects.toThrow(/without a ChatGPT account id/);
  });
});

describe("openai-codex device code login", () => {
  function deviceIO(fetchImpl: typeof fetch, clock = { t: 0 }): LoginIO {
    return {
      print: () => {},
      readLine: () => new Promise(() => {}),
      fetch: fetchImpl,
      now: () => clock.t,
      sleep: async (ms) => {
        clock.t += ms;
      },
    };
  }

  it("starts a device login, accepting a string interval", async () => {
    const { fetch, calls } = scriptedFetch([json({ device_auth_id: "d1", user_code: "ABCD-EFGH", interval: "5" })]);
    expect(await startDeviceAuth(fetch)).toEqual({ deviceAuthId: "d1", userCode: "ABCD-EFGH", intervalMs: 5000 });
    expect(calls[0]?.url).toBe(DEVICE_USER_CODE_URL);
    expect(JSON.parse(String(calls[0]?.init?.body))).toEqual({ client_id: CLIENT_ID });
  });

  it("explains a 404 as device login not being enabled", async () => {
    const { fetch } = scriptedFetch([new Response("", { status: 404 })]);
    await expect(startDeviceAuth(fetch)).rejects.toThrow(/not enabled/);
  });

  it("polls until approved, treating 403/404 and authorization_pending as not yet", async () => {
    const { fetch, calls } = scriptedFetch([
      new Response("", { status: 403 }),
      json({ error: { code: "deviceauth_authorization_pending" } }, 400),
      new Response("", { status: 404 }),
      json({ authorization_code: "ac", code_verifier: "cv" }),
    ]);
    const result = await pollDeviceAuth(deviceIO(fetch), { deviceAuthId: "d1", userCode: "U", intervalMs: 1000 });
    expect(result).toEqual({ authorizationCode: "ac", codeVerifier: "cv" });
    expect(calls).toHaveLength(4);
    expect(calls.every((call) => call.url === DEVICE_TOKEN_URL)).toBe(true);
  });

  it("slows down when asked to", async () => {
    const clock = { t: 0 };
    const { fetch } = scriptedFetch([json({ error: "slow_down" }, 400), json({ authorization_code: "ac", code_verifier: "cv" })]);
    await pollDeviceAuth(deviceIO(fetch, clock), { deviceAuthId: "d1", userCode: "U", intervalMs: 1000 });
    expect(clock.t).toBe(6000);
  });

  it("fails on any other error", async () => {
    const { fetch } = scriptedFetch([json({ error: { code: "expired_token" } }, 400)]);
    await expect(pollDeviceAuth(deviceIO(fetch), { deviceAuthId: "d1", userCode: "U", intervalMs: 1000 })).rejects.toThrow(/expired_token/);
  });

  it("times out after 15 minutes", async () => {
    const pending = Array.from({ length: 2000 }, () => new Response("", { status: 403 }));
    const { fetch } = scriptedFetch(pending);
    await expect(pollDeviceAuth(deviceIO(fetch), { deviceAuthId: "d1", userCode: "U", intervalMs: 1000 })).rejects.toThrow(/timed out/);
  });

  it("runs the whole device flow through the provider and exchanges with the device redirect URI", async () => {
    const access = accessToken("acct-2");
    const { fetch, calls } = scriptedFetch([
      json({ device_auth_id: "d1", user_code: "U", interval: 1 }),
      json({ authorization_code: "ac", code_verifier: "cv" }),
      json({ access_token: access, refresh_token: "r", expires_in: 60 }),
    ]);
    const lines: string[] = [];
    const io = { ...deviceIO(fetch), print: (line: string) => lines.push(line) };
    const tokens = await openaiCodexProvider.login("device-code", io);
    expect(tokens.accountId).toBe("acct-2");
    expect(lines.join("\n")).toContain("U");
    expect(formBody(calls[2]!).get("redirect_uri")).toBe(DEVICE_REDIRECT_URI);
  });
});

describe("openai-codex guest stand-in", () => {
  it("builds a stand-in that carries only the account id and the marker", () => {
    const token = buildStandInAccessToken("acct-1", "m1");
    const payload = JSON.parse(Buffer.from(token.split(".")[1]!, "base64").toString()) as Record<string, unknown>;
    expect(payload).toEqual({ [JWT_CLAIM_PATH]: { chatgpt_account_id: "acct-1" }, corb: { stand_in: true, marker: "m1" } });
  });

  it("builds Pi's auth.json entry with a dummy refresh token and a far-future expiry", () => {
    const credential = storedCredential();
    const guest = openaiCodexProvider.buildGuestCredential(credential, "marker-1");
    expect(guest.piAuthEntry).toEqual({
      type: "oauth",
      access: guest.standIn,
      refresh: STAND_IN_REFRESH,
      expires: STAND_IN_EXPIRES,
      accountId: "acct-1",
    });
    expect(JSON.stringify(guest)).not.toContain(credential.access);
    expect(JSON.stringify(guest)).not.toContain(credential.refresh);
    expect(extractAccountId(guest.standIn)).toBe("acct-1");
  });

  it("makes each session's stand-in distinct", () => {
    const credential = storedCredential();
    expect(openaiCodexProvider.buildGuestCredential(credential, "a").standIn).not.toBe(
      openaiCodexProvider.buildGuestCredential(credential, "b").standIn,
    );
  });

  it("falls back to the access token's claim when accountId is not stored", () => {
    const { accountId: _omit, ...rest } = storedCredential();
    expect(openaiCodexProvider.buildGuestCredential(rest as StoredCredential, "m").piAuthEntry.accountId).toBe("acct-1");
  });

  it("refuses a stored login with no account id at all", () => {
    const { accountId: _omit, ...rest } = storedCredential({ access: buildUnsignedJwt({}, "x") });
    expect(() => openaiCodexProvider.buildGuestCredential(rest as StoredCredential, "m")).toThrow(/no ChatGPT account id/);
  });

  it("asks Pi for SSE only when WebSockets are blocked", () => {
    expect(openaiCodexProvider.guestPiSettings({ websockets: false })).toEqual({ transport: "sse" });
    expect(openaiCodexProvider.guestPiSettings({ websockets: true })).toEqual({});
  });

  it("rewrites only on chatgpt.com", () => {
    expect(openaiCodexProvider.apiHosts).toEqual(["chatgpt.com"]);
  });
});
