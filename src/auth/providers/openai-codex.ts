// `src/auth/providers/openai-codex.ts` — host-brokered login for Pi's
// `openai-codex` provider: a ChatGPT Plus/Pro subscription used through the
// Codex backend at `https://chatgpt.com/backend-api` (ADR 0012).
//
// Mirrors Pi 1.4.0's own implementation
// (`@earendil-works/pi-ai/dist/auth/oauth/openai-codex.js`): the same public
// OAuth client id, endpoints, scope, redirect URI, PKCE + state, and the same
// device-code endpoints. It is corb's own code, not an import: `pi-ai` is
// not a corb dependency, and this runs on the host where Pi is not installed.
//
// What Pi does with the result, confirmed against Pi 1.4.0's source:
//
// - `auth.json` holds `{"openai-codex": {"type": "oauth", "access", "refresh",
//   "expires", "accountId"}}` (`dist/core/auth-storage.js` validates `type`,
//   the two strings and a finite `expires`; `accountId` is written by Pi's
//   login but never read back).
// - Pi refreshes only when `Date.now() >= expires` (pi-ai `models.js`) or
//   within five minutes of it (pi-ai `auth/resolve.js`). It never inspects
//   the JWT's own `exp` and never verifies a signature.
// - Each request derives the account id from the access token with
//   `JSON.parse(atob(token.split(".")[1]))["https://api.openai.com/auth"].chatgpt_account_id`
//   (`extractAccountId`), then sends `Authorization: Bearer <access>` and
//   `chatgpt-account-id: <id>` to `chatgpt.com`.
//
// So the guest's stand-in is an unsigned JWT-shaped string whose payload
// carries only the real account id and a per-session marker, with a dummy
// refresh token and a far-future `expires`. The host swaps it for the real
// access token on HTTPS requests to `chatgpt.com` only.
import { buildUnsignedJwt, decodeJwtPayload } from "../jwt.ts";
import { createOAuthState, generatePkce } from "../pkce.ts";
import { startCallbackServer, waitForAuthorizationCode, type CallbackServer } from "../callback.ts";
import type { BrokeredProvider, GuestCredential, LoginIO, LoginMethod, TokenSet } from "../provider.ts";
import type { StoredCredential } from "../store.ts";

export const CLIENT_ID = "app_EMoamEEZ73f0CkXaXp7hrann";
export const AUTH_BASE_URL = "https://auth.openai.com";
export const AUTHORIZE_URL = `${AUTH_BASE_URL}/oauth/authorize`;
export const TOKEN_URL = `${AUTH_BASE_URL}/oauth/token`;
export const REDIRECT_URI = "http://localhost:1455/auth/callback";
export const SCOPE = "openid profile email offline_access";
export const DEVICE_USER_CODE_URL = `${AUTH_BASE_URL}/api/accounts/deviceauth/usercode`;
export const DEVICE_TOKEN_URL = `${AUTH_BASE_URL}/api/accounts/deviceauth/token`;
export const DEVICE_VERIFICATION_URI = `${AUTH_BASE_URL}/codex/device`;
export const DEVICE_REDIRECT_URI = `${AUTH_BASE_URL}/deviceauth/callback`;
export const JWT_CLAIM_PATH = "https://api.openai.com/auth";
/** The one host Pi's Codex client sends the access token to. */
export const CODEX_API_HOST = "chatgpt.com";

const CALLBACK_HOST = "127.0.0.1";
const CALLBACK_PORT = 1455;
const CALLBACK_PATH = "/auth/callback";
const DEVICE_CODE_TIMEOUT_MS = 15 * 60 * 1000;
const MIN_POLL_INTERVAL_MS = 1000;
/** Bounds each token request, so a refresh never holds the credential lock for long (see `src/auth/store.ts`). */
const TOKEN_REQUEST_TIMEOUT_MS = 30_000;
/**
 * The stand-in's `expires`: 2100-01-01T00:00:00Z. Far enough that Pi never
 * decides to refresh it during any session, and a plain finite number, which
 * is all Pi's `auth.json` validation requires.
 */
export const STAND_IN_EXPIRES = Date.UTC(2100, 0, 1);
/** The stand-in's refresh token. Never valid anywhere; Pi never uses it because `expires` is far away. */
export const STAND_IN_REFRESH = "corb-host-brokered-refresh-token-not-valid";

/** Builds the browser authorization URL, with the same parameters Pi sends. */
export function buildAuthorizeUrl(challenge: string, state: string): string {
  const url = new URL(AUTHORIZE_URL);
  url.searchParams.set("response_type", "code");
  url.searchParams.set("client_id", CLIENT_ID);
  url.searchParams.set("redirect_uri", REDIRECT_URI);
  url.searchParams.set("scope", SCOPE);
  url.searchParams.set("code_challenge", challenge);
  url.searchParams.set("code_challenge_method", "S256");
  url.searchParams.set("state", state);
  url.searchParams.set("id_token_add_organizations", "true");
  url.searchParams.set("codex_cli_simplified_flow", "true");
  url.searchParams.set("originator", "pi");
  return url.toString();
}

/** The ChatGPT account id from an access token's claims, or `undefined` when absent. */
export function extractAccountId(accessToken: string): string | undefined {
  const auth = decodeJwtPayload(accessToken)?.[JWT_CLAIM_PATH];
  if (typeof auth !== "object" || auth === null) {
    return undefined;
  }
  const accountId = (auth as Record<string, unknown>).chatgpt_account_id;
  return typeof accountId === "string" && accountId.length > 0 ? accountId : undefined;
}

/**
 * The guest's stand-in access token: an unsigned JWT-shaped string that Pi's
 * `extractAccountId` can read the real account id from, plus `marker` so it
 * is unique to one session. Contains nothing secret.
 */
export function buildStandInAccessToken(accountId: string, marker: string): string {
  return buildUnsignedJwt(
    {
      [JWT_CLAIM_PATH]: { chatgpt_account_id: accountId },
      corb: { stand_in: true, marker },
    },
    `corb-stand-in-${marker}`,
  );
}

/** Thrown for a failed token request. Never includes a token value. */
export class CodexTokenError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "CodexTokenError";
  }
}

function withTimeout(signal: AbortSignal | undefined): AbortSignal {
  const timeout = AbortSignal.timeout(TOKEN_REQUEST_TIMEOUT_MS);
  return signal === undefined ? timeout : AbortSignal.any([signal, timeout]);
}

/**
 * Reads a token endpoint response into a `TokenSet`. An error response's body
 * is included (OpenAI returns a short JSON error there); a success body is
 * never echoed, because it holds tokens. A response with no new refresh token
 * keeps `previousRefresh` (RFC 6749 §6 allows omitting it); Pi treats that as
 * an error, which is stricter than the spec requires.
 */
async function readTokenResponse(response: Response, operation: string, previousRefresh?: string, now: () => number = Date.now): Promise<TokenSet> {
  if (!response.ok) {
    const text = await response.text().catch(() => "");
    throw new CodexTokenError(`OpenAI Codex token ${operation} failed (HTTP ${response.status})${text ? `: ${text.slice(0, 500)}` : ""}`);
  }
  let json: Record<string, unknown>;
  try {
    json = (await response.json()) as Record<string, unknown>;
  } catch {
    throw new CodexTokenError(`OpenAI Codex token ${operation} returned a response that is not JSON`);
  }
  const access = json.access_token;
  const refresh = typeof json.refresh_token === "string" && json.refresh_token !== "" ? json.refresh_token : previousRefresh;
  const expiresIn = json.expires_in;
  if (typeof access !== "string" || access === "" || refresh === undefined || typeof expiresIn !== "number") {
    throw new CodexTokenError(`OpenAI Codex token ${operation} response is missing access_token, refresh_token or expires_in`);
  }
  const accountId = extractAccountId(access);
  if (accountId === undefined) {
    throw new CodexTokenError(`OpenAI Codex token ${operation} returned an access token without a ChatGPT account id`);
  }
  return { access, refresh, expires: now() + expiresIn * 1000, accountId };
}

/** Exchanges an authorization code (from the browser or device flow) for tokens. */
export async function exchangeAuthorizationCode(
  fetchImpl: typeof fetch,
  code: string,
  verifier: string,
  redirectUri: string,
  signal?: AbortSignal,
): Promise<TokenSet> {
  const response = await fetchImpl(TOKEN_URL, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "authorization_code",
      client_id: CLIENT_ID,
      code,
      code_verifier: verifier,
      redirect_uri: redirectUri,
    }),
    signal: withTimeout(signal),
  });
  return readTokenResponse(response, "exchange");
}

/** Exchanges a refresh token for a new token set. */
export async function refreshAccessToken(fetchImpl: typeof fetch, refreshToken: string, signal?: AbortSignal): Promise<TokenSet> {
  let response: Response;
  try {
    response = await fetchImpl(TOKEN_URL, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "refresh_token",
        refresh_token: refreshToken,
        client_id: CLIENT_ID,
      }),
      signal: withTimeout(signal),
    });
  } catch (err) {
    throw new CodexTokenError(`OpenAI Codex token refresh request failed: ${err instanceof Error ? err.message : String(err)}`);
  }
  return readTokenResponse(response, "refresh", refreshToken);
}

async function loginWithBrowser(io: LoginIO): Promise<TokenSet> {
  const { verifier, challenge } = generatePkce();
  const state = createOAuthState();
  const url = buildAuthorizeUrl(challenge, state);

  let callback: CallbackServer | undefined;
  try {
    callback = await startCallbackServer({ host: CALLBACK_HOST, port: CALLBACK_PORT, path: CALLBACK_PATH, state, providerName: "OpenAI" });
  } catch (err) {
    io.print(
      `Could not listen on ${CALLBACK_HOST}:${CALLBACK_PORT} (${err instanceof Error ? err.message : String(err)}). ` +
        "After signing in, paste the URL your browser lands on.",
    );
  }

  io.print("Open this URL in a browser and sign in with your ChatGPT account:");
  io.print("");
  io.print(`  ${url}`);
  io.print("");
  io.print(
    callback !== undefined
      ? "Waiting for the browser to return here. If it runs on another machine, paste the URL it lands on (it starts with http://localhost:1455/) and press Enter."
      : "Paste the URL the browser lands on (it starts with http://localhost:1455/) and press Enter.",
  );
  io.openUrl?.(url);

  try {
    const code = await waitForAuthorizationCode({ callback, readLine: io.readLine, state });
    return await exchangeAuthorizationCode(io.fetch, code, verifier, REDIRECT_URI);
  } finally {
    callback?.close();
  }
}

interface DeviceAuth {
  deviceAuthId: string;
  userCode: string;
  intervalMs: number;
}

/** Starts a device-code login. Exported for tests. */
export async function startDeviceAuth(fetchImpl: typeof fetch): Promise<DeviceAuth> {
  const response = await fetchImpl(DEVICE_USER_CODE_URL, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ client_id: CLIENT_ID }),
    signal: withTimeout(undefined),
  });
  if (!response.ok) {
    if (response.status === 404) {
      throw new CodexTokenError("OpenAI Codex device code login is not enabled for this account. Use the browser login instead.");
    }
    const text = await response.text().catch(() => "");
    throw new CodexTokenError(`OpenAI Codex device code request failed (HTTP ${response.status})${text ? `: ${text.slice(0, 500)}` : ""}`);
  }
  const json = (await response.json()) as Record<string, unknown>;
  const rawInterval = json.interval;
  const intervalSeconds = typeof rawInterval === "string" ? Number(rawInterval.trim()) : rawInterval;
  if (
    typeof json.device_auth_id !== "string" ||
    typeof json.user_code !== "string" ||
    typeof intervalSeconds !== "number" ||
    !Number.isFinite(intervalSeconds) ||
    intervalSeconds < 0
  ) {
    throw new CodexTokenError("OpenAI Codex device code response is missing device_auth_id, user_code or interval");
  }
  return {
    deviceAuthId: json.device_auth_id,
    userCode: json.user_code,
    intervalMs: Math.max(MIN_POLL_INTERVAL_MS, Math.floor(intervalSeconds * 1000)),
  };
}

/** Polls a device-code login until the user approves it. Exported for tests. */
export async function pollDeviceAuth(io: LoginIO, device: DeviceAuth): Promise<{ authorizationCode: string; codeVerifier: string }> {
  const now = io.now ?? Date.now;
  const sleep = io.sleep ?? ((ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms)));
  const deadline = now() + DEVICE_CODE_TIMEOUT_MS;
  let intervalMs = device.intervalMs;
  while (now() < deadline) {
    const response = await io.fetch(DEVICE_TOKEN_URL, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ device_auth_id: device.deviceAuthId, user_code: device.userCode }),
      signal: withTimeout(undefined),
    });
    if (response.ok) {
      const json = (await response.json()) as Record<string, unknown>;
      if (typeof json.authorization_code !== "string" || typeof json.code_verifier !== "string") {
        throw new CodexTokenError("OpenAI Codex device auth response is missing authorization_code or code_verifier");
      }
      return { authorizationCode: json.authorization_code, codeVerifier: json.code_verifier };
    }
    // 403/404 mean "not approved yet" on this endpoint, as Pi treats them.
    if (response.status !== 403 && response.status !== 404) {
      const text = await response.text().catch(() => "");
      let errorCode: unknown;
      try {
        const error = (JSON.parse(text) as { error?: unknown }).error;
        errorCode = typeof error === "object" && error !== null ? (error as { code?: unknown }).code : error;
      } catch {
        errorCode = undefined;
      }
      if (errorCode === "slow_down") {
        intervalMs += 5000;
      } else if (errorCode !== "deviceauth_authorization_pending") {
        throw new CodexTokenError(`OpenAI Codex device auth failed (HTTP ${response.status})${text ? `: ${text.slice(0, 500)}` : ""}`);
      }
    }
    await sleep(Math.min(intervalMs, Math.max(0, deadline - now())));
  }
  throw new CodexTokenError("OpenAI Codex device code login timed out. Run 'corb login openai-codex --device-code' again.");
}

async function loginWithDeviceCode(io: LoginIO): Promise<TokenSet> {
  const device = await startDeviceAuth(io.fetch);
  io.print(`Open ${DEVICE_VERIFICATION_URI} in any browser and enter this code:`);
  io.print("");
  io.print(`  ${device.userCode}`);
  io.print("");
  io.print("Waiting for approval (up to 15 minutes)...");
  const code = await pollDeviceAuth(io, device);
  return exchangeAuthorizationCode(io.fetch, code.authorizationCode, code.codeVerifier, DEVICE_REDIRECT_URI);
}

/** Builds the guest's `auth.json` entry and stand-in token. Exported for tests through `openaiCodexProvider`. */
function buildGuestCredential(credential: StoredCredential, marker: string): GuestCredential {
  const accountId = credential.accountId ?? extractAccountId(credential.access);
  if (accountId === undefined) {
    throw new CodexTokenError("stored OpenAI Codex login has no ChatGPT account id. Run 'corb login openai-codex' again.");
  }
  const standIn = buildStandInAccessToken(accountId, marker);
  return {
    standIn,
    piAuthEntry: {
      type: "oauth",
      access: standIn,
      refresh: STAND_IN_REFRESH,
      expires: STAND_IN_EXPIRES,
      accountId,
    },
  };
}

export const openaiCodexProvider: BrokeredProvider = {
  id: "openai-codex",
  displayName: "OpenAI Codex (ChatGPT Plus/Pro)",
  loginMethods: ["browser", "device-code"],
  async login(method: LoginMethod, io: LoginIO): Promise<TokenSet> {
    return method === "device-code" ? loginWithDeviceCode(io) : loginWithBrowser(io);
  },
  refresh: (refreshToken, fetchImpl, signal) => refreshAccessToken(fetchImpl, refreshToken, signal),
  apiHosts: [CODEX_API_HOST],
  buildGuestCredential,
  // Pi's Codex client tries a WebSocket first (`transport: "auto"`). With
  // `egress.websockets = false` (corb's default), Gondolin answers the
  // upgrade with 501 before any hook runs; Pi then falls back to SSE, but
  // also attaches a transport-failure diagnostic to the first reply of each
  // session. Asking for SSE up front skips that dead attempt. With
  // WebSockets allowed, Pi keeps its default: Gondolin's `onRequest` does see
  // the upgrade request, so the host rewrite applies to it too.
  guestPiSettings: ({ websockets }) => (websockets ? {} : { transport: "sse" }),
};
