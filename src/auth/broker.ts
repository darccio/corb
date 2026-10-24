// `src/auth/broker.ts` — the runtime half of host-brokered OAuth (ADR 0012):
// storing a fresh login, keeping a stored login fresh, and the per-session
// broker that swaps the guest's stand-in token for the real one on the wire.
//
// Every write to a credential file happens under `withCredentialLock`
// (`src/auth/store.ts`), and every refresh re-reads the file after taking the
// lock. So when several corb sessions share one login and its access token
// expires, one of them refreshes and the others pick up its result instead
// of spending the (possibly rotating) refresh token a second time.
import { randomBytes } from "node:crypto";
import type { BrokeredProvider, GuestCredential, LoginIO, LoginMethod } from "./provider.ts";
import {
  CREDENTIAL_FILE_VERSION,
  deleteStoredCredential,
  readStoredCredential,
  withCredentialLock,
  writeStoredCredential,
  type CredentialLockOptions,
  type StoredCredential,
} from "./store.ts";

/**
 * Refresh this long before the stored expiry, so a token never expires
 * between the check and the request reaching the provider. Matches the
 * five-minute window Pi itself uses (pi-ai `auth/resolve.js`).
 */
export const REFRESH_MARGIN_MS = 5 * 60 * 1000;

/**
 * After a 401 from the provider, the next request forces a refresh even if
 * the stored expiry says the token is fine. At most once per this interval,
 * so a login the provider keeps rejecting cannot turn every request into a
 * token-endpoint call.
 */
export const FORCED_REFRESH_INTERVAL_MS = 60 * 1000;

/** Thrown when a brokered provider has no stored login. */
export class NotLoggedInError extends Error {
  constructor(provider: BrokeredProvider) {
    super(`corb: not logged in to ${provider.displayName}. Run 'corb login ${provider.id}' first.`);
    this.name = "NotLoggedInError";
  }
}

export interface BrokerOptions {
  /** Credentials directory (`credentialsStateDir()` in production). */
  dir: string;
  fetch?: typeof fetch;
  now?: () => number;
  lock?: CredentialLockOptions;
}

function isFresh(credential: StoredCredential, now: number): boolean {
  return now + REFRESH_MARGIN_MS < credential.expires;
}

/** Runs `provider`'s interactive login and stores the result, replacing any earlier login. */
export async function loginAndStore(
  provider: BrokeredProvider,
  method: LoginMethod,
  io: LoginIO,
  options: BrokerOptions,
): Promise<StoredCredential> {
  const tokens = await provider.login(method, io);
  const now = options.now ?? Date.now;
  const credential: StoredCredential = {
    version: CREDENTIAL_FILE_VERSION,
    provider: provider.id,
    type: "oauth",
    access: tokens.access,
    refresh: tokens.refresh,
    expires: tokens.expires,
    ...(tokens.accountId !== undefined ? { accountId: tokens.accountId } : {}),
    updatedAt: new Date(now()).toISOString(),
  };
  await withCredentialLock(options.dir, provider.id, async () => writeStoredCredential(options.dir, credential), options.lock);
  return credential;
}

/** Deletes `provider`'s stored login. Returns whether there was one. */
export async function logout(provider: BrokeredProvider, options: BrokerOptions): Promise<boolean> {
  return withCredentialLock(options.dir, provider.id, async () => deleteStoredCredential(options.dir, provider.id), options.lock);
}

/**
 * Returns `provider`'s stored login, refreshing it first when it is within
 * `REFRESH_MARGIN_MS` of expiry, or when its access token is `rejectedAccess`
 * (the provider answered 401 to it). Throws `NotLoggedInError` when there is
 * no stored login.
 */
export async function ensureFreshCredential(
  provider: BrokeredProvider,
  options: BrokerOptions,
  rejectedAccess?: string,
): Promise<StoredCredential> {
  const now = options.now ?? Date.now;
  const needsRefresh = (credential: StoredCredential): boolean =>
    !isFresh(credential, now()) || (rejectedAccess !== undefined && credential.access === rejectedAccess);

  const current = readStoredCredential(options.dir, provider.id);
  if (current === undefined) {
    throw new NotLoggedInError(provider);
  }
  if (!needsRefresh(current)) {
    return current;
  }
  return withCredentialLock(
    options.dir,
    provider.id,
    async () => {
      // Re-read under the lock: another session may have refreshed while we waited.
      const latest = readStoredCredential(options.dir, provider.id);
      if (latest === undefined) {
        throw new NotLoggedInError(provider);
      }
      if (!needsRefresh(latest)) {
        return latest;
      }
      const tokens = await provider.refresh(latest.refresh, options.fetch ?? fetch);
      const accountId = tokens.accountId ?? latest.accountId;
      const updated: StoredCredential = {
        ...latest,
        access: tokens.access,
        refresh: tokens.refresh,
        expires: tokens.expires,
        ...(accountId !== undefined ? { accountId } : {}),
        updatedAt: new Date(now()).toISOString(),
      };
      writeStoredCredential(options.dir, updated);
      return updated;
    },
    options.lock,
  );
}

export interface BrokeredSessionOptions extends BrokerOptions {
  /** Called with every real token value this session holds, so the audit log can redact them. */
  onSecrets?: (values: readonly string[]) => void;
  /** Injectable for tests. Default: 16 random bytes, hex. */
  marker?: string;
}

/** One session's broker: what to put in the guest, and the host-side hooks that swap the stand-in. */
export interface BrokeredSession {
  provider: BrokeredProvider;
  guest: GuestCredential;
  /**
   * The `onRequest` step. Returns `req` itself when it is not a request
   * carrying this session's stand-in to one of the provider's API hosts over
   * HTTPS; otherwise a copy carrying the real access token. When the login can
   * no longer be refreshed, returns a 401 `Response` explaining what to do,
   * instead of sending the stand-in upstream.
   */
  rewrite(req: Request): Promise<Request | Response>;
  /** The `onResponse` step: a 401 to a request this broker rewrote forces a refresh on the next one. */
  noteResponse(res: Response, req: Request): void;
}

function brokerErrorResponse(provider: BrokeredProvider, reason: string): Response {
  const message = `corb: the ${provider.displayName} login could not be refreshed (${reason}). Run 'corb login ${provider.id}' on the host.`;
  return new Response(JSON.stringify({ error: { message, type: "corb_login_required" } }), {
    status: 401,
    headers: { "content-type": "application/json" },
  });
}

/**
 * Starts the broker for one session. Fails before anything boots when there
 * is no stored login, or when the stored login is stale and cannot be
 * refreshed.
 */
export async function startBrokeredSession(provider: BrokeredProvider, options: BrokeredSessionOptions): Promise<BrokeredSession> {
  const now = options.now ?? Date.now;
  let current = await ensureFreshCredential(provider, options);
  options.onSecrets?.([current.access, current.refresh]);
  const guest = provider.buildGuestCredential(current, options.marker ?? randomBytes(16).toString("hex"));
  const expectedAuthorization = `Bearer ${guest.standIn}`;
  const apiHosts = new Set(provider.apiHosts.map((host) => host.toLowerCase()));

  let inflight: Promise<StoredCredential> | undefined;
  let rejectedAccess: string | undefined;
  let lastForcedRefresh = Number.NEGATIVE_INFINITY;

  const accessToken = async (): Promise<string> => {
    const forced = rejectedAccess !== undefined && rejectedAccess === current.access && now() - lastForcedRefresh >= FORCED_REFRESH_INTERVAL_MS;
    if (!forced && isFresh(current, now())) {
      return current.access;
    }
    if (inflight === undefined) {
      if (forced) {
        lastForcedRefresh = now();
      }
      inflight = ensureFreshCredential(provider, options, forced ? rejectedAccess : undefined).finally(() => {
        inflight = undefined;
      });
    }
    try {
      current = await inflight;
    } catch (err) {
      // A token that has not actually expired is still worth sending.
      if (now() < current.expires) {
        return current.access;
      }
      throw err;
    }
    options.onSecrets?.([current.access, current.refresh]);
    return current.access;
  };

  return {
    provider,
    guest,
    async rewrite(req) {
      if (req.headers.get("authorization") !== expectedAuthorization) {
        return req;
      }
      const url = new URL(req.url);
      if (url.protocol !== "https:" || !apiHosts.has(url.hostname.toLowerCase())) {
        return req;
      }
      let token: string;
      try {
        token = await accessToken();
      } catch (err) {
        return brokerErrorResponse(provider, err instanceof Error ? err.message : String(err));
      }
      const headers = new Headers(req.headers);
      headers.set("authorization", `Bearer ${token}`);
      return new Request(req, { headers });
    },
    noteResponse(res, req) {
      if (res.status !== 401) {
        return;
      }
      const authorization = req.headers.get("authorization");
      if (authorization !== null && authorization === `Bearer ${current.access}`) {
        rejectedAccess = current.access;
      }
    },
  };
}
