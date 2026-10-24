// `src/auth/provider.ts` — the interface every host-brokered OAuth provider
// implements, and the registry of the ones corb ships (ADR 0012).
//
// This is corb's one deliberate exception to ADR 0010's "no provider-specific
// code": a provider listed here gets a `corb login`, host-side token storage
// and refresh, a stand-in credential in the guest, and a host-side request
// rewrite. Every provider *not* listed here is untouched and still uses
// `[secrets.NAME]`. Adding a provider means writing one module under
// `src/auth/providers/` and adding it to `PROVIDERS` below; nothing else in
// corb names a provider.
import type { StoredCredential } from "./store.ts";
import { openaiCodexProvider } from "./providers/openai-codex.ts";

/** The ways a provider can run its interactive login. The first entry in `BrokeredProvider.loginMethods` is the default. */
export type LoginMethod = "browser" | "device-code";

/** A fresh token set from a login or a refresh. `expires` is a Unix timestamp in milliseconds. */
export interface TokenSet {
  access: string;
  refresh: string;
  expires: number;
  accountId?: string;
}

/** The terminal and network side of an interactive login, injectable for tests. */
export interface LoginIO {
  /** Shows one line to the user (stderr in the real CLI). */
  print(line: string): void;
  /** Best-effort attempt to open `url` in a browser. Absent or failing is fine: the URL is always printed too. */
  openUrl?(url: string): void;
  /** Reads one pasted line; resolves `undefined` at end of input. Must stop waiting when `signal` aborts. */
  readLine(signal: AbortSignal): Promise<string | undefined>;
  fetch: typeof fetch;
  /** Injectable for tests (device-code polling). */
  sleep?(ms: number): Promise<void>;
  /** Injectable for tests. */
  now?(): number;
}

/** What a session writes into the guest so Pi uses the brokered login. */
export interface GuestCredential {
  /**
   * The stand-in access token Pi will send. The host recognises exactly this
   * string in `Authorization: Bearer ...` and swaps in the real token. It
   * must be useless on its own: no signature, no real secret inside.
   */
  standIn: string;
  /** The value for this provider's key in Pi's `auth.json`. */
  piAuthEntry: Record<string, unknown>;
}

export interface BrokeredProvider {
  /** Matches both `[agent].provider` and Pi's own provider id, e.g. `openai-codex`. */
  id: string;
  /** Human name for CLI output. */
  displayName: string;
  /** Supported login methods; the first is the default. */
  loginMethods: readonly LoginMethod[];
  /** Runs an interactive login on the host. */
  login(method: LoginMethod, io: LoginIO): Promise<TokenSet>;
  /** Exchanges a refresh token for a new token set. May rotate the refresh token. */
  refresh(refreshToken: string, fetchImpl: typeof fetch, signal?: AbortSignal): Promise<TokenSet>;
  /**
   * Exact hostnames (no wildcards) where the stand-in is swapped for the real
   * access token, over HTTPS only. Never a token endpoint: the guest must not
   * need one. Each must also be in `egress.allow` for the session to work.
   */
  apiHosts: readonly string[];
  /** Builds this session's stand-in credential. `marker` is a fresh random string, unique per session. */
  buildGuestCredential(credential: StoredCredential, marker: string): GuestCredential;
  /** Extra Pi `settings.json` keys for the guest, e.g. a transport that works with `egress.websockets`. */
  guestPiSettings(options: { websockets: boolean }): Record<string, unknown>;
}

const PROVIDERS: readonly BrokeredProvider[] = [openaiCodexProvider];

/** Every host-brokered provider corb ships, in display order. */
export function listBrokeredProviders(): readonly BrokeredProvider[] {
  return PROVIDERS;
}

/** The host-brokered provider with this id, or `undefined` for every other (API-key) provider. */
export function findBrokeredProvider(id: string | undefined): BrokeredProvider | undefined {
  if (id === undefined) {
    return undefined;
  }
  return PROVIDERS.find((provider) => provider.id === id);
}

/** Thrown when a CLI argument names no host-brokered provider. */
export class UnknownProviderError extends Error {
  constructor(id: string) {
    const known = PROVIDERS.map((provider) => provider.id).join(", ");
    super(`corb: '${id}' is not a provider corb can log in to. Available: ${known}.`);
    this.name = "UnknownProviderError";
  }
}

/** Like `findBrokeredProvider`, but throws `UnknownProviderError` instead of returning `undefined`. */
export function getBrokeredProvider(id: string): BrokeredProvider {
  const provider = findBrokeredProvider(id);
  if (provider === undefined) {
    throw new UnknownProviderError(id);
  }
  return provider;
}

/**
 * Whether `hostname` matches one `egress.allow` pattern, with Gondolin's own
 * semantics (`host/patterns.js`, which the package does not export): `*`
 * alone matches everything, and `*` inside a pattern matches any substring.
 * Case-insensitive.
 */
function matchesAllowPattern(hostname: string, pattern: string): boolean {
  const normalized = pattern.trim().toLowerCase();
  if (normalized === "") {
    return false;
  }
  if (normalized === "*") {
    return true;
  }
  const escaped = normalized
    .split("*")
    .map((part) => part.replace(/[.+?^${}()|[\]\\]/g, "\\$&"))
    .join(".*");
  return new RegExp(`^${escaped}$`, "i").test(hostname);
}

/** `provider`'s API hosts that `allow` (`egress.allow`) does not permit. A login does not grant network access. */
export function unreachableApiHosts(provider: BrokeredProvider, allow: readonly string[] | undefined): string[] {
  return provider.apiHosts.filter((host) => !(allow ?? []).some((pattern) => matchesAllowPattern(host, pattern)));
}
