// Unit tests for `src/auth/broker.ts`: storing a login, refresh-on-expiry
// with the cross-process re-read, and the per-session rewrite (only the
// stand-in, only to the provider's API hosts, only over HTTPS). Uses a fake
// provider so the tests pin the broker's own behaviour, not Codex's.
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  FORCED_REFRESH_INTERVAL_MS,
  NotLoggedInError,
  REFRESH_MARGIN_MS,
  ensureFreshCredential,
  loginAndStore,
  logout,
  startBrokeredSession,
} from "../../../src/auth/broker.ts";
import type { BrokeredProvider, LoginIO, TokenSet } from "../../../src/auth/provider.ts";
import {
  CREDENTIAL_FILE_VERSION,
  readStoredCredential,
  withCredentialLock,
  writeStoredCredential,
  type StoredCredential,
} from "../../../src/auth/store.ts";

const HOUR = 60 * 60 * 1000;

interface FakeProvider extends BrokeredProvider {
  refreshCalls: string[];
  nextRefresh: () => TokenSet;
}

function fakeProvider(): FakeProvider {
  let counter = 0;
  const provider: FakeProvider = {
    id: "fake",
    displayName: "Fake",
    loginMethods: ["browser"],
    refreshCalls: [],
    nextRefresh: () => {
      counter += 1;
      return { access: `access-${counter}`, refresh: `refresh-${counter}`, expires: clock.t + HOUR, accountId: "acct" };
    },
    login: async () => ({ access: "login-access", refresh: "login-refresh", expires: clock.t + HOUR, accountId: "acct" }),
    async refresh(refreshToken) {
      provider.refreshCalls.push(refreshToken);
      return provider.nextRefresh();
    },
    apiHosts: ["api.fake.test"],
    buildGuestCredential: (_credential, marker) => ({ standIn: `stand-in-${marker}`, piAuthEntry: { access: `stand-in-${marker}` } }),
    guestPiSettings: () => ({}),
  };
  return provider;
}

const clock = { t: 1_000_000_000_000 };

function stored(overrides: Partial<StoredCredential> = {}): StoredCredential {
  return {
    version: CREDENTIAL_FILE_VERSION,
    provider: "fake",
    type: "oauth",
    access: "access-0",
    refresh: "refresh-0",
    expires: clock.t + HOUR,
    accountId: "acct",
    updatedAt: "2026-10-24T00:00:00.000Z",
    ...overrides,
  };
}

function request(url: string, authorization?: string): Request {
  return new Request(url, { method: "POST", body: "{}", headers: authorization === undefined ? {} : { authorization } });
}

describe("auth/broker", () => {
  let root: string;
  let dir: string;
  let provider: FakeProvider;
  const now = (): number => clock.t;

  beforeEach(() => {
    root = fs.mkdtempSync(path.join(os.tmpdir(), "corb-auth-broker-"));
    dir = path.join(root, "credentials");
    provider = fakeProvider();
    clock.t = 1_000_000_000_000;
  });

  afterEach(() => {
    fs.rmSync(root, { recursive: true, force: true });
  });

  describe("loginAndStore / logout", () => {
    it("stores the login result and logout removes it", async () => {
      const io: LoginIO = { print: () => {}, readLine: async () => undefined, fetch };
      await loginAndStore(provider, "browser", io, { dir, now });
      expect(readStoredCredential(dir, "fake")).toMatchObject({ access: "login-access", refresh: "login-refresh", accountId: "acct" });
      expect(await logout(provider, { dir })).toBe(true);
      expect(readStoredCredential(dir, "fake")).toBeUndefined();
      expect(await logout(provider, { dir })).toBe(false);
    });
  });

  describe("ensureFreshCredential", () => {
    it("throws NotLoggedInError without a stored login", async () => {
      await expect(ensureFreshCredential(provider, { dir, now })).rejects.toBeInstanceOf(NotLoggedInError);
    });

    it("returns a fresh login without refreshing", async () => {
      writeStoredCredential(dir, stored());
      expect((await ensureFreshCredential(provider, { dir, now })).access).toBe("access-0");
      expect(provider.refreshCalls).toEqual([]);
    });

    it("refreshes inside the margin and stores the rotated tokens", async () => {
      writeStoredCredential(dir, stored({ expires: clock.t + REFRESH_MARGIN_MS - 1 }));
      const result = await ensureFreshCredential(provider, { dir, now });
      expect(result).toMatchObject({ access: "access-1", refresh: "refresh-1" });
      expect(provider.refreshCalls).toEqual(["refresh-0"]);
      expect(readStoredCredential(dir, "fake")).toMatchObject({ access: "access-1", refresh: "refresh-1" });
    });

    it("uses another process's refresh instead of spending the refresh token again", async () => {
      writeStoredCredential(dir, stored({ expires: clock.t - 1 }));
      let releaseOther: () => void = () => {};
      const otherHolds = new Promise<void>((resolve) => {
        releaseOther = resolve;
      });
      let otherHasLock: () => void = () => {};
      const lockTaken = new Promise<void>((resolve) => {
        otherHasLock = resolve;
      });
      // A second corb process holding the lock while it refreshes.
      const other = withCredentialLock(dir, "fake", async () => {
        otherHasLock();
        await otherHolds;
        writeStoredCredential(dir, stored({ access: "other-access", refresh: "other-refresh", expires: clock.t + HOUR }));
      });
      await lockTaken;
      const ours = ensureFreshCredential(provider, { dir, now, lock: { sleep: (ms) => new Promise((r) => setTimeout(r, Math.min(ms, 5))) } });
      await new Promise((r) => setTimeout(r, 20));
      releaseOther();
      await other;
      expect((await ours).access).toBe("other-access");
      expect(provider.refreshCalls).toEqual([]);
    });

    it("refreshes a token the provider rejected even before its expiry", async () => {
      writeStoredCredential(dir, stored());
      expect((await ensureFreshCredential(provider, { dir, now }, "access-0")).access).toBe("access-1");
      expect((await ensureFreshCredential(provider, { dir, now }, "access-0")).access).toBe("access-1");
      expect(provider.refreshCalls).toEqual(["refresh-0"]);
    });
  });

  describe("startBrokeredSession", () => {
    async function session(overrides: Partial<StoredCredential> = {}) {
      writeStoredCredential(dir, stored(overrides));
      const secrets: string[] = [];
      const broker = await startBrokeredSession(provider, { dir, now, marker: "m1", onSecrets: (values) => secrets.push(...values) });
      return { broker, secrets };
    }

    it("fails before boot without a login", async () => {
      await expect(startBrokeredSession(provider, { dir, now })).rejects.toBeInstanceOf(NotLoggedInError);
    });

    it("hands the guest only the stand-in and reports the real tokens for redaction", async () => {
      const { broker, secrets } = await session();
      expect(broker.guest.standIn).toBe("stand-in-m1");
      expect(JSON.stringify(broker.guest)).not.toContain("access-0");
      expect(secrets).toEqual(["access-0", "refresh-0"]);
    });

    it("swaps the stand-in for the real token on HTTPS to an API host", async () => {
      const { broker } = await session();
      const out = await broker.rewrite(request("https://api.fake.test/v1/x", "Bearer stand-in-m1"));
      expect(out).toBeInstanceOf(Request);
      expect((out as Request).headers.get("authorization")).toBe("Bearer access-0");
      expect(await (out as Request).text()).toBe("{}");
    });

    it("matches the API host case-insensitively", async () => {
      const { broker } = await session();
      const out = (await broker.rewrite(request("https://API.Fake.Test/x", "Bearer stand-in-m1"))) as Request;
      expect(out.headers.get("authorization")).toBe("Bearer access-0");
    });

    it.each([
      ["another host", "https://evil.test/x", "Bearer stand-in-m1"],
      ["a subdomain of the API host", "https://x.api.fake.test/x", "Bearer stand-in-m1"],
      ["plain HTTP", "http://api.fake.test/x", "Bearer stand-in-m1"],
      ["another bearer token", "https://api.fake.test/x", "Bearer something-else"],
      ["another session's stand-in", "https://api.fake.test/x", "Bearer stand-in-m2"],
      ["no authorization", "https://api.fake.test/x", undefined],
    ])("leaves %s untouched", async (_label, url, authorization) => {
      const { broker } = await session();
      const req = request(url, authorization);
      expect(await broker.rewrite(req)).toBe(req);
    });

    it("refreshes mid-session once the token nears expiry, once for concurrent requests", async () => {
      const { broker, secrets } = await session();
      clock.t += HOUR;
      const [a, b] = await Promise.all([
        broker.rewrite(request("https://api.fake.test/x", "Bearer stand-in-m1")),
        broker.rewrite(request("https://api.fake.test/x", "Bearer stand-in-m1")),
      ]);
      expect((a as Request).headers.get("authorization")).toBe("Bearer access-1");
      expect((b as Request).headers.get("authorization")).toBe("Bearer access-1");
      expect(provider.refreshCalls).toEqual(["refresh-0"]);
      expect(secrets).toContain("access-1");
      expect(secrets).toContain("refresh-1");
    });

    it("answers 401 itself when an expired login cannot be refreshed", async () => {
      const { broker } = await session();
      provider.nextRefresh = () => {
        throw new Error("invalid_grant");
      };
      clock.t += 2 * HOUR;
      const out = await broker.rewrite(request("https://api.fake.test/x", "Bearer stand-in-m1"));
      expect(out).toBeInstanceOf(Response);
      expect((out as Response).status).toBe(401);
      expect(await (out as Response).text()).toMatch(/corb login fake/);
    });

    it("keeps using a not-yet-expired token when a refresh inside the margin fails", async () => {
      const { broker } = await session();
      provider.nextRefresh = () => {
        throw new Error("network down");
      };
      clock.t += HOUR - REFRESH_MARGIN_MS + 1;
      const out = (await broker.rewrite(request("https://api.fake.test/x", "Bearer stand-in-m1"))) as Request;
      expect(out.headers.get("authorization")).toBe("Bearer access-0");
    });

    it("forces a refresh after a 401, at most once per interval", async () => {
      const { broker } = await session();
      const rewritten = (await broker.rewrite(request("https://api.fake.test/x", "Bearer stand-in-m1"))) as Request;
      broker.noteResponse(new Response("", { status: 401 }), rewritten);
      const next = (await broker.rewrite(request("https://api.fake.test/x", "Bearer stand-in-m1"))) as Request;
      expect(next.headers.get("authorization")).toBe("Bearer access-1");

      broker.noteResponse(new Response("", { status: 401 }), next);
      const throttled = (await broker.rewrite(request("https://api.fake.test/x", "Bearer stand-in-m1"))) as Request;
      expect(throttled.headers.get("authorization")).toBe("Bearer access-1");
      expect(provider.refreshCalls).toEqual(["refresh-0"]);

      clock.t += FORCED_REFRESH_INTERVAL_MS;
      const later = (await broker.rewrite(request("https://api.fake.test/x", "Bearer stand-in-m1"))) as Request;
      expect(later.headers.get("authorization")).toBe("Bearer access-2");
    });

    it("ignores a 401 to a request it did not rewrite", async () => {
      const { broker } = await session();
      broker.noteResponse(new Response("", { status: 401 }), request("https://evil.test/x", "Bearer other"));
      await broker.rewrite(request("https://api.fake.test/x", "Bearer stand-in-m1"));
      expect(provider.refreshCalls).toEqual([]);
    });
  });
});
