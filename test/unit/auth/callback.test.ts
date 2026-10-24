// Unit tests for `src/auth/callback.ts`: pasted-redirect parsing, the
// loopback callback server (on an ephemeral port), and the race between the
// two in `waitForAuthorizationCode`.
import { afterEach, describe, expect, it } from "vitest";
import {
  OAuthStateMismatchError,
  parseAuthorizationInput,
  startCallbackServer,
  waitForAuthorizationCode,
  type CallbackServer,
} from "../../../src/auth/callback.ts";

/** A `readLine` that yields `lines` in order, then never resolves (or resolves `undefined` when `eof`). */
function scriptedReadLine(lines: string[], eof = false): (signal: AbortSignal) => Promise<string | undefined> {
  const queue = [...lines];
  return () => {
    if (queue.length > 0) {
      return Promise.resolve(queue.shift());
    }
    return eof ? Promise.resolve(undefined) : new Promise(() => {});
  };
}

const never = (): Promise<string | undefined> => new Promise(() => {});

describe("parseAuthorizationInput", () => {
  it("reads code and state from a full redirect URL", () => {
    expect(parseAuthorizationInput("http://localhost:1455/auth/callback?code=abc&state=xyz")).toEqual({ code: "abc", state: "xyz" });
  });

  it("reads a bare query string", () => {
    expect(parseAuthorizationInput("code=abc&state=xyz")).toEqual({ code: "abc", state: "xyz" });
  });

  it("reads the code#state form", () => {
    expect(parseAuthorizationInput("abc#xyz")).toEqual({ code: "abc", state: "xyz" });
  });

  it("treats anything else as a bare code, trimming whitespace", () => {
    expect(parseAuthorizationInput("  abc \n")).toEqual({ code: "abc" });
  });

  it("returns nothing for empty input or a URL without a code", () => {
    expect(parseAuthorizationInput("   ")).toEqual({});
    expect(parseAuthorizationInput("http://localhost:1455/auth/callback")).toEqual({});
  });
});

describe("startCallbackServer", () => {
  let server: CallbackServer | undefined;

  afterEach(() => {
    server?.close();
    server = undefined;
  });

  async function start(): Promise<CallbackServer> {
    server = await startCallbackServer({ host: "127.0.0.1", port: 0, path: "/auth/callback", state: "s1", providerName: "Test" });
    return server;
  }

  it("resolves with the code from a matching callback", async () => {
    const s = await start();
    const response = await fetch(`http://127.0.0.1:${s.port}/auth/callback?code=c1&state=s1`);
    expect(response.status).toBe(200);
    await expect(s.wait()).resolves.toBe("c1");
  });

  it("refuses a wrong state and keeps waiting", async () => {
    const s = await start();
    expect((await fetch(`http://127.0.0.1:${s.port}/auth/callback?code=bad&state=other`)).status).toBe(400);
    expect((await fetch(`http://127.0.0.1:${s.port}/auth/callback?code=good&state=s1`)).status).toBe(200);
    await expect(s.wait()).resolves.toBe("good");
  });

  it("returns 404 for other paths", async () => {
    const s = await start();
    expect((await fetch(`http://127.0.0.1:${s.port}/elsewhere?code=c&state=s1`)).status).toBe(404);
  });

  it("rejects when the provider reports an error", async () => {
    const s = await start();
    await fetch(`http://127.0.0.1:${s.port}/auth/callback?error=access_denied&state=s1`);
    await expect(s.wait()).rejects.toThrow(/access_denied/);
  });

  it("does not let a second callback replace the first code", async () => {
    const s = await start();
    await fetch(`http://127.0.0.1:${s.port}/auth/callback?code=first&state=s1`);
    expect((await fetch(`http://127.0.0.1:${s.port}/auth/callback?code=second&state=s1`)).status).toBe(409);
    await expect(s.wait()).resolves.toBe("first");
  });

  it("fails to start when the port is taken", async () => {
    const s = await start();
    await expect(
      startCallbackServer({ host: "127.0.0.1", port: s.port, path: "/auth/callback", state: "s2", providerName: "Test" }),
    ).rejects.toThrow(/EADDRINUSE/);
  });
});

describe("waitForAuthorizationCode", () => {
  it("uses a pasted redirect when there is no callback server", async () => {
    const code = await waitForAuthorizationCode({
      callback: undefined,
      readLine: scriptedReadLine(["", "http://localhost:1455/auth/callback?code=pasted&state=st"]),
      state: "st",
    });
    expect(code).toBe("pasted");
  });

  it("rejects a pasted redirect from another login attempt", async () => {
    await expect(
      waitForAuthorizationCode({ callback: undefined, readLine: scriptedReadLine(["code=x&state=other"]), state: "st" }),
    ).rejects.toBeInstanceOf(OAuthStateMismatchError);
  });

  it("accepts a bare pasted code, which has no state to check", async () => {
    await expect(waitForAuthorizationCode({ callback: undefined, readLine: scriptedReadLine(["bare"]), state: "st" })).resolves.toBe("bare");
  });

  it("fails when input closes and there is no callback server", async () => {
    await expect(waitForAuthorizationCode({ callback: undefined, readLine: scriptedReadLine([], true), state: "st" })).rejects.toThrow(
      /input closed/,
    );
  });

  it("keeps waiting on the browser when input closes", async () => {
    const callback = await startCallbackServer({ host: "127.0.0.1", port: 0, path: "/cb", state: "st", providerName: "Test" });
    try {
      const pending = waitForAuthorizationCode({ callback, readLine: scriptedReadLine([], true), state: "st" });
      await fetch(`http://127.0.0.1:${callback.port}/cb?code=browser&state=st`);
      await expect(pending).resolves.toBe("browser");
    } finally {
      callback.close();
    }
  });

  it("aborts the pending read once the browser wins", async () => {
    const callback = await startCallbackServer({ host: "127.0.0.1", port: 0, path: "/cb", state: "st", providerName: "Test" });
    let seen: AbortSignal | undefined;
    try {
      const pending = waitForAuthorizationCode({
        callback,
        readLine: (signal) => {
          seen = signal;
          return never();
        },
        state: "st",
      });
      await fetch(`http://127.0.0.1:${callback.port}/cb?code=browser&state=st`);
      await expect(pending).resolves.toBe("browser");
      expect(seen?.aborted).toBe(true);
    } finally {
      callback.close();
    }
  });
});
