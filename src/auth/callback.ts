// `src/auth/callback.ts` — the browser half of a host-side OAuth
// authorization-code login (ADR 0012): a one-shot loopback HTTP server that
// receives the provider's redirect, plus the fallback for when that server
// cannot be used (the port is taken, or the browser runs on another machine
// and cannot reach this host's loopback): the user pastes the redirect URL,
// or just the code, into the terminal.
//
// Both paths race; whichever produces a code first wins. Modelled on Pi's
// own `callback-server.js`/`waitForCallbackOrManualInput`, written for corb.
import http from "node:http";

export interface CallbackServerOptions {
  /** Interface to bind. Loopback only in practice. */
  host: string;
  port: number;
  /** Redirect path, e.g. `/auth/callback`. Other paths get a 404. */
  path: string;
  /** Expected OAuth `state`. A callback with any other value is refused and the server keeps waiting. */
  state: string;
  /** Used in the page shown to the user. */
  providerName: string;
}

export interface CallbackServer {
  /** The bound port (useful when `port: 0` asked for an ephemeral one). */
  port: number;
  /** Resolves with the authorization code, or rejects when the provider reports an error or the server is closed. */
  wait(): Promise<string>;
  close(): void;
}

function page(response: http.ServerResponse, status: number, message: string): void {
  response.writeHead(status, { "content-type": "text/plain; charset=utf-8", "cache-control": "no-store" });
  response.end(`${message}\n`);
}

/**
 * Starts the loopback callback server. Rejects if it cannot listen (most
 * often `EADDRINUSE`: port 1455 is shared with OpenAI's own Codex CLI), so the
 * caller can fall back to the pasted-code path alone.
 */
export async function startCallbackServer(options: CallbackServerOptions): Promise<CallbackServer> {
  let settled = false;
  let resolveWait: (code: string) => void = () => {};
  let rejectWait: (err: Error) => void = () => {};
  const waitPromise = new Promise<string>((resolve, reject) => {
    resolveWait = resolve;
    rejectWait = reject;
  });
  // A wait nobody observes (the pasted code won) must not surface as an unhandled rejection.
  waitPromise.catch(() => undefined);

  const finish = (result: { code: string } | { error: Error }): void => {
    if (settled) {
      return;
    }
    settled = true;
    if ("code" in result) {
      resolveWait(result.code);
    } else {
      rejectWait(result.error);
    }
  };

  const server = http.createServer((request, response) => {
    const url = new URL(request.url ?? "/", "http://localhost");
    if (request.method !== "GET" || url.pathname !== options.path) {
      page(response, 404, "Not found.");
      return;
    }
    if (url.searchParams.get("state") !== options.state) {
      page(response, 400, "State mismatch. Start the login again from corb.");
      return;
    }
    if (settled) {
      page(response, 409, "This sign-in has already been handled.");
      return;
    }
    const error = url.searchParams.get("error");
    if (error !== null) {
      const description = url.searchParams.get("error_description") ?? error;
      page(response, 400, `${options.providerName} authorization failed: ${description}`);
      finish({ error: new Error(`${options.providerName} authorization failed: ${description}`) });
      return;
    }
    const code = url.searchParams.get("code");
    if (code === null || code === "") {
      page(response, 400, "Missing authorization code.");
      return;
    }
    page(response, 200, `Signed in to ${options.providerName}. You can close this page and return to the terminal.`);
    finish({ code });
  });

  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(options.port, options.host, () => {
      server.off("error", reject);
      resolve();
    });
  });
  server.on("error", (err) => finish({ error: err }));
  const address = server.address();
  const port = typeof address === "object" && address !== null ? address.port : options.port;

  return {
    port,
    wait: () => waitPromise,
    close: () => {
      finish({ error: new Error("OAuth callback server closed") });
      server.close();
      server.closeAllConnections();
    },
  };
}

export interface ParsedAuthorizationInput {
  code?: string;
  state?: string;
}

/**
 * Parses what a user pasted after a browser login: the full redirect URL
 * (`http://localhost:1455/auth/callback?code=...&state=...`), a bare query
 * string (`code=...&state=...`), Codex's `code#state` form, or just the code.
 * Matches Pi's own `parseAuthorizationInput`, so instructions written for Pi
 * work here too.
 */
export function parseAuthorizationInput(input: string): ParsedAuthorizationInput {
  const value = input.trim();
  if (value === "") {
    return {};
  }
  const fromParams = (params: URLSearchParams): ParsedAuthorizationInput => {
    const result: ParsedAuthorizationInput = {};
    const code = params.get("code");
    const state = params.get("state");
    if (code !== null && code !== "") {
      result.code = code;
    }
    if (state !== null && state !== "") {
      result.state = state;
    }
    return result;
  };
  try {
    return fromParams(new URL(value).searchParams);
  } catch {
    // Not a URL.
  }
  if (value.includes("#")) {
    const [code, state] = value.split("#", 2);
    const result: ParsedAuthorizationInput = {};
    if (code) {
      result.code = code;
    }
    if (state) {
      result.state = state;
    }
    return result;
  }
  if (value.includes("code=")) {
    return fromParams(new URLSearchParams(value));
  }
  return { code: value };
}

/** Thrown when a pasted redirect carries a `state` that does not match this login attempt. */
export class OAuthStateMismatchError extends Error {
  constructor() {
    super("corb login: the pasted redirect belongs to a different login attempt (state mismatch). Start again.");
    this.name = "OAuthStateMismatchError";
  }
}

export interface WaitForCodeOptions {
  /** The loopback server, if it started. `undefined` means pasted input is the only path. */
  callback: CallbackServer | undefined;
  /** Reads one line of pasted input. Resolves `undefined` at end of input. Must stop when `signal` aborts. */
  readLine: (signal: AbortSignal) => Promise<string | undefined>;
  /** Expected OAuth `state`, checked against a pasted redirect that carries one. */
  state: string;
}

/**
 * Waits for an authorization code from whichever source produces one first:
 * the loopback callback, or a pasted redirect/code. A pasted value with a
 * `state` must match; a bare code has no state to check (the same trade-off
 * Pi makes — PKCE still binds the code to this attempt's verifier). Empty
 * pasted lines are ignored. End of input with no callback is an error.
 */
export async function waitForAuthorizationCode(options: WaitForCodeOptions): Promise<string> {
  const pasteAbort = new AbortController();
  const fromPaste = (async (): Promise<string> => {
    for (;;) {
      const line = await options.readLine(pasteAbort.signal);
      if (line === undefined) {
        if (options.callback !== undefined) {
          // Input closed (e.g. stdin is not a terminal); keep waiting on the browser.
          return new Promise<string>(() => {});
        }
        throw new Error("corb login: no authorization code received (input closed).");
      }
      const parsed = parseAuthorizationInput(line);
      if (parsed.code === undefined) {
        continue;
      }
      if (parsed.state !== undefined && parsed.state !== options.state) {
        throw new OAuthStateMismatchError();
      }
      return parsed.code;
    }
  })();
  try {
    const sources = [fromPaste];
    if (options.callback !== undefined) {
      sources.push(options.callback.wait());
    }
    return await Promise.race(sources);
  } finally {
    pasteAbort.abort();
    fromPaste.catch(() => undefined);
  }
}
