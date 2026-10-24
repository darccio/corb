// `corb login [PROVIDER] [--device-code]` and `corb logout PROVIDER` — the
// CLI side of host-brokered OAuth (ADR 0012). The login runs on the host, so
// the browser redirect to `localhost` reaches it directly, and the tokens are
// stored in corb's state directory, never in a guest.
//
// `corb login` with no provider lists the providers corb can log in to and
// whether each one has a stored login. That listing never prints a token.
import { spawn } from "node:child_process";
import readline from "node:readline";
import { parseArgs } from "node:util";
import { loginAndStore, logout } from "../auth/broker.ts";
import { getBrokeredProvider, listBrokeredProviders, type BrokeredProvider, type LoginIO, type LoginMethod } from "../auth/provider.ts";
import { credentialFilePath, readStoredCredential, type StoredCredential } from "../auth/store.ts";
import { credentialsStateDir } from "../config/paths.ts";

export interface LoginCommandArgs {
  /** `undefined` means "list providers and their status". */
  provider?: string;
  method?: LoginMethod;
}

export function parseLoginArgs(argv: string[]): LoginCommandArgs {
  const { values, positionals } = parseArgs({
    args: argv,
    options: { "device-code": { type: "boolean" } },
    allowPositionals: true,
    strict: true,
  });
  if (positionals.length > 1) {
    throw new Error(`corb login: unexpected argument '${positionals[1]}' (corb login takes one provider)`);
  }
  const provider = positionals[0];
  if (provider === undefined) {
    if (values["device-code"] === true) {
      throw new Error("corb login: --device-code needs a provider, e.g. 'corb login openai-codex --device-code'");
    }
    return {};
  }
  return { provider, ...(values["device-code"] === true ? { method: "device-code" } : {}) };
}

export function parseLogoutArgs(argv: string[]): { provider: string } {
  const { positionals } = parseArgs({ args: argv, options: {}, allowPositionals: true, strict: true });
  if (positionals.length !== 1 || positionals[0] === undefined) {
    throw new Error("corb logout: expected exactly one provider, e.g. 'corb logout openai-codex'");
  }
  return { provider: positionals[0] };
}

/** One status line per provider. Shows only non-secret fields. */
export function renderLoginStatus(
  providers: readonly BrokeredProvider[],
  read: (provider: BrokeredProvider) => StoredCredential | undefined,
  now: number = Date.now(),
): string {
  const lines = providers.map((provider) => {
    let status: string;
    try {
      const credential = read(provider);
      if (credential === undefined) {
        status = "not logged in";
      } else {
        const expiry = credential.expires > now ? `access token valid until ${new Date(credential.expires).toISOString()}` : "access token expired, refreshed on next use";
        status = `logged in${credential.accountId !== undefined ? ` (account ${credential.accountId})` : ""}, ${expiry}`;
      }
    } catch (err) {
      status = `unusable login: ${err instanceof Error ? err.message.split("\n")[0] : String(err)}`;
    }
    return `${provider.id}  ${provider.displayName}: ${status}`;
  });
  return lines.join("\n");
}

/** A line reader over stdin that survives being raced and abandoned by `waitForAuthorizationCode`. */
function stdinLineReader(): { readLine: LoginIO["readLine"]; close(): void } {
  const rl = readline.createInterface({ input: process.stdin, terminal: false });
  const buffered: string[] = [];
  let closed = false;
  let waiter: ((line: string | undefined) => void) | undefined;
  rl.on("line", (line) => {
    if (waiter !== undefined) {
      const resolve = waiter;
      waiter = undefined;
      resolve(line);
    } else {
      buffered.push(line);
    }
  });
  rl.on("close", () => {
    closed = true;
    waiter?.(undefined);
    waiter = undefined;
  });
  return {
    readLine(signal) {
      const next = buffered.shift();
      if (next !== undefined) {
        return Promise.resolve(next);
      }
      if (closed || signal.aborted) {
        return Promise.resolve(undefined);
      }
      return new Promise((resolve) => {
        waiter = resolve;
        signal.addEventListener(
          "abort",
          () => {
            if (waiter === resolve) {
              waiter = undefined;
              resolve(undefined);
            }
          },
          { once: true },
        );
      });
    },
    close: () => rl.close(),
  };
}

/** Best effort: the URL is always printed as well, so any failure here is ignored. */
function openInBrowser(url: string): void {
  const command = process.platform === "darwin" ? "open" : process.platform === "win32" ? undefined : "xdg-open";
  if (command === undefined || !process.stderr.isTTY) {
    return;
  }
  try {
    const child = spawn(command, [url], { detached: true, stdio: "ignore" });
    child.on("error", () => undefined);
    child.unref();
  } catch {
    // Ignored: see above.
  }
}

export async function runLoginCommand(argv: string[]): Promise<void> {
  let args: LoginCommandArgs;
  let provider: BrokeredProvider | undefined;
  try {
    args = parseLoginArgs(argv);
    provider = args.provider === undefined ? undefined : getBrokeredProvider(args.provider);
  } catch (err) {
    console.error(err instanceof Error ? err.message : String(err));
    process.exitCode = 1;
    return;
  }

  const dir = credentialsStateDir();
  if (provider === undefined) {
    console.log(renderLoginStatus(listBrokeredProviders(), (p) => readStoredCredential(dir, p.id)));
    return;
  }

  const method = args.method ?? provider.loginMethods[0] ?? "browser";
  if (!provider.loginMethods.includes(method)) {
    console.error(`corb login: ${provider.id} does not support ${method} login`);
    process.exitCode = 1;
    return;
  }

  const reader = stdinLineReader();
  try {
    const credential = await loginAndStore(
      provider,
      method,
      {
        print: (line) => process.stderr.write(`${line}\n`),
        openUrl: openInBrowser,
        readLine: reader.readLine,
        fetch,
      },
      { dir },
    );
    console.error(
      `Logged in to ${provider.displayName}${credential.accountId !== undefined ? ` (account ${credential.accountId})` : ""}.\n` +
        `Saved to ${credentialFilePath(dir, provider.id)}.\n` +
        `To use it, set [agent] provider = "${provider.id}" and add ${provider.apiHosts.map((h) => `"${h}"`).join(", ")} to egress.allow.`,
    );
  } catch (err) {
    console.error(`corb login: ${err instanceof Error ? err.message : String(err)}`);
    process.exitCode = 1;
  } finally {
    reader.close();
  }
}

export async function runLogoutCommand(argv: string[]): Promise<void> {
  let provider: BrokeredProvider;
  try {
    provider = getBrokeredProvider(parseLogoutArgs(argv).provider);
  } catch (err) {
    console.error(err instanceof Error ? err.message : String(err));
    process.exitCode = 1;
    return;
  }
  const removed = await logout(provider, { dir: credentialsStateDir() });
  console.log(removed ? `Logged out of ${provider.displayName}.` : `Not logged in to ${provider.displayName}; nothing to remove.`);
}
