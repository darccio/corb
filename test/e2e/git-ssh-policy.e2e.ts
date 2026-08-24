// M4.4 — real-VM proof that M4's git-over-SSH policy stack (`buildGitSshOptions()`,
// `src/vm/gitssh.ts`, M4.1; `githubApiGate()`, `src/policy/github.ts`, M4.2;
// both wired into `session.ts`'s real `VM.create()` call, M4.3) actually
// holds against a booted guest, not just against unit tests that never open a
// real SSH channel or HTTP request. Matches M4's own stated acceptance
// criteria exactly: fetch on an allowed repo works; push is denied with a
// readable message; a non-allowlisted repo is denied; `gh api -X DELETE` is
// refused.
//
// Gating and layout matches `test/e2e/egress.e2e.ts` (M3.4) and
// `test/e2e/workspace-mounts.e2e.ts` (M2.4) exactly: `vitest.config.ts` never
// matches `test/e2e/**`, so a plain `npm test` never touches this file, and
// `describe.skipIf` below additionally gates the whole suite on `CORB_E2E=1`.
// Run via `CORB_E2E=1 npx vitest run --config vitest.e2e.config.ts
// test/e2e/git-ssh-policy.e2e.ts`, `npm run test:e2e`, or `make e2e`.
//
// This suite calls `buildGitSshOptions()` and `buildEgressConfig()` — the
// exact, real production functions `session.ts`'s `runSession()` calls — and
// wires their results into `VM.create()` using the exact same field mapping
// `session.ts` uses (`ssh: gitSshOptions`, `httpHooks`/`env`/`allowWebSockets`
// from `egressConfig`). A drift between this test's wiring and `session.ts`'s
// own wiring fails this suite, not silently diverges — the same discipline
// `egress.e2e.ts` established for `buildEgressConfig()` alone, extended here
// to also cover `buildGitSshOptions()`.
//
// ## Five things that had to be worked out empirically before this suite
// could exist at all (each verified against the real installed SDK, not
// assumed) — kept here, not just in the PR description, because the next
// person to touch git-over-SSH e2e coverage will hit the same five walls:
//
// 1. **The host-key-trust problem.** `buildGitSshOptions()` (M4.1) deliberately
//    never sets `SshOptions.knownHostsFile` — it defers to the SDK's own
//    default resolution (`createQemuSshInternals`,
//    `node_modules/@earendil-works/gondolin/dist/src/qemu/ssh.js`): whenever
//    `agent` or `credentials` is set, a default host-key verifier is built via
//    `createOpenSshKnownHostsHostVerifier(normalizeSshKnownHostsFiles(...))`,
//    which — when `knownHostsFile` is `undefined` — reads BOTH
//    `path.join(os.homedir(), ".ssh", "known_hosts")` AND
//    `/etc/ssh/ssh_known_hosts` (`.../dist/src/ssh/utils.js`). Since this
//    suite must never touch this machine's real `~/.ssh/known_hosts` as a side
//    effect, `process.env.HOME` is temporarily overridden to a scratch
//    directory containing a `.ssh/known_hosts` this suite populates itself,
//    strictly for the duration of the `buildGitSshOptions()` + `VM.create()`
//    calls (both `os.homedir()`'s resolution happens synchronously at that
//    point, not lazily per-exec) — restored in a `finally`, and again in
//    `afterAll` in case `beforeAll` throws partway through. This is a
//    test-only mechanism; nothing in production code reads `HOME` this way.
//
// 2. **The known_hosts line must use the bracketed `[host]:port` host-pattern
//    form, not a bare hostname.** Read `hostMatchesOpenSshKnownHostsList`
//    (`.../dist/src/ssh/utils.js`): for a non-default port (anything other
//    than 22 — which this suite must use, since binding port 22 needs root),
//    the only candidate string checked against known_hosts host patterns is
//    `` `[hostname]:${port}` ``, not the bare hostname. A known_hosts line
//    written as `hostname ssh-rsa ...` (the bare form, correct only for port
//    22) silently never matches and host-key verification fails closed. This
//    suite writes `` `[${GIT_HOSTNAME}]:${sshPort} ssh-rsa ${base64}` ``
//    instead.
//
// 3. **A real, DNS-resolvable-shaped hostname is required — a literal IP is
//    not enough for the SSH path, unlike the HTTP path.** `egress.e2e.ts`
//    targets its "allowed" scenario at a literal LAN IP address directly, and
//    that's fine for HTTP (Host-header-based policy, no DNS involved). SSH
//    egress is different: `isSshFlowAllowed`
//    (`.../dist/src/qemu/ssh.js`) requires `session.syntheticHostname`, which
//    is populated only via `syntheticDnsHostMap.lookupHostByIp(dstIP)`
//    (`.../dist/src/qemu/net.js`) — i.e. only ever set when the guest actually
//    issued a DNS query for a hostname and Gondolin's synthetic DNS mediation
//    (`dns.mode: "synthetic"`) answered it with a fabricated per-host address.
//    A guest connecting directly to a literal IP never triggers that lookup at
//    all, so `isSshFlowAllowed` sees `hostname === null` and denies the flow
//    outright — this is *not* the `git.allow-hosts` policy layer working, it's
//    SSH egress never engaging in the first place. So this suite's mock
//    server is addressed by a real hostname (`GIT_HOSTNAME`, an RFC
//    2606-reserved `.invalid` name — never expected to resolve in real DNS),
//    which the guest's own `git`/`ssh` DNS-resolves via Gondolin's synthetic
//    mediation (works regardless of real-world resolvability — that's the
//    entire point of synthetic mode), while `git.allow-hosts`/the mock
//    server's bind address are wired together via mechanism #4 below on the
//    *host* side.
//
// 4. **The upstream connection Gondolin's own host process makes still needs
//    `GIT_HOSTNAME` to resolve to this suite's mock server, for real, on this
//    literal host machine** — `bridgeSshExecChannel`
//    (`.../dist/src/qemu/ssh.js`) connects upstream via a plain `ssh2.Client`
//    with `host: hostname` (the exact string the guest queried), which
//    resolves it via Node's own `net.Socket.connect()` -> `dns.lookup()` (OS
//    resolver), entirely independent of the guest's synthetic DNS. This
//    suite cannot register a real DNS record for an `.invalid` name (and
//    modifying `/etc/hosts` is out of bounds for an automated test — a system
//    file, not a scratch resource). The fix, verified empirically to work
//    (`dns.lookup` is looked up by Node's own `net.js` at call time via the
//    same `dns` module singleton `node:dns` exposes to userland, so
//    monkeypatching the exported `lookup` function is actually observed by
//    `net.connect()`, confirmed with a standalone script before trusting it
//    here): this suite temporarily replaces `dns.lookup` for the lifetime of
//    the VM, intercepting only `GIT_HOSTNAME` (answering with the real
//    `bindHost` LAN address `pickHostLanAddress()` found) and delegating
//    every other hostname to the original implementation — restored in
//    `afterAll`. This is, like `HOME`, a documented test-only mechanism.
//
// 5. **The guest's own git/ssh client needs `StrictHostKeyChecking=no` /
//    `UserKnownHostsFile=/dev/null`.** `docs/gondolin-notes.md` §6 records that
//    the guest-facing proxy host key (Gondolin's own ephemeral, freshly
//    generated per boot, distinct from the *upstream* host key this suite
//    verifies host-side via mechanism #1/#2 above) triggers an OpenSSH
//    warning about the KEX algorithm — but the more fundamental issue,
//    verified here directly (the referenced "docs give a GIT_SSH_COMMAND
//    workaround" could not actually be located in the SDK's current published
//    docs — `network.md`/`ssh.md`/`security.md` were all checked directly —
//    so this was independently re-derived rather than copied): the guest's
//    OpenSSH client has never seen this ephemeral proxy host key before and,
//    non-interactively, refuses to proceed past an unknown host key at all
//    (`git`/`ssh` fail closed, not with a warning). There is no way to
//    pre-populate the guest's own known_hosts with this key in advance — it's
//    generated inside the SDK, per VM instance, with no accessor exposed.
//    `GIT_SSH_COMMAND="ssh -o StrictHostKeyChecking=no -o
//    UserKnownHostsFile=/dev/null -o LogLevel=ERROR -o BatchMode=yes"`
//    (exported into the guest exec's env below) is the workaround, verified
//    end-to-end against a standalone mock server (outside any VM) before
//    trusting it here: without it, `git clone` hangs/fails; with it, a real
//    `git clone` against a real `git-upload-pack` succeeds cleanly. This does
//    not weaken *Corb's* security boundary — `ssh.execPolicy` (host-side,
//    verified by this suite) is the actual enforcement point, per
//    `src/vm/gitssh.ts`'s own module comment; skipping the guest's host-key
//    check only affects trust of Gondolin's own already-trusted proxy layer.
//
// One more real bug found and fixed while building this suite's own mock SSH
// server (not an SDK issue — see `bridgeGitService()`'s comment): closing the
// server-side exec channel as soon as the spawned `git-upload-pack`/
// `git-receive-pack` child *process* exits races the `.pipe()`-buffered
// flush of its last chunk of stdout to the channel, intermittently truncating
// the pack stream and making a real `git clone` fail with "fatal: remote
// transport reported an error" despite every byte technically having been
// sent. The fix is to wait for the piped streams' own `"end"` event, not just
// the child's `"exit"`, before calling `channel.exit()`/`channel.end()`.
//
// Also confirmed empirically (see the github-api-DELETE test below): once
// `[egress.github-api]` is configured, `githubApiGate`'s `onRequest` runs
// *before* the hostname-allowlist check (`docs/gondolin-notes.md` §4:
// "`onRequest` may return a synthetic `Response` to short-circuit the
// request. Doing so skips upstream DNS and IP checks.") — so the
// `DELETE`-refused scenario does not require `api.github.com` to be reachable,
// resolvable, or even present in `egress.allow` for the block itself to work.
// It's included in `egress.allow` anyway below for scenario realism (a real
// workspace using this gate would also need the host allowlisted for the
// methods it *does* permit), not because the denial depends on it.
import crypto from "node:crypto";
import dns from "node:dns";
import fs from "node:fs";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import { spawn, execFileSync } from "node:child_process";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { VM, getInfoFromSshExecRequest, type SshExecRequest } from "@earendil-works/gondolin";
import ssh2 from "ssh2";
import { resolveRuntimeImage } from "../../src/vm/image.ts";
import { buildEgressConfig } from "../../src/vm/egress.ts";
import { buildGitSshOptions } from "../../src/vm/gitssh.ts";
import { createAuditWriter, type AuditEvent, type AuditWriter } from "../../src/policy/audit.ts";
import type { EffectiveEgressConfig, EffectiveGitConfig } from "../../src/config/load.ts";

const { Server: SshServer, utils: ssh2Utils } = ssh2;

// Matches `image/corb-image.json`'s `postBuild.commands` and
// `image/verify.ts`'s own hardcoded convention, exactly like the other e2e
// suites — not read dynamically from `/etc/corb/image.json` here, see those
// suites' own module comments for why.
const AGENT_UID = 1000;
const AGENT_GID = 1000;
const DROPCAP_PATH = "/usr/local/bin/dropcap";
const GUEST_HOME = "/home/agent";

// No login shell for any exec (array-form `exec` runs none), matching
// `image/verify.ts`'s own `BASE_PATH` convention.
const BASE_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";

// See module comment point 5. `BatchMode=yes` is extra insurance against any
// other non-interactive prompt hanging the guest exec (host-key trust is the
// only one actually expected here, given the mock server's own
// `authentication` handler accepts anything).
const GIT_SSH_COMMAND =
  "ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -o BatchMode=yes";

// An RFC 2606-reserved TLD: guaranteed to never resolve in real DNS, so this
// suite's `dns.lookup` monkeypatch (module comment point 4) is the only thing
// that could ever make it resolve to anything, on the host. What the guest
// resolves it to is irrelevant (synthetic DNS answers everything) — see point
// 3.
const GIT_HOSTNAME = "corb-e2e-git.invalid";

// Two-segment repo names are required: `getInfoFromSshExecRequest`'s own
// shape check (`node_modules/@earendil-works/gondolin/dist/src/ssh/exec.js`)
// rejects a single-segment repo argument outright, so `"repo"` alone would
// silently fail to parse and every scenario would deny for the wrong reason.
const ALLOWED_REPO = "corb-e2e/repo";
const DENIED_REPO = "corb-e2e/denied-repo";

const SESSION_ID = "corb-e2e-git-ssh-policy-session";
const SESSION_LABEL = "corb-e2e-git-ssh-policy";

const COMMIT_FILE_NAME = "hello.txt";
const COMMIT_FILE_CONTENT = "hello from corb git-ssh-policy e2e\n";

/**
 * Finds a real, non-loopback IPv4 address the host is reachable at — the
 * same mechanism `egress.e2e.ts`'s own `pickHostLanAddress()` uses, for the
 * identical reason (a literal `127.0.0.1` destination is routed by the
 * guest's own kernel to the guest's own loopback device and never traverses
 * the virtio-net path Gondolin's egress mediation intercepts). Duplicated
 * rather than shared: this project's e2e files are each deliberately
 * self-contained with their own small local helpers rather than a shared
 * e2e-utils module (matching `workspace-mounts.e2e.ts`/`egress.e2e.ts`'s own
 * precedent of small local duplication over a shared module for this exact
 * helper).
 */
function pickHostLanAddress(): string {
  const interfaces = os.networkInterfaces();
  for (const addrs of Object.values(interfaces)) {
    for (const addr of addrs ?? []) {
      if (addr.family === "IPv4" && !addr.internal) {
        return addr.address;
      }
    }
  }
  throw new Error(
    "git-ssh-policy e2e: no non-loopback IPv4 interface found on this host — this suite needs a real " +
      "LAN-facing address for its mock ssh server (127.0.0.1 does not work; see the module comment).",
  );
}

function run(cmd: string, args: string[], cwd?: string): void {
  execFileSync(cmd, args, { cwd, stdio: "pipe" });
}

/** Builds a bare git repo at `bareRepoPath` with exactly one commit, via a throwaway working clone. */
function setupBareRepo(bareRepoPath: string): void {
  const workDir = fs.mkdtempSync(path.join(os.tmpdir(), "corb-e2e-git-work-"));
  try {
    run("git", ["init", "--bare", "-q", bareRepoPath]);
    run("git", ["init", "-q", workDir]);
    fs.writeFileSync(path.join(workDir, COMMIT_FILE_NAME), COMMIT_FILE_CONTENT);
    run("git", ["-C", workDir, "config", "user.email", "corb-e2e@example.invalid"]);
    run("git", ["-C", workDir, "config", "user.name", "Corb E2E"]);
    run("git", ["-C", workDir, "add", COMMIT_FILE_NAME]);
    run("git", ["-C", workDir, "commit", "-q", "-m", "init"]);
    run("git", ["-C", workDir, "push", "-q", bareRepoPath, "HEAD:refs/heads/main"]);
  } finally {
    fs.rmSync(workDir, { recursive: true, force: true });
  }
}

/**
 * Generates the guest-facing... no — the *upstream* host key this suite's
 * mock server presents (verified host-side by Gondolin's own default
 * known_hosts host verifier, module comment point 1). Deliberately
 * reimplemented inline rather than importing the SDK's own
 * `generateSshHostKey()` (`node_modules/@earendil-works/gondolin/dist/src/ssh/utils.js`):
 * that function is not part of the package's public API (absent from
 * `dist/src/index.d.ts`), and this codebase only ever *reads* SDK internals
 * for verification, never imports them into anything that runs. Verified
 * identical to the SDK's own implementation. PEM PKCS#1 RSA specifically:
 * `ssh2`'s `Server` `hostKeys` option requires it — ed25519 pkcs8 is not
 * accepted there (same constraint the SDK's own source comments out).
 */
function generateHostKey(): string {
  const { privateKey } = crypto.generateKeyPairSync("rsa", {
    modulusLength: 3072,
    privateKeyEncoding: { format: "pem", type: "pkcs1" },
    publicKeyEncoding: { format: "pem", type: "spki" },
  });
  return privateKey;
}

/** Builds one `known_hosts` line for `hostPattern` (already bracketed `[host]:port` shape — see module comment point 2) from a PEM PKCS#1 RSA private key. */
function buildKnownHostsLine(hostPattern: string, privateKeyPem: string): string {
  const parsed = ssh2Utils.parseKey(privateKeyPem);
  if (parsed instanceof Error) {
    throw parsed;
  }
  const publicKeyWire = parsed.getPublicSSH();
  return `${hostPattern} ssh-rsa ${Buffer.from(publicKeyWire).toString("base64")}`;
}

interface ThrowawayAgent {
  sock: string;
  process: ReturnType<typeof spawn>;
}

/**
 * Starts a fresh, throwaway `ssh-agent` bound to its own scratch socket and
 * adds a freshly generated ed25519 key to it — never the real, already
 * present `SSH_AUTH_SOCK` (1Password's agent in this environment, which has
 * already caused interactive-signing friction elsewhere this session). The
 * returned socket path is handed to `buildGitSshOptions()` via its own `env`
 * parameter (never via `process.env`) — see that call site below.
 */
function startThrowawayAgent(scratchDir: string): ThrowawayAgent {
  const keyPath = path.join(scratchDir, "id_ed25519");
  run("ssh-keygen", ["-t", "ed25519", "-f", keyPath, "-N", "", "-q"]);

  const sock = path.join(scratchDir, "agent.sock");
  // `-D`: stay in the foreground (do not self-daemonize) so `spawn()`'s
  // returned child process handle is the real, live agent process — a
  // background-forking `ssh-agent` (the default) would exit immediately here
  // and leave nothing for `afterAll` to kill.
  const agentProcess = spawn("ssh-agent", ["-a", sock, "-D"], { stdio: "ignore" });

  // `ssh-agent` needs a moment to create and bind its socket before `ssh-add`
  // can connect to it. A short, fixed wait (not polling) is fine here: this
  // is host-side setup with no VM involved yet, nowhere near the 180s e2e
  // budget.
  const deadline = Date.now() + 5_000;
  while (!fs.existsSync(sock)) {
    if (Date.now() > deadline) {
      throw new Error("git-ssh-policy e2e: throwaway ssh-agent did not create its socket in time");
    }
    execFileSync("sleep", ["0.1"]);
  }

  execFileSync("ssh-add", [keyPath], { env: { ...process.env, SSH_AUTH_SOCK: sock }, stdio: "pipe" });

  return { sock, process: agentProcess };
}

/**
 * Bridges one accepted git-over-SSH exec channel to the real
 * `git-upload-pack`/`git-receive-pack` binary against `bareRepoPath`. Not a
 * protocol simulation: the actual git smart-SSH protocol logic is handled
 * entirely by the real binary; this is purely a transport bridge.
 *
 * The `{ end: false }` + explicit wait for each piped stream's own `"end"`
 * event (rather than closing the channel as soon as the child process exits)
 * is load-bearing, not defensive styling — found and fixed empirically while
 * building this suite (see the module comment): `child.stdout.pipe(channel)`
 * does not synchronously flush every buffered chunk before `child`'s own
 * `"exit"` event fires, and closing the channel at that point intermittently
 * truncates the last chunk of pack data. A real `git clone` against the
 * truncated stream fails with "fatal: remote transport reported an error"
 * despite the child process having exited 0 and having written every byte —
 * confirmed by reproducing this exact failure with a standalone script before
 * this fix, and confirming the fix resolves it.
 */
function bridgeGitService(channel: ssh2.ServerChannel, service: string, bareRepoPath: string): void {
  const child = spawn(service, [bareRepoPath], { stdio: ["pipe", "pipe", "pipe"] });

  let exitCode: number | null = null;
  let stdoutDone = false;
  let stderrDone = false;
  const maybeFinish = () => {
    if (exitCode !== null && stdoutDone && stderrDone) {
      channel.exit(exitCode);
      channel.end();
    }
  };

  channel.pipe(child.stdin);
  child.stdout.pipe(channel, { end: false });
  child.stdout.on("end", () => {
    stdoutDone = true;
    maybeFinish();
  });
  child.stderr.pipe(channel.stderr as NodeJS.WritableStream, { end: false });
  child.stderr.on("end", () => {
    stderrDone = true;
    maybeFinish();
  });
  child.on("exit", (code) => {
    exitCode = code ?? 0;
    maybeFinish();
  });
  child.on("error", () => {
    exitCode = 1;
    stdoutDone = true;
    stderrDone = true;
    maybeFinish();
  });
}

/**
 * Starts the mock SSH server this suite's "upstream" git host — real
 * `git-upload-pack`/`git-receive-pack` behind a plain transport bridge (see
 * `bridgeGitService`), not a protocol simulation. Authentication accepts any
 * method/credential unconditionally: this suite is not testing SSH's own
 * auth security, only Corb's `execPolicy` layer sitting in front of it
 * (`ssh.execPolicy` denies the guest's SSH *exec request* before it is ever
 * forwarded upstream to this server at all — the scenarios that are meant to
 * be denied never reach this server's `exec` handler in the first place).
 */
function startMockGitSshServer(
  bindHost: string,
  hostKeyPem: string,
  bareRepoPath: string,
): Promise<{ server: ssh2.Server; port: number }> {
  const server = new SshServer({ hostKeys: [hostKeyPem], ident: "SSH-2.0-corb-e2e-mock" }, (client) => {
    client.on("authentication", (ctx) => ctx.accept());
    client.on("error", () => {
      // Ignore: a guest exec that Corb's own execPolicy already denied never
      // reaches this connection at all, and a client-initiated disconnect
      // after a completed exec is normal, not a test failure.
    });
    client.on("ready", () => {
      client.on("session", (accept) => {
        const session = accept();
        session.on("exec", (accept, reject, info) => {
          const req: SshExecRequest = {
            hostname: bindHost,
            port: 0,
            guestUsername: "git",
            command: info.command,
            src: { ip: "0.0.0.0", port: 0 },
          };
          const parsed = getInfoFromSshExecRequest(req);
          if (!parsed || parsed.repo !== ALLOWED_REPO) {
            // Defense in depth only: Corb's own `execPolicy` (the real thing
            // under test) is expected to have already denied any request
            // that would land here with an unrecognized or non-allowlisted
            // repo, before it was ever forwarded to this mock server.
            const channel = accept();
            channel.stderr.write("corb-e2e mock: unrecognized or unexpected repo/service\n");
            channel.exit(1);
            channel.end();
            return;
          }
          const channel = accept();
          bridgeGitService(channel, parsed.service, bareRepoPath);
        });
      });
    });
  });

  return new Promise((resolve, reject) => {
    server.on("error", reject);
    server.listen(0, bindHost, () => {
      const address = server.address();
      if (address === null || typeof address === "string") {
        reject(new Error("git-ssh-policy e2e: mock ssh server has no usable address after listen()"));
        return;
      }
      resolve({ server, port: address.port });
    });
  });
}

function stopServer(server: ssh2.Server): Promise<void> {
  return new Promise((resolve) => server.close(() => resolve()));
}

describe.skipIf(!process.env.CORB_E2E)("git-ssh-policy e2e (real VM boot)", () => {
  let bindHost: string;
  let scratchDir: string;
  let bareRepoPath: string;
  let sshServer: ssh2.Server;
  let sshPort: number;
  let agent: ThrowawayAgent;
  let originalDnsLookup: typeof dns.lookup;
  let auditPath: string;
  let audit: AuditWriter;
  let vm: VM | undefined;

  beforeAll(async () => {
    bindHost = pickHostLanAddress();
    scratchDir = fs.mkdtempSync(path.join(os.tmpdir(), "corb-e2e-git-ssh-policy-"));
    bareRepoPath = path.join(scratchDir, "repo.git");
    setupBareRepo(bareRepoPath);

    const hostKeyPem = generateHostKey();
    const started = await startMockGitSshServer(bindHost, hostKeyPem, bareRepoPath);
    sshServer = started.server;
    sshPort = started.port;

    agent = startThrowawayAgent(scratchDir);

    // Module comment point 4: the *host* process's own upstream SSH connect
    // needs `GIT_HOSTNAME` to resolve to `bindHost`, for real, on this
    // machine — independent of the guest's synthetic DNS. Scoped to exactly
    // this one hostname; every other lookup is delegated unchanged. Restored
    // in `afterAll`, not before (unlike the `HOME` override below, this one
    // must stay active for the guest exec's entire lifetime, not just
    // `VM.create()` — every SSH exec the guest opens triggers a fresh
    // upstream connect, and thus a fresh `dns.lookup` call, later).
    originalDnsLookup = dns.lookup;
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (dns as any).lookup = (hostname: string, ...rest: unknown[]) => {
      if (hostname === GIT_HOSTNAME) {
        const callback = rest[rest.length - 1] as (err: Error | null, address: unknown, family?: number) => void;
        const options = rest.length > 1 ? (rest[0] as { all?: boolean }) : undefined;
        if (options?.all) {
          callback(null, [{ address: bindHost, family: 4 }]);
        } else {
          callback(null, bindHost, 4);
        }
        return;
      }
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      return (originalDnsLookup as any)(hostname, ...rest);
    };

    const tmpAuditDir = fs.mkdtempSync(path.join(os.tmpdir(), "corb-e2e-git-ssh-policy-audit-"));
    auditPath = path.join(tmpAuditDir, "audit.jsonl");
    audit = createAuditWriter({ path: auditPath });

    const git: EffectiveGitConfig = {
      "ssh-agent": true,
      "allow-hosts": [`${GIT_HOSTNAME}:${sshPort}`],
      "allow-repos": [ALLOWED_REPO],
      "allow-push": false,
    };
    const egress: EffectiveEgressConfig = {
      // Not required for the DELETE-refused scenario to work (see module
      // comment) — included anyway for scenario realism, matching what a
      // real workspace using `[egress.github-api]` would also configure.
      allow: ["api.github.com"],
      "block-internal-ranges": true,
      websockets: false,
      "github-api": { methods: ["GET", "POST", "PATCH"] },
    };
    const gitHostEnv: NodeJS.ProcessEnv = { SSH_AUTH_SOCK: agent.sock };

    // The exact real production functions `session.ts`'s `runSession()`
    // calls — see the module comment for why this suite calls them directly
    // rather than going through `runSession()` itself (which launches Pi's
    // interactive TUI, not scriptable for an automated assertion, the same
    // reasoning `egress.e2e.ts`/`workspace-mounts.e2e.ts` give for the same
    // choice).
    const egressConfig = buildEgressConfig(egress, undefined, {}, audit, SESSION_ID);

    // Module comment point 1: `buildGitSshOptions()` never sets
    // `knownHostsFile`, so the SDK resolves `os.homedir()` itself, internally,
    // synchronously, at this call (and again inside `VM.create()` just below).
    // Overriding `process.env.HOME` only around these two calls — never
    // touching this machine's real `~/.ssh/known_hosts` — is a documented
    // test-only mechanism, not something production code does.
    const realHome = process.env.HOME;
    process.env.HOME = scratchDir;
    fs.mkdirSync(path.join(scratchDir, ".ssh"), { recursive: true });
    fs.writeFileSync(
      path.join(scratchDir, ".ssh", "known_hosts"),
      buildKnownHostsLine(`[${GIT_HOSTNAME}]:${sshPort}`, hostKeyPem) + "\n",
    );

    let gitSshOptions: ReturnType<typeof buildGitSshOptions>;
    try {
      gitSshOptions = buildGitSshOptions(git, gitHostEnv, audit, SESSION_ID);

      const resolvedImage = resolveRuntimeImage();
      vm = await VM.create({
        sandbox: { imagePath: resolvedImage.assetDir },
        dns: { mode: "synthetic", syntheticHostMapping: "per-host" },
        httpHooks: egressConfig.httpHooks,
        env: egressConfig.env,
        allowWebSockets: egressConfig.allowWebSockets,
        ssh: gitSshOptions,
        sessionLabel: SESSION_LABEL,
      });
    } finally {
      if (realHome === undefined) {
        delete process.env.HOME;
      } else {
        process.env.HOME = realHome;
      }
    }
  }, 180_000);

  afterAll(async () => {
    try {
      if (vm) {
        await vm.close();
      }
    } finally {
      await stopServer(sshServer);
      agent?.process.kill();
      if (originalDnsLookup) {
        dns.lookup = originalDnsLookup;
      }
      fs.rmSync(scratchDir, { recursive: true, force: true });
      if (auditPath) {
        fs.rmSync(path.dirname(auditPath), { recursive: true, force: true });
      }
    }
  }, 180_000);

  function requireVm(): VM {
    if (!vm) {
      throw new Error("git-ssh-policy e2e: VM was not booted (beforeAll must have failed)");
    }
    return vm;
  }

  /** Runs a shell script as the dropped-privilege `agent` uid via `dropcap`, with `GIT_SSH_COMMAND` set (module comment point 5). */
  async function guestShell(script: string) {
    return requireVm().exec([DROPCAP_PATH, String(AGENT_UID), String(AGENT_GID), "/bin/sh", "-c", script], {
      env: { PATH: BASE_PATH, HOME: GUEST_HOME, GIT_SSH_COMMAND },
      stdout: "buffer",
      stderr: "buffer",
    });
  }

  it("fetch on an allowed repo: git clone succeeds and the guest has the real commit content", async () => {
    const cloneDir = "/tmp/corb-e2e-allowed";
    const result = await guestShell(
      `rm -rf ${cloneDir} && git clone ssh://git@${GIT_HOSTNAME}:${sshPort}/${ALLOWED_REPO} ${cloneDir} && cat ${cloneDir}/${COMMIT_FILE_NAME}`,
    );
    expect(result.ok, `exit ${result.exitCode}: ${result.stderr}`).toBe(true);
    expect(result.stdout).toContain(COMMIT_FILE_CONTENT.trim());
  });

  it("push is denied: git push fails with the readable denial message, not just a bare non-zero exit", async () => {
    const cloneDir = "/tmp/corb-e2e-push";
    const cloneResult = await guestShell(
      `rm -rf ${cloneDir} && git clone ssh://git@${GIT_HOSTNAME}:${sshPort}/${ALLOWED_REPO} ${cloneDir}`,
    );
    expect(cloneResult.ok, `setup clone failed: exit ${cloneResult.exitCode}: ${cloneResult.stderr}`).toBe(true);

    const pushResult = await guestShell(`cd ${cloneDir} && git push origin HEAD:refs/heads/main`);
    expect(pushResult.ok, "a push unexpectedly succeeded while git.allow-push is false").toBe(false);
    // The exact guest-facing message `buildGitSshOptions()` produces
    // (`src/vm/gitssh.ts`) — not just "it failed".
    expect(pushResult.stderr).toContain("corb git: push is disabled for this session");
  });

  it("a repository outside git.allow-repos is denied", async () => {
    const cloneDir = "/tmp/corb-e2e-denied";
    const result = await guestShell(
      `rm -rf ${cloneDir} && git clone ssh://git@${GIT_HOSTNAME}:${sshPort}/${DENIED_REPO} ${cloneDir}`,
    );
    expect(result.ok, "a clone of a non-allowlisted repo unexpectedly succeeded").toBe(false);
    expect(result.stderr).toContain("is not in git.allow-repos.");
  });

  it("gh api -X DELETE against api.github.com is refused (403 at the policy layer)", async () => {
    // curl drives the authoritative assertion, matching `egress.e2e.ts`'s own
    // convention exactly (`-w '%{http_code}'` distinguishes "blocked by
    // policy" from "failed for some unrelated reason" precisely, the same
    // reasoning that suite's disallowed-host scenario documents). `-f`: curl
    // itself exits non-zero on an HTTP error status.
    const curlResult = await guestShell(
      `curl -sS -f -o /dev/null -w '%{http_code}' --max-time 15 -X DELETE https://api.github.com/corb-e2e-test`,
    );
    expect(curlResult.ok, "a DELETE to the github-api gate unexpectedly succeeded").toBe(false);
    expect(curlResult.stdout.trim()).toBe("403");

    // Best-effort, secondary check with the real `gh` CLI (the image ships
    // `github-cli`, per `image/corb-image.json`): a placeholder `GH_TOKEN` is
    // enough to get `gh` past its own local "not logged in" short-circuit and
    // actually issue the HTTP request — the token never needs to be valid,
    // since `githubApiGate` blocks before any upstream request (real or
    // fake-authenticated) is ever attempted. Not the authoritative assertion
    // (gh's own error-reporting for a non-JSON 403 body is not as precisely
    // scriptable as curl's `-w`), but real evidence `gh` itself is refused
    // too, not only a raw `curl` invocation.
    const ghResult = await guestShell(`GH_TOKEN=corb-e2e-placeholder-token gh api -X DELETE /corb-e2e-test`);
    expect(ghResult.ok, "gh api -X DELETE unexpectedly succeeded").toBe(false);
  });

  it("audit log: real channel=ssh entries (allow and deny) and a channel=http, decision=deny entry are on disk after flush()", () => {
    audit.flush();
    expect(fs.existsSync(auditPath)).toBe(true);
    const lines = fs
      .readFileSync(auditPath, "utf8")
      .trim()
      .split("\n")
      .map((line) => JSON.parse(line) as AuditEvent);

    const sshAllow = lines.find(
      (event) =>
        event.channel === "ssh" && event.decision === "allow" && event.subject === `git-upload-pack ${ALLOWED_REPO}`,
    );
    expect(sshAllow, `no matching ssh/allow entry in: ${JSON.stringify(lines)}`).toBeDefined();
    expect(sshAllow?.sessionId).toBe(SESSION_ID);

    const sshPushDeny = lines.find(
      (event) =>
        event.channel === "ssh" &&
        event.decision === "deny" &&
        event.subject === `git-receive-pack ${ALLOWED_REPO}` &&
        event.reason?.includes("push is disabled for this session"),
    );
    expect(sshPushDeny, `no matching ssh/deny (push) entry in: ${JSON.stringify(lines)}`).toBeDefined();

    const sshRepoDeny = lines.find(
      (event) =>
        event.channel === "ssh" &&
        event.decision === "deny" &&
        event.subject === `git-upload-pack ${DENIED_REPO}` &&
        event.reason?.includes("is not in git.allow-repos."),
    );
    expect(sshRepoDeny, `no matching ssh/deny (allow-repos) entry in: ${JSON.stringify(lines)}`).toBeDefined();

    const httpDeny = lines.find(
      (event) =>
        event.channel === "http" && event.decision === "deny" && event.subject.startsWith("DELETE api.github.com"),
    );
    expect(httpDeny, `no matching http/deny entry in: ${JSON.stringify(lines)}`).toBeDefined();
    expect(httpDeny?.reason).toBe("method not allowed");
  });
});
