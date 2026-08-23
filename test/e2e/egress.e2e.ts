// M3.4 — real-VM proof that `src/vm/session.ts`'s new wiring of
// `buildEgressConfig()` (`src/vm/egress.ts`, M3.2/M3.3) into `VM.create()`
// actually holds against a booted guest: the placeholder-for-real-secret
// substitution genuinely happens on the wire for an allowed host, a
// disallowed host is genuinely blocked (not just "untested"), and the
// `http`-channel audit record `buildEgressConfig()` wires up genuinely lands
// on disk — none of which M3.3's own unit tests could exercise, since they
// never boot a VM.
//
// Gating and layout matches `test/e2e/workspace-mounts.e2e.ts` (M2.4)
// exactly: `vitest.config.ts` never matches `test/e2e/**`, so a plain `npm
// test` never touches this file regardless of its content, and
// `describe.skipIf` below additionally gates the whole suite on
// `CORB_E2E=1`. Run via `npm run test:e2e` (with `CORB_E2E=1`) or `make e2e`.
//
// Why this drives `buildEgressConfig()` + `VM.create()` directly instead of
// `runSession()`: `runSession()` launches Pi's *interactive* TUI (`dropcap`
// -> `pi`) attached to real stdio, and — more fundamentally for this suite —
// there is no deterministic, scriptable way to make an interactive `pi`
// process exit so an automated test can assert on it, the same reasoning
// `workspace-mounts.e2e.ts`'s own module comment gives for the same choice.
// What's under test here is `session.ts`'s *egress* wiring specifically
// (`buildEgressConfig()`'s output threaded into `VM.create({ httpHooks, env,
// allowWebSockets })`, and `buildGuestEnv()` receiving that `env`), not the
// agent session itself. So this suite calls `buildEgressConfig()` — the
// exact, real production function `session.ts` now calls — and then wires
// its result into `VM.create()` using the exact same field mapping
// `session.ts`'s `runSession()` uses (`httpHooks: egressConfig.httpHooks`,
// `env: egressConfig.env`, `allowWebSockets: egressConfig.allowWebSockets`).
// A drift between this test's wiring and `session.ts`'s own wiring would
// fail this suite, not silently diverge — the same principle
// `workspace-mounts.e2e.ts` applied to `rawWorkspacePath`/
// `publicWorkspacePath`, generalized here to `buildEgressConfig`. Guest
// identity (uid/gid 1000, `/usr/local/bin/dropcap`) is hardcoded rather than
// read from `/etc/corb/image.json` at runtime, matching that suite's own
// convention for the same reason (orthogonal to what this item changed).
//
// Real network access, not a local test server, was the M0.1 spike's own
// approach for proving HTTP/2 negotiation against `api.anthropic.com`
// specifically (`docs/spike-results.md` M0.1) — but a fixed external host is
// a poor fit for *this* suite's job, which needs to assert precisely what
// the "allowed" destination actually received (the real secret value, not
// the placeholder) and precisely what a "disallowed" destination did NOT
// receive (anything at all). A real host's API 401 response would prove far
// less than a local server's own captured request. So, following that same
// spike's own fallback design (`spike/m0-1-http2/stream-server.mjs`), this
// suite runs a small local HTTP server on the host, bound to the host's real
// LAN-facing interface address — **not** `127.0.0.1`. `docs/spike-results.md`
// documents in detail why: a literal `127.0.0.1` destination is routed by
// the *guest's own kernel* to the guest's own loopback device and never
// traverses the virtio-net path Gondolin's egress mediation intercepts, so
// it can never reach the host's loopback at all, regardless of any allowlist
// or secret-binding configuration. `pickHostLanAddress()` below finds a real
// address the same way that spike did (`os.networkInterfaces()`).
//
// Scenario 2 (disallowed host) deliberately does *not* use "the same host,
// a different port" — despite that being one of the options this item's own
// brief suggested — because Gondolin's own hostname-allowlist matching
// (`matchesAnyHost`, confirmed against the installed SDK's
// `dist/src/host/patterns.js`) matches on hostname only and ignores port
// entirely. A second server on the *same* allowed host at a different port
// would therefore still pass the allowlist check; using it here would make
// the "disallowed" scenario coincidentally fail for an unrelated reason
// (nothing listening on that port) rather than actually exercising the
// hostname-allowlist block this scenario means to test.
//
// It also deliberately does *not* use "literally any host string" in the
// form of a fabricated hostname (e.g. an invented `*.invalid` name) — tried
// first, and reverted after empirical evidence (this is exactly the kind of
// thing this project's own standard says to verify for real rather than
// assume): the installed SDK's `resolveHostname()`
// (`dist/src/qemu/http.js`) only takes its literal-IP fast path when
// `net.isIP(hostname)` is truthy; for anything else, including a fabricated
// hostname, it falls through to a **real, host-side `dns.lookup()`** for
// policy-check purposes — a completely separate resolution from the guest's
// own synthetic DNS answers, and one this suite has no control over. On this
// host that lookup did not fail as expected; it returned addresses in the
// RFC 3849/RFC 2544 documentation ranges (this network's resolver
// apparently answers unresolvable names rather than returning `NXDOMAIN`),
// which took a *different* internal error path than the intended
// "blocked by policy" one (a `400 Bad Request` from request-shape
// validation, not the `403` `HttpRequestBlockedError` default) — a false
// pass/fail for the wrong reason, and not portable across hosts with
// different resolver behavior regardless. Using a **literal IP** address
// instead (`DISALLOWED_HOST`, an RFC 5737 `192.0.2.0/24` "TEST-NET-1"
// documentation address — guaranteed non-routable, never assigned to a real
// host) takes `resolveHostname()`'s `net.isIP` fast path, so this scenario
// never performs a real DNS lookup at all and is blocked purely by the
// hostname-allowlist check (`matchesAnyHost` against `egress.allow`)
// returning false — confirmed against a real boot below to synthesize a
// deterministic `403 Forbidden` from Gondolin's own policy layer, not an
// unrelated `400`.
//
// DNS-rebinding-style bypass (`dns: { mode: "synthetic", syntheticHostMapping:
// "per-host" }`, unchanged by this item) is deliberately **not** tested here.
// That protection is entirely Gondolin's own, and testing it properly needs
// DNS-control machinery (a resolver the test can flip mid-session) beyond
// what this item's scope justifies — a deliberately deferred piece of M3's
// overall acceptance criteria, not a hole in this item's own verification.
import fs from "node:fs";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { VM } from "@earendil-works/gondolin";
import { resolveRuntimeImage } from "../../src/vm/image.ts";
import { buildEgressConfig } from "../../src/vm/egress.ts";
import { createAuditWriter, type AuditEvent, type AuditWriter } from "../../src/policy/audit.ts";
import type { EffectiveEgressConfig } from "../../src/config/load.ts";
import type { PartialSecretConfig } from "../../src/config/schema.ts";

// Matches `image/corb-image.json`'s `postBuild.commands` and
// `image/verify.ts`'s own hardcoded convention for the same values, exactly
// like `workspace-mounts.e2e.ts` — not read dynamically from
// `/etc/corb/image.json` here, see the module comment for why.
const AGENT_UID = 1000;
const AGENT_GID = 1000;
const DROPCAP_PATH = "/usr/local/bin/dropcap";

// No login shell for any exec (array-form `exec` runs none), matching
// `image/verify.ts`'s own `BASE_PATH` convention.
const BASE_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";

const SECRET_NAME = "TEST_TOKEN";
const REAL_SECRET_VALUE = `real-secret-${crypto.randomUUID()}`;
const SESSION_ID = "corb-e2e-egress-session";
const SESSION_LABEL = "corb-e2e-egress";

// A literal IP, deliberately not derived from `bindHost` and deliberately
// not a hostname — see the module comment for why both "same host, different
// port" and "a fabricated hostname" are the wrong shape for this scenario.
// RFC 5737 reserves 192.0.2.0/24 ("TEST-NET-1") for documentation: it is
// guaranteed to never be a real, routable host, so this scenario's failure
// is guaranteed to come from Gondolin's own hostname-allowlist check, not
// from anything address-specific.
const DISALLOWED_HOST = "192.0.2.1";

/**
 * Finds a real, non-loopback IPv4 address the host is reachable at, the same
 * way `spike/m0-1-http2/stream-server.mjs` did — `127.0.0.1` specifically
 * does not work here (see module comment), and there is no other portable
 * way to get "an address the guest's virtio-net egress path can actually
 * reach" than asking the OS what its real interfaces are.
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
    "egress e2e: no non-loopback IPv4 interface found on this host — this suite needs a real " +
      "LAN-facing address to bind its local test server to (127.0.0.1 does not work; see the module comment).",
  );
}

/** Starts a plain HTTP server on `host`, an ephemeral port, resolving once listening. Returns the server and its bound port. */
function startHttpServer(host: string, handler: http.RequestListener): Promise<{ server: http.Server; port: number }> {
  return new Promise((resolve, reject) => {
    const server = http.createServer(handler);
    server.on("error", reject);
    server.listen(0, host, () => {
      const address = server.address();
      if (address === null || typeof address === "string") {
        reject(new Error("egress e2e: test server has no usable address after listen()"));
        return;
      }
      resolve({ server, port: address.port });
    });
  });
}

function stopHttpServer(server: http.Server): Promise<void> {
  return new Promise((resolve, reject) => {
    server.close((err) => (err ? reject(err) : resolve()));
  });
}

describe.skipIf(!process.env.CORB_E2E)("egress e2e (real VM boot)", () => {
  let bindHost: string;
  let allowedServer: http.Server;
  let allowedPort: number;
  let receivedAuthHeader: string | undefined;
  let allowedRequestCount = 0;

  let auditPath: string;
  let audit: AuditWriter;
  let vm: VM | undefined;

  beforeAll(async () => {
    bindHost = pickHostLanAddress();

    // The "allowed" destination: captures the `Authorization` header it
    // actually received (proof of host-side substitution) and responds 200.
    const started = await startHttpServer(bindHost, (req, res) => {
      allowedRequestCount++;
      receivedAuthHeader = req.headers.authorization;
      res.writeHead(200, { "Content-Type": "text/plain" }).end("ok\n");
    });
    allowedServer = started.server;
    allowedPort = started.port;

    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "corb-e2e-egress-audit-"));
    auditPath = path.join(tmpDir, "audit.jsonl");
    audit = createAuditWriter({ path: auditPath });

    const egress: EffectiveEgressConfig = {
      allow: [bindHost],
      // `bindHost` (a real LAN-facing interface address — see
      // `pickHostLanAddress()`) is itself a private/internal-range address
      // by the installed SDK's own `isPrivateIPv4()` classification
      // (`dist/src/http/hooks.js`), and `block-internal-ranges` defaults on
      // (`docs/design.md` §8/`src/config/load.ts`'s own
      // `DEFAULT_BLOCK_INTERNAL_RANGES`) — without listing it here too, the
      // "allowed" scenario below would itself be denied as an internal
      // destination, verified against a real boot the first time this
      // suite was written (empirically required, not assumed).
      "allow-internal": [bindHost],
      "block-internal-ranges": true,
      websockets: false,
    };
    const secrets: Record<string, PartialSecretConfig> = {
      [SECRET_NAME]: { hosts: [bindHost] },
    };
    const hostEnv: NodeJS.ProcessEnv = { [SECRET_NAME]: REAL_SECRET_VALUE };

    // The exact real production function `session.ts`'s `runSession()` now
    // calls — see the module comment for why this suite calls it directly
    // rather than going through `runSession()` itself.
    const egressConfig = buildEgressConfig(egress, secrets, hostEnv, audit, SESSION_ID);

    const resolvedImage = resolveRuntimeImage();
    vm = await VM.create({
      sandbox: { imagePath: resolvedImage.assetDir },
      dns: { mode: "synthetic", syntheticHostMapping: "per-host" },
      httpHooks: egressConfig.httpHooks,
      env: egressConfig.env,
      allowWebSockets: egressConfig.allowWebSockets,
      sessionLabel: SESSION_LABEL,
    });

    // Sanity check on the harness itself, before trusting any assertion
    // below: the guest-visible env var must be the placeholder Gondolin
    // minted, never the real value — if this ever fails, every other
    // assertion in this suite would be meaningless.
    if (egressConfig.env[SECRET_NAME] === REAL_SECRET_VALUE) {
      throw new Error("egress e2e: buildEgressConfig() handed the real secret value to the guest, not a placeholder");
    }
  }, 180_000);

  afterAll(async () => {
    try {
      if (vm) {
        await vm.close();
      }
    } finally {
      await stopHttpServer(allowedServer);
      fs.rmSync(path.dirname(auditPath), { recursive: true, force: true });
    }
  }, 180_000);

  function requireVm(): VM {
    if (!vm) {
      throw new Error("egress e2e: VM was not booted (beforeAll must have failed)");
    }
    return vm;
  }

  /** Runs a shell script as the dropped-privilege `agent` uid via `dropcap`, with the guest env `buildEgressConfig()` produced (placeholder secrets only). */
  async function guestShell(script: string) {
    return requireVm().exec([DROPCAP_PATH, String(AGENT_UID), String(AGENT_GID), "/bin/sh", "-c", script], {
      env: { PATH: BASE_PATH },
      stdout: "buffer",
      stderr: "buffer",
    });
  }

  it("allowed host: the guest's request succeeds, the real server receives the real secret, and the guest's own env never holds it", async () => {
    const result = await guestShell(
      `curl -sS -o /dev/null -w '%{http_code}' --max-time 20 ` +
        `-H "Authorization: Bearer $${SECRET_NAME}" ` +
        `http://${bindHost}:${allowedPort}/allowed`,
    );
    expect(result.ok, `exit ${result.exitCode}: ${result.stderr}`).toBe(true);
    expect(result.stdout.trim()).toBe("200");

    // The concrete proof host-side substitution actually happened: the real
    // server received the *real* value, not the placeholder the guest held.
    expect(allowedRequestCount).toBe(1);
    expect(receivedAuthHeader).toBe(`Bearer ${REAL_SECRET_VALUE}`);

    // The guest's own view of its environment — both the exec'd process's
    // plain `env` and its `/proc/self/environ` — must contain only the
    // placeholder, never the real value. Also scans every other
    // `/proc/<pid>/environ` this unprivileged process can read (the same
    // process tree `docs/design.md` §2 bounds — anything unreadable to it is
    // equally unreadable to whatever it's modeling), matching
    // `docs/gondolin-notes.md` §5's own "process environment, /proc/*/environ"
    // verification for the earlier hardcoded-single-secret case, re-run here
    // for the new generalized path.
    const dumpResult = await guestShell(
      `env; echo ---SELF-ENVIRON---; tr '\\0' '\\n' < /proc/self/environ; ` +
        // `2>/dev/null` before the input redirect (not after): a shell
        // reports a failed input redirection itself, before ever invoking
        // `tr`, so the redirect that silences it must be the one already in
        // effect at that point — ordering it after `< "$p/environ"` (which
        // was tried first) does not suppress this shell's own "can't open"
        // message. Most other pids' `/proc/<pid>/environ` are expected to
        // be unreadable to this unprivileged uid (owned by root or another
        // uid) — that is fine and expected, not a failure, so `; true` at
        // the end keeps the overall script's exit code meaningful (0)
        // regardless of how many individual entries were skipped.
        `echo ---ALL-ENVIRON---; for p in /proc/[0-9]*; do tr '\\0' '\\n' 2>/dev/null < "$p/environ"; done; true`,
    );
    expect(dumpResult.ok, `exit ${dumpResult.exitCode}: ${dumpResult.stderr}`).toBe(true);
    expect(dumpResult.stdout).not.toContain(REAL_SECRET_VALUE);
    // The placeholder, in contrast, is expected to be present (it's how we
    // know the guest env was actually populated at all, not just empty).
    expect(dumpResult.stdout).toContain(`${SECRET_NAME}=`);
  });

  it("disallowed host: the guest's request fails (blocked), not a successful response", async () => {
    // `-f`: curl itself exits non-zero on an HTTP error status rather than
    // treating "got a response" as success — the concrete verification
    // (against a real boot, not assumed) that a hostname-allowlist denial
    // manifests as a real HTTP-level `403 Forbidden` from Gondolin's own
    // policy layer (`HttpRequestBlockedError`'s own default status, per the
    // installed SDK's `dist/src/http/utils.js`), not a connection-level
    // failure — both are "the request fails, not a successful response" as
    // this scenario's brief asks for; this suite asserts the specific,
    // deterministic one this SDK version actually produces. `-w` still
    // captures the status code even with `-f`, so the assertion below is
    // precise about *why* it failed, not just that it failed.
    const result = await guestShell(
      `curl -sS -f -o /dev/null -w '%{http_code}' --max-time 10 http://${DISALLOWED_HOST}/blocked`,
    );
    expect(result.ok, "a request to a disallowed host unexpectedly succeeded").toBe(false);
    expect(result.stdout.trim()).toBe("403");
  });

  it("audit log: a channel=http, decision=allow entry for the allowed request is on disk after flush()", () => {
    audit.flush();
    expect(fs.existsSync(auditPath)).toBe(true);
    const lines = fs
      .readFileSync(auditPath, "utf8")
      .trim()
      .split("\n")
      .map((line) => JSON.parse(line) as AuditEvent);

    // `safeSubject()` (`src/vm/egress.ts`) is `${method} ${hostname}${pathname}`
    // — deliberately no port (and no query string, no headers; see that
    // function's own doc comment) — so the match is on hostname + path, not
    // `bindHost:allowedPort`.
    const httpAllow = lines.find(
      (event) => event.channel === "http" && event.decision === "allow" && event.subject === `GET ${bindHost}/allowed`,
    );
    expect(httpAllow, `no matching http/allow entry in: ${JSON.stringify(lines)}`).toBeDefined();
    expect(httpAllow?.sessionId).toBe(SESSION_ID);
    // Never a raw URL, header, or query string — `docs/design.md` §6.
    expect(httpAllow?.subject).not.toContain(REAL_SECRET_VALUE);
  });
});
