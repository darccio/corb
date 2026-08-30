// M9.4 — real-VM proof that `--expose PORT`'s wiring (`vm.enableIngress()` +
// `vm.setIngressRoutes()` in `src/vm/session.ts`) actually forwards a real
// HTTP request from the host, through Gondolin's host-to-guest ingress
// reverse proxy, to a real server listening inside the guest — not just that
// the host-side types compile. Closes `docs/gondolin-notes.md` R10
// empirically (it was `resolved-by-inspection` — reading the shipped types
// and docs — but never verified against a real boot).
//
// Gating matches every other suite under `test/e2e/`: `vitest.config.ts`
// never matches `test/e2e/**`, so a plain `npm test` never touches this file
// regardless of content, and `describe.skipIf` below additionally gates the
// whole suite on `CORB_E2E=1`. Run via `npm run test:e2e` (with
// `CORB_E2E=1`) or `make e2e`.
//
// Why this drives `VM.create()` directly instead of `runSession()`: the same
// reasoning `egress.e2e.ts`'s own module comment gives for its own wiring —
// `runSession()` launches Pi's *interactive* TUI (`dropcap` -> `pi`) attached
// to real stdio, and there is no deterministic, scriptable way to make an
// interactive `pi` process exit so an automated test can assert on it. What's
// under test here is `session.ts`'s *ingress* wiring specifically
// (`vm.enableIngress()` called with no overrides, and the single
// `{ prefix: "/", port, stripPrefix: true }` route `setIngressRoutes()` is
// given when `options.expose` is set), not the agent session itself. So this
// suite calls `vm.enableIngress()`/`vm.setIngressRoutes()` directly, using
// the exact same call shape `session.ts`'s `runSession()` uses — a drift
// between this test's wiring and `session.ts`'s own wiring would fail this
// suite, not silently diverge, the same principle `workspace-mounts.e2e.ts`
// and `egress.e2e.ts` already apply to their own respective wiring. `vfs` is
// deliberately left unset in `VM.create()` below (matching
// `session-watchdog.e2e.ts`'s own minimal boot, which does the same):
// `gondolin-notes.md` §9 records that ingress requires the SDK's own default
// `/etc/gondolin` mount, which only exists when nothing overrides `vfs` — a
// custom `vfs.mounts` entry at `/etc/gondolin`, or `vfs: null`, would make
// `enableIngress()` fail outright.
//
// The guest server: a one-line inline Node HTTP server (`node -e ...`) —
// `nodejs` is in `image/corb-image.json`'s `rootfsPackages`, so `/usr/bin/node`
// is present (confirmed by `image/verify.ts`'s own `gateCaTrust`, which
// already execs it at that exact path). It is deliberately **not**
// shell-backgrounded (`cmd &`): nothing in this SDK documents a backgrounded
// shell child surviving past its parent exec's own completion inside this
// guest. Instead, following the *measured* behavior `gondolin-notes.md`
// §3/§13 (M0.4, risk R2) established — a second, concurrent `vm.exec()`
// genuinely runs in parallel with anything else already running, with no
// serialization — the server's own `vm.exec()` call is simply never awaited
// to completion; it runs for the whole suite, exactly like production's
// long-lived `pi` exec under `dropcap`. Its promise is given a no-op
// `.catch()` so `vm.close()` rejecting it with `server_shutdown` during
// teardown (`gondolin-notes.md` edge #18) doesn't surface as an unhandled
// rejection and crash the test process.
import http from "node:http";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createHttpHooks, VM, type IngressAccess } from "@earendil-works/gondolin";
import { resolveRuntimeImage } from "../../src/vm/image.ts";

// No login shell for any exec (array-form `exec` runs none), matching
// `image/verify.ts`'s own `BASE_PATH` convention and every other e2e suite's.
const BASE_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";

const GUEST_PORT = 8099;
const GUEST_RESPONSE_BODY = "corb-ingress-e2e-hello";

describe.skipIf(!process.env.CORB_E2E)("ingress e2e (real VM boot)", () => {
  let vm: VM | undefined;
  let ingressAccess: IngressAccess | undefined;

  beforeAll(async () => {
    const resolvedImage = resolveRuntimeImage();
    // Deny-all egress — this suite exercises host-to-guest ingress, not
    // guest-to-host egress, so nothing here needs an allowed host, matching
    // `workspace-mounts.e2e.ts`'s own `createHttpHooks({ allowedHosts: [],
    // allowedInternalHosts: [] })` for the same reason.
    const { httpHooks, env } = createHttpHooks({ allowedHosts: [], allowedInternalHosts: [] });

    vm = await VM.create({
      sandbox: { imagePath: resolvedImage.assetDir },
      dns: { mode: "synthetic", syntheticHostMapping: "per-host" },
      httpHooks,
      env,
      sessionLabel: "corb-e2e-ingress",
    });

    // The guest server — see the module comment for why this is a
    // never-awaited, concurrent `vm.exec()` rather than a shell-backgrounded
    // process. Responds with a fixed, distinctive body regardless of request
    // path or method, so the assertion below proves the request genuinely
    // round-tripped through the guest process, not merely that ingress
    // accepted a connection.
    const serverScript =
      "require('http').createServer((req,res)=>{" +
      "res.writeHead(200,{'Content-Type':'text/plain'});" +
      `res.end('${GUEST_RESPONSE_BODY}');` +
      `}).listen(${GUEST_PORT},'127.0.0.1',()=>{console.log('LISTENING');});`;
    const serverProc = vm.exec(["/usr/bin/node", "-e", serverScript], {
      env: { PATH: BASE_PATH, HOME: "/root" },
      stdout: "buffer",
      stderr: "buffer",
    });
    serverProc.catch(() => {
      // Expected during teardown: `vm.close()` rejects every live exec with
      // `server_shutdown` (`gondolin-notes.md` edge #18). Nothing to do with
      // that rejection here — this exec's whole job was to run, unawaited,
      // for the suite's own lifetime.
    });

    // Give the server a moment to actually start listening before wiring
    // ingress at it (the milestone's own expectation) — a fixed delay rather
    // than a poll, since `vm.exec`'s `"buffer"` mode only exposes stdout once
    // the process has exited, not incrementally, so there is no lower-level
    // guest signal this suite can poll on short of the HTTP request itself
    // (which `getWithRetry` below retries against regardless).
    await new Promise((resolve) => setTimeout(resolve, 1000));

    ingressAccess = await vm.enableIngress();
    vm.setIngressRoutes([{ prefix: "/", port: GUEST_PORT, stripPrefix: true }]);
  }, 180_000);

  afterAll(async () => {
    // `close-ingress` before `close-vm` — mirrors `src/vm/session.ts`'s own
    // shutdown ordering (stop accepting new external connections before
    // tearing down the VM), not merely convenient cleanup order.
    if (ingressAccess) {
      await ingressAccess.close();
    }
    if (vm) {
      await vm.close();
    }
  }, 180_000);

  function requireIngressAccess(): IngressAccess {
    if (!ingressAccess) {
      throw new Error("ingress e2e: ingress was not enabled (beforeAll must have failed)");
    }
    return ingressAccess;
  }

  /**
   * GETs `url`, retrying briefly both on a connection error *and* on a `502`
   * response. The guest server's `listen()` and the ingress route becoming
   * live are both asynchronous relative to this suite's fixed startup delay
   * above, and — confirmed empirically — the ingress gateway itself comes up
   * and accepts the connection before the guest server is necessarily ready
   * to accept the proxied one, which surfaces as a normal HTTP `502` from the
   * gateway (an upstream-connect failure), not a host-side connection error.
   * A short retry budget absorbs both without making the fixed delay itself
   * longer than it needs to be in the common case.
   */
  function getWithRetry(url: string, attemptsLeft = 10): Promise<{ status: number; body: string }> {
    return new Promise((resolve, reject) => {
      const retryOrSettle = (result: { status: number; body: string } | undefined, err: unknown): void => {
        const shouldRetry = (result !== undefined && result.status === 502) || (result === undefined && err !== undefined);
        if (!shouldRetry || attemptsLeft <= 1) {
          if (result !== undefined) {
            resolve(result);
          } else {
            reject(err);
          }
          return;
        }
        setTimeout(() => {
          getWithRetry(url, attemptsLeft - 1).then(resolve, reject);
        }, 500);
      };

      const req = http.get(url, (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (chunk: Buffer) => chunks.push(chunk));
        res.on("end", () => {
          retryOrSettle({ status: res.statusCode ?? 0, body: Buffer.concat(chunks).toString("utf8") }, undefined);
        });
      });
      req.on("error", (err) => {
        retryOrSettle(undefined, err);
      });
    });
  }

  it("forwards a real HTTP request from the host, through ingress, to the guest server", async () => {
    const access = requireIngressAccess();
    const response = await getWithRetry(access.url);
    expect(response.status).toBe(200);
    expect(response.body).toBe(GUEST_RESPONSE_BODY);
  });
});
