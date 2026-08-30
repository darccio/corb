# Spike results

Dated, evidence-backed answers to the blocking M0 spike gates in
[`gondolin-notes.md`](./gondolin-notes.md) §13. Throwaway code lives under
`spike/`; this file is the durable record of what was run and what came back.

---

## M0.1 — R1: HTTP/2 to the model API

**Date:** 2026-08-22
**Gondolin version:** `@earendil-works/gondolin@0.12.0` (pinned exact, no caret)
**Verdict: PASS.** Gondolin's HTTP/1.x-only egress is not a blocker. A real TLS
handshake to `api.anthropic.com` completes and negotiates HTTP/1.1 (never
HTTP/2), and chunked/streaming responses are delivered to the guest
incrementally, not buffered and dumped at the end.

### What was built

`spike/m0-1-http2/`:

- `package.json` — standalone package, depends on exactly
  `@earendil-works/gondolin@0.12.0`.
- `build-config.json` — minimal `BuildConfig`: `alpine.rootfsPackages:
  ["linux-virt", "nodejs", "curl", "ca-certificates", "bash"]`, **no
  `postBuild` section**, so the build needs neither Docker nor root on this
  native-Linux host. Built via the `gondolin build` CLI (from
  `node_modules/.bin`) with `/usr/sbin:/sbin` prepended to `PATH` for
  `mkfs.ext4`/`resize2fs` — the notes' warning about e2fsprogs not being on
  this user's PATH was confirmed accurate; the build fails obscurely without
  the prepend and succeeds cleanly with it. Assets under
  `spike/m0-1-http2/assets/`.
- `run-spike.mjs` — boots the VM (`sandbox.imagePath` pointing at the assets
  directory, `dns: { mode: "synthetic", syntheticHostMapping: "per-host" }`,
  `httpHooks` from `createHttpHooks({ allowedHosts, allowedInternalHosts })`,
  `env.NODE_EXTRA_CA_CERTS = "/run/gondolin/ca-certificates.crt"`), runs both
  checks via `vm.exec`, closes the VM in a `finally`.
- `stream-server.mjs` — host-side chunked test server (5 chunks, 400ms apart,
  `Transfer-Encoding: chunked`, SSE-shaped payload), HTTPS with a self-signed
  cert or plain HTTP via `--http`.
- `guest-stream-check.mjs` — runs inside the guest via `node`, consumes the
  stream with global `fetch`, logs a timestamp per chunk.

### Check 1 — real-endpoint protocol check (no API key needed)

`vm.exec(["/usr/bin/curl", "-v", "--cacert", "/run/gondolin/ca-certificates.crt", "https://api.anthropic.com/v1/messages", "-X", "POST", "-d", "{}"])`.

Verbatim key lines from curl's verbose output (full log:
`spike/m0-1-http2/evidence-05-final-combined-pass.log`):

```
* ALPN: curl offers h2,http/1.1
* TLSv1.3 (IN), TLS handshake, Server hello (2):
* SSL connection using TLSv1.3 / TLS_AES_256_GCM_SHA384 / X25519MLKEM768 / RSASSA-PSS
* ALPN: server accepted http/1.1
* Server certificate:
*   subject: CN=api.anthropic.com
*   issuer: CN=gondolin-mitm-ca
* OpenSSL verify result: 0
* SSL certificate verified via OpenSSL.
* Established connection to api.anthropic.com (198.19.0.1 port 443) from 192.168.127.3 port 58376
* using HTTP/1.x
> POST /v1/messages HTTP/1.1
< HTTP/1.1 401 Unauthorized
```

Response body: `{"type":"error","error":{"type":"authentication_error","message":"x-api-key header is required"}}`.

Reading: curl offered both `h2` and `http/1.1` in its ALPN extension; the
connection (proxied through Gondolin's MITM at `192.168.127.3`, the guest's
fixed LAN address, to the real upstream at `198.19.0.1`, an address inside the
synthetic-DNS mapped range) came back negotiated to `http/1.1`. The leaf
certificate is issued by `gondolin-mitm-ca` for `CN=api.anthropic.com` — the
MITM terminating-TLS behaviour documented in §4 of `gondolin-notes.md`,
confirmed live. The TLS handshake fully completed, the HTTP/1.1 request went
out and a real HTTP/1.1 response (401, API-key-gated, exactly as expected with
no key configured) came back. This is the "pass" shape described in the task
brief: a hard protocol failure would have looked like a stalled or reset
connection before any HTTP-layer response, not a clean 401.

### Check 2 — incremental (streaming) delivery

This required two rounds of debugging past the originally planned test setup,
both of which are themselves informative results and are kept as evidence.

**Round 1 (failed, and why):** the initial plan was to bind the local test
server to `127.0.0.1` on the host and have the guest fetch
`https://127.0.0.1:<port>/stream`, on the theory that Gondolin's egress
mediation would intercept and forward it (this is also why
`allowedInternalHosts` needs to explicitly list `127.0.0.1` — it is one of the
ranges `blockInternalRanges` blocks by default). This failed with:

```
[guest] fetch failed: TypeError: fetch failed
[guest] cause: Error: connect ECONNREFUSED 127.0.0.1:8443
```

— reproduced identically with plain HTTP too (ruling out a TLS/cert cause; see
`evidence-02-plain-http-still-fails-on-127-loopback.log`). The host-side
server's access log showed **zero** connection attempts during these guest
runs, confirming the request never reached the host at all. Root cause: a
literal `127.0.0.1` destination is routed by the **guest's own kernel** to the
guest's own loopback device and never traverses the virtio-net path that
Gondolin's egress mediator sits on — it isn't network traffic from the guest's
perspective, so there is nothing for the host-side proxy to intercept.
`blockInternalRanges`/`allowedInternalHosts` evidently exist to guard against
a *hostname* resolving (via the host's own DNS resolution of the `Host`
header) to an internal-looking address, not to imply that literal
guest-loopback traffic is proxied to the host. **This is a test-harness
finding, not a Gondolin defect** — nothing in the constraints permitted
editing `/etc/hosts`, so the fix was to bind the test server to the host's
real LAN-facing interface address (`192.168.1.201`, found via `ip -4 addr
show`) instead of loopback, and pass that literal IP in the guest's request
URL and in `allowedHosts`/`allowedInternalHosts`. Still no system
configuration changes — only a socket bind to an address the host already
owns.

**Round 2 (self-signed HTTPS on the LAN IP, failed as anticipated):** with the
server rebound to `192.168.1.201`, HTTPS with the self-signed cert
(`openssl req -x509 ... -subj '/CN=127.0.0.1'`) was tried first, per the task
brief. It failed:

```
[guest] fetch failed: TypeError: fetch failed
[guest] cause: Error: ...SSL alert number 40 (handshake failure)
```

(full log: `evidence-03-selfsigned-https-rejected-on-host-upstream-leg.log`).
This is exactly the anticipated risk: the host-to-upstream leg (Gondolin's own
outbound connection from the host process to the local test server) uses the
host's normal TLS stack, which rejects a self-signed certificate it has no
reason to trust. Per the documented fallback, the test server was restarted
in plain-HTTP mode. **Streaming behaviour does not depend on TLS** — MITM CA
trust is M0.2's concern, not this one — so this is a legitimate substitution,
not a compromise of what's being tested.

**Round 3 (pass):** plain HTTP, bound to `192.168.1.201`. Verbatim guest
output (full log: `evidence-05-final-combined-pass.log`, also standalone in
`evidence-04-http-lanip-check2-only-pass.log`):

```
[guest] response status 200 at t+530ms
[guest] chunk 0 at t+533ms bytes=14 text="data: chunk-0\n"
[guest] chunk 1 at t+915ms bytes=14 text="data: chunk-1\n"
[guest] chunk 2 at t+1316ms bytes=14 text="data: chunk-2\n"
[guest] chunk 3 at t+1717ms bytes=14 text="data: chunk-3\n"
[guest] chunk 4 at t+2118ms bytes=14 text="data: chunk-4\n"
[guest] stream ended at t+2526ms, total chunks=5
```

The host-side server sends chunks 400ms apart; the guest received them
~400ms apart in return (533 → 915 → 1316 → 1717 → 2118, deltas of 382, 401,
401, 401ms), matching the send cadence to within scheduling jitter. Server-side
log for this run confirms exactly one connection at the matching timestamp,
sourced from the host's own proxy address (as expected for a MITM'd
connection):

```
[server] connection from 192.168.1.201:43876 at 2026-08-22T12:47:57.536Z
[server] wrote chunk 0 at 2026-08-22T12:47:57.937Z
...
[server] wrote chunk 4 at 2026-08-22T12:47:59.538Z
```

This is the "pass" shape from the task brief: timestamps spread out over the
full 2+ second duration, not clustered at one instant — the mediation layer is
not buffering the whole response before releasing it to the guest.

### Verdict and reasoning

**PASS**, on both the letter and the intent of the gate:

1. A real TLS handshake to `api.anthropic.com` completes; ALPN negotiates
   `http/1.1` even though the client offered `h2` — consistent with the
   documented "HTTP/1.x and TLS interception only, no HTTP/2" behaviour, and
   consistent with the plan's own prediction that this would be a non-issue
   because Node's undici doesn't request HTTP/2 unless `allowH2: true` is set
   explicitly (which Corb's design does not do).
2. Incremental delivery survives the egress mediation end-to-end: chunk
   arrival timestamps are spread across the full send duration, not
   clustered.

Nothing ambiguous was left outstanding for R1 specifically. The two dead ends
along the way (guest-loopback routing, self-signed cert on the upstream leg)
were both anticipated risks called out in the task brief and were resolved by
the documented fallbacks, not by working around the actual thing being
tested.

### What surprised us / had to be routed around

- **The 127.0.0.1 loopback-routing dead end was not anticipated by name in
  the brief**, though the brief did leave room for "or find another approach
  that stays inside your process." Worth remembering for future host-loopback
  test harnesses against Gondolin guests: bind to a real host-owned interface
  address, not `127.0.0.1`.
- The self-signed-cert rejection on the host→upstream leg happened exactly as
  the brief predicted, and the HTTP fallback resolved it cleanly.
- Left running: nothing. Both the guest VM and the host test server were torn
  down (`vm.close()` in a `finally`; the server process killed) after each
  run.

### Evidence files

All under `spike/m0-1-http2/`:

| File | Contents |
|---|---|
| `evidence-01-first-attempt-127-loopback-fails.log` | Check 1 pass + Check 2 first failed attempt (HTTPS, `127.0.0.1`) |
| `evidence-02-plain-http-still-fails-on-127-loopback.log` | Check 2, plain HTTP, `127.0.0.1` — rules out a TLS cause, isolates the loopback-routing issue |
| `evidence-03-selfsigned-https-rejected-on-host-upstream-leg.log` | Check 2, self-signed HTTPS, real LAN IP — anticipated host-upstream cert rejection |
| `evidence-04-http-lanip-check2-only-pass.log` | Check 2 only, plain HTTP, real LAN IP — pass |
| `evidence-05-final-combined-pass.log` | Both checks in a single VM boot — final combined pass, the primary evidence record |

---

*(M0.2 — R3, MITM CA trust — is separate and not yet run as part of this
entry.)*

---

## M0.2 — R3: MITM CA trust for node, curl, git and go

**Date:** 2026-08-22
**Gondolin version:** `@earendil-works/gondolin@0.12.0` (pinned exact, no caret)
**Verdict: PASS for all four tools** — with a surprising, load-bearing
correction to the premise: **none of them need an explicit CA env var from
Corb's own configuration.** Gondolin's own guest init unconditionally exports
`SSL_CERT_FILE`, `CURL_CA_BUNDLE`, `REQUESTS_CA_BUNDLE` and
`NODE_EXTRA_CA_CERTS` for every process it execs, regardless of what `env` is
passed to `VM.create()` or `vm.exec()`. Corb's design can still set these
explicitly (harmless, self-documenting, defensive against a future Gondolin
change), but it is not required for trust to work.

### What was built

`spike/m0-2-mitm-ca/`:

- `package.json` — standalone package, depends on exactly
  `@earendil-works/gondolin@0.12.0`.
- `build-config.json` — minimal `BuildConfig`: `alpine.rootfsPackages:
  ["linux-virt", "nodejs", "curl", "ca-certificates", "bash", "git", "go"]`,
  **no `postBuild` section** — every package is a plain `apk` add needing no
  compilation, so the build needs neither Docker nor root. Built via the
  `gondolin build` CLI with `/usr/sbin:/sbin` prepended to `PATH` (same
  e2fsprogs-on-PATH requirement M0.1 found). `rootfs.sizeMb` bumped to 3072
  (from M0.1's 2048) to fit the Go toolchain. Assets under
  `spike/m0-2-mitm-ca/assets/`.
- `check.go` — stdlib-only (`net/http`) POST to `https://api.anthropic.com/v1/messages`;
  a completed handshake plus any HTTP response (even 401) is a pass, a
  certificate error is a fail. No API key, no external Go modules (so `go
  run` needs no module downloads).
- `run-spike.mjs` — the main driver: boots one VM (`httpHooks` from
  `createHttpHooks({ allowedHosts: ["api.anthropic.com", "github.com"] })`,
  **no CA env vars set at the `VM.create()` level on purpose**), then for each
  of node/curl/git/go runs the same real-endpoint check twice via
  `vm.exec(argv, { env })` — once with a deliberately minimal `env` (no
  tool-specific CA var) and once with that tool's documented var pointed at
  `/run/gondolin/ca-certificates.crt`. Also runs a diagnostic comparing the
  guest's system trust bundle (`/etc/ssl/certs/ca-certificates.crt`) against
  Gondolin's merged bundle.
- `diag-env.mjs`, `diag-env2.mjs` — follow-up diagnostics (see "what
  surprised us" below): dump the full guest process environment via
  `/usr/bin/env` under different `VM.create()`/`vm.exec()` env configurations,
  to find out where the CA trust env vars actually come from.
- `diag-ca-install.mjs` — checks whether Gondolin's attempt to install its CA
  into the guest's system trust store via `update-ca-certificates` actually
  changes `/etc/ssl/certs/ca-certificates.crt`.
- `diag-negative-control.mjs` — the rigorous version of the "with/without"
  test: since Gondolin's init makes a true "without" baseline impossible via
  simple omission (see below), this explicitly overrides *every* relevant CA
  env var to a nonexistent path (`/nonexistent/definitely-not-a-cert.crt`) for
  a genuine negative control, then restores the real merged bundle path as a
  positive control, both within the same VM boot, for all four tools.

### What surprised us: a "bare" run is not actually bare

The task brief's plan was: run each tool once with its CA env var unset, once
with it set, and expect "fails without / passes with" as the diagnostic
signal. The first full run (`evidence-01-full-run.log`) did **not** produce
that split — every tool passed on both the "bare" and "explicit" run. Digging
into why (rather than assuming Alpine's system store already trusted the CA):

1. `evidence-02-env-diagnostic.log`: a direct-exec `/usr/bin/env` inside the
   guest, called with `vm.exec(["/usr/bin/env"], { env: { PATH: "/usr/bin:/bin" } })`
   — i.e. an `ExecOptions.env` that mentions nothing CA-related — still shows:

   ```
   CURL_CA_BUNDLE=/run/gondolin/ca-certificates.crt
   NODE_EXTRA_CA_CERTS=/etc/gondolin/mitm/ca.crt
   SSL_CERT_FILE=/run/gondolin/ca-certificates.crt
   REQUESTS_CA_BUNDLE=/run/gondolin/ca-certificates.crt
   UV_SYSTEM_CERTS=true
   ```

2. `evidence-03-env-source-diagnostic.log`: ruling out that this comes from
   `createHttpHooks()`'s returned `env` — that object was logged as `{}` (no
   secrets configured) — and ruling out that `VM.create()`'s own `env` field
   is the source, by omitting it from `VM.create()` entirely. The same five
   vars still appeared in the guest process environment.
3. Reading the shipped package directly settled it:
   `node_modules/@earendil-works/gondolin/dist/src/alpine/init-scripts.js`
   contains a shell function that runs during Gondolin's own guest `/init`
   (PID 1, per `gondolin-notes.md` §8) which unconditionally does:

   ```sh
   export SSL_CERT_FILE="${runtime_ca_bundle}"
   export CURL_CA_BUNDLE="${runtime_ca_bundle}"
   export REQUESTS_CA_BUNDLE="${runtime_ca_bundle}"
   export NODE_EXTRA_CA_CERTS="${mitm_ca_cert}"
   ```

   (`runtime_ca_bundle` = `/run/gondolin/ca-certificates.crt`, the merged
   bundle; `mitm_ca_cert` = `/etc/gondolin/mitm/ca.crt`, the raw CA cert —
   Node gets pointed at the single CA cert, the other three at the merged
   bundle). This runs regardless of any host-side JS configuration, and its
   exports are inherited by every process the guest execs.
4. `diag-ca-install.mjs` / `evidence-04-update-ca-certificates-diagnostic.log`:
   the same init script also tries to install the CA into the system trust
   store proper via `update-ca-certificates`, and the guest does have that
   binary and a populated `/usr/local/share/ca-certificates/gondolin-mitm-ca.crt`.
   But a manual re-run of `update-ca-certificates` still leaves
   `/etc/ssl/certs/ca-certificates.crt` at its original 120-certificate count
   (never picking up the 121st, Gondolin's own CA) — so **the system trust
   store itself does *not* end up trusting the CA** on this Alpine build; only
   the four exported env vars do. This is a minor loose end (not chased
   further — it doesn't change any verdict below, since the env-var path
   already gives all four tools working trust) but is worth knowing: any
   guest tool that consults *only* the OS trust store, ignoring all of
   `SSL_CERT_FILE`/`SSL_CERT_DIR`/`CURL_CA_BUNDLE`/`NODE_EXTRA_CA_CERTS`, would
   still fail today, despite `update-ca-certificates` reporting success.

Because of this, "unset the var, see it fail" isn't achievable by omission —
Gondolin's init has already set it before any exec runs. The genuine negative
control is to override the var(s) to a bad path, done in
`diag-negative-control.mjs`.

### Per-tool evidence (bogus-override negative control vs. real bundle)

All from `evidence-05-negative-control.log`, one VM boot, all four tools run
twice: once with `SSL_CERT_FILE`, `SSL_CERT_DIR`, `CURL_CA_BUNDLE`,
`REQUESTS_CA_BUNDLE`, `NODE_EXTRA_CA_CERTS` and `GIT_SSL_CAINFO` all pointed at
`/nonexistent/definitely-not-a-cert.crt`, once with the applicable ones
pointed at the real `/run/gondolin/ca-certificates.crt`.

**node** (`NODE_EXTRA_CA_CERTS`):

```
--- node bogus --- exitCode=1 ok=false
[stderr]
Warning: Ignoring extra certs from `/nonexistent/definitely-not-a-cert.crt`, load failed: error:80000002:system library::No such file or directory
NODE_FETCH_ERROR Error: self-signed certificate in certificate chain

--- node real --- exitCode=0 ok=true
[stdout]
NODE_STATUS 401
```

**curl** (`CURL_CA_BUNDLE`):

```
--- curl bogus --- exitCode=77 ok=false
[stderr]
curl: (77) error adding trust anchors from file: /nonexistent/definitely-not-a-cert.crt

--- curl real --- exitCode=0 ok=true
[stdout]
{"type":"error","error":{"type":"authentication_error","message":"x-api-key header is required"},"request_id":"req_011CeJ5b8aYH5QMipou958UR"}
```

**git** (`GIT_SSL_CAINFO`, plus the `SSL_CERT_FILE` git's libcurl backend
consults directly):

```
--- git bogus --- exitCode=128 ok=false
[stderr]
fatal: unable to access 'https://github.com/octocat/Hello-World.git/': error adding trust anchors from file: /nonexistent/definitely-not-a-cert.crt

--- git real --- exitCode=0 ok=true
[stdout]
7fd1a60b01f91b314f59955a4e4d4e80d8edf11d	HEAD
... (full ref list for octocat/Hello-World)
```

**go** (`SSL_CERT_FILE`/`SSL_CERT_DIR`, read directly by `crypto/x509` on
Linux):

```
--- go bogus --- exitCode=1 ok=false
[stdout]
GO_FETCH_ERROR: Post "https://api.anthropic.com/v1/messages": tls: failed to verify certificate: x509: certificate signed by unknown authority

--- go real --- exitCode=0 ok=true
[stdout]
GO_STATUS: 401
GO_BODY: {"type":"error","error":{"type":"authentication_error","message":"x-api-key header is required"},"request_id":"req_011CeJ5cdoihvSccANJp8oq7"}
```

Every "bogus" failure is a **certificate-trust error specifically**
(`self-signed certificate in certificate chain`, `error adding trust anchors`,
`x509: certificate signed by unknown authority`) — not a DNS failure, a
network-unreachable error, or a protocol error. That isolates the cause
precisely to CA trust, for all four tools.

### Why the first ("bare", pre-negative-control) run is still useful evidence

`evidence-01-full-run.log` is kept because it answers the practical question
Corb actually cares about: *does a guest process launched the way Corb will
actually launch it (inheriting Gondolin's default guest environment, with no
special handling) get TLS trust for these four tools?* Answer: **yes, for all
four, with zero extra configuration required from Corb.** The
negative-control run in `evidence-05-negative-control.log` exists to prove
*why* — to confirm this isn't an accident of the system trust store (it
isn't — see the `update-ca-certificates` finding above) but a direct,
reproducible effect of Gondolin's own env-var injection.

### Reasoning per tool

| Tool | Var(s) that matter | Auto-injected by Gondolin init? | Needs Corb to set it explicitly? |
|---|---|---|---|
| node | `NODE_EXTRA_CA_CERTS` | yes | no |
| curl | `CURL_CA_BUNDLE` (also honours `SSL_CERT_FILE`, also auto-injected) | yes | no |
| git | no git-specific var needed — its libcurl/OpenSSL backend reads `SSL_CERT_FILE` directly | yes (`SSL_CERT_FILE`) | no |
| go | `SSL_CERT_FILE`/`SSL_CERT_DIR`, read directly by `crypto/x509` on Linux | yes (`SSL_CERT_FILE`) | no |

This means `docs/design.md` §8's guest-env template (which sets
`NODE_EXTRA_CA_CERTS` and `SSL_CERT_FILE` explicitly alongside `...env` from
`createHttpHooks`) is **not wrong, but is redundant** — Gondolin already
guarantees these before that `env` object is even applied. Setting them
explicitly is harmless defensive belt-and-braces (and guards against a future
Gondolin version changing this default), so no change to `design.md` is
required by this finding, but it is worth the design doc's authors knowing the
explicit vars are a safety net, not the mechanism actually carrying trust
today.

### Evidence files

All under `spike/m0-2-mitm-ca/`:

| File | Contents |
|---|---|
| `evidence-01-full-run.log` | Main driver run: all four tools, "no var mentioned" vs "var explicitly set to the real bundle" (both pass — the surprise that led to the rest) |
| `evidence-02-env-diagnostic.log` | Full guest process env dump proving the CA vars are present even when `ExecOptions.env` doesn't mention them |
| `evidence-03-env-source-diagnostic.log` | Rules out `createHttpHooks()`'s `env` and `VM.create()`'s `env` as the source (both absent/omitted, vars still present) |
| `evidence-04-update-ca-certificates-diagnostic.log` | Confirms the guest's system trust store (`/etc/ssl/certs/ca-certificates.crt`) does **not** end up containing Gondolin's CA, despite `update-ca-certificates` reporting success |
| `evidence-05-negative-control.log` | The rigorous fail-without/pass-with test: every CA env var forced to a nonexistent path (genuine failure, cert-trust errors only) vs. pointed at the real merged bundle (pass), all four tools, one VM boot |

Left running: nothing. The VM was closed in a `finally` block on every run
(`run-spike.mjs`, `diag-env.mjs`, `diag-env2.mjs`, `diag-ca-install.mjs`,
`diag-negative-control.mjs` all follow this pattern); no lingering
QEMU/`gondolin-krun-runner` processes after the session.

---

## M0.4 — R2: exec concurrency with a long-lived interactive process

**Date:** 2026-08-30
**Gondolin version:** `@earendil-works/gondolin@0.12.0` (pinned exact, no caret)
**Verdict: PASS — exec does not serialise.** A second `exec` runs immediately
and in parallel with a long-lived `pty: true` exec, from the same host
process *and* from a separate host process over `connectToSession()`. The
long-lived exec is unaffected: it keeps answering commands throughout, and
there is zero cross-talk in either direction. **`corb attach` (M8.7) is
therefore viable** — but only as a *new* shell in the running session, never
as a rejoin of Pi's existing TUI, which the control protocol cannot express
at all. The SDK's self-contradiction (§3) resolves in favour of the
"independent command channel, no cross-talk" page; the "one command at a
time" page is wrong for `exec`. It is, however, *accidentally* right about
one thing: `waitForExecIdle()` is real serialisation pressure, and it gates
`vm.fs`'s **file operations** — which means Corb's `runSession()` can never
use `vm.fs.readFile`/`writeFile`/`deleteFile` while Pi's TUI is running.

### What was built

`spike/m0-4-exec-concurrency/`. Unlike M0.1 and M0.2 this spike has **no
`package.json`, no `build-config.json` and no `assets/`**: it deliberately
boots the *real* tagged runtime image via `resolveRuntimeImage()`
(`src/vm/image.ts`), from the repo's own already-pinned `node_modules`, so
that what is measured is the guest Corb actually ships — a standalone package
with its own dependency tree would have measured a different image. It drives
`VM.create()` directly rather than `runSession()`, the established convention
for narrow SDK-behaviour checks (see `test/e2e/policygate-content.e2e.ts` and
`test/e2e/dropcap-status.e2e.ts` for the same reasoning).

- `lib.mjs` — shared helpers. The important one is `withTimeout`: **every**
  wait in this spike is bounded, and "still pending after N ms" is recorded
  as a result rather than hung on. If exec had genuinely serialised, a naive
  `await` would have hung forever and produced no evidence at all.
- `same-process.mjs` — measurements 1, 1b, 3, 4 and 5, in one process and one
  VM boot, run twice over two long-exec shapes: `A` = plain `/bin/sh` with a
  pty, `B` = `dropcap 1000 1000 /bin/sh` with a pty, i.e. production's exact
  wrapper with `pi` swapped for a shell. Takes `--no-warmup` to reproduce a
  trap this spike fell into (see below).
- `session-holder.mjs` — the "`corb run`" side of the cross-process leg.
  Boots a VM, starts one long-lived `dropcap 1000 1000 /bin/sh` exec
  (`pty: true`, `stdin: true`, `stdout: "pipe"` — `session.ts`'s shape),
  logs every byte that exec emits with a wall-clock timestamp, samples
  `execPressure()` every 2s, and takes commands (`send`, `expect`,
  `assert-absent`, `pressure`, `status`, `quit`) so the spike can
  independently interrogate the long exec from outside.
- `attach-client.mjs` — the `corb attach` side. A **separate host process**
  with no `VM` object, holding nothing but the session's unix socket. Speaks
  the raw control protocol over `connectToSession()`.
- `run-cross-process.sh` — orchestrates the two, `setsid`s the holder, waits
  bounded for its state file, runs the attach client, then asks the holder
  whether its long exec survived. Redirects `CORB_STATE_DIR`,
  `CORB_CONFIG_DIR` and `GONDOLIN_SESSIONS_DIR` (to `/tmp/gsess`, 10
  characters — well inside `src/vm/sockpath.ts`'s 66-character budget, so the
  socket bind cannot silently fail and be misread as a concurrency failure).
- `exec-ceiling.mjs` — how many concurrent execs the session actually allows.
- `inspect-sdk.sh` — the reading half, made reproducible: prints the exact
  shipped-SDK source behind every "why" claim below.

### Reading the SDK first: what `corb attach` can and cannot be

Confirmed independently, as the brief asked (full output:
`evidence-06-sdk-inspection.log`). `ClientMessage` is a closed union and the
complete client-to-server vocabulary is:

```
export type ClientMessage = BootCommandMessage | ExecCommandMessage | StdinCommandMessage | PtyResizeCommandMessage | ExecWindowCommandMessage | LifecycleCommandMessage | SnapshotCommandMessage;
```

There is **no "list running execs" and no "join exec N"**. `SessionIpcServer`
additionally gives every connected client its own request-id space
(`// Per-client id translation to keep each external channel independent.`,
with internal ids allocated downward from `0xffffffff` above an
`INTERNAL_ID_FLOOR` of `0x80000000`, disjoint from the session owner's small
ids), and an id a client never allocated is refused rather than routed:

```
        const forwardMappedIdMessage = (message) => {
            const internalId = externalToInternal.get(message.id);
            if (internalId === undefined) {
                sendError(socket, "unknown_id", "request id not found", message.id);
```

So rejoining Pi's existing TUI stream is not expressible, and a **new exec is
the only thing `corb attach` could ever do**. This was then confirmed live —
see Check 4b below.

The mechanism that makes a second exec *work* is equally explicit.
`handleExec` in `dist/src/sandbox/server-ops.js` has exactly one queueing
branch, and it is not about other execs:

```
912:        // Keep file operations mutually exclusive with exec start. Once the file
913-        // operation completes, queued execs are started concurrently.
914-        if (this.activeFileOpId !== null) {
915-            this.execQueue.push(entry);
916-            return;
917-        }
918-        this.startExecNow(entry);
```

The only other gate is an admission limit, `maxQueuedExecs`, defaulting to
`64`. Nothing serialises exec against exec.

### Check 1 — same-process concurrency

From `evidence-02-same-process.log`, shape A (plain `/bin/sh` + pty). The
long exec is proven alive first, then a second `vm.exec()` is issued:

```
[15:29:10.084 t+ 33609ms] ================ SHAPE A (plain /bin/sh + pty): ["/bin/sh"] ================
[15:29:10.136 t+ 33661ms]   long exec alive: true
[15:29:10.137 t+ 33662ms]   execPressure(long exec running) = 1
[15:29:10.137 t+ 33662ms] MEASUREMENT 1 — second one-shot vm.exec() while the long exec runs
[15:29:10.142 t+ 33667ms]   second one-shot exec: resolved after 5ms
[15:29:10.142 t+ 33667ms]   exitCode=0 stdout="SECOND_ONESHOT_9483760E\n"
```

Shape B (`dropcap 1000 1000 /bin/sh` + pty — production's wrapper) is
identical:

```
[15:29:25.476 t+ 49001ms]   second one-shot exec: resolved after 5ms
[15:29:25.476 t+ 49001ms]   exitCode=0 stdout="SECOND_ONESHOT_4DBC9534\n"
```

**5-6ms across runs** (6ms in
`evidence-01-boot-warmup-trap-negative-control.log`), **not queued behind a
shell that never exits.** The two shapes do not differ, so the simple
stand-in is representative and the `dropcap` wrapper changes nothing about
exec admission.

"Accepted promptly" is not the same as "actually parallel", so measurement 1b
uses wall-clock time as an independent check — four concurrent `sleep 3`
execs alongside the long exec:

```
[15:29:10.894 t+ 34419ms]   execPressure(long exec + 4 sleeps, sampled 750ms in) = 5
[15:29:13.155 t+ 36680ms]   four concurrent 3s sleeps: resolved after 2261ms
[15:29:13.155 t+ 36680ms]   wall clock for 4x 'sleep 3': 3013ms (parallel ~3000ms, serialised ~12000ms)
[15:29:13.155 t+ 36680ms]   exit codes: [0,0,0,0]
```

3013ms, not 12000ms. Genuinely parallel in the guest, not merely queued
politely.

### Check 2 — cross-process concurrency via `connectToSession()`

**This is the one that decides M8.7.** From
`evidence-03-cross-process-attach.log`. The holder process (pid 509514) has
the long-lived `dropcap`+pty exec; the attach client (pid 509974) is a
different process that only ever sees the socket:

```
-- gondolin sessions dir --
srwxr-xr-x  1 dario dario    0 30 d’ag.    17:16 48f14dba-f89f-490e-abe6-6c3051c5bde1.sock

[15:16:37.417 t+     1ms] attach client pid=509974, target session 48f14dba-f89f-490e-abe6-6c3051c5bde1
[15:16:37.420 t+     4ms] ATTACH CHECK 1 — one-shot /bin/echo over connectToSession()
[15:16:37.420 t+     4ms]   -> {"type":"exec","id":1,"cmd":"/bin/echo","argv":["ATTACH_ONESHOT_52411C42"],"env":["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"]}
[15:16:37.425 t+     9ms]   <- JSON {"type":"status","state":"running"}
[15:16:37.433 t+    17ms]   <- stdout (id=1) "ATTACH_ONESHOT_52411C42\n"
[15:16:37.433 t+    17ms]   <- JSON {"type":"exec_response","id":1,"exit_code":0}
```

It executes, and **its stdout comes back** — 13ms end to end, over a socket,
from a process that has no `VM` object.

### Check 4 — an *interactive* second exec (what `corb attach` actually wants)

Both in-process and over the attach socket. Over the socket, a `pty: true`
`/bin/sh`, driven for two round-trips with a `pty_resize` in between (the
`\u001b[6n` cursor-position queries are the shell's own output; the logs
JSON-escape them, so what appears below is literal text, not control bytes):

```
[15:16:37.433 t+    17ms] ATTACH CHECK 2 — interactive pty:true /bin/sh over connectToSession()
[15:16:37.440 t+    24ms]   <- stdout (id=2) "attach$ \u001b[6n"
[15:16:37.809 t+   393ms]   <- stdout (id=2) "40 120\r\n"
[15:16:37.810 t+   394ms]   <- stdout (id=2) "0\r\n"
[15:16:37.810 t+   394ms]   <- stdout (id=2) "ATTACH_PTY_TURN2_1B7E5C33\r\nattach$ \u001b[6n"
[15:16:37.858 t+   442ms]   <- JSON {"type":"exec_response","id":2,"exit_code":0}
```

The command that produced `40 120` was `stty size; id -u; echo
ATTACH_PTY_TURN2_1B7E5C33`, visible in that exec's full transcript on line 50
of the log.

`stty size` returns `40 120` — the exact geometry sent in the `pty_resize`
message — so it is a real pty with a real, resizable window size, not a pipe.

And in production's shape, an unprivileged shell via `dropcap`:

```
[15:16:37.859 t+   443ms] ATTACH CHECK 3 — dropcap 1000 1000 /bin/sh, pty:true (what `corb attach` would actually run)
[15:16:38.162 t+   746ms]   <- stdout (id=3) "id -u; id -g; echo ATTACH_DROPCAP_A74EBF18\r\n"
[15:16:38.184 t+   768ms]   <- stdout (id=3) "1000\r\n"
[15:16:38.184 t+   768ms]   <- stdout (id=3) "1000\r\n"
[15:16:46.292 t+  8876ms]   result: {"answered":true,"exited":true,"response":{"type":"exec_response","id":3,"exit_code":0},...}
```

uid 1000, gid 1000 — an attach shell can be dropped to the agent's own
privilege exactly the way `session.ts` drops Pi's.

The same shape works in-process too (`evidence-02-same-process.log`), with
two independent interactive execs live at once:

```
[15:29:25.214 t+ 48739ms]   second pty exec produced its own marker: true
[15:29:25.266 t+ 48791ms]   second pty exec second round-trip: true
[15:29:25.266 t+ 48791ms]   execPressure(two interactive execs, both confirmed live) = 2
```

### Check 3 — does the first exec survive? (and cross-talk)

The strongest evidence is the cross-process one, because the two sides are
logged by two different processes and can be correlated by wall clock. The
attach client held its `dropcap` pty shell open from **15:16:37.859** to
**15:16:46.292** and, while holding it, drove the holder's long exec. The
holder's own log for that window:

```
[15:16:38.402 t+ 38952ms] CMD: pressure
[15:16:38.402 t+ 38952ms]   execPressure(on demand) = 2
[15:16:38.402 t+ 38952ms]   writing to long exec stdin: "echo DURING_ATTACH_LONG_EXEC_187EA76D"
[15:16:38.426 t+ 38976ms]   LONG-STDOUT "DURING_ATTACH_LONG_EXEC_187EA76D\r\n"
[15:16:38.452 t+ 39002ms]   EXPECT DURING_ATTACH_LONG_EXEC_187EA76D -> FOUND in the long exec's own stream
[15:16:39.340 t+ 39890ms]   execPressure(periodic) = 2
[15:16:41.341 t+ 41891ms]   execPressure(periodic) = 2
[15:16:43.341 t+ 43891ms]   execPressure(periodic) = 2
[15:16:45.341 t+ 45891ms]   execPressure(periodic) = 2
[15:16:47.342 t+ 47892ms]   execPressure(periodic) = 1
```

The long exec **accepted new input and produced correct output at 15:16:38.4,
in the middle of the attach client's shell session** — not just "the process
still exists". Pressure sat at 2 for the whole overlap and fell back to 1
when the attach shell exited at ~15:16:46.3.

After the attach client had exited entirely, the holder was asked again:

```
[15:16:47.872 t+ 48422ms]   writing to long exec stdin: "echo AFTER_ATTACH_658927980"
[15:16:47.896 t+ 48446ms]   LONG-STDOUT "AFTER_ATTACH_658927980\r\n"
[15:16:47.923 t+ 48473ms]   EXPECT AFTER_ATTACH_658927980 -> FOUND in the long exec's own stream
[15:16:47.923 t+ 48473ms]   ASSERT-ABSENT ATTACH_ONESHOT -> absent (no cross-talk)
[15:16:47.923 t+ 48474ms]   ASSERT-ABSENT ATTACH_PTY_TURN1 -> absent (no cross-talk)
[15:16:47.924 t+ 48474ms]   ASSERT-ABSENT ATTACH_DROPCAP -> absent (no cross-talk)
[15:16:47.924 t+ 48474ms]   ASSERT-ABSENT ATTACH_HIJACK_ATTEMPT -> absent (no cross-talk)
[15:16:47.924 t+ 48474ms]   long exec settled? no — still running
```

The long exec's complete captured output for the whole run contains its own
four markers and nothing else:

```
"echo HOLDER_LONG_UP_206D7921\r\ncorb-long# echo HOLDER_LONG_UP_206D7921\r\nHOLDER_LONG_UP_206D7921\r\ncorb-long# \u001b[6necho BEFORE_ATTACH_207071007\r\nBEFORE_ATTACH_207071007\r\ncorb-long# \u001b[6necho DURING_ATTACH_LONG_EXEC_187EA76D\r\nDURING_ATTACH_LONG_EXEC_187EA76D\r\ncorb-long# \u001b[6necho AFTER_ATTACH_658927980\r\nAFTER_ATTACH_658927980\r\ncorb-long# \u001b[6n"
```

Symmetrically, the attach client saw no frame it had not asked for, and the
in-process run reports the same in both directions for both shapes:

```
[15:29:25.317 t+ 48842ms]   CROSS-TALK: {"secondPtyMarkerLeakedIntoFirst":false,"oneShotMarkerLeakedIntoFirst":false,"firstMarkersLeakedIntoSecond":false}
```

**Check 4b — can an attach client reach the session owner's exec at all?**
Since the protocol has no "join", the only thing left to try is addressing
the owner's request id directly. It is refused, exactly as the id-remapping
code predicts:

```
[15:16:46.292 t+  8876ms]   holder's long exec has VM-internal id=5
[15:16:46.293 t+  8877ms]   <- JSON {"type":"error","code":"unknown_id","message":"request id not found","id":5}
[15:16:46.293 t+  8877ms]   <- JSON {"type":"error","code":"unknown_id","message":"request id not found","id":5}
```

and `ATTACH_HIJACK_ATTEMPT` never appears in the long exec's stream (above).
This is a *good* result: it means a stray or hostile attach client cannot
inject keystrokes into Pi's TUI. It is also the definitive proof that
`corb attach` cannot mirror the agent's screen.

### Check 5 — `execPressure()` and `waitForExecIdle()`, read then measured

Read first (`evidence-06-sdk-inspection.log`). `execPressure()` is a plain
count of live exec requests — started plus admitted-but-not-yet-started:

```
42:    execPressure() {
43-        let pressure = this.startedExecs.size;
44-        for (const id of this.inflight.keys()) {
45-            if (!this.startedExecs.has(id))
46-                pressure += 1;
47-        }
48-        return pressure;
49-    }
```

`waitForExecIdle()` is a 10ms busy-wait for **zero** live execs:

```
518:    async waitForExecIdle(signal) {
519-        while (this.inflight.size > 0 ||
520-            this.startedExecs.size > 0 ||
521-            this.activeFileOpId !== null ||
522-            this.execQueue.length > 0) {
```

Measured values match exactly: `0` before any exec, `1` with the long exec,
`2` with two interactive execs both confirmed live, `5` with the long exec
plus four sleeps, `64` at the ceiling, back to `0` once everything exits.

Its three callers are the whole story of what a live exec actually blocks:

```
4:66-    async readGuestFileStream(filePath, options = {}) {
7:69:        await this.waitForExecIdle(options.signal);
12:151-    async writeGuestFile(filePath, input, options = {}) {
15:154:        await this.waitForExecIdle(options.signal);
20:205-    async deleteGuestFile(filePath, options = {}) {
23:208:        await this.waitForExecIdle(options.signal);
```

Measured, with the long exec running and then not (`evidence-02`):

```
[15:29:19.156 t+ 42681ms]   waitForExecIdle() with the long exec running: timeout after 6000ms
[15:29:25.157 t+ 48682ms]   vm.fs.readFile() with the long exec running: timeout after 6001ms
[15:29:25.164 t+ 48689ms]   vm.fs.stat() with the long exec running (exec-backed, not file-op-backed): resolved after 6ms
...
[15:29:25.416 t+ 48941ms]   execPressure(no execs running) = 0
[15:29:25.416 t+ 48941ms]   waitForExecIdle() with nothing running: resolved after 0ms
[15:29:25.420 t+ 48945ms]   vm.fs.readFile() with nothing running: resolved after 3ms
[15:29:25.420 t+ 48945ms]     readFile -> "localhost\n"
```

**This is the one real serialisation in the system, and it is the exact
opposite of what R2 assumed.** R2's own mitigation text said that if exec
serialised, "everything else must be network- or VFS-mediated — and `vm.fs`
must cover host-side file needs." The measurement inverts that: *exec* is the
concurrent path and `vm.fs`'s **file operations** are the serialised one.
`vm.fs.readFile`, `writeFile` and `deleteFile` can never complete while Pi's
TUI exec is alive — which is to say, never, for the entire duration of a
`corb run` session. (`vm.fs.stat`/`listDir`/`mkdir`/`access`/`rename` are
implemented as `exec` calls, not file ops, and keep working fine — 6ms
above.) Corb does not currently call any of the three blocked methods, so
nothing is broken today; this is a constraint on what future host-side code
may do, not a live bug.

### The concurrency ceiling

`evidence-05-exec-ceiling.log`: one long pty exec plus 80 attempted
concurrent `sleep 60` execs.

```
[15:20:03.997 t+ 38664ms] still running: 63, rejected: 17
[15:20:03.998 t+ 38665ms] first rejection at index 63: error queue_full: too many concurrent exec requests (limit 64)
[15:20:03.998 t+ 38665ms]   execPressure(at the ceiling) = 64
[15:20:04.049 t+ 38716ms] long pty exec still answering after the flood: true
```

63 accepted + 1 long exec = exactly `maxQueuedExecs`'s default of 64, then
clean `queue_full` rejections. The ceiling is **session-wide**, shared
between the owner's execs and every attach client's execs — the admission
check reads one counter. The long exec survived the flood untouched.

### Verdict and reasoning

**PASS. R2 is closed.** Point by point:

1. **Same-process concurrency:** the second exec runs, promptly (5-6ms),
   and genuinely in parallel (4x `sleep 3` in 3013ms).
2. **Cross-process via `connectToSession()`:** it executes and its stdout
   comes back, 13ms end to end.
3. **The first exec survives:** it accepted input and produced correct output
   *during* the second exec's session, stayed unsettled throughout, and
   showed zero cross-talk in either direction.
4. **Interactive second exec:** works, with a real resizable pty
   (`stty size` gives `40 120`) and under `dropcap` at uid/gid 1000.
5. **`execPressure()`/`waitForExecIdle()`:** exactly what their
   implementations say — a live-exec counter, and a wait-for-zero that gates
   `vm.fs`'s three file operations and nothing else.

**Recommendation on M8.7: build it — as `corb attach` opening a *new*
interactive shell in the running session. Not as a way to see or share Pi's
screen, which is impossible in 0.12.0.** Caveats the implementation must
carry:

- **Naming and UX must be honest.** The user gets a fresh shell beside the
  agent, not the agent's terminal. "attach" invites the second reading; if
  the command keeps that name, its help text and first-run output must say
  which one it is. `corb shell` would be the more truthful name.
- **Run it under `dropcap <uid> <gid>`**, like `session.ts` does, and build
  its guest env the same way — an attach shell that skipped `dropcap` would
  be a root shell in the guest and a hole in the privilege-drop story that
  R18 and `dropcap` exist to hold up. Verified working: uid/gid 1000.
- **Host-side policy is preserved for free.** An attach exec is executed by
  the *session owner's* sandbox server, so the same `httpHooks`, sentinel and
  VFS providers apply. The attach client supplies only argv/env; it cannot
  reach the host-side hooks or the secret manager.
- **Handle `server_shutdown`.** When `corb run` exits (or its watchdog
  fires), `vm.close()` rejects every live exec with `error server_shutdown:
  server is shutting down` and the attach client's socket closes. An attach
  client must render that as "session ended", not as a crash — see the dead
  end below for how loudly this fails if ignored.
- **`lifecycle` is refused over attach IPC** (`"lifecycle actions are not
  supported over attach IPC"`), so `corb attach` can never stop the session.
  `corb kill`'s existing signal-based approach stays the right one.
- **Budget against the 64-exec session-wide ceiling.** Not a practical limit
  for a human opening a shell or two, but it is shared, and a future feature
  that fans out execs would compete with attach sessions for it.
- **No way to kill an attach exec from the host.** §3's "no exec timeout and
  no kill" applies here too: an abandoned attach shell (client killed with
  the pty still open) holds a slot until `vm.close()`. Worth a thought in
  M8.7's design, not a blocker.

### What surprised us / had to be routed around

- **`VM.create()` returns before the guest exists, and that nearly produced
  the exact wrong answer.** The first run of `same-process.mjs` used a 15s
  per-step timeout and reported `long exec alive: false` for *both* shapes —
  which reads exactly like "a long-lived exec is blocked". It was not: boot
  is lazy and happens on the first exec, taking ~33s on this machine.
  `VM.create()` had resolved in 86ms with `getHostPid()` still `null`. The
  fix is the `BOOT` warm-up exec in `main()`. Kept as a runnable negative
  control (`--no-warmup`,
  `evidence-01-boot-warmup-trap-negative-control.log`), because
  distinguishing "the second exec is blocked" from "the guest wasn't up yet"
  is the single most dangerous confusion available in this spike:

  ```
  [15:20:38.866 t+    84ms] VM.create() returned, id=5d799965-61a5-4212-8c93-6e813818b01a hostPid=null
  [15:20:38.866 t+    84ms] --no-warmup: skipping the boot warm-up (negative control)
  [15:20:58.937 t+ 20155ms]   long exec alive: false
  [15:21:12.333 t+ 33551ms]   long exec alive: true
  ```

  The `false` is shape A, timing out at its 20s budget while the guest is
  still booting; the `true` is shape B, which succeeds only because by then
  ~33s of wall clock has passed and the guest has finally come up.

  That control has a second lesson in it. Shape A's abandoned exec is never
  reaped — there is no kill — so it stays live for the rest of the process
  and offsets every later `execPressure()` reading by one
  (`execPressure(no execs running) = 1`) and makes `waitForExecIdle()` never
  resolve even when the spike believes it is idle. Any future
  `execPressure()`-based logic has to assume leaked execs are permanent.

- **`execPressure()` and `waitForExecIdle()` are not on the `VM` public
  surface at all.** §3 said "the types expose `waitForExecIdle()` and
  `execPressure()`", which is true only of `SandboxServerOps`; `VM` holds it
  in a `private server` field and never re-exposes either method
  (`grep -c "execPressure\|waitForExecIdle" dist/src/vm/core.d.ts` gives `0`).
  This spike reaches them via `vm.server` from `.mjs`, which works only
  because TypeScript `private` is compile-time. Production code cannot use
  them, so no Corb design may depend on either — including any future
  "is the session busy?" check.

- **A `vm.exec()` promise with no rejection handler kills the host process on
  `vm.close()`.** The first ceiling run produced its full, correct result and
  *then* died (absolute paths abbreviated to `.../` here; the log has them in
  full):

  ```
  Error: error server_shutdown: server is shutting down
      at VM.handleError (.../dist/src/vm/core.js:1445:23)
      at SandboxServer.failInflight (.../dist/src/sandbox/server-ops.js:1276:13)
      at SandboxServer.closeInternal (.../dist/src/sandbox/server-ops.js:453:14)
  ```

  `vm.close()` rejects every live exec; Node's default
  `--unhandled-rejections=throw` turns an unhandled one into an uncaught
  exception. `runSession()` is safe today because it always `await`s its one
  exec — but any code that starts an exec it does not await (an attach
  client's, a future background exec) must attach a handler.
  `evidence-04-exec-ceiling-first-attempt-unhandled-rejection.log` is the
  failing run, kept.

- **The session socket's permissions come from the process umask, and
  Gondolin never chmods it.** Observed `srwxr-xr-x` in `/tmp/gsess`, i.e.
  `0777 & ~umask` with the usual `0022`. Under the default umask no other
  local user can `connect()` (that needs write permission), and in the
  default `~/.cache/gondolin/sessions` location `~/.cache` is `drwx------`
  anyway. But under a permissive umask the socket would be `0777` (verified
  directly: a Node `listen()` with `umask(0)` yields mode `777`), and it is
  an unauthenticated exec channel into the guest. Relevant because
  `src/vm/sockpath.ts` actively recommends relocating the directory to
  `/tmp/gondolin-sessions` when the path is too long — which removes the
  `~/.cache` parent-directory protection and leaves only the umask. Worth a
  mode check in whatever M8.7 builds; not chased further here.

- **The SDK's contradiction is resolved, but not symmetrically.** The
  "independent command channel, no cross-talk" page is right about `exec`.
  The "one command at a time" page is wrong about `exec` — yet
  `waitForExecIdle()` exists precisely because the guest *does* serialise its
  **file-transfer** channel against execs. The two pages appear to describe
  two different subsystems and have been collapsed into one claim.

- Left running: nothing. `vm.close()` in a `finally` on every script;
  `run-cross-process.sh` ends with an explicit leak check, which for the
  recorded run reported `(none)` for both `qemu-system` and `gondolin`, and
  an empty `/tmp/gsess`.

### Evidence files

All under `spike/m0-4-exec-concurrency/`:

| File | Contents |
|---|---|
| `evidence-01-boot-warmup-trap-negative-control.log` | `--no-warmup` negative control: without a boot warm-up the long exec looks dead for ~33s, which is the failure mode most likely to be misread as serialisation. Also shows an abandoned exec permanently skewing `execPressure()`/`waitForExecIdle()` |
| `evidence-02-same-process.log` | Measurements 1, 1b, 3, 4, 5 in one VM boot, over both long-exec shapes (plain `/bin/sh`, and production's `dropcap 1000 1000 /bin/sh`) — the primary same-process record |
| `evidence-03-cross-process-attach.log` | The `corb attach` leg: holder log and attach-client log for one run, wall-clock correlated. Contains the one-shot, interactive-pty and `dropcap`-pty attach execs, the id-hijack refusal, the holder's `execPressure()=2` overlap window, the cross-talk assertions, and the process/socket leak check |
| `evidence-04-exec-ceiling-first-attempt-unhandled-rejection.log` | The ceiling run that produced a correct result and then died on an unhandled `server_shutdown` rejection at `vm.close()` |
| `evidence-05-exec-ceiling.log` | The ceiling: 63 concurrent execs accepted alongside the long exec, then `queue_full` at `execPressure()` 64 |
| `evidence-06-sdk-inspection.log` | The reading half: the closed `ClientMessage` union (no "list execs"/"join exec"), `handleExec`'s file-op-only queueing branch, `maxQueuedExecs`, `execPressure()`, `waitForExecIdle()` and its three callers, the absence of both from `VM`'s public surface, and `SessionIpcServer`'s per-client id space and `unknown_id` refusal |
