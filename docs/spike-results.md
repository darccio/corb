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
