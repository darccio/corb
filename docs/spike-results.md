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
