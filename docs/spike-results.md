# Spike results

Dated, evidence-backed answers to the blocking M0 spike gates in
[`gondolin-notes.md`](./gondolin-notes.md) §13. Throwaway code lives under
`spike/`. This file is the durable record of what was run and what came back.

---

## M0.1: R1: HTTP/2 to the model API

**Date:** 2026-08-22

**Gondolin version:** `@earendil-works/gondolin@0.12.0` (pinned exact, no caret)

**Verdict: PASS.** Gondolin's HTTP/1.x egress works for the model API.
A real TLS handshake to `api.anthropic.com` negotiates HTTP/1.1 rather than HTTP/2.
The guest receives chunked and streaming responses incrementally.
The relay does not buffer the complete response before delivery.

### What was built

`spike/m0-1-http2/`:

- `package.json` defines a standalone package. It depends on exactly `@earendil-works/gondolin@0.12.0`.
- `build-config.json` is a minimal `BuildConfig`. It sets `alpine.rootfsPackages:
  ["linux-virt", "nodejs", "curl", "ca-certificates", "bash"]` and has no `postBuild` section.
  The native Linux build needs neither Docker nor root.
  The build used `gondolin build` from `node_modules/.bin`.
  It prepended `/usr/sbin:/sbin` to `PATH` for `mkfs.ext4` and `resize2fs`.
  The notes correctly warned that this user's `PATH` omitted e2fsprogs.
  The build fails without this prefix and succeeds with it.
  Assets live under `spike/m0-1-http2/assets/`.
- `run-spike.mjs` boots the VM with `sandbox.imagePath` set to the assets directory.
  It sets `dns: { mode: "synthetic", syntheticHostMapping: "per-host" }`.
  It gets `httpHooks` from `createHttpHooks({ allowedHosts, allowedInternalHosts })`.
  It sets `env.NODE_EXTRA_CA_CERTS = "/run/gondolin/ca-certificates.crt"`.
  It runs both checks through `vm.exec` and closes the VM in a `finally`.
- `stream-server.mjs` runs a host HTTP or HTTPS server with a self-signed certificate.
  It sends five chunks, 400ms apart, with `Transfer-Encoding: chunked` and an SSE payload.
  `--http` selects plain HTTP.
- `guest-stream-check.mjs` runs in the guest through `node`.
  It reads the stream through global `fetch` and logs a timestamp per chunk.

### Check 1: real-endpoint protocol check (no API key needed)

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

Curl offered both `h2` and `http/1.1` in its ALPN extension.
The connection negotiated `http/1.1` through Gondolin's MITM proxy.
The proxy used `192.168.127.3`, the guest's fixed LAN address.
The upstream used `198.19.0.1` from the synthetic DNS range.
`gondolin-mitm-ca` issued the leaf certificate for `CN=api.anthropic.com`.
This confirms the TLS termination described in §4 of `gondolin-notes.md`.

The TLS handshake completed, and the HTTP/1.1 request received a real 401 response.
No API key was configured, so the 401 was expected.
This meets the task brief's pass condition.
A protocol failure instead stalls or resets the connection before any HTTP response.

### Check 2: incremental (streaming) delivery

This required two rounds of debugging past the originally planned test setup,
both of which are themselves informative results and are kept as evidence.

**Round 1 failed.** The initial plan bound the host test server to `127.0.0.1`.
The guest then fetched `https://127.0.0.1:<port>/stream`.
The test assumed Gondolin's egress mediator forwarded this request.
`allowedInternalHosts` explicitly included `127.0.0.1` because `blockInternalRanges` blocks it by default.
The request failed with:

```
[guest] fetch failed: TypeError: fetch failed
[guest] cause: Error: connect ECONNREFUSED 127.0.0.1:8443
```

Plain HTTP failed in the same way.
This rules out a TLS or certificate cause.
See `evidence-02-plain-http-still-fails-on-127-loopback.log`.
The host server logged zero connection attempts during these guest runs.
The request never reached the host.

The guest kernel routes a literal `127.0.0.1` destination to its own loopback device.
The request never crosses the virtio-net path where Gondolin mediates egress.
The host proxy therefore has no request to intercept.
`blockInternalRanges` and `allowedInternalHosts` guard hostnames that resolve to internal addresses.
They do not route guest loopback traffic to the host.
The host resolves the HTTP `Host` header independently.

This finding concerns the test setup rather than a Gondolin defect.
The task prohibited edits to `/etc/hosts`.
The test instead bound the server to the host's existing LAN address, `192.168.1.201`.
`ip -4 addr show` supplied that address.
The guest request URL, `allowedHosts`, and `allowedInternalHosts` then used this IP.
The test only bound a socket and changed no system configuration.

**Round 2 failed as expected.** The server now listened at `192.168.1.201`.
The task first required HTTPS with the self-signed certificate from `openssl req -x509 ... -subj '/CN=127.0.0.1'`.
That request failed:

```
[guest] fetch failed: TypeError: fetch failed
[guest] cause: Error: ...SSL alert number 40 (handshake failure)
```

The full log is `evidence-03-selfsigned-https-rejected-on-host-upstream-leg.log`.
Gondolin's outbound host connection uses the host's normal TLS stack.
That stack rejected the test server's untrusted self-signed certificate, as expected.
The test then used the documented plain HTTP fallback.
Streaming behaviour does not depend on TLS.
M0.2 separately tests MITM CA trust, so this substitution preserves this test's purpose.

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

The host server sent chunks 400ms apart.
The guest received them at 533, 915, 1316, 1717, and 2118ms.
The gaps were 382, 401, 401, and 401ms, within scheduling jitter of the send cadence.
The server logged one connection at the matching timestamp.
The source was the host's proxy address, as expected for a MITM connection:

```
[server] connection from 192.168.1.201:43876 at 2026-08-22T12:47:57.536Z
[server] wrote chunk 0 at 2026-08-22T12:47:57.937Z
...
[server] wrote chunk 4 at 2026-08-22T12:47:59.538Z
```

This meets the task brief's pass condition.
The timestamps span the full duration of more than two seconds.
They do not cluster at one instant, so the mediation layer preserves incremental delivery.

### Verdict and reasoning

**PASS**, on both the letter and the intent of the gate:

1. A real TLS handshake to `api.anthropic.com` completed.
   ALPN negotiated `http/1.1` although the client offered `h2`.
   This matches the documented HTTP/1.x TLS interception behaviour.
   Node's undici requests HTTP/2 only with `allowH2: true`.
   Corb does not set that option, as the plan already noted.
2. Incremental delivery survives egress mediation.
   Chunk arrival timestamps span the full send duration.

R1 has no unresolved findings.
The guest loopback route and the self-signed upstream certificate caused two failed attempts.
The task brief allowed fallbacks for both risks.
Those fallbacks resolved the setup problems without changing the property under test.

### What surprised us / had to be routed around

- The brief did not name the `127.0.0.1` loopback routing problem.
  It allowed another approach within the process.
  Future tests can bind to an existing host interface instead of `127.0.0.1`.
- The self-signed certificate rejection matched the brief's prediction.
  The HTTP fallback resolved it.
- No process stayed running.
  Each run closed the guest VM through `vm.close()` in a `finally` and killed the host test server.

### Evidence files

All under `spike/m0-1-http2/`:

| File | Contents |
|---|---|
| `evidence-01-first-attempt-127-loopback-fails.log` | Check 1 pass + Check 2 first failed attempt (HTTPS, `127.0.0.1`) |
| `evidence-02-plain-http-still-fails-on-127-loopback.log` | Check 2, plain HTTP, `127.0.0.1`, rules out a TLS cause, isolates the loopback-routing issue |
| `evidence-03-selfsigned-https-rejected-on-host-upstream-leg.log` | Check 2, self-signed HTTPS, real LAN IP, anticipated host-upstream cert rejection |
| `evidence-04-http-lanip-check2-only-pass.log` | Check 2 only, plain HTTP, real LAN IP, pass |
| `evidence-05-final-combined-pass.log` | Both checks in a single VM boot, final combined pass, the primary evidence record |

---

*(M0.2, R3, MITM CA trust, is separate and not yet run as part of this
entry.)*

---

## M0.2: R3: MITM CA trust for node, curl, git and go

**Date:** 2026-08-22

**Gondolin version:** `@earendil-works/gondolin@0.12.0` (pinned exact, no caret)

**Verdict: PASS for all four tools.** Corb need not set explicit CA environment variables for these checks.
Gondolin's guest init exports `SSL_CERT_FILE`, `CURL_CA_BUNDLE`, `REQUESTS_CA_BUNDLE`, and `NODE_EXTRA_CA_CERTS` unconditionally.
These reach every guest process regardless of the `env` passed to `VM.create()` or `vm.exec()`.
Corb can set them explicitly to guard against a future Gondolin change.
The current guest defaults already provide trust.

### What was built

`spike/m0-2-mitm-ca/`:

- `package.json` defines a standalone package. It depends on exactly `@earendil-works/gondolin@0.12.0`.
- `build-config.json` is a minimal `BuildConfig`. It sets `alpine.rootfsPackages:
  ["linux-virt", "nodejs", "curl", "ca-certificates", "bash", "git", "go"]` with no `postBuild` section.
  Each package needs only APK extraction, without compilation.
  The build needs neither Docker nor root.
  It uses `gondolin build` with `/usr/sbin:/sbin` prepended to `PATH`, as M0.1 required for e2fsprogs.
  `rootfs.sizeMb` increased from 2048 to 3072 for Go.
  Assets live under `spike/m0-2-mitm-ca/assets/`.
- `check.go` sends an HTTP POST to `https://api.anthropic.com/v1/messages` through the standard `net/http` package.
  A completed handshake with any HTTP response passes. A 401 also passes.
  A certificate error fails.
  The check needs no API key or external Go modules.
  `go run` needs no module downloads.
- `run-spike.mjs` boots one VM.
  It uses `createHttpHooks({ allowedHosts: ["api.anthropic.com", "github.com"] })` without explicit CA variables at the `VM.create()` level.
  It checks node, curl, git, and go through `vm.exec(argv, { env })`.
  Each tool runs once with minimal `env`.
  It then runs with its CA variable set to `/run/gondolin/ca-certificates.crt`.
  The script also compares `/etc/ssl/certs/ca-certificates.crt` with Gondolin's merged bundle.
- `diag-env.mjs` and `diag-env2.mjs` locate the source of the CA variables.
  They dump the guest environment through `/usr/bin/env` under different `VM.create()` and `vm.exec()` configurations.
- `diag-ca-install.mjs` checks whether `update-ca-certificates` changes the guest system bundle at `/etc/ssl/certs/ca-certificates.crt`.
- `diag-negative-control.mjs` supplies a real negative control.
  Gondolin's init makes omission of the variables insufficient.
  The script overrides every relevant CA variable with `/nonexistent/definitely-not-a-cert.crt`.
  It then restores the merged bundle path for a positive control.
  Both checks run for all four tools within one VM.

### What surprised us: a "bare" run is not actually bare

The task expected each tool to fail without its CA variable and pass with it.
The first run in `evidence-01-full-run.log` did not show that split.
Every tool passed with both the minimal and explicit environment.
The diagnostics traced this result rather than assuming the system store already trusted the CA.

1. `evidence-02-env-diagnostic.log` captures a direct `/usr/bin/env` in the guest.
   It uses `vm.exec(["/usr/bin/env"], { env: { PATH: "/usr/bin:/bin" } })` without CA settings.
   The output still contains:

   ```
   CURL_CA_BUNDLE=/run/gondolin/ca-certificates.crt
   NODE_EXTRA_CA_CERTS=/etc/gondolin/mitm/ca.crt
   SSL_CERT_FILE=/run/gondolin/ca-certificates.crt
   REQUESTS_CA_BUNDLE=/run/gondolin/ca-certificates.crt
   UV_SYSTEM_CERTS=true
   ```

2. `evidence-03-env-source-diagnostic.log` excludes `createHttpHooks()` as the source.
   Its returned `env` was `{}` because the check configured no secrets.
   The check also omitted `VM.create()`'s `env` field.
   The same five variables still appeared.
3. The shipped `node_modules/@earendil-works/gondolin/dist/src/alpine/init-scripts.js` settles the source.
   Its guest `/init` function runs as PID 1, as `gondolin-notes.md` §8 describes.
   It unconditionally exports:

   ```sh
   export SSL_CERT_FILE="${runtime_ca_bundle}"
   export CURL_CA_BUNDLE="${runtime_ca_bundle}"
   export REQUESTS_CA_BUNDLE="${runtime_ca_bundle}"
   export NODE_EXTRA_CA_CERTS="${mitm_ca_cert}"
   ```

   `runtime_ca_bundle` means `/run/gondolin/ca-certificates.crt`, the merged bundle.
   `mitm_ca_cert` means `/etc/gondolin/mitm/ca.crt`, the single raw CA certificate.
   Node receives the single certificate while the other three tools receive the merged bundle.
   These exports run independently of host JS configuration.
   Every guest child process inherits them.
4. `diag-ca-install.mjs` records its result in `evidence-04-update-ca-certificates-diagnostic.log`.
   The init script also runs `update-ca-certificates` to add the CA to the system store.
   The guest has that binary and a populated `/usr/local/share/ca-certificates/gondolin-mitm-ca.crt`.
   A manual rerun still leaves `/etc/ssl/certs/ca-certificates.crt` at 120 certificates.
   It never gains Gondolin's certificate as the 121st entry.
   The system store therefore does not trust the CA on this Alpine build.

Only the four exported variables provide trust in these checks.
The spike did not investigate the system-store problem further because the exported paths passed for all four tools.
A guest tool that uses only the system store can still fail despite `update-ca-certificates` reporting success.
Such a tool ignores `SSL_CERT_FILE`, `SSL_CERT_DIR`, `CURL_CA_BUNDLE`, and `NODE_EXTRA_CA_CERTS`.

Because of this, "unset the var, see it fail" is not achievable by omission, Gondolin's init has already set it before any exec runs. The genuine negative
control is to override the var(s) to a bad path, done in
`diag-negative-control.mjs`.

### Per-tool evidence (bogus-override negative control vs. real bundle)

`evidence-05-negative-control.log` records one VM boot and two runs per tool.
The negative run points `SSL_CERT_FILE`, `SSL_CERT_DIR`, `CURL_CA_BUNDLE`, `REQUESTS_CA_BUNDLE`, `NODE_EXTRA_CA_CERTS`, and `GIT_SSL_CAINFO` at `/nonexistent/definitely-not-a-cert.crt`.
The positive run points the applicable variables at `/run/gondolin/ca-certificates.crt`.

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
`x509: certificate signed by unknown authority`), not a DNS failure, a
network-unreachable error, or a protocol error. That isolates the cause
precisely to CA trust, for all four tools.

### Why the first ("bare", pre-negative-control) run is still useful evidence

`evidence-01-full-run.log` preserves the result for Corb's normal guest launch.
All four tools get TLS trust through the default guest environment without extra configuration from Corb.
The negative control in `evidence-05-negative-control.log` explains why.
It proves that Gondolin's environment variables provide the trust.
The system trust store alone does not, as the `update-ca-certificates` check showed.

### Reasoning per tool

| Tool | Var(s) that matter | Auto-injected by Gondolin init? | Needs Corb to set it explicitly? |
|---|---|---|---|
| node | `NODE_EXTRA_CA_CERTS` | yes | no |
| curl | `CURL_CA_BUNDLE` (also honours `SSL_CERT_FILE`, also auto-injected) | yes | no |
| git | no git-specific var needed, its libcurl/OpenSSL backend reads `SSL_CERT_FILE` directly | yes (`SSL_CERT_FILE`) | no |
| go | `SSL_CERT_FILE`/`SSL_CERT_DIR`, read directly by `crypto/x509` on Linux | yes (`SSL_CERT_FILE`) | no |

The guest environment template in `docs/design.md` §8 sets `NODE_EXTRA_CA_CERTS` and `SSL_CERT_FILE` alongside `...env` from `createHttpHooks`.
Gondolin already supplies these variables before it applies that `env` object.
Explicit values remain a harmless defence against future default changes.
This finding requires no change to `design.md`.
The explicit variables provide a safety net while Gondolin's init provides trust today.

### Evidence files

All under `spike/m0-2-mitm-ca/`:

| File | Contents |
|---|---|
| `evidence-01-full-run.log` | Main driver run: all four tools, "no var mentioned" vs "var explicitly set to the real bundle" (both pass, the surprise that led to the rest) |
| `evidence-02-env-diagnostic.log` | Full guest process env dump proving the CA vars are present even when `ExecOptions.env` does not mention them |
| `evidence-03-env-source-diagnostic.log` | Rules out `createHttpHooks()`'s `env` and `VM.create()`'s `env` as the source (both absent/omitted, vars still present) |
| `evidence-04-update-ca-certificates-diagnostic.log` | Confirms the guest's system trust store (`/etc/ssl/certs/ca-certificates.crt`) does **not** end up containing Gondolin's CA, despite `update-ca-certificates` reporting success |
| `evidence-05-negative-control.log` | The rigorous fail-without/pass-with test: every CA env var forced to a nonexistent path (genuine failure, cert-trust errors only) vs. pointed at the real merged bundle (pass), all four tools, one VM boot |

Left running: nothing. The VM was closed in a `finally` block on every run
(`run-spike.mjs`, `diag-env.mjs`, `diag-env2.mjs`, `diag-ca-install.mjs`,
`diag-negative-control.mjs` all follow this pattern). No lingering
QEMU/`gondolin-krun-runner` processes after the session.

---

## M0.4: R2: exec concurrency with a long-lived interactive process

**Date:** 2026-08-30

**Gondolin version:** `@earendil-works/gondolin@0.12.0` (pinned exact, no caret)

**Verdict: PASS, exec does not serialise.** A second `exec` runs alongside a long-lived `pty: true` exec.
This works within one host process and across processes through `connectToSession()`.
The long-lived exec keeps answering commands without cross-talk.

`corb attach` in M8.7 is viable as a new shell in the running session.
The control protocol cannot rejoin Pi's existing TUI.
The SDK page describing independent command channels is correct about exec.
The page describing one command at a time is incorrect about exec.

`waitForExecIdle()` instead gates `vm.fs` file operations.
Corb's `runSession()` cannot use `vm.fs.readFile`, `writeFile`, or `deleteFile` while Pi's TUI runs.

### What was built

`spike/m0-4-exec-concurrency/` boots the tagged runtime image through `resolveRuntimeImage()` in `src/vm/image.ts`.
It uses the repository's pinned `node_modules` rather than a separate dependency tree.
It has no `package.json`, `build-config.json`, or `assets/`.
This measures the guest Corb ships rather than a different image.
The script drives `VM.create()` directly to isolate SDK behaviour.
`test/e2e/policygate-content.e2e.ts` and `test/e2e/dropcap-status.e2e.ts` use the same approach.

- `lib.mjs` supplies shared helpers such as `withTimeout`.
  Every wait has a bound and records "still pending after N ms" rather than hanging.
  Serial execs can otherwise leave a plain `await` pending forever without evidence.
- `same-process.mjs` runs measurements 1, 1b, 3, 4, and 5 within one process and VM.
  It tests shape `A`, a plain `/bin/sh` with a pty.
  Shape `B` uses `dropcap 1000 1000 /bin/sh` with a pty.
  Shape B matches production's wrapper with a shell instead of `pi`.
  `--no-warmup` reproduces the boot trap described below.
- `session-holder.mjs` represents the `corb run` process.
  It boots a VM and starts a long-lived `dropcap 1000 1000 /bin/sh` exec.
  It uses `pty: true`, `stdin: true`, and `stdout: "pipe"`, as `session.ts` does.
  It timestamps every output byte and samples `execPressure()` every two seconds.
  It accepts `send`, `expect`, `assert-absent`, `pressure`, `status`, and `quit` commands for independent checks.
- `attach-client.mjs` represents `corb attach` in a separate host process.
  It holds only the Unix socket, without a `VM` object.
  It uses the raw protocol through `connectToSession()`.
- `run-cross-process.sh` starts the holder through `setsid` and waits a bounded time for its state file.
  It runs the attach client and then checks whether the holder's long exec survived.
  It redirects `CORB_STATE_DIR`, `CORB_CONFIG_DIR`, and `GONDOLIN_SESSIONS_DIR`.
  The sessions path is `/tmp/gsess`, 10 characters within `src/vm/sockpath.ts`'s 66-character budget.
  This avoids confusing a socket bind failure with an exec concurrency failure.
- `exec-ceiling.mjs` measures the session's exec limit.
- `inspect-sdk.sh` prints the shipped SDK source behind the findings.

### Reading the SDK first: what `corb attach` can and cannot be

Confirmed independently, as the brief asked (full output:
`evidence-06-sdk-inspection.log`). `ClientMessage` is a closed union and the
complete client-to-server vocabulary is:

```
export type ClientMessage = BootCommandMessage | ExecCommandMessage | StdinCommandMessage | PtyResizeCommandMessage | ExecWindowCommandMessage | LifecycleCommandMessage | SnapshotCommandMessage;
```

The protocol has no "list running execs" or "join exec N" operation.
`SessionIpcServer` gives each client a separate request ID space.
The source says `// Per-client id translation to keep each external channel independent.`
Internal IDs decrease from `0xffffffff` above `INTERNAL_ID_FLOOR`, which is `0x80000000`.
They do not overlap the session owner's small IDs.
The server refuses an ID that the requesting client never allocated:

```
        const forwardMappedIdMessage = (message) => {
            const internalId = externalToInternal.get(message.id);
            if (internalId === undefined) {
                sendError(socket, "unknown_id", "request id not found", message.id);
```

`corb attach` can only start a new exec, because the protocol cannot rejoin Pi's TUI stream.
Check 4b confirms this in a running session.

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

The other admission gate is `maxQueuedExecs`, which defaults to `64`.
It does not serialise exec against exec.

### Check 1: same-process concurrency

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

Shape B (`dropcap 1000 1000 /bin/sh` + pty, production's wrapper) is
identical:

```
[15:29:25.476 t+ 49001ms]   second one-shot exec: resolved after 5ms
[15:29:25.476 t+ 49001ms]   exitCode=0 stdout="SECOND_ONESHOT_4DBC9534\n"
```

The second exec starts in 5-6ms across runs.
`evidence-01-boot-warmup-trap-negative-control.log` records 6ms.
It does not wait for the long-lived shell to exit.
Both shapes behave the same, so the `dropcap` wrapper does not change exec admission.

Prompt admission alone does not prove parallel execution.
Measurement 1b checks elapsed time for four concurrent `sleep 3` execs alongside the long exec:

```
[15:29:10.894 t+ 34419ms]   execPressure(long exec + 4 sleeps, sampled 750ms in) = 5
[15:29:13.155 t+ 36680ms]   four concurrent 3s sleeps: resolved after 2261ms
[15:29:13.155 t+ 36680ms]   wall clock for 4x 'sleep 3': 3013ms (parallel ~3000ms, serialised ~12000ms)
[15:29:13.155 t+ 36680ms]   exit codes: [0,0,0,0]
```

3013ms, not 12000ms. Genuinely parallel in the guest, not merely queued
politely.

### Check 2: cross-process concurrency via `connectToSession()`

**This is the one that decides M8.7.** From
`evidence-03-cross-process-attach.log`. The holder process (pid 509514) has
the long-lived `dropcap`+pty exec. The attach client (pid 509974) is a
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

It executes, and **its stdout comes back**, 13ms end to end, over a socket,
from a process that has no `VM` object.

### Check 4: an *interactive* second exec (what `corb attach` actually wants)

Both in-process and over the attach socket. Over the socket, a `pty: true`
`/bin/sh`, driven for two round-trips with a `pty_resize` in between (the
`\u001b[6n` cursor-position queries are the shell's own output. The logs
JSON-escape them, so what appears below is literal text, not control bytes):

```
[15:16:37.433 t+    17ms] ATTACH CHECK 2 — interactive pty:true /bin/sh over connectToSession()
[15:16:37.440 t+    24ms]   <- stdout (id=2) "attach$ \u001b[6n"
[15:16:37.809 t+   393ms]   <- stdout (id=2) "40 120\r\n"
[15:16:37.810 t+   394ms]   <- stdout (id=2) "0\r\n"
[15:16:37.810 t+   394ms]   <- stdout (id=2) "ATTACH_PTY_TURN2_1B7E5C33\r\nattach$ \u001b[6n"
[15:16:37.858 t+   442ms]   <- JSON {"type":"exec_response","id":2,"exit_code":0}
```

The command that produced `40 120` was `stty size; id -u; echo ATTACH_PTY_TURN2_1B7E5C33`, visible in that exec's full transcript on line 50
of the log.

`stty size` returns `40 120`, the geometry sent through `pty_resize`.
This confirms a real pty with a resizable window rather than a pipe.

And in production's shape, an unprivileged shell via `dropcap`:

```
[15:16:37.859 t+   443ms] ATTACH CHECK 3 — dropcap 1000 1000 /bin/sh, pty:true (what `corb attach` would actually run)
[15:16:38.162 t+   746ms]   <- stdout (id=3) "id -u; id -g; echo ATTACH_DROPCAP_A74EBF18\r\n"
[15:16:38.184 t+   768ms]   <- stdout (id=3) "1000\r\n"
[15:16:38.184 t+   768ms]   <- stdout (id=3) "1000\r\n"
[15:16:46.292 t+  8876ms]   result: {"answered":true,"exited":true,"response":{"type":"exec_response","id":3,"exit_code":0},...}
```

uid 1000, gid 1000, an attach shell can be dropped to the agent's own
privilege exactly the way `session.ts` drops Pi's.

The same shape works in-process too (`evidence-02-same-process.log`), with
two independent interactive execs live at once:

```
[15:29:25.214 t+ 48739ms]   second pty exec produced its own marker: true
[15:29:25.266 t+ 48791ms]   second pty exec second round-trip: true
[15:29:25.266 t+ 48791ms]   execPressure(two interactive execs, both confirmed live) = 2
```

### Check 3: does the first exec survive? (and cross-talk)

The cross-process run supplies the strongest evidence.
Separate processes log both sides, so their timestamps allow an independent comparison.
The attach client held its `dropcap` pty open from 15:16:37.859 to 15:16:46.292.
During that interval it drove the holder's long exec.
The holder logged:

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

The long exec accepted new input and produced correct output at 15:16:38.4.
This happened during the attach client's shell session and proves more than process survival.
Pressure stayed at 2 throughout the overlap.
It returned to 1 when the attach shell exited near 15:16:46.3.

After the attach client exited, another check asked the holder:

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

**Check 4b tests access to the session owner's exec.**
The protocol has no join operation.
The check therefore addresses the owner's request ID directly.
The server refuses it, as the ID remapping code predicts:

```
[15:16:46.292 t+  8876ms]   holder's long exec has VM-internal id=5
[15:16:46.293 t+  8877ms]   <- JSON {"type":"error","code":"unknown_id","message":"request id not found","id":5}
[15:16:46.293 t+  8877ms]   <- JSON {"type":"error","code":"unknown_id","message":"request id not found","id":5}
```

and `ATTACH_HIJACK_ATTEMPT` never appears in the long exec's stream (above).
This is a *good* result: it means a stray or hostile attach client cannot
inject keystrokes into Pi's TUI. It is also the definitive proof that
`corb attach` cannot mirror the agent's screen.

### Check 5: `execPressure()` and `waitForExecIdle()`, read then measured

Read first (`evidence-06-sdk-inspection.log`). `execPressure()` is a plain
count of live exec requests, started plus admitted-but-not-yet-started:

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

The measured counts match the implementation exactly.
Pressure is `0` before exec, `1` with the long exec, and `2` with two live interactive execs.
It reaches `5` with the long exec plus four sleeps and `64` at the ceiling.
It returns to `0` after every exec exits.

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

This is the actual serialisation point, opposite to R2's initial assumption.
If exec serialised, R2 proposed network or VFS mediation with `vm.fs` for host file needs.
Measurements show that exec runs concurrently while `vm.fs` file transfers serialise.
`vm.fs.readFile`, `writeFile`, and `deleteFile` cannot finish while Pi's TUI stays alive.
This lasts for the full `corb run` session.

`vm.fs.stat`, `listDir`, `mkdir`, `access`, and `rename` use exec instead of file transfers.
They still work, with the 6ms example above.
Corb currently calls none of the three blocked methods.
This constrains future host code rather than breaking a current feature.

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
between the owner's execs and every attach client's execs, the admission
check reads one counter. The long exec survived the flood untouched.

### Verdict and reasoning

**PASS. The measurements close R2.** Each check passed:

1. The same-process second exec starts in 5-6ms.
   Four parallel `sleep 3` calls complete in 3013ms.
2. `connectToSession()` executes from a separate process and returns stdout in 13ms end to end.
3. The first exec accepts input and produces output throughout the second session without cross-talk.
4. A second interactive exec uses a real resizable pty.
   `stty size` returns `40 120` under `dropcap` with uid and gid 1000 too.
5. `execPressure()` counts live execs.
   `waitForExecIdle()` waits for zero and only gates the three `vm.fs` file transfer methods.

**Recommendation on M8.7: build it, as `corb attach` opening a *new*
interactive shell in the running session. Not as a way to see or share Pi's
screen, which is impossible in 0.12.0.** Caveats the implementation must
carry:

- **Explain the command's behaviour clearly.** The user gets a fresh shell beside the agent.
  It does not rejoin the agent's terminal.
  If the command keeps the name `attach`, its help and first-run output must explain this.
  `corb shell` describes the behaviour more directly.
- **Use `dropcap <uid> <gid>` and production's guest environment.** `session.ts` uses this wrapper.
  Omitting it gives the attach user a root shell and breaks the R18 privilege boundary.
  The test confirms uid and gid 1000 work.
- **The session owner's server preserves host policy.** It executes attach requests with the same `httpHooks`, sentinel, and VFS providers.
  The client supplies only argv and env.
  It cannot access host hooks or the secret manager.
- **Handle `server_shutdown`.** When `corb run` exits or its watchdog fires, `vm.close()` rejects every live exec.
  The error is `error server_shutdown:
  server is shutting down`, and the attach socket closes.
  Render this as "session ended" rather than a crash.
  The failed attempt below shows the consequence of ignoring it.
- **Attach IPC refuses `lifecycle`.** It returns `"lifecycle actions are not
  supported over attach IPC"`.
  `corb attach` therefore cannot stop the session.
  `corb kill` keeps its signal-based approach.
- **Account for the 64-exec session limit.** A few human shells fit within the limit.
  Future features that start many execs must share those slots with attach sessions.
- **The host cannot kill an individual attach exec.** The limitation in §3 also applies here.
  An abandoned pty shell retains a slot until `vm.close()`.
  M8.7 must consider that behaviour, but it does not block attach.

### What surprised us / had to be routed around

- **`VM.create()` resolves before guest boot.** The first `same-process.mjs` run used a 15-second timeout per step.
  It reported `long exec alive: false` for both shapes.
  That resembled exec serialisation, but the guest was still booting.
  Boot starts lazily with the first exec and takes about 33 seconds on this machine.
  `VM.create()` resolved in 86ms while `getHostPid()` still returned `null`.
  The correction adds a `BOOT` warm-up exec in `main()`.
  `--no-warmup` preserves the failed setup as a negative control.
  Its evidence is `evidence-01-boot-warmup-trap-negative-control.log`.
  The result distinguishes blocked exec admission from an unfinished guest boot:

  ```
  [15:20:38.866 t+    84ms] VM.create() returned, id=5d799965-61a5-4212-8c93-6e813818b01a hostPid=null
  [15:20:38.866 t+    84ms] --no-warmup: skipping the boot warm-up (negative control)
  [15:20:58.937 t+ 20155ms]   long exec alive: false
  [15:21:12.333 t+ 33551ms]   long exec alive: true
  ```

  Shape A returns `false` after its 20-second budget while the guest still boots.
  Shape B later returns `true` because the guest becomes ready near 33 seconds.

  Shape A's abandoned exec also stays live because there is no kill operation.
  It offsets later pressure counts by one: `execPressure(no execs running) = 1`.
  It prevents `waitForExecIdle()` from resolving even when the test expects idle.
  Future pressure logic must treat leaked execs as permanent until VM closure.

- **`VM` exposes neither pressure method.** §3's earlier description applied only to `SandboxServerOps`.
  `VM` holds that object in a `private server` field and provides no public forwarding methods.
  `grep -c "execPressure\|waitForExecIdle" dist/src/vm/core.d.ts` returns `0`.
  This `.mjs` spike reaches `vm.server` because TypeScript only enforces `private` at compile time.
  Production code cannot depend on either method for a session busy check or other purpose.

- **Unhandled exec rejections can kill the host process during `vm.close()`.**
  The first ceiling run produced its correct result, then died.
  The excerpt abbreviates absolute paths to `.../`, but the evidence log keeps them in full:

  ```
  Error: error server_shutdown: server is shutting down
      at VM.handleError (.../dist/src/vm/core.js:1445:23)
      at SandboxServer.failInflight (.../dist/src/sandbox/server-ops.js:1276:13)
      at SandboxServer.closeInternal (.../dist/src/sandbox/server-ops.js:453:14)
  ```

  `vm.close()` rejects every live exec.
  Node's default `--unhandled-rejections=throw` converts an unhandled rejection into an uncaught exception.
  `runSession()` safely awaits its one exec today.
  Any future code that starts an exec without awaiting it must attach a rejection handler.
  This includes attach clients and background execs.
  `evidence-04-exec-ceiling-first-attempt-unhandled-rejection.log` preserves the failed run.

- **The process umask determines socket permissions.** Gondolin never calls chmod on the session socket.
  The test saw `srwxr-xr-x` in `/tmp/gsess`, equal to `0777 & ~umask` for the usual `0022`.
  Other local users cannot call `connect()` because they lack write permission.
  The default directory is `~/.cache/gondolin/sessions`.
  Its parent `~/.cache` also has mode `drwx------`.
  A permissive umask instead gives mode `0777` and permits other users to connect to this unauthenticated guest exec channel.
  A direct Node `listen()` under `umask(0)` confirmed mode `777`.
  `src/vm/sockpath.ts` recommends `/tmp/gondolin-sessions` when the default path is too long.
  That move removes the parent directory's protection and leaves only the umask.
  M8.7 can check the mode.
  This spike did not investigate further.

- **The contradictory SDK pages describe different subsystems.** The independent-channel page correctly describes exec.
  The single-command page incorrectly applies file-transfer serialisation to exec.
  `waitForExecIdle()` serialises file transfers against execs, rather than execs against each other.

- No process stayed running.
  Every script calls `vm.close()` in a `finally`.
  `run-cross-process.sh` also checks for leaks.
  The recorded run found `(none)` for both `qemu-system` and `gondolin`, with an empty `/tmp/gsess`.

### Evidence files

All under `spike/m0-4-exec-concurrency/`:

| File | Contents |
|---|---|
| `evidence-01-boot-warmup-trap-negative-control.log` | `--no-warmup` negative control: without a boot warm-up the long exec looks dead for ~33s, which is the failure mode most likely to be misread as serialisation. Also shows an abandoned exec permanently skewing `execPressure()`/`waitForExecIdle()` |
| `evidence-02-same-process.log` | Measurements 1, 1b, 3, 4, 5 in one VM boot, over both long-exec shapes (plain `/bin/sh`, and production's `dropcap 1000 1000 /bin/sh`), the primary same-process record |
| `evidence-03-cross-process-attach.log` | The `corb attach` leg: holder log and attach-client log for one run, wall-clock correlated. Contains the one-shot, interactive-pty and `dropcap`-pty attach execs, the id-hijack refusal, the holder's `execPressure()=2` overlap window, the cross-talk assertions, and the process/socket leak check |
| `evidence-04-exec-ceiling-first-attempt-unhandled-rejection.log` | The ceiling run that produced a correct result and then died on an unhandled `server_shutdown` rejection at `vm.close()` |
| `evidence-05-exec-ceiling.log` | The ceiling: 63 concurrent execs accepted alongside the long exec, then `queue_full` at `execPressure()` 64 |
| `evidence-06-sdk-inspection.log` | The reading half: the closed `ClientMessage` union (no "list execs"/"join exec"), `handleExec`'s file-op-only queueing branch, `maxQueuedExecs`, `execPressure()`, `waitForExecIdle()` and its three callers, the absence of both from `VM`'s public surface, and `SessionIpcServer`'s per-client id space and `unknown_id` refusal |

---

## M9.5: `vm.checkpoint()`/`resume()`: does it actually skip any boot cost?

**Date:** 2026-08-30

**Gondolin version:** `@earendil-works/gondolin@0.12.0` (pinned exact, no caret)

**Verdict: NO SPEEDUP.** Checkpoint and resume do not skip guest boot.
`vm.checkpoint(path)` stops the VM and writes a qcow2 disk with a JSON trailer.
`VmCheckpoint.resume(options)` creates a fresh QEMU VM with an overlay backed by that disk.
It uses the same `createVm()` path as a cold `VM.create()`.

Both paths start the kernel, initramfs, `/init`, `sandboxd`, `sandboxfs`, and `rootfsInitExtra` with the `bindfs` re-export.
`gondolin-notes.md` §2 already states that checkpoints contain no memory snapshots.
This spike measures the resulting boot cost.

Four boots use the tagged `corb:0.1.0` image.
Each measurement starts at `VM.create()` or `resume()` and ends after a successful first `vm.exec()`.
That exec reads `cat /etc/corb/image.json`, as `session.ts`'s `readGuestIdentity()` does:

| Boot | Time to first exec |
|---|---|
| Cold #1 | 33472ms |
| Cold #2 | 33568ms |
| **Resumed from a checkpoint of Cold #1** | **33548ms** |
| Cold #3 (after the resume, same run) | 33552ms |

All four measurements agree within noise.
A resumed VM takes as long as a cold VM to become usable.
Checkpointing immediately after boot saves no startup time.
M0.4 independently recorded the same roughly 33-second cost months earlier.
Its `evidence-01-boot-warmup-trap-negative-
control.log` measured a cold boot without warm-up for an unrelated exec test.
The independent measurements agree on the guest's boot cost.

### Why: reading `checkpoint.js`'s `resume()`

`resume()`'s merge logic (`node_modules/@earendil-works/gondolin/dist/src/checkpoint.js`):

```js
const mergedForResume = { ...base, ...options, sandbox: { ...(base.sandbox ?? {}), ...(options.sandbox ?? {}) } };
// ...
const merged = { ...mergedForResume, sandbox: { ...(mergedForResume.sandbox ?? {}), imagePath: resolved.imagePath, rootDiskPath: overlayPath, rootDiskFormat: "qcow2", rootDiskReadOnly: false, rootDiskDeleteOnClose: true } };
return await createVm(merged);
```

Two things worth being explicit about, neither obvious from the `.d.ts` alone:

- **`VmCheckpoint.load(path)` sets `baseVmOptions` to `null`.**
  A later process loading that checkpoint therefore starts with `base` equal to `{}`.
  `resume(options)` must get every `VMOptions` field through `options`.
  These include `vfs.mounts`, `httpHooks`, `env`, `ssh`, `dns`, and `sessionLabel`.
  A checkpoint can therefore resume with a new session's mounts and policies.
  This does not reduce boot cost.
- **`resume()` calls the same `createVm()` as `VM.create()`.** There is no partial boot path.
  Every resume runs the kernel, initramfs, `/init`, `sandboxd`, `sandboxfs`, and `rootfsInitExtra` with bindfs.
  The roughly 33.5-second measurement covers this full sequence.
  Checkpoint and resume cannot skip any part.

### Why this makes "warm starts" a dead end for Corb specifically, not a missing feature

Even apart from boot time, Corb's architecture leaves little session data for a disk checkpoint to capture:

- Session data already lives behind VFS mounts.
  These include `/work/<name>`, `/home/agent/.pi` through `MemoryProvider`, and `/home/agent/sessions` through `RealFSProvider`.
  `/run/corb` holds the mounted gate config.
  As `gondolin-notes.md` §2 states, checkpoints never capture VFS data.
- Persistent disk content mostly comes from `corb image build`.
  `postBuild.copy` and `postBuild.commands` in `image/corb-image.json` supply it.
  The tagged image selector `sandbox.imagePath: "corb:0.1.0"` already reuses that content across sessions.
  A checkpoint of a freshly booted, unused VM adds no useful state.
- The image removes `npm`, `npx`, `apk`, `su`, `sudo`, and `doas`.
  A normal session therefore has no intended action that creates useful persistent disk state to checkpoint.
  See the supporting image measures in `docs/design.md` §2.
  `/root`, `/tmp`, `/var/tmp`, `/var/cache`, and `/var/log` use tmpfs and cannot contribute checkpoint content.

### What was built

`spike/m9-5-checkpoint/run-spike.mjs` boots the tagged `corb:<pkgVersion>` image through `sandbox.imagePath`.
Like M0.4, it measures Corb's shipped image rather than a separate test image.
It times four boots through the first successful `vm.exec()`.
Two cold boots establish baselines.
The first VM then checkpoints, and `VmCheckpoint.load().resume()` uses fresh `VMOptions` with a different `sessionLabel` and `httpHooks`.
A third cold boot follows for comparison within the same run.

The `deny-all` `createHttpHooks` configuration blocks egress because the check needs none.
The script closes every VM in sequence and removes the checkpoint file.

### Evidence files

`spike/m9-5-checkpoint/evidence-01-boot-timing-comparison.log`, the four
timed boots verbatim, plus the checkpoint's own JSON metadata trailer
(`guestAssetBuildId`, `compatibleVmm: ["qemu","krun"]`, `snapshotKind:
"disk"`).

## DAR-15 — toolchain layers from disk checkpoints <!-- se: ignore=SE_NO_EMDASH -->

**Date:** 2026-10-25

**Gondolin version:** `@earendil-works/gondolin@0.12.0`

**Verdict:** **go with limits** for one flat toolchain layer per workspace.

A layer can add Go and PostgreSQL tools, retain Corb's protected files, and resume with real session mounts and egress hooks.
The agreed package database recipe covers the missing base packages.
It does not correct every old package record.

The current content tag also omits inputs that affect the base.
DAR-16 must resolve these limits before it can promise complete stale-layer detection.
The image's Git TLS check fails on the stock base as well as the layers.

No complete image-gate pass is claimed.

### What was built

All spike code lives in `spike/dar-15-layers/`.
Production code, guest helpers, and image sources did not change.
The script copies the image gates and builds session options from the real egress and mount helpers.

It uses qemu with explicit `memory: "1G"` and `cpus: 2` for the final trials.

The stock image remained `corb:0.1.0`, buildId `2747a805-7a7e-5798-84ca-077fb5086311`.
Its content tag is `corb:0.1.0-x86_64-171874b9`.
Two separate spike images use only `corb-spike:dar-15-plain` and `corb-spike:dar-15-fixed`.

The code calls `buildAssets`, `importImageFromDirectory`, and `tagImage` directly.
It checks the stock tag before and after both builds.
It never calls `corb image build`.

The build VM mounts the host's verified `apk.static` read-only at `/opt/corb-build`.
It has no workspace mount or secrets.
Later build trials allow only `dl-cdn.alpinelinux.org` through `createHttpHooks`.

The first trial used Corb's normal egress builder, which also adds the inert `policy.corb.invalid` sentinel.
No request reached that sentinel.
The script corrects this difference in later trials.

Checkpoints and adjacent JSON files live under the spike's `runtime/layers/dar-15/` directory.
This models `corbStateDir()/layers/<workspace>/` without changing user state.
The JSON records the local base buildId, layer sha256, creation time, and size.

Ignored runtime files hold the large disks and full file manifests.
Tracked evidence logs hold the results and manifest hashes.

### 1. Can `apk.static` run?

Yes. The host downloads `apk-tools-static` 3.0.8-r0 from Alpine v3.23 for x86_64.
It verifies the APKINDEX signature with keys read from the trusted base image.
It checks the package's `C:` value, package signature, and signed payload `datahash` before extracting the binary.

A one-byte index change fails signature verification.
The verified package checksum is `Q1TYC5NlmaJJePxA9+zAkNE5CJYMU=`.

Root can run the binary from the read-only VFS mount outside `PATH`.
The image's `/etc/apk/keys` and `/etc/apk/repositories` suffice.
HTTPS updates and package downloads work through the egress relay.

The build commands use `SSL_CERT_FILE=/run/gondolin/ca-certificates.crt`.
All observed package requests contact `dl-cdn.alpinelinux.org`.
No trial needs `--allow-untrusted` or an HTTP trust fallback.

One later update receives HTTP 502 before installation.
Its separate retry succeeds over HTTPS.

### 2. What happens with the package database gap?

The gap is real.
Gondolin unpacks `rootfsPackages` without registering their packages or running their install scripts.
The plain rebuilt image records 20 packages.

It lacks the 13 configured non-kernel package capabilities.
The installed `apk-tools` record survives today's removal of `/sbin/apk`.

On the stock image, simulation and installation of `go postgresql16-client` select 18 added packages.
The install takes 10.14 seconds in this trial.
It adds dependencies such as GCC and binutils without replacing the missing Node package record.

It does not install `apk-tools` or restore `/sbin/apk`.
It leaves the existing `libapk` files in place.
The GCC package download succeeds with an `onResponse` hook and the SDK's default 64 MiB response limit.

Node, Pi, Git, bindfs, `go version`, and `psql --version` still work.
All 11 protected file hashes stay equal.
However, the BusyBox trigger recreates `/bin/su`.

The image's removals check then fails.
An accepted build must repeat the removals cleanup after its last APK transaction.

The PostgreSQL trigger prints `apk: not found` but returns success.
Its script calls bare `apk list` for an optional newer-major-version notice.
The trigger has already selected the default `psql` binary at that point.

The client runs as PostgreSQL 16.15.
This result supports the tested package set, not every Alpine install script.
Toolchains with their own installers, such as Go, pip, and Cargo, remain allowed.

The forbidden `PATH` names remain `npm`, `npx`, `su`, `sudo`, `doas`, `apk`, and `apk.static`.

### 3. Does a layer work with real session options?

Yes. A loaded checkpoint resumes with qemu and the canonical runtime asset directory.
The options include `buildEgressConfig` hooks and environment, synthetic DNS, a real workspace provider, and `buildGateConfigMount()`.
The build-only APK mount is absent on resume.

Its leftover `/opt/corb-build` directory is empty.

Through `dropcap 1000 1000`, Go, PostgreSQL, Node, Pi, Git, and bindfs work.
The agent reads and writes `/work/work`.
The host sees its written file.

The agent reads `/run/corb/gate.json`.
Curl and Node validate HTTPS through the merged CA bundle.
These requests also exercise DNS.

A real Pi 1.4.0 session starts, sends a request, receives `ready`, and exits successfully.
The script supplies a small synthetic model response through an HTTP hook.
It uses no real model credentials or external model service.

This verifies the Pi session path, not a live provider integration.

### 4. Do the image gates detect bad layers?

The copied gates run against a VM resumed after the build VM stops.
The original uncleaned layer passes five of seven gates.
It fails removals because `/bin/su` returned.

After cleanup, the layer passes six of seven gates.
The stock base and fixed base also pass six of seven.

The shared failure is the Git leg of the CA gate.
`git ls-remote https://github.com/octocat/Hello-World.git` reports `curl 35` and `tlsv1 alert decrypt error`.
Forcing HTTP/1.1 or setting `GIT_SSL_CAINFO` explicitly does not fix it.

Curl and Node TLS checks pass.
The spike does not attribute this stock-image failure to checkpoints or claim that it fixed it.

Each negative uses an independent mutation, checkpoint, and resumed VM.
The assertions require the intended detector to fail.
The unrelated Git failure cannot satisfy a negative test.

| Mutation | Required detector | Result |
| --- | --- | --- |
| Add an unexpected SUID binary | Copied SUID gate | Rejects it |
| Put `apk.static` on `PATH` | Seven-name removals check | Rejects it |
| Add the SUID path to `/etc/corb/suid-allowlist.txt` | Protected hashes | Rejects it, although the copied SUID gate accepts the changed allowlist |
| Append bytes to `/usr/local/bin/dropcap` | Protected hashes | Rejects it, although the functional privilege gate still passes |

The protected check hashes `/init`, `/usr/local/bin/dropcap`, `/usr/local/libexec/*`, `/etc/corb/*`, `/usr/bin/bindfs`, and `/etc/apk/keys`.
It compares the resumed layer with hashes from a separate base VM.
The copied removals gate checks six names.

The spike adds an explicit `apk.static` check to cover all seven agreed names.
The SUID gate does not inspect file capabilities.
The spike does not claim capability coverage.

### 5. Does the agreed base database recipe work?

The fixed spike registers `rootfsPackages` except `linux-virt` with `apk add --no-cache` before removals.
It removes the installer with `apk del apk-tools`.
The fixed database records 55 packages and covers every configured non-kernel capability.

`openssh-client-default` provides the virtual `openssh-client` capability.
There is no `apk-tools` package record afterward.
Removals passes on the fixed base.

The other gates have the same single Git TLS failure as the stock control.

Two sequential host builds measured 44.60 seconds for plain and 86.30 seconds for fixed.
These are single observations, not a controlled estimate of the recipe's added time.
Both ext4 files have the same 3,221,225,472-byte logical size.

Used filesystem space rises by 311,296 bytes, or 304 KiB.

Registration has two limits.
First, both stock and fixed libraries match signed OpenSSL 3.5.9-r0 package bytes.
Their database records still name 3.5.4-r0 and its older checksums.

The recipe covers absent packages but does not reconcile every existing package record with Gondolin's unpacked files.
The spike adds no unapproved upgrade or reinstall recipe.
Second, registration changes the SSH provider.

The plain image's binary matches signed `openssh-client-krb5` 10.2_p1-r0.
The fixed image matches signed `openssh-client-default` at the same version.
Seven other sampled tool binaries retain equal hashes.

A Go and PostgreSQL install on the fixed base changes no pre-existing tool or library file content.
Its 10 changed existing regular files are APK database/world files, account databases, and their backups.
It adds 6,758 regular files.

All protected hashes remain equal.
The build still needs the removals cleanup after the BusyBox trigger.
The clean checkpoint resumes with the same working tools, workspace, gate config, TLS checks, and Pi session.

### 6. Are checkpoints flat after another install?

Yes. The script resumes the Go-only layer, adds PostgreSQL, and checkpoints again.
The resulting qcow2 header points directly to the fixed base's `rootfs.ext4`.
It does not point to the Go layer.

The script hides that first layer, boots the result, and passes the real session checks.
It restores the hidden file in `finally`.

The flat result is 390,005,044 bytes.
A single build of both package sets is 389,808,432 bytes.
The difference is 196,612 bytes, about 192 KiB.

Installing PostgreSQL onto the Go layer takes 1.60 seconds.
The flattened checkpoint takes 0.56 seconds.
The agreed one-flat-layer design stands.

A fresh rebuild takes seconds to tens of seconds for these packages.
It avoids managing a dependency chain of checkpoints.

### 7. What does a layer cost?

These are individual x86_64 measurements on this host.
Install time excludes repository update, simulation, manifests, and gate checks.
Checkpoint time includes the SDK's sync and VM stop.

The full spike spends more time on evidence and validation than this table shows.

| Layer | Boot to first exec | Install | Checkpoint | Layer bytes |
| --- | ---: | ---: | ---: | ---: |
| Go only | 2.79 s | 7.20 s | 0.151 s | 385,941,800 |
| PostgreSQL only | 2.78 s | 1.00 s | 0.097 s | 11,075,880 |
| Both, first fixed trial | 2.78 s | 16.77 s | 0.145 s | 389,808,432 |
| Both, repeated definition | 2.83 s | 7.79 s | 0.119 s | 389,677,360 |

The clean combined layer resumes to first exec in 3.03 seconds.
The stock cold control with the same gate mount takes 2.96 seconds.
Without that mount, the same stock image takes 33.66 seconds.

`init-extra.sh` polls for the absent gate file for about 30 seconds.
This explains M9.5's earlier 33.5-second measurement.
Resume still performs a full boot and gives no memory snapshot or faster startup path.

The host's `/tmp` is a 16 GiB tmpfs.
Fresh build overlays start at 589,824 logical bytes and 528,384 allocated bytes.
Before the combined checkpoint, the overlay uses 389,808,128 logical and 389,746,688 allocated bytes.

A clean resumed overlay starts at 655,360 logical and 593,920 allocated bytes.
The stacked install uses a small temporary overlay, then flattens into a new roughly 390 MB checkpoint.
Builds and resumes therefore consume host RAM through tmpfs as well as guest memory.

The evidence records the actual temporary paths and available space at each boot.

### 8. Are layers reproducible, and what does hashing mean?

Two builds of the same package definition produce different layer hashes and sizes.
Their backing paths are equal.
Their metadata differs only in `createdAt`.

Their persistent regular-file content manifests are equal.
The CA certificate and bundle bytes are equal too.
Their inode timestamps and generations differ, as do APK database file timestamps.

The raw guest disks differ from ext4 metadata onward.
The spike does not claim that CA contents changed in these trials.

Resuming the canonical checkpoint does not change its hash.
Two concurrent canonical resumes also preserve it.
Resuming a copy against a relocated copy of the same-buildId base changes that checkpoint in place.

The header's backing path changes, its sha256 changes, and its trailer remains readable.
The original checkpoint remains unchanged.

DAR-16 must verify the recorded hash and base identity before resume.
It must compare the checkpoint's full backing path with the resolved canonical base path.
If a rebase is needed, it must serialize that change before sessions can share the file.

After a successful rebase, it must compute the new hash and replace the local JSON atomically.
A copied checkpoint can avoid mutating an artifact already in use.

The shareable inputs remain the agreed content tag, exact package versions, APKINDEX `C:` values, and layer-definition hash.
They identify the intended recipe but do not fully identify today's fetched base bytes.
The content hash covers the config and `postBuild.copy` inputs.

It omits the file referenced by `rootfsInitExtra`.
A copied-input experiment changes that file without changing `171874b9`.
Changing a copied helper does change the hash.

The same content tag also permits newly fetched base package versions under the current build process.
DAR-16 must resolve this gap without moving per-machine buildIds or artifact hashes into `corb.sum`.

`pins-proposal.toml` gives the complete proposed format for the measured stock-base trial.
It contains all 18 added package pins and covers dependencies.
The shape is:

```toml
version = 1

[target.x86_64]
base = "corb:0.1.0-x86_64-171874b9"
definition-sha256 = "<sha256 of the normalized layer definition>"

[[target.x86_64.package]]
name = "go"
version = "1.25.10-r0"
apkindex-checksum = "<the signed APKINDEX C: value>"
repository = "community"
```

The definition hash in the example covers sorted JSON fields for requested packages and `build-hosts`.
This is a format proposal for review, not a new approved canonicalization rule.
The real example keeps Gondolin buildIds, local file hashes, paths, and creation times in local state only.

A rebuild must validate every exact version and `C:` value against a signed index and the downloaded package.
If a version disappears, it must fail clearly and require new pins.
A local APK cache remains follow-up work.

A host-only verifier checks all 18 exact pins against fresh signed indexes and CDN packages.
It verifies the package signatures, `C:` values, exact identities, and payload hashes.
A missing version and a changed checksum both fail with clear messages.

The verifier deletes its temporary downloads and adds no APK cache feature.

### 9. What else breaks?

DNS, CA bundles, the `/work` re-export, `dropcap`, and Pi startup work on resumed layers.
A real guest HTTP server is reachable through `enableIngress()` and host HTTP GET.
`corb gc` leaves the live VM and layer intact.

That check uses task-only state and registry directories set before Node imports Gondolin.
It does not exercise deletion of old layers or define a future retention policy.

Two sessions can resume the same canonical layer together.
Both receive distinct temporary overlays with explicit 1 GiB memory and two CPUs each.
Different writes to the same guest root path stay isolated.

The shared checkpoint hash remains equal.
This checks the same-path case only.
A shared checkpoint must not undergo an in-place rebase while another session uses it.

### Limits and notes for DAR-16

- Keep one flattened layer per workspace and rebuild it after definition changes.
- Export the image gates so a resumed VM can run them without a second image-only boot path.
- Add `apk.static` to removals and repeat removals after the final package transaction.
- Hash protected files against the trusted base before accepting a checkpoint.
- Correct the base package database gap in `image/corb-image.json`.
  The tested recipe leaves stale OpenSSL metadata and changes the SSH provider.
  Those differences need an explicit production decision.
- Resolve the current base content-tag omissions before promising complete stale detection.
  Compare local buildId and resolved base assets before calling `resume()`.
  A mismatched buildId requires a rebuild, not a forced rebase.
- Keep the shareable pins separate from local checkpoint metadata.
  Verify signed indexes and exact package identities during rebuild.
- Serialize backing-path changes and update the local hash after rebase.
- Change the `--tag` behavior in `src/commands/image.ts` before using it for alternate images.
  Today it also retags `corb:<pkgVersion>`.
- Preserve build isolation: no workspace, no secrets, a separate read-only installer mount, and only the agreed build hosts.
- Treat package script failures carefully.
  The measured PostgreSQL warning is harmless for the tested client commands, but APK success alone cannot prove every toolchain works.
- Track the stock Git TLS gate failure separately.
  A layer cannot claim every image gate passes while that control also fails.

The spike verifies x86_64 with qemu only.
It does not verify aarch64, krun, file-capability scanning, live model credentials, or arbitrary package sets.
It does not implement production layer selection, invalidation, pin refresh, or garbage collection.

### Differences from the prompt and trial corrections

- The libraries described as OpenSSL 3.5.4-r0 actually contain signed 3.5.9-r0 bytes.
  Both stock and fixed database records still name 3.5.4-r0.
- The agreed registration recipe covers missing capabilities but changes the SSH provider and leaves those stale OpenSSL records.
- The earlier 33.5-second boot figure includes an avoidable gate-mount wait.
  The controlled complete mount setup takes about 3 seconds.
- The current content tag omits `rootfsInitExtra` bytes and does not pin fetched base package versions.
  The agreed shareable fields cannot yet detect every changed base.
- Package triggers restore `su` and print a non-fatal missing-`apk` warning.
  The spike repeats removals and records the warning rather than restoring the package manager.
- The stock Git TLS gate fails during this experiment.
  Neither a base nor a layer earns a complete gate pass.
- The first build hook includes an inert policy sentinel.
  Later build hooks use only the CDN host.
- The first host comparison cannot find `debugfs` on `PATH`.
  A later run uses its absolute path.
  Another follow-up corrects the CA filename and confirms equal CA bytes.
- The initial package coverage check treats `openssh-client` as a literal package name.
  The corrected check accounts for virtual package capabilities.
- One fixed install attempt stops at an HTTP 502 before installing anything.
  The retry uses a new log and succeeds over HTTPS.

### Evidence files

All paths below are under `spike/dar-15-layers/`.

| Logs | Evidence |
| --- | --- |
| `evidence-01-signed-bootstrap.log` through `evidence-04-base-database.log` | Signed installer, source checks, signature negative, stock database |
| `evidence-05-original-install.log` through `evidence-08-cleaned-original.log` | Stock install, real resume, stock gate control, removals cleanup |
| `evidence-09-negative-suid.log` through `evidence-12-negative-dropcap.log` | Four independent negative layers and intended detector results |
| `evidence-13-busybox-trigger.log`, `evidence-14-postgresql-trigger.log` | Verified trigger source and the restored `su` and missing `apk` causes |
| `evidence-15-build-plain.log` through `evidence-20-content-tag-inputs.log` | Separate image builds, package capabilities, signed library bytes, tag inputs |
| `evidence-21-fixed-base-control.log`, `evidence-22-fixed-install.log` | Fixed base gates and the preserved HTTP 502 failure before install |
| `evidence-23-base-tool-bytes.log`, `evidence-24-ssh-package-identity.log` | Tool byte comparison and signed SSH provider identities |
| `evidence-25-fixed-install-retry.log`, `evidence-26-fixed-resume.log` | Successful HTTPS retry phase, file changes, cleaned checkpoint, session checks |
| `evidence-27-pins-proposal.log` | Signed-index pin proposal |
| `evidence-28-go-only-cost.log` through `evidence-30-stacking.log` | Separate layer costs, flattening, boot without the first layer |
| `evidence-31-repeat-layer.log`, `evidence-32-boot-delay-control.log` | Repeated definition and controlled gate-mount boot delay |
| `evidence-33-repeat-hashes.log` | Preserved host script failure because `debugfs` was absent from `PATH` |
| `evidence-34-repeat-hash-details.log`, `evidence-35-repeat-ca-details.log` | Host comparison, then corrected CA path, equal bytes and differing inode metadata |
| `evidence-36-moved-base.log` | Copied checkpoint rebase, hash change, readable trailer, real session checks |
| `evidence-37-ingress-gc.log`, `evidence-38-concurrent-resume.log` | Isolated ingress/GC and two safe concurrent resumers |
| `evidence-39-exact-pin-verification.log` | All 18 exact pins, signed packages and payloads, plus two rejection checks |

## DAR-16: one portable Go SDK on two Corb bases

### Verdict and scope

Go with limits for a shared Go SDK payload.
The same verified Go 1.27.3 archive works on two different existing Corb bases.
It also works after each base's separate composed checkpoint resumes.
No second Go download, build, APK installation or package transaction is needed.

This is a validation spike, not a production DAR-16 implementation.
It changes no public commands, configuration schema, package dependencies or image recipes.
The pending production prompt remains unapproved.

Image readiness remains blocked by the existing Git TLS failure.
Each untouched base, composed candidate and resumed candidate passes six of seven image gates.
The failed `ca-trust` gate reports Git's curl 35 TLS decrypt alert.
It is not counted as a successful full gate pass.
No new candidate gate failure appears.

### Verified shared input

The SDK comes from the [official Go release download](https://go.dev/dl/).
Preparation checks the fixed archive against its official release metadata.
Its expected and actual SHA-256 values match:

```text
go1.27.3.linux-amd64.tar.gz
65efbc80fdc1fa2cd2631cad5b481777a68e8725f34e89f50fc6ac714e379b40
```

The complete extracted tree contains 15,657 files and 17,373 total entries.
The script derives its expected file bytes and read-only modes from the authenticated archive.
It compares that manifest with the whole extracted tree.
Later runs repeat this check.
The tree manifest SHA-256 is:

```text
dcbf86ee66b1f6f03677befc8440855d4b3d172dc3b9c9536a8ca34ab4a8e33d
```

All 10 SDK tool executables lack an ELF interpreter and shared-library `NEEDED` entries.
The SDK also contains 58 ELF test fixtures.
Those are not runtime tools.
The trial does not claim that every ELF file in Go's source tree is a static executable.

The real ORAS 1.3.5 CLI copies the artifact between two local OCI layouts.
Fetching the copied archive blob preserves its official digest.
The OCI root manifest digest is:

```text
sha256:fc05a8b6beae66ab326502203fdab003ec16c3916f7b8a82eed4447e67ed56a6
```

That artifact contains the Go archive and version/platform metadata, with no base build ID.
No remote registry or registry authentication flow ran.

### Two distinct bases

Both existing images pass host asset verification before and after the trials.
They share Alpine 3.23.0 and a kernel, but have different rootfs and initramfs bytes.
Their package databases contain 20 and 55 package records.

| Base | Gondolin build ID | Rootfs SHA-256 |
| --- | --- | --- |
| Stock `corb:0.1.0` | `2747a805-7a7e-5798-84ca-077fb5086311` | `66dcee4cc7bcc04b67f1567a806bc16e8d0c00e0b09763593f72b4841533b5cf` |
| DAR-15 fixed | `e8292a0a-0a1a-52d5-959b-9ed372068d54` | `de13c9757a2aaef4aecbc331bbb54416940e8f0dca4367ffbd7b766e9716cec7` |

These are real existing bases, not renamed copies.
There is no invented Corb 0.2.0 release in this trial.
The comparison does not prove compatibility with another Alpine release or every future base.

### Composition and resume

Four VM runs execute serially, with 1 GiB and two CPUs each.
Each fresh VM receives the same read-only host SDK directory outside `/mnt/corb-raw`.
Root copies only that SDK into `/opt/corb/go`, makes it root-owned, and removes write permissions.
No protected Corb path is overwritten.

Uid 1000 runs through production `dropcap` with `GOTOOLCHAIN=local` and `CGO_ENABLED=0`.
The program sorts and hashes independent JSON inputs through concurrent workers.
It writes a checked report to the mounted test workspace.
Three Go tests pass in each composition and each resume: 12 test executions in total.
The pure Go phase makes zero outbound HTTP requests.
Build, module and installation caches are writable outside the SDK.

All 15,657 SDK file hashes match the shared payload in all four runs.
The agent's attempted SDK write is denied.
All seven forbidden names remain absent from `PATH`.
The complete protected path/hash set and each base's APK database bytes stay unchanged.

Copying takes 29.7 seconds on stock and 27.9 seconds on the fixed base.
First compile and test take about 13.8 seconds on each.
Resume compile and test take about 0.65 seconds with the fixture's warm build cache.
These timings do not establish a general startup performance claim.

Each composed checkpoint records its own exact base identity, SDK digest and composition policy.
The two composition identities and checkpoint hashes differ.
Each resumes only against its own exact base.
The SDK input mount is absent on resume, so the copied SDK is captured in the checkpoint.
The canonical checkpoints remain unchanged after resume and the wrong-base rejection.
Global image refs and both bases' original assets stay unchanged too.

### Rejection checks and gate results

A one-byte archive change fails the same checksum verifier used for the accepted SDK.
A protected destination fails the bounded-prefix check before VM composition.
Resuming the stock checkpoint against the fixed base rejects the wrong build ID before boot.
No cross-base disk rebase is attempted.

The spike adapts the current image gates without editing production code.
It records the verifier and adapter source hashes.
All seven gates run on both untouched bases, both compositions and both resumes.
Each report has the same six passes and one Git TLS failure.
Host tests verify that an unrelated baseline failure or any new candidate failure rejects the verdict.
A truly clean seven-gate baseline is allowed.

### Trial corrections and limits

The first preparation attempt treats Go's debug ELF fixtures as tool executables.
The corrected check examines executable tools under `bin` and `pkg/tool` and counts the fixtures separately.
A manifest-ordering correction makes both tree checks use relative-path order.
Both checks then match every authenticated file and normalized mode.

The first VM run completes all four trials, then its final audit fails because it does not await `listSessions()`.
The corrected audit reuses the saved completed results and boots no new VM.
The summary labels this recovery.
The script now awaits the SDK call and captures QEMU PIDs after lazy startup.
Separate host monitoring finds no surviving VM processes.

Copying and separate checkpoint caches are tested.
Direct SDK execution through a read-only VFS mount is not tested.
Other architectures, krun, cgo, native dependencies, arbitrary APKs and arbitrary install commands remain untested.
No personal workspace, live provider credential or secret is supplied.

The result supports sharing a bounded Go filesystem payload across these two compatible bases.
A composed checkpoint remains a cache tied to one exact base.
This does not make an arbitrary base-disk diff portable.

### Reproduction and evidence

The script and commands are in [the spike README](../spike/dar-16-portable-go/README.md).
Use a fresh disk-backed runtime and one coordinator VM slot.
`DAR16_EVIDENCE_DIR` keeps independent review output outside tracked evidence.

All tracked evidence paths below are under `spike/dar-16-portable-go/evidence/`.

| Files | Evidence |
| --- | --- |
| `preparation.json` | Official archive checksums, tool ELF checks, full-tree identity, OCI roundtrip and checksum negative |
| `baseline.json` | Exact base manifests, prior refs and verifier/adapter hashes |
| `stock.json`, `fixed.json` | Package identities, all gate reports, checked program outputs and per-base checkpoint identities |
| `*-protected-*.sha256` | Complete protected-file path/hash sets before composition, after composition and after resume |
| `events.jsonl` | Timed commands, Go test output and expected rejection results |
| `result.json`, `cleanup.json` | Recovered final integrity audit, unchanged inputs and empty task registry |
| `host-vm-lifecycle.json` | Separate monitor of three observed VM PIDs, serial execution and no surviving processes |
| `checks.json` | Required repository checks and separate spike test counts |

Typecheck and source lint pass.
All 1,518 repository unit tests pass across 55 files.
All 53 serial e2e tests pass across 10 files.
Seven host tests cover the gate-report verdict rules.
Both changed Markdown files pass `se lint`.
The separate image-gate controls retain their six known Git TLS failures.
