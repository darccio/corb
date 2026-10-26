# Gondolin SDK notes

What is true about the Gondolin micro-VM SDK, as verified against a specific
version. Corb builds on this SDK, so this file is the ground truth Corb's
design assumes. It changes when Gondolin releases. The design in
[`design.md`](./design.md) changes when Corb's own decisions change.

> Adapted from an earlier design brief for a similar system.

---

## 1. Scope and pinning

- Package: `@earendil-works/gondolin`
- Verified version: **0.12.0**
- Licence: Apache-2.0. Requires Node >= 23.6.0. Host platforms: macOS and Linux
  only.
- Docs site: `https://earendil-works.github.io/gondolin/<slug>/`. The site is
  flat, with no section prefixes in the path. Raw markdown source lives at
  `https://raw.githubusercontent.com/earendil-works/gondolin/main/docs/<slug>.md`.

The project describes itself as early.
Recent minor releases introduced breaking changes. WHATWG-style hook signatures arrived in 0.6.0.
Pin the version exactly in `package.json`, without a caret or tilde.
For each version bump, recheck the risk register below.

Everything in this file was checked against the shipped `.d.ts` for 0.12.0 and
the published docs. Where the two disagree, that is called out.

---

## 2. VM lifecycle

```ts
import { VM } from "@earendil-works/gondolin";

const vm = await VM.create({ /* VMOptions */ });  // autoStart defaults to true
await vm.close();                                 // otherwise QEMU keeps running
```

`VMOptions`:

| Field | Notes |
|---|---|
| `sandbox` | `SandboxServerOptions`. Carries `imagePath`, see [§8](#8-guest-images). |
| `rootfs` | `{ mode?: "readonly" \| "memory" \| "cow", size? }` |
| `autoStart` | Default `true` |
| `fetch` | Custom fetch implementation for egress |
| `httpHooks` | From `createHttpHooks()`, see [§4](#4-network-egress-hooks-dns) |
| `dns` | `{ mode, syntheticHostMapping }` |
| `ssh` | `SshOptions`, see [§6](#6-ssh-egress) |
| `tcp` | Mapped raw TCP escape hatch |
| `maxHttpBodyBytes`, `maxHttpResponseBodyBytes` | Request/response body caps |
| `allowWebSockets` | Default `true` |
| `vfs` | `{ mounts, hooks, fuseMount }`, see [§7](#7-vfs-providers) |
| `env` | Guest environment. Pass the `env` returned by `createHttpHooks`. |
| `memory` | Default `"1G"` |
| `cpus` | Default `2` |
| `startTimeoutMs`, `sessionLabel`, `debugLog` | |

Instance surface: `vm.id`, `vm.getHostPid()`, `vm.checkpoint(path)`,
`vm.shell()`, `vm.fs`, `vm.enableSsh()`, `vm.enableIngress()`,
`vm.getIngressRoutes()` / `vm.setIngressRoutes()`, `vm.setDebugLog()`.

Session registry (module level): `listSessions`, `findSession`, `gcSessions`,
`connectToSession`. A running VM is discoverable and re-attachable from another
host process, which is what makes a detached session model possible.

Checkpoints are **disk only**. There are no memory snapshots. `/root`, `/tmp`,
`/var/tmp`, `/var/cache` and `/var/log` are tmpfs and are excluded from
checkpoints, and data living behind a VFS mount is not captured either.

---

## 3. `exec`

```ts
exec(command: string | string[], options?: ExecOptions): ExecProcess
```

| Form | Behaviour |
|---|---|
| `string` | Run through a login shell, that is `["/bin/sh", "-lc", cmd]` |
| `string[]` | Direct exec. **No `$PATH` search, absolute paths required.** |

`ExecOptions`: `argv`, `env`, `cwd`, `stdin`, `pty`, `encoding`, `signal`,
`stdout` / `stderr` (`"buffer" \| "pipe" \| "inherit" \| "ignore" \| WritableStream`),
`windowBytes`, `buffer`.

`ExecResult` is **always returned**. A non-zero exit does not throw. Fields:
`exitCode`, `signal?`, `ok`, `stdout` / `stderr`, `stdoutBuffer` /
`stderrBuffer`, `json<T>()`, `lines()`.

### Interactive full-screen processes

This is the documented pattern for hosting a TUI:

```ts
const proc = vm.exec(["/bin/bash", "-i"], {
  stdin: true, pty: true, stdout: "pipe", stderr: "pipe",
});
proc.attach(process.stdin, process.stdout, process.stderr);
const result = await proc;
```

`attach()` wires stdin through, enables raw mode, and forwards terminal resize
events into the guest. Call it at most once per process, and do not also
consume `proc.stdout` yourself.

### Sharp edges

- **Exec has no timeout or kill operation.** `ExecOptions` only offers `AbortSignal` for cancellation.
  Aborting rejects the local promise without guaranteeing that the guest process dies.
  The callback surface exposes neither `sendSignal` nor `kill`.
  The caller must implement timeout and termination behaviour.
  `vm.close()` is the only reliable termination primitive.
- **The documentation contradicts itself about concurrency.** One page says a long exec blocks all further exec requests.
  Another says attached clients get independent command channels.
  M0.4 measured the behaviour on 2026-08-30 for R2: `exec` does not serialise.
  A second exec alongside a long-lived `pty: true` exec starts in 5-6ms.
  Four concurrent `sleep 3` execs complete in 3013ms rather than about 12000ms.
  This holds within one host process and across processes through `connectToSession()`.
  The first exec continues to accept input and produce correct output without cross-talk.
  `handleExec` only waits for an in-flight file operation.
  `SandboxServerOptions.maxQueuedExecs` limits the entire session to 64 execs by default.
  Excess requests receive `code: "queue_full"` rather than a queue slot.
- **A live exec blocks some `vm.fs` operations.** `waitForExecIdle()` waits for zero live execs.
  Its callers are `readGuestFileStream`, `writeGuestFile`, and `deleteGuestFile`.
  These implement `vm.fs.readFile`, `vm.fs.writeFile`, and `vm.fs.deleteFile`.
  They never complete while an interactive exec stays live.
  `vm.fs.stat`, `listDir`, `mkdir`, `access`, and `rename` use exec and remain unaffected.
  See R2 and M0.4 in `spike-results.md`.
- **`VM` exposes neither `execPressure()` nor `waitForExecIdle()`.** Both live on `SandboxServerOps`.
  `VM` holds that object in a `private server` field without public forwarding methods.
  `vm/core.d.ts` mentions neither method.
  Host code cannot use them to check whether a session is busy.

---

## 4. Network: egress, hooks, DNS

```ts
const { httpHooks, env, secretManager } = createHttpHooks({
  allowedHosts: ["api.anthropic.com", "*.github.com"],   // wildcards, NOT CIDR
  allowedInternalHosts: [],                              // hosts exempt from the private-range block
  secrets: { API_KEY: { hosts: ["api.anthropic.com"], value: process.env.API_KEY! } },
  blockInternalRanges: true,                             // default
  isRequestAllowed: (req) => req.method !== "DELETE",     // NOTE: req.body is null here
  isIpAllowed: ({ ip }) => !ip.startsWith("203.0.113."),
  onRequest: async (req) => { /* Request | Response | void */ },
  onResponse: async (res, req) => { /* Response | void */ },
});

const vm = await VM.create({ httpHooks, env /* ... */ });  // pass BOTH
```

### Rules that bite

- **The `allowedHosts` defaults are asymmetric.** Omitting the field allows every host.
  An explicit empty array `[]` denies every host.
  Set it explicitly and handle absent configuration values before passing them.
- **`allowedHosts` cannot express IP or CIDR policy.** It matches hostnames with wildcards.
  Use `isIpAllowed` for address rules.
- `blockInternalRanges` defaults to true.
  It covers 127/8, 10/8, 172.16/12, 192.168/16, 169.254/16, and 100.64/10.
  It also covers IPv6 loopback, link-local, and ULA ranges.
- **TLS uses a terminating MITM.** The host reads ClientHello and issues a leaf certificate from its local CA.
  It decrypts the connection and opens an upstream connection.
  The CA lives at `~/.cache/gondolin/ssl`.
  The guest receives it at `/etc/gondolin/mitm/ca.crt` and a merged bundle at `/run/gondolin/ca-certificates.crt`.
  `mitmCertDir` selects a separate CA directory per run.
  The private CA key is a sensitive host asset.
- **The host mediates DNS but uses HTTP for policy.** The host checks the HTTP `Host` header and resolves it independently.
  It largely disregards guest DNS answers, which defeats DNS rebinding.
  The modes are `"open" | "trusted" | "synthetic"`, with `synthetic` as the default.
  Only UDP/53 passes. The relay drops all other UDP.
- `onRequest` can return a synthetic `Response` to answer the request locally.
  This skips upstream DNS, IP checks, and `onResponse`.
  It supports host callbacks. See [§11](#11-there-is-no-guesthost-rpc-by-design).
- **`onRequest` can receive expanded secrets.** Do not log headers or URLs inside a hook.
- The relay classifies non-HTTP flows as `http`, `tls`, or `ssh`.
  It denies other traffic as `unknown-protocol` and denies HTTP `CONNECT`.
- **The relay supports neither HTTP/2 nor HTTP/3.** It supports HTTP/1.x over plain TCP or intercepted HTTPS.
  It supports neither QUIC nor WebRTC.
  WebSockets pass opaquely after the 101 handshake.
  Keep-alive weakens rebinding protection.
- The guest uses gateway `192.168.127.1` and address `192.168.127.3/24`.
- Mapped TCP through `tcp.hosts` provides a raw tunnel.
  It requires `dns.mode: "synthetic"` and `syntheticHostMapping: "per-host"`.
  It bypasses HTTP hooks and secret substitution.
  Any real credentials placed in the guest can reach the tunnel destination.

The SDK documentation states a limitation.
The network layer blocks unexpected egress destinations and limits protocol abuse.
It does not prevent exfiltration to an allowed destination.

---

## 5. Secrets

```ts
const { httpHooks, env } = createHttpHooks({
  allowedHosts: ["api.anthropic.com"],
  secrets: { ANTHROPIC_API_KEY: { hosts: ["api.anthropic.com"], value: real } },
});
```

The host generates a placeholder string. The guest's environment holds only the
placeholder. On outbound HTTP to an **allowed** host, the host substitutes the
real value. A placeholder aimed at a host outside that secret's `hosts` list
causes the request to be blocked rather than silently sent.

| | Substituted |
|---|---|
| Plain header values | yes |
| `Authorization: Basic` / `Proxy-Authorization: Basic` | yes, decoded, replaced, re-encoded |
| URL query string | only with `replaceSecretsInQuery: true` |
| Request body | **no** |
| URL path | **no** |
| Response content | **no** |

The real secret never enters the VM.
The guest therefore cannot read it from its environment, disk, or memory.
An allowed server that echoes request headers in its response can expose the secret.

Placeholder modes are `"shared"` (default) and `"unique"`. Custom shapes come
from `makePlaceholderFunc({ prefix, length, alphabet })`. Matching is
exact-substring, so keep placeholder entropy high.

Runtime rotation: `secretManager.updateSecret(name, { value?, hosts? })`,
`listSecrets()`, `deleteSecret()`.

---

## 6. SSH egress

This is how git-over-SSH works without the guest ever holding a key.

```ts
import { VM, getInfoFromSshExecRequest } from "@earendil-works/gondolin";

const vm = await VM.create({
  dns: { mode: "synthetic", syntheticHostMapping: "per-host" },
  ssh: {
    allowedHosts: ["github.com"],
    agent: process.env.SSH_AUTH_SOCK,
    execPolicy: (req) => {
      const git = getInfoFromSshExecRequest(req);
      if (!git) return { allow: false, message: "non-git ssh denied" };
      if (!allowedRepos.has(git.repo)) return { allow: false, message: "repo not allowed" };
      if (git.service === "git-receive-pack") return { allow: false, message: "push disabled" };
      return { allow: true };
    },
  },
});
```

Upstream authentication happens on the host, against the host's ssh-agent or a
configured key. The guest never receives private key material. Upstream host
keys are verified host-side against `known_hosts` or a custom `hostVerifier`.

`SshOptions`: `allowedHosts` (accepts `HOST:PORT`), `credentials`, `agent`,
`knownHostsFile`, `execPolicy`, connection caps, timeouts, `hostKey`,
`hostVerifier`.

`getInfoFromSshExecRequest` parses the SSH exec request into `{ repo, service }`,
where `service` is `git-upload-pack` (fetch/clone) or `git-receive-pack` (push).
That is what makes "allow fetch, deny push, only these repositories" a short
predicate rather than an argument-vector guessing game.

Restrictions: **exec channels only**. Interactive shells are denied and
subsystems (including sftp) are denied. The guest-facing proxy host key lacks
post-quantum key exchange, so modern OpenSSH clients print a warning. The docs
give a `GIT_SSH_COMMAND` workaround to suppress it.

Note that SSH egress, like mapped TCP, bypasses the HTTP hooks and secret
substitution, `ssh.execPolicy` is the enforcement point on that path.

Separately, `vm.enableSsh()` is **host to guest** debug access. It mints an
ephemeral Ed25519 key, runs guest sshd on loopback only, and explicitly disables
agent forwarding and port forwarding at both ends. It defaults to `user: "root"`.
a non-root user must already exist in the guest image.

---

## 7. VFS providers

```ts
vfs: {
  mounts: { "/work/repo": new RealFSProvider("/host/path") },
  hooks: { before, after },
  fuseMount: "/data",   // default
}
```

Routing selects the longest matching prefix.
The guest can also reach each VFS path through `fuseMount`.
A mount at `/work` therefore typically appears at both `/work` and `/data/work`.
`MountRouterProvider` removes the mount prefix before dispatch to a `VirtualProvider`.
Requests for `/data/work/foo` and `/work/foo` reach that provider with the same relative path.

A provider wrapper such as Corb's `withGlobPolicy` needs no alias handling.
Corb briefly stripped a `/data` prefix inside `normalizeGuestPath` and broke valid paths.
`docs/design.md` §3, "Path aliasing", explains that failure and the correction.

`VirtualProvider` requires `readonly`, `supportsSymlinks`, `supportsWatch`, and
both async **and `*Sync`** variants of `open`, `stat`, `lstat`, `readdir`,
`mkdir`, `rmdir`, `unlink` and `rename`. Optional members: `link`, `readFile`,
`writeFile`, `appendFile`, `exists`, `copyFile`, `realpath`, `access`,
`readlink`, `symlink`, `statfs`, and the `watch*` family. `VirtualFileHandle`
provides `read` / `write` / `stat` / `truncate` / `close` plus sync twins.
`ERRNO` is exported for precise errno control. Extend `VirtualProviderClass`
(read/write) or `ReadonlyVirtualProvider` (sync, read-only).

Built-in providers: `MemoryProvider`, `RealFSProvider`, `ReadonlyProvider`,
`ReadonlyVirtualProvider`, `ShadowProvider`.

```ts
new ShadowProvider(backend, {
  shouldShadow: ({ path }) => path === "/.env" || path.startsWith("/secrets/"),
  writeMode: "deny",            // or "tmpfs"
  denySymlinkBypass: true,      // default; also consults realpath()
  denyWriteErrno: ERRNO.EACCES,
});
```

### Sharp edges

- **`VfsHooks` observe operations.** Both `before` and `after` return `void`.
  Hooks cannot deny or rewrite an operation.
  Use hooks for audit and a provider for enforcement.
- **`createShadowPathPredicate` has no glob support.** It matches exact paths and prefixes.
  The caller must implement glob rules.
- `ShadowProvider` redirects or denies writes.
  It cannot hide a path with `ENOENT` or deny reads.
- **Keep `denySymlinkBypass` enabled.** `ShadowProvider` enables it by default and checks `realpath()` to prevent symlink aliases bypassing rules.
  A provider that checks only the requested path loses this protection.
  `ln -s .env decoy && cat decoy` then bypasses its rules.
- `RealFSProvider` blocks following symlinks that escape the exposed directory.
  It also rejects dangling links.
  It permits `lstat`, `readlink`, and `unlink` on the link entry itself.
- A custom provider mounted at `/` can hide the distribution CA bundle and break TLS.
- **`MAX_RPC_DATA` is 60 KiB.** It caps one VFS operation's payload.
  The cap does not apply to HTTP hooks.
- `vm.checkpoint()` does not capture VFS data.

Host JavaScript enforces VFS policy below the guest kernel's filesystem view.
The guest cannot bypass it through raw syscalls because no real filesystem exists beneath that mount.

---

## 8. Guest images

`gondolin build` consumes a **JSON build config**, not a Dockerfile:

```bash
gondolin build --init-config > build-config.json
gondolin build --config build-config.json --output ./assets
```

An OCI image can supply the root filesystem:

```json
{
  "arch": "aarch64",
  "distro": "alpine",
  "oci": { "image": "docker.io/library/node:22-alpine" }
}
```

OCI support swaps the **root filesystem contents**, not the whole image build
pipeline. Boot artefacts (kernel, initramfs) remain Alpine-derived and the OCI
filesystem is layered on as `rootfs.ext4`. `alpine.rootfsPackages` is ignored
when `oci` is set, and the supplied rootfs must contain `/bin/sh`. Host build
tools required: `cpio`, `lz4`, `e2fsprogs`, and optionally Docker or Podman.

Init hooks: `rootfsInit`, `initramfsInit`, and `rootfsInitExtra`, the last of
which is appended to the rootfs init and runs **before** `sandboxd` starts.
`postBuild.copy` and `postBuild.commands` (run through `/bin/sh -lc` in a build
chroot) inject files.

Gondolin's `/init` runs as PID 1.
It starts `sandboxfs`, `sandboxssh`, `sandboxingress`, and `sandboxd`.
The host control plane requires these processes.
The SDK exposes no supervisor or replacement entrypoint.
Replacing `sandboxd` loses the SDK control plane.
Use `rootfsInitExtra` for boot customisation.

Do **not** put real secrets in the image `env`. It is baked into the image.

### Selecting a custom-built image

`VMOptions` has no `image` field, but image selection needs no environment variable.
Its `sandbox` field takes `SandboxServerOptions`.
The nested `imagePath` accepts an asset directory, a `GuestAssets` object, or an image selector.
Selectors include `name:tag` and build IDs:

```ts
const vm = await VM.create({ sandbox: { imagePath: "corb:0.1.0" } });
```

is sufficient to boot a locally built image. (Risk R17, resolved.)

---

## 9. Ingress

```ts
const ingress = await vm.enableIngress({ listenHost: "127.0.0.1", listenPort: 0 });
vm.setIngressRoutes([{ prefix: "/", port: 8000, stripPrefix: true }]);
```

A host-to-guest **HTTP reverse proxy**, deliberately not a generic port forward.
Routes are stored in `/etc/gondolin/listeners`, longest prefix wins. Hooks:
`isAllowed`, `onRequest`, `onResponse` (header patching: a string or array sets
a header, `null` deletes it). Deny by throwing `IngressRequestBlockedError`.
HTTP/1.1 host-side only. The WebSocket handshake is hookable but opaque after
the 101.

Ingress requires the default `/etc/gondolin` mount. Setting `vfs: null` or
overriding `/etc/gondolin` with a custom mount makes `enableIngress()` fail.

---

## 10. Threat model, and what Gondolin does not give you

Untrusted code runs in a real Linux VM.
Host code under your control mediates the guest's network and persistence.
The guest remains adversarial, and the host enforces policy.

Explicit non-goals: a malicious host. A malicious local user on the same
account.  VM escape and QEMU bugs. Side channels. And **denial of service**.

The SDK adds no hardening inside the guest.
A search of its documentation and shipped package found no `seccomp`, `cgroup`, `apparmor`, `selinux`, or `landlock`.
It also found no `namespace`, `no-new-privs`, `rlimit`, `CAP_SYS`, or `prctl`.
Resource controls consist of the `memory` and `cpus` options plus I/O buffer caps.
The documentation says these do not provide full resource governance.
It assumes a root guest.

Consequences for anything built on top:

- The caller must drop guest privilege.
- The SDK does not contain CPU burn, memory pressure, fork bombs, or disk fill inside the VM.
  Apply resource limits to the host VM process.
- The caller must bound a session's elapsed lifetime.

---

## 11. There is no guest→host RPC, by design

The QEMU documentation explains "Why We Do Not Use Vsock" as a policy choice.
A general guest-to-host socket can accidentally create an unrestricted tunnel.
The design keeps egress policy enforcement on the host.

The host starts four channels: exec control, VFS RPC, SSH forwarding, and ingress forwarding.
`SandboxServer.openTcpStream()` only connects from host to guest loopback.
The types warn against exposing `openIngressStream` as a general port forwarding tool.

For a host callback, return a local response from `onRequest` for a sentinel hostname.
This documented hook carries the full request and response without network traffic.
Vsock is unnecessary.
A VFS side channel instead abuses file operations and encounters the 60 KiB frame cap.

---

## 12. Sharp edges, quick reference

| # | Edge | Consequence |
|---|---|---|
| 1 | No HTTP/2 or HTTP/3 | Clients that negotiate h2 must be pinned to HTTP/1.1 |
| 2 | Terminating MITM TLS, not SNI passthrough | Every guest TLS client needs the injected CA bundle |
| 3 | Node ignores the system CA store | Must set `NODE_EXTRA_CA_CERTS` explicitly for Node guests |
| 4 | `allowedHosts` omitted = allow all.  `[]` = deny all | An undefined config value silently opens egress |
| 5 | `exec` array form does no `$PATH` search | Absolute paths required |
| 6 | No exec timeout, no kill | Build your own watchdog.  `vm.close()` is the only hard stop |
| 7 | `VfsHooks` are observe-only | Enforce in a provider, not a hook |
| 8 | `MAX_RPC_DATA` = 60 KiB | Caps a single VFS operation payload |
| 9 | `createShadowPathPredicate` has no globs | Hand-write the matcher |
| 10 | Custom providers can lose `denySymlinkBypass` | Symlink aliasing defeats path rules |
| 11 | No guest→host RPC | Use an `onRequest` sentinel-host short-circuit |
| 12 | No in-guest hardening at all | Privilege drop is yours.  DoS is an explicit non-goal |
| 13 | SSH egress and mapped TCP bypass HTTP hooks and secrets | Police those paths separately |
| 14 | Every VFS path is aliased under `fuseMount`, but only from the guest's point of view | `MountRouterProvider` dispatches with an already mount-relative path, so a `VirtualProvider`'s own path policy never sees the alias and needs no handling for it |
| 15 | Adding guest packages requires an image rebuild | Alpine-only image builder |
| 16 | `exec` is concurrent, but `vm.fs`'s file ops are not | `readFile`/`writeFile`/`deleteFile` wait for **zero** live execs, so they never complete during a long-running interactive exec |
| 17 | `maxQueuedExecs` defaults to 64, counted session-wide | Past it `exec` fails with `queue_full`. Every attach client draws on the same budget |
| 18 | `vm.close()` rejects every live exec with `server_shutdown` | An un-awaited `vm.exec()` promise becomes an unhandled rejection and, under Node's default, kills the host process |

---

## 13. Risk register

Status values:

- **open**, unresolved. Needs an empirical test or a build decision.
- **closed**, resolved by a decision recorded in [`design.md`](./design.md) or
  by a documented workaround.
- **resolved-by-inspection**, settled by reading the shipped types or docs, with
  no test required.

| # | Risk | Detail | Status |
|---|---|---|---|
| R1 | HTTP/2 to the model API | Gondolin supports HTTP/1.x and TLS interception only, with no HTTP/2 or HTTP/3. Model-provider SDKs commonly negotiate h2, and some agent configurations select a WebSocket transport (supported, but opaque after the 101 handshake). **Closed by M0.1 (2026-08-22):** a real TLS handshake to `api.anthropic.com` from inside a guest completes and negotiates `http/1.1` even though the client offers `h2`. A local chunked-response test confirms the egress mediation delivers streamed chunks incrementally, not buffered. See `spike-results.md` for verbatim evidence. | closed |
| R2 | Exec concurrency with a long-lived interactive process | The docs contradict themselves (§3). The agent's TUI is one long-running `exec`. **Closed by M0.4 (2026-08-30): `exec` does not serialise, and the risk's own proposed mitigation was backwards.** With a long-lived `pty: true`/`stdin: true` exec running (production's `dropcap` -> shell shape), a second `vm.exec()` starts in 5-6ms and runs genuinely in parallel (four concurrent `sleep 3` execs finish in 3013ms, not ~12000ms.  `execPressure()` reads 5). The same holds for a second exec issued from a *separate host process* over `connectToSession()` (13ms end to end, stdout returned). The long exec survives untouched, it accepted input and produced correct output *during* the second exec's session, and neither stream saw a byte of the other's. Cause, read from the shipped 0.12.0 source: `handleExec`'s only queueing branch is against an in-flight **file operation**, never against another exec. The sole limit is `maxQueuedExecs` (default 64, session-wide across all clients, then `code: "queue_full"`). The inversion: it is `vm.fs`'s file operations that serialise, via `waitForExecIdle()`'s wait-for-*zero*-execs, `vm.fs.readFile`/`writeFile`/`deleteFile` can never complete while Pi's TUI exec is alive, so this risk's "`vm.fs` must cover host-side file needs" fallback was the one thing that cannot work. (`vm.fs.stat`/`listDir`/`mkdir`/`access`/`rename` are exec-backed and unaffected.  Corb calls none of the three blocked methods today.) Two secondary corrections: `execPressure()`/`waitForExecIdle()` are **not** on `VM`'s public surface (`private server`.  `vm/core.d.ts` mentions neither), so no design may depend on them. And `vm.close()` rejects every live exec with `server_shutdown`. If the exec promise has no handler, Node's default `--unhandled-rejections=throw` kills the host process. **Consequence for M8.7:** `corb attach` is viable, but only as a *new* interactive shell in the running session, the control protocol has no "list execs" and no "join exec N" (`ClientMessage` is a closed union), `SessionIpcServer` gives each client a disjoint request-id space, and addressing the owner's exec id from an attach client is refused with `unknown_id`. Rejoining or mirroring Pi's TUI is not expressible in 0.12.0. See `spike-results.md` M0.4 for verbatim evidence. | closed |
| R3 | MITM CA and Node | **Closed by M0.2 (2026-08-22):** HTTPS from node, curl, git and go all pass inside the guest, and, surprisingly, none needs an explicit CA env var from the host application: Gondolin's own guest init (`init-scripts.js`) unconditionally exports `SSL_CERT_FILE`/`CURL_CA_BUNDLE`/`REQUESTS_CA_BUNDLE`/`NODE_EXTRA_CA_CERTS` for every guest process regardless of `VM.create()`/`vm.exec()` config. Git and go inherit trust via `SSL_CERT_FILE` with no tool-specific var needed. A genuine negative control (all CA vars forced to a bad path) reproduces a clean cert-trust failure per tool. This confirms causality. See `spike-results.md` for verbatim evidence. **Addendum (see R20):** this spike ran as root, never through `dropcap`'s privilege drop, `NODE_EXTRA_CA_CERTS`'s specific default (`/etc/gondolin/mitm/ca.crt`) turned out to be unreadable by a dropped-privilege `agent` uid, a gap this closure did not have the scope to catch. | closed |
| R4 | OCI rootfs viability | OCI swaps the rootfs only. Boot stays Alpine-derived. The rootfs must contain `/bin/sh`. Confirm the agent and any toolchains work in the resulting rootfs, and that `arch` matches the host (aarch64 on Apple Silicon). | open |
| R5 | VFS uid/gid reporting | Can a provider report `uid`/`gid` in `stat` such that the non-root guest user appears to own the workspace? If yes, no `/etc/passwd` fixup is needed at all. If no, an equivalent fixup belongs in `rootfsInitExtra`. **Closed (2026-08-22):** irrelevant either way, the question this risk asked no longer matters, because `stat`-level uid/gid reporting was never the actual blocker. The real blocker, found empirically: `sandboxfs` mounts every `vfs.mounts` path with a hardcoded FUSE option string (`mountFuse` in `guest/src/sandboxfs/main.zig`: `fd={d},rootmode=40000,user_id=0,group_id=0,default_permissions`) with **no `allow_other`**, so per plain Linux FUSE semantics only the mounting uid (0) can touch the mount at all. Reporting a friendlier `uid`/`gid` in `stat` responses cannot help, since the kernel FUSE layer rejects a non-owning uid's request before any inode metadata (including a provider-supplied `uid`/`gid`) is even consulted. No upstream config surface exists to add `allow_other` (Gondolin issue #76, closed unanswered against 0.12.0). Fixed by re-exporting the raw mount through `bindfs` (built from source. Not packaged for any current Alpine stable branch) with the workspace uid/gid squashed via `--force-user`/`--force-group` and `allow_other` on by bindfs's own default, see R18 and `image/overlay/init-extra.sh`. | closed |
| R6 | VFS performance under a real build | A JS-implemented FUSE-over-RPC layer with a 60 KiB frame cap is a genuine risk on a large source tree. Benchmark a full build and a recursive grep. If too slow, use a VFS mount only for policy-sensitive trees and a checkpointed disk for scratch. **Re-quantified for the bindfs re-export (2026-08-23). These results replace the fuse-overlayfs numbers below:** the R18 re-export still adds a second FUSE hop (agent → `bindfs` → the untouched `sandboxfs` mount → virtio RPC → host) for every guest workspace operation, but the tool doing that hop changed from `fuse-overlayfs` to `bindfs`. Measured in a real booted `corb:0.1.0` VM against the same-shaped benchmark as before, an 800-file/3.2 MiB synthetic tree, 5 runs per path after a per-path warm-up, single-hop raw mount vs double-hop public mount, with one methodology fix: bulk `rm -rf` immediately after a bulk create hit a genuine readdir/unlink race in `sandboxfs` itself (reproduced directly against the raw mount, nothing to do with bindfs, busybox `rm -rf` returns `ENOTEMPTY` mid-sweep), so each write-loop run now uses a fresh, uniquely-named directory instead of deleting between runs, and cleanup is untimed and run after all measurements. Results: `find -type f` averaged 371.6ms raw vs 426.4ms through the re-export (**1.15x**).  `grep -rl` averaged 844.6ms raw vs 1484.4ms through the re-export (**1.76x**). The 200×1 KiB sequential write loop averaged 443.0ms raw vs 639.4ms through the re-export (**1.44x**, that is ~2.21ms/file raw vs ~3.20ms/file through the re-export). Caveat: raw was measured before public in this run, so page-cache warming can inflate the find/grep ratios somewhat in the re-export's disfavor (the write loop touches fresh data each run and is less exposed to this). Even discounting that, all three phases now show a real but modest cost, a marked improvement over fuse-overlayfs's ~3.0x write-loop penalty (696ms vs 2086ms average, ~3.5ms/file raw vs ~10.4ms/file through the re-export) with no workdir round-trip on every create to explain the difference. Still open: a benchmark against a real build (for example `go build`/`npm install`/`tsc`) rather than a synthetic file tree, and the mitigation this risk already proposed (VFS mount only for policy-sensitive trees, checkpointed disk for scratch) has not been evaluated against the added re-export cost specifically. | open |
| R7 | Exec timeout and kill | The SDK provides neither (§3). Anything beyond the single foreground process needs a bespoke watchdog. | open |
| R8 | No glob support in the shadow predicate | `createShadowPathPredicate` is exact-path and prefix only. Corb needs `**/.env*`-shaped rules. Addressed by the glob policy provider in `design.md`. | closed |
| R9 | Git-over-SSH warnings | The guest-facing proxy host key lacks post-quantum KEX, so OpenSSH warns on every operation. Apply the documented `GIT_SSH_COMMAND` workaround so the noise does not confuse the agent. | closed |
| R10 | Ingress depends on `/etc/gondolin` | `vfs: null` or a custom `/etc/gondolin` mount makes `enableIngress()` fail. **Closed by M9.4 (2026-08-30):** ingress is adopted (`corb run --expose PORT`, `docs/design.md`'s ingress subsection) and verified against a real booted `corb:0.1.0` VM, `test/e2e/ingress.e2e.ts` boots a VM with `vfs` left unset (so the SDK's default `/etc/gondolin` mount is intact, confirmed by the earlier resolved-by-inspection reasoning still holding), starts a real HTTP server inside the guest, calls `vm.enableIngress()`/`vm.setIngressRoutes()`, and a real host HTTP GET through the resulting `IngressAccess.url` reaches the guest server and returns its actual response body. `src/vm/session.ts`'s production wiring (`vfs: { mounts: vfsMounts }`, none of which target `/etc/gondolin`) was independently checked against the same constraint. | closed |
| R11 | Project maturity | 0.12.0, self-described as early, with breaking reshapes as recently as 0.6.0. Pin exactly and expect churn on upgrade. | open |
| R12 | VFS write semantics versus guest uid | The assumption is that writes go over RPC to a provider in the host process, which performs the real write as the host user, so guest-kernel DAC against a guest uid is not the enforcement point. This is load-bearing for the design. Test it rather than assume it. **Closed (2026-08-22):** the assumption about where writes are ultimately performed (host process, as the host user, over RPC) was never wrong, but it was insufficient on its own: the guest-kernel FUSE layer gates the RPC round-trip itself on the *mounting* uid, before any provider or host-side DAC logic ever runs. `sandboxfs`'s hardcoded `user_id=0,group_id=0,default_permissions` (see R5) means a `vfs.mounts` path mounted directly is unreachable by any guest uid other than 0, `dropcap`'s drop to uid 1000 left the agent with zero filesystem access, verified empirically (every `stat`/`open`/write from uid 1000 against a direct mount returned `EACCES` at the kernel FUSE layer). Fixed by R18: the raw mount stays exactly as `sandboxfs` produces it (untouched, still root-only), and a `bindfs` re-export in front of it is what the agent actually talks to. | closed |
| R13 | `VirtualProviderClass` defaults | Confirm that extending it and overriding a subset of methods delegates the rest correctly, before relying on partial overrides in a policy provider. | open |
| R14 | Sentinel-host round-trip latency | A host round-trip on every gated command adds latency. Measure it. If it is annoying, cache by payload hash within a session. | open |
| R15 | Cgroup attach timing on Linux | Confirm `vm.getHostPid()` returns a stable PID early enough to attach a cgroup before the guest can do meaningful work. **Closed by M8.3 (2026-08-30):** made moot rather than answered, the attach was never attempted. `corb run` re-execs itself under `systemd-run --user --scope` with the `vm.limits` properties applied *before* `VM.create()` runs (`src/vm/scope.ts`, `docs/design.md` §7), so the limit already covers the whole process tree by the time QEMU exists and no pid is ever observed. There is no window to measure and nothing about `vm.getHostPid()`'s timing left to depend on. | closed |
| R16 | Reading a request body inside `onRequest` | `HttpHooks.onRequest` is typed `(request: Request) => Promise<Request \| Response \| void> \| Request \| Response \| void` and receives a full WHATWG `Request`. The "request body is always null" caveat in the SDK's JSDoc is attached to `isRequestAllowed`, not to `onRequest`. A separate `ON_REQUEST_EARLY_POLICY_SAFE` marker symbol exists specifically to opt a hook into pre-body policy checks. Awaiting `req.json()` inside `onRequest` is sound. | resolved-by-inspection (0.12.0 .d.ts) |
| R17 | Selecting a custom-built guest image | `VMOptions` has no `image` field, but `VMOptions.sandbox` is a `SandboxServerOptions` whose `imagePath` accepts an asset directory path, an explicit `GuestAssets` object, or an image selector string (`name:tag` or a build id). `VM.create({ sandbox: { imagePath: "corb:0.1.0" } })` works. No environment-variable juggling is needed. | resolved-by-inspection (0.12.0 .d.ts) |
| R18 | Workspace re-export mount (`bindfs`, built from source) is now a permanent, load-bearing part of the boot sequence | Closes R5/R12. Without it, `dropcap`'s privilege drop to uid 1000 leaves the agent with **no filesystem access whatsoever**, every workspace `stat`/`open`/write returns `EACCES` at the guest kernel FUSE layer, before any host-side policy (VFS or otherwise) is ever consulted. `src/vm/session.ts` mounts the host workspace `RealFSProvider` at an internal-only guest path (`WORKSPACE_RAW_GUEST_PATH = "/mnt/corb-raw/work"`), never referenced again after boot.  `image/overlay/init-extra.sh` (wired via `corb-image.json`'s `init.rootfsInitExtra`, confirmed by reading `injectBeforeSandboxdExec` to run after `sandboxfs` mounts and binds every `vfs.mounts` path, and before `sandboxd` starts accepting exec requests) re-exports it at the public `WORKSPACE_GUEST_PATH = "/work"` via `bindfs --force-user=<uid> --force-group=<gid> <raw> <public>`, uid/gid read from `/etc/corb/image.json` (never hardcoded. This follows `image/verify.ts`'s convention for the same values), `allow_other` left implicit (bindfs's own default.  `--no-allow-other` is the flag that turns it off, and this mount always runs as root during boot regardless). This is the same tier of importance as `dropcap` itself: the two together are what make the agent's process tree both unprivileged *and* able to do anything at all. Verified in a real booted `corb:0.1.0` VM: `dropcap`-dropped uid 1000 can `stat`/read/write through `/work`, and `ls -ln` shows files squashed to `1000:1000`. A host-created file is visible in the guest. A guest-written file (including through `mkdir`/`mv`/`rm`, which exercise the raw `sandboxfs` mount's more exotic FUSE opcodes) round-trips back to the host directory with the real host user as owner. **Package choice, `bindfs`, built from source, not `fuse-overlayfs` from `community` (supersedes an earlier version of this fix):** `bindfs` is purpose-built for this exact job (`--force-user`/`--force-group`/`allow_other`, no overlay semantics at all, a straight passthrough, not a copy-up filesystem), a better fit than the overlay tool a previous iteration of this fix used. It does not exist in any current Alpine stable branch, checked 3.22, 3.23 (the version this project pins) and 3.24 via the aports git tree (`git.alpinelinux.org/aports`, branch `<version>-stable`). None carry a `bindfs` APKBUILD outside `testing/`, and Alpine only *publishes* built binary packages for `testing` against `edge`, never against a stable release branch. It lands only in `edge/testing` (confirmed by reading `testing/bindfs/APKBUILD` directly from the aports tree), which this project avoids as an ongoing provenance/trust cost for a security-relevant boot-time binary, and doubly so for `edge/testing` specifically, a tier below even `edge/community`. Corb instead builds it from source at image-build time. **Build recipe, verified independently rather than trusted from a prior run:** source is a plain tarball, `https://bindfs.org/downloads/bindfs-1.18.4.tar.gz` (there is no GitHub Releases entry for this project, the aports `APKBUILD` fetches from bindfs.org too). Version and sha512 checksum were re-fetched live from Alpine's own (source-only, unshipped-as-a-binary) build recipe at `https://git.alpinelinux.org/aports/plain/testing/bindfs/APKBUILD` (the `gitlab.alpinelinux.org` mirror this was originally sourced from now sits behind a bot-detection JS challenge.  `git.alpinelinux.org`'s cgit mirror serves the same file unauthenticated) and matched what was assumed going in: `pkgver=1.18.4`, `sha512sums` for `bindfs-1.18.4.tar.gz` = `1fedfcd082980180ccdd684478cc5308f4ea3fa541af12b5aef0b75fb0ec5b285009c4b783fc3cd5550505a83baf015e243f88eb322540d0f82e1952babc799a`. The APKBUILD applies one patch, `musl-getmntent-issue.patch`. Fetched and read directly, it touches only `tests/common.rb` (a Ruby test-suite helper that shells out to `fusermount3`/`fusermount` to unmount during test teardown. The patch skips that and unmounts with plain `umount` instead) and Alpine's own recipe already sets `options="!check"` (tests never run), so the patch is irrelevant to a build that, like Alpine's own, does not run `make check`. Not applied. Build dependencies `build-base`, `linux-headers`, `fuse3-dev` are all in Alpine 3.23 stable (confirmed by installing them in a real `alpine:3.23.0` container). The build itself is the standard `./configure --prefix=/usr --sysconfdir=/etc --mandir=/usr/share/man --localstatedir=/var && make && make install`, unpatched, and it compiled and installed cleanly first try in a real `alpine:3.23.0` container and again inside the actual `corb image build` container. **This is more supply-chain-controlled than an apk-managed package is, not less:** Corb pins the exact source tarball URL and a checksum it verifies itself (`sha512sum -c` against a hardcoded value in `corb-image.json`, build-breaking on mismatch), rather than trusting whatever bytes a `community` or `edge` mirror happens to serve for a given package name at build time. The checksum's provenance is Alpine's own aports tree, not an ad hoc value. Re-deriving it from that tree (rather than reusing a previously recorded number blindly) is exactly what was done here, and is what must happen again before any future version bump. **Runtime dependencies, determined empirically rather than assumed:** `ldd /usr/bin/bindfs` after a real build showed exactly one non-libc dependency, `libfuse3.so.4`, provided by the `fuse3-libs` package. Installing only `fuse3-dev` (the build-time header/pkg-config package) pulls in `fuse3-libs` and `pkgconf` but **not** the main `fuse3` package, confirmed directly (`apk info -e fuse3` reports absent after `apk add fuse3-dev` alone). That matters because the main `fuse3` package is what ships `/usr/bin/fusermount3`, built with Alpine's own `options="suid"` (that is installed SUID-root), the exact binary the previous `fuse-overlayfs` implementation had to `chmod u-s,g-s` at build time to keep it out of the live SUID/SGID set. With `bindfs`, that binary is never installed in the first place, which is a strictly better position than stripping its bit: there is no bit to strip. If a future Alpine bump changes fuse3's default permissions, this binary remains absent. A human or the `suid` gate has one fewer file to check. Confirmed the mount does not need `fusermount3` even functionally, not by absence of the dependency edge: a real `alpine:3.23.0` container with `fusermount3` verified absent from the filesystem entirely (not merely non-SUID) still mounted, read, and wrote successfully via `bindfs --force-user=1000 --force-group=1000` run as root, consistent with libfuse3 calling `mount(2)` directly when the calling process is already root (which the boot-time re-export always is) rather than shelling out to the setuid helper, which exists specifically to let *non-root* callers mount. The `suid-allowlist.txt` gate is unaffected either way: it was already empty (0 entries) before this change and remains empty after it. Stripping a bit neutralized `fuse-overlayfs`'s SUID cost, `bindfs`'s SUID cost never existed to begin with, and both end at the same "0 live SUID/SGID binaries" outcome the `suid` gate asserts. **A second, non-obvious runtime-dependency finding, specific to how this had to be built (not a bindfs property):** `corb-image.json`'s `postBuild.commands` run real `apk add`/`apk del` inside the rootfs *after* `alpine.rootfsPackages` has already been installed into it, but `rootfsPackages` installation uses Gondolin's own from-scratch package fetcher (`installPackages` in the SDK's `alpine/packages.js`), which downloads and extracts `.apk` tarballs directly without ever writing to `/lib/apk/db/installed`. So from the real `apk` binary's point of view (used for the first time only once `postBuild.commands` runs), no package installed via `rootfsPackages` exists in the database. These packages include `nodejs` and its linked libraries `libstdc++`, `libgcc`, and `zstd-libs`. `apk add build-base linux-headers fuse3-dev` (to build bindfs) pulls in real, apk-tracked copies of `libstdc++`, `libgcc` and `zstd-libs` as transitive build dependencies (gcc needs the first two to run. The toolchain needs the third). A plain `apk del build-base linux-headers fuse3-dev` afterward then orphan-removes all three, because apk's dependency solver has no record of `nodejs` needing them, and promptly deletes the files nodejs (silently, from apk's perspective) depends on. This reproduced concretely: `npm i -g …` failed with `Error relocating /usr/bin/node: … symbol not found` (first for ICU/ada C++ symbols after `libstdc++`/`libgcc` were purged, then for `ZSTD_*` symbols after `zstd-libs` was purged too, once the first fix was in but before this one was found). The fix is the same "pin it into apk's world before deleting its puller" trick already used for `fuse3-libs`: `apk add --no-cache build-base linux-headers fuse3-dev fuse3-libs libstdc++ libgcc zstd-libs` explicitly names all four runtime libraries alongside the actual build toolchain, so `apk del build-base linux-headers fuse3-dev` (which never names them) leaves them installed. Confirmed empirically in isolation (a plain `alpine:3.23.0` container: `apk add fuse3-dev` alone does not pull `fuse3-libs` into apk's del-safe world unless added explicitly. The same pattern holds for the other three) and then end to end (a full `corb image build` run with `npm i -g @earendil-works/pi-coding-agent`, `image/verify.ts`'s `pi` gate, and every other gate). This is not a property of `bindfs` or of Corb's design. It is a real interaction between Gondolin's own two-tier package-installation model (untracked bulk rootfs packages, real `apk` for anything in `postBuild.commands`) and any future `postBuild.commands` step that does its own `apk add`/`apk del`, worth remembering for whoever touches this file next, regardless of what they are adding. **No workdir artifact, a real improvement, not a swap:** `bindfs` has no workdir concept at all, because it is not a copy-up filesystem, it never needs scratch space on the same device as the mount. The previous `fuse-overlayfs` implementation's `.corb-fuse-overlay-workdir` directory, visible on the host disk inside every workspace directory Corb mounted, is gone with this change, not relocated or hidden. Confirmed on a real booted VM: after mounting, reading, writing, and exercising `mkdir`/`mv`/`rm` through the public mount, `find <host-dir> -mindepth 1` on the host side shows only the files the test actually created, no corb-authored artifact of any kind. **Quantified performance cost:** see R6 for the current, bindfs-specific benchmark numbers (superseding the earlier `fuse-overlayfs` numbers there). | closed |
| R19 | Does `vm.checkpoint()`/`resume()` give `corb run` a faster warm start? | **Closed by M9.5 (2026-08-30): no.** `resume()` calls the exact same `createVm()` codepath `VM.create()` does, same kernel, initramfs, `/init`, `sandboxd`, `sandboxfs`, `rootfsInitExtra` (bindfs re-export), every time. There is no partial/fast-path boot for a resumed VM.  "no memory snapshots" (already stated in §2) turns out to mean the guest reboots fully from scratch regardless. Measured against the real tagged `corb:0.1.0` image: two cold boots and one checkpoint-then-resume, timed `VM.create()`/`resume()` call to first successful `vm.exec()`, all landed at ~33.5s within noise, cross-checked against M0.4's own independent `~33s` boot-warmup figure, recorded for an unrelated reason months earlier. Separately, even as a pure disk-state fork (ignoring boot time), Corb's architecture leaves checkpoint/resume little to usefully capture: everything session-relevant lives behind a VFS mount (never captured by a checkpoint), and what *is* on the persistent disk is baked in at image-build time already reused for free via `sandbox.imagePath`. See `docs/spike-results.md` M9.5 for the full write-up and evidence. **DAR-15 timing correction (2026-10-25):** an omitted gate mount caused about 30 seconds of init polling. A controlled stock boot takes 2.96 seconds with that mount and 33.66 seconds without it. Resume still performs a full boot. | closed |
| R20 | `NODE_EXTRA_CA_CERTS` is unreadable by the `agent` uid, R3 tested this only as root | R3 closed "does Node need an explicit CA env var" without ever exercising it through `dropcap`'s privilege drop. Found later, dogfooding a real `corb run` session, as a startup warning from Pi (a Node program): `Warning: Ignoring extra certs from /etc/gondolin/mitm/ca.crt, load failed: ... Permission denied`. **Root cause, confirmed empirically in a real booted `corb:0.1.0` VM:** Gondolin's own `setup_mitm_ca` (`alpine/init-scripts.js`) exports `NODE_EXTRA_CA_CERTS` pointed at `/etc/gondolin/mitm/ca.crt`, the raw file inside Gondolin's automatic MITM-CA mount (`vm/mitm-vfs.js`'s `createMitmCaProvider`, wired in automatically whenever `VM.create()` has networking enabled and nothing else already mounts that path), which is the exact same root-only `sandboxfs` mount class R5/R12/R18 already found and fixed for corb's own workspace/gate-config mounts (`fd=…,rootmode=40000,user_id=0,group_id=0,default_permissions`, no `allow_other`). `dropcap 1000 1000 cat /etc/gondolin/mitm/ca.crt` returns `Permission denied`.  `dropcap 1000 1000 cat /run/gondolin/ca-certificates.crt` (the same script's own merged bundle, written to a plain `0644` file on `/run`'s tmpfs, which `SSL_CERT_FILE`/`CURL_CA_BUNDLE`/`REQUESTS_CA_BUNDLE` already correctly use) reads all 181693 bytes cleanly, the merged bundle already contains the MITM CA, baked in during the same boot-time step. **Consequence when it fires:** silent, not fatal, Node falls back to its own bundled public root store, which is why the real Anthropic/OpenRouter traffic in the sessions that surfaced this kept working (a real, publicly-signed cert validates fine against Node's bundled roots with no MITM involved). It only breaks a connection that uses the MITM for content inspection (for example a future extension of the `git`-over-HTTPS or content-check gates), Node then cannot validate Gondolin's re-signed leaf certificate. **Fix:** unlike R18 (a directory bindfs re-export, since corb owns that mount request), this mount is Gondolin's own automatic one, not something `src/vm/session.ts` configures, so the fix is simpler: `buildGuestEnv()` (`src/vm/session.ts`) now explicitly overrides `NODE_EXTRA_CA_CERTS` to `/run/gondolin/ca-certificates.crt`. This matches the other three CA vars it already leaves to Gondolin's default. No new mount, no `init-extra.sh` change. | closed |
| R21 | Gondolin's HTTP relay corrupts large compressed responses, strips `content-encoding` without guaranteeing the body is actually decompressed | Found dogfooding: Pi's `/model` catalog refresh (`https://pi.dev/api/models/providers/<id>`, a ~162 KiB `content-encoding: gzip` response) consistently failed with `Could not refresh <provider>; showing cached models.` even after the host itself was correctly allowlisted and confirmed reachable (real `200`s in the audit log). Root cause, isolated by running `pi update --models --force` directly in a real booted `corb:0.1.0` VM (bypassing the interactive TUI entirely) and reading the exact error: `Error: Could not refresh model catalogs: openrouter: Unexpected token '(', "(<binary garbage>"... is not valid JSON`, the response body handed to the guest's `fetch()`/`.json()` is still raw gzip bytes. Read from the installed SDK's own source (`qemu/http.js`, the same file R20 touches): once an upstream response arrives with a `content-encoding` header, Gondolin's relay unconditionally deletes both `content-encoding` and `content-length` from what it forwards to the guest, on the assumption that the body it relays is already decompressed, an assumption that does not hold for at least this real, reproducible case. Confirmed the origin genuinely does compress by default (`curl -D- https://pi.dev/api/models/providers/openrouter` shows `content-encoding: gzip`) and genuinely honors a plain client request to skip it (`curl -H 'accept-encoding: identity' ...` gets an uncompressed, correctly-sized body back with no `content-encoding` header at all), so the origin is not the problem, Gondolin's relay is. **Fix, corb-side (no Gondolin patch available):** `forceIdentityAcceptEncoding()` (`src/vm/egress.ts`), wired as an unconditional wrapper around `buildEgressConfig`'s `onRequest` (outside `composeOnRequest`'s policy hooks, none of which need to rewrite a request), sets `Accept-Encoding: identity` on every outbound guest request, so no upstream ever has a reason to compress a response in the first place. This avoids the relay bug before it corrupts output. Verified in a real booted VM: the identical `pi update --models --force` invocation that reliably reproduced `Unexpected token '(' ... is not valid JSON` reports `Model catalogs refreshed` once this header is forced, with `openrouter.ai`'s own (uncompressed, small-response) POST traffic unaffected either way. | closed |
| R22 | Workspace toolchain disk layers | DAR-15 confirms flat qemu checkpoints with working Go, PostgreSQL, mounts, egress, ingress, and isolated root writes. Package triggers restore `su`, so builds must repeat removals and check protected base hashes. A moved backing path changes the checkpoint hash in place, so builds must serialize rebases and update local metadata. The stock Git TLS gate still fails. See `docs/spike-results.md` DAR-15 for limits and evidence. | go with limits, production work remains |
| R23 | Missing and stale APK database records | Gondolin unpacks rootfs packages without registering them. DAR-15 confirms 13 missing non-kernel capabilities and verifies that registration covers them. It still leaves OpenSSL 3.5.4 database records over signed 3.5.9 bytes and changes the SSH provider. Later tool installs preserve protected files after cleanup. Base registration and version reconciliation need a production decision, as described in `docs/spike-results.md` DAR-15. | open |


## DAR-23 production composition notes

The DAR-15/DAR-16 measurements above remain historical spike evidence.
Production uses authenticated input graphs and real per-base composition, rather than installed-state deltas.
The coherent base `8d1ad38c-602a-50b2-a6b4-247a2b6824bc` passed package coherence and all seven production gates.

A real `tree=2.2.1-r0` composition added only tree while retaining its existing musl provider.
A complete Go 1.27.3 payload passed the same gates and two sequential uid-1000 test/build/run workloads.
The source-controlled serial lifecycle tests repeat these paths with private state and failure controls.
Remote HTTPS registry/auth acceptance and packaged Redis startup remain DAR-21 work.

Source details that constrain production:

- A live checkpoint retains builder clone options. Corb reloads stored checkpoint bytes and supplies complete verifier or run options.
- The SDK trailer loader checks safe integers and file bounds but has no small metadata cap. Corb limits the trailer to 64 KiB and requires a regular non-symlink file first.
- The SDK compares resolved backing path spelling before rebasing in place. Corb requires the exact canonical direct backing before SDK resume.
- The seven gates set their own base PATH. Corb separately checks the complete SDK PATH and supplies it to Pi.
- APK 3.0.8 recursive fetch ignores installed state and conflicts. Corb separately simulates the actual add against the base.
- Bare signed hooks do not inherit parent APK options. Corb supplies temporary frozen default config and proves a sanitized child query uses it.
- APK local repository URLs append the architecture. The read-only repository layout retains that directory.
- Installed npm packages ship compiled JavaScript. The single verifier lives in `src/image` and compiles to `dist/image`. Checkout-only image files are thin bridges.
- ORAS 1.3.5 blob fetch needs an explicit output option. Its localhost default also permits HTTP. Corb forces false-valued plain-HTTP options on remote sides.

Canonical base assets and refs stay unchanged during tests. Checkpoints are disk caches and resume through a full boot.
See [the sharing guide](layers.md) for exact public interfaces and boundaries.

The [production validation report](layer-validation.md) records final image/input/generation identities, measured tests, failure recovery and cleanup.
It keeps source mismatches and unverified remote/service cases separate from the historical spike evidence.
