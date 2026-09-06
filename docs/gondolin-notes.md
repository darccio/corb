# Gondolin SDK notes

What is true about the Gondolin micro-VM SDK, as verified against a specific
version. Corb builds on this SDK, so this file is the ground truth Corb's
design assumes. It changes when Gondolin releases; the design in
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

The project describes itself as early. It has had breaking reshapes in recent
minor releases (the WHATWG-style hook signatures landed in 0.6.0). **Pin the
version exactly** in `package.json` — no caret, no tilde — and treat a version
bump as a change that needs the risk register below re-walked.

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
| `sandbox` | `SandboxServerOptions`. Carries `imagePath` — see [§8](#8-guest-images). |
| `rootfs` | `{ mode?: "readonly" \| "memory" \| "cow", size? }` |
| `autoStart` | Default `true` |
| `fetch` | Custom fetch implementation for egress |
| `httpHooks` | From `createHttpHooks()` — see [§4](#4-network-egress-hooks-dns) |
| `dns` | `{ mode, syntheticHostMapping }` |
| `ssh` | `SshOptions` — see [§6](#6-ssh-egress) |
| `tcp` | Mapped raw TCP escape hatch |
| `maxHttpBodyBytes`, `maxHttpResponseBodyBytes` | Request/response body caps |
| `allowWebSockets` | Default `true` |
| `vfs` | `{ mounts, hooks, fuseMount }` — see [§7](#7-vfs-providers) |
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
| `string` | Run through a login shell, i.e. `["/bin/sh", "-lc", cmd]` |
| `string[]` | Direct exec. **No `$PATH` search — absolute paths required.** |

`ExecOptions`: `argv`, `env`, `cwd`, `stdin`, `pty`, `encoding`, `signal`,
`stdout` / `stderr` (`"buffer" \| "pipe" \| "inherit" \| "ignore" \| WritableStream`),
`windowBytes`, `buffer`.

`ExecResult` is **always returned**; a non-zero exit does not throw. Fields:
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

- **No exec timeout and no kill.** `ExecOptions` has no timeout field. The only
  lever is an `AbortSignal`, and aborting rejects the local promise without
  guaranteeing the guest process actually dies. There is no `sendSignal` or
  `kill` anywhere in the callback surface. Any timeout-and-terminate behaviour
  is yours to build, and the only reliable termination primitive is
  `vm.close()`.
- **Concurrency is documented inconsistently — and measurement settled it in
  favour of the permissive page.** One page says the guest runs one command at
  a time and that a long-running `exec` blocks further exec requests; another
  says each attached client gets an independent command channel with no
  cross-talk. **Measured (M0.4, 2026-08-30, risk R2): `exec` does not
  serialise.** A second `exec` issued alongside a long-lived `pty: true` exec
  starts in 5-6ms and runs genuinely in parallel (four concurrent `sleep 3`
  execs complete in 3013ms, not ~12000ms), from the same host process and from
  a separate one over `connectToSession()`; the first exec keeps accepting
  input and producing correct output throughout, with no cross-talk in either
  direction. The only queueing branch in `handleExec` is against an in-flight
  **file operation**, not against other execs. The one real limit is
  `SandboxServerOptions.maxQueuedExecs`, default 64, counted session-wide
  across every connected client; past it, `exec` is refused with
  `code: "queue_full"` rather than queued.
- **A live `exec` does block `vm.fs`'s file operations, though.** That is what
  `waitForExecIdle()` is for, and its only three callers are
  `readGuestFileStream`, `writeGuestFile` and `deleteGuestFile` — i.e.
  `vm.fs.readFile`, `vm.fs.writeFile` and `vm.fs.deleteFile`. They wait for
  **zero** live execs, so with a long-running interactive exec they never
  complete. `vm.fs.stat`/`listDir`/`mkdir`/`access`/`rename` are implemented
  as execs and are unaffected. See risk R2 and `spike-results.md` M0.4.
- **`execPressure()` and `waitForExecIdle()` are not reachable from `VM`.**
  They live on `SandboxServerOps`, which `VM` holds in a `private server`
  field and never re-exposes (`vm/core.d.ts` mentions neither). No host code
  can call them; do not design a "is the session busy?" check around either.

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

- **`allowedHosts` sentinels are asymmetric.** Omitting the field means **allow
  all**. Passing an explicit empty array `[]` means **deny all**. There is no
  safe default here; always set it explicitly, and never build it from a
  possibly-undefined config value.
- **`allowedHosts` cannot express IP or CIDR policy.** It matches hostnames with
  wildcards. Use `isIpAllowed` for address-shaped policy.
- `blockInternalRanges` (default true) covers 127/8, 10/8, 172.16/12,
  192.168/16, 169.254/16 and 100.64/10, plus IPv6 loopback, link-local and ULA.
- **TLS is terminating MITM, not SNI passthrough.** The host reads the
  ClientHello, mints a leaf certificate from a local CA, decrypts, and re-issues
  the connection upstream. The CA lives at `~/.cache/gondolin/ssl`, is injected
  into the guest at `/etc/gondolin/mitm/ca.crt`, and a merged bundle is placed at
  `/run/gondolin/ca-certificates.crt`. `mitmCertDir` isolates it per run. The CA
  private key is a sensitive host asset.
- **DNS is mediated and is not the policy input.** The guest resolves names, but
  those answers are largely disregarded for policy: the host enforces against
  the HTTP `Host` header and performs its own resolution, which is what defeats
  DNS rebinding. Modes are `"open" | "trusted" | "synthetic"`, default
  `synthetic`. Only UDP/53 is handled; **all other UDP is dropped**.
- `onRequest` may return a synthetic `Response` to short-circuit the request.
  Doing so skips upstream DNS and IP checks and skips `onResponse` entirely.
  This is the sanctioned mechanism for a host-side callback (see [§11](#11-there-is-no-guesthost-rpc-by-design)).
- **Secrets may already be expanded by the time `onRequest` runs.** Do not log
  request headers or URLs from inside a hook.
- Non-HTTP flows are sniffed and classified as `http`, `tls` or `ssh`. Anything
  else is denied as `unknown-protocol`. HTTP `CONNECT` is denied.
- **No HTTP/2 and no HTTP/3.** Only HTTP/1.x over plain TCP and HTTPS via the
  TLS interception path. No QUIC, no WebRTC. WebSockets are supported but opaque
  after the 101 handshake. Keep-alive weakens the rebinding protection.
- Guest LAN addressing is fixed: gateway `192.168.127.1`, guest
  `192.168.127.3/24`.
- Escape hatch: `tcp.hosts` mapped TCP gives a raw tunnel (requires
  `dns.mode: "synthetic"` with `syntheticHostMapping: "per-host"`). It bypasses
  the HTTP hooks **and** secret substitution, so anything reached this way sees
  real credentials if you put them in the guest.

An honest limitation stated by the SDK's own docs: the network layer exists to
prevent *unexpected* egress destinations and limit protocol abuse. It does not
prevent exfiltration to a destination you have allowed.

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
| `Authorization: Basic` / `Proxy-Authorization: Basic` | yes — decoded, replaced, re-encoded |
| URL query string | only with `replaceSecretsInQuery: true` |
| Request body | **no** |
| URL path | **no** |
| Response content | **no** |

The guarantee is that the guest cannot read the real value from its process
environment, its disk, or its memory, because the real value never enters the
VM. The stated caveat is that an allowed server which echoes request headers
back in a response defeats this.

Placeholder modes are `"shared"` (default) and `"unique"`; custom shapes come
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
post-quantum key exchange, so modern OpenSSH clients print a warning; the docs
give a `GIT_SSH_COMMAND` workaround to suppress it.

Note that SSH egress, like mapped TCP, bypasses the HTTP hooks and secret
substitution — `ssh.execPolicy` is the enforcement point on that path.

Separately, `vm.enableSsh()` is **host to guest** debug access. It mints an
ephemeral Ed25519 key, runs guest sshd on loopback only, and explicitly disables
agent forwarding and port forwarding at both ends. It defaults to `user: "root"`;
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

Routing is longest-matching-prefix. Note the aliasing: from the guest's own
point of view, every VFS path is *also* reachable under `fuseMount`, so a
mount at `/work` typically appears at both `/work` and `/data/work`. This does
**not**, however, mean a `VirtualProvider`'s own methods ever see both
spellings: `MountRouterProvider` is the thing that dispatches a FUSE request
to the matching mount's provider, and it does so with the path already made
relative to that mount — a request that arrived at the guest kernel as
`/data/work/foo` reaches the provider the same way one that arrived as
`/work/foo` does. Path-shaped policy written *inside* a `VirtualProvider` (or
a wrapper around one, e.g. corb's `withGlobPolicy`) therefore has nothing to
account for here; corb learned this the hard way after `normalizeGuestPath`
briefly stripped a `/data` prefix defensively — see `docs/design.md` §3 "Path
aliasing" for the corrected explanation and what that stripping actually
broke.

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

- **`VfsHooks` are observe-only.** Both `before` and `after` return `void`. You
  cannot deny or rewrite an operation from a hook. Use hooks for the audit log;
  use a *provider* to enforce.
- **`createShadowPathPredicate` has no glob support.** It does exact-path and
  prefix matching only. Any glob semantics must be hand-written.
- `ShadowProvider` is a *redirect-or-deny-writes* primitive. It has no concept
  of hiding a path (returning `ENOENT` on lookup) and no concept of denying
  reads.
- **`denySymlinkBypass` is the load-bearing detail.** `ShadowProvider` defaults
  it on and consults `realpath()` so that a symlink cannot alias around a rule.
  Any custom provider that checks only the requested path silently loses this,
  and `ln -s .env decoy && cat decoy` then defeats every rule.
- `RealFSProvider` blocks symlinks that escape the exposed directory for
  follow-style operations, failing closed including on dangling links.
  `lstat`, `readlink` and `unlink` on the link entry itself are still allowed.
- Mounting a custom provider at `/` can hide the distribution CA bundle and
  break TLS.
- **`MAX_RPC_DATA` is 60 KiB**, which caps the payload of a single VFS
  operation. This is a VFS-RPC limit; it does not apply to the HTTP hook path.
- VFS-backed data is not captured in `vm.checkpoint()`.

The enforcement point being in host JavaScript, below the guest kernel's view of
the filesystem, is the reason there is no raw-syscall escape hatch: there is no
real filesystem underneath the mount for a guest process to fall back to.

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

**PID 1 is Gondolin's own `/init`**, which starts `sandboxfs`, `sandboxssh`,
`sandboxingress` and `sandboxd`. The entire host control plane depends on those.
There is no documented supervisor or entrypoint concept and no way to run your
own long-running PID 1 — replacing `sandboxd` forfeits the SDK.
`rootfsInitExtra` is the sanctioned boot hook.

Do **not** put real secrets in the image `env`; it is baked into the image.

### Selecting a custom-built image

`VMOptions` has no `image` field, which is easy to misread as "you must juggle
an environment variable to point at your build output". You do not.
`VMOptions.sandbox` is a `SandboxServerOptions`, whose `imagePath` accepts three
things: an asset directory path, an explicit `GuestAssets` object, or **an image
selector string** — either `name:tag` or a build id. So:

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
HTTP/1.1 host-side only; the WebSocket handshake is hookable but opaque after
the 101.

Ingress requires the default `/etc/gondolin` mount. Setting `vfs: null` or
overriding `/etc/gondolin` with a custom mount makes `enableIngress()` fail.

---

## 10. Threat model, and what Gondolin does not give you

The thesis is that untrusted code runs in a real Linux VM whose I/O surface
(network and persistence) is mediated by host code you control. The guest is
treated as adversarial; the host is the policy enforcement point.

Explicit non-goals: a malicious host; a malicious local user on the same
account; VM escape and QEMU bugs; side channels; and **denial of service**.

**There is no in-guest hardening whatsoever.** Searching the documentation set
and the shipped package for `seccomp`, `cgroup`, `apparmor`, `selinux`,
`landlock`, `namespace`, `no-new-privs`, `rlimit`, `CAP_SYS` and `prctl`
produces zero hits. The only resource controls are the `memory` and `cpus`
options plus I/O buffer caps, and the docs are explicit that this is not full
resource governance. The documentation assumes a root guest throughout.

Consequences for anything built on top:

- Dropping privilege inside the guest is entirely your responsibility.
- CPU burn, memory pressure, fork bombs and disk fill inside the VM are not
  addressed by the SDK. Host-side resource limits on the VM process are the only
  lever.
- Bounding a session's wall-clock lifetime is your responsibility.

---

## 11. There is no guest→host RPC, by design

The SDK's QEMU documentation carries a section titled "Why We Do Not Use Vsock".
Its reasoning is a policy argument, not a technical one: giving the guest a
general socket transport to the host makes it easy to accidentally create a
generic tunnel, and the design wants the host to remain the egress policy
enforcement point.

Four fixed-purpose virtio-serial channels exist (exec control, VFS RPC, SSH
forwarding, ingress forwarding), all host-initiated. The one backchannel,
`SandboxServer.openTcpStream()`, is host-to-guest and restricted to loopback
targets, and the types annotate `openIngressStream` with a warning that it
should not be exposed as a generic port-forwarding primitive.

**If you need a host callback, the composable route is an `onRequest`
short-circuit against a sentinel hostname.** It is documented, purpose-built,
gives you the full request and response, and never touches the network. It is
not vsock, and it is not a VFS side channel (60 KiB frame cap, and it abuses
file semantics).

---

## 12. Sharp edges, quick reference

| # | Edge | Consequence |
|---|---|---|
| 1 | No HTTP/2 or HTTP/3 | Clients that negotiate h2 must be pinned to HTTP/1.1 |
| 2 | Terminating MITM TLS, not SNI passthrough | Every guest TLS client needs the injected CA bundle |
| 3 | Node ignores the system CA store | Must set `NODE_EXTRA_CA_CERTS` explicitly for Node guests |
| 4 | `allowedHosts` omitted = allow all; `[]` = deny all | An undefined config value silently opens egress |
| 5 | `exec` array form does no `$PATH` search | Absolute paths required |
| 6 | No exec timeout, no kill | Build your own watchdog; `vm.close()` is the only hard stop |
| 7 | `VfsHooks` are observe-only | Enforce in a provider, not a hook |
| 8 | `MAX_RPC_DATA` = 60 KiB | Caps a single VFS operation payload |
| 9 | `createShadowPathPredicate` has no globs | Hand-write the matcher |
| 10 | Custom providers can lose `denySymlinkBypass` | Symlink aliasing defeats path rules |
| 11 | No guest→host RPC | Use an `onRequest` sentinel-host short-circuit |
| 12 | No in-guest hardening at all | Privilege drop is yours; DoS is an explicit non-goal |
| 13 | SSH egress and mapped TCP bypass HTTP hooks and secrets | Police those paths separately |
| 14 | Every VFS path is aliased under `fuseMount`, but only from the guest's point of view | `MountRouterProvider` dispatches with an already mount-relative path, so a `VirtualProvider`'s own path policy never sees the alias and needs no handling for it |
| 15 | Adding guest packages requires an image rebuild | Alpine-only image builder |
| 16 | `exec` is concurrent, but `vm.fs`'s file ops are not | `readFile`/`writeFile`/`deleteFile` wait for **zero** live execs, so they never complete during a long-running interactive exec |
| 17 | `maxQueuedExecs` defaults to 64, counted session-wide | Past it `exec` fails with `queue_full`; every attach client draws on the same budget |
| 18 | `vm.close()` rejects every live exec with `server_shutdown` | An un-awaited `vm.exec()` promise becomes an unhandled rejection and, under Node's default, kills the host process |

---

## 13. Risk register

Status values:

- **open** — unresolved; needs an empirical test or a build decision.
- **closed** — resolved by a decision recorded in [`design.md`](./design.md) or
  by a documented workaround.
- **resolved-by-inspection** — settled by reading the shipped types or docs, with
  no test required.

| # | Risk | Detail | Status |
|---|---|---|---|
| R1 | HTTP/2 to the model API | Gondolin supports HTTP/1.x and TLS interception only, with no HTTP/2 or HTTP/3. Model-provider SDKs commonly negotiate h2, and some agent configurations select a WebSocket transport (supported, but opaque after the 101 handshake). **Closed by M0.1 (2026-08-22):** a real TLS handshake to `api.anthropic.com` from inside a guest completes and negotiates `http/1.1` even though the client offers `h2`; a local chunked-response test confirms the egress mediation delivers streamed chunks incrementally, not buffered. See `spike-results.md` for verbatim evidence. | closed |
| R2 | Exec concurrency with a long-lived interactive process | The docs contradict themselves (§3). The agent's TUI is one long-running `exec`. **Closed by M0.4 (2026-08-30): `exec` does not serialise, and the risk's own proposed mitigation was backwards.** With a long-lived `pty: true`/`stdin: true` exec running (production's `dropcap` -> shell shape), a second `vm.exec()` starts in 5-6ms and runs genuinely in parallel (four concurrent `sleep 3` execs finish in 3013ms, not ~12000ms; `execPressure()` reads 5); the same holds for a second exec issued from a *separate host process* over `connectToSession()` (13ms end to end, stdout returned). The long exec survives untouched — it accepted input and produced correct output *during* the second exec's session, and neither stream saw a byte of the other's. Cause, read from the shipped 0.12.0 source: `handleExec`'s only queueing branch is against an in-flight **file operation**, never against another exec; the sole limit is `maxQueuedExecs` (default 64, session-wide across all clients, then `code: "queue_full"`). The inversion: it is `vm.fs`'s file operations that serialise, via `waitForExecIdle()`'s wait-for-*zero*-execs — `vm.fs.readFile`/`writeFile`/`deleteFile` can never complete while Pi's TUI exec is alive, so this risk's "`vm.fs` must cover host-side file needs" fallback was the one thing that would not have worked. (`vm.fs.stat`/`listDir`/`mkdir`/`access`/`rename` are exec-backed and unaffected; Corb calls none of the three blocked methods today.) Two secondary corrections: `execPressure()`/`waitForExecIdle()` are **not** on `VM`'s public surface (`private server`; `vm/core.d.ts` mentions neither), so no design may depend on them; and `vm.close()` rejects every live exec with `server_shutdown`, which under Node's default `--unhandled-rejections=throw` kills the host process if the exec promise has no handler. **Consequence for M8.7:** `corb attach` is viable, but only as a *new* interactive shell in the running session — the control protocol has no "list execs" and no "join exec N" (`ClientMessage` is a closed union), `SessionIpcServer` gives each client a disjoint request-id space, and addressing the owner's exec id from an attach client is refused with `unknown_id`. Rejoining or mirroring Pi's TUI is not expressible in 0.12.0. See `spike-results.md` M0.4 for verbatim evidence. | closed |
| R3 | MITM CA and Node | **Closed by M0.2 (2026-08-22):** HTTPS from node, curl, git and go all pass inside the guest, and — surprisingly — none needs an explicit CA env var from the host application: Gondolin's own guest init (`init-scripts.js`) unconditionally exports `SSL_CERT_FILE`/`CURL_CA_BUNDLE`/`REQUESTS_CA_BUNDLE`/`NODE_EXTRA_CA_CERTS` for every guest process regardless of `VM.create()`/`vm.exec()` config; git and go inherit trust via `SSL_CERT_FILE` with no tool-specific var needed. A genuine negative control (all CA vars forced to a bad path) reproduces a clean cert-trust failure per tool, confirming causality. See `spike-results.md` for verbatim evidence. **Addendum (see R20):** this spike ran as root, never through `dropcap`'s privilege drop — `NODE_EXTRA_CA_CERTS`'s specific default (`/etc/gondolin/mitm/ca.crt`) turned out to be unreadable by a dropped-privilege `agent` uid, a gap this closure didn't have the scope to catch. | closed |
| R4 | OCI rootfs viability | OCI swaps the rootfs only; boot stays Alpine-derived; the rootfs must contain `/bin/sh`. Confirm the agent and any toolchains work in the resulting rootfs, and that `arch` matches the host (aarch64 on Apple Silicon). | open |
| R5 | VFS uid/gid reporting | Can a provider report `uid`/`gid` in `stat` such that the non-root guest user appears to own the workspace? If yes, no `/etc/passwd` fixup is needed at all. If no, an equivalent fixup belongs in `rootfsInitExtra`. **Closed (2026-08-22):** irrelevant either way — the question this risk asked no longer matters, because `stat`-level uid/gid reporting was never the actual blocker. The real blocker, found empirically: `sandboxfs` mounts every `vfs.mounts` path with a hardcoded FUSE option string (`mountFuse` in `guest/src/sandboxfs/main.zig`: `fd={d},rootmode=40000,user_id=0,group_id=0,default_permissions`) with **no `allow_other`**, so per plain Linux FUSE semantics only the mounting uid (0) can touch the mount at all — reporting a friendlier `uid`/`gid` in `stat` responses would not have helped, since the kernel FUSE layer rejects a non-owning uid's request before any inode metadata (including a provider-supplied `uid`/`gid`) is even consulted. No upstream config surface exists to add `allow_other` (Gondolin issue #76, closed unanswered against 0.12.0). Fixed by re-exporting the raw mount through `bindfs` (built from source; not packaged for any current Alpine stable branch) with the workspace uid/gid squashed via `--force-user`/`--force-group` and `allow_other` on by bindfs's own default — see R18 and `image/overlay/init-extra.sh`. | closed |
| R6 | VFS performance under a real build | A JS-implemented FUSE-over-RPC layer with a 60 KiB frame cap is a genuine risk on a large source tree. Benchmark a full build and a recursive grep. If too slow, use a VFS mount only for policy-sensitive trees and a checkpointed disk for scratch. **Re-quantified for the bindfs re-export (2026-08-23), superseding the fuse-overlayfs numbers below:** the R18 re-export still adds a second FUSE hop (agent → `bindfs` → the untouched `sandboxfs` mount → virtio RPC → host) for every guest workspace operation, but the tool doing that hop changed from `fuse-overlayfs` to `bindfs`. Measured in a real booted `corb:0.1.0` VM against the same-shaped benchmark as before — an 800-file/3.2 MiB synthetic tree, 5 runs per path after a per-path warm-up, single-hop raw mount vs double-hop public mount — with one methodology fix: bulk `rm -rf` immediately after a bulk create hit a genuine readdir/unlink race in `sandboxfs` itself (reproduced directly against the raw mount, nothing to do with bindfs — busybox `rm -rf` returns `ENOTEMPTY` mid-sweep), so each write-loop run now uses a fresh, uniquely-named directory instead of deleting between runs, and cleanup is untimed and run after all measurements. Results: `find -type f` averaged 371.6ms raw vs 426.4ms through the re-export (**1.15x**); `grep -rl` averaged 844.6ms raw vs 1484.4ms through the re-export (**1.76x**); the 200×1 KiB sequential write loop averaged 443.0ms raw vs 639.4ms through the re-export (**1.44x**, i.e. ~2.21ms/file raw vs ~3.20ms/file through the re-export). Caveat: raw was measured before public in this run, so page-cache warming could inflate the find/grep ratios somewhat in the re-export's disfavor (the write loop touches fresh data each run and is less exposed to this); even discounting that, all three phases now show a real but modest cost, a marked improvement over fuse-overlayfs's ~3.0x write-loop penalty (696ms vs 2086ms average, ~3.5ms/file raw vs ~10.4ms/file through the re-export) with no workdir round-trip on every create to explain the difference. Still open: a benchmark against a real build (e.g. `go build`/`npm install`/`tsc`) rather than a synthetic file tree, and the mitigation this risk already proposed (VFS mount only for policy-sensitive trees, checkpointed disk for scratch) has not been evaluated against the added re-export cost specifically. | open |
| R7 | Exec timeout and kill | The SDK provides neither (§3). Anything beyond the single foreground process needs a bespoke watchdog. | open |
| R8 | No glob support in the shadow predicate | `createShadowPathPredicate` is exact-path and prefix only. Corb needs `**/.env*`-shaped rules. Addressed by the glob policy provider in `design.md`. | closed |
| R9 | Git-over-SSH warnings | The guest-facing proxy host key lacks post-quantum KEX, so OpenSSH warns on every operation. Apply the documented `GIT_SSH_COMMAND` workaround so the noise does not confuse the agent. | closed |
| R10 | Ingress depends on `/etc/gondolin` | `vfs: null` or a custom `/etc/gondolin` mount makes `enableIngress()` fail. **Closed by M9.4 (2026-08-30):** ingress is adopted (`corb run --expose PORT`, `docs/design.md`'s ingress subsection) and verified against a real booted `corb:0.1.0` VM — `test/e2e/ingress.e2e.ts` boots a VM with `vfs` left unset (so the SDK's default `/etc/gondolin` mount is intact, confirmed by the earlier resolved-by-inspection reasoning still holding), starts a real HTTP server inside the guest, calls `vm.enableIngress()`/`vm.setIngressRoutes()`, and a real host HTTP GET through the resulting `IngressAccess.url` reaches the guest server and returns its actual response body. `src/vm/session.ts`'s production wiring (`vfs: { mounts: vfsMounts }`, none of which target `/etc/gondolin`) was independently checked against the same constraint. | closed |
| R11 | Project maturity | 0.12.0, self-described as early, with breaking reshapes as recently as 0.6.0. Pin exactly and expect churn on upgrade. | open |
| R12 | VFS write semantics versus guest uid | The assumption is that writes go over RPC to a provider in the host process, which performs the real write as the host user, so guest-kernel DAC against a guest uid is not the enforcement point. This is load-bearing for the design; test it rather than assume it. **Closed (2026-08-22):** the assumption about where writes are ultimately performed (host process, as the host user, over RPC) was never wrong, but it was insufficient on its own: the guest-kernel FUSE layer gates the RPC round-trip itself on the *mounting* uid, before any provider or host-side DAC logic ever runs. `sandboxfs`'s hardcoded `user_id=0,group_id=0,default_permissions` (see R5) means a `vfs.mounts` path mounted directly is unreachable by any guest uid other than 0 — `dropcap`'s drop to uid 1000 left the agent with zero filesystem access, verified empirically (every `stat`/`open`/write from uid 1000 against a direct mount returned `EACCES` at the kernel FUSE layer). Fixed by R18: the raw mount stays exactly as `sandboxfs` produces it (untouched, still root-only), and a `bindfs` re-export in front of it is what the agent actually talks to. | closed |
| R13 | `VirtualProviderClass` defaults | Confirm that extending it and overriding a subset of methods delegates the rest correctly, before relying on partial overrides in a policy provider. | open |
| R14 | Sentinel-host round-trip latency | A host round-trip on every gated command adds latency. Measure it; if it is annoying, cache by payload hash within a session. | open |
| R15 | Cgroup attach timing on Linux | Confirm `vm.getHostPid()` returns a stable PID early enough to attach a cgroup before the guest can do meaningful work. **Closed by M8.3 (2026-08-30):** made moot rather than answered — the attach was never attempted. `corb run` re-execs itself under `systemd-run --user --scope` with the `vm.limits` properties applied *before* `VM.create()` runs (`src/vm/scope.ts`, `docs/design.md` §7), so the limit already covers the whole process tree by the time QEMU exists and no pid is ever observed. There is no window to measure and nothing about `vm.getHostPid()`'s timing left to depend on. | closed |
| R16 | Reading a request body inside `onRequest` | `HttpHooks.onRequest` is typed `(request: Request) => Promise<Request \| Response \| void> \| Request \| Response \| void` and receives a full WHATWG `Request`. The "request body is always null" caveat in the SDK's JSDoc is attached to `isRequestAllowed`, not to `onRequest`; a separate `ON_REQUEST_EARLY_POLICY_SAFE` marker symbol exists specifically to opt a hook into pre-body policy checks. Awaiting `req.json()` inside `onRequest` is sound. | resolved-by-inspection (0.12.0 .d.ts) |
| R17 | Selecting a custom-built guest image | `VMOptions` has no `image` field, but `VMOptions.sandbox` is a `SandboxServerOptions` whose `imagePath` accepts an asset directory path, an explicit `GuestAssets` object, or an image selector string (`name:tag` or a build id). `VM.create({ sandbox: { imagePath: "corb:0.1.0" } })` works; no environment-variable juggling is needed. | resolved-by-inspection (0.12.0 .d.ts) |
| R18 | Workspace re-export mount (`bindfs`, built from source) is now a permanent, load-bearing part of the boot sequence | Closes R5/R12. Without it, `dropcap`'s privilege drop to uid 1000 leaves the agent with **no filesystem access whatsoever** — every workspace `stat`/`open`/write returns `EACCES` at the guest kernel FUSE layer, before any host-side policy (VFS or otherwise) is ever consulted. `src/vm/session.ts` mounts the host workspace `RealFSProvider` at an internal-only guest path (`WORKSPACE_RAW_GUEST_PATH = "/mnt/corb-raw/work"`), never referenced again after boot; `image/overlay/init-extra.sh` (wired via `corb-image.json`'s `init.rootfsInitExtra`, confirmed by reading `injectBeforeSandboxdExec` to run after `sandboxfs` has mounted and bound every `vfs.mounts` path, and before `sandboxd` starts accepting exec requests) re-exports it at the public `WORKSPACE_GUEST_PATH = "/work"` via `bindfs --force-user=<uid> --force-group=<gid> <raw> <public>`, uid/gid read from `/etc/corb/image.json` (never hardcoded, matching `image/verify.ts`'s own convention for the same values), `allow_other` left implicit (bindfs's own default; `--no-allow-other` is the flag that would turn it off, and this mount always runs as root during boot regardless). This is the same tier of importance as `dropcap` itself: the two together are what make the agent's process tree both unprivileged *and* able to do anything at all. Verified in a real booted `corb:0.1.0` VM: `dropcap`-dropped uid 1000 can `stat`/read/write through `/work`, and `ls -ln` shows files squashed to `1000:1000`; a host-created file is visible in the guest; a guest-written file (including through `mkdir`/`mv`/`rm`, which exercise the raw `sandboxfs` mount's more exotic FUSE opcodes) round-trips back to the host directory with the real host user as owner. **Package choice — `bindfs`, built from source, not `fuse-overlayfs` from `community` (supersedes an earlier version of this fix):** `bindfs` is purpose-built for this exact job (`--force-user`/`--force-group`/`allow_other`, no overlay semantics at all — a straight passthrough, not a copy-up filesystem), a better fit than the overlay tool a previous iteration of this fix used. It does not exist in any current Alpine stable branch — checked 3.22, 3.23 (the version this project pins) and 3.24 via the aports git tree (`git.alpinelinux.org/aports`, branch `<version>-stable`); none carry a `bindfs` APKBUILD outside `testing/`, and Alpine only *publishes* built binary packages for `testing` against `edge`, never against a stable release branch. It lands only in `edge/testing` (confirmed by reading `testing/bindfs/APKBUILD` directly from the aports tree), which this project avoids as an ongoing provenance/trust cost for a security-relevant boot-time binary, and doubly so for `edge/testing` specifically — a tier below even `edge/community`. Corb instead builds it from source at image-build time. **Build recipe, verified independently rather than trusted from a prior run:** source is a plain tarball, `https://bindfs.org/downloads/bindfs-1.18.4.tar.gz` (there is no GitHub Releases entry for this project — the aports `APKBUILD` fetches from bindfs.org too). Version and sha512 checksum were re-fetched live from Alpine's own (source-only, unshipped-as-a-binary) build recipe at `https://git.alpinelinux.org/aports/plain/testing/bindfs/APKBUILD` (the `gitlab.alpinelinux.org` mirror this was originally sourced from now sits behind a bot-detection JS challenge; `git.alpinelinux.org`'s cgit mirror serves the same file unauthenticated) and matched what was assumed going in: `pkgver=1.18.4`, `sha512sums` for `bindfs-1.18.4.tar.gz` = `1fedfcd082980180ccdd684478cc5308f4ea3fa541af12b5aef0b75fb0ec5b285009c4b783fc3cd5550505a83baf015e243f88eb322540d0f82e1952babc799a`. The APKBUILD applies one patch, `musl-getmntent-issue.patch`; fetched and read directly — it touches only `tests/common.rb` (a Ruby test-suite helper that shells out to `fusermount3`/`fusermount` to unmount during test teardown; the patch skips that and unmounts with plain `umount` instead) and Alpine's own recipe already sets `options="!check"` (tests never run), so the patch is irrelevant to a build that, like Alpine's own, does not run `make check`. Not applied. Build dependencies `build-base`, `linux-headers`, `fuse3-dev` are all in Alpine 3.23 stable (confirmed by installing them in a real `alpine:3.23.0` container). The build itself is the standard `./configure --prefix=/usr --sysconfdir=/etc --mandir=/usr/share/man --localstatedir=/var && make && make install`, unpatched, and it compiled and installed cleanly first try in a real `alpine:3.23.0` container and again inside the actual `corb image build` container. **This is more supply-chain-controlled than an apk-managed package would be, not less:** Corb pins the exact source tarball URL and a checksum it verifies itself (`sha512sum -c` against a hardcoded value in `corb-image.json`, build-breaking on mismatch), rather than trusting whatever bytes a `community` or `edge` mirror happens to serve for a given package name at build time. The checksum's provenance is Alpine's own aports tree, not an ad hoc value; re-deriving it from that tree (rather than reusing a previously recorded number blindly) is exactly what was done here, and is what should be done again before any future version bump. **Runtime dependencies, determined empirically rather than assumed:** `ldd /usr/bin/bindfs` after a real build showed exactly one non-libc dependency, `libfuse3.so.4`, provided by the `fuse3-libs` package. Installing only `fuse3-dev` (the build-time header/pkg-config package) pulls in `fuse3-libs` and `pkgconf` but **not** the main `fuse3` package — confirmed directly (`apk info -e fuse3` reports absent after `apk add fuse3-dev` alone). That matters because the main `fuse3` package is what ships `/usr/bin/fusermount3`, built with Alpine's own `options="suid"` (i.e. installed SUID-root) — the exact binary the previous `fuse-overlayfs` implementation had to `chmod u-s,g-s` at build time to keep it out of the live SUID/SGID set. With `bindfs`, that binary is never installed in the first place, which is a strictly better position than stripping its bit: there is nothing to strip, nothing to regress if a future Alpine bump changes fuse3's default permissions, and one fewer file for a human or the `suid` gate to have to reason about. Confirmed the mount does not need `fusermount3` even functionally, not just by absence of the dependency edge: a real `alpine:3.23.0` container with `fusermount3` verified absent from the filesystem entirely (not merely non-SUID) still mounted, read, and wrote successfully via `bindfs --force-user=1000 --force-group=1000` run as root — consistent with libfuse3 calling `mount(2)` directly when the calling process is already root (which the boot-time re-export always is) rather than shelling out to the setuid helper, which exists specifically to let *non-root* callers mount. The `suid-allowlist.txt` gate is unaffected either way: it was already empty (0 entries) before this change and remains empty after it — `fuse-overlayfs`'s SUID cost was neutralized by stripping a bit, `bindfs`'s SUID cost never existed to begin with, and both end at the same "0 live SUID/SGID binaries" outcome the `suid` gate asserts. **A second, non-obvious runtime-dependency finding, specific to how this had to be built (not a bindfs property):** `corb-image.json`'s `postBuild.commands` run real `apk add`/`apk del` inside the rootfs *after* `alpine.rootfsPackages` has already been installed into it — but `rootfsPackages` installation uses Gondolin's own from-scratch package fetcher (`installPackages` in the SDK's `alpine/packages.js`), which downloads and extracts `.apk` tarballs directly without ever writing to `/lib/apk/db/installed`. So from the real `apk` binary's point of view (used for the first time only once `postBuild.commands` runs), nothing installed via `rootfsPackages` — including `nodejs`, and by extension `libstdc++`, `libgcc` and `zstd-libs`, which `nodejs` links against — exists. `apk add build-base linux-headers fuse3-dev` (to build bindfs) pulls in real, apk-tracked copies of `libstdc++`, `libgcc` and `zstd-libs` as transitive build dependencies (gcc needs the first two to run; the toolchain needs the third); a plain `apk del build-base linux-headers fuse3-dev` afterward then orphan-removes all three, because apk's dependency solver has no record of `nodejs` needing them — and promptly deletes the files nodejs (silently, from apk's perspective) depends on. This reproduced concretely: `npm i -g …` failed with `Error relocating /usr/bin/node: … symbol not found` (first for ICU/ada C++ symbols after `libstdc++`/`libgcc` were purged, then for `ZSTD_*` symbols after `zstd-libs` was purged too, once the first fix was in but before this one was found). The fix is the same "pin it into apk's world before deleting its puller" trick already used for `fuse3-libs`: `apk add --no-cache build-base linux-headers fuse3-dev fuse3-libs libstdc++ libgcc zstd-libs` explicitly names all four runtime libraries alongside the actual build toolchain, so `apk del build-base linux-headers fuse3-dev` (which never names them) leaves them installed. Confirmed empirically in isolation (a plain `alpine:3.23.0` container: `apk add fuse3-dev` alone does not pull `fuse3-libs` into apk's del-safe world unless added explicitly; the same pattern holds for the other three) and then end to end (a full `corb image build` run, including `npm i -g @earendil-works/pi-coding-agent`, `image/verify.ts`'s `pi` gate, and every other gate). This is not a property of `bindfs` or of Corb's design; it is a real interaction between Gondolin's own two-tier package-installation model (untracked bulk rootfs packages, real `apk` for anything in `postBuild.commands`) and any future `postBuild.commands` step that does its own `apk add`/`apk del` — worth remembering for whoever touches this file next, regardless of what they're adding. **No workdir artifact — a real improvement, not just a swap:** `bindfs` has no workdir concept at all, because it is not a copy-up filesystem — it never needs scratch space on the same device as the mount. The previous `fuse-overlayfs` implementation's `.corb-fuse-overlay-workdir` directory, visible on the host disk inside every workspace directory Corb mounted, is gone with this change, not relocated or hidden. Confirmed on a real booted VM: after mounting, reading, writing, and exercising `mkdir`/`mv`/`rm` through the public mount, `find <host-dir> -mindepth 1` on the host side shows only the files the test actually created — no corb-authored artifact of any kind. **Quantified performance cost:** see R6 for the current, bindfs-specific benchmark numbers (superseding the earlier `fuse-overlayfs` numbers there). | closed |
| R19 | Does `vm.checkpoint()`/`resume()` give `corb run` a faster warm start? | **Closed by M9.5 (2026-08-30): no.** `resume()` calls the exact same `createVm()` codepath `VM.create()` does — same kernel, initramfs, `/init`, `sandboxd`, `sandboxfs`, `rootfsInitExtra` (bindfs re-export), every time. There is no partial/fast-path boot for a resumed VM; "no memory snapshots" (already stated in §2) turns out to mean the guest reboots fully from scratch regardless. Measured against the real tagged `corb:0.1.0` image: two cold boots and one checkpoint-then-resume, timed `VM.create()`/`resume()` call to first successful `vm.exec()`, all landed at ~33.5s within noise — cross-checked against M0.4's own independent `~33s` boot-warmup figure, recorded for an unrelated reason months earlier. Separately, even as a pure disk-state fork (ignoring boot time), Corb's architecture leaves checkpoint/resume little to usefully capture: everything session-relevant lives behind a VFS mount (never captured by a checkpoint), and what *is* on the persistent disk is baked in at image-build time already reused for free via `sandbox.imagePath`. See `docs/spike-results.md` M9.5 for the full write-up and evidence. | closed |
| R20 | `NODE_EXTRA_CA_CERTS` is unreadable by the `agent` uid — R3 tested this only as root | R3 closed "does Node need an explicit CA env var" without ever exercising it through `dropcap`'s privilege drop; found later, dogfooding a real `corb run` session, as a startup warning from Pi (a Node program): `Warning: Ignoring extra certs from /etc/gondolin/mitm/ca.crt, load failed: ... Permission denied`. **Root cause, confirmed empirically in a real booted `corb:0.1.0` VM:** Gondolin's own `setup_mitm_ca` (`alpine/init-scripts.js`) exports `NODE_EXTRA_CA_CERTS` pointed at `/etc/gondolin/mitm/ca.crt` — the raw file inside Gondolin's automatic MITM-CA mount (`vm/mitm-vfs.js`'s `createMitmCaProvider`, wired in automatically whenever `VM.create()` has networking enabled and nothing else already mounts that path), which is the exact same root-only `sandboxfs` mount class R5/R12/R18 already found and fixed for corb's own workspace/gate-config mounts (`fd=…,rootmode=40000,user_id=0,group_id=0,default_permissions`, no `allow_other`). `dropcap 1000 1000 cat /etc/gondolin/mitm/ca.crt` returns `Permission denied`; `dropcap 1000 1000 cat /run/gondolin/ca-certificates.crt` (the same script's own merged bundle, written to a plain `0644` file on `/run`'s tmpfs, which `SSL_CERT_FILE`/`CURL_CA_BUNDLE`/`REQUESTS_CA_BUNDLE` already correctly use) reads all 181693 bytes cleanly — the merged bundle already contains the MITM CA, baked in during the same boot-time step. **Consequence when it fires:** silent, not fatal — Node falls back to its own bundled public root store, which is why the real Anthropic/OpenRouter traffic in the sessions that surfaced this kept working (a real, publicly-signed cert validates fine against Node's bundled roots with no MITM involved). It would only actually break something the moment a connection is genuinely MITM'd for content inspection (e.g. a future extension of the `git`-over-HTTPS or content-check gates) — Node would then be unable to validate Gondolin's own re-signed leaf certificate at all. **Fix:** unlike R18 (a directory bindfs re-export, since corb owns that mount request), this mount is Gondolin's own automatic one, not something `src/vm/session.ts` configures — so the fix is simpler: `buildGuestEnv()` (`src/vm/session.ts`) now explicitly overrides `NODE_EXTRA_CA_CERTS` to `/run/gondolin/ca-certificates.crt`, matching the other three CA vars it already leaves to Gondolin's default. No new mount, no `init-extra.sh` change. | closed |
