# Corb design

Corb is a command-line tool that boots a [Gondolin](https://earendil-works.github.io/gondolin/)
micro-VM, mounts one or more host directories into it as a restricted workspace,
and runs the Pi coding agent (`@earendil-works/pi-coding-agent`) interactively
inside it.

The properties Corb exists to provide:

- The model API key never enters the guest.
- Network egress is restricted to an explicit allowlist.
- Git and GitHub access are mediated by policy, with credentials staying on the
  host.
- Per-path filesystem rules are enforced below the guest kernel, so no guest
  process can route around them.
- Every policy decision lands in one audit log.

This file describes Corb's own architecture and the reasoning behind it. The
facts about the SDK it builds on live in [`gondolin-notes.md`](./gondolin-notes.md)
and are not repeated here.

> Adapted from an earlier design brief for a similar system.

---

## 1. Why the architecture is shaped this way

Five rules constrain everything below. They are not style preferences; each one
closes a specific class of failure, and the design is what falls out of taking
them seriously.

### No host process ever executes a guest-chosen command

Repository content is guest-authored. Git hooks (`.git/hooks/pre-commit`) and
`[alias]` entries in `.git/config` prefixed with `!` are both arbitrary shell,
and both are stored *inside* a repository the guest can write to. So any
host-side `git` invocation against a guest-writable repository is arbitrary code
execution on the host, with whatever credentials that host process happens to
hold. No argument-vector filter can prevent this, because the payload is not in
the argument vector.

The consequence: git and `gh` run **in the guest**, unmodified. Only the wire
protocol crosses to the host.

### No general guest→host RPC channel

A general socket transport from guest to host becomes a generic tunnel by
accident, which is why the SDK deliberately does not provide one. Corb does not
rebuild one. Where a host callback is genuinely needed, the sanctioned mechanism
is an `onRequest` short-circuit against a sentinel hostname: purpose-built,
never touches the network, full request and response available.

The invariant that keeps this from re-becoming the previous rule's problem: the
host executes only its own fixed, versioned check functions. It may feed
guest-supplied *data* into them. It must never execute anything the guest
supplies as code, in any form, over any transport.

### Allowlist, never blocklist, for anything with a CLI-sized surface

A blocklist over a tool the size of `git` or `gh` cannot be completed. Blocking
five git subcommands leaves `--git-dir`, `--work-tree`, `remote add`, `push` to
an arbitrary URL, `svn`, `daemon`; blocking `gh auth` leaves `gh api` with the
entire REST surface including `PUT` and `DELETE`. Enumerating what is permitted
is finite; enumerating what is forbidden is not.

Wherever Corb must be non-exhaustive (see the local command gate in §4), it is
because the failure mode of a miss is bounded to "the guest does something to
itself", never "the host does something on the guest's behalf".

### Credentials never enter the guest

The model API key, the GitHub token and any SSH private key stay on the host.
Secrets are bound host-side via `createHttpHooks({ secrets })`, so the guest's
environment holds only an opaque placeholder and the substitution happens on the
wire, for allowed hosts only. The real value is not in guest environment,
memory, or disk, so a compromised guest cannot read it out and prompt injection
cannot exfiltrate it.

This is the property that mapped raw TCP would forfeit, which is why Corb does
not use it.

### Guest paths are validated host-side after normalisation

Translating a guest path to a host path by string-prefix substitution, without
re-checking containment on the result, is a traversal bug:
`/work/repo/../../../../etc` prefixes cleanly and resolves to `/etc`. Every
guest-supplied path that reaches host code is normalised first and then
re-checked for containment in its mount root, and the same discipline applies
inside the filesystem policy layer, where the check must run against the
resolved path and not the requested one (§3).

---

## 2. In-guest privilege drop

The SDK provides no in-guest hardening of any kind and assumes a root guest
throughout. That makes the guest's privilege posture entirely Corb's problem.

Corb runs the agent as **`agent`, uid 1000, gid 1000, home `/home/agent`**, with
`NoNewPrivs=1` and no supplementary groups. The mechanism is a small setuid-free
helper installed in the image and used as the `vm.exec` target, so that the drop
happens in the exec'd process itself rather than depending on any in-guest init
script cooperating.

```go
// cmd/dropcap/main.go — the exec target for the agent process.
// Order matters: PR_SET_NO_NEW_PRIVS, then setgroups(nil), then setresgid,
// then setresuid, then exec. Any other order leaves privilege behind.
package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"syscall"

	"golang.org/x/sys/unix"
)

func main() {
	if len(os.Args) < 4 {
		fmt.Fprintln(os.Stderr, "usage: dropcap <uid> <gid> <cmd> [args...]")
		os.Exit(2)
	}
	uid, err := strconv.Atoi(os.Args[1])
	if err != nil {
		fmt.Fprintf(os.Stderr, "dropcap: bad uid %q: %v\n", os.Args[1], err)
		os.Exit(2)
	}
	gid, err := strconv.Atoi(os.Args[2])
	if err != nil {
		fmt.Fprintf(os.Stderr, "dropcap: bad gid %q: %v\n", os.Args[2], err)
		os.Exit(2)
	}

	// 1. No new privileges. Survives execve and cannot be unset. Must be set
	//    before the drop; setting it afterwards is a no-op for privilege
	//    already held.
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		fmt.Fprintf(os.Stderr, "dropcap: PR_SET_NO_NEW_PRIVS: %v\n", err)
		os.Exit(1)
	}
	// 2. Clear supplementary groups. Skipping this is the classic bug: root's
	//    supplementary group memberships (wheel, docker, and friends) survive
	//    a setresgid/setresuid drop and grant the "unprivileged" process
	//    access it should not have. setgroups() requires CAP_SETGID, so it
	//    must happen before the uid drop.
	if err := syscall.Setgroups(nil); err != nil {
		fmt.Fprintf(os.Stderr, "dropcap: setgroups: %v\n", err)
		os.Exit(1)
	}
	// 3. gid before uid — dropping uid first makes the gid change fail once
	//    CAP_SETGID is gone.
	if err := syscall.Setresgid(gid, gid, gid); err != nil {
		fmt.Fprintf(os.Stderr, "dropcap: setresgid: %v\n", err)
		os.Exit(1)
	}
	// 4. uid last.
	if err := syscall.Setresuid(uid, uid, uid); err != nil {
		fmt.Fprintf(os.Stderr, "dropcap: setresuid: %v\n", err)
		os.Exit(1)
	}

	bin, err := exec.LookPath(os.Args[3])
	if err != nil {
		fmt.Fprintf(os.Stderr, "dropcap: %v\n", err)
		os.Exit(127)
	}
	err = syscall.Exec(bin, os.Args[3:], os.Environ())
	// Only reachable if execve failed. Falling off the end of main here would
	// exit 0 and report success for a process that never started.
	fmt.Fprintf(os.Stderr, "dropcap: exec %s: %v\n", bin, err)
	if errors.Is(err, syscall.ENOENT) {
		os.Exit(127)
	}
	os.Exit(126)
}
```

Three details in that listing are the whole point of it:

- **`setgroups(nil)` is not optional.** Without it the drop is cosmetic for any
  group root belongs to.
- **The failure path must exit non-zero.** `syscall.Exec` only returns on
  failure. A helper that ignores the return value and falls off the end of
  `main` exits 0, so a target binary that does not exist looks like a session
  that ran and succeeded. 127 for not-found and 126 otherwise matches shell
  convention.
- **The group and id calls come from the `syscall` package**, whose Linux
  implementations apply the change across every OS thread, rather than the raw
  single-thread variants in `golang.org/x/sys/unix`. Go programs are
  multi-threaded before `main` runs, so the distinction is real.

Wiring:

```ts
const proc = vm.exec(
  ["/usr/local/bin/dropcap", "1000", "1000", "/usr/local/bin/pi", ...piArgs],
  { cwd: "/work/<name>", stdin: true, pty: true, stdout: "pipe", stderr: "pipe" },
);
proc.attach(process.stdin, process.stdout, process.stderr);
```

### What this does and does not bound

It bounds **the agent's process tree** — the exec'd process and everything it
spawns. It is not "the only process in the image that runs as root", and
claiming so would be wrong: the SDK's own `/init` (PID 1), `sandboxd`,
`sandboxfs`, `sandboxssh` and `sandboxingress` all run as root for the entire
lifetime of the VM, and the host control plane depends on them doing so. There
is no supported way to change that.

So the guarantee is precise but narrow: nothing the agent runs holds
capabilities or can regain them via a setuid binary. Anything that escalates
would have to first find a bug in the SDK's guest daemons.

### Supporting measures in the image

- Remove `su` and `sudo` from the image at build time. Cheap, and a second layer
  if the privilege drop is ever bypassed.
- **Build-time SUID gate**: fail the image build if the rootfs contains any SUID
  binary outside an explicit expected set. `NoNewPrivs=1` already neuters SUID
  for the agent's tree, but the gate catches an unexpected one arriving via a
  base-image bump.
- Make `npm` and `npx` non-executable. The agent does not need them at runtime
  and they are a package-execution surface.

---

## 3. Filesystem policy

Workspace directories are mounted at `/work/<name>`, one mount-table entry per
directory. There is no symlink shuffling and no in-guest setup step; the mount
table is the whole story.

Policy is enforced by a custom `VirtualProvider` that decorates the real
provider. It has to be a provider rather than a VFS hook, because the SDK's VFS
hooks return `void` and cannot deny anything. `ShadowProvider` is close but not
sufficient: it is a redirect-or-deny-writes primitive with no way to hide a path
or deny a read, and the predicate helper it ships with supports only exact-path
and prefix matching.

### Rule model

```ts
export type GlobRuleMode = "deny-write" | "deny-read" | "hidden" | "shadow-write";

export interface GlobRule {
  glob: string;    // "**/*_test.go" — ** matches across path segments
  mode: GlobRuleMode;
  reason: string;  // surfaced in the error and in the audit log
}
```

Rules are evaluated in order and first match wins.

```ts
new GlobPolicyProvider(new RealFSProvider(hostPath), [
  { glob: "**/.env",       mode: "hidden",     reason: "local secrets file" },
  { glob: "**/.env.*",     mode: "hidden",     reason: "local secrets file" },
  { glob: "**/secrets/**", mode: "hidden",     reason: "secrets directory" },
  { glob: "**/*_test.go",  mode: "deny-write", reason: "tests are not editable in this sandbox" },
  { glob: "go.sum",        mode: "deny-write", reason: "lockfile — regenerate with go mod tidy" },
], onDeny)
```

### Semantics matrix

| Operation | no rule | `deny-write` | `deny-read` | `hidden` | `shadow-write` |
|---|---|---|---|---|---|
| `stat` / `lstat` | allow | allow | allow | `ENOENT` | allow |
| appears in `readdir` | yes | yes | yes | no | yes |
| `open` for read | allow | allow | `EACCES` | `ENOENT` | allow |
| `open` for write / create / truncate / append | allow | `EACCES` | `EACCES` | `ENOENT` | shadowed (tmpfs) |
| `readFile` | allow | allow | `EACCES` | `ENOENT` | allow |
| `writeFile` / `appendFile` | allow | `EACCES` | `EACCES` | `ENOENT` | shadowed (tmpfs) |
| `mkdir` / `rmdir` / `unlink` | allow | `EACCES` | `EACCES` | `ENOENT` | shadowed (tmpfs) |
| `rename`, either endpoint | allow | `EACCES` | `EACCES` | `ENOENT` | shadowed (tmpfs) |
| `rename` of a directory containing a matched path | allow | `EACCES` | `EACCES` | `EACCES` | `EACCES` |
| `copyFile` source | allow | allow | `EACCES` | `ENOENT` | allow |
| `copyFile` destination | allow | `EACCES` | `EACCES` | `ENOENT` | shadowed (tmpfs) |
| `link` / `symlink`, either endpoint | allow | `EACCES` | `EACCES` | `ENOENT` | shadowed (tmpfs) |

`deny-read` implies deny-write. A path the agent must not read but may
overwrite is worse than useless: it is blind-clobberable, and losing the content
is a worse outcome than reading it. There is no mode that denies reads while
permitting writes.

`hidden` reports `ENOENT` rather than `EACCES` everywhere, and is filtered out
of directory listings, so the path does not merely fail to open — it does not
appear to exist.

`shadow-write` lets every operation appear to succeed from the guest's point of
view, but anything that would mutate the real backend — a write, a create, a
directory removal, a rename endpoint, a copy destination, a link or symlink
endpoint — is redirected instead to ephemeral, session-scoped storage
(`ShadowProvider(writeMode: "tmpfs")`) and never reaches the real file. Reads,
`stat`, and directory listings keep reflecting the real backend unchanged.
`link`/`symlink` are shadowed rather than merely allowed even though one of
`link`'s two arguments is nominally a read: letting the call reach the real
backend would create a second, real name for the same inode that no rule
covers, and a write through that name would land on the real backend for real,
defeating the redirect. Renaming a directory that contains a shadow-write path
is denied outright, not shadowed, for the same reason it is denied under every
other mode: relocating the subtree would move it out from under its own rule,
so the next write to it would no longer be shadowed at all.

`deny-write` still permits reads, deliberately. The agent can read a test file
to understand what is expected of the code; it just cannot edit or create one.

### The three things that make it actually hold

Path-shaped policy is easy to write and easy to write *wrong*. Three
requirements, each closing a bypass:

**1. Check the resolved path, not just the requested one.** Every check runs
twice: once against the normalised request path, and once against
`realpath()` of that path (or of its parent, for operations that create). Without
this, `ln -s .env decoy && cat decoy` defeats every rule in the table, because
`decoy` matches nothing. `ShadowProvider` gets this right by default via
`denySymlinkBypass`; a hand-rolled provider that checks only the requested path
silently loses it.

**Fail closed when `realpath` errors.** An `ENOENT` from `realpath` on a
create-path is expected and fine. Any other error — `ELOOP`, `EACCES`, a
provider fault — must deny the operation. A resolver that cannot answer is not
evidence that the path is safe.

**2. Gate `link()` and `symlink()` at creation time.** `realpath` does not help
against hard links: after `link("secret", "decoy")`, `decoy` is a genuinely
equal name for the same inode and resolves to itself. The only place to stop it
is at creation. Both endpoints of `link` and `symlink` are therefore checked,
which is why they appear in the matrix.

**3. Treat directory `rename` as covering its subtree.** Renaming
`repo/secrets` to `repo/tmp` relocates every path under it out of the reach of a
`**/secrets/**` rule in one operation. A `rename` whose source is a directory
must be denied if any rule could match inside it. The conservative
implementation — deny a directory rename when any configured rule's glob could
match a path under the source — is cheap and correct; a precise one requires
walking the subtree.

### Path aliasing

Every VFS path is also reachable under the SDK's `fuseMount` (default `/data`),
so `/work/repo/.env` is also `/data/work/repo/.env`. Path normalisation must
strip the alias prefix before rule matching, or every rule has a trivial second
spelling that misses.

### Why this is the strong layer

The enforcement point is host JavaScript, below the guest kernel's view of the
filesystem. It applies to the agent's edit tools, to its shell tool, to a
compiler writing an output file, to anything at all in the guest — because there
is no real filesystem underneath the mount for a guest process to fall back to.
This is the layer to put static rules in.

Verification item: confirm that `VirtualProviderClass` delegates unoverridden
methods correctly before relying on a partial override (`gondolin-notes.md`
R13).

---

## 4. Local git and `gh` gate

git and `gh` run in the guest, so a policy table in front of them is a
convenience layer, not a security boundary. Being clear about that is what makes
it safe to have one at all: the worst case of a bypass is the guest doing
something to itself, as an unprivileged user, with no real credentials present.
The actual enforcement for anything that leaves the guest is `ssh.execPolicy`
for git and the HTTP allowlist plus secret binding for `gh`.

The gate exists for two reasons: to fail fast and legibly on operations that
never leave the guest (local config edits, history rewriting), and to be the
launch point for the content checks in §5.

It shadows exactly two binaries on `PATH`. It does **not** replace `/bin/sh`.
Replacing the shell means hand-parsing shell syntax, which is a large amount of
fragile code that buys nothing here, since there is no host round-trip to
intercept before.

```
/usr/local/bin/git      -> policygate
/usr/local/bin/gh       -> policygate
/usr/local/libexec/real-git
/usr/local/libexec/real-gh
```

Named `real-git`/`real-gh`, not `git-real`/`gh-real`: git's own `cmd_main()`
strips a literal `git-` prefix from its invoked basename and dispatches the
remainder as a builtin (the mechanism behind `git-upload-pack`/
`git-receive-pack`/`git-shell`), so a binary renamed to `git-real` fails
immediately with `fatal: cannot handle real as a builtin` — confirmed against
a real booted image. `real-gh` matches for naming symmetry even though `gh`
doesn't share that convention.

```go
type toolPolicy struct {
	real               string
	blockedSubcommands []string
	blockedFlags       []string
	gated              map[string]hookSpec // subcommand -> out-of-guest content check
}

var policies = map[string]toolPolicy{
	"git": {
		real:               "/usr/local/libexec/real-git",
		blockedSubcommands: []string{"config", "credential", "filter-branch", "init"},
		blockedFlags:       []string{"-c", "--config-env", "--exec-path", "--upload-pack", "--receive-pack", "--no-gpg-sign"},
		gated: map[string]hookSpec{
			"commit": {name: "git.commit", collect: collectStagedDiff},
			"push":   {name: "git.push", collect: collectPushRange},
		},
	},
	"gh": {
		real:               "/usr/local/libexec/real-gh",
		blockedSubcommands: []string{"auth", "secret", "ssh-key", "gpg-key", "config"},
		blockedFlags:       []string{"--with-token"},
	},
}
```

Flow: resolve the tool from `argv[0]`, consult the table, run any content check
attached to the subcommand, then `exec` the real binary in-guest as the same
unprivileged user. The gate never asks the host to execute anything.

### Exit codes

| Code | Meaning |
|---|---|
| `86` | Denied by the local policy table |
| `87` | Denied by an out-of-guest content check |

`126` would be a poor choice for either: POSIX shells already use it for "command
found but not executable", so a policy denial would be indistinguishable from a
permissions problem in a transcript. `86` and `87` are unused by shells and by
git, so both an agent reading its own tool output and a human reading a log can
grep for them and know unambiguously what happened.

Because a bypass is low-severity, the table can afford to be *stricter* than a
security-critical one would dare, including duplicating restrictions that
`onRequest` also enforces host-side, so failures surface instantly and readably
rather than as a generic 403 several network hops later.

---

## 5. Out-of-guest content checks

Some policy needs to see content, not paths: a secret pasted into a diff, a
commit spanning eighty files. That check has to run on the host, because the
guest can trivially skip anything that runs in the guest.

There is no guest→host RPC, so the transport is an `onRequest` short-circuit
against a sentinel hostname:

```
policy.corb.invalid
```

`.invalid` is reserved by RFC 2606 and can never resolve, so if the
short-circuit is ever removed the request fails to connect rather than leaking
the payload to a real host. The hostname is added to `allowedHosts` so it is not
dropped before the hook sees it; it never leaves the host process either way.

**Never bind a secret to the sentinel host.** Secrets may already be expanded by
the time `onRequest` runs, and this handler reads and logs its request body.

### Host side

```ts
export interface PolicyCheckRequest {
  op: "git.commit" | "git.push";
  changedFiles: string[];
  diff: string;
}

export interface Violation {
  rule: string; message: string; hint: string; file?: string;
}
```

The handler dispatches on hostname inside the same `onRequest` used for the
outbound allowlist, and returns a synthetic `Response` without touching the
network. Reading the body with `await req.json()` is sound here: `onRequest`
receives a full WHATWG `Request` (`gondolin-notes.md` R16).

The checks themselves are fixed functions versioned in Corb's own repository:
secret-shaped patterns in the diff, a changed-file-count ceiling, path rules
duplicated from §3 as a second look on the content path. None of them are
guest-configurable, and none of them shell out to anything constructed from the
payload. A check that runs a fixed formatter over supplied text is fine; a check
that evaluates supplied text is the exact failure this whole design avoids.

### The handler is talking to an adversary

The guest can loop on this endpoint, send a gigabyte, or send garbage. Three
things are load-bearing:

- **Body-size cap.** Reject anything over a fixed limit (256 KiB is generous for
  a diff) by `Content-Length` *and* by counting bytes as the body streams, since
  the header is guest-supplied. Reject with a denial, not a parse error. Note
  this path is HTTP, so the VFS `MAX_RPC_DATA` limit of 60 KiB does not apply;
  the cap is Corb's own choice. The guest-side collector truncates the diff well
  below the cap so the cap is only ever reached by something misbehaving.
- **Field-by-field shape validation.** After parsing, check that `op` is one of
  the two literals, that `changedFiles` is an array of strings within a length
  and count bound, and that `diff` is a string. Do not pass an unvalidated
  parsed object into check functions, and do not reflect any of it into the
  response.
- **Rate limit.** A fixed budget of checks per session with a token bucket.

### Failure behaviour

An unreachable or erroring check service **fails open**: the operation proceeds
and the audit log records loudly that the check did not run. The reasoning is
that this is a second layer over §3's kernel-facing rules, and an operator's
mistake in the check service should not silently stop the agent from working.

**But a rate-limit rejection is a denial, not an infrastructure error.** If it
were treated as an infrastructure error, the guest could deliberately exhaust
the budget to obtain fail-open on demand, which converts the convenience into a
bypass. The guest-side gate must distinguish the two responses and exit `87` on
a rate-limit rejection.

### Error output

The denial the agent sees is structured, attributable, and actionable:

```
git commit: blocked by corb policy (2 issues)

  [no-test-edits] internal/foo_test.go
    reason: modifying *_test.go is not allowed in this sandbox
    hint:   revert the test change; edit the corresponding source file instead

  [secret-in-diff]
    reason: diff contains what looks like a cloud access key
    hint:   remove the credential from the diff

exit 87
```

Each violation names a rule, optionally a file, a reason, and a hint about what
to do instead. An agent that gets a bare non-zero exit will retry the same thing;
one that gets a hint will do something else.

### Division of labour with the filesystem layer

They are complementary, not redundant:

| | §3 filesystem policy | §5 content checks |
|---|---|---|
| Enforces | *where* — is this path writable at all | *what* — is this specific change acceptable |
| Sees | one path at a time | the whole staged diff or push range |
| Bypass surface | none; kernel-facing, every process | only tools routed through the gate |
| Good for | static path rules | content rules (secrets in a diff, commit size) |
| On failure | fails closed | fails open, except rate limiting |

Static, path-shaped rules belong in §3. Content-shaped rules belong in §5. Using
one mechanism for both would either force path rules to see file content, which
they cannot, or force content checks to enumerate every path up front, which
they should not have to.

---

## 6. Unified audit log

The SDK hands you four independent, differently-shaped observation points and
has no opinion about correlating them:

| Channel | Source |
|---|---|
| `http` | `httpHooks.onRequest` / `onResponse` |
| `ssh` | `ssh.execPolicy` |
| `vfs` | the policy provider's deny callback |
| `gate` | content-check outcomes, recorded by the sentinel handler |

A fifth channel is Corb's own rather than the SDK's:

| Channel | Source |
|---|---|
| `session` | `runSession()` itself — one line per session lifecycle transition |

`session` records `start` before anything is booted (so a pre-boot validation
failure still lands in the log), `exit:<code>` on a normal end, `error` on an
abnormal one, and `watchdog-expired` when the wall-clock limit in §7 fires. It
exists because none of the four SDK-derived channels can say whether a session
began at all, and a log of policy decisions with no record of the run they
belong to is hard to read after the fact.

Corb writes all five to one JSONL file with one schema:

```ts
interface AuditEvent {
  ts: number;
  channel: "http" | "ssh" | "vfs" | "gate" | "session";
  decision: "allow" | "deny";
  subject: string;    // host, repo, path, or op
  reason?: string;
  sessionId: string;
}
```

Timestamps come from the host clock, not the guest, and the file is written by
the host process to a location the guest has no mount for. The guest cannot
forge, reorder or truncate it.

The in-guest gate has no durable log of its own by design; its outcomes are
recorded on the host when the sentinel handler runs. Local table denials that
never reach the host are best-effort and are reported on stderr only.

Never log request URLs or headers from an HTTP hook. Secrets may already be
expanded at that point. Log the hostname, the method, and the decision.

---

## 7. Resource governance and session lifetime

Denial of service is an explicit non-goal of the SDK: a guest can burn CPU,
allocate memory, fork, and fill disk inside the VM. There is no in-guest
mechanism to stop it. Everything here is therefore host-side and needs zero
guest cooperation.

**Wall-clock watchdog.** A session configured with `vm.max-session` gets a
maximum lifetime, after which the host closes the VM. `vm.close()` is the
termination primitive because it is the only reliable one Corb has: there is no
exec timeout and no way to kill a guest process.

```ts
const watchdog = setTimeout(() => vm.close(), maxSessionMs);
```

Expiry records a `session` / `watchdog-expired` line in the audit log and exits
`124` — `timeout(1)`'s conventional code for the same event — so a session that
ran out of time is distinguishable in a transcript from one that crashed or was
signalled. Leaving `vm.max-session` unset disables the watchdog outright; that
is a real choice a config can make, not a default worth pretending away.

### Host resource limits: re-exec, not attach

The limit has to exist *before* the hypervisor does. The obvious approach loses
that race by construction: `vm.getHostPid()` returns the real hypervisor process
id, but it only returns it once the VM has been created, so attaching a cgroup
to that pid from outside the SDK leaves a window — of unknown length, with
nothing in the SDK to narrow it or report when it closes — in which the guest is
already running unconstrained.

Corb inverts it. When a session configures `[vm.limits]` and `CORB_SCOPED` is
unset, `corb run` re-executes *itself* under a transient systemd user scope,
before `VM.create()` is ever reached:

```
systemd-run --user --scope --collect --quiet \
  -p MemoryMax=… -p TasksMax=… -p CPUQuota=… \
  -- <process.execPath> <process.argv.slice(1)…>
```

with `CORB_SCOPED=1` in the child's environment so it does not re-exec again.
The command is rebuilt from `process.execPath` and `process.argv.slice(1)`,
never a textual `corb …` reconstruction, so it behaves identically under
`node src/cli.ts run …` in development and under the installed bin shim. `stdio`
is inherited, so the agent's TUI and pty behave exactly as in a direct run, and
the parent exits with the child's exact exit code: this is a re-exec, not a
supervisor. `--collect` unloads the transient unit once it completes even on
failure, so no "failed"-looking unit lingers; `--quiet` suppresses systemd-run's
`Running as unit: run-xxxx.scope` line, which would otherwise read as stray
`corb` output.

The limit then applies to the whole process tree — `corb`, QEMU, everything they
spawn — from before QEMU exists, and no pid is ever observed.

**Config key to systemd property.** The mapping is not one-to-one in spelling:

| Config key | systemd property |
|---|---|
| `vm.limits.memory-max` | `MemoryMax=` |
| `vm.limits.pids-max` | `TasksMax=` |
| `vm.limits.cpu-quota` | `CPUQuota=` |

`TasksMax=`, not `PidsMax=`: the pids controller's systemd property is spelled
`TasksMax`, and `-p PidsMax=…` fails outright with `Unknown assignment` —
confirmed against a real `systemd-run` and `man systemd.resource-control`, not
inferred from the controller's name. Corb's own config key stays `pids-max`;
only the systemd-side spelling differs. `MemoryMax=` and `CPUQuota=` take the
raw config strings unchanged, because the size and percentage formats Corb's
schema already validates are systemd's own.

**Only what was configured, and never partially.** Only the `vm.limits` keys
actually set are examined: an unset key contributes no property and its
controller is not required. Each configured key needs its controller (`memory`,
`pids`, `cpu`) delegated to the user's systemd manager, read from
`/sys/fs/cgroup/user.slice/user-<uid>.slice/user@<uid>.service/cgroup.controllers`.
If any configured key's controller is missing, the whole mechanism is skipped —
never a partial re-exec applying just the deliverable subset, which would hand a
session quietly fewer limits than its config asked for while looking like it
worked. The session then runs unlimited with a warning on stderr rather than
failing outright: an operator's incomplete cgroup delegation should not stop the
agent from working, the same fail-open-and-say-so posture §5 takes for the
content-check service.

That warn-and-continue path covers every other way this can be unavailable, not
only missing delegation: `systemd-run` absent (the spawn fails with `ENOENT`), or
a platform with no `/sys/fs/cgroup` at all — macOS reads as "nothing delegated"
and falls through identically. A polling watchdog sampling resident memory and
CPU would be the macOS-shaped equivalent of a cgroup; **it is not built.** A
macOS session that configures `[vm.limits]` today gets the wall-clock watchdog,
no resource limits at all, and a warning saying so.

### Cleanup and session sidecars

`vm.close()` on every exit path, including signal handlers and unhandled
rejections. A VM whose host process exits without closing leaves QEMU running.
Gondolin's own session registry (`listSessions`, `findSession`, `gcSessions`) is
the recovery path for those orphans.

That registry is not enough on its own, because it knows nothing about
workspaces: its record is `{ id, pid, socketPath, createdAt, label }`. What a
session actually mounted, which image it booted, and where its audit log went are
all absent from it. Corb therefore writes a sidecar alongside it — one
`<id>.json` under `~/.local/state/corb/sessions/`, holding the workspace dirs
(name, host path, `ro`/`rw`), the image ref and its content hash, the audit path,
the pid, and the start time.

- `id` is Gondolin's own `vm.id`, and is also the sidecar's filename stem, so the
  two registries join by exact id with no mapping table between them.
- `pid` is the host `corb run` process, matching what Gondolin's registry records
  for the same session — deliberately *not* `vm.getHostPid()`, which is a
  different process, so that "pid" means one thing across both files.
- The sidecar is written as soon as `vm.id` is known, so a session is visible
  while it is still running rather than only after it ends, and removed during
  shutdown after `vm.close()`.

The human-legible label is a separate value: `corb:<name>:<shortid>`, where
`<shortid>` is eight characters minted host-side *before* `VM.create()`. It is
not `vm.id`, tempting as that would be, and cannot be: `sessionLabel` is one of
`VM.create()`'s own inputs, so at the moment the label has to exist, `vm.id` does
not yet. The label is for humans to read; the join key is `id`.

**Not built yet — M8.4 through M8.7:** `corb ls`, `corb attach`, `corb kill` and
`corb gc`. The sidecar is what makes them possible, and is already written and
cleaned up on every session, but nothing reads it back yet. Until those land, the
recovery path for an orphan is Gondolin's own registry and nothing richer.

---

## 8. Session shape

One host TypeScript program is the entire host side. In outline:

1. Resolve configuration: workspace directories, allowed hosts, allowed
   repositories, whether push is permitted, session limits.
2. Bind secrets host-side. Each `[secrets.NAME]` entry in config names a host
   environment variable and the host(s) it may be sent to; every configured
   secret is bound through `createHttpHooks({ secrets })` the same way,
   regardless of provider. The guest receives a placeholder for each. A secret
   name is chosen by the user to match whatever their model provider's SDK
   (or Pi itself) expects as an environment variable — Corb does not hardcode
   any one provider's key name or API host.
3. Build the mount table: one `GlobPolicyProvider`-wrapped `RealFSProvider` per
   workspace directory at `/work/<name>`, a `MemoryProvider` for the agent's
   configuration so nothing is written to host disk even transiently, and a
   `RealFSProvider` for session transcripts that should outlive the VM.
4. Create the VM with `dns: { mode: "synthetic", syntheticHostMapping: "per-host" }`,
   the SSH egress policy, and the CA-bundle environment variables the guest's
   TLS clients need.
5. Attach the watchdog and the host resource limits.
6. `vm.exec` the privilege-drop helper with the agent as its target, `pty: true`,
   and `attach()` for the interactive terminal.
7. On exit: clear the watchdog, `vm.close()`, propagate the exit code.

Environment the guest needs, beyond the placeholder secrets:

```ts
env: {
  ...env,                                                    // from createHttpHooks
  HOME: "/home/agent",
  NODE_EXTRA_CA_CERTS: "/run/gondolin/ca-certificates.crt",  // Node ignores the system store
  SSL_CERT_FILE:       "/run/gondolin/ca-certificates.crt",
}
```

### Provider and model selection

Pi (`@earendil-works/pi-coding-agent`) already has full multi-provider support
built in — over two dozen providers, each authenticated via its own named
environment variable, `auth.json` entry, or OAuth subscription (see the
installed package's own `docs/providers.md`). Corb's job is narrow: pass the
user's choice through, not reimplement provider logic.

- **Model/provider choice.** Pi selects a provider and model via its own
  `--provider`/`--model` CLI flags (also settable interactively via `/model`).
  Corb's `[agent].provider`/`[agent].model` config fields (`src/config/
  schema.ts`) exist to be translated into those two flags, prepended to the
  `piArgs` a real (non-dry-run) `corb run` passes to `pi` — nothing does this
  translation yet. `RunSessionOptions.piArgs` is exactly where they belong;
  `session.ts` doesn't need to know what a "provider" is beyond passing the
  string through.
- **Credential binding.** Pi resolves a provider's credential in this order:
  CLI `--api-key`, `auth.json` (under `PI_CODING_AGENT_DIR`, default
  `~/.pi/agent`), a provider-specific environment variable, then `models.json`.
  Corb only ever supplies the third. `buildSecretBindings()` (`src/vm/
  egress.ts`, M3.2) is already fully generic, and `buildGuestEnv`'s
  `...secretEnv` spread already forwards whatever `createHttpHooks()` mints
  into the guest's real environment under its own literal name — **no new
  mechanism is needed**. The only requirement is naming discipline: a
  workspace's `[secrets.NAME]` must be spelled exactly as Pi's own table
  expects (`ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, `GEMINI_API_KEY`, …).
  Corb must not maintain its own copy of that name-to-provider table — it
  would just drift from Pi's.
- **M3.4's job — high priority, do this as soon as M3.3 lands:** delete
  `session.ts`'s `ANTHROPIC_HOST` constant, `requireApiKey`, and
  `MissingApiKeyError` outright, replacing the current hardcoded
  single-host/single-secret `createHttpHooks()` call with M3.3's
  egress-config-derived `allowedHosts`/`allowedInternalHosts` plus
  `buildSecretBindings(fullConfig.secrets, hostEnv)`. This is a deletion, not
  a generalization — the generic mechanism it's deleted in favor of already
  exists. Every session `corb run` starts today is still hardcoded to
  `api.anthropic.com`/`ANTHROPIC_API_KEY` regardless of what `config.toml`
  says, which silently makes the entire `[secrets]`/`[egress]` config surface
  a no-op for anyone using a different provider — this should not sit for
  more than one more milestone.
- **Zero-config failure mode.** `buildSecretBindings` returning `{}` for an
  unconfigured `[secrets]` is correct (M3.2's own decision — no fallback), but
  left alone it means a VM boots and only then fails inside Pi's own
  no-credentials UX — worse than failing on the host before boot. M3.5's `corb
  doctor` should add a soft, provider-neutral check: warn (not hard-block) when
  no `[secrets.*]` entry is configured at all, pointing at `corb explain` and
  Pi's own provider docs rather than guessing which provider the user wants.

---

## 9. Non-goals

- **VM escape and hypervisor bugs.** That is QEMU's boundary and Corb treats it
  as trusted, as the SDK does.
- **A malicious host, or a malicious local user on the same account.**
- **Complete DoS isolation.** §7 bounds resource use; it does not make the guest
  well-behaved.
- **Exfiltration to an allowed destination.** The egress allowlist prevents
  *unexpected* destinations. If a host is allowed, data can leave through it.
  Keep the allowlist small and justified.
- **seccomp and cgroups inside the guest.** Neither the SDK nor Corb implements
  them today. Worth revisiting; not in scope now.

---

## 10. Acceptance criteria

- The agent's TUI runs interactively, reflows on terminal resize, and streams
  from the model API.
- Searching the guest for the real API key and the real GitHub token — process
  environment, `/proc/*/environ`, and disk — returns nothing.
- `git fetch` on an allowed repository succeeds; `git push` is denied when push
  is disabled for the session; a repository outside the allowlist is denied.
- A request to a host outside the allowlist is blocked, and DNS manipulation
  does not bypass it.
- Writing to a `deny-write` or `hidden` path fails with the expected errno **from
  the shell tool specifically**, not only from the agent's edit tool.
- `ln -s <hidden path> decoy && cat decoy` is denied, and so is
  `ln <deny-read path> decoy && cat decoy`.
- Renaming a directory that contains a rule-matched path is denied.
- A commit containing a secret-shaped string is blocked with a structured error
  and exit `87`; a local table denial exits `86`.
- An unreachable check service does not block commits, and the audit log records
  that the check did not run. Exhausting the rate limit **does** block, and exits
  `87`.
- The privilege-drop helper's target process shows `NoNewPrivs=1` and no
  supplementary groups in `/proc/self/status`.
- Pointing the helper at a nonexistent binary exits 127, not 0.
- The audit log contains at least one entry from each of the five channels after
  a representative session.
- A session exceeding its wall-clock limit is closed, and no hypervisor process
  survives host exit.
