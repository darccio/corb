# Corb design

Corb is a command-line tool that boots a [Gondolin](https://earendil-works.github.io/gondolin/)
micro-VM. It mounts host directories as a restricted workspace and runs the Pi
coding agent (`@earendil-works/pi-coding-agent`) interactively inside the guest.

The properties Corb exists to provide:

- The model API key never enters the guest.
- Network egress follows an explicit allowlist.
- Host-side policy mediates Git and GitHub access. Credentials stay on the host.
- Per-path filesystem rules run below the guest kernel. Guest processes cannot bypass them.
- Every policy decision lands in one audit log.

This file describes Corb's own architecture and the reasoning behind it. The
facts about the SDK it builds on live in [`gondolin-notes.md`](./gondolin-notes.md)
and are not repeated here.

> Adapted from an earlier design brief for a similar system.

---

## 1. Why the architecture is shaped this way

Five rules constrain everything below. Each rule closes a specific class of
failure. These rules determine the design.

### No host process ever executes a guest-chosen command

Repository content can come from the guest. Git hooks (`.git/hooks/pre-commit`)
and `[alias]` entries in `.git/config` prefixed with `!` can execute arbitrary
shell commands. Both live inside a repository the guest can write. Host-side
`git` against that repository can therefore execute code with the host process's
credentials. Argument-vector filters cannot prevent this because the payload
lives outside the arguments.

The consequence: git and `gh` run **in the guest**, unmodified. Only the wire
protocol crosses to the host.

### No general guest→host RPC channel

A general socket transport from guest to host can become a generic tunnel by
accident. The SDK deliberately provides no such transport, and Corb does not
add one. Host callbacks use an `onRequest` short-circuit against a sentinel
hostname. This purpose-built mechanism exposes the full request and response
without network traffic.

The invariant that keeps this from re-becoming the previous rule's problem: the
host executes only its own fixed, versioned check functions. It may feed
guest-supplied *data* into them. It must never execute anything the guest
supplies as code, in any form, over any transport.

### Allowlist, never blocklist, for anything with a CLI-sized surface

A blocklist cannot cover the full surface of `git` or `gh`. Blocking five git
subcommands still leaves `--git-dir`, `--work-tree`, `remote add`, and `push` to
an arbitrary URL. It also leaves `svn` and `daemon`. Blocking `gh auth` leaves
`gh api` and its REST surface, such as `PUT` and `DELETE`. An allowlist names
the finite permitted set.

Corb can use incomplete checks only when a miss affects the guest itself (§4).
A miss must never make the host act on the guest's behalf.

### Credentials never enter the guest

The model API key, the GitHub token and SSH private keys stay on the host.
`createHttpHooks({ secrets })` binds secrets host-side. The guest environment
holds only opaque placeholders. The host substitutes each real value on the
wire for allowed hosts only.

The real value never enters guest environment, memory, or disk. A compromised
guest therefore cannot read or exfiltrate it through prompt injection.

Mapped raw TCP forfeits this property, so Corb does not use it.

### Guest paths are validated host-side after normalisation

String-prefix substitution alone cannot safely translate a guest path to a host
path. `/work/repo/../../../../etc` has the expected prefix but resolves to
`/etc`. Corb normalises every guest-supplied path before host code uses it.
It then checks that the result stays within its mount root. Filesystem policy
also checks the resolved path (§3).

---

## 2. In-guest privilege drop

The SDK provides no in-guest hardening of any kind and assumes a root guest
throughout. That makes the guest's privilege posture entirely Corb's problem.

Corb runs the agent as **`agent`, uid 1000, gid 1000, home `/home/agent`**.
The process has `NoNewPrivs=1` and no supplementary groups. A small setuid-free
helper in the image serves as the `vm.exec` target. The helper drops privileges
in the target process itself. It does not depend on a guest init script.

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

- **`setgroups(nil)` is required.** Without it, the process keeps root's supplementary group memberships.
- **The failure path must exit non-zero.** `syscall.Exec` returns only on failure. Exit 127 means not found, and 126 means another execution failure.
- **The group and id calls come from `syscall`.** Its Linux implementations apply the change across every OS thread. The raw `golang.org/x/sys/unix` variants affect one thread, but Go creates several before `main`.

Wiring:

```ts
const proc = vm.exec(
  ["/usr/local/bin/dropcap", "1000", "1000", "/usr/local/bin/pi", ...piArgs],
  { cwd: "/work/<name>", stdin: true, pty: true, stdout: "pipe", stderr: "pipe" },
);
proc.attach(process.stdin, process.stdout, process.stderr);
```

### What this does and does not bound

The helper drops privileges for **the agent's process tree**: the target process
and all its children. The SDK's `/init` (PID 1), `sandboxd`, `sandboxfs`,
`sandboxssh` and `sandboxingress` stay root for the VM's lifetime. The host control plane depends
on them, and the SDK provides no supported way to change this.

Nothing the agent runs holds capabilities or can regain privileges through a
setuid binary. Escalation requires a bug in the SDK's guest daemons.

### Supporting measures in the image

- Remove `su` and `sudo` at image build time. If privilege dropping fails, their absence provides another barrier.
- **Build-time SUID gate**: reject unexpected SUID binaries. If the rootfs contains a SUID binary outside the expected set, fail the build. `NoNewPrivs=1` already blocks SUID elevation for the agent's tree. The gate catches unexpected additions after a base-image bump.
- Make `npm` and `npx` non-executable. The agent needs neither at runtime, and both can execute packages.

---

## 3. Filesystem policy

Each workspace directory has one mount-table entry at `/work/<name>`. The mount
table supplies this layout without symlink shuffling or a guest setup step.

A custom `VirtualProvider` decorates the real provider and enforces policy.
VFS hooks return `void` and cannot deny an operation. `ShadowProvider` can
redirect or deny writes but cannot hide paths or deny reads. Its predicate
helper supports only exact-path and prefix matching.

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

Every read/write mount gets built-in Git `deny-write` rules before user rules,
even when no repository exists at startup. The computed `builtin-rules` field
on `DirConfig` holds them separately from `rules`. The merge rebuilds this
field from the final mode and `protect-git` flag. TOML cannot set it.
Read-only mounts get an empty list because `ReadonlyProvider` already blocks
writes. `protect-git` defaults to true and can be disabled per `[[dir]]`.

The rules cover the root `.git` entry, config files and locks, hooks, and
`commondir`, plus metadata under `.git/modules/**` and `.git/worktrees/*`.
They do not start with `**/`, so unrelated directory renames remain available.
See the [exact rule list](configuration.md#built-in-git-protection) and
[security limits](security.md#git-metadata-protection).

Trust compares built-in rules like user rules, with an absent list treated as
empty. Adding these rules preserves old trust records. Removing them or
disabling `protect-git` requires confirmation. User rules keep their own
append-only comparison. `corb explain` shows the two lists separately.

```ts
new GlobPolicyProvider(new RealFSProvider(hostPath), [
  { glob: "**/.env",       mode: "hidden",     reason: "local secrets file" },
  { glob: "**/.env.*",     mode: "hidden",     reason: "local secrets file" },
  { glob: "**/secrets/**", mode: "hidden",     reason: "secrets directory" },
  { glob: "**/*_test.go",  mode: "deny-write", reason: "tests are not editable in this sandbox" },
  { glob: "go.sum",        mode: "deny-write", reason: "lockfile — regenerate with go mod tidy" },
], onDeny)
```

Corb matches each glob against a path relative to its directory's root, without
leading or trailing `/`. `matchRule` in `src/vfs/policy.ts` requires this form.
A glob with leading `/` or trailing `/` cannot match a real path. Embedded `//` also prevents matches.
`toGlobRules` in `src/vm/session.ts` rejects them before any VM boots.
Otherwise `corb explain` can show an apparently active rule that matches nothing.

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
| directory `rename` from or into a subtree a rule may match | allow | `EACCES` | `EACCES` | `EACCES` | `EACCES` |
| `copyFile` source | allow | allow | `EACCES` | `ENOENT` | allow |
| `copyFile` destination | allow | `EACCES` | `EACCES` | `ENOENT` | shadowed (tmpfs) |
| `link` / `symlink`, either endpoint | allow | `EACCES` | `EACCES` | `ENOENT` | shadowed (tmpfs) |

`deny-read` also denies writes. Allowing blind overwrites of unreadable files
lets the agent destroy content it cannot inspect. No mode denies reads while
permitting writes.

`hidden` reports `ENOENT` rather than `EACCES` and removes paths from directory
listings. A hidden path appears absent.

`shadow-write` redirects mutations into ephemeral, session-scoped storage
(`ShadowProvider(writeMode: "tmpfs")`). It covers writes, creates, directory
removals, rename endpoints, copy destinations, links and symlinks. These
operations do not change the real file. Reads, `stat`, and listings still
reflect the unchanged real backend.

Both link endpoints need shadowing. A real link creates another name for a
protected inode, so a write through that name can bypass the redirect.
Directory renames that affect possible rule matches fail with `EACCES` under
every mode. Otherwise the rename can move a subtree beyond its rule and expose
it to later writes.

`deny-write` permits reads. The agent can read a test file to understand the
expected behavior, but cannot edit or create one.

### The three things that make it actually hold

Path rules need three checks to prevent bypasses.

**1. Check both the requested and resolved paths.** Each operation checks the
normalised request, then its `realpath()`. Create operations resolve the parent
instead. Without this check, `ln -s .env decoy && cat decoy` bypasses rules
because `decoy` matches nothing. `ShadowProvider` provides the same check
through `denySymlinkBypass`.

**Fail closed when `realpath` errors.** A create operation can encounter an
expected `ENOENT` when its parent does not exist. Any other error, such as
`ELOOP`, `EACCES`, or a provider fault, must deny the operation. A failed
resolver does not establish that the path is safe.

**2. Gate `link()` and `symlink()` at creation time.** Hard links resolve to
themselves, so `realpath` cannot identify their aliases. After
`link("secret", "decoy")`, the new name reaches the same inode. Corb checks
both endpoints during link creation to prevent that bypass.

**3. Treat directory `rename` as covering its subtree.** A rename from
`repo/secrets` to `repo/tmp` moves its contents beyond a `**/secrets/**` rule. Renaming a prepared directory into
`config` can also bypass a `config/*.json` rule. If the source is a directory,
deny the rename when any rule can match under its source or destination.
Check the destination's requested path and its resolved parent path. This
conservative check needs no subtree walk.

### Path aliasing

The SDK's guest-wide `fuseMount` (default `/data`) exposes every mounted path
through another name. `MountRouterProvider` strips the mount prefix before it
calls Corb's provider. Thus `/data/work/repo/.env` reaches the provider with the
same mount-relative path as `/work/repo/.env`. Corb's raw mounts follow the same
rule under `/mnt/corb-raw/<name>`. No `/data`-prefixed alias reaches
`normalizeGuestPath` or other code in `src/vfs/`.

An earlier `normalizeGuestPath` stripped `/data` unnecessarily. That broke
workspaces with a real top-level `data` directory: `/data/secrets/**` became
`/secrets/...`, and `.env` incorrectly matched `/data/.env`. Corb removed the
strip. `normalizeGuestPath` in `src/vfs/glob.ts` now only normalises slashes.

### Why this is the strong layer

Host JavaScript enforces these rules below the guest kernel's filesystem view.
The same checks cover edit tools, shells, compilers, and every other guest
process. No alternative real filesystem exists beneath the mount. Static rules
belong at this layer.

Verification item: confirm that `VirtualProviderClass` delegates unoverridden
methods correctly before relying on a partial override (`gondolin-notes.md`
R13).

---

## 4. Local git and `gh` gate

Command filtering uses a shim installed in the image before a selected guest
tool. The shim checks the invocation before running the real binary. This
pattern can be extended to other commands. The shipped implementation below
supports `git` and `gh`.

git and `gh` run in the guest. Their local policy table provides convenience,
not a security boundary. A bypass affects an unprivileged guest process with
no real credentials.

Host-side `ssh.execPolicy` controls Git over SSH. The HTTP allowlist and secret
bindings control `gh`. A third check, `gitHttpGate` in `src/vm/githttp.ts`,
applies `git.allow-repos` and `git.allow-push` to Git's smart-HTTP protocol over
HTTPS. It supplements the other enforcement points.

The gate gives fast, readable errors for local operations such as config edits
and history rewriting. It also launches the content checks in §5.

The stock image shadows exactly two binaries on `PATH`. It does not replace
`/bin/sh`. A shell replacement requires a fragile shell parser and adds no
benefit because these operations have no host round-trip to intercept.

```
/usr/local/bin/git      -> policygate
/usr/local/bin/gh       -> policygate
/usr/local/libexec/real-git
/usr/local/libexec/real-gh
```

The names `real-git` and `real-gh` avoid git's `cmd_main()` convention.
Git strips a `git-` prefix from its invoked basename and dispatches the
remainder as a builtin. This supports names such as `git-upload-pack`,
`git-receive-pack`, and `git-shell`.

A binary named `git-real` therefore fails with
`fatal: cannot handle real as a builtin`. A real VM boot confirmed this.
The name `real-gh` follows the same pattern for consistency, although `gh`
does not share that convention.

```go
type toolPolicy struct {
	real               string
	blockedSubcommands []string
	blockedFlags       []string
	allowedGlobalFlags []string // value-less flags allowed before the subcommand
	gated              map[string]hookSpec // subcommand -> out-of-guest content check
}

var policies = map[string]toolPolicy{
	"git": {
		real:               "/usr/local/libexec/real-git",
		blockedSubcommands: []string{"config", "credential", "filter-branch", "init"},
		blockedFlags:       []string{"-c", "-C", "--config-env", "--exec-path", "--upload-pack", "--receive-pack", "--no-gpg-sign", "--git-dir", "--work-tree"},
		allowedGlobalFlags: []string{"-P", "--no-pager", "--bare", "--no-replace-objects", "--no-lazy-fetch", "--no-optional-locks", "--no-advice", "--literal-pathspecs", "--glob-pathspecs", "--noglob-pathspecs", "--icase-pathspecs"},
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

Flow: resolve the tool from `argv[0]`. Walk past leading flags in that tool's
`allowedGlobalFlags` to find its subcommand (`ResolveSubcommand` in
`guest/internal/gate/policy.go`). Git and `gh` accept flags before subcommands,
as in `git --no-pager commit`. The subcommand is therefore not always `argv[1]`.

Consult the table for the resolved subcommand and run any attached content
check. Then `exec` the real binary in the guest as the same unprivileged user.
The gate never asks the host to execute anything.

### Extending command coverage

Adding a command filter is an image and runtime change today:

1. Install the real tool and its shim in the image. See [`image/corb-image.json`](../image/corb-image.json).
2. Extend `ToolFromInvocation` in [`guest/internal/gate/policy.go`](../guest/internal/gate/policy.go) and the host's `GATE_CONFIG` in [`src/vm/session.ts`](../src/vm/session.ts). Dispatch currently rejects every basename except `git` and `gh`. Adapt the checks to the new tool's arguments. The existing logic allows only value-less global flags before the subcommand.
3. If the tool needs a content check, add its collector and `GatedHook` dispatch. Extend host validation in [`src/policy/checks.ts`](../src/policy/checks.ts) and [`src/policy/sentinel.ts`](../src/policy/sentinel.ts). The host currently accepts only `git.commit` and `git.push`.

A symlink to `policygate` alone does not add command support. Corb has no user
configuration for per-tool argument policies. Shims provide convenience.
Host-side filesystem and network rules cover real binaries and tools with no shim.

### Exit codes

| Code | Meaning |
|---|---|
| `86` | Denied by the local policy table |
| `87` | Denied by an out-of-guest content check |

POSIX shells use `126` for "command found but not executable". Reusing it
makes policy denials look like permissions problems. Shells and git do not use
`86` or `87`, so agents and users can identify these denials in logs.

The table can duplicate host-side `onRequest` restrictions to give immediate,
readable errors instead of a later generic 403. But subcommand resolution also
controls content checks. `GatedHook` dispatches `commit` and `push` from the
same resolved subcommand that the local table uses. If resolution misses a
subcommand, both checks miss it.

Review found this problem with `git -C /path commit`. Leading global flags move
the subcommand beyond `args[0]`. The old `blockedFlags` list named `-C`,
`--git-dir`, and `--work-tree`. It missed other valid leading flags such as
`--no-pager`, `--bare`, and `--literal-pathspecs`. Each omission bypassed both
checks.

`allowedGlobalFlags` and `ResolveSubcommand` fix this with an allowlist
(ADR 0005). Only listed value-less flags can precede the subcommand. The gate
therefore sees `commit` after every allowed leading flag and rejects all others.
`blockedFlags` still rejects `-C`, `--git-dir`, and `--work-tree` because they
retarget the repository or config file.

`blockedFlags` no longer closes the argument-shifting gap. See
`ResolveSubcommand` in `guest/internal/gate/policy.go` for flag handling.
`CheckLocal` documents the order of the two checks and their handling of glued
values such as `-C/path`.

---

## 5. Out-of-guest content checks

Some policy needs content: a secret in a diff or a commit that spans 80 files.
These checks run on the host because the guest can skip guest-side checks.

There is no guest→host RPC, so the transport is an `onRequest` short-circuit
against a sentinel hostname:

```
policy.corb.invalid
```

RFC 2606 reserves `.invalid`, which never resolves. If the short-circuit is
removed, requests fail to connect instead of leaking the payload. Corb adds the
hostname to `allowedHosts` so requests reach the hook. They never leave the host
process.

**Never bind a secret to the sentinel host.** The host can expand secrets
before `onRequest` runs. This handler reads and logs the request body.

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

The handler dispatches on hostname inside the outbound allowlist's `onRequest`.
It returns a synthetic `Response` without network traffic. `onRequest` receives
a full WHATWG `Request`, so `await req.json()` can read its body
(`gondolin-notes.md` R16).

Corb versions the checks as fixed functions in its repository. They check
secret-shaped patterns, changed-file counts, and path rules (§3). The guest
cannot configure these functions. They never construct shell commands from the
payload. Running a fixed formatter over supplied text is safe, but evaluating
supplied text violates the design.

### The handler is talking to an adversary

The guest can loop on this endpoint, send a gigabyte, or send garbage. Three
things are load-bearing:

- **Body-size cap.** Reject bodies over 256 KiB. Check both `Content-Length` and streamed byte counts because the guest controls the header. Return a denial rather than a parse error. This HTTP path does not use VFS's 60 KiB `MAX_RPC_DATA` limit. The guest collector truncates diffs below Corb's cap, so normal requests stay under it.
- **Field-by-field shape validation.** Accept only the two `op` literals. Check that `changedFiles` is a string array within length and count bounds, and `diff` is a string. Validate before calling check functions. Do not reflect payload fields in the response.
- **Rate limit.** Use a token bucket with a fixed budget of checks per session.

### Failure behaviour

An unreachable or erroring check service **fails open**. The operation proceeds,
and the audit log records that the check did not run. This check supplements
§3's filesystem rules. An operator's check-service mistake must not silently
stop the agent.

**A rate-limit rejection is a denial.** Treating it as an infrastructure error
lets the guest exhaust the budget to trigger fail-open behavior. The guest gate
must distinguish these responses and exit `87` for a rate-limit rejection.

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

Each violation names a rule, an optional file, a reason, and a hint. A bare
non-zero exit encourages repeated attempts. A hint tells the agent what to
change.

### Division of labour with the filesystem layer

They are complementary, not redundant:

| | §3 filesystem policy | §5 content checks |
|---|---|---|
| Enforces | *where*: is this path writable | *what*: is this change acceptable |
| Sees | one path at a time | the whole staged diff or push range |
| Bypass surface | none, kernel-facing for every process | only tools routed through the gate |
| Good for | static path rules | content rules (secrets in a diff, commit size) |
| On failure | fails closed | fails open, except rate limiting |

Static path rules belong in §3, and content rules belong in §5. Combining them
forces path rules to inspect content or content checks to enumerate every path.
Neither is appropriate.

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
| `session` | `runSession()` itself, one line per session lifecycle transition |

`session` records `start` before boot, so pre-boot validation failures appear in
the log. It records `exit:<code>` for normal endings, `error` for abnormal ones,
and `watchdog-expired` for §7's wall-clock limit. The other four channels cannot
show whether a session began. These lifecycle events connect policy decisions
to their run.

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

The host clock supplies timestamps, and the host process writes the file outside
every guest mount. The guest cannot forge, reorder, or truncate it.

Corb writes each event immediately with `fs.writeSync` on an append-mode file
descriptor. It does not buffer events for a later flush. An earlier version
buffered events to reduce write costs. A `SIGKILL`, OOM kill, or other abnormal
exit then lost the entire session log, even the event that caused the kill.

The unbounded buffer also let a guest exhaust host memory by repeating denied
operations. `subject` and `reason` now have length caps
(`MAX_SUBJECT_BYTES` and `MAX_REASON_BYTES` in `src/policy/audit.ts`). Several
channels derive these strings from guest-controlled paths, so their lengths
need bounds too. Corb creates the log with mode `0600` and its directory with
mode `0700`. It also tightens existing log files to `0600` on first use.

The guest gate has no durable log. The host records its outcomes when the
sentinel handler runs. Local table denials that never reach the host appear
only on stderr, on a best-effort basis.

Never log request URLs or headers from an HTTP hook. Secrets may already be
expanded at that point. Log the hostname, the method, and the decision.

---

## 7. Resource governance and session lifetime

Denial of service is an explicit non-goal of the SDK: a guest can burn CPU,
allocate memory, fork, and fill disk inside the VM. There is no in-guest
mechanism to stop it. Everything here is therefore host-side and needs zero
guest cooperation.

**Wall-clock watchdog.** `vm.max-session` sets a maximum session lifetime.
When it expires, the host closes the VM. `vm.close()` is Corb's only reliable
termination primitive. The SDK has no exec timeout or guest-process kill operation.

```ts
const watchdog = setTimeout(() => vm.close(), maxSessionMs);
```

Expiry records `session` / `watchdog-expired` and exits `124`. This matches
`timeout(1)`. This separates expiry from crashes or signals in transcripts.
Leaving `vm.max-session` unset disables the watchdog.

### Host resource limits: re-exec, not attach

Limits must exist before the hypervisor starts. `vm.getHostPid()` supplies the
hypervisor pid only after VM creation. Attaching a cgroup at that point leaves
an unmeasured window with an unconstrained guest. The SDK cannot narrow or
report this window.

Corb inverts it. When a session configures `[vm.limits]` and `CORB_SCOPED` is
unset, `corb run` re-executes *itself* under a transient systemd user scope,
before `VM.create()` is ever reached:

```
systemd-run --user --scope --collect --quiet \
  -p MemoryMax=… -p TasksMax=… -p CPUQuota=… \
  -- <process.execPath> <process.argv.slice(1)…>
```

Set `CORB_SCOPED=1` in the child environment to prevent another re-exec.
Corb builds the command from `process.execPath` and `process.argv.slice(1)`,
without reconstructing a textual `corb …` command. Development runs and the
installed bin shim therefore behave alike. The child inherits `stdio`, which
preserves the TUI and pty behavior. The parent returns the child's exact exit
code.

`--collect` unloads the transient unit on success or failure. `--quiet`
suppresses systemd-run's `Running as unit: run-xxxx.scope` line so it does not
look like Corb output.

The limit covers the whole process tree, from before QEMU exists. This includes
Corb, QEMU, and their children. Corb never needs to observe a pid.

**Config key to systemd property.** The mapping is not one-to-one in spelling:

| Config key | systemd property |
|---|---|
| `vm.limits.memory-max` | `MemoryMax=` |
| `vm.limits.pids-max` | `TasksMax=` |
| `vm.limits.cpu-quota` | `CPUQuota=` |

The pids controller uses `TasksMax=`, not `PidsMax=`. A real `systemd-run`
and `man systemd.resource-control` confirmed that `-p PidsMax=…` fails with
`Unknown assignment`. Corb keeps its config key `pids-max` and maps it to
`TasksMax`. `MemoryMax=` and `CPUQuota=` accept the config strings unchanged
because Corb validates systemd's size and percentage formats.

**Apply all configured limits or none.** An unset `vm.limits` key contributes
no property and needs no controller. Each configured key needs its controller
(`memory`, `pids`, or `cpu`) delegated to the user's systemd manager. Corb
reads delegation from
`/sys/fs/cgroup/user.slice/user-<uid>.slice/user@<uid>.service/cgroup.controllers`.

If any required controller is missing, Corb skips the whole re-exec. A partial
set can silently supply fewer limits than requested. Corb instead warns on
stderr and runs without resource limits. An operator's incomplete delegation
must not stop the agent. This matches §5's failure behavior.

Corb also warns and continues when `systemd-run` is absent (`ENOENT`) or the
platform lacks `/sys/fs/cgroup`. macOS therefore follows the same path as
missing delegation. A host watchdog that polls memory and CPU can substitute
for cgroups, but **Corb does not implement one**. A macOS session with
`[vm.limits]` gets the wall-clock watchdog and a warning that resource limits
do not apply.

### Cleanup and session sidecars

Call `vm.close()` on every exit path. This includes signal handlers and
unhandled rejections. Otherwise QEMU remains alive after the host process exits.
Gondolin's `listSessions`, `findSession`, and `gcSessions` recover these orphans.

Gondolin's registry contains `{ id, pid, socketPath, createdAt, label }`.
It has no workspace, image, or audit information. Corb adds a sidecar,
`<id>.json` under `~/.local/state/corb/sessions/`. It stores workspace names,
host paths, access modes, the image ref and content hash, audit path, pid, and
start time.

- `id` is Gondolin's `vm.id` and the sidecar's filename stem. The registries join on this exact value.
- `pid` identifies the host `corb run` process in both registries. It is not the hypervisor pid from `vm.getHostPid()`.
- Corb writes the sidecar once it knows `vm.id`, so active sessions appear immediately. It removes the sidecar after `vm.close()` during shutdown.

The label `corb:<name>:<shortid>` helps people identify sessions. The host mints
the eight-character `<shortid>` before `VM.create()`. It cannot use `vm.id`
because `sessionLabel` is an input to VM creation. The label serves people,
and `id` joins the registries.

`corb ls` (M8.4) joins Gondolin entries and Corb sidecars by `id`. It shows
matched pairs, Gondolin VMs without sidecars, and sidecars without Gondolin
entries. It leaves unknown workspace columns empty. A sidecar without a
Gondolin entry marks an orphan, such as a session that skipped clean teardown.
`ls` shows it as not running but does not prune it. Pruning belongs to
`corb gc`.

`corb kill <session>` (M8.5) resolves an id or unambiguous prefix through
Gondolin's `findSession`. It sends `SIGTERM` to the owning host `corb run`
process, which both registries identify. The signal triggers the shutdown
controller's ordered teardown.

Corb provides no `--force` or `SIGKILL` path. `SIGKILL` skips teardown and
leaves orphaned QEMU processes and stale sidecars. Corb signals only sessions
that pass Gondolin's pid-and-socket life check. An unrelated process can reuse
a dead session's pid. Stale or orphaned entries therefore get an explanation
and non-zero exit rather than a signal.

`corb gc [--older-than 1h]` (M8.6) first calls Gondolin's `gcSessions()`, then
checks Corb's sidecars. **Kill requires proof of life. GC requires proof
of death.** Corb never prunes a sidecar while its recorded host pid lives,
regardless of registry status.

This protects three windows where healthy sessions appear dead. Startup can
precede Gondolin's lazy registration. Teardown can remove Gondolin's entry before
Corb removes its sidecar. An IPC socket path beyond `sun_path` can also leave
a session permanently marked `alive: false`. Gondolin can collect that last
session's metadata, but Corb's pid check keeps its sidecar.

Pid reuse can leave a collectable sidecar for a later run. This is safer than
deleting a running session's only record. `--older-than` additionally requires
the dead session to exceed the given age. Without it, no age filter applies
because the dead host pid already establishes that the session ended. Finding
nothing to collect is a success.

**Not built yet, M8.7:** `corb attach`.

---

## 8. Session shape

One host TypeScript program is the entire host side. In outline:

1. Resolve workspace directories, allowed hosts and repositories, push permission, and session limits.
2. Bind secrets host-side with `createHttpHooks({ secrets })`. Each `[secrets.NAME]` names a host environment variable and permitted destinations. The guest receives a placeholder for each secret. The user chooses names that match the provider SDK or Pi. Corb hardcodes no provider's key name or API host.
3. Build the mount table. Wrap each workspace `RealFSProvider` in `GlobPolicyProvider` at `/work/<name>`. Store agent configuration in a `MemoryProvider` so it never reaches host disk. Use a `RealFSProvider` for session transcripts that must survive the VM.
4. Create the VM with `dns: { mode: "synthetic", syntheticHostMapping: "per-host" }` and the SSH egress policy. Supply the CA-bundle environment variables that guest TLS clients need.
5. Arm the wall-clock watchdog and write the session sidecar (§7). Host resource limits already apply through the earlier re-exec.
6. Use `vm.exec` to run the privilege-drop helper with the agent as its target and `pty: true`. Connect the interactive terminal with `attach()`.
7. On exit, clear the watchdog, call `vm.close()`, and propagate the exit code.

Environment the guest needs, beyond the placeholder secrets:

```ts
env: {
  ...env,                                                    // from createHttpHooks
  HOME: "/home/agent",
  NODE_EXTRA_CA_CERTS: "/run/gondolin/ca-certificates.crt",  // Node ignores the system store
}
```

Gondolin's guest init exports `SSL_CERT_FILE`, `CURL_CA_BUNDLE`, and
`REQUESTS_CA_BUNDLE` for every guest process. All point to the same merged
bundle (`docs/gondolin-notes.md` R3), so Corb need not repeat them.

`NODE_EXTRA_CA_CERTS` needs an explicit override. Gondolin defaults it to
`/etc/gondolin/mitm/ca.crt`, inside a root-only MITM-CA mount
(`docs/gondolin-notes.md` R5/R12/R20). The unprivileged agent cannot read that
file, so Node silently falls back to its bundled public roots. `buildGuestEnv()`
in `src/vm/session.ts` points it at the merged bundle, which the agent can read.

### Provider and model selection

Pi (`@earendil-works/pi-coding-agent`) supports more than 24 providers.
Each uses a named environment variable, `auth.json`, or OAuth subscription.
See the installed package's `docs/providers.md`. Corb passes the user's choices
through and does not reimplement provider logic.

- **Model/provider choice.** Pi accepts `--provider` and `--model`, or interactive selection through `/model`. Corb's `[agent].provider` and `[agent].model` in `src/config/schema.ts` exist for translation into those flags. They belong before user `piArgs` in `RunSessionOptions.piArgs`, but that translation is not implemented yet. `session.ts` only needs to pass the strings through.
- **Credential binding.** Pi checks CLI `--api-key`, then `auth.json`, a provider environment variable, and `models.json`. `auth.json` lives under `PI_CODING_AGENT_DIR`, which defaults to `~/.pi/agent`. Corb supplies only the environment variable. `buildSecretBindings()` in `src/vm/egress.ts` (M3.2) handles arbitrary names. `buildGuestEnv` forwards the `...secretEnv` from `createHttpHooks()` under those names. Use Pi's exact names, such as `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, and `GEMINI_API_KEY`. Corb must not duplicate Pi's provider-name table because the copies can drift.
- **M3.4, high priority after M3.3:** delete `session.ts`'s `ANTHROPIC_HOST`, `requireApiKey`, and `MissingApiKeyError`. Replace the hardcoded `createHttpHooks()` call with M3.3's config-derived `allowedHosts` and `allowedInternalHosts`. Supply `buildSecretBindings(fullConfig.secrets, hostEnv)` too. The generic replacement already exists. Current `corb run` sessions hardcode `api.anthropic.com` and `ANTHROPIC_API_KEY` regardless of `config.toml`. This makes `[secrets]` and `[egress]` ineffective for other providers and must not wait beyond the next milestone.
- **Zero-config failure mode.** `buildSecretBindings` returns `{}` for an unconfigured `[secrets]`, as decided in M3.2. Without another check, the VM boots before Pi reports missing credentials. M3.5's `corb doctor` must add a provider-neutral warning when no `[secrets.*]` entry exists. Point users to `corb explain` and Pi's provider docs without guessing their provider. This warning must not block startup.

### Ingress (`--expose`)

Some workspaces need direct host access to a guest server, such as a dev server
or preview build. Gondolin's `vm.enableIngress()` opens a host-to-guest HTTP
reverse proxy. `vm.setIngressRoutes()` selects a guest loopback port
(`gondolin-notes.md` §9).

`corb run --expose PORT` (M9.4) connects these primitives for one guest port.
`runSession()` calls `vm.enableIngress()` with the SDK defaults:
`listenHost` is `127.0.0.1`, and `listenPort` is ephemeral. It then calls
`vm.setIngressRoutes([{ prefix: "/", port: PORT, stripPrefix: true }])`.

Corb exposes one guest port at `/`. It does not multiplex several ports by
path prefix. That needs prefix names and multi-port configuration, which the
current design does not require.

Corb prints the URL as a one-line `stderr` banner before attaching the pty.
This keeps it visible before Pi's TUI starts. Corb also stores the URL in the
sidecar's `exposed` field (`src/vm/registry.ts`), so `corb ls` can show it for
active sessions.

Shutdown closes ingress before `vm.close()`. The `close-ingress` step precedes
`close-vm`. This stops new host connections before the guest disappears and
prevents requests from racing VM teardown.

---

## 9. Non-goals

- **VM escape and hypervisor bugs.** Corb trusts QEMU's boundary, as the SDK does.
- **A malicious host, or a malicious local user on the same account.**
- **Complete DoS isolation.** §7 bounds resource use but does not make the guest behave well.
- **Exfiltration to an allowed destination.** The egress allowlist prevents unexpected destinations. Allowed hosts can still receive data. Keep the list small and justified.
- **seccomp and cgroups inside the guest.** Neither the SDK nor Corb implements them today. They remain outside the current scope.

---

## 10. Acceptance criteria

- The agent's TUI runs interactively, reflows on terminal resize, and streams from the model API.
- The real API key and GitHub token appear nowhere in guest process environments, `/proc/*/environ`, or disk.
- `git fetch` works for allowed repositories. Host policy denies pushes when disabled and denies repositories outside the allowlist.
- Host policy blocks requests outside the allowlist, even with DNS manipulation.
- Shell writes to `deny-write` and `hidden` paths fail with the expected errno. Edit-tool checks alone do not suffice.
- Host policy denies `ln -s <hidden path> decoy && cat decoy` and `ln <deny-read path> decoy && cat decoy`.
- Host policy denies directory renames from or into subtrees that a rule can match.
- A commit with a secret-shaped string fails with a structured error and exit `87`. Local table denials exit `86`.
- An unreachable check service allows commits and logs the skipped check. Rate-limit exhaustion blocks commits with exit `87`.
- The privilege-drop target shows `NoNewPrivs=1` and no supplementary groups in `/proc/self/status`.
- A nonexistent helper target exits 127 rather than 0.
- A representative session produces at least one audit event in each of the five channels.
- Corb closes sessions at their wall-clock limit. No hypervisor process survives host exit.