# Security and policy

Corb constrains the agent's processes with VM isolation and host-side filesystem
and network rules. Command shims in the image check selected tool invocations
before they run. Credentials stay on the host. Each control has a defined
enforcement point.

## Guest process

Pi runs inside a Gondolin micro-VM as the unprivileged `agent` user. The
privilege-drop helper clears supplementary groups, drops Linux capabilities, and
enables `no_new_privs` before starting it.

This applies to Pi's whole process tree. It includes shell tools and programs Pi starts.
The guest kernel and VM remain part of the isolation boundary.

## Filesystem

Workspace mounts use host-side filesystem providers. Read-only mounts and
per-path rules are enforced there, below the guest's file tools and shell
commands.

Rules can hide paths, deny reads and writes, deny writes alone, or route writes
into memory. Shadow writes leave the host file unchanged. Reads, metadata, and
listings still show that host file. Shadow writes do not provide an overlay.
Ordinary writable mounts modify the real host files.

Host directories outside the chosen mounts are not exposed through the workspace
filesystem. Select mounts deliberately. This includes reference and scratch
directories.

### Git metadata protection

Git runs inside the guest, but files it changes can affect the user's next
host Git command. Hooks, config settings, and `commondir` redirects can make
host Git execute code outside the VM.

Corb adds `deny-write` rules to every read/write mount by default. They protect
the root `.git` entry, its config files and locks, `commondir`, and hooks.
They also cover config and `commondir` in `.git/worktrees/*`, plus config,
`commondir`, and hooks under `.git/modules/**`. Rules apply before user rules.
They block replacing a protected entry and renaming a directory into a
protected subtree. The [configuration guide](configuration.md#built-in-git-protection)
lists the paths and explains `protect-git = false`.

The protection has limits:

- A host config can already point `core.hooksPath` at tracked folders such as
  `.husky/` or `.githooks/`. These remain writable.
- Corb does not cover nested repositories. This includes clones or worktrees created inside a mount.
- A submodule's own `sub/.git` file is not covered.

Treat anything the agent wrote as untrusted before running host Git inside it.

## Network and credentials

Outbound requests pass through host-side mediation. Allowed destinations are
explicit. Corb blocks internal address ranges by default.

The guest receives secret placeholders. The host replaces a placeholder with the
real value only for the secret's configured destination hosts. The network
allowlist and secret destination list are separate settings.

A subscription login (`corb login`) works the same way. Its access and refresh
tokens stay on the host. Pi gets a stand-in token that is not signed and holds
no secret. The host replaces it with the real access token only on HTTPS
requests to the provider's API host, such as `chatgpt.com`. A stand-in copied
out of the guest is useless. A process in the guest can still use the stand-in
to make its own requests to that API host, as it can with a placeholder.

Corb disables WebSocket access by default. Enabled WebSocket traffic is opaque
after the upgrade. The token swap also applies to the upgrade request.

### Transport and API checks

Git transport has separate host-side checks for permitted hosts, repositories,
and push access. SSH credentials remain on the host. These checks apply even
when the command shim is bypassed.

The optional GitHub API gate constrains HTTP methods and paths. With its
configuration table absent, that extra gate is inactive.

## Command filtering

A command shim is a wrapper installed in the image in front of a real guest
binary. Corb's `policygate` shim identifies the invoked tool. It checks the
subcommands and flags against a policy table. If policy allows the invocation,
the shim runs the real binary as the same unprivileged user. Selected subcommands can
also collect content for a host-side check before proceeding.

This pattern can be extended to other commands. Today's stock image installs
shims for `git` and `gh`, and `policygate` only recognizes those two tool names.
The host generates their policy tables from fixed entries in Corb's code. There
is no TOML setting to add a tool or change its argument policy.

To add another command, install its shim and real binary in the image. Extend
tool dispatch and the generated policy table. Handle that command's argument
syntax. A symlink to `policygate` alone is insufficient.
Additional content checks also need a collector and host-check support.

Required arguments and extensible tool registration are
[planned improvements](todo.md).

The shims are a convenience layer. The real binaries remain executable, so
invoking one directly bypasses its shim. Filesystem and network rules remain
enforced on the host for every guest process. This includes tools with no shim.

## Built in content checks

The current content-check hooks cover `git commit` and `git push`. They submit
content to a host-authored checker for selected secret-shaped patterns, a
changed-file count limit, and path rules. Other commands do not have content
collectors or accepted host-check operations today.

The fixed scanner cannot identify every kind of secret. A passing content check
is not a general approval of the code.

> Guest-side content collection and transport failures proceed with a
> diagnostic. `policy.fail-open = false` only makes internal host-checker errors
> fail closed. It does not change those guest-side failure paths. Local wrapper
> configuration failures fail closed.

## Configuration boundary

Corb configuration lives outside mounted directories. Write access to the next
run's configuration lets a guest expand its own permissions before that run starts.

Corb refuses mounts that overlap its configuration directory, state directory,
or explicit audit path. This also protects the stored trust records.

The trust comparison tracks persistent settings. First use and policy widening
require `--trust-config`. Corb treats CLI overrides as choices from the person
who launches the command.

## Audit

Filesystem denials and shadow writes, network and Git policy decisions, and host
content-check results are recorded in one JSON Lines audit log. Session events
use the same log.

The default is `~/.local/state/corb/audit.jsonl`. Keep an explicit alternative
path outside all mounts.

For the detailed guarantees and their reasoning, consult the repository's design
document and architecture decisions.
