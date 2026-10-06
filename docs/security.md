# Security and policy

Corb separates the agent's working environment from host credentials and host
policy. Each control below has a defined enforcement point.

## Guest process

Pi runs inside a Gondolin micro-VM as the unprivileged `agent` user. The
privilege-drop helper clears supplementary groups, drops Linux capabilities, and
enables `no_new_privs` before starting it.

This applies to Pi's process tree, including shell tools and programs it starts.
The guest kernel and VM remain part of the isolation boundary.

## Filesystem

Workspace mounts use host-side filesystem providers. Read-only mounts and
per-path rules are enforced there, below the guest's file tools and shell
commands.

Rules can hide paths, deny reads and writes, deny writes alone, or route writes
into an in-memory shadow overlay. Ordinary writable mounts modify the real host
files.

Host directories outside the chosen mounts are not exposed through the workspace
filesystem. Select mounts deliberately, including reference and scratch
directories.

## Network and credentials

Outbound requests pass through host-side mediation. Allowed destinations are
explicit; internal address ranges are blocked by default.

The guest receives secret placeholders. The host replaces a placeholder with the
real value only for the secret's configured destination hosts. The network
allowlist and secret destination list are separate settings.

Git transport is mediated on the host, including permitted hosts, repositories,
and push access. SSH credentials remain on the host.

The optional GitHub API gate constrains HTTP methods and paths. With its
configuration table absent, that extra gate is inactive. WebSocket access is
disabled by default; enabled WebSocket traffic is opaque after the upgrade.

## Git and content checks

Guest command wrappers restrict selected Git and GitHub CLI operations.
Host-side transport and HTTP policy provide additional checks on the resulting
requests.

Git commit and push operations can submit content to a host-authored checker.
Its checks cover selected secret-shaped patterns, a changed-file count limit,
and path rules.

The fixed scanner cannot identify every kind of secret. A passing content check
is not a general approval of the code.

> Guest-side content collection and transport failures proceed with a
> diagnostic. `policy.fail-open = false` only makes internal host-checker errors
> fail closed; it does not change those guest-side failure paths. Local wrapper
> configuration failures fail closed.

## Configuration boundary

Corb configuration lives outside mounted directories. A guest that could edit
the next run's configuration could expand its own permissions before that run
starts.

Corb refuses mounts that overlap its configuration directory, state directory,
or explicit audit path. This also protects the stored trust records.

The trust comparison tracks persistent settings. First use and policy widening
require `--trust-config`; CLI overrides are treated as choices made by the
person launching the command.

## Audit

Filesystem denials and shadow writes, network and Git policy decisions, and host
content-check results are recorded in one JSON Lines audit log. Session events
use the same log.

The default is `~/.local/state/corb/audit.jsonl`. Keep an explicit alternative
path outside all mounts.

For the detailed guarantees and their reasoning, consult the repository's design
document and architecture decisions.
