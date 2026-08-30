# No host-side execution of guest-chosen commands

## Status

Accepted

## Context and Problem Statement

Corb mediates git and GitHub access for an agent running inside a guest VM, so
that credentials can stay on the host. One design shape for that would run
`git`/`gh` on the host, against a repository checked out from the guest, so the
host process could apply policy inline. Should git/gh commands ever execute on
the host against guest-writable content?

See `docs/design.md` §1, "No host process ever executes a guest-chosen
command."

## Decision Drivers

* Repository content is guest-authored: git hooks (`.git/hooks/pre-commit`) and
  `[alias]` entries in `.git/config` prefixed with `!` are both arbitrary shell,
  stored inside a repository the guest can write to.
* Any host-side `git` invocation against a guest-writable repository is
  therefore arbitrary code execution on the host, with whatever credentials
  that host process holds — the model API key, GitHub token, or SSH key.
* No argument-vector filter can prevent this, because the payload (a hook body,
  an alias definition) is not in the argument vector at all.

## Considered Options

* Run git/gh on the host against the guest's repository, with an
  argument-vector filter or sanitizer in front
* Run git/gh entirely inside the guest, unmodified, and only let the wire
  protocol (SSH exec requests, HTTPS requests) cross to the host for policy
  enforcement

## Decision Outcome

Chosen option: "Run git/gh entirely inside the guest, unmodified", because an
argument-vector filter cannot close the hook/alias attack surface — the
dangerous payload lives in file content the guest controls, not in the command
line. The only sound boundary is to never let the host execute a command that
touches guest-writable content at all. Enforcement instead happens on the wire:
`ssh.execPolicy` for git-over-SSH (repo allowlist, push/fetch distinction) and
the HTTP allowlist plus secret binding for `gh`'s HTTPS traffic.

### Consequences

* Good, because the host never holds a process that could be hijacked by
  guest-authored hook or alias content — the class of "host-side git RCE" bugs
  this rule closes is closed structurally, not by enumeration.
* Good, because credentials (SSH key, GitHub token) never need to be readable
  by a process running attacker-influenced code; authentication happens
  host-side, against the host's own agent/key, orthogonal to whatever the guest
  requested.
* Bad, because everything git/gh actually do is only visible to Corb at the
  wire-protocol level (an SSH exec request's `{repo, service}`, or an HTTP
  request's method/host/path) — there is no way to inspect, say, "which files
  changed in this rebase" without a separate content-check mechanism (see the
  sentinel-hostname ADR).
* Neutral, because a local git/gh policy gate in the guest (`policygate`) is
  still worth having as a fast, readable UX guardrail, precisely because its
  bypass is bounded to "the guest does something to itself" — never "the host
  does something on the guest's behalf" (see the allowlist ADR).
