# No host-side execution of guest-chosen commands

## Status

Accepted

## Context and Problem Statement

Corb mediates git and GitHub access for an agent inside a guest VM.
Credentials stay on the host. One possible design runs `git`/`gh` on the host
against a repository checked out from the guest. The host process then applies
policy inline. Is host execution against guest-writable content acceptable?

See `docs/design.md` §1, "No host process ever executes a guest-chosen
command."

## Decision Drivers

* The guest authors repository content and can write git hooks (`.git/hooks/pre-commit`).
  It can also write `[alias]` entries in `.git/config` prefixed with `!`.
  Both contain arbitrary shell code.
* Host-side `git` against a guest-writable repository therefore allows arbitrary code execution with that host process's credentials.
  Those credentials include the model API key, GitHub token, or SSH key.
* No argument-vector filter can prevent this.
  The payload, such as a hook body or alias definition, lives outside the argument vector.

## Considered Options

* Run git/gh on the host against the guest's repository, behind an argument-vector filter or sanitizer
* Run git/gh entirely inside the guest, unmodified.
  Only the wire protocol (SSH exec requests, HTTPS requests) crosses to the host for policy enforcement.

## Decision Outcome

Chosen option: "Run git/gh entirely inside the guest, unmodified".
An argument-vector filter cannot close the hook/alias attack surface.
The guest controls the dangerous payload in file content, outside the command
line. The host must never execute a command that touches guest-writable content.

Enforcement happens on the wire. `ssh.execPolicy` handles git-over-SSH with a
repo allowlist and a push/fetch distinction. The HTTP allowlist and secret
binding handle `gh`'s HTTPS traffic.

### Consequences

* Good, because guest-authored hook or alias content cannot hijack a host process.
  This rule closes the "host-side git RCE" class structurally, without enumerating individual attacks.
* Good, because processes running attacker-influenced code never need to read credentials (SSH key, GitHub token).
  Authentication happens host-side against the host's own agent/key, independently of the guest's request.
* Bad, because Corb sees git/gh actions only at the wire-protocol level.
  It sees an SSH exec request's `{repo, service}` or an HTTP request's method/host/path.
  Inspecting "which files changed in this rebase" requires a separate content-check mechanism (see the sentinel-hostname ADR).
* Neutral, because the guest's local git/gh policy gate (`policygate`) still gives fast, readable feedback.
  A bypass lets "the guest do something to itself", never "the host do something on the guest's behalf".
  See the allowlist ADR.
