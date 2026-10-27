# Allowlist, never blocklist, for anything with a CLI-sized surface

## Status

Accepted

## Context and Problem Statement

Several parts of Corb gate access to large command surfaces that keep changing.
These include git and `gh` invocations, outbound network hosts, and GitHub REST
API methods and paths. Policy can enumerate forbidden actions (a blocklist) or
permitted actions (an allowlist). Which fits Corb?

See `docs/design.md` §1 ("Allowlist, never blocklist, for anything with a
CLI-sized surface") and §4 (the local git/gh gate).
Also see `docs/gondolin-notes.md` §4 (`allowedHosts`) and the
`[egress.github-api]` config in the project plan.

## Decision Drivers

* A complete blocklist for a tool the size of `git` or `gh` is impractical.
  Blocking five git subcommands still leaves `--git-dir`, `--work-tree`, `--exec-path`, `remote add` to an arbitrary URL, `push`, `svn`, `daemon`.
  Blocking `gh auth` still leaves `gh api` with the entire REST surface and arbitrary `PUT`/`DELETE`.
* Enumerating permitted actions is finite and reviewable.
  Enumerating forbidden actions is not, because the tool's authors keep adding surface Corb must track.
* Gondolin's `createHttpHooks` and its `allowedHosts` sentinel behavior show the same network-layer asymmetry.
  Omitting the field allows all hosts. An explicit empty array denies all hosts.
  Safety requires an explicit list rather than reliance on a default.

## Considered Options

* Blocklist specific dangerous subcommands, flags, hosts, or API paths
* Allowlist: enumerate permitted actions and deny everything else by default

## Decision Outcome

Chosen option: "Allowlist". Apply it to the local git/gh gate,
egress host allowlist (`createHttpHooks({ allowedHosts })`), and SSH repo
allowlist (`ssh.execPolicy`). Also apply it to the GitHub API method/path gate
(`[egress.github-api].methods`/`deny-paths`). The local gate uses
`policygate`'s `blockedSubcommands`/`blockedFlags`, an acknowledged exception
explained below.

A complete blocklist over these surfaces is impractical. A missed case fails
open silently. An allowlist's failure mode is a visible, safe false denial.

### Consequences

* Good, because an allowlist miss denies a permitted action. The denial is loud, safe, and fixable by widening the list.
  A blocklist miss silently permits a forbidden action, which is unsafe.
* Good, because the "trust ratchet" has a clear meaning.
  Widening an allowlist is a detectable, confirmable event. A blocklist has no equivalent well-defined notion of "widening".
* Bad, because enumerating every permitted git/gh invocation first is impractical.
  The local git/gh gate therefore uses a blocklist (`blockedSubcommands`, `blockedFlags`) rather than a pure allowlist.
  This exception is acceptable only because a bypass lets "the guest do something to itself".
  It never lets "the host do something on the guest's behalf" (see the no-host-side-execution ADR).

  That bound is narrower than it first looks. §4/§5's out-of-guest content check
  for `commit`/`push` uses the *same* resolved subcommand as the local blocklist.
  An incomplete `blockedFlags` entry can silently skip both the content check
  and the local table. For example, an unblocked `-C` shifts the subcommand out of
  `args[0]` entirely.

  A later review found this hazard in practice. `blockedFlags` covered only
  flags its authors chose to enumerate: `-C`, `--git-dir`, `--work-tree`, and a
  handful of others. Git accepts many more global flags before the subcommand.
  Examples include `--no-pager`, `--bare`, and `--literal-pathspecs`.
  Each silently skipped both the subcommand blocklist and content check, as an
  unblocked `-C` does.

  Completing `blockedFlags` for this purpose requires another unwinnable
  blocklist inside the first. The fix uses `AllowedGlobalFlags`/`ResolveSubcommand`
  (`guest/internal/gate/policy.go`) to allowlist exactly which flags can precede
  the subcommand. This follows the ADR's decision rather than adding another
  exception.

  `blockedFlags` still denies repository- or config-retargeting flags such as
  `-C`/`--git-dir`/`--work-tree` as redundant defense-in-depth.
  These flags also fail the new allowlist independently.
  This hazard no longer depends on `blockedFlags` completeness.
* Neutral, because ongoing maintenance keeps allowlists current with new egress hosts and allowed GitHub API paths.
  It does not track a moving target of forbidden actions.
