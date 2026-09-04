# Allowlist, never blocklist, for anything with a CLI-sized surface

## Status

Accepted

## Context and Problem Statement

Several parts of Corb gate access to something with a large, evolving command
surface: git and `gh` invocations, outbound network hosts, and the GitHub REST
API's methods and paths. For each of these, policy could either enumerate what
is forbidden (a blocklist) or enumerate what is permitted (an allowlist). Which
should Corb use?

See `docs/design.md` §1 ("Allowlist, never blocklist, for anything with a
CLI-sized surface") and §4 (the local git/gh gate), and
`docs/gondolin-notes.md` §4 (`allowedHosts`) and the `[egress.github-api]`
config in the project plan.

## Decision Drivers

* A blocklist over a tool the size of `git` or `gh` cannot be completed:
  blocking five git subcommands still leaves `--git-dir`, `--work-tree`,
  `--exec-path`, `remote add` to an arbitrary URL, `push`, `svn`, `daemon`;
  blocking `gh auth` still leaves `gh api` with the entire REST surface
  including arbitrary `PUT`/`DELETE`.
* Enumerating what is permitted is finite and reviewable; enumerating what is
  forbidden is not, because the tool's authors keep adding surface Corb would
  have to track.
* `allowedHosts`'s own sentinel behavior in Gondolin's `createHttpHooks`
  underscores the same asymmetry at the network layer: omitting the field
  means allow-all, and an explicit empty array means deny-all — there is no
  safe default, only an explicit list.

## Considered Options

* Blocklist specific dangerous subcommands, flags, hosts, or API paths
* Allowlist: enumerate exactly what is permitted, deny everything else by
  default

## Decision Outcome

Chosen option: "Allowlist", applied consistently to the local git/gh gate
(`policygate`'s `blockedSubcommands`/`blockedFlags`, which is itself an
acknowledged exception — see Consequences), the egress host allowlist
(`createHttpHooks({ allowedHosts })`), the SSH repo allowlist
(`ssh.execPolicy`), and the GitHub API method/path gate
(`[egress.github-api].methods`/`deny-paths`), because a blocklist over any of
these surfaces cannot be completed and a missed case fails open silently, while
an allowlist's failure mode is a false denial — visible and safe.

### Consequences

* Good, because a miss in an allowlist denies something that should have been
  permitted (loud, safe, and fixable by widening the list), while a miss in a
  blocklist permits something that should have been denied (silent and
  unsafe).
* Good, because this makes the "trust ratchet" concept coherent: widening an
  allowlist is a detectable, confirmable event, whereas there is no equivalent
  well-defined notion of "widening" a blocklist.
* Bad, because the local git/gh gate is itself necessarily a blocklist
  (`blockedSubcommands`, `blockedFlags`) rather than a pure allowlist, since
  enumerating every permitted git/gh invocation up front is impractical — this
  is accepted specifically because the gate's failure mode is bounded: a bypass
  there means "the guest does something to itself," never "the host does
  something on the guest's behalf" (see the no-host-side-execution ADR), so the
  cost of an incomplete enumeration is tolerable only in that one place. This
  bound is narrower than it first looks, though: §4/§5's out-of-guest content
  check for `commit`/`push` is dispatched off the *same* resolved subcommand
  the local blocklist matches on, so an incomplete `blockedFlags` entry (e.g.
  missing `-C`, which shifts the subcommand out of `args[0]` entirely) can
  silently skip the content check too — not just the local table. This hazard
  was real, not hypothetical: a later review found `blockedFlags` covered only
  the specific flags its authors had thought to enumerate (`-C`, `--git-dir`,
  `--work-tree`, and a handful of others), while git's own
  global-flag-before-subcommand form accepts many more (`--no-pager`,
  `--bare`, `--literal-pathspecs`, and others), each silently skipping both
  the subcommand blocklist and the content check the same way `-C` would
  have. Completing `blockedFlags` for this purpose would just be a second,
  unwinnable blocklist nested inside the first one — so the actual fix is not
  a longer `blockedFlags`, it is `AllowedGlobalFlags`/`ResolveSubcommand`
  (`guest/internal/gate/policy.go`): a real allowlist of exactly which flags
  may precede the subcommand, consistent with this ADR's own decision rather
  than an exception to it. `blockedFlags` continues to cover `-C`/
  `--git-dir`/`--work-tree`/etc. as redundant defense-in-depth — those flags
  retarget which repository or config git reads, so they stay denied
  outright, and they would also fail the new allowlist independently — but it
  is no longer the mechanism this particular hazard depends on.
* Neutral, because this pushes ongoing maintenance cost onto keeping the
  allowlists current (new egress hosts, new allowed GitHub API paths) rather
  than onto tracking a moving target of things to forbid.
