# Workspace config as named TOML files outside every mount, not project-local `./corb.toml`

## Status

Accepted

## Context and Problem Statement

Corb needs a place to store per-workspace configuration: which directories to
mount, egress allowlists, secret bindings, git policy. A natural-seeming
location is a project-local file (e.g. `./corb.toml` inside the repository
being worked on), read at session startup. Where should this configuration
actually live?

See the project plan's "Decisions" table (`let-s-read-the-docs-nifty-russell.md`):
"Workspace: Named TOML files under `~/.config/corb/workspaces/`, overridable by
flags... Deliberately not project-local `./corb.toml`."

## Decision Drivers

* A config file living inside a directory the agent can write is, at session
  startup, effectively host code execution: the agent's *previous* session (or
  anyone else with write access to the repo) can shape what the *next*
  session's Corb process does — which directories get mounted, which hosts get
  network access, which secrets get bound — before any sandboxing takes effect.
* This is the same class of problem the "no host-side execution of
  guest-chosen commands" rule addresses, but at config-load time on the host
  rather than at git-invocation time.

## Considered Options

* Project-local config file (e.g. `./corb.toml` in the repository root),
  read by `corb run` at startup
* Named TOML files outside every mount (`~/.config/corb/workspaces/<name>.toml`),
  addressed by name or path, with CLI flags able to override any field

## Decision Outcome

Chosen option: "Named TOML files outside every mount", because a config file
that lives inside a directory the agent can write is host code execution at
session startup — the host process trusts and parses that file before any
guest isolation exists. Workspace files live under
`~/.config/corb/workspaces/`, entirely outside any directory a workspace
mounts, so nothing a previous or concurrent agent session wrote can influence
what the next `corb run` invocation does.

### Consequences

* Good, because the set of files that can affect Corb's host-side behavior at
  startup is fixed and outside agent reach, closing an entire class of
  "config injection via a prior session's edits" attacks.
* Good, because one workspace file can be reused across multiple checkouts or
  invocations by name, rather than needing to be duplicated per-repository.
* Bad, because workspace configuration is one more thing to set up outside the
  project itself, rather than living conveniently alongside the code it
  configures — there is no "just drop a file in the repo and go" workflow.
* Neutral, because CLI flags exist specifically to override any workspace-file
  field for a one-off run, so the fixed-location file is not the only way to
  adjust a session's configuration.
* Neutral, because as of this writing only the *location* half of this decision
  is implemented: a single global `~/.config/corb/config.toml` is read (merged
  with CLI flags and a directory argument), while per-name addressing under
  `~/.config/corb/workspaces/<name>.toml` is reserved for a later milestone
  (`src/config/paths.ts`'s own comment) — `corb run`/`corb explain` take a
  directory path today, not a workspace name.
* Good, because the rule this ADR records (never inside a mount) is now
  actively **enforced**, not merely true by convention. Originally this said
  "the rule already holds for the file that does exist" — but nothing checked
  it: `corb run ~` (or any `[[dir]]`/`--dir` host path containing
  `~/.config/corb`) mounted `config.toml`/`trusted.json` read-write into the
  guest with no error, letting a hostile agent rewrite the config and
  pre-accept a matching trust record for a future, wider-than-intended run —
  `hashEffectiveConfig` is an unkeyed hash the guest can reproduce.
  `src/config/resolve.ts`'s `assertNoMountOverlapsCorbDirs` now refuses any
  mount whose host path is, or overlaps (in either direction, and through
  symlinks — `realpathOrResolve`), `corbConfigDir()` or `corbStateDir()`. It
  runs inside `resolveWorkspace`, so it covers `--dir` flags as well as
  `[[dir]]` entries, and `corb explain`/`--dry-run` as well as a real
  `corb run`.
