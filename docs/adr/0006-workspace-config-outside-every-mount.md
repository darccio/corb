# Workspace config as named TOML files outside every mount, not project-local `./corb.toml`

## Status

Accepted

## Context and Problem Statement

Corb needs a place to store per-workspace configuration: which directories to
mount, egress allowlists, secret bindings, git policy. A natural-seeming
location is a project-local file (for example, `./corb.toml` inside the repository
being worked on), read at session startup. Where can this configuration live?

See the project plan's "Decisions" table (`let-s-read-the-docs-nifty-russell.md`):
"Workspace: Named TOML files under `~/.config/corb/workspaces/`, overridable by
flags... Deliberately not project-local `./corb.toml`."

## Decision Drivers

* A config file inside a directory the agent can write is effectively host
  code execution at session startup. The agent's *previous* session, or anyone
  with write access to the repo, can shape the *next* session's Corb process.
  They can choose mounts, network hosts and secret bindings before any
  sandboxing takes effect.
* The "no host-side execution of guest-chosen commands" rule addresses the same
  class of problem. This occurs at config-load time on the host instead of
  git-invocation time.

## Considered Options

* Project-local config file (for example, `./corb.toml` in the repository root),
  read by `corb run` at startup
* Named TOML files outside every mount (`~/.config/corb/workspaces/<name>.toml`),
  addressed by name or path, with CLI flags able to override any field

## Decision Outcome

Chosen option: "Named TOML files outside every mount", because agent-writable
configuration is host code execution at session startup. The host process
trusts and parses that file before any guest isolation exists.
Workspace files live under `~/.config/corb/workspaces/`, entirely outside any
directory a workspace mounts. Previous or concurrent agent sessions therefore
cannot write configuration that influences the next `corb run` invocation.

### Consequences

* Good, because the files that can affect Corb's host-side behavior at startup
  are fixed and outside agent reach. This closes an entire class of
  "config injection via a prior session's edits" attacks.
* Good, because users can reuse one workspace file across multiple checkouts
  or invocations by name. They need no per-repository copies.
* Bad, because workspace configuration needs a separate location outside the
  project itself. It cannot live conveniently alongside the code it configures.
  Users cannot drop a file in the repo and go.
* Neutral, because CLI flags can override any workspace-file field for a
  one-off run. The fixed-location file is not the only way to adjust a
  session's configuration.
* Neutral, because as of this writing only the *location* half of this decision
  is implemented. Corb reads a single global `~/.config/corb/config.toml`,
  then merges it with CLI flags and a directory argument. Per-name addressing
  under `~/.config/corb/workspaces/<name>.toml` remains reserved for a later
  milestone (`src/config/paths.ts`'s own comment). `corb run`/`corb explain`
  take a directory path today, not a workspace name.
  See [ADR 0013](0013-workspaces-as-directories-shared-like-dotfiles.md) for the replacement directory layout.
* Good, because Corb now actively **enforces** this ADR's rule that configuration
  never lives inside a mount. Originally this said the existing file followed
  the rule. Nothing checked it. `corb run ~` mounted
  `config.toml`/`trusted.json` read-write into the guest with no error.
  Any `[[dir]]`/`--dir` host path containing `~/.config/corb` did the same.
  That let a hostile agent rewrite config and pre-accept a matching trust
  record. A future run then applied wider-than-intended policy. `hashEffectiveConfig` is an
  unkeyed hash the guest can reproduce.
  `src/config/resolve.ts`'s `assertNoMountOverlapsCorbDirs` now refuses any
  mount whose host path overlaps `corbConfigDir()` or `corbStateDir()`.
  This includes equal paths and overlaps in either direction, with symlinks
  resolved through `realpathOrResolve`. It runs inside `resolveWorkspace` and
  covers both `--dir` flags and `[[dir]]` entries. It also covers
  `corb explain`/`--dry-run` and a real `corb run`.
* Good, because the same enforcement covers the unified audit log's path
  (`docs/design.md` §6), alongside `config.toml`/`trusted.json`. The *default*
  audit path needed no separate protection. It already lives inside
  `corbStateDir()`, itself always forbidden. Corb never checked an explicit
  `[audit] path = "..."` naming a location *inside* a workspace's own mount.
  That gave a hostile guest read-write access to the record of its own denials.
  `assertNoMountOverlapsCorbDirs` now takes the resolved `audit.path` when a
  caller explicitly sets one. It becomes a third forbidden location alongside
  `corbConfigDir()`/`corbStateDir()`. This uses the same overlap check rather
  than a parallel one.
