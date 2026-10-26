# Workspaces as directories, shared like dotfiles

## Status

Accepted

DAR-10 provides workspace sources and the mount guard. DAR-9 provides selection,
configuration layering, portable hosts, and workspace trust keys.
DAR-14 provides implied provider hosts. DAR-17 records the workspace when its file sets the provider.

DAR-22 defines shareable input pins, OCI graphs and runtime directories.
DAR-23 implements explicit pin/build/push/pull and exact-base local composition after the DAR-20 coherent base.
The conditional-delta DAR-16 spike remains historical evidence only.

## Context and Problem Statement

[ADR 0006](0006-workspace-config-outside-every-mount.md) keeps configuration
outside every directory the agent can write. It originally reserved named files at `~/.config/corb/workspaces/<name>.toml`.
This decision replaces that layout with workspace directories.

Teams need to share workspace settings without sharing personal trust records.
They also need several mount paths, portable across different home directories.
A workspace holds authenticated input pins alongside its configuration.

`CORB_CONFIG_DIR` can select a separate configuration for each project.
That replaces both the global configuration and its `trusted.json`.
It does not add project settings to personal defaults.

## Decision Drivers

* The host must never read configuration from a directory the agent can write.
* Teams need to share workspace definitions through an ordinary Git checkout.
* Users need personal overrides without copying a shared workspace definition.
* Shared paths must work across home directories and project locations.
* Each user must review changes that widen the configuration they previously accepted.
* Workspace sources and their mount protection must ship together.
* Existing merge rules must stay consistent across configuration layers.

## Considered Options

* Keep ADR 0006's named TOML files in one fixed directory.
* Read project-local `./corb.toml` with a deny-write rule and the trust gate.
* Select a separate global configuration through `CORB_CONFIG_DIR` for each project.
* Use workspace directories in ordered sources, shared through Git like dotfiles.

## Decision Outcome

Chosen option: "Workspace directories in ordered sources", because teams can
share complete definitions while each user keeps personal sources and trust.

This keeps ADR 0006's rule: configuration stays outside every mount.
It replaces that ADR's file layout with workspace directories in several sources.
Project-local `./corb.toml` stays rejected.
A protected in-repository file needs protection beyond the existing guard.
An external workspace needs no such protection and can set every supported workspace option.

### Workspace identity and contents

A workspace is a directory at `<source>/<name>/`.
The name is one path component, and the directory name identifies the workspace.
The top-level `name` in `corb.toml` remains a session label.
It does not identify the workspace or its trust record.

Each directory holds:

* `corb.toml`, with the global `config.toml` schema except `[workspaces]`.
* `corb.sum`, with authenticated shareable input pins.
* Workspace-only layer definitions through `[image.layer]`.

Directories keep related configuration and pins together, unlike the reserved
single-file layout. A workspace can set secrets, mounts, push permission and
every other global option except `[workspaces]`.
Corb rejects `[workspaces]` in a workspace file because shared configuration
must not add sources to a user's search path.

### Ordered sources and sharing

The user's global `config.toml` lists workspace sources in order:

```toml
[workspaces]
paths = ["~/corbfiles/workspaces", "~/.config/corb/workspaces"]
```

When `paths` is unset, the default is `corbConfigDir()/workspaces`.
It therefore follows `CORB_CONFIG_DIR`.
Setting `paths` replaces that default.

Later sources override earlier sources.
If a name appears twice, the later source replaces the whole workspace directory.
Corb does not merge files from the two directories.
`corb explain` shows which workspace the later source replaced.
This gives each workspace one complete definition and permits personal overrides.

A team keeps a "corbfiles" Git repository, and each person checks it out.
Git handles sharing. Corb does not need an import command.
Unlike one fixed directory, ordered sources let shared and personal definitions
coexist without copying files.

### Configuration layering

The order is:

```text
built-in defaults < global config.toml < workspace corb.toml < CLI flags
```

Each table keeps its existing merge rule in `src/config/load.ts`.
Directories merge by name. A later entry replaces fields it explicitly sets,
and its `rules` append to the earlier rules.
List-type security settings remain additive.
Global directory entries and global `egress.allow` still apply to workspace runs.

An additive list cannot drop a global item.
A workspace also cannot remove a whole global directory entry or an earlier rule.
It can replace scalar values such as `egress.block-internal-ranges`,
`git.allow-push` and fields in `[policy]`.
It can replace `host`, `mode`, `create`, and `protect-git` on a same-named directory.
A secret's `hosts` also replace the global value, unlike additive security lists.

`mergeConfigLayers` and `evaluateTrust` already support these rules.
Every such widening requires `--trust-config`.
The workspace layer builds on personal defaults instead of replacing them.
The `CORB_CONFIG_DIR` workaround replaces global configuration and trust records
instead. `CORB_CONFIG_DIR` remains supported.

### Selection and the positional directory

Users can select a workspace explicitly with `corb run --workspace <name>`.
Corb can also select by path when a workspace's directory host contains the
positional directory, or equals it.
Only workspace `[[dir]]` entries with a `host` count.
Host-less entries never select a workspace.

If several workspaces match, Corb reports an error and names the candidates.
If several hosts within one workspace match, the deepest host wins.
Path selection loads every valid winning file. A broken file causes an error even when another workspace matches.
Only hosts set in the workspace file count. Inherited global hosts do not count.

If none matches, Corb uses the global configuration alone, as today.
These two selection methods support saved definitions and ordinary directory
runs without guessing between matching candidates.

If the positional directory matches a workspace host, that entry becomes primary.
Corb adds no extra mount for a directory inside that host. Pi starts at the mount root.
Otherwise, it adds the positional directory after the workspace layer, as today.
A basename that conflicts with a hosted merged entry is an error and suggests `--dir NAME=HOST`.
A same-named host-less entry remains allowed.

`--workspace <name>` without DIR adds no positional mount.
It does not automatically mount the current directory. Global configured mounts still apply.
The first hosted entry in the workspace's own file supplies the default primary.
If there is no such entry, an explicit `--primary` must name a hosted global or CLI entry.

### Portable host paths

Corb expands `~` and `$HOME` in `[[dir]] host` values.
Relative values resolve against the user's global `[workspaces] projects-root`.
This keeps shared definitions independent of `/home/<user>/...` paths.
`projects-root` stays personal because each user chooses where projects live.

A relative `host` without `projects-root` is an error.
This also applies to global `config.toml` and changes earlier behaviour.
Before DAR-9, `path.resolve` in the resolver and session code resolved relative
or literal `~` values against the current directory.
The new resolver expands home prefixes and rejects relative hosts without `projects-root`.
Empty hosts and partial prefixes such as `~bob/x`, `${HOME}/x`, and `$OTHER/x` are errors.
CLI `--dir` hosts also expand home prefixes, but relative CLI hosts still use cwd.

The new rule replaces that accidental dependence on the current directory.
Expansion happens before the mount guard and before trust hashing.
The guard and trust comparison therefore see the paths Corb will actually mount.

### Personal trust

`trusted.json` stays in the user's own configuration directory, never in a
workspace source. A workspace run uses this key:

```text
workspace:<name>:<resolved dir>
```

`<resolved dir>` is the matched workspace entry's resolved host when DIR is
inside it or absent. If Corb adds DIR as an extra mount, the key uses that
resolved positional directory instead.
Corb canonicalizes workspace host paths through symlinks for these keys.
With no DIR and no workspace-owned host, the explicit primary supplies the key's host path.
All subdirectories of one workspace host therefore share one trust record.
Runs without a workspace keep today's plain path key.

Corb does not reuse old path-keyed records for workspace runs.
The first workspace run needs `--trust-config` once.
When `git pull` brings a widening change, Corb shows the itemised difference
and requires `--trust-config`. `TrustConfirmationRequiredError` already prints
that difference. This is each user's review step for shared changes.

Shared acceptance records let one teammate approve changes for another.
Personal records preserve each user's decision instead.
A dotfiles checkout of the whole configuration directory is unsupported.
Users must never commit `trusted.json`.
DAR-10 refuses a source or child directory that contains that file.

### Protection of sources and directories

Every workspace source and every workspace directory joins the mount guard's
forbidden list. Corb resolves each through symlinks.
The existing list already covers the configuration directory, state directory
and an explicit `audit.path`.
The guard rejects overlaps in either direction.

DAR-10 ships this protection with workspace sources.
Unprotected sources let an agent rewrite future configuration.
The earlier guard resolved only the configuration directory. It did not protect linked sources beneath it.

For example, `~/.config/corb/workspaces` can link to a checkout beneath `~/src`.
Before DAR-10, both `corb run ~/src` and `--dir x=~/.config/corb/workspaces:rw` passed
the guard in that case. The extended guard rejects both overlaps.

### Implied allowed hosts

Corb adds brokered providers' API hosts to `egress.allow` automatically.
DAR-14 applies this before trust. DAR-9 includes the workspace layer in that merge.
DAR-17 names the workspace when its file sets the provider. Other provider sources remain global.

Layer runtime hosts also become implied through the shared recipe.
`corb explain` shows each implied host and its source.
A newly implied host counts as widening and requires personal acceptance.

This amends [ADR 0012](0012-host-brokered-oauth-providers.md), which originally
required explicit network allowance for a login.
Implied API hosts replace the need to repeat the provider's required hosts manually.
Secret `hosts` still do not grant network access.
That separation remains deliberate, as documented in `docs/configuration.md`.

### Open questions

* DAR-22 defines the strict version-1 `corb.sum` format. DAR-23 implements its lifecycle.
* How will `corb ls` show the workspace a session used? Its WORKSPACE column
  currently lists mounted directory names.

### Consequences

* Good, because shared workspace definitions stay outside the agent's writable mounts.
* Good, because ordered sources support shared defaults and complete personal overrides.
* Good, because workspace runs retain global settings and the existing merge rules.
* Good, because portable paths avoid hardcoded home directories in shared definitions.
* Good, because each user reviews widening changes through their own trust records.
* Bad, because configuration still needs a separate checkout or directory outside the project mounts.
* Bad, because additive lists, directory entries and rules cannot remove global settings from a workspace.
* Bad, because even previously working relative global host paths now need `projects-root`.
* Bad, because old path-keyed acceptance does not cover a workspace's first run.
* Neutral, because scalars, same-named directory fields and secret host lists still replace earlier values. Widening requires acceptance.
* Neutral, because sharing the whole configuration directory through dotfiles is unsupported. DAR-10 rejects sources containing `trusted.json`.
* Neutral, because shared pins describe reusable inputs while exact-base generation state stays local.


## Production layer implementation

The winning raw workspace controls definition and pins for all image preparation commands.
Explicit name selection needs no primary mount. Normal run retains its existing session assembly and personal trust flow.
A reusable input graph contains no base, installed delta, checkpoint, local path or Gondolin build ID.

Each compatible recipient performs its own APK transaction and SDK copy on an exact local base.
Immutable generations are local caches. Separate base OCI commands distribute raw SDK assets when needed.
See [the production workflow](../layers.md) for commands and trust, service and recovery limits.