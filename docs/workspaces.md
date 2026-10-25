# Workspaces

A workspace definition is a directory with a `corb.toml` file outside every mount.
Its directory name identifies the workspace. A session combines that definition
with global settings and any CLI overrides.

Use `corb run --workspace <name>` to select a definition.
You can also run `corb run DIR`. Corb selects a workspace whose own host paths contain DIR.
If no workspace matches, Corb uses global settings and adds DIR as a mount.

There is no creation or registration command. Corb does not read repository-local
policy files or run setup scripts. Follow the [development
walkthrough](walkthrough.md) for a complete example.

Each run starts a fresh VM and one Pi process. Multiple mounts belong to that
same session and agent. Mounted host files persist. Guest-only files and default
Pi history do not. The walkthrough shows how to mount persistent history.

## Directory mounts

```bash
corb run ~/Code/packet-loss \
  --dir reference=/home/bec/Code/reference:ro \
  --dir scratch=/home/bec/Code/scratch:rw \
  --trust-config
```

| Directory   | Guest path          | Access     |
|-------------|---------------------|------------|
| packet-loss | `/work/packet-loss` | Read/write |
| reference   | `/work/reference`   | Read only  |
| scratch     | `/work/scratch`     | Read/write |

The mounts expose the host directories directly. Corb does not copy their
contents or create separate checkouts or Git worktrees. Sessions that mount
the same host path share its files, and ordinary read/write edits are visible
to the host and other sessions using that directory.

Replace the example paths with existing directories on your host.
Without `--workspace`, an omitted DIR defaults to your current directory.
If DIR is outside the selected workspace's own hosts, Corb adds it as a read/write mount.
Each additional directory gets a guest path based on its name.

Pi starts in the matching workspace mount, or the added positional mount. `--primary scratch` changes its
working directory to `/work/scratch`. All configured mounts remain available.

To make the positional directory read only, override its generated mount by
name:

```bash
corb run ~/Code/packet-loss \
  --dir "packet-loss=$HOME/Code/packet-loss:ro"
```

This example assumes you have already accepted the persistent configuration. Add
`--trust-config` when required.

## Configuration resolution

```text
built-in defaults
  + global config.toml
  + selected workspace corb.toml
  + positional directory, only when outside the workspace's own hosts
  + CLI overrides
  = effective session configuration
```

Every global `[[dir]]` participates in every run. Global `egress.allow` values
also remain in workspace runs. A workspace can set every option except `[workspaces]`.
That table stays in the personal global file.

Lists only add. A workspace cannot remove a global directory entry or an earlier rule.
Scalars replace. This covers VM settings, provider, model, policy, and Git push permission.

Directories merge by name. Later `host`, `mode`, `create`, and `protect-git` fields replace earlier values.
Rules for the same directory append across layers. Secret `hosts` replace instead of appending.
The trust check flags every widening change.

A workspace that sets a brokered `[agent] provider` gets its API hosts added to `egress.allow`.
`corb explain` marks them as implied and names the workspace.
If a change implies a new host, the next run needs `--trust-config`.

Without a workspace match, the positional directory retains its existing behavior.
Its generated `rw` mode overrides a global `ro` entry with the same name.
Use a CLI override when you need a read-only positional mount.

## Selection and primary directory

`--workspace <name>` selects the winning copy from the ordered sources below.
An unknown or invalid name is an error. Without that flag, Corb loads every valid winning workspace.
A broken file is an error even when another workspace matches DIR.

Only hosts set in a workspace's own file count for path selection.
Host-less entries and hosts inherited from global entries do not count.
Corb compares paths after resolving symlinks. More than one matching workspace is an error that names the candidates.
If several hosts within one workspace contain DIR, the deepest host wins.

When DIR equals or is inside a workspace host, Corb adds no extra mount.
That host's mount becomes primary. Pi starts at its root, such as `/work/project`, even for a subdirectory DIR.
Otherwise Corb adds DIR after the workspace layer.
If its basename conflicts with a hosted mount name, Corb reports an error and suggests `--dir NAME=HOST`.
A same-named entry without a host is allowed.

With `--workspace <name>` and no DIR, Corb does not mount cwd automatically.
Global configured mounts still apply. The first hosted entry in the workspace's own file becomes primary.
If the file has no hosted entry, you must give `--primary` for a hosted global or CLI entry.
Use `--primary NAME` to choose another mount.

## Portable host paths

Corb expands a complete leading `~` or `$HOME` component in every `[[dir]] host`.
Relative hosts use the global `projects-root`:

```toml
[workspaces]
projects-root = "~/Code"
```

A workspace file can then use `host = "packet-loss"` for `~/Code/packet-loss`.
Without `projects-root`, a relative host is an error. This also applies to global `config.toml`.
`projects-root` must be absolute after home expansion and cannot appear in a workspace file.
Empty hosts and forms such as `~bob/x`, `${HOME}/x`, and `$OTHER/x` are errors.

`--dir NAME=HOST` also expands `~` and `$HOME`. Relative CLI hosts still use cwd.
Corb expands hosts before selection, the mount guard, and trust hashing.
This does not expand `~` in `audit.path` or other path settings.

## Rules within a directory

```toml
[[dir]]
name = "packet-loss"
rules = [
  { glob = "**/.env*", mode = "hidden" },
  { glob = "**/*_test.go", mode = "deny-write" },
]
```

When you run the `packet-loss` directory, the generated mount supplies its host
path and the rules above remain attached. Globs are relative to that mount's
root.

This host-less entry must match the basename of an added positional directory.
It does not apply when DIR is inside a workspace host. Put rules and `protect-git`
on that workspace entry instead. Other host-less entries need a host path before a real run.

`hidden` makes a path absent from listings and access. `deny-read` blocks reads
and writes. `deny-write` preserves reads while refusing edits.

These restrictions apply through the host filesystem provider to shell commands
and other guest processes, as well as Pi's own file tools.

Even without a repository at startup, every read/write mount gets built-in
Git protection. These `deny-write` rules run before user rules. They
protect the root `.git` entry, config files and locks, hooks, and `commondir`.
They also cover metadata under `.git/modules/**` and `.git/worktrees/*`.
Read-only mounts already block writes and need no built-in rules.

Set `protect-git = false` in a `[[dir]]` entry to disable this protection for
that mount. For the positional directory, use a host-less entry with its
basename, as in the example above. See the [rule list and side effects](configuration.md#built-in-git-protection)
and the [security limits](security.md#git-metadata-protection). Nested
repositories and a submodule's own `.git` file remain outside this protection.

## Trust and inspection

```bash
corb explain ~/Code/packet-loss
corb run ~/Code/packet-loss --dry-run
corb workspace ls
corb workspace show packet-loss
corb explain --workspace packet-loss --trusted
```

Corb keeps personal acceptance records in `~/.config/corb/trusted.json`.
Runs without a workspace use the positional directory's resolved absolute path as the key.
Workspace runs use `workspace:<name>:<resolved dir>`.

When DIR is inside a workspace host, that host's resolved path supplies `<resolved dir>`.
All subdirectories of that host share one record.
With no DIR, Corb uses the default primary host, or the explicit primary when the workspace has no own host.
When Corb adds DIR as an extra mount, the key uses that resolved DIR instead.

Corb does not reuse old path-keyed records for workspace runs.
The first workspace run therefore needs `--trust-config` once.

A first run, or a change that widens policy, requires `--trust-config`. Examples
include a new permitted host, a mount change from `ro` to `rw`, Git push
permission, and removal of a filesystem rule. Narrowing changes apply without
confirmation.

Disabling Git protection requires confirmation. Mode changes between `rw` and `ro` also
require confirmation for protected mounts. Adding protection to an older trust record needs no new
acceptance. `corb explain` lists built-in rules separately from user rules,
and its JSON output includes `builtin-rules` on each directory.

CLI overrides are treated as explicit user choices. They affect the running
session but are excluded from the stored trust snapshot.

After `git pull` updates shared definitions, use `corb workspace ls` to find changed settings.
Review one workspace with `corb workspace show <name>`.
Use `corb explain --workspace <name> DIR --trusted` to review a specific extra mount.
Both print the full accepted snapshot alongside current settings and the trust comparison.
Accept a widening change with `corb run --workspace <name> --trust-config`.

`narrowed` means the current config removes access and can run without confirmation.
Removing an allowed host narrows access.
Changing `rw` to `ro` also narrows an unprotected mount.
Protected mode changes still require confirmation, as described above.
The old snapshot stays until a run uses `--trust-config` again.
An order-only difference is shown separately and does not affect trust.

Implied hosts are marked in current config only.
Accepted snapshots include the allowed hosts but no source metadata, so the snapshot carries a note instead.
Secret names and host metadata are visible. Secret values are never printed.

`workspace ls` lists records for missing workspace names after its table.
These orphan records stay in the personal trust store. Listing never deletes them.
An extra-mount record for a deleted directory shows `cannot compare` in `show`.
A workspace without own hosted mounts still shows its details and extra-mount records.
Run that workspace with `--workspace <name> DIR`.

## Workspace sources

A workspace definition is a directory at `<source>/<name>/`, with one `corb.toml` file.
The directory name identifies the workspace. A `name` inside its TOML remains a session label.
The file uses the global configuration schema except `[workspaces]`, which stays personal.
Image and layer pins in `corb.sum` will follow in DAR-16.

The global `config.toml` lists source directories in order:

```toml
[workspaces]
paths = ["~/corbfiles/workspaces", "~/.config/corb/workspaces"]
```

When `paths` is unset, the default is `<configDir>/workspaces`.
It follows `CORB_CONFIG_DIR`. An explicit list replaces that default.
Use `paths = []` to disable all sources.
Source paths also expand a leading `~` or `$HOME`.

Later sources replace earlier workspaces with the same name.
They replace the whole directory instead of merging its files.
`corb explain` shows source order and missing paths.
It marks invalid names and replaced copies.
`corb doctor` reports source counts and problems.
A missing source is allowed, but a dangling source symlink is an error.

A team can share a "corbfiles" Git checkout and add its workspace directory as a source.
Each user keeps `trusted.json` in their personal config directory.
Never commit `trusted.json` to a source. Corb refuses trust records in a source or its child directories.

Corb refuses mounts that overlap any source or workspace directory.
This covers replaced and invalid copies.
The guard resolves symlinks and protects linked `corb.toml` and existing `corb.sum` targets too.
Even a missing source stays protected when a mount contains its future location.

`CORB_CONFIG_DIR` remains supported. It selects the personal configuration directory,
its `trusted.json`, and the default workspace source. Workspace files still layer
above that selected global `config.toml`.
