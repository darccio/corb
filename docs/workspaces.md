# Workspaces

A workspace is the collection of host directories and settings used to start a
Corb session. One session can include several repositories, reference material,
and scratch space.

To start a new workspace, prepare a directory on the host and run `corb run DIR`.
There is no creation or registration command. Corb does not read repository-local
policy files or run setup scripts. Follow the [development
walkthrough](walkthrough.md) for a complete example. It covers project-specific
host configuration and Pi's repository instructions.

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

Replace the example paths with existing directories on your host. The positional
directory defaults to your current directory and is automatically mounted
read/write. Each additional directory gets a guest path based on its name.

Pi starts in the positional directory's mount. `--primary scratch` changes its
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
  + positional directory (read/write)
  + CLI overrides
  = effective session configuration
```

Every `[[dir]]` in the global configuration participates in every run. Corb does
not select global mounts according to the project you pass.

Directories merge by name. A later entry overrides the fields it sets. These
include the host path and access mode. Rules for the same directory append across layers.

The positional directory is added after the global file. Its generated `rw` mode
overrides a global `ro` entry with the same name. Use an explicit CLI override
when you need a read-only primary mount.

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

This host-less entry must match the basename of the positional directory on each
run. Other runs need a host path for it or will fail before starting a VM.

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
```

Corb records accepted persistent configuration in `~/.config/corb/trusted.json`,
keyed by the positional directory's resolved absolute path.

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
Only these source paths expand a leading `~` or `$HOME` today.

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

`corb run` does not use workspace definitions yet.
It still takes a directory path and applies the global configuration.
Workspace selection and layering will follow in DAR-9.

A current workaround is to select a different configuration directory:

```bash
CORB_CONFIG_DIR="$HOME/.config/corb/roost-ops" \
  corb run ~/Code/packet-loss --trust-config
```

This reads `roost-ops/config.toml` instead of the global file. It does not
inherit the global configuration and uses its own `trusted.json`. Keep the
configuration directory outside every mounted directory.
