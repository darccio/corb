# Everyday development walkthrough

This guide takes you from an existing repository to a reviewed feature. Complete
[Getting started](getting-started.md) once to build Corb, build its VM image, and
configure a model credential. Examples below use the linked `corb` command;
without linking, use `node /absolute/path/to/corb/src/cli.ts` instead.

## Choose a project and branch

A workspace is the host directories and settings you give a session. To start a
new workspace, point Corb at an existing directory. There is no workspace
creation command or registration step.

On the host, choose a project path:

```bash
project="$HOME/Code/packet-loss"
```

For an existing repository, create a feature branch:

```bash
cd "$project"
git switch -c feat/export-report
```

For a brand-new project, create the directory and initialize Git on the host
first, then create your branch:

```bash
mkdir -p "$project"
cd "$project"
git init
git switch -c feat/export-report
```

Corb uses the checkout you provide. It does not clone the repository, create a
Git worktree, install dependencies, or run a repository setup script.

## Apply repository-specific setup

Corb reads `~/.config/corb/config.toml` by default. It does not discover
`corb.toml`, `.corb/`, or other Corb policy files in your repository. All
`[[dir]]` entries in the selected config participate in every run using it.
If the default settings already fit your project, continue to
[Inspect the workspace and start Pi](#inspect-the-workspace-and-start-pi).

For settings specific to this project, create a separate host configuration
directory. For a new configuration, copy your default file as a starting point:

```bash
export CORB_CONFIG_DIR="$HOME/.config/corb/projects/packet-loss"
mkdir -p "$CORB_CONFIG_DIR"
cp "$HOME/.config/corb/config.toml" "$CORB_CONFIG_DIR/config.toml"
```

The selected file replaces the default config; it does not inherit it. Keep
the provider, secret bindings, and network destinations the project needs, and
remove any copied mounts that do not belong in this workspace. Keep this
directory outside every mount.

For example, append a rule to hide this repository's local environment files.
If the copied file already has a `packet-loss` entry, edit its rules instead:

```bash
cat >> "$CORB_CONFIG_DIR/config.toml" <<'TOML'

[[dir]]
name = "packet-loss"
rules = [
  { glob = "**/.env*", mode = "hidden", reason = "local credentials" },
]
TOML
```

The name matches the project directory's basename; the positional project
path supplies its host path and read/write mode. This config is intended for
that project. See [Workspaces](workspaces.md) for merge behavior.

Keep using the same `CORB_CONFIG_DIR` for subsequent runs. In a new terminal,
export it again. `unset CORB_CONFIG_DIR` returns to the default configuration.
Each configuration directory has its own `trusted.json`.

Repository instructions are handled by Pi separately. Pi loads a root
`AGENTS.md` or `CLAUDE.md` at startup; `AGENTS.override.md` takes precedence
when present. It searches from its guest working directory, so host parent
directories and your host `~/.pi/agent` settings are not automatically exposed.
Ask it to read instructions in any additional mounted repository before
working there.

Pi can also load project `.pi/settings.json` and resources. It may ask you to
trust those project files inside its terminal. That is Pi's own trust decision;
Corb's `--trust-config` accepts Corb's mounts and policy. Pi project settings
cannot grant additional filesystem or network access through Corb.

Check the repository's README for required tools and setup commands. The stock
image includes Node, Git, `gh`, and shell tools, but removes `npm` and `npx` and
does not include Go or Python. Host-installed tools are not automatically
available in the VM. For a project needing additional tools, build a custom
[image](cli.md#image-build), select it with `[vm].image`, and configure the
destinations its setup and tests need in `egress.allow`. Installing dependencies
on the host does not guarantee they will work in the Alpine Linux guest,
especially when they include native binaries.

## Inspect the workspace and start Pi

```bash
corb explain "$project"
corb run "$project" --trust-config
```

`explain` shows the mounts, model settings, allowed destinations, and trust
verdict without starting a VM. Check that these match the project you intend
to work on. `--trust-config` accepts Corb's persistent configuration on the
first run; later runs can omit it unless that configuration widens access.

The run opens Pi's interactive terminal in `/work/packet-loss`. One Corb session
has one VM and one configured Pi process. Adding another repository mount gives
that same agent more context. Corb has no agent-selection or agent-team command;
`[agent]` selects Pi's provider and model.

| Item | What happens |
|---|---|
| Files in the read/write project mount | Edits immediately change your host checkout and remain after exit. |
| Branch, staged changes, and commits | Belong to that same checkout on the host. |
| Guest home, temporary files, and default Pi history | Disappear when the VM closes. See [Keep conversation history](#keep-conversation-history-across-runs). |
| Accepted Corb configuration and audit records | Remain on the host, outside the workspace. |

Each `corb run` example opens a foreground Pi session. Use `/quit` to leave it
before running the next host command in that terminal. Ending a session keeps
its edits; use Git on the host to review or undo them.

## Develop and review a feature

In Pi's terminal, give it a concrete task and a review point:

```text
Read the repository instructions and README. Add CSV export for the current
report. First describe the files you would change and how you would test it;
wait for my review before editing.
```

After reviewing the plan, ask Pi to implement it and run the relevant checks
available in the guest. Its file edits and shell commands operate on the
mounted checkout under Corb's policy. You can also supply an initial prompt
from the host; everything after `--` goes to Pi:

```bash
corb run "$project" -- "Read the README and propose a plan for CSV export."
```

Review the result from another host terminal, or after leaving Pi with `/quit`:

```bash
cd "$project"
git status --short
git diff
```

Run the repository's normal tests on the host when its toolchain is unavailable
in the guest. Commit and push on the host after review. Guest Git transport
needs a permitted host and repository in `[git]`; pushes are disabled by
default. See [Git transport](configuration.md#git-transport) if the agent
needs remote access. Corb does not automatically commit changes or open a PR.

## Add context or run another agent

To give the same Pi process read-only access to another repository:

```bash
corb run "$project" --dir "reference=$HOME/Code/reference:ro"
```

Create the reference checkout on the host first. Pi can read it at
`/work/reference`; tell it which files matter. Include the same `--dir` flag
in `corb explain` when inspecting this run. Add `--trust-config` if required.

For independent feature sessions, prepare separate checkouts and run Corb on
each in a separate terminal. Each run gets its own VM and Pi process. Two
sessions on the same host directory share edits, the index, and the branch;
VM isolation does not give them independent checkouts.

## Keep conversation history across runs

A fresh run starts a fresh VM. To preserve Pi history, give it a writable host
directory and point its session storage at the guest mount:

```bash
history_dir="$HOME/.local/share/corb/pi-history/packet-loss"
mkdir -p "$history_dir"
corb run "$project" --dir "history=$history_dir:rw" \
  -- --session-dir /work/history
```

After quitting, continue the most recent conversation with the same mount:

```bash
corb run "$project" --dir "history=$history_dir:rw" \
  -- --session-dir /work/history --continue
```

Use a separate history directory for each project. These are Pi transcripts,
not VM snapshots: guest processes and temporary files still start afresh.

## Inspect, preview, and stop a session

From another host terminal:

```bash
corb ls
corb attach SESSION_ID
```

Replace `SESSION_ID` with an identifier from `ls`. `attach` opens a new shell
in the running VM at `/work`; `cd /work/packet-loss` to inspect the project or
run a check. Leaving that shell with `exit` leaves Pi running. It does not
reconnect to Pi's terminal.

For a development server, start the session with a port exposed:

```bash
corb run "$project" --expose 3000
```

Then ask Pi to start the project's server on guest loopback port 3000, if its
toolchain is available. Open the host URL Corb prints; `corb ls` also records
it. The URL works while the VM and server are running.

Use `/quit` in Pi to finish normally, or `corb kill SESSION_ID` from the host
to stop its session. Both tear down the VM and keep changes in ordinary
read/write mounts. `corb gc --dry-run` previews cleanup of stale session records.

If startup or a command fails, use `corb doctor` for host dependencies,
`corb explain "$project"` for policy, and the host audit log at
`~/.local/state/corb/audit.jsonl` for policy denials. Config changes take effect
on the next run; widening persistent access requires `--trust-config` again.
