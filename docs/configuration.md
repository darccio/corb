# Configuration

Corb reads global and selected workspace TOML files. Unknown keys and invalid values fail at parse time.

## Location

```bash
~/.config/corb/config.toml
```

`CORB_CONFIG_DIR` selects a different configuration directory. Corb reads
`config.toml` and stores `trusted.json` there. The override replaces the default
directory.

Corb does not read policy files from the repository. Use an external [workspace definition](workspaces.md) for project settings. Pi's repository
instructions and `.pi` settings are separate from Corb's configuration.

Corb expands leading `~` and `$HOME` in `[workspaces] paths`, `projects-root`, and `[[dir]] host`.
Relative hosts use the global `[workspaces] projects-root`.
Without it, a relative host is an error. This also applies to global `config.toml`.

Other path settings keep their existing behavior. This includes `audit.path`.
Configuration, state, and the audit file must not overlap a mounted directory.

Inspect the effective settings with `corb explain DIR` or
`corb explain DIR --json`.

## Workspace sources

```toml
[workspaces]
paths = ["~/corbfiles/workspaces", "~/.config/corb/workspaces"]
projects-root = "~/Code"
```

Each source contains workspace directories at `<source>/<name>/corb.toml`.
When `paths` is unset, Corb uses `<configDir>/workspaces`.
The default follows `CORB_CONFIG_DIR`.
An explicit list replaces that default. `paths = []` disables sources.

Each path must be absolute after leading `~` or `$HOME` expansion.
Duplicate expanded paths are errors.

Later sources replace whole same-named workspace directories from earlier sources.
The `[workspaces]` table is allowed only in the global `config.toml`.
Shared workspace files cannot add sources.
Keep `trusted.json` in the personal config directory and outside every source.

Sources and workspace files remain outside all mounts. The guard resolves their symlink targets too.
Missing sources stay protected. Dangling source symlinks fail with an error.

`corb explain` shows the listing, and `corb doctor` checks it.
Select a definition with `corb run --workspace <name>`, or let Corb select it by DIR.
With no DIR, explicit workspace selection does not mount cwd.
Workspace files layer above global settings and below CLI flags.
Read [selection and primary directory](workspaces.md#selection-and-primary-directory) for matching and error rules.

`projects-root` must be absolute after home expansion. It resolves relative hosts in both TOML layers.
A workspace file cannot set it. A host may use `~`, `~/x`, `$HOME`, or `$HOME/x`.
Empty hosts and forms such as `~bob/x` or `${HOME}/x` are errors.
Relative `--dir` hosts still resolve against cwd after home expansion.

## Agent and secrets

```toml
[agent]
provider = "anthropic"
model = "claude-opus-4-5"

[secrets.ANTHROPIC_API_KEY]
hosts = ["api.anthropic.com"]

[secrets.GITHUB_TOKEN]
hosts = ["api.github.com"]
optional = true
```

`provider` and `model` are forwarded to Pi. Corb does not validate
provider-specific model names or select a different agent executable.

Each secret name identifies a host environment variable. `hosts` restricts where
its placeholder can be expanded into the real value. A missing required variable
prevents the session from starting. `optional = true` permits it to be absent.

The secret binding does not itself grant network access. Add each required
destination to `egress.allow`.

Optional credential verification is configured separately:

```toml
[secrets.ANTHROPIC_API_KEY.verify]
url = "https://api.anthropic.com/v1/models"
header = "x-api-key"
expect-status = [200]
```

`corb doctor --verify-secrets` makes a real request with the real credential on
the host. Normal `doctor` does not. A `header-prefix` can supply a provider's
required prefix, such as `"Bearer "`.

### Subscription logins

Some providers use a subscription login instead of an API key. Corb runs the
login on the host and keeps the tokens there. `openai-codex` (ChatGPT Plus or
Pro) is the only such provider so far.

```toml
[agent]
provider = "openai-codex"
model = "gpt-6.1-sol"

[egress]
allow = ["pi.dev"]
```

Log in once with `corb login openai-codex`. Corb stores the login in
`~/.local/state/corb/credentials/` (or `$CORB_STATE_DIR/credentials/`). The
file is readable only by you. Every Corb session on the host uses the same
login, and Corb refreshes it when it is close to expiry.

No `[secrets.*]` entry is needed. Corb adds the provider's API hosts to
`egress.allow` automatically. `corb explain` shows each host as implied and
names its source. If an earlier trusted run did not allow the host, the next
`corb run` asks for `--trust-config` once. `auth.openai.com` is not needed in
the guest, because the login and every refresh happen on the host.

The provider can also be set in a workspace's `[agent]` table.

`corb run` stops before it boots the VM if there is no stored login. Pick a
model from Pi's `/model` list for the provider.

## VM and resources

```toml
[vm]
image = "corb:0.1.0"
memory = "4G"
cpus = 4
max-session = "4h"
limits = { memory-max = "6G", pids-max = 1024, cpu-quota = "400%" }
```

`memory` and `cpus` size the guest. `max-session` sets the wall-clock session
limit. Host `limits` use a systemd user scope on supported Linux hosts.

If the required cgroup controllers are unavailable, Corb reports that the
affected limits are not applied and continues. VM sizing is separate from host
cgroup limits.

## Network access

```toml
[egress]
allow = ["api.anthropic.com", "pi.dev", "api.github.com"]
block-internal-ranges = true
websockets = false

[egress.github-api]
methods = ["GET", "HEAD"]
deny-paths = ["**/actions/secrets/**"]
```

`egress.allow` lists permitted hosts for outbound requests from any guest
process. Configure the destinations required by your workflow explicitly.
Corb adds brokered providers' API hosts automatically and shows their source in `corb explain`.

The optional GitHub API table adds HTTP method and path restrictions for that
API. It does not enable its host on its own. With the table absent, this
additional API gate is inactive.

## Directory entries

```toml
[[dir]]
name = "reference"
host = "/home/bec/Code/reference"
mode = "ro"

[[dir]]
name = "scratch"
host = "/home/bec/.cache/corb/scratch"
mode = "rw"
create = true
rules = [
  { glob = "**/.env*", mode = "hidden", reason = "local secrets" },
]
```

`name` identifies a mount at `/work/<name>`. It must be a single path component.
`create = true` creates a missing host directory before startup.

Global directory entries are included in every run. Read [Workspace
resolution](workspaces.md#configuration-resolution) for precedence and
positional-directory behavior.

Rule modes are `hidden`, `deny-read`, `deny-write`, and `shadow-write`. Shadow
writes go to memory instead of changing the host file. Reads, metadata, and
listings still show the host file. This mode does not provide an overlay.

### Built-in Git protection

Every read/write mount gets built-in `deny-write` rules before its user rules.
This applies even when the mount has no Git repository at startup. Read-only
mounts get no built-in rules because their provider already blocks writes.

The rules protect these paths relative to the mount root:

```text
.git
.git/config*
.git/commondir
.git/hooks/**
.git/worktrees/*/commondir
.git/worktrees/*/config*
.git/modules/**/config*
.git/modules/**/commondir
.git/modules/**/hooks/**
```

The `.git` rule protects that entry itself. It also blocks creating or replacing
a root Git directory or gitfile. `config*` covers config files and their locks.
It includes `config.worktree`. Directory renames into or out of a protected
subtree fail too. Ordinary edits, `git add`, `git commit`, and unrelated
directory renames remain available.

`protect-git` is a per-directory boolean that defaults to true. To disable it
for the positional directory, use a host-less entry with its basename:

```toml
[[dir]]
name = "packet-loss"
protect-git = false
```

Disabling protection requires `--trust-config`. Mode changes between `rw` and `ro` also
require confirmation for protected mounts. Existing trust records remain trusted
when Corb adds these rules during an upgrade. Adding user rules still narrows
policy. `corb explain` shows the built-in rules separately. JSON stores them
in `builtin-rules`, which cannot be set in TOML.

The protection blocks config writes needed by `git remote add`, `branch -u`,
`push -u`, `checkout --track`, and `submodule init` inside the guest.
[DAR-19](https://linear.app/darccio/issue/DAR-19/copy-on-write-path-rule-mode-so-the-guest-can-change-git-config-safely)
tracks support for safe config edits. `git init` and `git clone <url> .` fail
at the mount root. A submodule branch named `config` becomes read-only because
its metadata path matches `config*`.

Read the [security limits](security.md#git-metadata-protection) before running
host Git against files the agent changed.

## Command filtering

Shims in the guest image supply command filters. The stock image shims
`git` and `gh`. Corb's runtime only dispatches those tool names and generates
fixed policy tables for them. TOML does not expose a list of commands to shim
or configurable subcommand and flag rules.

Supporting another command requires matching image and runtime changes. See
[Command filtering](security.md#command-filtering) for how the shims work and
where enforcement happens. The `[policy]` settings below control the built-in
content checks. They do not configure filters for arbitrary commands.

## Git transport

```toml
[git]
allow-hosts = ["github.com"]
allow-repos = ["bec/packet-loss"]
allow-push = false
```

`git.allow-hosts` and `git.allow-repos` constrain Git transport on the host,
independently of command shims. Corb disables pushes by default.

## Content policy and audit

```toml
[policy]
enabled = true
secret-scan = true
max-changed-files = 40
fail-open = true

[audit]
path = "/home/bec/.local/state/corb/audit.jsonl"
```

The content checks inspect Git commit and push payloads for configured limits,
selected secret-shaped patterns, and path-rule violations. The scanner is a
fixed set of patterns, not an exhaustive secret detector.

`fail-open` defaults to `true` and controls unexpected errors inside the host
checker. Set it to `false` to deny an operation when that checker fails
internally.

Guest-side content collection and transport failures still proceed with a
diagnostic, regardless of this setting. It does not make the entire
content-check path fail closed.

The default audit file is `~/.local/state/corb/audit.jsonl`. `CORB_STATE_DIR`
selects a different state directory. An explicit audit path must stay outside
all workspace mounts.

## Unsupported settings

Non-empty `agent.extensions` and any `agent.append-system-prompt-file` are
rejected because they are not wired to Pi. An empty extension list is accepted.

Multiple named agent profiles are also not implemented.
There is one agent declaration per effective configuration.
