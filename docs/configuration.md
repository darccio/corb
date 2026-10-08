# Configuration

Corb reads one TOML configuration file. Unknown keys and invalid values fail at
parse time.

## Location

```bash
~/.config/corb/config.toml
```

`CORB_CONFIG_DIR` selects a different configuration directory. Corb reads
`config.toml` and stores `trusted.json` there. The override replaces the default
directory.

Host paths in TOML are used as written; `~` is not expanded. Use absolute paths.
Configuration, state, and the audit file must not overlap a mounted directory.

Inspect the effective settings with `corb explain DIR` or
`corb explain DIR --json`.

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
prevents the session from starting; `optional = true` permits it to be absent.

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

The optional GitHub API table adds HTTP method and path restrictions for that
API; it does not enable its host on its own. With the table absent, this
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
writes use an in-memory overlay instead of changing the host file.

## Command filtering

Command filters are supplied by shims in the guest image. The stock image shims
`git` and `gh`; Corb's runtime only dispatches those tool names and generates
fixed policy tables for them. TOML does not expose a list of commands to shim
or configurable subcommand and flag rules.

Supporting another command requires matching image and runtime changes. See
[Command filtering](security.md#command-filtering) for how the shims work and
where enforcement happens. The `[policy]` settings below control the built-in
content checks; they do not configure filters for arbitrary commands.

## Git transport

```toml
[git]
allow-hosts = ["github.com"]
allow-repos = ["bec/packet-loss"]
allow-push = false
```

`git.allow-hosts` and `git.allow-repos` constrain Git transport on the host,
independently of command shims. Pushes are disabled by default.

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

Named workspace files and multiple named agent profiles are not implemented.
There is one agent declaration per effective configuration.
