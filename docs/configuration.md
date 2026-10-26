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

## Workspace layer recipes

`[image.layer]` belongs only in a workspace `corb.toml`.
Even an empty global `[image]` table is an error.
`[vm].image` still selects the local base.
The workspace owns one complete recipe. Recipe lists do not merge across sources.
Corb rejects unknown fields and user-written `image.pins`.

```toml
[image.layer]
packages = ["go", "make"]
commands = []
build-hosts = ["dl-cdn.alpinelinux.org"]
hosts = ["proxy.golang.org"]

[[image.layer.runtime-dir]]
path = "/var/log/myapp"
mode = "0755"
owner = "agent"
group = "agent"
```

The parser and inspection commands support these contracts now.
Workspace layer support for image pin/build/push/pull arrives in the integration issue.
A real run with a layer stops before credentials or VM creation until that integration lands.

`corb explain` and `corb run --dry-run` need neither pins nor a local generation.
Missing pins show `corb image pin --workspace <name>`. This command is not available yet.
Malformed or stale pins are errors during inspection.

`packages` is required. Keep `packages = []` for recipes that contain only SDK archives or commands.
Names must match `^[a-z0-9][a-z0-9+_.-]*$` and identify real Alpine `P:` records.
Constraints, virtual dependencies, URLs and APK filenames are errors.
At least one package, payload or command is required.
Package and host lists become sorted sets.

`commands` defaults to `[]`. Corb preserves each command's bytes and their order.
Entries must be nonempty strings without NUL.
These are unpinned root install steps. Integration will run each separately with `/bin/sh -ec` from `/`.
They cannot change base or pinned package records or silently add dependencies.

`build-hosts` defaults to `["dl-cdn.alpinelinux.org"]`. An explicit list replaces that default.
`hosts` defaults to `[]` and implies runtime egress through the existing host policy.
Patterns use the existing `*` substring wildcard rule.
Schemes, paths, ports, whitespace and empty patterns are errors.
Build hosts and archive download hosts grant no runtime access.

### SDK payloads

Each `[[image.layer.payload]]` has the following fields. Only complete `tar.gz` SDK trees are supported.
The URL needs no filename suffix. Integration validates the archive bytes.

| Field | Contract |
| --- | --- |
| `name` | Unique identifier matching `^[a-z0-9][a-z0-9_-]*$`. |
| `url` | Absolute HTTPS archive URL without user information, query or fragment. |
| `sha256` | Expected archive digest, with 64 lowercase hexadecimal characters. |
| `arch` | Exactly `x86_64` or `aarch64`. It must match the selected target. |
| `destination` | Normalized absolute POSIX path at or below `/opt/corb/toolchains/<name>`. |
| `strip-components` | Integer from 0 through 16. Default: 0. |
| `path` | Ordered relative directory paths under the destination. Default: `[]`. |

For Go, use `name="go"`, `destination="/opt/corb/toolchains/go"`, `strip-components=1` and `path=["bin"]`.
Choose the architecture, URL and digest through explicit review of an official Go archive.
Corb does not discover toolchain versions or read hidden version overrides.
A digest pins bytes. It does not authenticate a publisher.

Payload order and each `path` list determine the PATH prefix before the ordinary base PATH.
Duplicate PATH entries and overlapping destinations are errors. Dot and dot-dot path components are also errors.
Architecture mismatches fail before downloads, builds or boots.

### Runtime directories

Each `[[image.layer.runtime-dir]]` has exactly `path`, `mode`, `owner` and `group`.
`path` must be normalized and strictly below `/run` or `/var/log`.
The root paths, duplicates and overlap with internal mount or credential roots are errors.
Corb sorts entries by path.

`mode` is a four-character octal string from `0000` through `0777`. Its default is `0755`.
Required owner and group names must match `^[a-z_][a-z0-9_-]*[$]?$`.
Integration resolves numeric ownership from the actual composed guest accounts. Those numbers stay local.

Integration will create or fix only each declared directory before agent startup and every checkpoint resume.
It must not follow symlinks, delete files or change children recursively.
The declaration starts no service. Service launch, supervision and startup scripts are not schema features.

### Shareable pins

The winning workspace directory owns `corb.sum`, a strict version-1 TOML lockfile.
It preserves independent `target.x86_64` and `target.aarch64` tables.
A target fixes Linux, musl, the Alpine branch and the normalized definition hash.
Package recipes also require signed main/community index identities, one static installer and all candidate closure archives.
Payload-only and command-only recipes have no index, installer or package rows.

Package rows fix name, version, repository, observed APKINDEX `Q1` checksum, archive SHA-256 and a `requested` boolean.
The requested rows equal the recipe package names exactly.
Closure collection must not omit a dependency because the producer base already provides it.
An optional artifact binds the target to `REGISTRY/REPOSITORY@sha256:<digest>`.
Tag-only and inferred registry references are errors.

The definition hash covers normalized UTF-8 JSON in this field order:
`packages`, `commands`, `build-hosts`, `hosts`, `payload`, `runtime-dir`.
It includes defaults, sorted sets and preserved command, payload and PATH order.
Recipe pins have a separate canonical JSON hash without their artifact binding.
Refreshing one target preserves other valid targets and clears the selected target's artifact.
An existing lockfile symlink keeps its link when Corb atomically replaces the validated real target.
Corb refuses to overwrite malformed old content.

Pins contain no base tag, SDK build ID, host path, timestamp, account number or checkpoint hash.
Local generations, output hashes, compatibility receipts and account mappings stay in local state.
Local generation publication never edits `corb.sum`.
Every added, changed or removed recipe or selected target requires fresh trust acceptance.
Changes to another target do not change selected trust inputs.
