# Corb

Corb is a command-line tool that boots a [Gondolin](https://earendil-works.github.io/gondolin/)
micro-VM and mounts host directories as a restricted workspace.
It runs the [Pi](https://pi.dev) coding agent (`@earendil-works/pi-coding-agent`) interactively inside the guest.
Host-side filesystem and network rules constrain every guest process.
Model credentials stay on the host, and policy decisions go into one audit log.

Command shims check selected tool invocations before running their real binaries.
The stock image shims `git` and `gh`.
Support for another tool requires image and runtime integration. See
[`docs/security.md`](docs/security.md) for the enforcement points and limits,
and [`docs/design.md`](docs/design.md) for the full architecture.

The [user documentation](docs/README.md) covers setup, workspaces,
configuration, commands, and the enforcement model.
For the usual operations, follow the [development walkthrough](docs/walkthrough.md):
choose a checkout, apply project settings, develop with Pi, and review its edits.

## Requirements

- **Node.js >= 24.0.0** (`package.json`'s `engines.node`).
- **Go >= 1.26** (`guest/go.mod`). Build the guest helpers with `make guest`.
  An already-built image needs no Go installation.
- **QEMU** (`qemu-system-x86_64` / `qemu-system-aarch64`) and, on Linux,
  read/write access to `/dev/kvm`. Gondolin boots a real, hardware-accelerated
  micro-VM. Host platforms are Linux and macOS.
- **Docker**. `corb image build` runs a `postBuild` step in a container.
  `image/corb-image.json` sets `container.force: true, runtime: "docker"`.
  See `docs/design.md`.
- **`e2fsprogs`** (`mkfs.ext4`, `resize2fs`, `e2fsck`) reachable on `PATH`.
  These tools commonly live only under `/sbin` or `/usr/sbin`.
  `corb image build` accounts for this. Manual commands may need those directories on `PATH`.
- **`cpio` and `lz4`**. These tools assemble the guest initramfs.

Run `corb doctor` after cloning to check all of the above (plus a few
Corb-specific environment traps) against your actual machine.

## Quickstart

Corb is not published to npm yet. Clone the repository and run it from a checkout.

```sh
git clone <this-repository> corb
cd corb
npm install

# Build the Go guest helpers (dropcap, policygate) into
# guest/build/<arch>/ (your host's own GOARCH, e.g. amd64 or arm64).
make guest

# Build and tag the guest VM image. Needs Docker, KVM, and e2fsprogs on PATH;
# runs an in-VM verification gate suite before tagging (image/verify.ts).
node src/cli.ts image build

# Bind a model credential. Corb never hardcodes a provider — it binds
# whatever host env var name Pi's own provider table expects, host-side, via
# a [secrets.NAME] entry in config.toml. For Anthropic that's
# ANTHROPIC_API_KEY.
mkdir -p ~/.config/corb
cat > ~/.config/corb/config.toml <<'EOF'
[egress]
allow = ["api.anthropic.com"]

[secrets.ANTHROPIC_API_KEY]
hosts = ["api.anthropic.com"]
EOF
export ANTHROPIC_API_KEY=sk-...

# Boot a session on the current directory. The first run against a new
# workspace requires --trust-config to accept its effective policy.
node src/cli.ts run --trust-config
```

This lands you in a live, interactive Pi TUI session with the current
directory mounted read-write at `/work/<basename>` inside the guest.

`npm run build` compiles `src/` to `dist/cli.js`, the `bin` target in `package.json`.
Use `npm link` for an installed `corb` command, or invoke `node src/cli.ts` directly.
Both run the same code.

## CLI surface

| Command | What it does |
|---|---|
| `corb run [DIR] [flags] [-- PI_ARGS...]` | Boots a session and runs Pi interactively in the foreground. `DIR` defaults to the current directory. |
| `corb explain [DIR] [flags] [--json]` | Prints the effective merged config and trust verdict for `DIR` without booting anything. |
| `corb workspace ls [--json]` | Lists workspace sources, own mounts, trust status and orphan records. Read-only. |
| `corb workspace show <name> [--json]` | Shows a workspace's current config and its full personal acceptance snapshots. Read-only. |
| `corb ls [--json]` | Lists known sessions through a join of Gondolin's registry and Corb's sidecars. Read-only. |
| `corb attach <session>` | Opens a new interactive shell inside a running session. It does not rejoin Pi's TUI. See `src/vm/attach.ts`. |
| `corb kill <session>` | Sends `SIGTERM` to a session's host process so it tears down cleanly (closes the VM, removes its sidecar, flushes its audit log). No `--force`/`SIGKILL` path, by design. |
| `corb gc [--older-than DURATION] [--dry-run\|-n]` | Prunes Gondolin's own stale registry entries and Corb's orphaned session sidecars. Never prunes a sidecar whose recorded host pid is still alive. |
| `corb login [PROVIDER] [--device-code]` / `corb logout PROVIDER` | Logs in to a subscription provider on the host and keeps the tokens there. `openai-codex` for ChatGPT Plus/Pro is the only one so far. The guest gets a stand-in. With no provider, lists login status. See [Subscription logins](docs/configuration.md#subscription-logins). |
| `corb doctor [--verify-secrets]` | Checks host dependencies, secrets, workspace sources, trust and subscription logins. It also checks Gondolin-specific environment traps. `--verify-secrets` sends the configured credential checks with real secrets. This option is off by default. |
| `corb image build [--config FILE] [--tag REF] [--arch x86_64\|aarch64]` | Builds, verifies, and tags the guest VM image. |

`corb run` and `corb explain` share the same flags:

| Flag | |
|---|---|
| `--workspace NAME` | Select a workspace definition. Without DIR, no cwd mount is added. |
| `--dir NAME=HOST[:ro\|:rw]` (repeatable) | Add or override a workspace directory. |
| `--primary NAME` | Select Pi's starting mount. The default follows workspace and positional-directory selection. |
| `--trust-config` | (`corb run` only) Accept a `requires-confirmation` verdict. Required on the first run and whenever persistent policy widens. |
| `--dry-run` | (`corb run` only) Print the effective config and trust verdict without booting a VM or requiring bound secrets. |
| `--expose PORT` | (`corb run` only) Expose a guest loopback port to the host via Gondolin's ingress reverse proxy. The resulting URL is printed to stderr and recorded in the session sidecar (`corb ls`). One port, not repeatable. |
| `--trusted` | (`corb explain` only) Include the full accepted snapshot for the selected trust key. |
| `--json` | Machine-readable output for `explain`, `ls`, `workspace ls` and `workspace show`. |
| `-- PI_ARGS...` | (`corb run` only) Everything after a literal `--` is forwarded to `pi` unmodified. |

A few things worth being explicit about, since the design docs describe a
larger target surface than what exists today:

- **`corb image` only has `build`.** `image ls`, `image verify`, and `image
  pin` remain unimplemented. `src/cli.ts` dispatches `image build` and prints
  a stub message for anything else under `image`.
- **`corb run` does not yet have** `--rule`, `--allow-host`, `--allow-repo`,
  `--allow-push`/`--no-push`, `--no-network`, `--image`, `--memory`, `--cpus`,
  `--max-session`, `--name`, `--session-dir`, `--env`, `--print-plan`, or
  `--debug-log`. The corresponding settings (VM image/memory/cpus/session
  limits, egress allowlist, git policy, per-path rules, agent provider/model)
  all come from `config.toml` (see below). `corb run` does not expose these flags yet.
- **`[agent].extensions` and `[agent].append-system-prompt-file` are rejected
  at config-parse time, not silently accepted.** Neither is wired to
  anything. Only `[agent].provider` and `[agent].model` reach `pi` through
  `withProviderModelArgs` in `src/commands/run.ts`. This repo implements neither
  extension loading nor system-prompt appending.
  If `[agent].append-system-prompt-file` has any value, Corb rejects the file with `ConfigParseError`.
  If `[agent].extensions` is non-empty, Corb also rejects the file.
  Corb accepts `extensions = []` because it requests zero extensions.

## Configuration

Corb reads `~/.config/corb/config.toml`, or the file selected through `CORB_CONFIG_DIR`.
`corb run` and `corb explain` select a workspace with `--workspace <name>` or by a matching directory path.
An omitted DIR defaults to cwd unless you select a workspace by name.
Explicit selection without DIR uses configured mounts and does not add cwd.
Global settings remain below workspace settings. CLI flags override both.

Workspace sources contain named directories at `<source>/<name>/corb.toml`.
The global `[workspaces] paths` list chooses sources, with later sources replacing earlier copies of the same name.
Its default is `<configDir>/workspaces`. An explicit list replaces that default, and `paths = []` disables sources.

Sources and workspace files stay outside every mount. The guard resolves symlink targets too.
`corb explain` lists them, and `corb doctor` checks their status.
If DIR is inside a workspace host, that mount becomes primary and Pi starts at its root.
Otherwise Corb adds DIR as a read/write mount after the workspace layer.
See [Workspaces](docs/workspaces.md) for selection, portable paths, and merge rules.

```toml
[vm]
image       = "corb:0.1.0"
memory      = "4G"
cpus        = 4
max-session = "4h"
limits      = { memory-max = "6G", pids-max = 1024, cpu-quota = "400%" }

[agent]
provider = "anthropic"
model    = "claude-opus-4-5"

# Host env var -> bound as a host-side secret. The guest only ever holds a
# placeholder; the real value is substituted on the wire, for allowed hosts
# only (createHttpHooks({ secrets })).
[secrets.ANTHROPIC_API_KEY]
hosts = ["api.anthropic.com"]
# Optional, and independent of `hosts` above: a live check `corb doctor
# --verify-secrets` can run, making a real request with the real secret
# value to catch a bad/expired/copy-pasted-wrong credential before a session
# ever boots — plain `corb doctor` never runs this on its own. Corb doesn't
# know Anthropic's (or any provider's) verification endpoint or auth header
# convention, so both are spelled out here, not assumed.
[secrets.ANTHROPIC_API_KEY.verify]
url            = "https://api.anthropic.com/v1/models"
header         = "x-api-key"
expect-status  = [200]  # optional, defaults to [200]
# `header-prefix` (also optional) is prepended to the value before it's
# placed in `header` — needed for a Bearer-scheme provider, e.g. OpenRouter:
#   [secrets.OPENROUTER_API_KEY.verify]
#   url            = "https://openrouter.ai/api/v1/models"
#   header         = "Authorization"
#   header-prefix  = "Bearer "
[secrets.GITHUB_TOKEN]
hosts    = ["api.github.com"]
optional = true

[egress]
# api.anthropic.com: the model provider (swap for whatever `[agent].provider`
# actually needs, e.g. `openrouter.ai`).
# api.github.com/objects.githubusercontent.com/codeload.github.com: your
# own git/gh workflow.
# pi.dev: Pi's own model-catalog service, needed regardless of provider --
# `/model`'s background refresh hits https://pi.dev/api/models/providers/<id>
# on every provider, not just the one you have configured. Missing this
# doesn't break chat/completions, only shows "Could not refresh <provider>;
# showing cached models." in `/model`. (The image's own `env` block sets
# PI_SKIP_VERSION_CHECK=1/PI_TELEMETRY=0, so Pi's separate startup
# update-check and install-telemetry pings to pi.dev never fire in the
# first place -- only the model-catalog refresh above needs this host.)
allow                  = ["api.anthropic.com", "api.github.com", "objects.githubusercontent.com", "codeload.github.com", "pi.dev"]
block-internal-ranges  = true

[git]
allow-hosts = ["github.com"]
allow-repos = ["you/your-repo"]
allow-push  = false

[[dir]]
name = "reference"
host = "/home/you/Code/reference-docs"
mode = "ro"

[[dir]]
name  = "scratch"
host  = "/home/you/.cache/corb/scratch"
mode  = "rw"
create = true
rules = [
  { glob = "**/.env*",     mode = "hidden",     reason = "local secrets file" },
  { glob = "**/*_test.go", mode = "deny-write", reason = "tests are frozen for this session" },
]

[policy]
enabled           = true
secret-scan       = true
max-changed-files = 40
fail-open         = true

[audit]
path = "/home/you/.local/state/corb/audit.jsonl"
```

Corb expands leading `~` and `$HOME` in `[[dir]] host`.
Relative hosts need the global `[workspaces] projects-root`. This also applies to global `config.toml`.
Relative CLI `--dir` hosts still use cwd.

**Trust ratchet.** Corb stores accepted persistent config in `~/.config/corb/trusted.json`.
Workspace runs use `workspace:<name>:<resolved dir>` keys. Subdirectories of one workspace host share its record.
Runs without a workspace keep plain resolved directory keys.
Old path-keyed records do not cover workspace runs, so the first workspace run needs `--trust-config` once.

It structurally compares that snapshot with the current effective config.
Any widening requires `--trust-config` before a real run proceeds.
Examples include new allowed hosts, writable mounts, push permission and removed rules.
Narrowing changes apply silently. Unknown fields require confirmation too, so new settings fail safe without a classification rule.

After a shared update, review it with `corb workspace show <name>` or `corb explain --workspace <name> --trusted`.
Both show the full accepted snapshot. Implied-host labels appear only on current settings because snapshots do not record their sources.
`corb workspace ls` lists status and orphan records without deleting them.
After a narrowing change, Corb keeps the old snapshot until the next run with `--trust-config`.

Each record stores `acceptedConfig` and its sha256 `configHash`.
Corb recomputes the hash on read. If it differs, Corb rejects the record.
This detects hand edits or partial writes. A host process with write access can still recompute the hash.

The first run always requires confirmation because there is no previous snapshot.
CLI `--dir` overrides stay outside the ratchet because the user supplied them directly.
Corb refuses mounts that overlap its config directory, state directory, workspace sources or workspace files.
This prevents a guest from rewriting future policy and pre-accepting a matching trust record.
See [ADR 0006](docs/adr/0006-workspace-config-outside-every-mount.md) and [ADR 0013](docs/adr/0013-workspaces-as-directories-shared-like-dotfiles.md).

## Verification / testing

- `npm test` runs unit tests with Vitest. It boots no VM and is safe for every commit.
- `npm run typecheck` and `npm run lint` run TypeScript and oxlint.
- `make e2e` runs the real VM suite against a freshly built guest image. It takes minutes and needs KVM. You can also build the guest helpers and image yourself, then run `CORB_E2E=1 npm run test:e2e`.

CI (`.github/workflows/ci.yml`) runs typecheck, lint, unit tests, and the guest module's Go vet, build and test steps.
It runs on every push and pull request.
The manual `workflow_dispatch` job in `.github/workflows/e2e.yml` runs e2e tests.
Hosted runners lack reliable nested virtualization, so the normal CI job skips that suite.

## Development notes

Before the first run in a fresh checkout:

- Run `npm install && make guest` before `corb doctor` or another command. The package is not published yet.
- Install QEMU, Docker, e2fsprogs, cpio and lz4 independently of `npm install`. `corb doctor` checks these tools. It also checks `/dev/kvm` access.
- Create `~/.config/corb/config.toml` yourself, or select another directory through `CORB_CONFIG_DIR`. Check the merged config with `corb run --dry-run` before binding secrets or booting a VM.
- Run `node src/cli.ts image build` after image or guest-binary changes. This step uses Docker and VM verification and can take time. It does not need repeating for every session.
- Use another project directory for the first Corb session. Running from the Corb checkout exposes the tool's own source to the guest under test. A separate project makes this easier to assess.

## Documentation map

- [`docs/todo.md`](docs/todo.md): planned command-policy improvements:
  mandatory arguments and extensible command shims.
- [`docs/design.md`](docs/design.md): Corb's own architecture and the
  reasoning behind it.
- [`docs/gondolin-notes.md`](docs/gondolin-notes.md): verified facts,
  sharp edges, and the risk register for the Gondolin SDK version Corb is
  pinned to.
- [`docs/spike-results.md`](docs/spike-results.md): evidence from the
  go/no-go spikes gating the early milestones.
- [`docs/adr/`](docs/adr/README.md): Architecture Decision Records for the
  load-bearing decisions made along the way.

## Status

M1 through M8 are complete. They cover the walking skeleton, git/gh policy gate,
VFS policy, image hardening, and sessions with limits.
The Git history records each milestone.

M9 covered CI, this README, ADRs, ingress through `--expose`, and a checkpoint warm-start spike.
CI (M9.1), this README (M9.2), ADRs (M9.3), and ingress (M9.4) shipped.
M9.5 evaluated checkpoint warm starts and deliberately left them unimplemented.
`vm.checkpoint()` and `resume()` save disk contents, without CPU or memory state.
The spike found that they still boot the guest from scratch and do not speed up `corb run` startup.
See [M9.5](docs/spike-results.md) and [R19](docs/gondolin-notes.md) for measurements and reasoning.

## License

The project has no chosen license yet. `package.json` has no `license` field, and the repository has no `LICENSE` file.
