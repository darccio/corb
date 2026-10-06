# Corb

Corb is a command-line tool that boots a [Gondolin](https://earendil-works.github.io/gondolin/)
micro-VM, mounts one or more host directories into it as a restricted workspace,
and runs the [Pi](https://pi.dev) coding agent (`@earendil-works/pi-coding-agent`)
interactively inside it. The properties it exists to provide: the model API key
never enters the guest; network egress is restricted to an explicit allowlist;
git and GitHub access are mediated by policy, with credentials staying on the
host; per-path filesystem rules are enforced below the guest kernel, so no
guest process can route around them; and every policy decision lands in one
audit log. See [`docs/design.md`](docs/design.md) for the full architecture and
the reasoning behind it.

The [user documentation](docs/README.md) covers setup, workspaces,
configuration, commands, and the enforcement model.

## Requirements

- **Node.js >= 24.0.0** (`package.json`'s `engines.node`).
- **Go >= 1.26** (`guest/go.mod`) — only needed to build the guest helper
  binaries (`make guest`); not required to run an already-built image.
- **QEMU** (`qemu-system-x86_64` / `qemu-system-aarch64`) and, on Linux,
  read/write access to `/dev/kvm` — Gondolin boots a real, hardware-accelerated
  micro-VM. Host platforms are Linux and macOS.
- **Docker** — `corb image build` runs a `postBuild` step in a container
  (`image/corb-image.json` sets `container.force: true, runtime: "docker"`;
  see `docs/design.md`).
- **`e2fsprogs`** (`mkfs.ext4`, `resize2fs`, `e2fsck`) reachable on `PATH`.
  These are commonly installed only under `/sbin`/`/usr/sbin`; `corb image
  build` accounts for that itself, but a manual invocation of these tools may
  not.
- **`cpio` and `lz4`** — used to assemble the guest initramfs.

Run `corb doctor` after cloning to check all of the above (plus a few
Corb-specific environment traps) against your actual machine.

## Quickstart

Corb is not published to npm yet — clone the repository and run it from a
checkout.

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

`npm run build` compiles `src/` to `dist/cli.js` (the `bin` target in
`package.json`) for anyone who wants to `npm link` an installed `corb`
command instead of invoking `node src/cli.ts` directly; both run the same
code.

## CLI surface

| Command | What it does |
|---|---|
| `corb run [DIR] [flags] [-- PI_ARGS...]` | Boots a session and runs Pi interactively in the foreground. `DIR` defaults to the current directory. |
| `corb explain [DIR] [flags] [--json]` | Prints the effective merged config and trust verdict for `DIR` without booting anything. |
| `corb ls [--json]` | Lists known sessions, joining Gondolin's own session registry with Corb's sidecars. Read-only. |
| `corb attach <session>` | Opens a new interactive shell inside a running session (a *new* shell — not a way to rejoin Pi's own TUI; see `src/vm/attach.ts`). |
| `corb kill <session>` | Sends `SIGTERM` to a session's host process so it tears down cleanly (closes the VM, removes its sidecar, flushes its audit log). No `--force`/`SIGKILL` path, by design. |
| `corb gc [--older-than DURATION] [--dry-run\|-n]` | Prunes Gondolin's own stale registry entries and Corb's orphaned session sidecars. Never prunes a sidecar whose recorded host pid is still alive. |
| `corb doctor [--verify-secrets]` | Checks the host environment (KVM, QEMU, Docker, Node/Go versions, e2fsprogs, cgroup delegation, required secrets, and a couple of Gondolin-specific sharp edges) and prints a report. `--verify-secrets` additionally makes a real HTTP request per `[secrets.NAME.verify]` entry (see Configuration below) to catch a syntactically-present-but-invalid credential — off by default since it's a real network call using the real secret value. |
| `corb image build [--config FILE] [--tag REF] [--arch x86_64\|aarch64]` | Builds, verifies, and tags the guest VM image. |

`corb run` and `corb explain` share the same flags:

| Flag | |
|---|---|
| `--dir NAME=HOST[:ro\|:rw]` (repeatable) | Add or override a workspace directory. |
| `--primary NAME` | Which directory becomes Pi's working directory (defaults to the positional `DIR`). |
| `--trust-config` | Accept a `requires-confirmation` trust verdict and proceed (`corb run` only — required on the first run against any workspace, and again whenever the effective policy widens). |
| `--dry-run` | (`corb run` only) Print what a real run would do — config, trust verdict — without booting a VM or requiring a secret to be bound. |
| `--expose PORT` | (`corb run` only) Expose a guest loopback port to the host via Gondolin's ingress reverse proxy. The resulting URL is printed to stderr and recorded in the session sidecar (`corb ls`). One port, not repeatable. |
| `--json` | (`corb explain`/`corb ls` only) Machine-readable output. |
| `-- PI_ARGS...` | (`corb run` only) Everything after a literal `--` is forwarded to `pi` unmodified. |

A few things worth being explicit about, since the design docs describe a
larger target surface than what exists today:

- **`corb image` only has `build`.** `image ls`, `image verify`, and `image
  pin` are part of the design but are not implemented yet — `src/cli.ts`
  dispatches `image build` specifically and falls through to a stub message
  for anything else under `image`.
- **`corb run` does not yet have** `--rule`, `--allow-host`, `--allow-repo`,
  `--allow-push`/`--no-push`, `--no-network`, `--image`, `--memory`, `--cpus`,
  `--max-session`, `--name`, `--session-dir`, `--env`, `--print-plan`, or
  `--debug-log`. The corresponding settings (VM image/memory/cpus/session
  limits, egress allowlist, git policy, per-path rules, agent provider/model)
  are all read from `config.toml` (see below) — they are just not yet
  exposed as `corb run` flags.
- **`[agent].extensions` and `[agent].append-system-prompt-file` are rejected
  at config-parse time, not silently accepted.** Neither is wired to
  anything: only `[agent].provider` and `[agent].model` actually reach `pi`
  (`withProviderModelArgs`, `src/commands/run.ts`), and there is no
  extension-loading or system-prompt-appending implementation anywhere in
  this repo to wire the other two to yet. Rather than accept-and-silently-
  ignore them, `corb.toml` fails to parse (`ConfigParseError`) if
  `[agent].append-system-prompt-file` is set to any value, or
  `[agent].extensions` is set to a non-empty list. An empty `extensions = []`
  is still accepted — it asks for zero extensions, and corb loading zero
  extensions is accurate, not a lie.

## Configuration

Corb reads one config file today: `~/.config/corb/config.toml`
(overridable via `CORB_CONFIG_DIR`). Named per-workspace files
(`~/.config/corb/workspaces/<name>.toml`, described in the design docs as the
target model) are not implemented yet — `corb run`/`corb explain` instead
take a directory path (the positional argument, defaulting to the current
directory), which is merged with `config.toml` as a synthesized single-`dir`
layer.

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

Note that `host` paths are used as-is (no `~` expansion) — use absolute
paths.

**Trust ratchet.** Corb stores the full effective config it was last accepted
with for a workspace in `~/.config/corb/trusted.json`, keyed by the
workspace's resolved absolute directory path, and structurally compares it
against the effective config now. Any change that *widens* policy — a new
allowed host, a directory gaining `rw`, `allow-push` turning on, a rule being
removed, or any field the widening/narrowing table doesn't have a rule for —
requires confirmation (`--trust-config`) before a real `corb run` proceeds;
narrowing changes apply silently. A field with no widening/narrowing rule is
a deny-list, not an allow-list: it defaults to requiring confirmation, so a
new config field added without an accompanying rule fails safe rather than
being silently trusted. Alongside `acceptedConfig`, each record also stores a
sha256 hash of it (`configHash`); on read, Corb recomputes that hash and
checks it still matches, refusing to treat the record as valid if it
doesn't — a fast integrity check against a hand-edited or partially-written
`trusted.json`, not a defense against a host process that already has write
access to the file. The very first run against a workspace always requires
confirmation, since there is nothing yet to compare against. `--dir` flags
passed on the command line are always trusted (a human just typed them) and
never participate in the ratchet. Corb also refuses to mount any host
directory that is, or overlaps, its own `~/.config/corb`/`~/.local/state/corb`
— see [`docs/adr/0006`](docs/adr/0006-workspace-config-outside-every-mount.md)
— since a workspace-writable copy of `trusted.json` would otherwise let an
agent pre-accept a wider config for a future run.

## Verification / testing

- `npm test` — unit tests (Vitest), no VM boot, safe to run on every commit.
- `npm run typecheck` / `npm run lint` — TypeScript and oxlint.
- `make e2e` (or `CORB_E2E=1 npm run test:e2e` after building the guest binaries
  and the image yourself) — the real end-to-end suite: boots actual VMs
  against a freshly built guest image. Takes minutes and needs a KVM-capable
  host.

CI (`.github/workflows/ci.yml`) runs `typecheck`, `lint`, `test`, and the Go
`vet`/`build`/`test` steps for the guest module on every push and pull
request. It does **not** run the e2e suite — nested virtualization isn't
reliable on hosted runners — which is instead wired as a manual-only
`workflow_dispatch` job (`.github/workflows/e2e.yml`).

## Development notes

Notes for dogfooding Corb from a fresh clone/worktree, before it's built or
configured on the host:

- `corb doctor` needs a build first — run `npm install && make guest` before
  it (or any other command) will work. There is no published package to
  install instead yet (see Quickstart).
- `corb doctor` checks the host, not just the repo: QEMU
  (`qemu-system-x86_64`/`qemu-system-aarch64`), `/dev/kvm` read/write access,
  Docker, `e2fsprogs` (`mkfs.ext4`, `resize2fs`, `e2fsck`), and `cpio`/`lz4`
  all have to be present on `PATH` independently of `npm install`.
- `~/.config/corb/config.toml` does not exist by default — it has to be
  created by hand (or via `CORB_CONFIG_DIR`) before the first `corb run`.
  `corb run --dry-run` is the safe way to check the merged config and trust
  verdict before binding a real secret or booting a VM.
- `node src/cli.ts image build` is the slow step (Docker plus an in-VM
  verification gate suite) and only needs to be redone when `image/` or the
  guest binaries change, not on every session.
- Dogfood Corb against a workspace other than the Corb checkout itself —
  running `corb run` from inside a Corb worktree mounts the tool's own
  source into the guest it's testing, which is confusing to reason about and
  unnecessary risk for a first session. Point `corb run` at some other
  project directory instead.

## Documentation map

- [`docs/design.md`](docs/design.md) — Corb's own architecture and the
  reasoning behind it.
- [`docs/gondolin-notes.md`](docs/gondolin-notes.md) — verified facts,
  sharp edges, and the risk register for the Gondolin SDK version Corb is
  pinned to.
- [`docs/spike-results.md`](docs/spike-results.md) — evidence from the
  go/no-go spikes gating the early milestones.
- [`docs/adr/`](docs/adr/README.md) — Architecture Decision Records for the
  load-bearing decisions made along the way.

## Status

M1 through M8 (walking skeleton through sessions/limits, plus the git/gh
policy gate, VFS policy, and image hardening gates in between) are complete —
see `git log` for the full milestone-by-milestone history. M9 (optional: CI,
this README, ADRs, `--expose`/ingress, and checkpoint-based warm starts) is
done: CI (M9.1), this README (M9.2), the ADRs (M9.3), and `--expose`/ingress
(M9.4) all shipped; checkpoint-based warm starts (M9.5) was evaluated and
deliberately **not** built — `vm.checkpoint()`/`resume()` measurably boots
the guest from scratch every time regardless (no CPU/memory state is ever
saved, only disk contents), so it cannot speed up `corb run`'s startup. See
[`docs/spike-results.md`](docs/spike-results.md) M9.5 and
[`docs/gondolin-notes.md`](docs/gondolin-notes.md) R19 for the measurements
and reasoning.

## License

No license has been chosen for this project yet — `package.json` has no
`license` field and there is no `LICENSE` file in this repository.
