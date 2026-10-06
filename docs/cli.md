# Command reference

These commands describe the implemented CLI. From an unlinked source checkout,
replace `corb` with `node src/cli.ts`.

## Run

```bash
corb run [DIR] [flags] [-- PI_ARGS...]
```

Start a VM and run Pi interactively in the foreground. `DIR` defaults to the
current directory.

- `--dir NAME=HOST[:ro|:rw]`: Add or override a directory mount. Repeatable. The
  default mode is read/write.

- `--primary NAME`: Select the mount where Pi starts. The default is the
  positional directory's basename.

- `--trust-config`: Accept the persistent configuration when the trust verdict
  requires confirmation.

- `--dry-run`: Print configuration and trust information without booting a VM or
  requiring a bound credential.

- `--expose PORT`: Expose one guest loopback port through Gondolin's ingress
  reverse proxy. Corb prints the host URL and records it in the session sidecar.

- `-- PI_ARGS...`: Forward everything after a literal `--` to Pi.

```bash
corb run ~/Code/packet-loss --trust-config
corb run ~/Code/packet-loss --dry-run
corb run ~/Code/packet-loss --expose 3000
```

## Explain

```bash
corb explain [DIR] [--dir NAME=HOST[:ro|:rw]] \
  [--primary NAME] [--json]
```

Print the merged configuration and trust verdict without starting a session. Use
the same mount flags as the run you want to inspect. `--json` emits
machine-readable output.

## Session commands

```bash
corb ls [--json]
corb attach <session>
corb kill <session>
corb gc [--older-than DURATION] [--dry-run|-n]
```

`ls` lists known sessions by joining Gondolin's registry with Corb's sidecars.
Use a session identifier from its output with `attach` or `kill`.

`attach` opens a new interactive shell in a running VM. It does not rejoin or
mirror Pi's terminal.

`kill` sends `SIGTERM` to the host process that owns the session, allowing the
VM, sidecar, and audit writer to close. There is no force-kill flag.

`gc` removes stale registry entries and orphaned sidecars. It preserves a
sidecar while its recorded host process is alive. Inspect proposed removals with
`--dry-run`.

## Doctor

```bash
corb doctor [--verify-secrets]
```

Check the host environment, dependencies, cgroup delegation, and required
credential variables. `--verify-secrets` additionally sends the configured
credential-verification requests.

## Image build

```bash
corb image build [--config FILE] [--tag REF] \
  [--arch x86_64|aarch64]
```

Build, verify, and tag a guest image. The default image configuration is
`image/corb-image.json` from the checkout.

`image ls`, `image verify`, and `image pin` are planned and are not implemented
commands.

## Current CLI limits

There are no run flags yet for image selection, memory, CPUs, network
allowlists, Git repositories, per-path rules, or session duration. Configure
those settings in [config.toml](configuration.md).

Only one positional workspace directory is accepted. Use repeated `--dir` flags
for additional mounts. `--expose` supports one port.
