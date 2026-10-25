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
corb run ~/Code/packet-loss -- "Read the README and propose a feature plan."
```

Paths passed to Pi after `--` are guest paths, such as `/work/packet-loss`.
For persistent Pi transcripts and `--continue`, see the
[walkthrough](walkthrough.md#keep-conversation-history-across-runs).

## Explain

```bash
corb explain [DIR] [--dir NAME=HOST[:ro|:rw]] \
  [--primary NAME] [--json]
```

Print the merged configuration and trust verdict without starting a session. Use
the same mount flags as the run you want to inspect. `--json` emits
machine-readable output.

## Login

```bash
corb login [PROVIDER] [--device-code]
corb logout PROVIDER
```

Log in to a subscription provider on the host. `openai-codex` (ChatGPT Plus or
Pro) is the only provider so far. With no provider, `login` lists the providers
and whether each has a stored login.

The default login prints a URL to open in a browser. The browser returns to
`localhost:1455` on the host when the login is done. If the browser runs on
another machine, or another program uses that port, paste the address the
browser ends on into the terminal. `--device-code` prints a code to enter at
the provider's site instead.

`logout` deletes the stored login from the host. It does not revoke it at the
provider.

See [Subscription logins](configuration.md#subscription-logins) for the
configuration a session needs.

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

`kill` sends `SIGTERM` to the host process that owns the session.
This allows the VM, sidecar, and audit writer to close. There is no force-kill flag.

`gc` removes stale registry entries and orphaned sidecars. It preserves a
sidecar while its recorded host process is alive. Inspect proposed removals with
`--dry-run`.

## Doctor

```bash
corb doctor [--verify-secrets]
```

Check the host environment, dependencies, cgroup delegation, and required
credential variables. When `[agent].provider` uses a subscription login, it also
checks that the login exists and reports the API hosts Corb allows automatically.
`--verify-secrets` additionally sends the configured credential-verification requests.

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
