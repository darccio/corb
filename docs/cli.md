# Command reference

These commands describe the implemented CLI. From an unlinked source checkout,
replace `corb` with `node src/cli.ts`.

## Run

```bash
corb run [DIR] [flags] [-- PI_ARGS...]
```

Start a VM and run Pi interactively in the foreground. `DIR` defaults to the
current directory unless `--workspace` is given without DIR.
Corb selects a workspace by a matching host path, or uses global settings when none matches.

- `--workspace NAME`: Select a workspace from the configured sources. Without DIR,
  use its configured mounts and global mounts. Corb does not add cwd.

- `--dir NAME=HOST[:ro|:rw]`: Add or override a directory mount. Repeatable. The
  default mode is read/write.

- `--primary NAME`: Select the mount where Pi starts. An inside DIR uses the
  matching workspace mount. Without DIR, the first hosted workspace entry is primary.
  An added positional directory uses its basename. Pi starts at the primary mount's root.

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
corb explain [DIR] [--workspace NAME] [--dir NAME=HOST[:ro|:rw]] \
  [--primary NAME] [--trusted] [--json]
```

Print the merged configuration and trust verdict without starting a session. Use
the same mount flags as the run you want to inspect. `--json` emits
machine-readable output. Both formats show the selected workspace, primary mount,
and trust key. JSON uses `null` for DIR when an explicit workspace has no DIR.

Selection, no-DIR behavior, and errors match `corb run`.
See [Workspaces](workspaces.md#selection-and-primary-directory) for the matching rules.

`--trusted` adds the complete accepted snapshot for the selected key.
It works with the usual DIR, workspace and mount flags.
With no record, text says so and JSON has `acceptedSnapshot: null`.
Without this flag, output has no accepted snapshot.
The snapshot contains secret names and host metadata, never secret values.

## Workspaces

```bash
corb workspace ls [--json]
corb workspace show <name> [--json]
```

`workspace ls` lists each workspace's source, own hosted mounts and worst trust status.
The statuses are `none`, `trusted`, `narrowed`, `changed` and `error`.
It also shows invalid names, replaced copies and orphan trust records.
The command only reads. It never deletes records.

`workspace show` displays one definition, its current config and full accepted snapshots.
It compares host records together and extra-mount records against their saved DIR.
A deleted extra-mount directory shows `cannot compare`.
Implied-host labels appear on current config only. Accepted snapshots carry no source labels.

`show` takes no DIR. Use `corb explain --workspace <name> DIR --trusted` to inspect a particular folder.
If a workspace has no own hosted mount, `show` still lists its details and extra-mount records.
Run it with `corb run --workspace <name> DIR`.

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

The `workspace-trust` line counts trusted, changed and never-trusted workspaces.
Narrowed settings count as trusted. Pending `--trust-config` changes are normal and do not cause a warning.
An unreadable workspace causes a warning. A corrupt `trusted.json` causes a failure.

Doctor also checks providers set only in workspace files. This includes files without own mounts.
A missing workspace-only login produces a warning. A missing global login remains a failure.
Workspace-only login details show a workspace count and do not list workspace names.

## Image build

```bash
corb image build [--config FILE] [--tag REF] \
  [--arch x86_64|aarch64]
```

Build, verify, and tag a guest image. The default image configuration is
`image/corb-image.json` from the checkout.

A successful default build writes `corb:<packageVersion>-<arch>-<hash>` and the `corb:<packageVersion>` alias.
With `--tag REF`, the build writes only `REF`. This includes an explicitly requested version alias.
A failed verification writes no refs and imports no object.

The hash covers the effective config, configured init files, and each resolved `postBuild.copy` source and destination.
Corb resolves referenced files against the config directory and rejects missing inputs before building.
Field boundaries and config order keep the input sequence distinct.
This tag identifies effective build inputs. It does not identify a reproducible disk or an immutable package repository snapshot.
Keep exact asset checksums and the Gondolin build ID when recording local images.

`image ls`, `image verify`, and `image pin` are planned and are not implemented
commands.

## Current CLI limits

There are no run flags yet for image selection, memory, CPUs, network
allowlists, Git repositories, per-path rules, or session duration. Configure
those settings in [config.toml](configuration.md).

Only one positional DIR is accepted. `--workspace` selects a definition by name. Use repeated `--dir` flags
for additional mounts. `--expose` supports one port.
