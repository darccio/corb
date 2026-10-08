# Getting started

Corb is not published to npm yet. Build it from the repository, then run it
against the project you want Pi to work on.

## Requirements

- Node.js 24 or newer.
- Go 1.26 or newer to build the guest helpers.
- QEMU for your architecture. On Linux, read/write access to `/dev/kvm`.
- Docker for the image build.
- `e2fsprogs`, `cpio`, and `lz4` on your host.

The host platforms are Linux and macOS. Linux sessions use KVM hardware
acceleration.

## Build from source

```bash
git clone https://github.com/darccio/corb.git
cd corb
npm install
make guest
node src/cli.ts doctor
node src/cli.ts image build
```

`make guest` builds the privilege-drop and policy-gate helpers. The image build
assembles the VM image and runs its verification suite before tagging it.

`doctor` checks dependencies, virtualization access, and host setup. Resolve
reported failures before building the image.

For an installed `corb` command, compile the checkout and link it:

```bash
npm run build
npm link
```

The remaining examples use `node src/cli.ts` from the Corb checkout. The linked
`corb` command accepts the same arguments.

## Configure a model credential

Create `~/.config/corb/config.toml`. This Anthropic example supplies the
provider, model, permitted destinations, and secret binding:

```toml
[agent]
provider = "anthropic"
model = "claude-opus-4-5"

[egress]
allow = ["api.anthropic.com", "pi.dev"]

[secrets.ANTHROPIC_API_KEY]
hosts = ["api.anthropic.com"]
```

Export your credential in the shell that launches Corb. This example reads it
without echoing it or putting its value in a shell-history command:

```bash
read -rsp 'Anthropic API key: ' ANTHROPIC_API_KEY
printf '\n'
export ANTHROPIC_API_KEY
```

The credential entry example uses Bash. Set the same environment variable using
your shell's private-input equivalent if needed.

Corb reads the real value on the host. Pi receives a placeholder; the host
substitutes the credential on permitted outbound requests. `pi.dev` allows Pi to
refresh its model catalog.

Other providers need their own Pi provider identifier, model, credential
variable, and permitted destinations. See [Agent and
secrets](configuration.md#agent-and-secrets).

## Inspect and start a session

```bash
node src/cli.ts explain ~/Code/packet-loss
node src/cli.ts run ~/Code/packet-loss --trust-config
```

The project directory must exist. `explain` prints the effective configuration
and trust verdict without booting a VM. `--trust-config` accepts the
configuration for the first run.

Pi starts interactively with the project mounted read/write at
`/work/packet-loss`. Edits in that mount change the host files. Later runs can
omit `--trust-config` unless the persistent configuration widens access.

> Use a project directory outside the Corb checkout for your first session.
> Rebuilding Corb while a session uses its image adds avoidable moving parts.

Continue with the [development walkthrough](walkthrough.md) for project-specific
configuration, repository instructions, feature development, review, and keeping
Pi history across sessions.
