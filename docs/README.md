# Corb documentation

Corb runs Pi in a restricted micro-VM with host-side filesystem and network
policy. These guides describe the implemented behavior and identify planned
features.

- [Getting started](getting-started.md): dependencies, image build,
  credentials, and the first session.
- [Workspaces](workspaces.md): live directory mounts, configuration
  resolution, per-path rules, and trust.
- [Configuration](configuration.md): the global TOML file, secret bindings,
  resources, and policy settings.
- [Command reference](cli.md): the implemented CLI commands and flags.
- [Security and policy](security.md): enforcement points and their limits.

The [design document](design.md) explains the architecture. The
[architecture decisions](adr/README.md) record its major choices.
