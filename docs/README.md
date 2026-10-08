# Corb documentation

Corb runs Pi in a restricted micro-VM. Filesystem and network rules apply to all
guest processes; command shims check selected tool invocations. These guides
describe the implemented behavior and identify planned features.

- [Getting started](getting-started.md): dependencies, image build,
  credentials, and the first session.
- [Workspaces](workspaces.md): live directory mounts, configuration
  resolution, per-path rules, and trust.
- [Configuration](configuration.md): the global TOML file, secret bindings,
  resources, and policy settings.
- [Command reference](cli.md): the implemented CLI commands and flags.
- [Security and policy](security.md): process isolation, filesystem and network
  rules, command filtering, content checks, and their limits.
- [Planned improvements](todo.md): mandatory arguments and extensible command
  shims.

The [design document](design.md) explains the architecture. The
[architecture decisions](adr/README.md) record its major choices.
