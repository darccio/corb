# Planned improvements

These command-policy improvements are not implemented. The stock image currently
shims `git` and `gh`, with fixed argument policies and content-check hooks for
`git commit` and `git push`.

## Mandatory arguments

- [ ] Add required-argument rules for specific tools and subcommands.

A rule should be able to require a flag or argument before allowing an
invocation. For example, require `-S` or `--gpg-sign` for `git commit-tree`, a
low-level command that creates commit objects and supports signing through
[those options](https://git-scm.com/docs/git-commit-tree).

The rule must check the effective arguments, including accepted option forms,
values, argument boundaries, and flags that negate a requirement. Blocking
`--no-gpg-sign` alone does not require a command to request signing. Tests should
cover missing requirements, valid forms, negation, and tokens passed as data
rather than options.

## Extensible command shims

- [ ] Make the shim mechanism extensible to any command provided by an image.

Provide a host-owned way to register tool names, real binary paths, argument
policies, and optional content-check handlers. Support commands with and without
subcommands, rather than limiting dispatch to the hardcoded `git` and `gh`
names. Keep image-installed shims and host-generated policy tables consistent.

Content-check extensions must define their collector and accepted host request
format. The real tool must still run in the guest as the same unprivileged
user; host-side filesystem and network rules continue to enforce the isolation
boundary independently of the shim.
