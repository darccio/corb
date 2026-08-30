# Provider-agnostic secrets and agent configuration

## Status

Accepted

## Context and Problem Statement

Corb runs Pi (`@earendil-works/pi-coding-agent`) inside the guest, and Pi
itself already supports over two dozen model providers, each authenticated via
its own named environment variable, `auth.json` entry, or OAuth subscription.
Corb also needs to bind the actual credential host-side (via
`createHttpHooks({ secrets })`) so it never enters the guest. Should Corb
hardcode a specific provider (name, API host, credential env-var name), or stay
agnostic and pass the user's choice through to Pi unchanged?

See `docs/design.md` §8 ("Provider and model selection") and commit `341a073`
("record provider-agnostic secrets/agent design decision").

## Decision Drivers

* Pi already has full multi-provider support built in; Corb reimplementing a
  provider table would just drift from Pi's own as Pi adds or changes
  providers.
* `buildSecretBindings()` (`src/vm/egress.ts`, M3.2) is already fully generic:
  it binds whatever `[secrets.NAME]` entries a workspace configures, regardless
  of what provider that name happens to belong to.
* Before this decision, `session.ts` had a hardcoded `ANTHROPIC_HOST` constant,
  a `requireApiKey` check, and a `MissingApiKeyError`, meaning every `corb run`
  silently ignored a workspace's actual `[secrets]`/`[egress]` configuration
  and always assumed a single Anthropic-shaped setup.

## Considered Options

* Corb hardcodes a single supported provider (model API host, credential
  env-var name) and only that one
* Corb maintains its own table mapping provider names to hosts and credential
  env-var names, wired through `[agent].provider`
* Corb stays provider-agnostic: `[secrets.NAME]` binds whatever host
  environment variable the user's chosen provider (via Pi) expects, and
  `[agent].provider`/`[agent].model` pass through untouched to Pi's own
  `--provider`/`--model` flags

## Decision Outcome

Chosen option: "Provider-agnostic pass-through", because Pi already solves
multi-provider selection and credential resolution, and Corb's job is narrow:
pass the user's choice through, not reimplement provider logic. Corb does not
hardcode any model provider's name, API host, or credential env-var name.
`[agent].provider`/`[agent].model` translate directly into Pi's own
`--provider`/`--model` CLI flags, and `[secrets.NAME]` binds whatever host
environment variable the user's chosen provider expects — the user is
responsible for spelling the secret name exactly as Pi's own table expects
(e.g. `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, `GEMINI_API_KEY`). Because
`buildSecretBindings()` and `buildGuestEnv`'s environment-spreading were already
generic, no new mechanism was needed — the decision was to actually wire the
existing generic mechanism into `session.ts` and delete the Anthropic-specific
hardcoding (M3.4), not to build something new.

### Consequences

* Good, because adding support for a new provider requires no Corb code
  change at all — it is purely a matter of the user's workspace config naming
  the right secret and the right `--provider`/`--model` values, both of which
  Pi already understands.
* Good, because Corb's provider knowledge cannot drift out of sync with Pi's
  own, since Corb maintains no copy of that name-to-provider table to go stale.
* Bad, because Corb has no way to validate that a `[secrets.NAME]` entry is
  spelled correctly for the chosen provider ahead of time — a misnamed secret
  fails only once the guest actually tries to use it, inside Pi's own
  no-credentials UX, after the VM has already booted.
* Neutral, because `corb doctor`'s job here is deliberately soft: warn (not
  hard-block) when no `[secrets.*]` entry is configured at all, pointing at
  `corb explain` and Pi's own provider docs, rather than trying to guess which
  provider the user intends to use.
