# Provider-agnostic secrets and agent configuration

## Status

Accepted

## Context and Problem Statement

Corb runs Pi (`@earendil-works/pi-coding-agent`) inside the guest.
Pi already supports over two dozen model providers. Each uses its own named
environment variable, `auth.json` entry, or OAuth subscription for
authentication. Corb must bind the actual credential host-side via
`createHttpHooks({ secrets })`, so it never enters the guest.
Does Corb need hardcoded provider names, API hosts, and credential environment
variable names, or can it pass the user's choice through to Pi?

See `docs/design.md` §8 ("Provider and model selection") and commit `341a073`
("record provider-agnostic secrets/agent design decision").

## Decision Drivers

* Pi already has full multi-provider support.
  A separate Corb provider table risks drifting from Pi's as Pi adds or changes providers.
* `buildSecretBindings()` (`src/vm/egress.ts`, M3.2) is already generic.
  It binds every workspace-configured `[secrets.NAME]` entry, regardless of provider.
* Before this decision, `session.ts` hardcoded `ANTHROPIC_HOST`, a `requireApiKey` check, and `MissingApiKeyError`.
  Every `corb run` silently ignored the workspace's `[secrets]`/`[egress]` configuration and assumed an Anthropic-shaped setup.

## Considered Options

* Corb hardcodes one supported provider's API host and credential environment variable name
* Corb maintains its own provider-to-host-and-credential table, wired through `[agent].provider`
* Corb stays provider-agnostic.
  `[secrets.NAME]` binds the host environment variable the user's chosen provider expects through Pi.
  `[agent].provider`/`[agent].model` pass unchanged to Pi's `--provider`/`--model` flags.

## Decision Outcome

Chosen option: "Provider-agnostic pass-through".
Pi already handles multi-provider selection and credential resolution.
Corb passes the user's choice through without reimplementing provider logic.
It hardcodes no model provider name, API host, or credential environment variable
name.

`[agent].provider`/`[agent].model` translate directly into Pi's
`--provider`/`--model` CLI flags. `[secrets.NAME]` binds the host environment
variable the user's chosen provider expects. The user must match Pi's secret
names exactly, for example `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, or
`GEMINI_API_KEY`.

`buildSecretBindings()` and `buildGuestEnv`'s environment spreading were already
generic, so no new mechanism was needed. M3.4 wired the existing mechanism into
`session.ts` and removed the Anthropic-specific hardcoding.

### Consequences

* Good, because supporting a new provider requires no Corb code change.
  The workspace config names the right secret and `--provider`/`--model` values that Pi already understands.
* Good, because Corb keeps no provider table that can drift out of sync with Pi's.
* Bad, because Corb cannot validate a `[secrets.NAME]` spelling for the chosen provider ahead of time.
  A misnamed secret fails only when Pi tries to use it, after the VM boots.
  Pi's own no-credentials UX reports the failure.
* Neutral, because `corb doctor` warns without blocking when no `[secrets.*]` entry is configured.
  It points to `corb explain` and Pi's provider docs, without guessing the intended provider.
