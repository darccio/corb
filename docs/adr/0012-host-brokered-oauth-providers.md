# Host-brokered OAuth providers

## Status

Accepted

## Context and Problem Statement

ADR 0010 keeps Corb provider-agnostic. A credential is a host environment
variable bound through `[secrets.NAME]`, and the guest sees a Gondolin placeholder.
`[agent].provider` and `[agent].model` pass through to Pi unchanged.
That works for every provider that takes a static API key.

It does not work for subscription logins such as ChatGPT Plus/Pro through Pi's
`openai-codex` provider. There is no static key. Pi signs in with OAuth at
`auth.openai.com`. It uses PKCE and a refresh token that may rotate.

Pi stores access and refresh tokens in `~/.pi/agent/auth.json` and refreshes
the access token as it expires. If Pi does this inside the guest, both tokens
live there. The guest also needs egress to `auth.openai.com`.
That breaks Corb's core property: real credentials never enter the guest.

How can Corb support a subscription OAuth provider without giving the guest
the tokens?

## Decision Drivers

* The access token and the refresh token are both real credentials.
  The refresh token outlives any one session and is more valuable.
* Sessions can run for hours, and an access token can expire mid-session.
  Refresh therefore needs to happen during a session too.
* Pi decides which provider and token to use from its own `auth.json`.
  It reads the ChatGPT account id from the access token's JWT payload (`extractAccountId`).
  It checks neither a signature nor the JWT `exp` claim.
  It refreshes only when the stored `expires` timestamp is in the past.
* Several Corb sessions on one host can share a login.
  With a rotating refresh token, two uncoordinated refreshes can invalidate each other.
* Corb has no provider-specific code today.
  ADR 0010's reasons for that still hold for API-key providers.
  Those reasons include avoiding drift from Pi's provider table.

## Considered Options

* Let Pi log in inside the guest, and allow `auth.openai.com` in egress
* Log in on the host, then copy the real `auth.json` into the guest
* Log in on the host and keep the tokens there.
  Give the guest a stand-in credential that the host swaps for the real token on the wire ("host-brokered OAuth").

## Decision Outcome

Chosen option: "host-brokered OAuth", because it is the only option that keeps
both tokens out of the guest.

* `corb login <provider>` runs the provider's OAuth flow on the host and stores tokens in Corb's state directory.
  It uses `credentials/<provider>.json`, mode 0600, in a 0700 directory, with atomic writes.
  `corb logout <provider>` deletes them. All Corb sessions on the host share the file.
  A refresh takes a file lock and re-reads the file after taking it.
  Concurrent sessions therefore never refresh with a stale refresh token.
* When `[agent].provider` names a brokered provider, `corb run` requires a stored login before boot.
  It refreshes the token on the host near expiry and writes a stand-in Pi `auth.json` into the guest.
  For `openai-codex`, the stand-in access token is an unsigned JWT-shaped string.
  It carries only the real account id plus a random per-session marker.
  The stand-in refresh token is a dummy, and `expires` is far in the future.
  Pi therefore never tries to refresh.
* The host's `onRequest` hook replaces `Authorization: Bearer <stand-in>` with the real access token.
  It does this only for HTTPS requests to the provider's own API hosts (`chatgpt.com` for `openai-codex`).
  It refreshes on the host during the session when needed.
  It never rewrites toward any other host. A stand-in that leaks anywhere else is worthless by construction.
* Corb adds the provider's API hosts to `egress.allow` automatically.
  They appear in `corb explain` with their source, and a newly implied host counts as widening.
  `auth.openai.com` is never needed in the guest.
  Amended by DAR-14 on 2026-10-25.
  See [ADR 0013](0013-workspaces-as-directories-shared-like-dotfiles.md).
* Providers live behind one small interface.
  It holds the id, login methods, refresh, guest-side Pi credential, rewrite hosts and guest Pi settings.
  Adding a provider means adding one module to the registry.

This is a deliberate, scoped exception to ADR 0010. It applies only to
providers in the registry, and only when `[agent].provider` names one. Every
other provider still uses `[secrets.NAME]`, unchanged.

### Consequences

* Good, because neither the access token nor the refresh token is readable inside the guest.
  The guest has no route to the token endpoint.
* Good, because refresh during long sessions happens on the host.
  Every session on the host shares the refresh lock.
* Good, because a stand-in that escapes the guest is useless to anyone else.
  It is unsigned, and only this session's host hook recognises it.
  This holds for leaks to a log, a commit or another host.
* Bad, because Corb now carries provider-specific code: OAuth endpoints, client id and the JWT claim Pi reads.
  It can drift from Pi or from the provider.
  The code is small and isolated, but needs care when Pi changes `auth.json` handling or the provider changes authentication.
* Bad, because the stand-in relies on Pi not verifying the token locally.
  If a future Pi checks the JWT signature or `exp`, the stand-in stops working.
  It fails safe with no real token leak, but brokered logins break until Corb adapts.
* Neutral, because WebSocket traffic is opaque after the upgrade.
  Gondolin's `onRequest` sees the upgrade request itself, so the rewrite works when `egress.websockets = true`.
  With the default `false`, Corb sets Pi's transport to SSE for the session.
  Pi's own fallback covers the rest.
