# Host-brokered OAuth providers

## Status

Accepted

## Context and Problem Statement

ADR 0010 keeps Corb provider-agnostic: a credential is a host environment
variable bound through `[secrets.NAME]`, the guest sees a Gondolin placeholder,
and `[agent].provider`/`[agent].model` pass through to Pi unchanged. That works
for every provider that takes a static API key.

It does not work for subscription logins such as ChatGPT Plus/Pro through Pi's
`openai-codex` provider. There is no static key. Pi signs in with OAuth
(`auth.openai.com`, PKCE, a refresh token that may rotate), stores an access
token and a refresh token in `~/.pi/agent/auth.json`, and refreshes the access
token itself as it expires. If Pi did that inside the guest, both tokens would
live in the guest, and the guest would need egress to `auth.openai.com`. That
breaks Corb's core property: real credentials never enter the guest.

How should Corb support a subscription OAuth provider without giving the guest
the tokens?

## Decision Drivers

* The access token and the refresh token are both real credentials. The
  refresh token is the more valuable of the two: it outlives any one session.
* Sessions can run for hours, and an access token can expire mid-session, so
  refresh has to happen somewhere during a session, not only at start.
* Pi decides which provider and token to use from its own `auth.json`. It
  reads the ChatGPT account id from the access token's JWT payload
  (`extractAccountId`), without checking a signature or the JWT `exp` claim.
  It refreshes only when the stored `expires` timestamp has passed.
* Several Corb sessions on one host can share a login. With a rotating
  refresh token, two uncoordinated refreshes can invalidate each other.
* Corb has no provider-specific code today, and ADR 0010's reasons for that
  (no drift from Pi's provider table) still hold for API-key providers.

## Considered Options

* Let Pi log in inside the guest, and allow `auth.openai.com` in egress
* Log in on the host, then copy the real `auth.json` into the guest
* Log in on the host, keep the tokens on the host, and give the guest a
  stand-in credential that the host swaps for the real token on the wire
  ("host-brokered OAuth")

## Decision Outcome

Chosen option: "host-brokered OAuth", because it is the only option that keeps
both tokens out of the guest.

* `corb login <provider>` runs the provider's OAuth flow on the host and stores
  the tokens in Corb's state directory
  (`credentials/<provider>.json`, mode 0600, directory 0700, written
  atomically). `corb logout <provider>` deletes them. All Corb sessions on the
  host share the file. A refresh takes a file lock and re-reads the file after
  taking it, so concurrent sessions never refresh with a stale refresh token.
* When `[agent].provider` names a brokered provider, `corb run` fails before
  boot if there is no stored login, refreshes the token on the host if it is
  close to expiry, and writes a stand-in Pi `auth.json` into the guest. For
  `openai-codex` the stand-in access token is an unsigned JWT-shaped string
  that carries only the real account id plus a random per-session marker. The
  stand-in refresh token is a dummy, and `expires` is far in the future, so Pi
  never tries to refresh.
* The host's `onRequest` hook replaces `Authorization: Bearer <stand-in>` with
  the real access token, only for HTTPS requests to the provider's own API
  hosts (`chatgpt.com` for `openai-codex`). It refreshes on the host during the
  session when needed. It never rewrites toward any other host. A stand-in
  that leaks anywhere else is worthless by construction.
* A login does not grant network access. The API host must still be in
  `egress.allow`. `auth.openai.com` is never needed in the guest.
* Providers live behind one small interface (id, login methods, refresh, the
  guest-side Pi credential, the rewrite hosts, and guest Pi settings). Adding a
  provider means adding one module to the registry.

This is a deliberate, scoped exception to ADR 0010. It applies only to
providers in the registry, and only when `[agent].provider` names one. Every
other provider still uses `[secrets.NAME]`, unchanged.

### Consequences

* Good, because neither the access token nor the refresh token is ever
  readable inside the guest, and the guest has no route to the token endpoint.
* Good, because refresh during long sessions happens on the host, with a lock
  shared by every session on the host.
* Good, because a stand-in that escapes the guest (to a log, a commit, another
  host) cannot be used by anyone: it is unsigned, and only this session's host
  hook recognises it.
* Bad, because Corb now carries provider-specific code (OAuth endpoints, client
  id, the JWT claim Pi reads). It can drift from Pi or from the provider. The
  code is small and isolated, but it needs care when Pi changes how it reads
  `auth.json` or how the provider authenticates.
* Bad, because the stand-in relies on Pi not verifying the token locally. If a
  future Pi checks the JWT signature or `exp`, the stand-in stops working. It
  fails safe (no real token leaks), but brokered logins break until Corb
  adapts.
* Neutral, because WebSocket traffic is opaque after the upgrade. Gondolin's
  `onRequest` does see the upgrade request itself, so the rewrite works when
  `egress.websockets = true`. With the default `false`, Corb sets Pi's
  transport to SSE for the session, and Pi's own fallback covers the rest.
