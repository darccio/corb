# No guest→host RPC; sentinel-hostname `onRequest` short-circuit is the one host callback mechanism

## Status

Accepted

## Context and Problem Statement

Some policy decisions need to see content the guest holds — a diff about to be
committed, a changed-file count — not just a path or hostname. That check must
run on the host, since the guest can trivially skip anything enforced only in
the guest. Gondolin provides no general guest→host RPC channel by design (its
own docs carry a section titled "Why We Do Not Use Vsock"). How does
guest-originated content reach a host-side check?

See `docs/design.md` §1 and §5, and `docs/gondolin-notes.md` §11 ("There is no
guest→host RPC, by design") and R16.

## Decision Drivers

* A general socket transport from guest to host becomes a generic tunnel by
  accident — this is Gondolin's own stated reason for not providing vsock, and
  Corb does not want to rebuild the thing the SDK deliberately omitted.
* Gondolin does expose an `onRequest` hook on the existing HTTP egress path,
  which can return a synthetic `Response` and short-circuit the request before
  it ever reaches the network.
* The 60 KiB `MAX_RPC_DATA` cap on the VFS channel makes it unsuitable as a
  disguised RPC channel, and abusing file semantics for this purpose was
  explicitly rejected.

## Considered Options

* Build a purpose-specific guest→host RPC channel (e.g. over the VFS mount, or
  a dedicated virtio-serial channel)
* Use the sentinel-hostname `onRequest` short-circuit: a fixed, reserved
  hostname (`policy.corb.invalid`) that the guest's HTTP traffic can reach, and
  which the host's `onRequest` hook recognizes and answers locally

## Decision Outcome

Chosen option: "Sentinel-hostname `onRequest` short-circuit", because it reuses
a mechanism the SDK already provides and already treats as host-authoritative,
rather than adding a new channel that risks becoming a general tunnel. The
sentinel hostname is `policy.corb.invalid` — `.invalid` is reserved by RFC 2606
and can never resolve publicly, so if the short-circuit is ever removed or
misconfigured, the request fails to connect instead of leaking the payload to a
real host. `onRequest` receives a full WHATWG `Request` and can read its body
(confirmed sound for this hook specifically, not for `isRequestAllowed`, which
sees a null body — R16), so the whole payload (diff, changed-file list) is
available without a second-guessing side channel.

### Consequences

* Good, because there is exactly one host callback mechanism to reason about,
  and it is the SDK's own sanctioned one — no separate protocol, framing, or
  transport to secure.
* Good, because the invariant this preserves is explicit and checkable: the
  host executes only its own fixed, versioned check functions, and may feed
  guest-supplied *data* into them, but never executes anything the guest
  supplies as code, over any transport.
* Bad, because this route is HTTP-shaped: every content check must be
  expressible as an HTTP request/response, and the handler must defend itself
  against an adversarial guest sending oversized or malformed bodies (a
  body-size cap, field-by-field shape validation, and a rate limit are all
  required — see `docs/design.md` §5).
* Bad, because a secret must never be bound to the sentinel host — secrets may
  already be expanded by the time `onRequest` runs, and the handler reads and
  logs its request body, so binding a secret there would leak it into the
  audit log.
* Neutral, because a rate-limit rejection on this path must be treated as a
  denial (exit 87), not an infrastructure failure, or the guest could
  deliberately exhaust the budget to obtain a fail-open response on demand.
