# No guest→host RPC. Sentinel-hostname `onRequest` short-circuit is the one host callback mechanism

## Status

Accepted

## Context and Problem Statement

Some policy decisions need guest-held content, such as a diff about to be
committed or a changed-file count. A path or hostname is not enough.
The check must run on the host, since the guest can skip guest-only enforcement.
Gondolin provides no general guest→host RPC channel by design.
Its docs explain this in "Why We Do Not Use Vsock".
How does guest-originated content reach a host-side check?

See `docs/design.md` §1 and §5, and `docs/gondolin-notes.md` §11 ("There is no
guest→host RPC, by design") and R16.

## Decision Drivers

* A general socket transport from guest to host risks becoming a generic tunnel.
  Gondolin states this as its reason for omitting vsock. Corb must not rebuild that channel.
* Gondolin exposes an `onRequest` hook on the existing HTTP egress path.
  It can return a synthetic `Response` and short-circuit the request before it reaches the network.
* The VFS channel's 60 KiB `MAX_RPC_DATA` cap makes it unsuitable as a disguised RPC channel.
  Abusing file semantics for this purpose was explicitly rejected.

## Considered Options

* Build a purpose-specific guest→host RPC channel, for example over the VFS mount or a dedicated virtio-serial channel
* Use the sentinel-hostname `onRequest` short-circuit with a fixed, reserved hostname (`policy.corb.invalid`).
  The guest's HTTP traffic can reach it. The host's `onRequest` hook recognizes it and answers locally.

## Decision Outcome

Chosen option: "Sentinel-hostname `onRequest` short-circuit".
It reuses an SDK mechanism that already treats the host as authoritative.
It avoids adding a channel that risks becoming a general tunnel.

The sentinel hostname is `policy.corb.invalid`. RFC 2606 reserves `.invalid`,
so it can never resolve publicly. If the short-circuit is removed or
misconfigured, the request fails to connect. It cannot leak the payload to a
real host.

`onRequest` receives a full WHATWG `Request` and can read its body.
R16 confirmed this for `onRequest`, whereas `isRequestAllowed` sees a null body.
The whole payload (diff, changed-file list) is available without another side
channel.

### Consequences

* Good, because there is one host callback mechanism to reason about, and the SDK already sanctions it.
  There is no separate protocol, framing, or transport to secure.
* Good, because the invariant is explicit and checkable.
  The host executes only its own fixed, versioned check functions and can feed guest-supplied *data* into them.
  It never executes guest-supplied code over any transport.
* Bad, because every content check must fit an HTTP request/response.
  The handler must defend against an adversarial guest sending oversized or malformed bodies.
  It needs a body-size cap, field-by-field shape validation, and a rate limit (see `docs/design.md` §5).
* Bad, because secret substitution can happen before `onRequest` runs, and the handler reads and logs its request body.
  Binding a secret to the sentinel host leaks it into the audit log. Never bind secrets there.
* Neutral, because the handler must treat a rate-limit rejection as denial (exit 87), rather than infrastructure failure.
  Otherwise, the guest can deliberately exhaust the budget to obtain a fail-open response.
