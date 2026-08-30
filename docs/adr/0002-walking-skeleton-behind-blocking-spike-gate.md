# Walking skeleton behind a blocking spike gate

## Status

Accepted

## Context and Problem Statement

Corb's design rests on assumptions about the Gondolin SDK (0.12.0, described as
"early" by its own authors) that were untested at project start: whether a
model-provider SDK's HTTP/2 negotiation actually works through Gondolin's
HTTP/1.x-only egress mediation (R1), and whether the MITM TLS interception's
injected CA is actually trusted by Node/curl/git inside the guest (R3). Building
the full design — filesystem policy, git/gh gating, content checks, sessions —
against untested assumptions about the SDK risked a large amount of work built
on a foundation that might not hold. How should delivery be sequenced?

See the project plan's "How we work" section and its M0/M1 milestone
definitions (`let-s-read-the-docs-nifty-russell.md`).

## Decision Drivers

* R1 and R3 are both load-bearing for the entire design: if HTTP/2 negotiation
  or CA trust fails, the egress-mediation architecture itself needs rethinking.
* Gondolin's own maturity ("early", breaking reshapes as recently as 0.6.0)
  means SDK behavior needs empirical verification, not just reading the docs.
* A full build-out of M2–M9 before M1's real Pi session works would mean
  discovering an SDK-level blocker only after substantial unrelated work is
  already committed.

## Considered Options

* Build out the full design (config layering, VFS policy, git gating, content
  checks, sessions) before ever booting a real VM against real Pi
* Walking skeleton first: a minimal end-to-end path (M1: `corb run --dir
  work=.` boots a tagged image and lands in a live Pi TUI), gated on M0's two
  blocking spikes (R1, R3) passing against a real boot

## Decision Outcome

Chosen option: "Walking skeleton first, gated on M0's blocking spikes", because
the two riskiest assumptions (HTTP/2-to-model-API interop and MITM-CA trust)
are cheap to test in isolation and expensive to discover wrong after the fact —
M0.1 and M0.2 are marked blocking specifically because nothing else should be
built until a real guest can actually reach the model API and trust the
injected CA.

### Consequences

* Good, because a real architectural blocker (the non-root VFS mount problem,
  found verifying M1.6) surfaced early, while only the walking skeleton existed,
  rather than after M5's filesystem policy layer was already built on top of a
  broken mount.
* Good, because M0's non-blocking items (M0.3–M0.7: R16, R2, R5/R12, R6, R13)
  were explicitly allowed to stay open and picked up only when they became
  load-bearing, rather than gating all progress on answering every open
  question up front.
* Bad, because the walking skeleton (M1) shipped with two acceptance criteria
  still unverified — real interactive-terminal behavior and a real model
  completion — since neither is reachable in the actual delivery environment,
  a residual risk carried forward rather than closed.
* Neutral, because this makes "one milestone item at a time, independently
  re-verified before commit" the standing delivery discipline for the rest of
  the project, not just for M0/M1.
