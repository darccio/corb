# Walking skeleton behind a blocking spike gate

## Status

Accepted

## Context and Problem Statement

Corb's design rests on assumptions about the Gondolin SDK (0.12.0).
Its authors describe it as "early". At project start, two assumptions were
untested. R1 asks whether a model-provider SDK's HTTP/2 negotiation works through
Gondolin's HTTP/1.x-only egress mediation. R3 asks whether Node/curl/git inside
the guest trust the CA that the MITM TLS interception injects.

Building the full design against these assumptions risked substantial work on
an unreliable foundation. That design includes filesystem policy, git/gh
gating, content checks, and sessions. What delivery sequence limits that risk?

See the project plan's "How we work" section and its M0/M1 milestone
definitions (`let-s-read-the-docs-nifty-russell.md`).

## Decision Drivers

* R1 and R3 support the entire design.
  If HTTP/2 negotiation or CA trust fails, the egress-mediation architecture needs rethinking.
* Gondolin's authors call it "early". Version 0.6.0 already introduced breaking reshapes.
  SDK behavior needs empirical verification beyond reading the docs.
* Building M2–M9 before M1's real Pi session works risks discovering an SDK blocker after substantial unrelated work.

## Considered Options

* Build the full design before booting a real VM against real Pi.
  This includes config layering, VFS policy, git gating, content checks, and sessions.
* Build a walking skeleton first. Require M0's two blocking spikes (R1, R3) to pass against a real boot.
  M1 provides the minimal end-to-end path: `corb run --dir
  work=.`. It boots a tagged image and lands in a live Pi TUI.

## Decision Outcome

Chosen option: "Walking skeleton first, gated on M0's blocking spikes".
The two riskiest assumptions are HTTP/2-to-model-API interop and MITM-CA trust.
They are cheap to test in isolation and expensive to discover wrong later.
M0.1 and M0.2 block further work until a real guest can reach the model API and
trust the injected CA.

### Consequences

* Good, because the non-root VFS mount blocker surfaced during M1.6 verification, while only the walking skeleton existed.
  This avoided building M5's filesystem policy layer on a broken mount.
* Good, because M0's non-blocking items (M0.3–M0.7: R16, R2, R5/R12, R6, R13) remained open until they became essential.
  Progress did not depend on answering every open question first.
* Bad, because the walking skeleton (M1) shipped with two unverified acceptance criteria.
  Real interactive-terminal behavior and a real model completion were unreachable in the delivery environment.
  Both remain residual risks.
* Neutral, because this makes "one milestone item at a time, independently re-verified before commit" the standing delivery discipline.
  It applies to the rest of the project as well as M0/M1.
