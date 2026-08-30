# `bindfs` re-export for the non-root VFS mount blocker

## Status

Accepted

## Context and Problem Statement

Corb drops the agent process to uid 1000 (`dropcap`) before it runs, so that
nothing in the agent's process tree holds root privilege. Verifying this against
a real boot (M1.6) surfaced a blocker: Gondolin's `sandboxfs` mounts every
`vfs.mounts` guest path with a compile-time-literal FUSE option string
(`user_id=0,group_id=0,default_permissions`, no `allow_other` — `main.zig`'s
`mountFuse`), so once `dropcap` drops to uid 1000, the agent has zero
filesystem access: every `stat`/`open`/write against the workspace mount
returns `EACCES` at the guest kernel FUSE layer, before any host-side policy is
ever consulted. No upstream fix exists (Gondolin issue #76, closed unanswered
against 0.12.0), and there is no config surface to add `allow_other` to
`sandboxfs`'s own mount. How should this be fixed without giving up the
privilege drop?

See `docs/gondolin-notes.md` R5, R12, R18, and `docs/design.md` §2.

## Decision Drivers

* The privilege drop (uid 1000) and actual filesystem access are both
  non-negotiable; neither can be sacrificed for the other.
* Whatever fixes this becomes a permanent, load-bearing part of the boot
  sequence, on the same tier of importance as `dropcap` itself.
* Options were evaluated on: coupling to unofficial forks, write performance,
  and whether they leave a visible artifact inside the host-mounted directory.

## Considered Options

* A patched `sandboxfs` binary adding `allow_other`
* `fuse-overlayfs` (from Alpine's `community` stable repo) re-exporting the raw
  mount
* `bindfs`, built from source (not packaged for any current Alpine stable
  branch), re-exporting the raw mount with `--force-user`/`--force-group`

## Decision Outcome

Chosen option: "`bindfs`, built from source, with a pinned and independently
re-derived checksum", because it is purpose-built for exactly this job — a
straight passthrough re-export with uid/gid squashing and `allow_other` on by
default, no overlay/copy-up semantics at all — and measured smaller overhead
than the alternative that also worked. The raw `sandboxfs` mount stays
untouched, root-only, at an internal-only guest path
(`/mnt/corb-raw/work`); `bindfs --force-user=<uid> --force-group=<gid>`
re-exports it at the public `/work`, spliced in via `rootfsInitExtra` after
`sandboxfs` mounts and before `sandboxd` starts accepting exec requests.

### Consequences

* Good, because it closes the blocker without forking anyone else's code: the
  patched-`sandboxfs` option was rejected specifically because it would couple
  Corb to a vendored fork of a Zig source tree Corb doesn't own.
* Good, because it leaves no artifact on the host filesystem — `bindfs` has no
  workdir concept (it is not a copy-up filesystem), unlike `fuse-overlayfs`,
  whose `.corb-fuse-overlay-workdir` directory was visible inside every
  mounted workspace directory on the host disk.
* Good, because it measured faster than the alternative that also worked:
  ~1.15–1.76x overhead on reads (`find`/`grep`) and ~1.44x on small sequential
  writes, versus `fuse-overlayfs`'s ~3x write-loop penalty in the same
  benchmark.
* Good, because it needs no SUID binary at runtime (`fusermount3` is not
  required when the caller is already root, which the boot-time re-export
  always is), whereas the `fuse-overlayfs` predecessor required stripping the
  SUID bit off `fusermount3` as a second layer of mitigation.
* Bad, because `bindfs` is not packaged for any current Alpine stable branch
  (checked 3.22, 3.23, 3.24) — it exists only in `edge/testing`, a provenance
  tier this project avoids, so it must be built from source at image-build
  time, with its source tarball and checksum re-derived from Alpine's own
  aports build recipe rather than trusted from a prior run.
* Bad, because it adds a second FUSE hop (agent → `bindfs` → `sandboxfs` →
  virtio RPC → host) on every guest workspace filesystem operation — a real,
  if modest, and now-measured performance cost that a real build (not just a
  synthetic file tree) still hasn't been benchmarked against (R6 remains open
  for that specific number).
* Neutral, because this fix converts what looked like a `stat`-level
  uid/gid-reporting question (R5/R12's original framing) into a
  kernel-FUSE-layer mounting-uid problem — the lesson generalizes: the actual
  blocker was found only by booting a real VM and testing as the
  dropped-privilege user, not by reading the SDK's types.
