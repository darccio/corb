# `bindfs` re-export for the non-root VFS mount blocker

## Status

Accepted

## Context and Problem Statement

Corb drops the agent process to uid 1000 (`dropcap`) before it runs.
Nothing in the agent's process tree holds root privilege.
A real boot during M1.6 verification exposed a blocker.
Gondolin's `sandboxfs` mounts every `vfs.mounts` guest path with a compile-time-literal
FUSE option string: `user_id=0,group_id=0,default_permissions`, with no
`allow_other` (`main.zig`'s `mountFuse`).

Once `dropcap` drops to uid 1000, every `stat`/`open`/write against the workspace
mount returns `EACCES`. The guest kernel FUSE layer denies access before
host-side policy runs. No upstream fix exists: Gondolin issue #76 closed
unanswered against 0.12.0. No configuration can add `allow_other` to
`sandboxfs`'s own mount. What fix preserves the privilege drop?

See `docs/gondolin-notes.md` R5, R12, R18, and `docs/design.md` §2.

## Decision Drivers

* Both the privilege drop (uid 1000) and filesystem access are non-negotiable.
* The fix becomes a permanent part of the boot sequence, as important as `dropcap` itself.
* Evaluation criteria were coupling to unofficial forks, write performance, and visible artifacts inside host-mounted directories.

## Considered Options

* A patched `sandboxfs` binary adding `allow_other`
* `fuse-overlayfs` (from Alpine's `community` stable repo) re-exporting the raw mount
* `bindfs`, built from source to re-export the raw mount with `--force-user`/`--force-group`.
  It is not packaged for any current Alpine stable branch.

## Decision Outcome

Chosen option: "`bindfs`, built from source, with a pinned and independently
re-derived checksum". It provides passthrough re-export with uid/gid squashing
and `allow_other` on by default, without overlay/copy-up semantics.
It measured less overhead than the other working option.

The raw `sandboxfs` mounts stay root-only at internal-only guest paths.
`bindfs --force-user=<uid> --force-group=<gid>` re-exports each workspace
from `/mnt/corb-raw/<name>` to `/work/<name>`, and the gate mount from
`/mnt/corb-raw-gate` to `/run/corb`. `rootfsInitExtra` inserts this step after
`sandboxfs` mounts and before `sandboxd` accepts exec requests.

### Consequences

* Good, because the fix closes the blocker without forking other projects' code.
  The patched-`sandboxfs` option couples Corb to a vendored fork of a Zig source tree it does not own.
* Good, because `bindfs` leaves no artifact on the host filesystem.
  It is not a copy-up filesystem and has no workdir concept.
  In contrast, `fuse-overlayfs` left `.corb-fuse-overlay-workdir` visible inside every mounted workspace directory on the host disk.
* Good, because it measured faster than the other working option.
  Reads (`find`/`grep`) had ~1.15–1.76x overhead, and small sequential writes had ~1.44x overhead.
  In the same benchmark, `fuse-overlayfs` had a ~3x write-loop penalty.
* Good, because it needs no SUID binary at runtime.
  The boot-time re-export always runs as root, so it does not require `fusermount3`.
  The `fuse-overlayfs` predecessor required stripping the SUID bit from `fusermount3` as a second mitigation layer.
* Bad, because `bindfs` is absent from current Alpine stable branches (checked 3.22, 3.23, 3.24).
  It exists only in `edge/testing`, whose provenance tier this project avoids.
  The image build must compile it from source.
  Re-derive its source tarball and checksum from Alpine's aports build recipe. Do not trust a prior run.
* Bad, because every guest workspace filesystem operation adds a second FUSE hop.
  The path is agent → `bindfs` → `sandboxfs` → virtio RPC → host.
  The measured performance cost is modest, but a real build remains unbenchmarked.
  R6 remains open for that number beyond the synthetic file-tree benchmark.
* Neutral, because R5/R12 originally framed this as a `stat`-level uid/gid-reporting question.
  The fix instead concerns the kernel FUSE mounting uid.
  Booting a real VM and testing as the unprivileged user exposed the blocker. Reading the SDK types did not.
