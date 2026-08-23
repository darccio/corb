# corb: re-export the raw, root-only workspace mount at a path the
# dropped-privilege `agent` uid can actually use.
#
# Why this exists: Gondolin's own `sandboxfs` mounts every `vfs.mounts` guest
# path with a compile-time-literal FUSE option string —
# "fd={d},rootmode=40000,user_id=0,group_id=0,default_permissions" (see
# node_modules/@earendil-works/gondolin/dist/guest/src/sandboxfs/main.zig's
# `mountFuse`) — with no `allow_other` and no config surface to add it.
# Per plain Linux FUSE semantics that means only the mounting uid (0 — the
# SDK's own /init performs the mount before any of Corb's code runs) can
# touch the mount at all; `dropcap`'s drop to the `agent` uid is otherwise
# unaffected but the dropped process gets EACCES on every stat/open/write
# against the raw mount, checked at the kernel FUSE layer before any
# file-level permission bit is even consulted. There is no upstream fix
# (Gondolin issue #76, closed unanswered as of 0.12.0). See
# docs/gondolin-notes.md's risk register (R5/R12, closed by this fix) and
# docs/design.md for the fuller writeup.
#
# The fix: `src/vm/session.ts` mounts the host workspace directory's
# `RealFSProvider` at an internal-only guest path (`CORB_RAW_WORK_MOUNT`
# below), never referenced again after boot, instead of at the public
# `/work` the rest of the system expects. This script — spliced into
# Gondolin's own rootfs init script via `init.rootfsInitExtra`
# (corb-image.json), which runs after `sandboxfs` has mounted and performed
# every configured bind (confirmed: `injectBeforeSandboxdExec` splices this
# right before `exec /usr/bin/sandboxd`, i.e. strictly after the
# `wait_for_sandboxfs`/bind-mount block earlier in the same script) and
# before `sandboxd` starts accepting exec requests — re-exports that raw
# mount at the public `/work` through `bindfs`, whose `--force-user`/
# `--force-group` squash the workspace uid/gid (read from
# `/etc/corb/image.json`, never hardcoded here — the same principle
# `image/verify.ts`'s gates already follow for the agent uid/gid and pinned
# Pi version) onto every path seen through the re-export. Nothing in this
# process — nor Pi, nor `dropcap` — ever talks to the raw mount directly;
# only this boot-time re-export does.
#
# bindfs, not fuse-overlayfs: bindfs is purpose-built for exactly this job
# (`--force-user`/`--force-group`/`allow_other`, no overlay semantics at
# all — it is a straight passthrough, not a copy-up filesystem), which is a
# better fit than the overlay tool an earlier version of this fix used. It
# is not packaged for any current Alpine stable branch (checked 3.22,
# 3.23 — the version this project pins — and 3.24; it exists only in
# `edge/testing`, which this project avoids as an ongoing provenance cost
# for a security-relevant boot-time binary, and doubly so for
# `edge/testing` specifically, a tier below even `edge/community`). Corb
# instead builds it from source at image-build time
# (`corb-image.json`'s `postBuild.commands`) from a pinned tarball with a
# checksum sourced from Alpine's own (unshipped, source-only) build recipe
# — see that file's comments for the version/checksum/build-dependency
# details. This is arguably *more* supply-chain-controlled than an
# apk-managed package would be: Corb pins the exact source tarball and
# checksum itself, rather than trusting whatever a repository happens to
# serve at build time.
#
# BENEFIT OVER THE PREVIOUS fuse-overlayfs IMPLEMENTATION: bindfs has no
# workdir concept, because it isn't a copy-up filesystem — it never needs
# scratch space on the same device as the mount, so there is no
# artifact directory of any kind left behind inside the host workspace
# directory. The previous implementation had a documented, visible cost
# here (`.corb-fuse-overlay-workdir` appearing inside every host workspace
# directory Corb mounts); this implementation does not have that cost at
# all. See docs/gondolin-notes.md's R18 for the fuller before/after.
#
# This still adds a second FUSE hop on every guest workspace file
# operation (agent -> this re-export mount -> the untouched sandboxfs mount
# -> virtio RPC -> host), same as the previous implementation.
# docs/gondolin-notes.md's R6 has current, bindfs-specific benchmark
# numbers; not repeated here.
set -eu

CORB_RAW_WORK_MOUNT="/mnt/corb-raw/work"
CORB_PUBLIC_WORK_MOUNT="/work"
CORB_IMAGE_JSON="/etc/corb/image.json"

# `wait_for_sandboxfs` (defined earlier in this same script, before this
# snippet is spliced in) already guarantees the fuseBinds loop — which
# creates and bind-mounts every `vfs.mounts` guest path, including
# CORB_RAW_WORK_MOUNT — has completed by the time control reaches here.
# Polling again anyway, rather than trusting that ordering blindly, is the
# same discipline the parent script itself applies before touching its own
# sandboxfs mount, and it is what makes this script correct independently
# of exactly how Gondolin's init happens to be sequenced in a future
# release.
corb_wait_for_raw_mount() {
  for i in $(seq 1 300); do
    if grep -q " ${CORB_RAW_WORK_MOUNT} fuse\.sandboxfs " /proc/mounts; then
      return 0
    fi
    sleep 0.1
  done
  return 1
}

if [ ! -d "${CORB_RAW_WORK_MOUNT}" ]; then
  log "[corb] raw workspace mount ${CORB_RAW_WORK_MOUNT} not present (no workspace configured for this session); skipping re-export"
elif ! corb_wait_for_raw_mount; then
  log "[corb] raw workspace mount ${CORB_RAW_WORK_MOUNT} never became ready; agent will have no workspace access"
elif [ ! -r "${CORB_IMAGE_JSON}" ]; then
  log "[corb] ${CORB_IMAGE_JSON} missing; cannot determine workspace uid/gid, skipping re-export"
else
  corb_agent_uid="$(jq -r '.uid // empty' "${CORB_IMAGE_JSON}" 2>/dev/null || true)"
  corb_agent_gid="$(jq -r '.gid // empty' "${CORB_IMAGE_JSON}" 2>/dev/null || true)"
  if [ -z "${corb_agent_uid}" ] || [ -z "${corb_agent_gid}" ]; then
    log "[corb] could not read a numeric uid/gid from ${CORB_IMAGE_JSON}; skipping re-export"
  else
    mkdir -p "${CORB_PUBLIC_WORK_MOUNT}"
    log "[corb] re-exporting ${CORB_RAW_WORK_MOUNT} at ${CORB_PUBLIC_WORK_MOUNT} (uid=${corb_agent_uid} gid=${corb_agent_gid}, allow_other)"
    # allow_other is bindfs's default (--no-allow-other is the flag to
    # disable it), so it is not passed explicitly here — this mount always
    # runs as root during boot (this script runs before sandboxd starts,
    # entirely within Gondolin's own root-owned init sequence), and
    # relying on a documented default rather than restating it keeps this
    # invocation minimal. If bindfs ever changes that default, the "agent
    # can't reach /work" failure mode would surface immediately and
    # loudly via image/verify.ts's own read/write gates against a real
    # booted VM, not silently.
    if bindfs "--force-user=${corb_agent_uid}" "--force-group=${corb_agent_gid}" "${CORB_RAW_WORK_MOUNT}" "${CORB_PUBLIC_WORK_MOUNT}"; then
      log "[corb] workspace re-export ready at ${CORB_PUBLIC_WORK_MOUNT}"
    else
      log "[corb] bindfs re-export mount FAILED; agent will have no workspace access"
    fi
  fi
fi
