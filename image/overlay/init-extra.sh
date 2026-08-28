# corb: re-export every raw, root-only mount `src/vm/session.ts` creates at a
# path the dropped-privilege `agent` uid can actually use.
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
# The fix: `src/vm/session.ts` mounts each workspace directory's
# `RealFSProvider`/`ReadonlyProvider` at an internal-only guest path under
# `CORB_RAW_ROOT` below (one subdirectory per directory, named after its
# guest-safe `name`), never referenced again after boot, instead of at the
# public `CORB_PUBLIC_ROOT/<name>` the rest of the system expects. This
# script — spliced into Gondolin's own rootfs init script via
# `init.rootfsInitExtra` (corb-image.json), which runs after `sandboxfs` has
# mounted and performed every configured bind (confirmed:
# `injectBeforeSandboxdExec` splices this right before
# `exec /usr/bin/sandboxd`, i.e. strictly after the
# `wait_for_sandboxfs`/bind-mount block earlier in the same script) and
# before `sandboxd` starts accepting exec requests — re-exports each raw
# mount at its public path through `bindfs`, whose `--force-user`/
# `--force-group` squash the agent uid/gid (read from `/etc/corb/image.json`,
# never hardcoded here — the same principle `image/verify.ts`'s gates already
# follow for the agent uid/gid and pinned Pi version) onto every path seen
# through the re-export. Nothing in this process — nor Pi, nor `dropcap` —
# ever talks to a raw mount directly; only this boot-time re-export does.
#
# M2.4 generalized this script from exactly one hardcoded workspace directory
# (formerly CORB_RAW_WORK_MOUNT="/mnt/corb-raw/work" ->
# CORB_PUBLIC_WORK_MOUNT="/work") to however many directories are actually
# configured for a given session: Gondolin's own init creates one
# subdirectory under CORB_RAW_ROOT per configured `vfs.mounts` guest path
# *before* this script runs (the same mechanism the single-dir version's
# "[ ! -d ... ]" check already relied on as an "is a workspace even
# configured" signal), so the directories under CORB_RAW_ROOT are discovered
# by listing it rather than assumed. Read-only (`ro`-mode) directories are
# re-exported through the exact same `bindfs` invocation as read-write ones
# — no read-only-specific bindfs flag is added. That enforcement is the
# host-side `ReadonlyProvider`'s job (`src/vm/session.ts`): the RPC layer
# denies a write before `bindfs` is even involved, so a second, guest-side
# FUSE read-only flag would only duplicate that enforcement with no
# corresponding UX benefit (contrast with `policygate`, which duplicates
# git/gh policy deliberately as a UX guardrail — see docs/design.md §4). This
# was verified empirically in a real booted VM (M2.4's e2e suite,
# test/e2e/workspace-mounts.e2e.ts): a write attempt through a `ro`-mode
# directory's public path fails.
#
# A later item generalized this further to also cover `src/vm/session.ts`'s
# `gate.json` mount (`GATE_CONFIG_RAW_ROOT` -> `GATE_CONFIG_MOUNT_ROOT`,
# `/run/corb`): that mount is a single, always-present raw path rather than
# 0..N optional named subdirectories, but it hits the exact same
# `sandboxfs`-is-root-only problem the workspace mounts already had, so it
# reuses the same `corb_export_one_mount` re-export primitive directly
# instead of duplicating it. Confirmed empirically against a real booted
# `corb:0.1.0` image before this fix: `dropcap 1000 1000 cat
# /run/corb/gate.json` failed with "Permission denied" even though the file
# is itself world-readable, and `policygate` failed closed on every
# invocation as a result (exit 78, "local policy table unavailable"). Unlike
# the workspace loop, this re-export is unconditional (not gated on any
# directory existing first): `runSession()` mounts `GATE_CONFIG_RAW_ROOT` on
# every session, workspace directories or not.
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
# artifact directory of any kind left behind inside any host workspace
# directory. The previous implementation had a documented, visible cost
# here (`.corb-fuse-overlay-workdir` appearing inside every host workspace
# directory Corb mounts); this implementation does not have that cost at
# all. See docs/gondolin-notes.md's R18 for the fuller before/after.
#
# This still adds a second FUSE hop on every guest file operation through a
# re-exported mount (agent -> this re-export mount -> the untouched
# sandboxfs mount -> virtio RPC -> host), same as the previous
# implementation. docs/gondolin-notes.md's R6 has current, bindfs-specific
# benchmark numbers; not repeated here.
set -eu

CORB_RAW_ROOT="/mnt/corb-raw"
CORB_PUBLIC_ROOT="/work"
CORB_GATE_RAW_ROOT="/mnt/corb-raw-gate"
CORB_GATE_PUBLIC_ROOT="/run/corb"
CORB_IMAGE_JSON="/etc/corb/image.json"

# `wait_for_sandboxfs` (defined earlier in this same script, before this
# snippet is spliced in) already guarantees the fuseBinds loop — which
# creates and bind-mounts every `vfs.mounts` guest path, including every
# subdirectory under CORB_RAW_ROOT and CORB_GATE_RAW_ROOT — has completed by
# the time control reaches here. Polling again anyway, per mount, rather than
# trusting that ordering blindly, is the same discipline the parent script
# itself applies before touching its own sandboxfs mount, and it is what
# makes this script correct independently of exactly how Gondolin's init
# happens to be sequenced in a future release.
#
# Takes the specific raw mount path to wait for as a parameter (generalized
# from an earlier single-directory version's implicit global) because, with
# multiple independent raw mounts, each one's underlying sandboxfs bind can
# become ready at a slightly different moment — waiting for one arbitrary
# mount and assuming the rest are ready too would be an unfounded assumption.
corb_wait_for_raw_mount() {
  raw_mount_path="$1"
  for i in $(seq 1 300); do
    if grep -q " ${raw_mount_path} fuse\.sandboxfs " /proc/mounts; then
      return 0
    fi
    sleep 0.1
  done
  return 1
}

# Re-exports one already-ready raw mount at its public path via `bindfs`.
# Failure here is logged loudly but does not abort the rest of the boot —
# one mount's `bindfs` failure must not take down every other mount's
# access, matching this script's pre-existing "log and degrade gracefully"
# discipline. `label` is only used in log lines, to identify which mount
# failed when more than one is re-exported in the same boot.
corb_export_one_mount() {
  raw_mount_path="$1"
  public_mount_path="$2"
  label="$3"

  if ! corb_wait_for_raw_mount "${raw_mount_path}"; then
    log "[corb] raw mount ${raw_mount_path} never became ready; agent will have no access to '${label}'"
    return 0
  fi

  mkdir -p "${public_mount_path}"
  log "[corb] re-exporting ${raw_mount_path} at ${public_mount_path} (uid=${corb_agent_uid} gid=${corb_agent_gid}, allow_other)"
  # allow_other is bindfs's default (--no-allow-other is the flag to
  # disable it), so it is not passed explicitly here — this mount always
  # runs as root during boot (this script runs before sandboxd starts,
  # entirely within Gondolin's own root-owned init sequence), and relying
  # on a documented default rather than restating it keeps this invocation
  # minimal. If bindfs ever changes that default, the "agent can't reach a
  # re-exported path" failure mode would surface immediately and loudly via
  # image/verify.ts's own read/write gates and this milestone's e2e suites
  # against a real booted VM, not silently. No read-only-specific flag is
  # added for a `ro`-mode workspace directory — see this file's header
  # comment for why that enforcement belongs to the host-side
  # `ReadonlyProvider`, not here.
  if bindfs "--force-user=${corb_agent_uid}" "--force-group=${corb_agent_gid}" "${raw_mount_path}" "${public_mount_path}"; then
    log "[corb] re-export ready at ${public_mount_path}"
  else
    log "[corb] bindfs re-export mount FAILED for '${label}'; agent will have no access to it"
  fi
}

if [ ! -r "${CORB_IMAGE_JSON}" ]; then
  log "[corb] ${CORB_IMAGE_JSON} missing; cannot determine agent uid/gid, skipping all raw-mount re-exports (workspace directories and gate config will be inaccessible to the agent)"
else
  corb_agent_uid="$(jq -r '.uid // empty' "${CORB_IMAGE_JSON}" 2>/dev/null || true)"
  corb_agent_gid="$(jq -r '.gid // empty' "${CORB_IMAGE_JSON}" 2>/dev/null || true)"
  if [ -z "${corb_agent_uid}" ] || [ -z "${corb_agent_gid}" ]; then
    log "[corb] could not read a numeric uid/gid from ${CORB_IMAGE_JSON}; skipping all raw-mount re-exports"
  else
    # Workspace directories: 0..N, optional — configured per-session via
    # `corb.toml`'s `[[dir]]` table, so CORB_RAW_ROOT may legitimately not
    # exist at all.
    #
    # POSIX `sh` glob caveat: `for d in "${CORB_RAW_ROOT}"/*/; do` on a
    # nonexistent or empty directory does NOT safely produce zero
    # iterations — it iterates once with the literal, unexpanded glob
    # pattern as a string, unlike bash with `nullglob`. Guarded against
    # explicitly below: first by checking CORB_RAW_ROOT exists at all (the
    # pre-existing "no workspace configured for this session" signal,
    # generalized from a single directory to a root), then by checking each
    # loop candidate is a real directory before using it, which is what
    # actually protects against the no-match-literal-glob case regardless
    # of shell.
    if [ ! -d "${CORB_RAW_ROOT}" ]; then
      log "[corb] ${CORB_RAW_ROOT} not present (no workspace directories configured for this session); skipping workspace re-export"
    else
      corb_found_any=0
      for d in "${CORB_RAW_ROOT}"/*/; do
        # Strips the trailing slash the trailing-slash glob form adds, so
        # dir_name is the bare directory-entry name (e.g. "corb"), not
        # "corb/". Guards the literal-glob-string case: if nothing matched,
        # $d is the pattern itself, which is not a real directory, so this
        # `[ -d ]` check (against the *unstripped* candidate, before
        # trusting it enough to strip anything) skips it cleanly.
        [ -d "${d}" ] || continue
        corb_found_any=1
        dir_name="${d%/}"
        dir_name="${dir_name##*/}"
        corb_export_one_mount "${CORB_RAW_ROOT}/${dir_name}" "${CORB_PUBLIC_ROOT}/${dir_name}" "workspace:${dir_name}"
      done
      if [ "${corb_found_any}" -eq 0 ]; then
        log "[corb] ${CORB_RAW_ROOT} exists but is empty (no workspace directories configured for this session); skipping workspace re-export"
      fi
    fi

    # `gate.json` config: always present — `runSession()` mounts
    # `GATE_CONFIG_RAW_ROOT` on every session unconditionally, unlike the
    # optional workspace directories above — so this re-export is not gated
    # on anything beyond the uid/gid lookup already having succeeded.
    corb_export_one_mount "${CORB_GATE_RAW_ROOT}" "${CORB_GATE_PUBLIC_ROOT}" "gate-config"
  fi
fi
