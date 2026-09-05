#!/usr/bin/env bash
# Packaging smoke test: does the published npm tarball actually install and
# run, as a real user would get it (npm install corb / npx corb)? This does
# NOT exercise `corb run` or `corb image build` — corb isn't published to npm
# yet, `guest/` isn't in package.json's `files` list, and there is no image
# registry, so neither can work today for reasons unrelated to packaging
# correctness. This only asserts that the packaged CLI itself installs and
# executes: `corb --help`, `corb doctor`, and a read-only workspace-inspection
# command (`corb explain DIR`) all run without a packaging-level failure —
# e.g. a missing `dist/`, a broken `bin` entry, or an unresolvable import.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

WORK_DIR="$(mktemp -d)"
trap 'rm -rf "$WORK_DIR"' EXIT

echo "==> smoke-test: building (npm run build)"
(cd "$ROOT_DIR" && npm run build)

echo "==> smoke-test: packing (npm pack)"
(cd "$ROOT_DIR" && npm pack --pack-destination "$WORK_DIR")

# Compute the tarball's filename ourselves rather than parsing npm pack's own
# stdout/notice output (fragile, format has varied across npm versions) --
# this matches npm's own stable <name>-<version>.tgz convention.
TARBALL_NAME="corb-$(node -p "require('$ROOT_DIR/package.json').version").tgz"
TARBALL_PATH="$WORK_DIR/$TARBALL_NAME"

INSTALL_DIR="$WORK_DIR/install"
mkdir -p "$INSTALL_DIR"

echo "==> smoke-test: installing $TARBALL_NAME into a fresh project"
(cd "$INSTALL_DIR" && npm init -y >/dev/null && npm install "$TARBALL_PATH")

CORB="$INSTALL_DIR/node_modules/.bin/corb"

echo "==> smoke-test: running corb --help"
"$CORB" --help

echo "==> smoke-test: running corb doctor"
# corb doctor's own exit code is not a safe pass/fail signal here: it exits 1
# whenever any individual check legitimately fails on this host (no
# /dev/kvm, no qemu, no docker, ...), which is unrelated to whether the npm
# tarball packaged correctly and would make this smoke test permanently red
# on CI runners that lack KVM. So the `|| true` below is required -- don't
# let `set -e` abort the script over an expected, tolerable host-capability
# fail/warn. What we actually assert is that the check pipeline ran to
# completion end to end (every import resolved, nothing threw or hung),
# which only the summary line below proves.
DOCTOR_OUTPUT="$("$CORB" doctor)" || true
echo "$DOCTOR_OUTPUT"
if ! grep -qE '^corb doctor: [0-9]+ check\(s\), [0-9]+ failed, [0-9]+ warning\(s\)\.$' <<<"$DOCTOR_OUTPUT"; then
  echo "smoke-test: FAILED -- corb doctor did not print its expected summary line (a packaging-level break, not a host-capability fail/warn)" >&2
  exit 1
fi

echo "==> smoke-test: running corb explain on a throwaway workspace"
EXPLAIN_DIR="$WORK_DIR/workspace"
mkdir -p "$EXPLAIN_DIR"
"$CORB" explain "$EXPLAIN_DIR"

echo "smoke-test: OK"
