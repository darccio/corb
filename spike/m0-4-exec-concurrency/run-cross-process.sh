#!/usr/bin/env bash
# M0.4 / R2 — measurement 2 and 3, across two host processes.
#
# 1. Start `session-holder.mjs` under `setsid` (so it survives this shell's
#    process group being torn down between tool calls) with its own log.
# 2. Wait, bounded, for the holder to write its state file — i.e. for the VM
#    to boot AND the long-lived interactive exec to prove itself alive.
# 3. Run `attach-client.mjs` as a SEPARATE process, talking only to the
#    session's unix socket. This is exactly the `corb attach` mechanism.
# 4. Ask the holder, over its own command channel, to prove the long exec is
#    still alive after the attach client has been and gone, and to check that
#    none of the attach client's markers leaked into the long exec's stream.
# 5. Tell the holder to quit; confirm no qemu-system process leaked.
#
# Everything is bounded. Nothing here waits forever.
set -uo pipefail

cd "$(dirname "$0")/../.."

# Never touch the real ~/.local/state/corb or ~/.cache/gondolin/sessions.
# GONDOLIN_SESSIONS_DIR must stay <= 66 chars or the session socket silently
# fails to bind (src/vm/sockpath.ts) and the attach leg would fail for a
# reason that has nothing to do with exec concurrency.
export GONDOLIN_SESSIONS_DIR=/tmp/gsess
export CORB_STATE_DIR=/tmp/corb-spike-m04/state
export CORB_CONFIG_DIR=/tmp/corb-spike-m04/config
mkdir -p "$GONDOLIN_SESSIONS_DIR" "$CORB_STATE_DIR" "$CORB_CONFIG_DIR"

SCRATCH=/tmp/corb-spike-m04
STATE="$SCRATCH/holder-state.json"
CMD="$SCRATCH/holder-cmd.txt"
HOLDER_LOG="$SCRATCH/holder.log"
rm -f "$STATE" "$CMD" "$HOLDER_LOG"

echo "== starting session holder (separate process, setsid) =="
setsid node spike/m0-4-exec-concurrency/session-holder.mjs \
  --state "$STATE" --cmd "$CMD" >"$HOLDER_LOG" 2>&1 &
HOLDER_SHELL_PID=$!

cleanup() {
  if [ -f "$CMD" ]; then echo quit >>"$CMD"; fi
  for _ in $(seq 1 60); do
    [ -f "$STATE" ] || break
    HP=$(sed -n 's/.*"pid": \([0-9]*\).*/\1/p' "$STATE" 2>/dev/null | head -1)
    [ -n "${HP:-}" ] && kill -0 "$HP" 2>/dev/null || break
    sleep 1
  done
}
trap cleanup EXIT

echo "== waiting (bounded, 240s) for the holder's state file =="
for i in $(seq 1 240); do
  [ -f "$STATE" ] && break
  sleep 1
done
if [ ! -f "$STATE" ]; then
  echo "!! holder never produced a state file; last 40 lines of its log:"
  tail -40 "$HOLDER_LOG"
  exit 1
fi
echo "-- holder state --"
cat "$STATE"
HOLDER_PID=$(sed -n 's/.*"pid": \([0-9]*\).*/\1/p' "$STATE" | head -1)
echo "-- holder pid: $HOLDER_PID (this shell's child was $HOLDER_SHELL_PID) --"
echo "-- gondolin sessions dir --"
ls -la "$GONDOLIN_SESSIONS_DIR"

echo
echo "== proving the long exec is alive BEFORE any attach =="
BEFORE="BEFORE_ATTACH_$RANDOM$RANDOM"
{ echo "send echo $BEFORE"; echo "expect $BEFORE"; } >>"$CMD"
sleep 3

echo
echo "== running the attach client, in a SEPARATE process =="
timeout 180 node spike/m0-4-exec-concurrency/attach-client.mjs --state "$STATE" --cmd "$CMD"
ATTACH_RC=$?
echo "-- attach client exit code: $ATTACH_RC --"

echo
echo "== asking the holder whether its long exec survived =="
AFTER="AFTER_ATTACH_$RANDOM$RANDOM"
{
  echo "status"
  echo "pressure"
  echo "send echo $AFTER"
  echo "expect $AFTER"
  echo "assert-absent ATTACH_ONESHOT"
  echo "assert-absent ATTACH_PTY_TURN1"
  echo "assert-absent ATTACH_DROPCAP"
  echo "assert-absent ATTACH_HIJACK_ATTEMPT"
  echo "status"
} >>"$CMD"
sleep 8

echo
echo "== telling the holder to quit =="
echo quit >>"$CMD"
for i in $(seq 1 60); do
  kill -0 "$HOLDER_PID" 2>/dev/null || break
  sleep 1
done
trap - EXIT

echo
echo "================ HOLDER LOG ================"
cat "$HOLDER_LOG"

echo
echo "================ LEAK CHECK ================"
echo "-- qemu-system processes --"
pgrep -af qemu-system || echo "(none)"
echo "-- gondolin-krun-runner processes --"
pgrep -af gondolin || echo "(none)"
echo "-- $GONDOLIN_SESSIONS_DIR --"
ls -la "$GONDOLIN_SESSIONS_DIR"
