#!/usr/bin/env bash
# M0.4 / R2 — the reading half of the spike, made reproducible.
#
# Prints the exact shipped-SDK source that explains the measured behaviour,
# so the write-up's claims about *why* concurrency works can be re-checked
# without re-reading the whole package. Pinned version: 0.12.0.
set -uo pipefail
cd "$(dirname "$0")/../.."
SDK=node_modules/@earendil-works/gondolin

echo "== pinned version =="
node -e 'const p=require("./node_modules/@earendil-works/gondolin/package.json");console.log(p.name, p.version)'

echo
echo "== 1. control protocol: the complete client->server message set =="
echo "-- (there is no 'list execs' and no 'join exec N'; ClientMessage is closed) --"
sed -n '/^export type ClientMessage/p' "$SDK/dist/src/sandbox/control-protocol.d.ts"
echo "-- and the complete server->client set --"
sed -n '/^export type ServerMessage/p' "$SDK/dist/src/sandbox/control-protocol.d.ts"

echo
echo "== 2. server-ops: handleExec's dispatch — what actually gates a second exec =="
grep -n "Keep file operations mutually exclusive" -A 8 "$SDK/dist/src/sandbox/server-ops.js"

echo
echo "== 3. server-ops: the only admission limit is maxQueuedExecs =="
grep -n "maxQueuedExecs" "$SDK/dist/src/sandbox/server-ops.js"
grep -n "DEFAULT_MAX_QUEUED_EXECS" "$SDK/dist/src/sandbox/server-options.js"

echo
echo "== 4. server-ops: execPressure() =="
grep -n "execPressure() {" -A 8 "$SDK/dist/src/sandbox/server-ops.js"

echo
echo "== 5. server-ops: waitForExecIdle() — busy-waits on ANY live exec =="
grep -n "async waitForExecIdle" -A 14 "$SDK/dist/src/sandbox/server-ops.js"

echo
echo "== 6. server-ops: who calls waitForExecIdle() (i.e. what a live exec blocks) =="
grep -n "await this.waitForExecIdle" -B 6 "$SDK/dist/src/sandbox/server-ops.js" | grep -n "async \|waitForExecIdle"

echo
echo "== 7. vm/core.d.ts: execPressure/waitForExecIdle are NOT on the VM surface =="
echo "-- 'server' is a private field; grep the whole public VM declaration: --"
grep -c "execPressure\|waitForExecIdle" "$SDK/dist/src/vm/core.d.ts"
grep -n "private server" "$SDK/dist/src/vm/core.d.ts"

echo
echo "== 8. session-registry: SessionIpcServer gives each client its own id space =="
grep -n "Per-client id translation" -A 4 "$SDK/dist/src/session-registry.js"
grep -n "INTERNAL_ID_FLOOR" "$SDK/dist/src/session-registry.js"
echo "-- an id the client never allocated is rejected, not routed: --"
grep -n "unknown_id" -B 4 "$SDK/dist/src/session-registry.js"

echo
echo "== 9. session-registry: what an attach client is NOT allowed to do =="
grep -n "Attach clients connect to an already-running VM" -A 3 "$SDK/dist/src/session-registry.js"
grep -n "lifecycle actions are not supported over attach IPC" -B 2 "$SDK/dist/src/session-registry.js"
