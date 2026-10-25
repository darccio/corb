import assert from "node:assert/strict";
import test from "node:test";
import { assertGateReports } from "./gate-report.mjs";

const passing = () => ["user", "privilege-drop", "suid", "removals", "ca-trust", "git-gh-shimmed", "pi"]
  .map(name => ({ name, ok: true, detail: "pass" }));
function failed(name, detail) {
  return passing().map(gate => gate.name === name ? { name, ok: false, detail } : gate);
}
const known = () => failed("ca-trust", "git: ls-remote over https to github.com failed, exit 128: curl 35 TLS connect error: tlsv1 alert decrypt error");

test("accepts seven passing gates", () => assert.doesNotThrow(() => assertGateReports(passing(), passing())));
test("retains only the known baseline Git TLS limit", () => assert.doesNotThrow(() => assertGateReports(known(), known(), passing())));
test("rejects an unrelated baseline failure", () => assert.throws(() => assertGateReports(failed("suid", "changed")), /unrelated baseline/));
test("rejects different baseline TLS failures", () => assert.throws(() => assertGateReports(failed("ca-trust", "node: certificate failure")), /unrelated baseline/));
test("rejects a new candidate failure", () => assert.throws(() => assertGateReports(known(), failed("suid", "changed")), /new candidate/));
test("rejects newly failing TLS after a clean base", () => assert.throws(() => assertGateReports(passing(), known()), /new candidate/));
test("rejects an incomplete report", () => assert.throws(() => assertGateReports(passing().slice(1)), /incomplete/));
