import test from "node:test";
import assert from "node:assert/strict";
import { parsePlan, delta, assertPreimages } from "./plan.mjs";

const before = [{ P: "musl", V: "1.2.5-r24" }];
test("accepts additions only", () => assert.deepEqual(parsePlan("(1/1) Installing tree (2.2.1-r0)\nOK", before), [{ name: "tree", version: "2.2.1-r0" }]));
test("rejects a base upgrade", () => assert.throws(() => parsePlan("(1/1) Upgrading musl (1.2.5-r24 -> 1.2.5-r25)", before), /base package change/));
test("rejects an unknown transaction operation", () => assert.throws(() => parsePlan("(1/1) Replacing musl (1.2.5-r25)", before), /unrecognized/));
test("rejects a malformed transaction line", () => assert.throws(() => parsePlan("(1/1) Installing tree", before), /unrecognized/));
test("rejects an unexpected reinstall disguised as addition", () => assert.throws(() => parsePlan("(1/1) Installing musl (1.2.5-r24)", before), /base package change/));
test("deletions carry and enforce their preimage", () => {
  const old = [{ path: "/etc/test", hash: "before" }];
  const changes = delta(old, []);
  assert.deepEqual(changes.deleted, ["/etc/test"]);
  assert.doesNotThrow(() => assertPreimages(changes.preimages, old));
  assert.throws(() => assertPreimages(changes.preimages, [{ path: "/etc/test", hash: "consumer" }]), /preconditions differ/);
});
test("a changed account file rejects a different base preimage", () => {
  const changes = delta([{ path: "/etc/passwd", hash: "producer-before" }], [{ path: "/etc/passwd", hash: "producer-after" }]);
  assert.throws(() => assertPreimages(changes.preimages, [{ path: "/etc/passwd", hash: "consumer" }]), /preconditions differ/);
});
