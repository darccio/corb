import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import { afterEach, expect, it } from "vitest";
import { OwnedDockerBuild, ownedBuildMounts } from "../../../e2e/helpers/owned-docker.ts";

const roots: string[] = [];
afterEach(() => { for (const root of roots.splice(0)) fs.rmSync(root, { recursive: true, force: true }); });
function fixture() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "corb-owned-docker-")); roots.push(root);
  const state = path.join(root, "state.json"); const output = path.join(root, "output"); const temporary = path.join(root, "private");
  const mounts = [{ Source: output, Destination: "/output" }, { Source: temporary + "/gondolin-build-abc123", Destination: "/work" }];
  const previous = "a".repeat(64); const owned = "b".repeat(64); const unrelated = "c".repeat(64);
  fs.writeFileSync(state, JSON.stringify({ rows: { [previous]: [] }, stopped: [] }));
  fs.writeFileSync(path.join(root, "docker"), `#!${process.execPath}\nconst fs=require("fs");const p=process.env.CORB_DOCKER_TEST_STATE;const s=JSON.parse(fs.readFileSync(p));const a=process.argv.slice(2);if(a[0]==="ps")console.log(Object.keys(s.rows).join("\\n"));else if(a[0]==="inspect")console.log(JSON.stringify(s.rows[a.at(-1)]));else if(a[0]==="stop"){s.stopped.push(a.at(-1));delete s.rows[a.at(-1)];fs.writeFileSync(p,JSON.stringify(s));}else process.exit(2);\n`, { mode: 0o700 });
  const docker = new OwnedDockerBuild(output, temporary, { PATH: root, CORB_DOCKER_TEST_STATE: state });
  fs.writeFileSync(state, JSON.stringify({ rows: { [previous]: [], [owned]: mounts, [unrelated]: [{ Source: "/elsewhere", Destination: "/output" }] }, stopped: [] }));
  return { state, docker, mounts, previous, owned, unrelated };
}

it("requires both exact owned output and the private SDK work parent", () => {
  const output = "/owned/a/cache/image-build/x86_64"; const temporary = "/tmp/c21-work-a-abc";
  const mounts = [{ Source: output, Destination: "/output" }, { Source: temporary + "/gondolin-build-123abc", Destination: "/work" }];
  expect(ownedBuildMounts(mounts, output, temporary)).toBe(true);
  for (const other of [[], mounts.slice(0, 1), [{ ...mounts[0]!, Source: output + "-other" }, mounts[1]!], [mounts[0]!, { ...mounts[1]!, Source: "/tmp/unrelated/gondolin-build-123abc" }], [mounts[0]!, { ...mounts[1]!, Source: temporary + "/other" }]]) expect(ownedBuildMounts(other, output, temporary)).toBe(false);
});
it("cleans a daemon-owned build container and preserves unrelated containers", () => {
  const value = fixture(); value.docker.sample(); expect(value.docker.cleanup()).toEqual([value.owned]);
  const state = JSON.parse(fs.readFileSync(value.state, "utf8")); expect(Object.keys(state.rows)).toEqual([value.previous, value.unrelated]); expect(state.stopped).toEqual([value.owned]);
});
it("refuses changed Docker mount identities before sending stop", () => {
  const value = fixture(); value.docker.sample(); const state = JSON.parse(fs.readFileSync(value.state, "utf8")); state.rows[value.owned][0].Source = "/unrelated"; fs.writeFileSync(value.state, JSON.stringify(state));
  expect(() => value.docker.cleanup()).toThrow("mount identity changed"); expect(JSON.parse(fs.readFileSync(value.state, "utf8")).stopped).toEqual([]);
});
