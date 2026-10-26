import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, expect, it } from "vitest";
import { selectLayerWorkspace } from "../../../src/layer/context.ts";
const directories: string[] = [];
afterEach(() => { for (const directory of directories.splice(0)) fs.rmSync(directory, { recursive: true, force: true }); });
function fixture() {
  const config = fs.mkdtempSync(path.join(os.tmpdir(), "corb-layer-context-")); directories.push(config);
  const workspace = path.join(config, "workspaces", "named"); fs.mkdirSync(workspace, { recursive: true });
  fs.writeFileSync(path.join(config, "config.toml"), '[vm]\nimage="private:base"\n');
  fs.writeFileSync(path.join(workspace, "corb.toml"), '[image.layer]\npackages=[]\ncommands=["true"]\n');
  return { config, workspace };
}
it("selects a named recipe without hosted directories or a primary", () => {
  const { config } = fixture(); const selected = selectLayerWorkspace("named", config);
  expect(selected.config.dir).toEqual([]); expect(selected.config.vm?.image).toBe("private:base"); selected.recheck();
});
it("suggests explicit selection without inventing a cwd mount", () => {
  const { config } = fixture(); expect(() => selectLayerWorkspace(undefined, config, "/")).toThrow("--workspace NAME");
});
it("rechecks source identity and definition before publication", () => {
  const { config, workspace } = fixture(); const selected = selectLayerWorkspace("named", config);
  fs.appendFileSync(path.join(workspace, "corb.toml"), '\nhosts=["example.com"]'); expect(() => selected.recheck()).toThrow("changed");
});
it("preserves cwd ambiguity checks when another matching workspace appears", () => {
  const { config, workspace } = fixture();
  const host = path.join(config, "project"); fs.mkdirSync(host);
  fs.appendFileSync(path.join(workspace, "corb.toml"), `\n[[dir]]\nname="project"\nhost=${JSON.stringify(host)}\n`);
  const selected = selectLayerWorkspace(undefined, config, host);
  const second = path.join(config, "workspaces", "second"); fs.mkdirSync(second);
  fs.writeFileSync(path.join(second, "corb.toml"), fs.readFileSync(path.join(workspace, "corb.toml")));
  expect(() => selected.recheck()).toThrow("matches several workspaces");
});
