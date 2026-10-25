import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { listWorkspaces, selectWorkspace, workspaceTrustKey, type ListedWorkspace } from "../../../src/config/workspaces.ts";
import { resolveLayerHosts } from "../../../src/config/hostpath.ts";
import { parseConfigLayer } from "../../../src/config/schema.ts";

describe("config/workspaces: selection", () => {
  let root: string;
  let source: string;
  let home: string;
  let previousHome: string | undefined;

  beforeEach(() => {
    root = fs.mkdtempSync(path.join(os.tmpdir(), "corb-selection-"));
    source = path.join(root, "source");
    home = path.join(root, "home");
    fs.mkdirSync(source);
    fs.mkdirSync(home);
    previousHome = process.env.HOME;
    process.env.HOME = home;
  });

  afterEach(() => {
    if (previousHome === undefined) delete process.env.HOME;
    else process.env.HOME = previousHome;
    fs.rmSync(root, { recursive: true, force: true });
  });

  function workspace(name: string, text: string, parent = source) {
    const dir = path.join(parent, name);
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(path.join(dir, "corb.toml"), text);
    return dir;
  }

  function hosts(entries: Array<[string, string | undefined]>) {
    return entries.map(([name, host]) => `[[dir]]\nname = ${JSON.stringify(name)}\n${host === undefined ? "" : `host = ${JSON.stringify(host)}\n`}`).join("\n");
  }

  function loadLayer(entry: ListedWorkspace) {
    return resolveLayerHosts(parseConfigLayer(fs.readFileSync(entry.corbToml, "utf8"), entry.corbToml, { scope: "workspace" }), { home, sourceLabel: entry.corbToml });
  }

  function select(opts: { byName?: string; dir?: string } = {}, paths = [source]) {
    const listing = listWorkspaces(paths.map((value) => ({ raw: value, path: value })), path.join(root, "config"));
    return selectWorkspace({ listing, loadLayer, ...opts });
  }

  it("selects by name and reports unknown or invalid names", () => {
    workspace("found", hosts([["project", "/project"]]));
    expect(select({ byName: "found" })).toMatchObject({ name: "found", selectedBy: "name" });
    expect(() => select({ byName: "unknown" })).toThrow("Valid names: found");
    workspace("bad name", "");
    expect(() => select({ byName: "bad name" })).toThrow("invalid workspace name");
  });

  it("never loads or selects a replaced copy", () => {
    const second = path.join(root, "second");
    workspace("shared", 'broken = [');
    const winner = workspace("shared", hosts([["new", "/new"]]), second);
    expect(select({ byName: "shared" }, [source, second])?.entry.dir).toBe(winner);
    expect(select({ dir: "/new/child" }, [source, second])?.name).toBe("shared");
    expect(select({ dir: "/old" }, [source, second])).toBeUndefined();
  });

  it.each(["/project", "/project/child"])("matches %s by path", (dir) => {
    workspace("found", hosts([["project", "/project"]]));
    expect(select({ dir })).toMatchObject({ name: "found", selectedBy: "path", matchedDir: { name: "project" } });
  });

  it("chooses the deepest host within one workspace", () => {
    workspace("found", hosts([["outer", "/project"], ["inner", "/project/deep"]]));
    expect(select({ dir: "/project/deep/child" })?.matchedDir?.name).toBe("inner");
  });

  it("does not match host-less entries or a sibling prefix", () => {
    workspace("found", hosts([["project", undefined], ["other", "/project"]]));
    expect(select({ dir: "/project-sibling" })).toBeUndefined();
    expect(select({ dir: "/unmatched" })).toBeUndefined();
  });

  it("reports all ambiguous workspace names and matching hosts", () => {
    workspace("first", hosts([["one", "/project"]]));
    workspace("second", hosts([["two", "/project/deep"]]));
    expect(() => select({ dir: "/project/deep/child" })).toThrow("first (/project), second (/project/deep)");
  });

  it("matches DIR and host symlinks and expanded home paths", () => {
    const project = path.join(home, "project");
    const child = path.join(project, "child");
    fs.mkdirSync(child, { recursive: true });
    const alias = path.join(root, "alias");
    fs.symlinkSync(project, alias);
    workspace("found", hosts([["project", "~/project"]]));
    expect(select({ dir: path.join(alias, "child") })?.name).toBe("found");
    workspace("found", hosts([["project", alias]]));
    expect(select({ dir: child })?.name).toBe("found");
  });

  it("loads every valid winner and fails on a broken unmatched workspace", () => {
    workspace("first", hosts([["project", "/project"]]));
    const bad = workspace("z-broken", 'unknown = true');
    expect(() => select({ dir: "/project" })).toThrow(path.join(bad, "corb.toml"));
    workspace("z-broken", hosts([["bad", "relative"]]));
    expect(() => select({ dir: "/project" })).toThrow("projects-root");
    expect(select({ byName: "first" })?.name).toBe("first");
  });

  it("exports the namespaced trust key", () => {
    expect(workspaceTrustKey("found", "/project")).toBe("workspace:found:/project");
  });
});
