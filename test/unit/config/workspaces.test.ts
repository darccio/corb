import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  assertValidWorkspaceName, InvalidWorkspaceNameError, listWorkspaces, WorkspaceSourceError, workspaceSourcePaths,
} from "../../../src/config/workspaces.ts";

describe("config/workspaces", () => {
  let root: string;
  let configDir: string;
  let source: string;
  const previousConfigDir = process.env.CORB_CONFIG_DIR;

  beforeEach(() => {
    root = fs.mkdtempSync(path.join(os.tmpdir(), "corb-workspaces-"));
    configDir = path.join(root, "config");
    source = path.join(root, "source");
    fs.mkdirSync(configDir);
    fs.mkdirSync(source);
  });

  afterEach(() => {
    if (previousConfigDir === undefined) delete process.env.CORB_CONFIG_DIR;
    else process.env.CORB_CONFIG_DIR = previousConfigDir;
    fs.rmSync(root, { recursive: true, force: true });
  });

  function workspace(parent: string, name: string, text = ""): string {
    const dir = path.join(parent, name);
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(path.join(dir, "corb.toml"), text);
    return dir;
  }

  function listing(paths = [source]) {
    return listWorkspaces(workspaceSourcePaths({ workspaces: { paths } }, configDir), configDir);
  }

  it("lists sources in order and replaces whole workspace directories", () => {
    const second = path.join(root, "second");
    const third = path.join(root, "third");
    const firstCopy = workspace(source, "shared", 'name = "first"');
    workspace(source, "only-first");
    const secondCopy = workspace(second, "shared", 'name = "second"');
    const thirdCopy = workspace(third, "shared", 'name = "third"');
    const result = listing([source, second, third]);
    expect(result.sources.map((entry) => entry.path)).toEqual([source, second, third]);
    expect(result.workspaces).toHaveLength(2);
    expect(result.workspaces.find((entry) => entry.name === "shared")).toMatchObject({
      dir: thirdCopy, realPath: fs.realpathSync(thirdCopy), source: 2, valid: true,
      corbToml: fs.realpathSync(path.join(thirdCopy, "corb.toml")),
      replaced: [{ source: 0, dir: firstCopy }, { source: 1, dir: secondCopy }],
    });
    expect(result.allWorkspaces).toHaveLength(4);
  });

  it("defaults to the config directory and follows CORB_CONFIG_DIR", () => {
    process.env.CORB_CONFIG_DIR = configDir;
    const dir = workspace(path.join(configDir, "workspaces"), "personal");
    expect(listWorkspaces(workspaceSourcePaths({})).workspaces[0]?.dir).toBe(dir);
    expect(workspaceSourcePaths({}, configDir)).toEqual([
      { raw: path.join(configDir, "workspaces"), path: path.join(configDir, "workspaces") },
    ]);
  });

  it("explicit paths replace the default and [] disables sources", () => {
    workspace(path.join(configDir, "workspaces"), "default");
    workspace(source, "explicit");
    expect(listing().workspaces.map((entry) => entry.name)).toEqual(["explicit"]);
    expect(listing([])).toEqual({ sources: [], workspaces: [], allWorkspaces: [] });
  });

  it("keeps raw path spelling alongside the expanded path", () => {
    const previousHome = process.env.HOME;
    process.env.HOME = root;
    try {
      const result = listWorkspaces(workspaceSourcePaths({ workspaces: { paths: ["~/source"] } }, configDir), configDir);
      expect(result.sources).toEqual([{ raw: "~/source", path: source, realPath: fs.realpathSync(source), exists: true }]);
    } finally {
      if (previousHome === undefined) delete process.env.HOME;
      else process.env.HOME = previousHome;
    }
  });

  it("keeps missing sources in metadata", () => {
    const missing = path.join(source, "missing", "nested");
    expect(listing([missing])).toEqual({
      sources: [{ raw: missing, path: missing, realPath: missing, exists: false }], workspaces: [], allWorkspaces: [],
    });
  });

  it("resolves existing symlinked ancestors for a missing source", () => {
    const alias = path.join(root, "alias");
    fs.symlinkSync(source, alias);
    expect(listing([path.join(alias, "missing")]).sources[0]).toMatchObject({ realPath: path.join(source, "missing"), exists: false });
  });

  it("rejects a source that is a file and names that source", () => {
    const file = path.join(root, "file");
    fs.writeFileSync(file, "");
    expect(() => listing([file])).toThrow(WorkspaceSourceError);
    expect(() => listing([file])).toThrow(`workspace source '${file}'`);
    expect(() => listing([file])).toThrow("not a directory");
  });

  it("fails rather than falling back when an existing source cannot be canonicalized", () => {
    const realpath = fs.realpathSync;
    const spy = vi.spyOn(fs, "realpathSync").mockImplementation((file) => {
      if (file === source) throw Object.assign(new Error("source canonicalization denied"), { code: "EACCES" });
      return realpath(file);
    });
    try {
      expect(() => listing()).toThrow(WorkspaceSourceError);
      expect(() => listing()).toThrow("source canonicalization denied");
    } finally {
      spy.mockRestore();
    }
  });

  it.each([false, true])("rejects a dangling source link or ancestor (nested=%s)", (nested) => {
    const alias = path.join(root, "dangling");
    fs.symlinkSync(path.join(root, "absent"), alias);
    const input = nested ? path.join(alias, "child") : alias;
    expect(() => listing([input])).toThrow(WorkspaceSourceError);
    expect(() => listing([input])).toThrow(input);
  });

  it("finds symlinked workspace directories and workspace files", () => {
    const target = workspace(path.join(root, "elsewhere"), "target");
    const file = path.join(root, "external.toml");
    const sum = path.join(root, "external.sum");
    fs.writeFileSync(file, "");
    fs.writeFileSync(sum, "pins");
    fs.unlinkSync(path.join(target, "corb.toml"));
    fs.symlinkSync(file, path.join(target, "corb.toml"));
    fs.symlinkSync(sum, path.join(target, "corb.sum"));
    const alias = path.join(source, "linked");
    fs.symlinkSync(target, alias);
    expect(listing().workspaces).toEqual([{
      name: "linked", dir: alias, realPath: fs.realpathSync(target), corbToml: file, corbSum: sum,
      source: 0, valid: true, replaced: [],
    }]);
  });

  it("skips dot directories, ordinary files and directories without corb.toml", () => {
    workspace(source, ".hidden");
    fs.mkdirSync(path.join(source, "empty"));
    fs.writeFileSync(path.join(source, "file"), "");
    fs.mkdirSync(path.join(source, "not-a-file"));
    fs.mkdirSync(path.join(source, "not-a-file", "corb.toml"));
    expect(listing().workspaces).toEqual([]);
  });

  it("lists bad names as invalid without parsing their TOML", () => {
    workspace(source, "bad name", "this is not TOML");
    workspace(source, "valid-name", "this is not TOML either");
    expect(listing().workspaces).toEqual(expect.arrayContaining([
      expect.objectContaining({ name: "bad name", valid: false, reason: expect.stringContaining("invalid workspace name") }),
      expect.objectContaining({ name: "valid-name", valid: true }),
    ]));
  });

  it.each(["source", "workspace", "non-workspace", "hidden"])("refuses trusted.json in %s", (location) => {
    let target = source;
    if (location === "workspace") target = workspace(source, "project");
    if (location === "non-workspace" || location === "hidden") {
      target = path.join(source, location === "hidden" ? ".private" : "empty");
      fs.mkdirSync(target);
    }
    fs.writeFileSync(path.join(target, "trusted.json"), "{}");
    expect(() => listing()).toThrow("Trust must stay in the personal config directory");
  });

  it("refuses a source equal to the personal config directory, including aliases", () => {
    const alias = path.join(root, "config-alias");
    fs.symlinkSync(configDir, alias);
    expect(() => listing([alias])).toThrow("source equals the personal config directory");
  });

  it.each(["", ".", "..", "bad/name", "bad\\name", "bad name", "-leading", "_leading", ".leading"])(
    "rejects workspace name %j", (name) => expect(() => assertValidWorkspaceName(name)).toThrow(InvalidWorkspaceNameError),
  );

  it.each(["a", "0", "project-name", "Project_2.3"])("accepts workspace name %s", (name) => {
    expect(() => assertValidWorkspaceName(name)).not.toThrow();
  });
});
