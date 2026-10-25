import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  loadWorkspaceLs, loadWorkspaceShow, parseWorkspaceLsArgs, parseWorkspaceShowArgs,
  renderWorkspaceLsJson, renderWorkspaceLsText, renderWorkspaceShowJson, renderWorkspaceShowText,
  runWorkspaceCommand,
} from "../../../src/commands/workspace.ts";
import { acceptWorkspace, resolveWorkspace } from "../../../src/config/resolve.ts";
import { readTrustStore } from "../../../src/config/resolve.ts";

describe("commands/workspace", () => {
  let root: string;
  let configDir: string;
  let project: string;
  let source: string;
  let file: string;
  let oldHome: string | undefined;
  let oldConfig: string | undefined;
  let oldState: string | undefined;

  beforeEach(() => {
    root = fs.mkdtempSync(path.join(os.tmpdir(), "corb-workspace-command-"));
    configDir = path.join(root, "config");
    source = path.join(configDir, "workspaces");
    project = path.join(root, "project");
    for (const dir of [path.join(source, "team"), project]) fs.mkdirSync(dir, { recursive: true });
    file = path.join(source, "team", "corb.toml");
    oldHome = process.env.HOME;
    oldConfig = process.env.CORB_CONFIG_DIR;
    oldState = process.env.CORB_STATE_DIR;
    process.env.HOME = root;
    process.env.CORB_CONFIG_DIR = configDir;
    process.env.CORB_STATE_DIR = path.join(root, "state");
    write();
  });

  afterEach(() => {
    vi.restoreAllMocks();
    if (oldHome === undefined) delete process.env.HOME;
    else process.env.HOME = oldHome;
    if (oldConfig === undefined) delete process.env.CORB_CONFIG_DIR;
    else process.env.CORB_CONFIG_DIR = oldConfig;
    if (oldState === undefined) delete process.env.CORB_STATE_DIR;
    else process.env.CORB_STATE_DIR = oldState;
    fs.rmSync(root, { recursive: true, force: true });
  });

  function write(extra = "", mode = "rw") {
    fs.writeFileSync(file, `${extra}\n[[dir]]\nname = "project"\nhost = ${JSON.stringify(project)}\nmode = ${JSON.stringify(mode)}\nprotect-git = false`);
  }

  function accept() {
    const resolved = resolveWorkspace(undefined, {}, { configDir, workspace: "team" });
    acceptWorkspace(resolved.trustKey, resolved.persistentConfig, 1234, { configDir });
    return resolved;
  }

  it("validates groups and positional arguments", async () => {
    expect(parseWorkspaceLsArgs([])).toEqual({ json: false });
    expect(parseWorkspaceLsArgs(["--json"])).toEqual({ json: true });
    expect(() => parseWorkspaceLsArgs(["extra"])).toThrow("corb workspace ls: unexpected argument");
    expect(() => parseWorkspaceLsArgs(["--unknown"])).toThrow();
    expect(parseWorkspaceShowArgs(["team", "--json"])).toEqual({ name: "team", json: true });
    expect(() => parseWorkspaceShowArgs([])).toThrow("exactly one workspace name");
    expect(() => parseWorkspaceShowArgs(["team", "extra"])).toThrow("exactly one workspace name");
    expect(() => parseWorkspaceShowArgs(["bad name"])).toThrow("invalid workspace name");
    await expect(runWorkspaceCommand([])).rejects.toThrow("unsupported subcommand 'undefined'");
    await expect(runWorkspaceCommand(["unknown"])).rejects.toThrow("use 'ls' or 'show'");
  });

  it("lists invalid and replaced copies, current trust and orphans without writes", () => {
    const resolved = accept();
    const record = readTrustStore(configDir)[resolved.trustKey]!;
    fs.writeFileSync(path.join(configDir, "trusted.json"), JSON.stringify({
      [resolved.trustKey]: record, [`workspace:gone:${project}`]: record, [project]: record,
    }));
    fs.mkdirSync(path.join(source, "bad name"));
    fs.writeFileSync(path.join(source, "bad name", "corb.toml"), "");
    const personal = path.join(root, "personal");
    fs.mkdirSync(path.join(personal, "team"), { recursive: true });
    fs.copyFileSync(file, path.join(personal, "team", "corb.toml"));
    fs.writeFileSync(path.join(configDir, "config.toml"), `[workspaces]\npaths = ${JSON.stringify([source, personal])}`);
    const before = fs.readFileSync(path.join(configDir, "trusted.json"), "utf8");
    const { payload, sources } = loadWorkspaceLs();
    const text = renderWorkspaceLsText(payload, sources);
    expect(text).toContain("NAME");
    expect(text).toContain("SOURCE");
    expect(text).toContain("DIRS");
    expect(text).toContain("TRUST");
    expect(text).toContain(`project=${project}`);
    expect(text).toContain("invalid: invalid workspace name");
    expect(text).toContain(`replaces ${path.join(source, "team")}`);
    expect(text).toContain("trust records for workspaces that no longer exist:");
    expect(text).toContain("only reads");
    const json = JSON.parse(renderWorkspaceLsJson(payload));
    expect(json.workspaces.find((row: { name: string }) => row.name === "team")).toMatchObject({ trust: "trusted", source: { index: 1, raw: personal }, records: 1 });
    expect(json.orphanRecords).toEqual([{ key: `workspace:gone:${project}`, name: "gone", dir: project }]);
    expect(fs.readFileSync(path.join(configDir, "trusted.json"), "utf8")).toBe(before);
  });

  it("prints empty sources and lists orphan records even without definitions", () => {
    const initial = accept();
    fs.rmSync(path.dirname(file), { recursive: true });
    const { payload, sources } = loadWorkspaceLs();
    const text = renderWorkspaceLsText(payload, sources);
    expect(text).toContain("corb workspace ls: no workspaces.");
    expect(text).toContain(`source: ${source}`);
    expect(text).toContain(initial.trustKey);
    expect(JSON.parse(renderWorkspaceLsJson(payload)).workspaces).toEqual([]);
  });

  it.each(["none", "trusted", "changed", "narrowed"] as const)("shows %s records in text and JSON", (status) => {
    write('[egress]\nallow = ["one.test"]');
    if (status !== "none") accept();
    if (status === "changed") write('[egress]\nallow = ["one.test", "two.test"]');
    if (status === "narrowed") write('[egress]\nallow = []', "ro");
    const payload = loadWorkspaceShow("team");
    expect(payload.records[0]?.status).toBe(status);
    const text = renderWorkspaceShowText(payload);
    expect(text).toContain(`status: ${status}`);
    expect(text).toContain("effective config:");
    expect(text).toContain("trust records (1):");
    expect(text).toContain(`key: workspace:team:${project}`);
    expect(text).toContain(status === "none" ? "(no record; the first run needs --trust-config)" : "accepted at: 1970-01-01T00:00:01.234Z");
    expect(JSON.parse(renderWorkspaceShowJson(payload)).records[0]).toMatchObject({ status, kind: "host" });
  });

  it("shows implied hosts only in effective config", () => {
    write('[agent]\nprovider = "openai-codex"');
    accept();
    const payload = loadWorkspaceShow("team");
    const text = renderWorkspaceShowText(payload);
    expect(text).toContain('chatgpt.com (implied by [agent] provider = "openai-codex" in workspace "team")');
    expect(text.slice(text.indexOf("accepted snapshot:"))).not.toContain("implied:");
    const json = JSON.parse(renderWorkspaceShowJson(payload));
    expect(json.impliedHosts[0].source).toEqual({ kind: "agent-provider", provider: "openai-codex", layer: "workspace", workspace: "team" });
    expect(json.records[0].acceptedConfig).not.toHaveProperty("impliedHosts");
    expect(json.records[0].acceptedConfig.egress.allow).toContain("chatgpt.com");
  });

  it("shows no-own-host details and retained extra-mount records", () => {
    fs.writeFileSync(file, "");
    const resolved = resolveWorkspace(project, {}, { configDir, workspace: "team" });
    acceptWorkspace(resolved.trustKey, resolved.persistentConfig, 1234, { configDir });
    const payload = loadWorkspaceShow("team");
    expect(payload.config).toBeNull();
    expect(payload.records[0]).toMatchObject({ kind: "extra-mount", status: "trusted" });
    expect(renderWorkspaceShowText(payload)).toContain("Run with --workspace team DIR.");
    const { payload: ls } = loadWorkspaceLs();
    expect(ls.workspaces[0]?.dirs).toEqual([]);
    expect(renderWorkspaceLsText(ls)).toMatch(/team\s+.*\s+-\s+error/);
  });

  it("dispatches successful text and JSON commands and rejects unknown names", async () => {
    const log = vi.spyOn(console, "log").mockImplementation(() => {});
    await runWorkspaceCommand(["ls", "--json"]);
    expect(JSON.parse(log.mock.calls.at(-1)?.[0] as string).workspaces).toHaveLength(1);
    await runWorkspaceCommand(["show", "team"]);
    expect(log.mock.calls.at(-1)?.[0]).toContain("workspace: team");
    await expect(runWorkspaceCommand(["show", "missing"])).rejects.toThrow("Valid names: team");
  });
});
