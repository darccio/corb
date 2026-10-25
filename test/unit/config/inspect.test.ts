import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { inspectWorkspaceTrust, orphanTrustRecords } from "../../../src/config/inspect.ts";
import { acceptWorkspace, loadWorkspaceContext, readTrustStore, resolveWorkspace } from "../../../src/config/resolve.ts";
import { parseWorkspaceTrustKey, workspaceTrustKey } from "../../../src/config/workspaces.ts";
import { hashEffectiveConfig, type TrustStore } from "../../../src/config/trust.ts";

describe("config/inspect", () => {
  let root: string;
  let configDir: string;
  let app: string;
  let second: string;
  let outside: string;
  let file: string;
  let oldHome: string | undefined;
  let oldState: string | undefined;

  beforeEach(() => {
    root = fs.mkdtempSync(path.join(os.tmpdir(), "corb-inspect-"));
    configDir = path.join(root, "config");
    app = path.join(root, "app");
    second = path.join(root, "second");
    outside = path.join(root, "outside");
    oldHome = process.env.HOME;
    oldState = process.env.CORB_STATE_DIR;
    process.env.HOME = root;
    process.env.CORB_STATE_DIR = path.join(root, "state");
    const workspace = path.join(configDir, "workspaces", "team");
    for (const dir of [workspace, app, second, outside]) fs.mkdirSync(dir, { recursive: true });
    file = path.join(workspace, "corb.toml");
    write();
  });

  afterEach(() => {
    if (oldHome === undefined) delete process.env.HOME;
    else process.env.HOME = oldHome;
    if (oldState === undefined) delete process.env.CORB_STATE_DIR;
    else process.env.CORB_STATE_DIR = oldState;
    fs.rmSync(root, { recursive: true, force: true });
  });

  function host(name: string, dir: string, mode = "rw") {
    return `[[dir]]\nname = ${JSON.stringify(name)}\nhost = ${JSON.stringify(dir)}\nmode = ${JSON.stringify(mode)}\nprotect-git = false`;
  }

  function write(extra = "", mode = "rw", other = "") {
    fs.writeFileSync(file, `${extra}\n${host("app", app, mode)}\n${other}`);
  }

  function accept(dir?: string) {
    const resolved = resolveWorkspace(dir, {}, { configDir, workspace: "team" });
    acceptWorkspace(resolved.trustKey, resolved.persistentConfig, 1234, { configDir });
    return resolved;
  }

  function inspect(store = readTrustStore(configDir)) {
    return inspectWorkspaceTrust("team", { configDir, store });
  }

  it("parses keys without splitting colons in directory paths", () => {
    expect(parseWorkspaceTrustKey("workspace:team:/projects/a:b")).toEqual({ name: "team", dir: "/projects/a:b" });
    expect(parseWorkspaceTrustKey("/projects/a:b")).toBeUndefined();
    expect(parseWorkspaceTrustKey("workspace:team")).toBeUndefined();
  });

  it("lists missing acceptance, then unchanged records without writing", () => {
    expect(inspect().status).toBe("none");
    expect(inspect().records[0]).toMatchObject({ kind: "host", status: "none" });
    expect(fs.existsSync(path.join(configDir, "trusted.json"))).toBe(false);
    accept();
    const before = fs.readFileSync(path.join(configDir, "trusted.json"), "utf8");
    const result = inspect();
    expect(result.status).toBe("trusted");
    expect(result.records[0]).toMatchObject({ status: "trusted", hashMatches: true, record: { acceptedAt: 1234 } });
    expect(fs.readFileSync(path.join(configDir, "trusted.json"), "utf8")).toBe(before);
  });

  it("reports widened egress and changed directory hosts", () => {
    write('[egress]\nallow = ["one.test"]', "rw", host("second", second));
    accept();
    write('[egress]\nallow = ["one.test", "two.test"]', "rw", host("second", path.join(root, "changed")));
    const result = inspect();
    expect(result.status).toBe("changed");
    expect(result.records[0]?.evaluation?.widened.map((change) => change.field)).toEqual(expect.arrayContaining(["egress.allow", "dir.second.host"]));
    expect(result.records[0]?.hashMatches).toBe(false);
  });

  it("reports lost hosts and unprotected rw-to-ro mounts as narrowing", () => {
    write('[egress]\nallow = ["one.test", "two.test"]');
    accept();
    write('[egress]\nallow = ["one.test"]', "ro");
    const result = inspect();
    expect(result.status).toBe("narrowed");
    expect(result.records[0]?.evaluation?.narrowed.map((change) => change.field)).toEqual(expect.arrayContaining(["egress.allow", "dir.app.mode"]));
  });

  it("keeps protected mode flips subject to DAR-13's existing trust rule", () => {
    fs.writeFileSync(file, host("app", app).replace("protect-git = false", "protect-git = true"));
    accept();
    fs.writeFileSync(file, host("app", app, "ro").replace("protect-git = false", "protect-git = true"));
    expect(inspect().status).toBe("changed");
  });

  it("treats order-only changes as trusted with a different hash", () => {
    write('[egress]\nallow = ["one.test", "two.test"]');
    accept();
    write('[egress]\nallow = ["two.test", "one.test"]');
    const result = inspect();
    expect(result.status).toBe("trusted");
    expect(result.records[0]).toMatchObject({ hashMatches: false, evaluation: { widened: [], narrowed: [] } });
  });

  it("uses each own host's canonical resolver key and one shared persistent config", () => {
    const alias = path.join(root, "alias");
    fs.symlinkSync(app, alias);
    fs.writeFileSync(file, `${host("app", alias)}\n${host("second", second)}`);
    accept(alias);
    accept(second);
    const result = inspect();
    expect(result.records).toHaveLength(2);
    for (const record of result.records) {
      expect(record.key).toBe(workspaceTrustKey("team", record.dir));
      expect(record.key).toBe(resolveWorkspace(record.dir, {}, { configDir, workspace: "team" }).trustKey);
      expect(record.status).toBe("trusted");
    }
    expect(result.records[0]?.dir).toBe(app);
  });

  it("compares extra mounts separately and explains a deleted directory", () => {
    accept();
    const extra = accept(outside);
    expect(inspect().records.find((record) => record.key === extra.trustKey)).toMatchObject({ kind: "extra-mount", status: "trusted" });
    fs.rmSync(outside, { recursive: true });
    const result = inspect();
    expect(result.status).toBe("error");
    const record = result.records.find((item) => item.key === extra.trustKey)!;
    expect(record.error).toContain("does not exist");
    expect(record.evaluation).toBeUndefined();
  });

  it("retains extra-mount records when the workspace has no own hosts", () => {
    fs.writeFileSync(file, "");
    const extra = accept(outside);
    const result = inspect();
    expect(result.error).toContain("no hosted directory of its own");
    expect(result.dirs).toEqual([]);
    expect(result.records).toMatchObject([{ key: extra.trustKey, kind: "extra-mount", status: "trusted" }]);
  });

  it("lists orphan workspace records while ignoring plain directory keys", () => {
    const resolved = accept();
    const record = readTrustStore(configDir)[resolved.trustKey]!;
    const store: TrustStore = { [resolved.trustKey]: record, [workspaceTrustKey("gone", app)]: record, [app]: record };
    expect(orphanTrustRecords(store, loadWorkspaceContext(configDir).listing).map((item) => item.name)).toEqual(["gone"]);
  });

  it("compares an old accepted config with missing builtin-rules", () => {
    const resolved = accept();
    const record = readTrustStore(configDir)[resolved.trustKey]!;
    for (const dir of record.acceptedConfig.dir) delete (dir as Partial<typeof dir>)["builtin-rules"];
    record.configHash = hashEffectiveConfig(record.acceptedConfig);
    const result = inspect({ [resolved.trustKey]: record });
    expect(result.status).toBe("trusted");
  });
});
