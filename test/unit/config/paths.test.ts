// Unit tests for `src/config/paths.ts`'s M3.1 additions: `corbStateDir()`
// and `defaultAuditPath()`. No dedicated `paths.test.ts` existed before
// this item — the rest of the file's functions (`corbConfigDir()`,
// `configTomlPath()`, `trustStorePath()`) are already exercised indirectly
// via `test/unit/config/resolve.test.ts` and friends, so this file covers
// only the new state-directory helpers, mirroring their reasoning.
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { corbStateDir, credentialsStateDir, defaultAuditPath, defaultWorkspacesDir, expandHomePrefix } from "../../../src/config/paths.ts";

describe("config/paths corbStateDir / defaultAuditPath", () => {
  const previousStateDir = process.env.CORB_STATE_DIR;

  afterEach(() => {
    if (previousStateDir === undefined) {
      delete process.env.CORB_STATE_DIR;
    } else {
      process.env.CORB_STATE_DIR = previousStateDir;
    }
  });

  it("corbStateDir() defaults to ~/.local/state/corb", () => {
    delete process.env.CORB_STATE_DIR;
    expect(corbStateDir()).toBe(path.join(os.homedir(), ".local", "state", "corb"));
  });

  it("corbStateDir() respects CORB_STATE_DIR", () => {
    process.env.CORB_STATE_DIR = "/tmp/custom-corb-state";
    expect(corbStateDir()).toBe("/tmp/custom-corb-state");
  });

  it("defaultAuditPath() produces <stateDir>/audit.jsonl for an explicit stateDir", () => {
    expect(defaultAuditPath("/tmp/custom-corb-state")).toBe(path.join("/tmp/custom-corb-state", "audit.jsonl"));
  });

  it("defaultAuditPath() defaults to corbStateDir()/audit.jsonl", () => {
    process.env.CORB_STATE_DIR = "/tmp/custom-corb-state";
    expect(defaultAuditPath()).toBe(path.join("/tmp/custom-corb-state", "audit.jsonl"));
  });

  it("credentialsStateDir() defaults to corbStateDir()/credentials, so it follows CORB_STATE_DIR", () => {
    process.env.CORB_STATE_DIR = "/tmp/custom-corb-state";
    expect(credentialsStateDir()).toBe(path.join("/tmp/custom-corb-state", "credentials"));
  });
});

describe("config/paths: workspace sources", () => {
  const previousHome = process.env.HOME;
  const previousConfigDir = process.env.CORB_CONFIG_DIR;
  let home: string;

  beforeEach(() => {
    home = fs.mkdtempSync(path.join(os.tmpdir(), "corb-paths-home-"));
    process.env.HOME = home;
  });

  afterEach(() => {
    if (previousHome === undefined) delete process.env.HOME;
    else process.env.HOME = previousHome;
    if (previousConfigDir === undefined) delete process.env.CORB_CONFIG_DIR;
    else process.env.CORB_CONFIG_DIR = previousConfigDir;
    fs.rmSync(home, { recursive: true, force: true });
  });

  it("uses the current HOME for complete leading home components", () => {
    for (const raw of ["~", "$HOME"]) expect(expandHomePrefix(raw)).toBe(home);
    for (const raw of ["~/Code", "$HOME/Code"]) expect(expandHomePrefix(raw)).toBe(path.join(home, "Code"));
    for (const raw of ["~other/Code", "$HOMES/Code", "relative", "/tmp/$HOME/Code"]) expect(expandHomePrefix(raw)).toBe(raw);
  });

  it("allows an explicit home without reading HOME", () => {
    expect(expandHomePrefix("~/Code", "/custom/home")).toBe("/custom/home/Code");
  });

  it("defaults to corbConfigDir and accepts an explicit config directory", () => {
    process.env.CORB_CONFIG_DIR = "/tmp/corb-personal";
    expect(defaultWorkspacesDir()).toBe("/tmp/corb-personal/workspaces");
    expect(defaultWorkspacesDir("/tmp/other-config")).toBe("/tmp/other-config/workspaces");
  });
});
