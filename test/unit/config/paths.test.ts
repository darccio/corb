// Unit tests for `src/config/paths.ts`'s M3.1 additions: `corbStateDir()`
// and `defaultAuditPath()`. No dedicated `paths.test.ts` existed before
// this item — the rest of the file's functions (`corbConfigDir()`,
// `configTomlPath()`, `trustStorePath()`) are already exercised indirectly
// via `test/unit/config/resolve.test.ts` and friends, so this file covers
// only the new state-directory helpers, mirroring their reasoning.
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { corbStateDir, defaultAuditPath } from "../../../src/config/paths.ts";

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
});
