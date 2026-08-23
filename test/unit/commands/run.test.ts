// Unit tests for `src/commands/run.ts`'s `--dry-run` flag (M2.5). Covers:
// argv parsing of `--dry-run` (alone, with a dir, with `-- pi args`,
// defaulting to false), that `--dry-run` does not require
// `ANTHROPIC_API_KEY` to be set, and — the important one — that `--dry-run`
// never calls `runSession` (mocked and asserted non-invocation), while a
// non-dry-run call still reaches it.
//
// `../vm/session.ts`'s `runSession` is mocked at the module level (not a
// real VM boot) precisely so this suite can assert non-invocation without
// depending on KVM/Docker being available.
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const { runSessionMock } = vi.hoisted(() => ({ runSessionMock: vi.fn().mockResolvedValue(undefined) }));
vi.mock("../../../src/vm/session.ts", () => ({
  runSession: runSessionMock,
}));

import { parseRunArgs, runRunCommand } from "../../../src/commands/run.ts";

describe("commands/run: parseRunArgs --dry-run", () => {
  it("defaults dryRun to false when not passed", () => {
    const args = parseRunArgs([]);
    expect(args.dryRun).toBe(false);
  });

  it("parses --dry-run alone", () => {
    const args = parseRunArgs(["--dry-run"]);
    expect(args.dryRun).toBe(true);
    expect(args.dir).toBe(process.cwd());
  });

  it("parses --dry-run together with an explicit dir", () => {
    const args = parseRunArgs(["some/dir", "--dry-run"]);
    expect(args.dryRun).toBe(true);
    expect(args.dir).toBe(path.resolve("some/dir"));
  });

  it("--dry-run is a corb-own flag, not forwarded to pi (it must appear before a literal --)", () => {
    const args = parseRunArgs(["--dry-run", "--", "--some-pi-flag"]);
    expect(args.dryRun).toBe(true);
    expect(args.piArgs).toEqual(["--some-pi-flag"]);
  });
});

describe("commands/run: runRunCommand --dry-run", () => {
  let workDir: string;
  let configDir: string;
  let previousConfigDir: string | undefined;
  let previousApiKey: string | undefined;
  let logSpy: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    workDir = fs.mkdtempSync(path.join(os.tmpdir(), "corb-run-dryrun-work-"));
    configDir = fs.mkdtempSync(path.join(os.tmpdir(), "corb-run-dryrun-config-"));
    previousConfigDir = process.env.CORB_CONFIG_DIR;
    process.env.CORB_CONFIG_DIR = configDir;
    previousApiKey = process.env.ANTHROPIC_API_KEY;
    delete process.env.ANTHROPIC_API_KEY;
    logSpy = vi.spyOn(console, "log").mockImplementation(() => {});
    runSessionMock.mockClear();
  });

  afterEach(() => {
    logSpy.mockRestore();
    if (previousConfigDir === undefined) {
      delete process.env.CORB_CONFIG_DIR;
    } else {
      process.env.CORB_CONFIG_DIR = previousConfigDir;
    }
    if (previousApiKey === undefined) {
      delete process.env.ANTHROPIC_API_KEY;
    } else {
      process.env.ANTHROPIC_API_KEY = previousApiKey;
    }
    fs.rmSync(workDir, { recursive: true, force: true });
    fs.rmSync(configDir, { recursive: true, force: true });
  });

  it("does not require ANTHROPIC_API_KEY and never calls runSession", async () => {
    expect(process.env.ANTHROPIC_API_KEY).toBeUndefined();
    await expect(runRunCommand([workDir, "--dry-run"])).resolves.toBeUndefined();
    expect(runSessionMock).not.toHaveBeenCalled();
  });

  it("prints the same resolve+render output corb explain would produce", async () => {
    await runRunCommand([workDir, "--dry-run"]);
    expect(logSpy).toHaveBeenCalledTimes(1);
    const output = logSpy.mock.calls[0]?.[0] as string;
    expect(output).toContain(`workspace: ${fs.realpathSync(workDir)}`);
    expect(output).toContain("trust:");
    expect(runSessionMock).not.toHaveBeenCalled();
  });
});
