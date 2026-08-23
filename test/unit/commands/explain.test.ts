// Unit tests for `src/commands/explain.ts` — M2.5. Covers: argv parsing
// (`--json` flag, default-to-cwd, an explicit dir argument, rejecting a
// second positional), and an end-to-end resolve+render smoke test against a
// temp dir for both the text and `--json` output.
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { parseExplainArgs, runExplainCommand } from "../../../src/commands/explain.ts";

describe("commands/explain: parseExplainArgs", () => {
  it("defaults dir to process.cwd() and json to false when no args are given", () => {
    const args = parseExplainArgs([]);
    expect(args.dir).toBe(process.cwd());
    expect(args.json).toBe(false);
  });

  it("resolves an explicit dir argument to an absolute path", () => {
    const args = parseExplainArgs(["."]);
    expect(args.dir).toBe(path.resolve("."));
  });

  it("parses --json", () => {
    const args = parseExplainArgs(["--json"]);
    expect(args.json).toBe(true);
    expect(args.dir).toBe(process.cwd());
  });

  it("parses an explicit dir together with --json, in either order", () => {
    expect(parseExplainArgs(["some/dir", "--json"])).toEqual({ dir: path.resolve("some/dir"), json: true });
    expect(parseExplainArgs(["--json", "some/dir"])).toEqual({ dir: path.resolve("some/dir"), json: true });
  });

  it("rejects a second positional argument", () => {
    expect(() => parseExplainArgs(["dir-one", "dir-two"])).toThrow(/unexpected extra argument/);
  });
});

describe("commands/explain: runExplainCommand (end-to-end smoke test)", () => {
  let workDir: string;
  let configDir: string;
  let previousConfigDir: string | undefined;
  let logSpy: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    workDir = fs.mkdtempSync(path.join(os.tmpdir(), "corb-explain-work-"));
    configDir = fs.mkdtempSync(path.join(os.tmpdir(), "corb-explain-config-"));
    previousConfigDir = process.env.CORB_CONFIG_DIR;
    process.env.CORB_CONFIG_DIR = configDir;
    logSpy = vi.spyOn(console, "log").mockImplementation(() => {});
  });

  afterEach(() => {
    logSpy.mockRestore();
    if (previousConfigDir === undefined) {
      delete process.env.CORB_CONFIG_DIR;
    } else {
      process.env.CORB_CONFIG_DIR = previousConfigDir;
    }
    fs.rmSync(workDir, { recursive: true, force: true });
    fs.rmSync(configDir, { recursive: true, force: true });
  });

  it("prints human-readable text by default", async () => {
    await runExplainCommand([workDir]);
    expect(logSpy).toHaveBeenCalledTimes(1);
    const output = logSpy.mock.calls[0]?.[0] as string;
    expect(output).toContain(`workspace: ${fs.realpathSync(workDir)}`);
    expect(output).toContain("trust:");
  });

  it("prints valid, parseable JSON with --json against a dir with a config.toml present", async () => {
    fs.writeFileSync(path.join(configDir, "config.toml"), 'name = "corb-dev"\n');
    await runExplainCommand([workDir, "--json"]);
    expect(logSpy).toHaveBeenCalledTimes(1);
    const output = logSpy.mock.calls[0]?.[0] as string;
    const parsed = JSON.parse(output);
    expect(parsed.config.name).toBe("corb-dev");
    expect(parsed.dir).toBe(fs.realpathSync(workDir));
  });
});
