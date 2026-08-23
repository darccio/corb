// Unit tests for `src/commands/explain.ts` — M2.5/M2.6. Covers: argv
// parsing (`--json` flag, default-to-cwd, an explicit dir argument,
// rejecting a second positional, and M2.6's `--dir`/`--primary`), an
// end-to-end resolve+render smoke test against a temp dir for both the text
// and `--json` output, and the regression test M2.6 cares most about: that
// `corb explain DIR --dir ... --primary ...` produces exactly the same
// `fullConfig` as the equivalent `corb run DIR --dir ... --primary ...
// --dry-run` invocation would.
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { parseExplainArgs, runExplainCommand } from "../../../src/commands/explain.ts";
import { PrimaryDirectoryError, buildCliLayer, parseRunArgs } from "../../../src/commands/run.ts";
import { resolveWorkspace } from "../../../src/config/resolve.ts";

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
    const expected = { dir: path.resolve("some/dir"), json: true, dirFlags: [], primary: undefined };
    expect(parseExplainArgs(["some/dir", "--json"])).toEqual(expected);
    expect(parseExplainArgs(["--json", "some/dir"])).toEqual(expected);
  });

  it("rejects a second positional argument", () => {
    expect(() => parseExplainArgs(["dir-one", "dir-two"])).toThrow(/unexpected extra argument/);
  });

  it("defaults dirFlags to [] and primary to undefined when not passed", () => {
    const args = parseExplainArgs([]);
    expect(args.dirFlags).toEqual([]);
    expect(args.primary).toBeUndefined();
  });

  it("parses --dir (repeatable) and --primary", () => {
    const args = parseExplainArgs(["--dir", "a=/tmp/a", "--dir", "b=/tmp/b:ro", "--primary", "b"]);
    expect(args.dirFlags).toEqual(["a=/tmp/a", "b=/tmp/b:ro"]);
    expect(args.primary).toBe("b");
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

  it("--dir adds the extra directory to the rendered dir: section, but the trust section is unaffected (still shows only the persistent-config verdict)", async () => {
    const extraDir = fs.mkdtempSync(path.join(os.tmpdir(), "corb-explain-extra-"));
    try {
      await runExplainCommand([workDir, "--dir", `extra=${extraDir}:ro`, "--json"]);
      const output = logSpy.mock.calls[0]?.[0] as string;
      const parsed = JSON.parse(output);
      const names = parsed.config.dir.map((d: { name: string }) => d.name);
      expect(names).toContain("extra");
      // Persistent-only trust: first-time-ever verdict, same as with no --dir at all.
      expect(parsed.trust.verdict).toBe("requires-confirmation");
      expect(parsed.trust.widened).toEqual([
        { field: "workspace", description: "no prior trust record exists for this workspace; treated as first-time widening" },
      ]);
    } finally {
      fs.rmSync(extraDir, { recursive: true, force: true });
    }
  });

  it("an unmatched --primary fails clearly, the same way it would for corb run --dry-run", async () => {
    await expect(runExplainCommand([workDir, "--primary", "does-not-exist"])).rejects.toThrow(PrimaryDirectoryError);
  });

  it("produces exactly the fullConfig an equivalent 'corb run DIR ... --dry-run' invocation would resolve", () => {
    const extraDir = fs.mkdtempSync(path.join(os.tmpdir(), "corb-explain-extra-"));
    try {
      const explainArgs = parseExplainArgs([workDir, "--dir", `extra=${extraDir}:rw`, "--primary", "extra"]);
      const runArgs = parseRunArgs([workDir, "--dir", `extra=${extraDir}:rw`, "--primary", "extra", "--dry-run"]);

      const explainResolved = resolveWorkspace(explainArgs.dir, buildCliLayer(explainArgs.dirFlags), { configDir });
      const runResolved = resolveWorkspace(runArgs.dir, buildCliLayer(runArgs.dirFlags), { configDir });

      expect(explainResolved.fullConfig).toEqual(runResolved.fullConfig);
      expect(explainArgs.primary).toBe(runArgs.primary);
    } finally {
      fs.rmSync(extraDir, { recursive: true, force: true });
    }
  });
});
