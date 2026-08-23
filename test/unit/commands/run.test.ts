// Unit tests for `src/commands/run.ts` — M2.5's `--dry-run` plus M2.6's
// `--dir`/`--primary`/`--trust-config` and the trust-gate branching. Covers:
// argv parsing of `--dry-run` (alone, with a dir, with `-- pi args`,
// defaulting to false); `--dry-run` never requires `ANTHROPIC_API_KEY` and
// never calls `runSession`; `--dir` flag parsing (single, multiple with a
// repeated NAME, every malformed case); `buildCliLayer`'s name-keyed
// last-one-wins behavior; `--primary` matching/not-matching a configured
// name; and the trust-gate branching in `runRunCommand` itself (mocked
// `runSession`, matching M2.5's established pattern).
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

import {
  DirFlagError,
  PrimaryDirectoryError,
  TrustConfirmationRequiredError,
  buildCliLayer,
  parseDirFlag,
  parseRunArgs,
  resolvePrimaryName,
  runRunCommand,
} from "../../../src/commands/run.ts";
import type { EffectiveConfig } from "../../../src/config/load.ts";

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

describe("commands/run: parseRunArgs --dir/--primary/--trust-config", () => {
  it("defaults dirFlags to [], primary to undefined, trustConfig to false", () => {
    const args = parseRunArgs([]);
    expect(args.dirFlags).toEqual([]);
    expect(args.primary).toBeUndefined();
    expect(args.trustConfig).toBe(false);
  });

  it("parses a single --dir", () => {
    const args = parseRunArgs(["--dir", "extra=/tmp/extra:ro"]);
    expect(args.dirFlags).toEqual(["extra=/tmp/extra:ro"]);
  });

  it("parses multiple --dir flags, in argv order", () => {
    const args = parseRunArgs(["--dir", "a=/tmp/a", "--dir", "b=/tmp/b:ro"]);
    expect(args.dirFlags).toEqual(["a=/tmp/a", "b=/tmp/b:ro"]);
  });

  it("parses --primary", () => {
    const args = parseRunArgs(["--primary", "extra"]);
    expect(args.primary).toBe("extra");
  });

  it("parses --trust-config", () => {
    expect(parseRunArgs([]).trustConfig).toBe(false);
    expect(parseRunArgs(["--trust-config"]).trustConfig).toBe(true);
  });
});

describe("commands/run: parseDirFlag", () => {
  it("parses NAME=HOST with no mode suffix, defaulting to rw", () => {
    expect(parseDirFlag("extra=/tmp/extra")).toEqual({ name: "extra", host: "/tmp/extra", mode: "rw" });
  });

  it("parses NAME=HOST:ro", () => {
    expect(parseDirFlag("extra=/tmp/extra:ro")).toEqual({ name: "extra", host: "/tmp/extra", mode: "ro" });
  });

  it("parses NAME=HOST:rw", () => {
    expect(parseDirFlag("extra=/tmp/extra:rw")).toEqual({ name: "extra", host: "/tmp/extra", mode: "rw" });
  });

  it("resolves a relative HOST against process.cwd(), same as the positional directory logic", () => {
    const parsed = parseDirFlag("extra=some/relative/dir:ro");
    expect(parsed.host).toBe(path.resolve("some/relative/dir"));
  });

  it("splits NAME from the rest on the first '=' only", () => {
    expect(parseDirFlag("extra=/tmp/a=b")).toEqual({ name: "extra", host: "/tmp/a=b", mode: "rw" });
  });

  it("treats a trailing colon segment containing '/' as part of the host, not a mode marker", () => {
    const parsed = parseDirFlag("extra=/tmp/weird:sub/dir");
    expect(parsed.host).toBe("/tmp/weird:sub/dir");
    expect(parsed.mode).toBe("rw");
  });

  it("rejects a --dir value missing '='", () => {
    expect(() => parseDirFlag("no-equals-sign")).toThrow(DirFlagError);
  });

  it("rejects a --dir value with an empty NAME", () => {
    expect(() => parseDirFlag("=/tmp/extra")).toThrow(DirFlagError);
  });

  it("rejects a --dir value with an empty HOST", () => {
    expect(() => parseDirFlag("extra=")).toThrow(DirFlagError);
  });

  it("rejects a --dir value with an empty HOST after stripping a mode suffix", () => {
    expect(() => parseDirFlag("extra=:ro")).toThrow(DirFlagError);
  });

  it("rejects a --dir value whose mode suffix isn't exactly ro or rw", () => {
    expect(() => parseDirFlag("extra=/tmp/extra:bogus")).toThrow(DirFlagError);
  });
});

describe("commands/run: buildCliLayer", () => {
  it("returns {} for an empty dirFlags array", () => {
    expect(buildCliLayer([])).toEqual({});
  });

  it("builds one dir entry per --dir flag, in argv order", () => {
    const layer = buildCliLayer(["a=/tmp/a", "b=/tmp/b:ro"]);
    expect(layer.dir).toEqual([
      { name: "a", host: "/tmp/a", mode: "rw" },
      { name: "b", host: "/tmp/b", mode: "ro" },
    ]);
  });

  it("two --dir flags sharing a NAME both appear in the layer, in order — later wins once merged (verified via mergeConfigLayers)", async () => {
    const { mergeConfigLayers } = await import("../../../src/config/load.ts");
    const layer = buildCliLayer(["a=/tmp/first:ro", "a=/tmp/second:rw"]);
    expect(layer.dir).toEqual([
      { name: "a", host: "/tmp/first", mode: "ro" },
      { name: "a", host: "/tmp/second", mode: "rw" },
    ]);
    const merged = mergeConfigLayers([layer]);
    expect(merged.dir).toEqual([{ name: "a", host: "/tmp/second", mode: "rw", rules: [] }]);
  });
});

describe("commands/run: resolvePrimaryName", () => {
  function config(names: string[]): EffectiveConfig {
    return {
      egress: { "block-internal-ranges": true, websockets: false },
      git: { "ssh-agent": true, "allow-push": false },
      dir: names.map((name) => ({ name, rules: [] })),
      policy: { enabled: true, "secret-scan": true, "fail-open": true },
    };
  }

  it("defaults to defaultName when primaryFlag is undefined", () => {
    expect(resolvePrimaryName(config(["myrepo"]), undefined, "myrepo")).toBe("myrepo");
  });

  it("uses primaryFlag when given, and it matches a configured name", () => {
    expect(resolvePrimaryName(config(["myrepo", "extra"]), "extra", "myrepo")).toBe("extra");
  });

  it("throws PrimaryDirectoryError when primaryFlag doesn't match any configured name", () => {
    expect(() => resolvePrimaryName(config(["myrepo"]), "nope", "myrepo")).toThrow(PrimaryDirectoryError);
  });
});

describe("commands/run: runRunCommand", () => {
  let workDir: string;
  let configDir: string;
  let previousConfigDir: string | undefined;
  let previousApiKey: string | undefined;
  let logSpy: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    workDir = fs.mkdtempSync(path.join(os.tmpdir(), "corb-run-work-"));
    configDir = fs.mkdtempSync(path.join(os.tmpdir(), "corb-run-config-"));
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

  describe("--dry-run", () => {
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

    it("a requires-confirmation verdict on --dry-run still just prints — it does not throw", async () => {
      // First run ever for this dir: no trusted.json entry -> requires-confirmation.
      await expect(runRunCommand([workDir, "--dry-run"])).resolves.toBeUndefined();
      const output = logSpy.mock.calls[0]?.[0] as string;
      expect(output).toContain("verdict: REQUIRES-CONFIRMATION");
      expect(runSessionMock).not.toHaveBeenCalled();
    });
  });

  describe("trust gate (real, non-dry-run invocations)", () => {
    it("requires-confirmation without --trust-config throws and never calls runSession", async () => {
      await expect(runRunCommand([workDir])).rejects.toThrow(TrustConfirmationRequiredError);
      expect(runSessionMock).not.toHaveBeenCalled();
      expect(fs.existsSync(path.join(configDir, "trusted.json"))).toBe(false);
    });

    it("requires-confirmation with --trust-config records acceptance (trusted.json written) then calls runSession", async () => {
      await expect(runRunCommand([workDir, "--trust-config"])).resolves.toBeUndefined();
      expect(runSessionMock).toHaveBeenCalledTimes(1);
      expect(fs.existsSync(path.join(configDir, "trusted.json"))).toBe(true);
      const stored = JSON.parse(fs.readFileSync(path.join(configDir, "trusted.json"), "utf8"));
      expect(Object.keys(stored)).toEqual([fs.realpathSync(workDir)]);
    });

    it("already-trusted proceeds straight to runSession without requiring --trust-config", async () => {
      // Accept once first (simulating a prior successful run).
      await runRunCommand([workDir, "--trust-config"]).catch(() => {});
      runSessionMock.mockClear();

      await runRunCommand([workDir]);
      expect(runSessionMock).toHaveBeenCalledTimes(1);
      const [options] = runSessionMock.mock.calls[0] as [{ dirs: unknown[]; primary: string }];
      expect(options.primary).toBe(path.basename(fs.realpathSync(workDir)));
    });

    it("--trust-config passed while already trusted is harmless and still proceeds", async () => {
      await runRunCommand([workDir, "--trust-config"]).catch(() => {});
      runSessionMock.mockClear();

      await expect(runRunCommand([workDir, "--trust-config"])).resolves.toBeUndefined();
      expect(runSessionMock).toHaveBeenCalledTimes(1);
    });
  });

  describe("--dir / --primary wiring into runSession", () => {
    it("passes fullConfig.dir (positional + --dir entries) and the resolved primary to runSession, after accepting trust", async () => {
      const extraDir = fs.mkdtempSync(path.join(os.tmpdir(), "corb-run-extra-"));
      try {
        await runRunCommand([workDir, "--dir", `extra=${extraDir}:ro`, "--trust-config"]);
        expect(runSessionMock).toHaveBeenCalledTimes(1);
        const [options] = runSessionMock.mock.calls[0] as [{ dirs: { name: string; hostPath: string; mode: string }[]; primary: string }];
        expect(options.dirs).toEqual([
          { name: path.basename(fs.realpathSync(workDir)), hostPath: fs.realpathSync(workDir), mode: "rw" },
          { name: "extra", hostPath: extraDir, mode: "ro" },
        ]);
        expect(options.primary).toBe(path.basename(fs.realpathSync(workDir)));
      } finally {
        fs.rmSync(extraDir, { recursive: true, force: true });
      }
    });

    it("--primary selects a --dir-added entry as primary", async () => {
      const extraDir = fs.mkdtempSync(path.join(os.tmpdir(), "corb-run-extra-"));
      try {
        await runRunCommand([workDir, "--dir", `extra=${extraDir}:rw`, "--primary", "extra", "--trust-config"]);
        const [options] = runSessionMock.mock.calls[0] as [{ primary: string }];
        expect(options.primary).toBe("extra");
      } finally {
        fs.rmSync(extraDir, { recursive: true, force: true });
      }
    });

    it("an unmatched --primary fails clearly before calling runSession", async () => {
      await expect(runRunCommand([workDir, "--primary", "does-not-exist"])).rejects.toThrow(PrimaryDirectoryError);
      expect(runSessionMock).not.toHaveBeenCalled();
    });

    it("a CLI-added --dir does not affect the trust verdict (still requires-confirmation on first run, same as with no --dir at all)", async () => {
      const extraDir = fs.mkdtempSync(path.join(os.tmpdir(), "corb-run-extra-"));
      try {
        await expect(runRunCommand([workDir, "--dir", `extra=${extraDir}:ro`])).rejects.toThrow(
          TrustConfirmationRequiredError,
        );
        expect(runSessionMock).not.toHaveBeenCalled();
      } finally {
        fs.rmSync(extraDir, { recursive: true, force: true });
      }
    });
  });
});
