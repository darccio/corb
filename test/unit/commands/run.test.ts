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
// Only `runSession` itself is mocked (no real VM boot) — everything else
// this module exports, including `toGlobRules`/`InvalidDirRuleError` (M5.4),
// stays the real implementation via `importOriginal`, so `toWorkspaceDirSpec`'s
// own eager `toGlobRules` validation call (see `src/commands/run.ts`) still
// actually validates in these tests rather than silently no-op'ing against a
// stub.
vi.mock("../../../src/vm/session.ts", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../../src/vm/session.ts")>();
  return { ...actual, runSession: runSessionMock };
});

import {
  DirFlagError,
  PrimaryDirectoryError,
  TrustConfirmationRequiredError,
  buildCliLayer,
  parseDirFlag,
  parseRunArgs,
  resolvePrimaryName,
  runRunCommand,
  withProviderModelArgs,
} from "../../../src/commands/run.ts";
import type { EffectiveConfig } from "../../../src/config/load.ts";
import type { AuditWriter } from "../../../src/policy/audit.ts";
import { InvalidDirRuleError } from "../../../src/vm/session.ts";

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

describe("commands/run: withProviderModelArgs", () => {
  it("leaves piArgs unchanged when agent is entirely unset", () => {
    expect(withProviderModelArgs(undefined, ["--some-pi-flag"])).toEqual(["--some-pi-flag"]);
  });

  it("leaves piArgs unchanged when agent is set but neither provider nor model is", () => {
    expect(withProviderModelArgs({}, ["--some-pi-flag"])).toEqual(["--some-pi-flag"]);
  });

  it("prepends --provider when only provider is set", () => {
    expect(withProviderModelArgs({ provider: "openai" }, ["--foo"])).toEqual(["--provider", "openai", "--foo"]);
  });

  it("prepends --model when only model is set", () => {
    expect(withProviderModelArgs({ model: "gpt-5" }, ["--foo"])).toEqual(["--model", "gpt-5", "--foo"]);
  });

  it("prepends both, provider before model, when both are set", () => {
    expect(withProviderModelArgs({ provider: "openai", model: "gpt-5" }, ["--foo"])).toEqual([
      "--provider",
      "openai",
      "--model",
      "gpt-5",
      "--foo",
    ]);
  });

  it("works against an empty piArgs array", () => {
    expect(withProviderModelArgs({ provider: "openai", model: "gpt-5" }, [])).toEqual([
      "--provider",
      "openai",
      "--model",
      "gpt-5",
    ]);
  });
});

describe("commands/run: runRunCommand", () => {
  let workDir: string;
  let configDir: string;
  let stateDir: string;
  let previousConfigDir: string | undefined;
  let previousStateDir: string | undefined;
  let previousApiKey: string | undefined;
  let logSpy: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    workDir = fs.mkdtempSync(path.join(os.tmpdir(), "corb-run-work-"));
    configDir = fs.mkdtempSync(path.join(os.tmpdir(), "corb-run-config-"));
    stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "corb-run-state-"));
    previousConfigDir = process.env.CORB_CONFIG_DIR;
    process.env.CORB_CONFIG_DIR = configDir;
    // `createAuditWriter`'s default path (`defaultAuditPath()`) falls back
    // to the real `~/.local/state/corb` if this isn't overridden — nothing
    // in these tests ever calls `.flush()` (runSession is mocked below, and
    // `flush()` only actually happens inside its real implementation), but
    // pointing this at a throwaway temp dir avoids even constructing an
    // `AuditWriter` that references the real user state dir, matching the
    // same discipline as `CORB_CONFIG_DIR` above.
    previousStateDir = process.env.CORB_STATE_DIR;
    process.env.CORB_STATE_DIR = stateDir;
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
    if (previousStateDir === undefined) {
      delete process.env.CORB_STATE_DIR;
    } else {
      process.env.CORB_STATE_DIR = previousStateDir;
    }
    if (previousApiKey === undefined) {
      delete process.env.ANTHROPIC_API_KEY;
    } else {
      process.env.ANTHROPIC_API_KEY = previousApiKey;
    }
    fs.rmSync(workDir, { recursive: true, force: true });
    fs.rmSync(configDir, { recursive: true, force: true });
    fs.rmSync(stateDir, { recursive: true, force: true });
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
        const [options] = runSessionMock.mock.calls[0] as [
          {
            dirs: { name: string; hostPath: string; mode: string }[];
            primary: string;
            piArgs: string[];
            egress: unknown;
            secrets: Record<string, unknown> | undefined;
            audit: AuditWriter;
          },
        ];
        expect(options.dirs).toEqual([
          { name: path.basename(fs.realpathSync(workDir)), hostPath: fs.realpathSync(workDir), mode: "rw", rules: [] },
          { name: "extra", hostPath: extraDir, mode: "ro", rules: [] },
        ]);
        expect(options.primary).toBe(path.basename(fs.realpathSync(workDir)));
        // No `[agent]` configured for this workspace, so `piArgs` passes
        // through unchanged (see the dedicated `withProviderModelArgs`
        // suite above for the translation logic itself).
        expect(options.piArgs).toEqual([]);
        // No `config.toml` at all for this workspace, so `egress` is just
        // `BUILTIN_DEFAULTS` and `secrets` stays entirely absent — matching
        // `EffectiveConfig.egress`'s own always-present-but-mostly-default
        // shape and `EffectiveConfig.secrets`'s own optionality.
        expect(options.egress).toEqual({ "block-internal-ranges": true, websockets: false });
        expect(options.secrets).toBeUndefined();
        expect(options.audit).toBeDefined();
        expect(typeof options.audit.record).toBe("function");
        expect(typeof options.audit.flush).toBe("function");
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

  describe("config.toml [agent]/[egress]/[secrets]/[audit] wiring into runSession", () => {
    it("translates [agent].provider/.model into --provider/--model prepended to piArgs, and passes egress/secrets/audit through, with the audit writer actually targeting the configured [audit].path", async () => {
      const customAuditPath = path.join(stateDir, "custom-audit.jsonl");
      const configToml = [
        "[agent]",
        'provider = "openai"',
        'model    = "gpt-5"',
        "",
        "[egress]",
        'allow = ["api.openai.com"]',
        "",
        "[secrets.OPENAI_API_KEY]",
        'hosts    = ["api.openai.com"]',
        "optional = true",
        "",
        "[git]",
        'allow-repos = ["dario/corb"]',
        "",
        "[audit]",
        `path = "${customAuditPath}"`,
      ].join("\n");
      fs.writeFileSync(path.join(configDir, "config.toml"), configToml);

      await runRunCommand([workDir, "--trust-config", "--", "--some-pi-flag"]);
      expect(runSessionMock).toHaveBeenCalledTimes(1);
      const [options] = runSessionMock.mock.calls[0] as [
        {
          piArgs: string[];
          egress: unknown;
          secrets: Record<string, unknown> | undefined;
          git: unknown;
          audit: AuditWriter;
        },
      ];

      // --provider before --model (Pi's own documented ordering), both
      // ahead of whatever was forwarded after a literal `--`.
      expect(options.piArgs).toEqual(["--provider", "openai", "--model", "gpt-5", "--some-pi-flag"]);
      expect(options.egress).toEqual({
        allow: ["api.openai.com"],
        "block-internal-ranges": true,
        websockets: false,
      });
      expect(options.secrets).toEqual({ OPENAI_API_KEY: { hosts: ["api.openai.com"], optional: true } });
      expect(options.git).toEqual({
        "ssh-agent": true,
        "allow-push": false,
        "allow-repos": ["dario/corb"],
      });

      // `AuditWriter` has no path getter, so the only way to prove
      // `options.audit` is a real writer targeting `[audit].path` (not a
      // stub, and not silently defaulting to `defaultAuditPath()`) is a
      // black-box round-trip: record, flush, and read back the configured
      // file.
      expect(fs.existsSync(customAuditPath)).toBe(false);
      options.audit.record({ channel: "session", decision: "allow", subject: "test-subject", sessionId: "test-session" });
      options.audit.flush();
      expect(fs.existsSync(customAuditPath)).toBe(true);
      const lines = fs.readFileSync(customAuditPath, "utf8").trim().split("\n");
      expect(JSON.parse(lines[lines.length - 1] as string)).toMatchObject({
        channel: "session",
        decision: "allow",
        subject: "test-subject",
        sessionId: "test-session",
      });
    });

    it("passes git through unconditionally (built-in defaults) when no [git] block is configured at all", async () => {
      await runRunCommand([workDir, "--trust-config"]);
      const [options] = runSessionMock.mock.calls[0] as [{ git: unknown }];
      expect(options.git).toEqual({ "ssh-agent": true, "allow-push": false });
    });

    it("falls back to defaultAuditPath() (under CORB_STATE_DIR) when [audit].path is not configured", async () => {
      await runRunCommand([workDir, "--trust-config"]);
      const [options] = runSessionMock.mock.calls[0] as [{ audit: AuditWriter }];

      const expectedDefaultPath = path.join(stateDir, "audit.jsonl");
      expect(fs.existsSync(expectedDefaultPath)).toBe(false);
      options.audit.record({ channel: "session", decision: "allow", subject: "test-subject", sessionId: "test-session" });
      options.audit.flush();
      expect(fs.existsSync(expectedDefaultPath)).toBe(true);
    });
  });

  describe("config.toml [[dir]].rules wiring into runSession (M5.4)", () => {
    it("a [[dir]].rules entry reaches runSession as part of the resolved WorkspaceDirSpec", async () => {
      const dirName = path.basename(fs.realpathSync(workDir));
      const configToml = [
        "[[dir]]",
        `name = "${dirName}"`,
        "rules = [",
        '  { glob = "secrets/**", mode = "hidden", reason = "keep secrets out of view" },',
        "]",
      ].join("\n");
      fs.writeFileSync(path.join(configDir, "config.toml"), configToml);

      await runRunCommand([workDir, "--trust-config"]);
      expect(runSessionMock).toHaveBeenCalledTimes(1);
      const [options] = runSessionMock.mock.calls[0] as [
        { dirs: { name: string; hostPath: string; mode: string; rules: unknown[] }[] },
      ];
      expect(options.dirs).toEqual([
        {
          name: dirName,
          hostPath: fs.realpathSync(workDir),
          mode: "rw",
          rules: [{ glob: "secrets/**", mode: "hidden", reason: "keep secrets out of view" }],
        },
      ]);
    });

    it("a [[dir]].rules entry missing 'glob' or 'mode' throws InvalidDirRuleError before runSession is ever called", async () => {
      const dirName = path.basename(fs.realpathSync(workDir));
      const configToml = [
        "[[dir]]",
        `name = "${dirName}"`,
        "rules = [",
        '  { reason = "incomplete rule, has neither glob nor mode" },',
        "]",
      ].join("\n");
      fs.writeFileSync(path.join(configDir, "config.toml"), configToml);

      await expect(runRunCommand([workDir, "--trust-config"])).rejects.toThrow(InvalidDirRuleError);
      expect(runSessionMock).not.toHaveBeenCalled();
    });

    it("a [[dir]].rules entry missing only 'mode' (glob present) still throws InvalidDirRuleError", async () => {
      const dirName = path.basename(fs.realpathSync(workDir));
      const configToml = [
        "[[dir]]",
        `name = "${dirName}"`,
        "rules = [",
        '  { glob = "secrets/**" },',
        "]",
      ].join("\n");
      fs.writeFileSync(path.join(configDir, "config.toml"), configToml);

      await expect(runRunCommand([workDir, "--trust-config"])).rejects.toThrow(InvalidDirRuleError);
      expect(runSessionMock).not.toHaveBeenCalled();
    });
  });
});
