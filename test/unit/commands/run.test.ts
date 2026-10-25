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
import { builtinGitRules } from "../../../src/config/gitprotect.ts";
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
  InvalidExposePortError,
  PrimaryDirectoryError,
  TrustConfirmationRequiredError,
  buildCliLayer,
  parseDirFlag,
  parseExposePort,
  parseRunArgs,
  resolvePrimaryName,
  runRunCommand,
  withProviderModelArgs,
} from "../../../src/commands/run.ts";
import type { EffectiveConfig } from "../../../src/config/load.ts";
import type { AuditWriter } from "../../../src/policy/audit.ts";
import { InvalidDirRuleError, UnmatchableDirRuleGlobError } from "../../../src/vm/session.ts";
import { CREDENTIAL_FILE_VERSION, writeStoredCredential } from "../../../src/auth/store.ts";

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

describe("commands/run: parseExposePort", () => {
  it("accepts a valid port", () => {
    expect(parseExposePort("8080")).toBe(8080);
  });

  it("accepts the boundary values 1 and 65535", () => {
    expect(parseExposePort("1")).toBe(1);
    expect(parseExposePort("65535")).toBe(65535);
  });

  it("rejects a non-numeric value", () => {
    expect(() => parseExposePort("nope")).toThrow(InvalidExposePortError);
  });

  it("rejects a value with trailing/leading junk (not a bare digit string)", () => {
    expect(() => parseExposePort("8080x")).toThrow(InvalidExposePortError);
    expect(() => parseExposePort(" 8080")).toThrow(InvalidExposePortError);
    expect(() => parseExposePort("1e2")).toThrow(InvalidExposePortError);
    expect(() => parseExposePort("-1")).toThrow(InvalidExposePortError);
  });

  it("rejects 0", () => {
    expect(() => parseExposePort("0")).toThrow(InvalidExposePortError);
  });

  it("rejects a value above 65535", () => {
    expect(() => parseExposePort("65536")).toThrow(InvalidExposePortError);
  });
});

describe("commands/run: parseRunArgs --expose", () => {
  it("defaults expose to undefined when not passed", () => {
    expect(parseRunArgs([]).expose).toBeUndefined();
  });

  it("parses a valid --expose value into a number", () => {
    expect(parseRunArgs(["--expose", "3000"]).expose).toBe(3000);
  });

  it("throws InvalidExposePortError for an invalid --expose value, before anything else is attempted", () => {
    expect(() => parseRunArgs(["--expose", "bogus"])).toThrow(InvalidExposePortError);
    expect(() => parseRunArgs(["--expose", "0"])).toThrow(InvalidExposePortError);
    expect(() => parseRunArgs(["--expose", "99999"])).toThrow(InvalidExposePortError);
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
    expect(merged.dir).toEqual([{ name: "a", host: "/tmp/second", mode: "rw", "builtin-rules": builtinGitRules(), rules: [] }]);
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
      expect(output).toContain(`directory: ${fs.realpathSync(workDir)}`);
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

  describe("[vm] config forwarding into runSession", () => {
    it("forwards image/memory/cpus to runSession when [vm] sets them", async () => {
      fs.writeFileSync(
        path.join(configDir, "config.toml"),
        ['[vm]', 'image = "corb:pinned-1.2.3"', 'memory = "8G"', "cpus = 6"].join("\n"),
      );

      await runRunCommand([workDir, "--trust-config"]);
      expect(runSessionMock).toHaveBeenCalledTimes(1);
      const [options] = runSessionMock.mock.calls[0] as [{ image?: string; memory?: string; cpus?: number }];
      expect(options.image).toBe("corb:pinned-1.2.3");
      expect(options.memory).toBe("8G");
      expect(options.cpus).toBe(6);
    });

    it("omits image/memory/cpus from runSession's options entirely when [vm] does not set them", async () => {
      await runRunCommand([workDir, "--trust-config"]);
      expect(runSessionMock).toHaveBeenCalledTimes(1);
      const [options] = runSessionMock.mock.calls[0] as [Record<string, unknown>];
      expect("image" in options).toBe(false);
      expect("memory" in options).toBe(false);
      expect("cpus" in options).toBe(false);
    });

    it("forwards only the [vm] fields that are actually set, leaving the rest absent", async () => {
      fs.writeFileSync(path.join(configDir, "config.toml"), ['[vm]', 'memory = "2G"'].join("\n"));

      await runRunCommand([workDir, "--trust-config"]);
      const [options] = runSessionMock.mock.calls[0] as [Record<string, unknown>];
      expect(options.memory).toBe("2G");
      expect("image" in options).toBe(false);
      expect("cpus" in options).toBe(false);
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
          { name: path.basename(fs.realpathSync(workDir)), hostPath: fs.realpathSync(workDir), mode: "rw", rules: builtinGitRules() },
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
        expect(options.egress).toEqual({ allow: [], "block-internal-ranges": true, websockets: false });
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

  describe("--expose wiring into runSession", () => {
    it("omits the expose option entirely when --expose is not passed", async () => {
      await runRunCommand([workDir, "--trust-config"]);
      const [options] = runSessionMock.mock.calls[0] as [Record<string, unknown>];
      expect(options.expose).toBeUndefined();
      expect(Object.prototype.hasOwnProperty.call(options, "expose")).toBe(false);
    });

    it("passes the validated port through to runSession when --expose is passed", async () => {
      await runRunCommand([workDir, "--expose", "8080", "--trust-config"]);
      const [options] = runSessionMock.mock.calls[0] as [{ expose: number }];
      expect(options.expose).toBe(8080);
    });

    it("an invalid --expose value fails before runSession is ever called", async () => {
      await expect(runRunCommand([workDir, "--expose", "bogus", "--trust-config"])).rejects.toThrow(
        InvalidExposePortError,
      );
      expect(runSessionMock).not.toHaveBeenCalled();
    });
  });

  describe("config.toml [[dir]].rules wiring into runSession (M5.4)", () => {
    it("places built-in rules before user rules that match Git metadata", async () => {
      const dirName = path.basename(fs.realpathSync(workDir));
      fs.writeFileSync(path.join(configDir, "config.toml"), [
        "[[dir]]",
        `name = "${dirName}"`,
        'rules = [{ glob = ".git/config*", mode = "shadow-write" }]',
      ].join("\n"));
      await runRunCommand([workDir, "--trust-config"]);
      const [options] = runSessionMock.mock.calls[0] as [{ dirs: { rules: unknown[] }[] }];
      expect(options.dirs[0]?.rules).toEqual([
        ...builtinGitRules(),
        { glob: ".git/config*", mode: "shadow-write" },
      ]);
    });

    it("keeps malformed user rule indexes independent of built-in rules", async () => {
      const dirName = path.basename(fs.realpathSync(workDir));
      fs.writeFileSync(path.join(configDir, "config.toml"), [
        "[[dir]]",
        `name = "${dirName}"`,
        'rules = [{ glob = "valid", mode = "hidden" }, { glob = "missing-mode" }]',
      ].join("\n"));
      await expect(runRunCommand([workDir, "--trust-config"])).rejects.toThrow("rules[1] is missing required field 'mode'");
      expect(runSessionMock).not.toHaveBeenCalled();
    });

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
          rules: [...builtinGitRules(), { glob: "secrets/**", mode: "hidden", reason: "keep secrets out of view" }],
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

    it("a [[dir]].rules entry with a leading-/ glob throws UnmatchableDirRuleGlobError before runSession is ever called", async () => {
      const dirName = path.basename(fs.realpathSync(workDir));
      const configToml = [
        "[[dir]]",
        `name = "${dirName}"`,
        "rules = [",
        '  { glob = "/secrets/**", mode = "hidden", reason = "leading slash typo" },',
        "]",
      ].join("\n");
      fs.writeFileSync(path.join(configDir, "config.toml"), configToml);

      await expect(runRunCommand([workDir, "--trust-config"])).rejects.toThrow(UnmatchableDirRuleGlobError);
      expect(runSessionMock).not.toHaveBeenCalled();
    });

    it("a [[dir]].rules entry with a trailing-/ glob throws UnmatchableDirRuleGlobError before runSession is ever called", async () => {
      const dirName = path.basename(fs.realpathSync(workDir));
      const configToml = [
        "[[dir]]",
        `name = "${dirName}"`,
        "rules = [",
        '  { glob = "secrets/", mode = "hidden", reason = "trailing slash typo" },',
        "]",
      ].join("\n");
      fs.writeFileSync(path.join(configDir, "config.toml"), configToml);

      await expect(runRunCommand([workDir, "--trust-config"])).rejects.toThrow(UnmatchableDirRuleGlobError);
      expect(runSessionMock).not.toHaveBeenCalled();
    });

    it("a [[dir]].rules entry with an embedded // in its glob throws UnmatchableDirRuleGlobError before runSession is ever called", async () => {
      const dirName = path.basename(fs.realpathSync(workDir));
      const configToml = [
        "[[dir]]",
        `name = "${dirName}"`,
        "rules = [",
        '  { glob = "secrets//key.pem", mode = "hidden", reason = "malformed double slash" },',
        "]",
      ].join("\n");
      fs.writeFileSync(path.join(configDir, "config.toml"), configToml);

      await expect(runRunCommand([workDir, "--trust-config"])).rejects.toThrow(UnmatchableDirRuleGlobError);
      expect(runSessionMock).not.toHaveBeenCalled();
    });
  });
});

describe("commands/run: runRunCommand with a host-brokered provider", () => {
  let root: string;
  let workDir: string;
  let configDir: string;
  let stateDir: string;
  const saved: Record<string, string | undefined> = {};
  let errorSpy: ReturnType<typeof vi.spyOn>;

  function writeConfig(allow: string[]): void {
    fs.writeFileSync(
      path.join(configDir, "config.toml"),
      ["[agent]", 'provider = "openai-codex"', "", "[egress]", `allow = [${allow.map((h) => `"${h}"`).join(", ")}]`].join("\n"),
    );
  }

  function writeLogin(): void {
    const enc = (value: unknown): string => Buffer.from(JSON.stringify(value)).toString("base64url");
    const access = `${enc({ alg: "RS256" })}.${enc({ "https://api.openai.com/auth": { chatgpt_account_id: "acct-1" } })}.sig`;
    writeStoredCredential(path.join(stateDir, "credentials"), {
      version: CREDENTIAL_FILE_VERSION,
      provider: "openai-codex",
      type: "oauth",
      access,
      refresh: "real-refresh",
      expires: Date.now() + 3_600_000,
      accountId: "acct-1",
      updatedAt: new Date().toISOString(),
    });
  }

  beforeEach(() => {
    root = fs.mkdtempSync(path.join(os.tmpdir(), "corb-run-brokered-"));
    workDir = path.join(root, "work");
    configDir = path.join(root, "config");
    stateDir = path.join(root, "state");
    for (const dir of [workDir, configDir, stateDir]) {
      fs.mkdirSync(dir);
    }
    saved.CORB_CONFIG_DIR = process.env.CORB_CONFIG_DIR;
    saved.CORB_STATE_DIR = process.env.CORB_STATE_DIR;
    process.env.CORB_CONFIG_DIR = configDir;
    process.env.CORB_STATE_DIR = stateDir;
    errorSpy = vi.spyOn(console, "error").mockImplementation(() => {});
    runSessionMock.mockClear();
    process.exitCode = undefined;
  });

  afterEach(() => {
    errorSpy.mockRestore();
    process.exitCode = undefined;
    for (const [key, value] of Object.entries(saved)) {
      if (value === undefined) {
        delete process.env[key];
      } else {
        process.env[key] = value;
      }
    }
    fs.rmSync(root, { recursive: true, force: true });
  });

  it("refuses to boot without a stored login, pointing at corb login", async () => {
    writeConfig(["chatgpt.com"]);
    await runRunCommand([workDir, "--trust-config"]);
    expect(runSessionMock).not.toHaveBeenCalled();
    expect(process.exitCode).toBe(1);
    expect(errorSpy.mock.calls.flat().join("\n")).toMatch(/corb login openai-codex/);
  });

  it("passes the started broker to runSession, with only the stand-in in its guest credential", async () => {
    writeConfig(["chatgpt.com"]);
    writeLogin();
    await runRunCommand([workDir, "--trust-config"]);
    expect(runSessionMock).toHaveBeenCalledTimes(1);
    const [options] = runSessionMock.mock.calls[0] as [{ piArgs: string[]; brokered?: { provider: { id: string }; guest: unknown } }];
    expect(options.piArgs.slice(0, 2)).toEqual(["--provider", "openai-codex"]);
    expect(options.brokered?.provider.id).toBe("openai-codex");
    expect(JSON.stringify(options.brokered?.guest)).not.toContain("real-refresh");
    expect(errorSpy).not.toHaveBeenCalled();
  });

  it("allows the provider's API host automatically without a warning", async () => {
    writeConfig(["pi.dev"]);
    writeLogin();
    await runRunCommand([workDir, "--trust-config"]);
    expect(runSessionMock).toHaveBeenCalledTimes(1);
    const [options] = runSessionMock.mock.calls[0] as [{ egress: { allow: string[] } }];
    expect(options.egress.allow).toEqual(["pi.dev", "chatgpt.com"]);
    expect(errorSpy).not.toHaveBeenCalled();
  });

  it("does not start a broker for an API-key provider", async () => {
    fs.writeFileSync(path.join(configDir, "config.toml"), '[agent]\nprovider = "anthropic"\n');
    await runRunCommand([workDir, "--trust-config"]);
    const [options] = runSessionMock.mock.calls[0] as [{ brokered?: unknown; egress: { allow: string[] } }];
    expect(options.brokered).toBeUndefined();
    expect(options.egress.allow).not.toContain("chatgpt.com");
    expect(errorSpy).not.toHaveBeenCalled();
  });
});

describe("commands/run: named workspaces", () => {
  let root: string;
  let configDir: string;
  let project: string;
  let previousConfig: string | undefined;
  let previousHome: string | undefined;
  let previousState: string | undefined;

  beforeEach(() => {
    root = fs.mkdtempSync(path.join(os.tmpdir(), "corb-run-named-"));
    configDir = path.join(root, "config");
    project = path.join(root, "project");
    fs.mkdirSync(project);
    fs.mkdirSync(path.join(configDir, "workspaces", "team"), { recursive: true });
    previousConfig = process.env.CORB_CONFIG_DIR;
    previousHome = process.env.HOME;
    previousState = process.env.CORB_STATE_DIR;
    process.env.CORB_CONFIG_DIR = configDir;
    process.env.HOME = root;
    process.env.CORB_STATE_DIR = path.join(root, "state");
    fs.writeFileSync(path.join(configDir, "workspaces", "team", "corb.toml"), `[[dir]]\nname = "saved"\nhost = ${JSON.stringify(project)}\nmode = "ro"`);
    runSessionMock.mockClear();
  });

  afterEach(() => {
    vi.restoreAllMocks();
    if (previousConfig === undefined) delete process.env.CORB_CONFIG_DIR;
    else process.env.CORB_CONFIG_DIR = previousConfig;
    if (previousHome === undefined) delete process.env.HOME;
    else process.env.HOME = previousHome;
    if (previousState === undefined) delete process.env.CORB_STATE_DIR;
    else process.env.CORB_STATE_DIR = previousState;
    fs.rmSync(root, { recursive: true, force: true });
  });

  it("parses --workspace and records whether DIR was explicit", () => {
    expect(parseRunArgs(["--workspace", "team"])).toMatchObject({ workspace: "team", dirExplicit: false, dir: process.cwd() });
    expect(parseRunArgs([project, "--workspace", "team"])).toMatchObject({ workspace: "team", dirExplicit: true, dir: project });
  });

  it("expands CLI home hosts while keeping relative hosts relative to cwd", () => {
    expect(parseDirFlag("work=~/project:ro")).toEqual({ name: "work", host: project, mode: "ro" });
    expect(parseDirFlag("work=$HOME/project").host).toBe(project);
    expect(parseDirFlag("work=relative").host).toBe(path.resolve("relative"));
  });

  it.each(["~bob/x", "${HOME}/x", "$OTHER/x", "$HOMELESS/x"])("rejects invalid CLI host prefix %s", (host) => {
    expect(() => parseDirFlag(`work=${host}`)).toThrow(DirFlagError);
  });

  it("runs a named workspace with no cwd mount and its own primary", async () => {
    await runRunCommand(["--workspace", "team", "--trust-config"]);
    const options = runSessionMock.mock.calls[0]?.[0];
    expect(options.primary).toBe("saved");
    expect(options.dirs).toEqual([{ name: "saved", hostPath: project, mode: "ro", rules: [] }]);
  });

  it("starts at the matching mount root for an inside positional directory", async () => {
    const child = path.join(project, "child");
    fs.mkdirSync(child);
    await runRunCommand([child, "--trust-config"]);
    const options = runSessionMock.mock.calls[0]?.[0];
    expect(options.primary).toBe("saved");
    expect(options.dirs).toHaveLength(1);
    expect(options.dirs[0].hostPath).toBe(project);
  });

  it("renders the actual --primary override in dry-run output", async () => {
    const log = vi.spyOn(console, "log").mockImplementation(() => {});
    await runRunCommand(["--workspace", "team", "--dir", `extra=${project}`, "--primary", "extra", "--dry-run"]);
    expect(log.mock.calls[0]?.[0]).toContain("primary: extra");
    expect(runSessionMock).not.toHaveBeenCalled();
  });

  it("prints matching workspace and DIR hints when trust is required", async () => {
    const outside = path.join(root, "outside");
    fs.mkdirSync(outside);
    await expect(runRunCommand(["--workspace", "team", outside])).rejects.toThrow(`corb explain --workspace team ${outside}`);
    await expect(runRunCommand(["--workspace", "team"])).rejects.toThrow("corb explain --workspace team'");
    await expect(runRunCommand(["--workspace", "team"])).rejects.toThrow("workspace 'team' requires confirmation");
    expect(runSessionMock).not.toHaveBeenCalled();
  });

  it("keeps --primary and --dir in a usable hint for a workspace with no own host", async () => {
    fs.writeFileSync(path.join(configDir, "workspaces", "team", "corb.toml"), "");
    fs.writeFileSync(path.join(configDir, "config.toml"), `[[dir]]\nname = "shared"\nhost = ${JSON.stringify(project)}`);
    await expect(runRunCommand(["--workspace", "team", "--primary", "shared"])).rejects.toThrow("corb explain --workspace team --primary shared");
    fs.writeFileSync(path.join(configDir, "config.toml"), "");
    const cliHost = `shared=${project}`;
    await expect(runRunCommand(["--workspace", "team", "--dir", cliHost, "--primary", "shared"])).rejects.toThrow(`corb explain --workspace team --dir ${cliHost} --primary shared`);
    const { runExplainCommand } = await import("../../../src/commands/explain.ts");
    const log = vi.spyOn(console, "log").mockImplementation(() => {});
    await runExplainCommand(["--workspace", "team", "--dir", cliHost, "--primary", "shared"]);
    expect(log.mock.calls[0]?.[0]).toContain("primary: shared");
    expect(runSessionMock).not.toHaveBeenCalled();
  });
});
