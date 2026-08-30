// Unit tests for `src/vm/scope.ts` — M8.3.
//
// `decideScope`/`buildSystemdRunArgv`/`exitCodeFromSpawnResult` are pure and
// tested directly against fabricated input. `reExecUnderScope` gets its
// `spawn`/`exit` injected (mirroring `src/vm/shutdown.ts`'s
// `ProcessLike`/`ExitFn` convention) so a test can assert the exact argv/env
// it would pass to a real `systemd-run` without ever invoking one.
import { describe, expect, it, vi } from "vitest";
import {
  buildSystemdRunArgv,
  decideScope,
  exitCodeFromSpawnResult,
  reExecUnderScope,
  type SpawnSyncResultLike,
} from "../../../src/vm/scope.ts";
import type { PartialVmLimits } from "../../../src/config/schema.ts";

describe("vm/scope: decideScope", () => {
  it("limits undefined -> no re-exec, both arrays empty", () => {
    expect(decideScope(undefined, new Set())).toEqual({ reExec: false, properties: [], missingControllers: [] });
  });

  it("limits present but empty -> no re-exec, both arrays empty (nothing configured)", () => {
    expect(decideScope({}, new Set(["memory", "pids", "cpu"]))).toEqual({ reExec: false, properties: [], missingControllers: [] });
  });

  it("memory-max alone, memory delegated -> re-exec with just MemoryMax=", () => {
    const limits: PartialVmLimits = { "memory-max": "6G" };
    expect(decideScope(limits, new Set(["memory"]))).toEqual({ reExec: true, properties: ["MemoryMax=6G"], missingControllers: [] });
  });

  it("pids-max alone, pids delegated -> re-exec with TasksMax= (not PidsMax=, see module comment)", () => {
    const limits: PartialVmLimits = { "pids-max": 512 };
    expect(decideScope(limits, new Set(["pids"]))).toEqual({ reExec: true, properties: ["TasksMax=512"], missingControllers: [] });
  });

  it("cpu-quota alone, cpu delegated -> re-exec with just CPUQuota=", () => {
    const limits: PartialVmLimits = { "cpu-quota": "400%" };
    expect(decideScope(limits, new Set(["cpu"]))).toEqual({ reExec: true, properties: ["CPUQuota=400%"], missingControllers: [] });
  });

  it("all three configured, all three delegated -> one property per key, in memory/pids/cpu order", () => {
    const limits: PartialVmLimits = { "memory-max": "6G", "pids-max": 512, "cpu-quota": "400%" };
    expect(decideScope(limits, new Set(["memory", "pids", "cpu"]))).toEqual({
      reExec: true,
      properties: ["MemoryMax=6G", "TasksMax=512", "CPUQuota=400%"],
      missingControllers: [],
    });
  });

  it("an unconfigured key contributes no flag even when its controller happens to be delegated", () => {
    const limits: PartialVmLimits = { "pids-max": 100 };
    expect(decideScope(limits, new Set(["memory", "pids", "cpu"]))).toEqual({
      reExec: true,
      properties: ["TasksMax=100"],
      missingControllers: [],
    });
  });

  it("memory-max configured, memory NOT delegated -> no re-exec, reports the missing controller", () => {
    const limits: PartialVmLimits = { "memory-max": "6G" };
    expect(decideScope(limits, new Set(["pids"]))).toEqual({ reExec: false, properties: [], missingControllers: ["memory"] });
  });

  it("two keys configured, only one delegated -> no partial re-exec; both intended properties are dropped, only the missing controller is reported", () => {
    const limits: PartialVmLimits = { "memory-max": "6G", "pids-max": 512 };
    expect(decideScope(limits, new Set(["pids"]))).toEqual({ reExec: false, properties: [], missingControllers: ["memory"] });
  });

  it("all three configured, none delegated -> reports all three missing controllers, in memory/pids/cpu order, deduplicated", () => {
    const limits: PartialVmLimits = { "memory-max": "6G", "pids-max": 512, "cpu-quota": "400%" };
    expect(decideScope(limits, new Set())).toEqual({ reExec: false, properties: [], missingControllers: ["memory", "pids", "cpu"] });
  });

  it("empty delegated-controllers set (e.g. non-Linux, or a missing cgroup.controllers file) with any key configured -> falls back, never throws", () => {
    const limits: PartialVmLimits = { "cpu-quota": "100%" };
    expect(() => decideScope(limits, new Set())).not.toThrow();
    expect(decideScope(limits, new Set())).toEqual({ reExec: false, properties: [], missingControllers: ["cpu"] });
  });
});

describe("vm/scope: buildSystemdRunArgv", () => {
  it("builds --user --scope --collect --quiet, one -p per property, then -- execPath ...execArgv", () => {
    expect(buildSystemdRunArgv(["MemoryMax=6G", "TasksMax=512"], "/usr/bin/node", ["src/cli.ts", "run", "."])).toEqual([
      "--user",
      "--scope",
      "--collect",
      "--quiet",
      "-p",
      "MemoryMax=6G",
      "-p",
      "TasksMax=512",
      "--",
      "/usr/bin/node",
      "src/cli.ts",
      "run",
      ".",
    ]);
  });

  it("no properties -> no -p flags at all, just the flags and the command", () => {
    expect(buildSystemdRunArgv([], "/usr/bin/node", ["src/cli.ts"])).toEqual([
      "--user",
      "--scope",
      "--collect",
      "--quiet",
      "--",
      "/usr/bin/node",
      "src/cli.ts",
    ]);
  });

  it("no execArgv -> just execPath after --", () => {
    expect(buildSystemdRunArgv(["CPUQuota=400%"], "/usr/bin/node", [])).toEqual([
      "--user",
      "--scope",
      "--collect",
      "--quiet",
      "-p",
      "CPUQuota=400%",
      "--",
      "/usr/bin/node",
    ]);
  });
});

describe("vm/scope: exitCodeFromSpawnResult", () => {
  it("a normal exit propagates the exact status code", () => {
    expect(exitCodeFromSpawnResult({ status: 0, signal: null })).toBe(0);
    expect(exitCodeFromSpawnResult({ status: 42, signal: null })).toBe(42);
  });

  it("a signal-terminated child maps to 128+signal number (matches src/vm/shutdown.ts's own convention)", () => {
    expect(exitCodeFromSpawnResult({ status: null, signal: "SIGTERM" })).toBe(128 + 15);
    expect(exitCodeFromSpawnResult({ status: null, signal: "SIGINT" })).toBe(128 + 2);
  });

  it("neither status nor signal set -> falls back to 1 rather than throwing", () => {
    expect(exitCodeFromSpawnResult({ status: null, signal: null })).toBe(1);
  });
});

describe("vm/scope: reExecUnderScope", () => {
  it("spawns 'systemd-run' with the exact argv, stdio: inherit, and CORB_SCOPED=1 merged into env, then exits with the child's status", () => {
    const spawn = vi.fn(
      (): SpawnSyncResultLike => ({ status: 7, signal: null }),
    );
    const exit = vi.fn();

    const outcome = reExecUnderScope({
      properties: ["MemoryMax=6G"],
      execPath: "/usr/bin/node",
      execArgv: ["src/cli.ts", "run", "."],
      env: { PATH: "/usr/bin", EXISTING: "1" },
      spawn,
      exit,
    });

    expect(spawn).toHaveBeenCalledExactlyOnceWith(
      "systemd-run",
      ["--user", "--scope", "--collect", "--quiet", "-p", "MemoryMax=6G", "--", "/usr/bin/node", "src/cli.ts", "run", "."],
      { stdio: "inherit", env: { PATH: "/usr/bin", EXISTING: "1", CORB_SCOPED: "1" } },
    );
    expect(exit).toHaveBeenCalledExactlyOnceWith(7);
    expect(outcome.spawnError).toBeUndefined();
    expect(outcome.env.CORB_SCOPED).toBe("1");
  });

  it("does not clobber an already-set CORB_SCOPED-shaped env, but always forces CORB_SCOPED to '1' on the child regardless of what the caller passed", () => {
    const spawn = vi.fn((): SpawnSyncResultLike => ({ status: 0, signal: null }));
    const exit = vi.fn();

    reExecUnderScope({
      properties: [],
      execPath: "/usr/bin/node",
      execArgv: [],
      env: { CORB_SCOPED: "should-be-overwritten", OTHER: "kept" },
      spawn,
      exit,
    });

    const [, , options] = spawn.mock.calls[0]!;
    expect(options.env).toEqual({ CORB_SCOPED: "1", OTHER: "kept" });
  });

  it("a signal-terminated child exits with 128+signal, not the raw null status", () => {
    const spawn = vi.fn((): SpawnSyncResultLike => ({ status: null, signal: "SIGTERM" }));
    const exit = vi.fn();

    reExecUnderScope({ properties: [], execPath: "/usr/bin/node", execArgv: [], env: {}, spawn, exit });

    expect(exit).toHaveBeenCalledExactlyOnceWith(143);
  });

  it("a spawn failure (e.g. systemd-run not installed, ENOENT) returns the error and never calls exit", () => {
    const spawnError = Object.assign(new Error("spawnSync systemd-run ENOENT"), { code: "ENOENT" });
    const spawn = vi.fn((): SpawnSyncResultLike => ({ status: null, signal: null, error: spawnError }));
    const exit = vi.fn();

    const outcome = reExecUnderScope({ properties: ["TasksMax=100"], execPath: "/usr/bin/node", execArgv: [], env: {}, spawn, exit });

    expect(outcome.spawnError).toBe(spawnError);
    expect(exit).not.toHaveBeenCalled();
  });

  it("defaults execPath/execArgv to process.execPath/process.argv.slice(1) when not given", () => {
    const spawn = vi.fn((): SpawnSyncResultLike => ({ status: 0, signal: null }));
    const exit = vi.fn();

    reExecUnderScope({ properties: [], env: {}, spawn, exit });

    const [, argv] = spawn.mock.calls[0]!;
    const expectedTail = ["--", process.execPath, ...process.argv.slice(1)];
    expect(argv.slice(-expectedTail.length)).toEqual(expectedTail);
  });
});
