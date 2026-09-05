// Unit tests for `src/commands/doctor.ts` — M3.5. `corb doctor` is almost
// entirely host-OS inspection (a device file, binaries on PATH, a running
// daemon, a subprocess version query, a cgroup file), so most of what's
// meaningfully unit-testable here is the *classification* logic each check
// reduces to, against a fabricated input — not the real filesystem or a
// real subprocess. Genuinely OS-dependent checks (`/dev/kvm`, `docker
// info`, `qemu-system-*` on PATH, the real Go/Node toolchain, the real
// e2fsprogs layout) are exercised for real via `runDoctorChecks()` only in
// one end-to-end smoke test below, and otherwise verified by hand against
// this machine's real environment (see the M3.5 report) — not re-mocked
// here, which would prove nothing beyond "the mock returns what it was
// told to return".
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  buildDoctorReport,
  checkRequiredSecrets,
  checkSecretsConfigured,
  checkVerifySecrets,
  classifyCgroupControllers,
  classifyE2fsprogs,
  classifyGoInstall,
  classifyNodeVersion,
  classifySessionSocketPermissions,
  classifySocketPathBudget,
  classifySshAuthSock,
  compareVersionTuples,
  locateTool,
  parseGoModFloor,
  parseGoVersionOutput,
  parseVersionTuple,
  qemuBinaryName,
  runDoctorChecks,
  splitPath,
  type DoctorCheckResult,
  type DoctorConfigLoad,
} from "../../../src/commands/doctor.ts";
import { ConfigParseError } from "../../../src/config/schema.ts";

describe("commands/doctor: buildDoctorReport", () => {
  it("ok is true when no check failed, even with warnings", () => {
    const checks: DoctorCheckResult[] = [
      { name: "a", status: "ok", detail: "" },
      { name: "b", status: "warn", detail: "" },
    ];
    expect(buildDoctorReport(checks)).toEqual({ checks, ok: true });
  });

  it("ok is false when any check failed", () => {
    const checks: DoctorCheckResult[] = [
      { name: "a", status: "ok", detail: "" },
      { name: "b", status: "fail", detail: "" },
      { name: "c", status: "warn", detail: "" },
    ];
    expect(buildDoctorReport(checks).ok).toBe(false);
  });

  it("ok is true for an empty check list", () => {
    expect(buildDoctorReport([])).toEqual({ checks: [], ok: true });
  });
});

describe("commands/doctor: splitPath / locateTool", () => {
  let dir: string;

  beforeEach(() => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), "corb-doctor-path-"));
  });

  afterEach(() => {
    fs.rmSync(dir, { recursive: true, force: true });
  });

  it("splitPath filters empty segments and handles undefined", () => {
    expect(splitPath(undefined)).toEqual([]);
    expect(splitPath("")).toEqual([]);
    expect(splitPath(`/a${path.delimiter}${path.delimiter}/b`)).toEqual(["/a", "/b"]);
  });

  it("locateTool finds an executable on a PATH dir and returns 'path'", () => {
    const bin = path.join(dir, "mytool");
    fs.writeFileSync(bin, "#!/bin/sh\n");
    fs.chmodSync(bin, 0o755);
    expect(locateTool("mytool", [dir])).toBe("path");
  });

  it("locateTool returns 'fallback' when only found in a fallback dir", () => {
    const fallbackDir = fs.mkdtempSync(path.join(os.tmpdir(), "corb-doctor-fallback-"));
    try {
      const bin = path.join(fallbackDir, "mytool");
      fs.writeFileSync(bin, "#!/bin/sh\n");
      fs.chmodSync(bin, 0o755);
      expect(locateTool("mytool", [dir], [fallbackDir])).toBe("fallback");
    } finally {
      fs.rmSync(fallbackDir, { recursive: true, force: true });
    }
  });

  it("locateTool returns 'missing' when found nowhere", () => {
    expect(locateTool("does-not-exist-anywhere", [dir], [dir])).toBe("missing");
  });

  it("locateTool ignores a non-executable file", () => {
    const bin = path.join(dir, "notexec");
    fs.writeFileSync(bin, "not a script");
    fs.chmodSync(bin, 0o644);
    expect(locateTool("notexec", [dir])).toBe("missing");
  });

  it("locateTool ignores a directory that happens to share the tool's name", () => {
    fs.mkdirSync(path.join(dir, "adir"));
    expect(locateTool("adir", [dir])).toBe("missing");
  });
});

describe("commands/doctor: e2fsprogs three-way classification", () => {
  it("all three on PATH -> ok", () => {
    const result = classifyE2fsprogs({ "mkfs.ext4": "path", "resize2fs": "path", "e2fsck": "path" });
    expect(result.status).toBe("ok");
  });

  it("all three found only via fallback (/sbin, /usr/sbin) -> warn, not ok or fail", () => {
    const result = classifyE2fsprogs({ "mkfs.ext4": "fallback", "resize2fs": "fallback", "e2fsck": "fallback" });
    expect(result.status).toBe("warn");
    expect(result.detail).toContain("not on PATH");
  });

  it("any genuinely missing -> fail, even if the others are on PATH", () => {
    const result = classifyE2fsprogs({ "mkfs.ext4": "path", "resize2fs": "missing", "e2fsck": "path" });
    expect(result.status).toBe("fail");
    expect(result.detail).toContain("resize2fs");
  });

  it("a mix of path and fallback (no missing) -> warn, listing only the fallback-only ones", () => {
    const result = classifyE2fsprogs({ "mkfs.ext4": "path", "resize2fs": "fallback", "e2fsck": "path" });
    expect(result.status).toBe("warn");
    expect(result.detail).toContain("resize2fs");
    expect(result.detail).not.toContain("mkfs.ext4,");
  });
});

describe("commands/doctor: qemuBinaryName", () => {
  it("maps common os.arch() values to the right qemu-system binary", () => {
    expect(qemuBinaryName("x64")).toBe("qemu-system-x86_64");
    expect(qemuBinaryName("arm64")).toBe("qemu-system-aarch64");
    expect(qemuBinaryName("ia32")).toBe("qemu-system-i386");
  });

  it("falls back to qemu-system-<arch> for an unrecognised arch rather than throwing", () => {
    expect(qemuBinaryName("mips")).toBe("qemu-system-mips");
  });
});

describe("commands/doctor: node version classification", () => {
  it("parseVersionTuple / compareVersionTuples", () => {
    expect(parseVersionTuple("v23.6.0")).toEqual([23, 6, 0]);
    expect(parseVersionTuple("23.6.0")).toEqual([23, 6, 0]);
    expect(parseVersionTuple("not a version")).toBeUndefined();
    expect(compareVersionTuples([23, 6, 0], [23, 6, 0])).toBe(0);
    expect(compareVersionTuples([23, 5, 9], [23, 6, 0])).toBe(-1);
    expect(compareVersionTuples([24, 0, 0], [23, 6, 0])).toBe(1);
  });

  it("running version at the floor -> ok", () => {
    expect(classifyNodeVersion("v23.6.0", ">=23.6.0").status).toBe("ok");
  });

  it("running version above the floor -> ok", () => {
    expect(classifyNodeVersion("v26.7.0", ">=23.6.0").status).toBe("ok");
  });

  it("running version below the floor -> fail", () => {
    const result = classifyNodeVersion("v20.0.0", ">=23.6.0");
    expect(result.status).toBe("fail");
    expect(result.detail).toContain("23.6.0");
  });

  it("an unparseable running version -> fail rather than throwing", () => {
    expect(classifyNodeVersion("garbage", ">=23.6.0").status).toBe("fail");
  });
});

describe("commands/doctor: go install classification", () => {
  it("go absent -> fail (the only hard-required part of this check)", () => {
    expect(classifyGoInstall(undefined, [1, 26]).status).toBe("fail");
  });

  it("go present, no pinned floor known -> ok", () => {
    expect(classifyGoInstall([1, 26], undefined).status).toBe("ok");
  });

  it("go present and at/above the pinned floor -> ok", () => {
    expect(classifyGoInstall([1, 26], [1, 26]).status).toBe("ok");
    expect(classifyGoInstall([1, 27], [1, 26]).status).toBe("ok");
    expect(classifyGoInstall([2, 0], [1, 26]).status).toBe("ok");
  });

  it("go present but older than the pinned floor -> warn, not fail", () => {
    const result = classifyGoInstall([1, 20], [1, 26]);
    expect(result.status).toBe("warn");
    expect(result.detail).toContain("1.20");
    expect(result.detail).toContain("1.26");
  });

  it("parseGoModFloor / parseGoVersionOutput extract major.minor", () => {
    expect(parseGoModFloor("module corb.ax/guest\n\ngo 1.26\n\nrequire ...\n")).toEqual([1, 26]);
    expect(parseGoModFloor("no go directive here")).toBeUndefined();
    expect(parseGoVersionOutput("go version go1.26.5 linux/amd64\n")).toEqual([1, 26]);
    expect(parseGoVersionOutput("nonsense")).toBeUndefined();
  });
});

describe("commands/doctor: SSH_AUTH_SOCK classification", () => {
  it("unset -> warn", () => {
    expect(classifySshAuthSock(undefined, false).status).toBe("warn");
    expect(classifySshAuthSock("", false).status).toBe("warn");
  });

  it("set but the socket path doesn't exist -> warn", () => {
    const result = classifySshAuthSock("/tmp/does-not-exist.sock", false);
    expect(result.status).toBe("warn");
    expect(result.detail).toContain("does not exist");
  });

  it("set, exists, generic path -> ok", () => {
    const result = classifySshAuthSock("/run/user/1000/ssh-agent.sock", true);
    expect(result.status).toBe("ok");
  });

  it("set, exists, path looks like a 1Password agent socket -> warn with the specific hint (case-insensitive)", () => {
    const result = classifySshAuthSock("/home/dario/.1password/agent.sock", true);
    expect(result.status).toBe("warn");
    expect(result.detail).toContain("1Password");

    const upper = classifySshAuthSock("/Users/x/Library/Group Containers/1PASSWORD/t/agent.sock", true);
    expect(upper.status).toBe("warn");
  });
});

describe("commands/doctor: cgroup controllers classification", () => {
  it("file missing -> warn", () => {
    expect(classifyCgroupControllers(undefined).status).toBe("warn");
  });

  it("has all three required controllers -> ok", () => {
    expect(classifyCgroupControllers("cpuset cpu io memory pids\n").status).toBe("ok");
  });

  it("missing one or more required controllers -> warn, listing what's missing", () => {
    const result = classifyCgroupControllers("pids\n");
    expect(result.status).toBe("warn");
    expect(result.detail).toContain("memory");
    expect(result.detail).toContain("cpu");
  });
});

describe("commands/doctor: Gondolin session socket path budget", () => {
  // The boundary arithmetic itself (108 / 42 / 66) is owned and exhaustively
  // tested by `test/unit/vm/sockpath.test.ts`; what matters here is only that
  // this check maps a fit/no-fit verdict onto the right `DoctorCheckResult`.
  it("a short sessions directory -> ok", () => {
    const result = classifySocketPathBudget("/home/u/.cache/gondolin/sessions");
    expect(result.status).toBe("ok");
    expect(result.name).toBe("gondolin-socket-path");
  });

  it("a directory exactly at the 66-char boundary -> ok", () => {
    expect(classifySocketPathBudget("/tmp/" + "d".repeat(61)).status).toBe("ok");
  });

  it("one character over -> warn, not fail (the VM still works; only session management degrades)", () => {
    const result = classifySocketPathBudget("/tmp/" + "d".repeat(62));
    expect(result.status).toBe("warn");
    expect(result.status).not.toBe("fail");
  });

  it("the warn detail names the directory, the symptom, and an actionable remedy", () => {
    const dir = "/tmp/" + "d".repeat(62);
    const result = classifySocketPathBudget(dir);
    expect(result.detail).toContain(dir);
    expect(result.detail).toContain("109");
    expect(result.detail).toContain("corb ls");
    expect(result.detail).toContain("GONDOLIN_SESSIONS_DIR");
  });

  it("an over-long directory never fails the overall report (warn only)", () => {
    const result = classifySocketPathBudget("/tmp/" + "d".repeat(400));
    expect(buildDoctorReport([result]).ok).toBe(true);
  });
});

describe("commands/doctor: Gondolin session socket permissions", () => {
  // The permission-bit predicate itself (isGroupOrOtherWritable) is owned
  // and tested by `test/unit/vm/sockpath.test.ts`; what matters here is only
  // that a scan maps onto the right `DoctorCheckResult`.
  const sessionsDir = "/home/u/.cache/gondolin/sessions";

  it("directory does not exist yet -> ok, nothing to check (a fresh machine, not a failure)", () => {
    const result = classifySessionSocketPermissions({ sessionsDir, dirMode: undefined, socketModes: {} });
    expect(result.status).toBe("ok");
    expect(result.name).toBe("gondolin-socket-permissions");
    expect(result.detail).toContain(sessionsDir);
  });

  it("directory 0o755 (default-umask shape) with no sockets present -> ok", () => {
    const result = classifySessionSocketPermissions({ sessionsDir, dirMode: 0o755, socketModes: {} });
    expect(result.status).toBe("ok");
  });

  it("directory 0o755 with a 0o755 socket (srwxr-xr-x, the M0.4-observed default) -> ok", () => {
    const result = classifySessionSocketPermissions({
      sessionsDir,
      dirMode: 0o755,
      socketModes: { "abc.sock": 0o755 },
    });
    expect(result.status).toBe("ok");
  });

  it("group- or other-writable directory -> warn, not fail (the VM still works; only the management surface is exposed)", () => {
    const result = classifySessionSocketPermissions({ sessionsDir, dirMode: 0o777, socketModes: {} });
    expect(result.status).toBe("warn");
    expect(result.status).not.toBe("fail");
    expect(result.detail).toContain("directory itself");
    expect(result.detail).toContain("777");
  });

  it("group- or other-writable socket (the umask(0) shape observed in the M0.4 spike) -> warn, names the socket", () => {
    const result = classifySessionSocketPermissions({
      sessionsDir,
      dirMode: 0o755,
      socketModes: { "48f14dba-f89f-490e-abe6-6c3051c5bde1.sock": 0o777 },
    });
    expect(result.status).toBe("warn");
    expect(result.detail).toContain("48f14dba-f89f-490e-abe6-6c3051c5bde1.sock");
    expect(result.detail).toContain("connect(2)");
  });

  it("a writable socket never fails the overall report (warn only)", () => {
    const result = classifySessionSocketPermissions({ sessionsDir, dirMode: 0o755, socketModes: { "x.sock": 0o777 } });
    expect(buildDoctorReport([result]).ok).toBe(true);
  });
});

describe("commands/doctor: required-secrets vs secrets-configured (config.toml + env)", () => {
  const absent: DoctorConfigLoad = { kind: "absent" };
  const parseError: DoctorConfigLoad = { kind: "parse-error", error: new ConfigParseError("config.toml", "bad TOML") };

  it("checkRequiredSecrets: absent config.toml -> ok, nothing to check", () => {
    expect(checkRequiredSecrets(absent, {}).status).toBe("ok");
  });

  it("checkRequiredSecrets: parse error -> fail with the parse error surfaced, not a crash", () => {
    const result = checkRequiredSecrets(parseError, {});
    expect(result.status).toBe("fail");
    expect(result.detail).toContain("bad TOML");
  });

  it("checkRequiredSecrets: a required secret with its env var set -> ok", () => {
    const layer: DoctorConfigLoad = { kind: "parsed", layer: { secrets: { FOO: { hosts: ["example.com"] } } } };
    expect(checkRequiredSecrets(layer, { FOO: "value" }).status).toBe("ok");
  });

  it("checkRequiredSecrets: a required secret with an empty-string env var counts as unset -> fail", () => {
    const layer: DoctorConfigLoad = { kind: "parsed", layer: { secrets: { FOO: { hosts: ["example.com"] } } } };
    expect(checkRequiredSecrets(layer, { FOO: "" }).status).toBe("fail");
  });

  it("checkRequiredSecrets: optional secret missing its env var -> ok (not required)", () => {
    const layer: DoctorConfigLoad = { kind: "parsed", layer: { secrets: { FOO: { hosts: ["example.com"], optional: true } } } };
    expect(checkRequiredSecrets(layer, {}).status).toBe("ok");
  });

  it("checkRequiredSecrets: several missing required secrets are all named, not just the first", () => {
    const layer: DoctorConfigLoad = {
      kind: "parsed",
      layer: { secrets: { FOO: { hosts: ["a.com"] }, BAR: { hosts: ["b.com"] }, BAZ: { hosts: ["c.com"], optional: true } } },
    };
    const result = checkRequiredSecrets(layer, {});
    expect(result.status).toBe("fail");
    expect(result.detail).toContain("FOO");
    expect(result.detail).toContain("BAR");
    expect(result.detail).not.toContain("BAZ");
  });

  it("checkSecretsConfigured: absent config.toml -> warn, provider-neutral, points at corb explain", () => {
    const result = checkSecretsConfigured(absent);
    expect(result.status).toBe("warn");
    expect(result.detail).toContain("corb explain");
  });

  it("checkSecretsConfigured: config.toml present with no [secrets.*] at all -> warn", () => {
    const layer: DoctorConfigLoad = { kind: "parsed", layer: {} };
    expect(checkSecretsConfigured(layer).status).toBe("warn");
  });

  it("checkSecretsConfigured: at least one [secrets.*] entry configured -> ok, regardless of whether its env var is set", () => {
    const layer: DoctorConfigLoad = { kind: "parsed", layer: { secrets: { FOO: { hosts: ["example.com"] } } } };
    expect(checkSecretsConfigured(layer).status).toBe("ok");
  });

  it("checkSecretsConfigured: does not name any specific provider in its detail (provider-neutrality)", () => {
    const result = checkSecretsConfigured(absent);
    expect(result.detail.toLowerCase()).not.toContain("anthropic");
    expect(result.detail.toLowerCase()).not.toContain("openai");
  });

  it("required-secrets (fail on missing env var) and secrets-configured (warn on zero secrets) are genuinely different situations", () => {
    // Secrets *are* configured, but the env var isn't set: required-secrets
    // must fail; secrets-configured must not warn (something is configured).
    const layer: DoctorConfigLoad = { kind: "parsed", layer: { secrets: { FOO: { hosts: ["example.com"] } } } };
    expect(checkRequiredSecrets(layer, {}).status).toBe("fail");
    expect(checkSecretsConfigured(layer).status).toBe("ok");
  });
});

describe("commands/doctor: checkVerifySecrets (opt-in, --verify-secrets only)", () => {
  const absent: DoctorConfigLoad = { kind: "absent" };
  const parseError: DoctorConfigLoad = { kind: "parse-error", error: new ConfigParseError("config.toml", "bad TOML") };

  function fakeFetch(status: number, statusText = ""): typeof fetch {
    return vi.fn().mockResolvedValue(new Response(null, { status, statusText })) as unknown as typeof fetch;
  }

  it("absent config.toml -> no checks (nothing to verify)", async () => {
    await expect(checkVerifySecrets(absent, {})).resolves.toEqual([]);
  });

  it("parse error -> no checks (already reported elsewhere)", async () => {
    await expect(checkVerifySecrets(parseError, {})).resolves.toEqual([]);
  });

  it("a [secrets.NAME] entry with no verify table -> skipped entirely", async () => {
    const layer: DoctorConfigLoad = { kind: "parsed", layer: { secrets: { FOO: { hosts: ["example.com"] } } } };
    const fetchImpl = fakeFetch(200);
    await expect(checkVerifySecrets(layer, { FOO: "value" }, fetchImpl)).resolves.toEqual([]);
    expect(fetchImpl).not.toHaveBeenCalled();
  });

  it("a verify-configured entry with no env var set -> skipped (checkRequiredSecrets's job to flag that)", async () => {
    const layer: DoctorConfigLoad = {
      kind: "parsed",
      layer: { secrets: { FOO: { hosts: ["example.com"], verify: { url: "https://example.com/check", header: "x-api-key" } } } },
    };
    const fetchImpl = fakeFetch(200);
    await expect(checkVerifySecrets(layer, {}, fetchImpl)).resolves.toEqual([]);
    expect(fetchImpl).not.toHaveBeenCalled();
  });

  it("a response status matching expect-status -> ok, and the header carries the real secret value", async () => {
    const layer: DoctorConfigLoad = {
      kind: "parsed",
      layer: { secrets: { FOO: { hosts: ["example.com"], verify: { url: "https://example.com/check", header: "x-api-key" } } } },
    };
    const fetchImpl = fakeFetch(200);
    const results = await checkVerifySecrets(layer, { FOO: "real-value" }, fetchImpl);
    expect(results).toHaveLength(1);
    expect(results[0]?.status).toBe("ok");
    expect(results[0]?.name).toBe("verify-secret:FOO");
    expect(fetchImpl).toHaveBeenCalledWith("https://example.com/check", { headers: { "x-api-key": "real-value" } });
  });

  it("default expect-status is [200] when not configured", async () => {
    const layer: DoctorConfigLoad = {
      kind: "parsed",
      layer: { secrets: { FOO: { hosts: ["example.com"], verify: { url: "https://example.com/check", header: "x-api-key" } } } },
    };
    expect((await checkVerifySecrets(layer, { FOO: "v" }, fakeFetch(401, "Unauthorized")))[0]?.status).toBe("fail");
    expect((await checkVerifySecrets(layer, { FOO: "v" }, fakeFetch(200)))[0]?.status).toBe("ok");
  });

  it("a configured expect-status list is honored, including non-2xx 'credential accepted' statuses", async () => {
    const layer: DoctorConfigLoad = {
      kind: "parsed",
      layer: {
        secrets: {
          FOO: { hosts: ["example.com"], verify: { url: "https://example.com/check", header: "x-api-key", "expect-status": [200, 400] } },
        },
      },
    };
    expect((await checkVerifySecrets(layer, { FOO: "v" }, fakeFetch(400, "Bad Request")))[0]?.status).toBe("ok");
  });

  it("a status outside expect-status -> fail, naming the actual status and the possibility the credential is bad", async () => {
    const layer: DoctorConfigLoad = {
      kind: "parsed",
      layer: { secrets: { FOO: { hosts: ["example.com"], verify: { url: "https://example.com/check", header: "x-api-key" } } } },
    };
    const results = await checkVerifySecrets(layer, { FOO: "v" }, fakeFetch(401, "Unauthorized"));
    expect(results[0]?.status).toBe("fail");
    expect(results[0]?.detail).toContain("401");
    expect(results[0]?.detail.toLowerCase()).toContain("invalid");
  });

  it("a network-level failure -> fail, not a thrown exception", async () => {
    const layer: DoctorConfigLoad = {
      kind: "parsed",
      layer: { secrets: { FOO: { hosts: ["example.com"], verify: { url: "https://example.com/check", header: "x-api-key" } } } },
    };
    const fetchImpl = vi.fn().mockRejectedValue(new Error("getaddrinfo ENOTFOUND example.com")) as unknown as typeof fetch;
    const results = await checkVerifySecrets(layer, { FOO: "v" }, fetchImpl);
    expect(results[0]?.status).toBe("fail");
    expect(results[0]?.detail).toContain("ENOTFOUND");
  });

  it("verifies every secret that has a verify table configured, independently", async () => {
    const layer: DoctorConfigLoad = {
      kind: "parsed",
      layer: {
        secrets: {
          FOO: { hosts: ["a.example.com"], verify: { url: "https://a.example.com/check", header: "x-api-key" } },
          BAR: { hosts: ["b.example.com"], verify: { url: "https://b.example.com/check", header: "authorization" } },
        },
      },
    };
    const fetchImpl = vi
      .fn()
      .mockResolvedValueOnce(new Response(null, { status: 200 }))
      .mockResolvedValueOnce(new Response(null, { status: 401 })) as unknown as typeof fetch;
    const results = await checkVerifySecrets(layer, { FOO: "foo-value", BAR: "bar-value" }, fetchImpl);
    expect(results.map((r) => r.name).sort()).toEqual(["verify-secret:BAR", "verify-secret:FOO"]);
    expect(results.find((r) => r.name === "verify-secret:FOO")?.status).toBe("ok");
    expect(results.find((r) => r.name === "verify-secret:BAR")?.status).toBe("fail");
  });
});

describe("commands/doctor: runDoctorChecks (real-environment smoke test)", () => {
  // Not mocked: this is the one place the real OS is exercised in this
  // suite, matching the module comment's own honesty about what's
  // meaningfully unit-testable versus what's only verified for real. Kept
  // to structural assertions (every check present, ok reflects fail
  // status) rather than asserting exact statuses, since those are
  // legitimately machine-dependent — see the M3.5 report for this
  // machine's real `corb doctor` output.
  let previousConfigDir: string | undefined;
  let configDir: string;

  beforeEach(() => {
    configDir = fs.mkdtempSync(path.join(os.tmpdir(), "corb-doctor-config-"));
    previousConfigDir = process.env.CORB_CONFIG_DIR;
    process.env.CORB_CONFIG_DIR = configDir;
  });

  afterEach(() => {
    if (previousConfigDir === undefined) {
      delete process.env.CORB_CONFIG_DIR;
    } else {
      process.env.CORB_CONFIG_DIR = previousConfigDir;
    }
    fs.rmSync(configDir, { recursive: true, force: true });
  });

  it("returns one result per check, with unique names, and ok matching the fail count", async () => {
    const report = await runDoctorChecks();
    const names = report.checks.map((c) => c.name);
    expect(new Set(names).size).toBe(names.length);
    expect(names).toEqual(
      expect.arrayContaining([
        "kvm",
        "qemu",
        "docker",
        "node",
        "go",
        "cpio-lz4",
        "e2fsprogs",
        "ssh-auth-sock",
        "required-secrets",
        "secrets-configured",
        "image-resolvable",
        "cgroup-controllers",
        "gondolin-socket-path",
        "gondolin-socket-permissions",
      ]),
    );
    expect(report.ok).toBe(report.checks.every((c) => c.status !== "fail"));
  });

  it("checkVerifySecrets only runs when verifySecrets: true, even with a [secrets.NAME.verify] configured", async () => {
    fs.writeFileSync(
      path.join(configDir, "config.toml"),
      `[secrets.FOO]\nhosts = ["example.com"]\n[secrets.FOO.verify]\nurl = "https://example.com/check"\nheader = "x-api-key"\n`,
    );
    process.env.FOO = "some-value";
    try {
      const withoutVerify = await runDoctorChecks();
      expect(withoutVerify.checks.map((c) => c.name)).not.toContain("verify-secret:FOO");

      const fetchImpl = vi.fn().mockResolvedValue(new Response(null, { status: 200 })) as unknown as typeof fetch;
      const withVerify = await runDoctorChecks({ verifySecrets: true, fetchImpl });
      expect(withVerify.checks.map((c) => c.name)).toContain("verify-secret:FOO");
      expect(fetchImpl).toHaveBeenCalledTimes(1);
    } finally {
      delete process.env.FOO;
    }
  });
});
