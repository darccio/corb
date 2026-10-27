import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  buildDoctorReport,
  parseDoctorArgs,
  renderDoctorJson,
  renderDoctorText,
  runDoctorCommand,
  type DoctorCheckResult,
  type DoctorJson,
} from "../../../src/commands/doctor.ts";

describe("commands/doctor: parseDoctorArgs", () => {
  it("disables JSON and secret verification by default", () => {
    expect(parseDoctorArgs([])).toEqual({ json: false, verifySecrets: false });
  });

  it("parses --json without enabling secret verification", () => {
    expect(parseDoctorArgs(["--json"])).toEqual({ json: true, verifySecrets: false });
  });

  it("parses --verify-secrets without enabling JSON", () => {
    expect(parseDoctorArgs(["--verify-secrets"])).toEqual({ json: false, verifySecrets: true });
  });

  it.each([
    ["--json", "--verify-secrets"],
    ["--verify-secrets", "--json"],
  ])("combines %s and %s", (first, second) => {
    expect(parseDoctorArgs([first, second])).toEqual({ json: true, verifySecrets: true });
  });

  it.each(["--unknown", "some-directory", "--json=true", "--verify-secrets=true"])("rejects %s", (arg) => {
    expect(() => parseDoctorArgs([arg])).toThrow();
  });
});

describe("commands/doctor: renderDoctorJson", () => {
  it.each([
    { status: "ok", ok: true },
    { status: "warn", ok: true },
    { status: "fail", ok: false },
  ] as const)("renders all checks with overall ok=$ok for $status", ({ status, ok }) => {
    const checks: DoctorCheckResult[] = [
      { name: "node", status: "ok", detail: "Node meets the required version." },
      { name: "workspace-sources", status, detail: "Workspace source status." },
    ];
    const report = buildDoctorReport(checks);
    expect(JSON.parse(renderDoctorJson(report))).toEqual({ checks, ok });
    expect(report).toEqual({ checks, ok });
  });

  it("renders an empty report as successful", () => {
    expect(JSON.parse(renderDoctorJson(buildDoctorReport([])))).toEqual({ checks: [], ok: true });
  });

  it("pretty prints only report fields and escapes check details", () => {
    const check = { name: "quoted", status: "ok" as const, detail: 'line one\n"line two"', internal: "private" };
    const report = { ...buildDoctorReport([check]), internal: "private" };
    const expected: DoctorJson = { checks: [{ name: check.name, status: check.status, detail: check.detail }], ok: true };
    expect(renderDoctorJson(report)).toBe(JSON.stringify(expected, null, 2));
  });
});

describe("commands/doctor: renderDoctorText", () => {
  it("preserves check labels and summary counts", () => {
    const report = buildDoctorReport([
      { name: "node", status: "ok", detail: "Current version." },
      { name: "go", status: "warn", detail: "Version unavailable." },
      { name: "docker", status: "fail", detail: "Missing executable." },
    ]);
    expect(renderDoctorText(report)).toBe([
      "[OK] node: Current version.",
      "[WARN] go: Version unavailable.",
      "[FAIL] docker: Missing executable.",
      "corb doctor: 3 check(s), 1 failed, 1 warning(s).",
    ].join("\n"));
  });

  it("renders the summary for an empty report", () => {
    expect(renderDoctorText(buildDoctorReport([]))).toBe("corb doctor: 0 check(s), 0 failed, 0 warning(s).");
  });
});

describe("commands/doctor: command output", () => {
  let root: string;
  let previousExitCode: typeof process.exitCode;
  let log: ReturnType<typeof vi.spyOn>;
  let fetchImpl: ReturnType<typeof vi.fn>;
  const credential = "fake-doctor-test-credential";

  beforeEach(() => {
    root = fs.mkdtempSync(path.join(os.tmpdir(), "corb-doctor-output-"));
    const configDir = path.join(root, "config");
    fs.mkdirSync(configDir);
    fs.writeFileSync(path.join(configDir, "config.toml"), [
      "[secrets.CORB_DOCTOR_TEST_KEY]",
      'hosts = ["example.com"]',
      "[secrets.CORB_DOCTOR_TEST_KEY.verify]",
      'url = "https://example.com/check"',
      'header = "x-api-key"',
    ].join("\n"));
    vi.stubEnv("CORB_CONFIG_DIR", configDir);
    vi.stubEnv("CORB_STATE_DIR", path.join(root, "state"));
    vi.stubEnv("CORB_DOCTOR_TEST_KEY", credential);
    vi.stubEnv("PATH", "");
    fetchImpl = vi.fn().mockResolvedValue(new Response(null, { status: 200 }));
    vi.stubGlobal("fetch", fetchImpl);
    log = vi.spyOn(console, "log").mockImplementation(() => {});
    previousExitCode = process.exitCode;
    process.exitCode = 0;
  });

  afterEach(() => {
    process.exitCode = previousExitCode;
    vi.restoreAllMocks();
    vi.unstubAllGlobals();
    vi.unstubAllEnvs();
    fs.rmSync(root, { recursive: true, force: true });
  });

  it.each([false, true])("keeps failure exit codes with json=%s and verification disabled", async (json) => {
    await runDoctorCommand(json ? ["--json"] : []);
    expect(process.exitCode).toBe(1);
    expect(log).toHaveBeenCalledTimes(1);
    expect(fetchImpl).not.toHaveBeenCalled();
    const output = log.mock.calls[0]?.[0] as string;
    expect(output.includes(credential)).toBe(false);
    if (json) {
      const payload = JSON.parse(output) as DoctorJson;
      expect(payload.ok).toBe(false);
      expect(payload.checks.some((check) => check.name.startsWith("verify-secret:"))).toBe(false);
    } else {
      expect(output).toContain("[FAIL] qemu:");
      expect(output).toContain("corb doctor:");
    }
  });

  it.each([
    { flags: ["--json", "--verify-secrets"], status: 200, expected: "ok" },
    { flags: ["--verify-secrets", "--json"], status: 401, expected: "fail" },
  ])("includes $expected credential verification in one JSON document", async ({ flags, status, expected }) => {
    fetchImpl.mockResolvedValue(new Response(null, { status }));
    await runDoctorCommand(flags);
    expect(log).toHaveBeenCalledTimes(1);
    expect(fetchImpl).toHaveBeenCalledTimes(1);
    expect(fetchImpl.mock.calls[0]?.[1]?.headers?.["x-api-key"] === credential).toBe(true);
    const output = log.mock.calls[0]?.[0] as string;
    expect(output.includes(credential)).toBe(false);
    const payload = JSON.parse(output) as DoctorJson;
    expect(payload.checks.find((check) => check.name === "verify-secret:CORB_DOCTOR_TEST_KEY")?.status).toBe(expected);
    expect(payload.ok).toBe(false);
    expect(process.exitCode).toBe(1);
  });
});
