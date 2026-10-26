import { beforeEach, describe, expect, it, vi } from "vitest";
const state = vi.hoisted(() => ({ create: vi.fn() }));
vi.mock("@earendil-works/gondolin", async (load) => ({ ...await load<object>(), VM: { create: state.create } }));
import type { VM } from "@earendil-works/gondolin";
import { verifyImage, verifyVm } from "../../../image/verify.ts";
import { GATE_CONFIG_RAW_ROOT } from "../../../src/vm/session.ts";

function candidate(forbidden = "", tlsTrace = "OpenSSL verify result: 0\nSSL certificate verified via OpenSSL.") {
  const exec = vi.fn(async (argv: string[]) => {
    const script = argv.join(" ");
    let stdout = "";
    let stderr = "";
    if (script.includes("id -u")) stdout = "1000";
    else if (script.includes("ls -ldn")) stdout = "1000 1000";
    else if (script.includes("/proc/self/status")) stdout = "NoNewPrivs: 1\nCapEff: 0000\nGroups: \nUid: 1000 1000 1000 1000\n";
    else if (script.includes("PRESENT:npm")) stdout = forbidden ? `PRESENT:${forbidden}` : "";
    else if (script.includes("ca-certificates.crt")) stdout = "PRESENT";
    else if (script.includes("fetch(")) stdout = "STATUS 401";
    else if (script.includes("ls-remote")) { stdout = `${"a".repeat(40)}\tHEAD\n`; stderr = tlsTrace; }
    else if (script.includes("command -v git")) stdout = "/usr/local/bin/git\n/usr/local/libexec/policygate\n/usr/local/libexec/policygate\nGIT_REAL_PRESENT\nGH_REAL_PRESENT\nPOLICYGATE_PRESENT\nOLD_GIT_GONE\nOLD_GH_GONE";
    else if (script.includes("image.json")) stdout = '{"piVersion":"1.4.0"}';
    else if (script.includes("pi --version")) stdout = "1.4.0";
    return { stdout, stderr, ok: true, exitCode: 0 };
  });
  const close = vi.fn();
  return { vm: { exec, close, server: { network: null } } as unknown as VM, exec, close };
}
beforeEach(() => vi.clearAllMocks());
const names = ["user", "privilege-drop", "suid", "removals", "ca-trust", "git-gh-shimmed", "pi"];
describe("image verifier", () => {
  it("runs all seven existing gates without closing a caller-owned VM", async () => {
    const { vm, close, exec } = candidate();
    const report = await verifyVm(vm);
    expect(report.ok).toBe(true);
    expect(report.gates.map((gate) => gate.name)).toEqual(names);
    expect(close).not.toHaveBeenCalled();
    const git = exec.mock.calls.filter(([argv]) => argv.includes("ls-remote"));
    expect(git).toHaveLength(4);
    expect(git.filter(([argv]) => argv.includes("/usr/local/bin/dropcap"))).toHaveLength(2);
  });
  it("accepts the older curl verification trace and rejects missing verification evidence", async () => {
    expect((await verifyVm(candidate("", "SSL certificate verify ok.").vm)).ok).toBe(true);
    const report = await verifyVm(candidate("", "certificate verification disabled").vm);
    expect(report.gates.find((gate) => gate.name === "ca-trust")).toMatchObject({ ok: false });
  });
  it("rejects the seventh forbidden PATH name", async () => {
    const { vm, exec } = candidate("apk.static");
    const report = await verifyVm(vm);
    expect(report.gates.find((gate) => gate.name === "removals")).toMatchObject({ ok: false, detail: expect.stringContaining("apk.static") });
    expect(exec.mock.calls.some(([argv]) => argv.join(" ").includes("command -v apk.static"))).toBe(true);
  });
  it("uses the same gates in the boot-and-close wrapper with production mounts and hosts", async () => {
    const direct = candidate();
    const wrapped = candidate();
    state.create.mockResolvedValue(wrapped.vm);
    expect(await verifyImage("candidate")).toEqual(await verifyVm(direct.vm));
    expect(wrapped.exec.mock.calls.map(([argv]) => argv)).toEqual(direct.exec.mock.calls.map(([argv]) => argv));
    expect(wrapped.close).toHaveBeenCalledOnce();
    const options = state.create.mock.calls[0]![0];
    expect(options.vfs.mounts[GATE_CONFIG_RAW_ROOT]).toBeDefined();
    expect(options).toMatchObject({ memory: "1G", cpus: 2, startTimeoutMs: 45_000 });
    const allowed = await options.httpHooks.isIpAllowed({ hostname: "github.com", ip: "140.82.114.3", family: 4, port: 443, protocol: "https" });
    expect(allowed).toBe(true);
    expect(await options.httpHooks.isIpAllowed({ hostname: "unexpected.example", ip: "203.0.113.1", family: 4, port: 443, protocol: "https" })).toBe(false);
  });
  it("continues after a gate throws and closes the wrapper VM", async () => {
    const { vm, exec, close } = candidate();
    exec.mockRejectedValueOnce(new Error("user lookup failed"));
    state.create.mockResolvedValue(vm);
    const report = await verifyImage("candidate");
    expect(report.gates.map((gate) => gate.name)).toEqual(names);
    expect(report.gates[0]).toMatchObject({ ok: false, detail: expect.stringContaining("user lookup failed") });
    expect(close).toHaveBeenCalledOnce();
  });
});
