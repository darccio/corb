import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { PassThrough } from "node:stream";
import { afterEach, expect, it, vi } from "vitest";
const state = vi.hoisted(() => ({ create: vi.fn() }));
vi.mock("@earendil-works/gondolin", async (load) => ({ ...await load<object>(), VM: { create: state.create } }));
import { runSession, GATE_CONFIG_RAW_ROOT, rawWorkspacePath, type RunSessionOptions } from "../../../src/vm/session.ts";
import type { ValidatedComposition } from "../../../src/layer/generation.ts";
const dirs: string[] = [];
afterEach(() => { vi.restoreAllMocks(); vi.unstubAllEnvs(); vi.clearAllMocks(); for (const dir of dirs.splice(0)) fs.rmSync(dir, { recursive: true, force: true }); });
function fixture() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "corb-session-layer-")); dirs.push(root); vi.stubEnv("CORB_STATE_DIR", path.join(root, "state"));
  const calls: Array<{ argv: string[]; options: Record<string, unknown> }> = [];
  const close = vi.fn().mockResolvedValue(undefined);
  const exec = vi.fn((argv: string[], options: Record<string, unknown>) => {
    calls.push({ argv, options });
    const stdout = argv.includes("--corb-layer-internal") ? "[]" : argv.includes("/etc/corb/image.json") ? JSON.stringify({ user: "agent", uid: 1000, gid: 1000, paths: { dropcapPath: "/usr/local/bin/dropcap", home: "/home/agent", sessionsDir: "/home/agent/sessions" } }) : "";
    return Object.assign(Promise.resolve({ ok: true, exitCode: 0, stdout, stderr: "" }), { attach: vi.fn() });
  });
  const vm = { id: "a70cf0e7-4091-4b46-a974-db3777506a8c", server: { network: null }, exec, close };
  const resume = vi.fn().mockResolvedValue(vm); const recheck = vi.fn().mockResolvedValue(undefined);
  const composition = { base: { selector: "private:base", directory: root, manifest: { buildId: "exact-base", config: { arch: "x86_64" } } }, metadata: { runtime: [], mapping: [], path: "/opt/corb/toolchains/go/bin:/usr/local/bin:/usr/bin:/bin" }, recheck, load: () => ({ resume }) } as unknown as ValidatedComposition;
  const options = { composition, dirs: [{ name: "project", hostPath: root, mode: "rw" }], primary: "project", piArgs: ["--version"], memory: "1G", cpus: 2,
    egress: { allow: ["example.com"], "block-internal-ranges": true, websockets: false }, git: { "ssh-agent": false, "allow-push": false }, policy: { enabled: false, "secret-scan": false, "fail-open": false }, dirConfigs: [], audit: { record: vi.fn(), flush: vi.fn(), addRedactedSecrets: vi.fn() }, auditPath: path.join(root, "audit"), env: {}, stdin: new PassThrough(), stdout: new PassThrough(), stderr: new PassThrough(), shutdownProcess: { on() { return this; } }, exit: vi.fn(), sessionLabel: "layer-test" } as unknown as RunSessionOptions;
  return { options, calls, close, resume, recheck };
}
it("resumes with the original session assembly and restores runtime dirs before Pi", async () => {
  const fixtureValue = fixture(); await runSession(fixtureValue.options);
  expect(state.create).not.toHaveBeenCalled(); expect(fixtureValue.recheck).toHaveBeenCalledOnce(); expect(fixtureValue.resume).toHaveBeenCalledOnce();
  const resumed = fixtureValue.resume.mock.calls[0]![0];
  expect(resumed).toMatchObject({ sandbox: { imagePath: fixtureValue.options.composition!.base.directory }, memory: "1G", cpus: 2, sessionLabel: "layer-test" });
  expect(resumed.vfs.mounts[GATE_CONFIG_RAW_ROOT]).toBeDefined(); expect(resumed.vfs.mounts[rawWorkspacePath("project")]).toBeDefined(); expect(resumed.httpHooks).toBeDefined(); expect(resumed.ssh).toBeDefined();
  const runtime = fixtureValue.calls.findIndex((call) => call.argv.includes("runtime")); const pi = fixtureValue.calls.findIndex((call) => call.argv[0] === "/usr/local/bin/dropcap");
  expect(runtime).toBe(0); expect(pi).toBeGreaterThan(runtime); expect(fixtureValue.calls[pi]!.options.env).toMatchObject({ PATH: fixtureValue.options.composition!.metadata.path }); expect(fixtureValue.close).toHaveBeenCalled();
});
it("refuses a changed composition at the creation boundary", async () => {
  const fixtureValue = fixture(); fixtureValue.recheck.mockRejectedValue(new Error("backing changed"));
  await expect(runSession(fixtureValue.options)).rejects.toThrow("backing changed"); expect(fixtureValue.resume).not.toHaveBeenCalled(); expect(state.create).not.toHaveBeenCalled();
});
it("closes a resumed VM when runtime restoration fails", async () => {
  const fixtureValue = fixture(); fixtureValue.resume.mockImplementation(async () => ({ id: "fake", server: { network: null }, close: fixtureValue.close, exec: () => Promise.resolve({ ok: false, stdout: "", stderr: "unsafe runtime parent", exitCode: 1 }) }));
  await expect(runSession(fixtureValue.options)).rejects.toThrow("unsafe runtime parent"); expect(fixtureValue.close).toHaveBeenCalled();
});
