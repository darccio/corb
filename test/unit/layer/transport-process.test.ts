import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { EventEmitter } from "node:events";
import { PassThrough } from "node:stream";
import { afterEach, expect, it, vi } from "vitest";
const state = vi.hoisted(() => ({ spawn: vi.fn() }));
vi.mock("node:child_process", async (load) => ({ ...await load<object>(), spawn: state.spawn }));
import { OrasTransport, fetchArtifactMetadata } from "../../../src/layer/transport.ts";
import { serializeInputConfig, serializeInputManifest } from "../../../src/layer/inputs.ts";
import { hashLayerDefinition, normalizeLayerDefinition } from "../../../src/layer/definition.ts";
import { sha256 } from "../../../src/layer/validate.ts";
const directories: string[] = [];
afterEach(() => { vi.restoreAllMocks(); vi.useRealTimers(); state.spawn.mockReset(); for (const directory of directories.splice(0)) fs.rmSync(directory, { recursive: true, force: true }); });
function directory() { const root = fs.mkdtempSync(path.join(os.tmpdir(), "corb-oras-process-")); directories.push(root); return root; }
function child(stdout: string | Buffer, stderr = "", code = 0) {
  const processValue = new EventEmitter() as EventEmitter & { stdout: PassThrough; stderr: PassThrough; kill: ReturnType<typeof vi.fn> };
  processValue.stdout = new PassThrough(); processValue.stderr = new PassThrough(); processValue.kill = vi.fn(() => { queueMicrotask(() => processValue.emit("close", 143)); return true; });
  queueMicrotask(() => { processValue.emit("spawn"); processValue.stdout.write(stdout); processValue.stderr.write(stderr); processValue.emit("close", code); });
  return processValue;
}
it("rejects any other ORAS version and checks again after a failed discovery", async () => {
  state.spawn.mockImplementation(() => child("Version: 1.3.6\n")); const transport = new OrasTransport({});
  await expect(transport.run(["cp", "source", "destination"])).rejects.toThrow("exactly 1.3.5");
  await expect(transport.run(["cp", "source", "destination"])).rejects.toThrow("exactly 1.3.5"); expect(state.spawn.mock.calls.every((call) => call[1][0] === "version")).toBe(true);
});
it("fetches bounded config bytes with ORAS's required output contract and TLS/auth options", async () => {
  const root = directory(); const definition = normalizeLayerDefinition({ packages: [], commands: ["true"] });
  const config = { version: 1 as const, definition, pins: { os: "linux" as const, abi: "musl" as const, "alpine-branch": "v3.23", "definition-sha256": hashLayerDefinition(definition), index: [], package: [] } };
  const configBytes = serializeInputConfig(config, "x86_64"); const manifest = serializeInputManifest(config, "x86_64", new Map()); const digest = `sha256:${sha256(manifest)}`;
  state.spawn.mockImplementation((_name: string, args: string[]) => {
    if (args[0] === "version") return child("Version:        1.3.5\n");
    if (args.includes("--descriptor")) return child(JSON.stringify({ mediaType: "application/vnd.oci.image.manifest.v1+json", digest, size: Buffer.byteLength(manifest) }));
    if (args[0] === "manifest") return child(manifest);
    expect(args.slice(0, 4)).toEqual(["blob", "fetch", "--output", "-"]); return child(configBytes);
  });
  const transport = new OrasTransport({ registryConfig: "/private/auth", caFile: "/private/ca" });
  expect((await fetchArtifactMetadata(transport, `registry.example/repo@${digest}`, "input", root)).config.toString()).toBe(configBytes);
  for (const call of state.spawn.mock.calls.filter((call) => call[1][0] !== "version")) { expect(call[1]).toContain("--ca-file"); expect(call[1]).toContain("--registry-config"); expect(call[1]).toContain("--plain-http=false"); expect(call[1]).not.toContain("--insecure"); expect(call[1]).not.toContain("--plain-http"); }
});
it("kills and reaps excessive output without retaining unbounded diagnostics", async () => {
  const root = directory(); let excessive: ReturnType<typeof child>;
  state.spawn.mockImplementation((_name: string, args: string[]) => args[0] === "version" ? child("Version: 1.3.5\n") : (excessive = child(Buffer.alloc(100))));
  await expect(new OrasTransport({}).run(["manifest", "fetch", "exact"], { filename: path.join(root, "raw"), limit: 10 })).rejects.toThrow("exceeds descriptor bounds");
  expect(excessive!.kill).toHaveBeenCalledWith("SIGTERM"); expect(fs.statSync(path.join(root, "raw")).size).toBe(0);
});

it("bounds each command and reaps a child that ignores graceful timeout", async () => {
  vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout", "Date"] });
  const stalled = new EventEmitter() as EventEmitter & { stdout: PassThrough; stderr: PassThrough; kill: ReturnType<typeof vi.fn> }; stalled.stdout = new PassThrough(); stalled.stderr = new PassThrough();
  stalled.kill = vi.fn((signal: string) => { if (signal === "SIGKILL") queueMicrotask(() => stalled.emit("close", null, signal)); return true; });
  state.spawn.mockImplementation((_name: string, args: string[]) => args[0] === "version" ? child("Version: 1.3.5\n") : stalled);
  const listeners = process.listenerCount("SIGTERM"); const pending = new OrasTransport({}).run(["cp", "source", "destination"]); const rejected = expect(pending).rejects.toThrow("time limit");
  for (let count = 0; count < 10 && state.spawn.mock.calls.length < 2; count++) await Promise.resolve();
  await vi.advanceTimersByTimeAsync(30 * 60_000); expect(stalled.kill).toHaveBeenCalledWith("SIGTERM"); await vi.advanceTimersByTimeAsync(1000); await rejected; expect(stalled.kill).toHaveBeenCalledWith("SIGKILL"); expect(process.listenerCount("SIGTERM")).toBe(listeners);
});
