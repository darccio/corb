import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { randomUUID } from "node:crypto";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import { corbCacheRoot } from "../../src/config/paths.ts";
import { normalizeLayerDefinition, hashLayerDefinition } from "../../src/layer/definition.ts";
import { publishInputGraph, readInputGraph } from "../../src/layer/graph.ts";
import { publishBlob, hashFile } from "../../src/layer/state.ts";
import { OrasTransport, writeOciLayout, registryFlags } from "../../src/layer/transport.ts";

describe.skipIf(!process.env.CORB_E2E)("input OCI layouts through real ORAS", () => {
  let root: string; let graph: Awaited<ReturnType<typeof publishInputGraph>>; let transport: OrasTransport;
  beforeAll(async () => {
    root = path.join(process.env.CORB_E2E_RUNTIME_DIR ?? corbCacheRoot(), `oras-layout-${randomUUID()}`); fs.mkdirSync(root, { recursive: true, mode: 0o700 }); vi.stubEnv("CORB_CACHE_DIR", path.join(root, "producer"));
    const definition = normalizeLayerDefinition({ packages: [], commands: ["true"] });
    graph = await publishInputGraph({ version: 1, definition, pins: { os: "linux", abi: "musl", "alpine-branch": "v3.23", "definition-sha256": hashLayerDefinition(definition), index: [], package: [] } }, "x86_64");
    writeOciLayout(path.join(root, "producer-layout"), graph.manifest, graph.digest); transport = new OrasTransport({});
  });
  afterAll(() => { vi.unstubAllEnvs(); if (root !== undefined) fs.rmSync(root, { recursive: true, force: true }); });
  it("uses the exact blob-fetch output contract with ORAS 1.3.5", async () => {
    const filename = path.join(root, "config");
    await transport.run(["blob", "fetch", "--oci-layout", "--output", "-", `${path.join(root, "producer-layout")}@${graph.manifest.config.digest}`], { filename, limit: graph.manifest.config.size });
    expect(fs.readFileSync(filename)).toEqual(graph.configBytes);
  });
  it("copies raw graph bytes between layouts and revalidates a distinct recipient cache", async () => {
    const destination = path.join(root, "recipient-layout");
    await transport.run(["cp", "--no-tty", "--from-oci-layout", "--to-oci-layout", `${path.join(root, "producer-layout")}:artifact`, `${destination}:artifact`]);
    vi.stubEnv("CORB_CACHE_DIR", path.join(root, "recipient"));
    for (const descriptor of [{ digest: graph.digest, size: graph.rootBytes.length }, graph.manifest.config, ...graph.manifest.layers]) {
      const filename = path.join(destination, "blobs/sha256", descriptor.digest.slice(7)); expect(await hashFile(filename)).toBe(descriptor.digest.slice(7)); await publishBlob(filename, descriptor.digest, descriptor.size);
    }
    expect((await readInputGraph(graph.digest, "x86_64")).rootBytes).toEqual(graph.rootBytes);
  });
  it("cancels and reaps a real ORAS child blocked on an owned local FIFO", async () => {
    await transport.run(["version"]);
    const filename = path.join(root, "producer-layout/blobs/sha256", graph.manifest.config.digest.slice(7)); const bytes = fs.readFileSync(filename); fs.unlinkSync(filename); expect(spawnSync("mkfifo", [filename]).status).toBe(0);
    const before = new Set(process.listeners("SIGINT"));
    const pending = transport.run(["blob", "fetch", "--oci-layout", "--output", "-", `${path.join(root, "producer-layout")}@${graph.manifest.config.digest}`], { filename: path.join(root, "cancelled-output"), limit: graph.manifest.config.size });
    const outcome = pending.then(() => ({ error: undefined as Error | undefined }), (error: Error) => ({ error }));
    const cancellation = process.listeners("SIGINT").find((listener) => !before.has(listener));
    try {
      expect(cancellation).toBeDefined(); await new Promise((resolve) => setTimeout(resolve, 100)); cancellation!();
      expect((await outcome).error?.message).toContain("cancelled"); expect(process.listeners("SIGINT").filter((listener) => !before.has(listener))).toEqual([]);
    } finally { fs.rmSync(filename, { force: true }); fs.writeFileSync(filename, bytes, { flag: "wx", mode: 0o600 }); }
  });

  it("explicitly disables ORAS localhost HTTP inference", async () => {
    const config = path.join(root, "private-registry-config.json"); fs.writeFileSync(config, '{"auths":{}}', { flag: "wx", mode: 0o600 });
    const remote = new OrasTransport({ registryConfig: config });
    await expect(remote.run(["manifest", "fetch", ...registryFlags(remote.options), `localhost:1/closed@sha256:${"a".repeat(64)}`])).rejects.toThrow("https://localhost:1/");
  });

});
