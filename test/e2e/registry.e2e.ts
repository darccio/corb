import fs from "node:fs";
import path from "node:path";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import { normalizeLayerDefinition, hashLayerDefinition } from "../../src/layer/definition.ts";
import { publishInputGraph, readInputGraph } from "../../src/layer/graph.ts";
import { OrasTransport, registryFlags, pushArtifact, fetchArtifactMetadata, copyArtifactToCache } from "../../src/layer/transport.ts";
import { validateInputArtifact } from "../../src/layer/inputs.ts";
import { blobPath, hashFile, publishBlob } from "../../src/layer/state.ts";
import { sha256 } from "../../src/layer/validate.ts";
import { startDistribution } from "./helpers/distribution.ts";

describe.skipIf(process.env.CORB_E2E !== "1")("authenticated HTTPS Distribution through real ORAS", () => {
  let root: string; let fixture: Awaited<ReturnType<typeof startDistribution>>; let transport: OrasTransport;
  let graph: Awaited<ReturnType<typeof publishInputGraph>>; let reference: string; let sequence = 0;
  const staging = () => { const directory = path.join(root, `transfer-${++sequence}`); fs.mkdirSync(directory, { mode: 0o700 }); return directory; };
  const options = () => ({ registryConfig: fixture.registryConfig, caFile: fixture.caFile });
  beforeAll(async () => {
    const parent = process.env.CORB_E2E_LAYER_ROOT ?? path.join(process.cwd(), "image/build/dar-21"); fs.mkdirSync(parent, { recursive: true });
    root = fs.mkdtempSync(path.join(parent, "registry-")); fixture = await startDistribution(path.join(root, "fixture"));
    vi.stubEnv("CORB_CACHE_DIR", path.join(root, "producer"));
    const definition = normalizeLayerDefinition({ packages: [], commands: ["true"] });
    graph = await publishInputGraph({ version: 1, definition, pins: { os: "linux", abi: "musl", "alpine-branch": "v3.23", "definition-sha256": hashLayerDefinition(definition), index: [], package: [] } }, "x86_64");
    transport = new OrasTransport(options()); reference = await pushArtifact(transport, `${fixture.host}/inputs:one`, graph.manifest, graph.digest, staging());
    console.log(`Distribution acceptance evidence: ${root}`);
  });
  afterAll(async () => { vi.unstubAllEnvs(); if (fixture) await fixture.close(); });
  it("uploads identical bytes under two tags and downloads into an empty independent cache", async () => {
    expect(await pushArtifact(transport, `${fixture.host}/inputs:two`, graph.manifest, graph.digest, staging())).toBe(reference);
    vi.stubEnv("CORB_CACHE_DIR", path.join(root, "recipient")); expect(fs.existsSync(blobPath(graph.digest))).toBe(false);
    const directory = staging(); const fetched = await fetchArtifactMetadata(new OrasTransport(options()), reference, "input", directory);
    await copyArtifactToCache(new OrasTransport(options()), reference, fetched.manifest, directory, fetched.root.length);
    expect((await readInputGraph(graph.digest, "x86_64")).rootBytes).toEqual(graph.rootBytes);
    for (const [method, role] of [["PUT", "/manifests/"], ["POST", "/blobs/uploads/"], ["GET", "/manifests/"], ["GET", "/blobs/"]]) expect(fixture.requests.some((row) => row.method === method && row.path.includes(role!) && row.authenticated && row.status >= 200 && row.status < 300)).toBe(true);
    expect(fixture.requests.some((row) => row.status === 401 && !row.authenticated)).toBe(true);
  });
  it.each(["missing", "wrong", "untrusted"])("rejects %s credentials or CA over real HTTPS", async (kind) => {
    const registryConfig = kind === "missing" ? fixture.emptyConfig : kind === "wrong" ? fixture.wrongConfig : fixture.registryConfig;
    const remote = new OrasTransport({ registryConfig, ...(kind === "untrusted" ? {} : { caFile: fixture.caFile }) });
    await expect(fetchArtifactMetadata(remote, reference, "input", staging())).rejects.toThrow(kind === "untrusted" ? /x509|certificate/ : /401|unauthorized|authentication/);
  });
  it("reports a real missing digest and preserves previously downloaded bytes", async () => {
    const before = await hashFile(blobPath(graph.digest));
    await expect(fetchArtifactMetadata(transport, `${fixture.host}/inputs@sha256:${"f".repeat(64)}`, "input", staging())).rejects.toThrow(/404|not found/);
    expect(await hashFile(blobPath(graph.digest))).toBe(before);
  });
  it.each(["artifact", "media", "url", "title", "path"])("rejects a remote malicious %s descriptor before composition", async (kind) => {
    const manifest = JSON.parse(graph.rootBytes.toString());
    if (kind === "artifact") manifest.artifactType = "application/example.unsupported";
    else if (kind === "media") manifest.config.mediaType = "application/example.unsupported";
    else {
      const descriptor = { ...manifest.config, annotations: { "org.opencontainers.image.title": kind === "title" ? "../../escape" : kind === "path" ? "/tmp/escape" : "payload/sdk" } };
      if (kind === "url") Object.assign(descriptor, { urls: ["https://attacker.invalid/blob"] });
      manifest.layers = [descriptor];
    }
    const bytes = Buffer.from(JSON.stringify(manifest)); const filename = path.join(root, `malicious-${kind}.json`); fs.writeFileSync(filename, bytes, { mode: 0o600 });
    await transport.run(["manifest", "push", ...registryFlags(options()), `${fixture.host}/inputs:bad-${kind}`, filename]);
    await expect(fetchArtifactMetadata(transport, `${fixture.host}/inputs@sha256:${sha256(bytes)}`, "input", staging())).rejects.toThrow(/unsupported|unknown|OCI role/);
  });
  it.each(["digest", "truncated"])("rejects %s response content from the owned HTTPS fault proxy", async (kind) => {
    fixture.setFault((method, pathname) => method === "GET" && pathname.endsWith(`/blobs/${graph.manifest.config.digest}`) ? kind === "digest" ? { body: Buffer.alloc(graph.configBytes.length, 32) } : { truncate: 1 } : undefined);
    try { await expect(fetchArtifactMetadata(transport, reference, "input", staging())).rejects.toThrow(/digest|mismatch|unexpected EOF|size|failed/); }
    finally { fixture.setFault(undefined); }
  });
  it("rejects a remote incompatible SDK architecture before payload extraction or boot", async () => {
    const definition = normalizeLayerDefinition({ packages: [], commands: ["true"], payload: [{ name: "go", url: "https://go.dev/dl/go1.27.3.linux-arm64.tar.gz", sha256: graph.manifest.config.digest.slice(7), arch: "aarch64", destination: "/opt/corb/toolchains/go", "strip-components": 1, path: ["bin"] }] });
    const config = { ...graph.config, definition, pins: { ...graph.config.pins, "definition-sha256": hashLayerDefinition(definition) } };
    const configBytes = Buffer.from(JSON.stringify(config)); const configFile = path.join(root, "foreign-config"); fs.writeFileSync(configFile, configBytes, { mode: 0o600 });
    await transport.run(["blob", "push", ...registryFlags(options()), `${fixture.host}/inputs`, configFile]);
    const manifest = { ...graph.manifest, config: { ...graph.manifest.config, digest: `sha256:${sha256(configBytes)}`, size: configBytes.length }, layers: [{ ...graph.manifest.config, mediaType: "application/vnd.corb.sdk.v1+tar+gzip", annotations: { "org.opencontainers.image.title": "payload/go" } }] };
    const bytes = Buffer.from(JSON.stringify(manifest)); const filename = path.join(root, "foreign-manifest"); fs.writeFileSync(filename, bytes, { mode: 0o600 });
    await transport.run(["manifest", "push", ...registryFlags(options()), `${fixture.host}/inputs:foreign`, filename]);
    const fetched = await fetchArtifactMetadata(transport, `${fixture.host}/inputs@sha256:${sha256(bytes)}`, "input", staging());
    expect(() => validateInputArtifact(fetched.root, fetched.config, "x86_64", new Map(fetched.manifest.layers.map((row) => [row.digest, row.size])))).toThrow(/architecture|arch/);
  });
  it("keeps an old immutable lock valid after moving its explicit tag", async () => {
    const definition = normalizeLayerDefinition({ packages: [], commands: ["echo moved"] });
    const moved = await publishInputGraph({ version: 1, definition, pins: { os: "linux", abi: "musl", "alpine-branch": "v3.23", "definition-sha256": hashLayerDefinition(definition), index: [], package: [] } }, "x86_64");
    expect(await pushArtifact(transport, `${fixture.host}/inputs:one`, moved.manifest, moved.digest, staging())).not.toBe(reference);
    expect((await fetchArtifactMetadata(transport, reference, "input", staging())).root).toEqual(graph.rootBytes);
  });
  it("revalidates a corrupt complete cache object without overwriting it", async () => {
    const filename = blobPath(graph.digest); const valid = fs.readFileSync(filename); fs.chmodSync(filename, 0o600); fs.writeFileSync(filename, "corrupt-owned-object");
    const source = path.join(root, "valid-root"); fs.writeFileSync(source, valid, { mode: 0o600 });
    try {
      await expect(readInputGraph(graph.digest, "x86_64")).rejects.toThrow("corrupt input cache object");
      await expect(publishBlob(source, graph.digest)).rejects.toThrow("corrupt input cache object");
      expect(fs.readFileSync(filename, "utf8")).toBe("corrupt-owned-object");
    } finally { fs.writeFileSync(filename, valid); fs.chmodSync(filename, 0o400); }
  });
  it("fails publication after real blobs exist and never logs credential markers", async () => {
    fixture.setFault((method, pathname) => method === "PUT" && pathname.endsWith("/manifests/partial") ? { status: 503 } : undefined);
    try { await expect(pushArtifact(transport, `${fixture.host}/partial:partial`, graph.manifest, graph.digest, staging())).rejects.toThrow(/503|failed/); }
    finally { fixture.setFault(undefined); }
    expect(fixture.requests.some((row) => row.method === "PUT" && row.path.startsWith("/v2/partial/blobs/uploads/") && row.status === 201 && row.authenticated)).toBe(true);
    expect(fixture.requests.some((row) => row.path === "/v2/partial/manifests/partial" && row.status === 503)).toBe(true);
    const ordinary = JSON.stringify({ requests: fixture.requests, graph: graph.config, root: graph.rootBytes.toString() });
    for (const marker of fixture.markers) expect(ordinary).not.toContain(marker);
  });
});
