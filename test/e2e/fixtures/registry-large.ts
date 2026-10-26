import fs from "node:fs";
import path from "node:path";
import { startDistribution } from "../helpers/distribution.ts";
import { OrasTransport, registryFlags } from "../../../src/layer/transport.ts";
import { hashFile } from "../../../src/layer/state.ts";
import { redactRegistryDiagnostics } from "../../../src/layer/diagnostics.ts";

const [directory, base] = process.argv.slice(2);
if (process.env.CORB_E2E !== "1" || !directory || !base) throw Error("CORB_E2E=1, a fresh owned directory and a completed base are required");
fs.mkdirSync(directory, { mode: 0o700 });
const manifest = JSON.parse(fs.readFileSync(path.join(base, "manifest.json"), "utf8"));
const source = path.join(base, manifest.assets.rootfs); const size = fs.statSync(source).size;
const expected = manifest.checksums.rootfs; const started = Date.now();
let registry: Awaited<ReturnType<typeof startDistribution>> | undefined;
let failure: unknown; let verified = false;
try {
  if (size !== 3 * 1024 ** 3 || await hashFile(source, size) !== expected) throw Error("source rootfs differs from the completed 3 GiB base");
  registry = await startDistribution(path.join(directory, "registry"));
  const transport = new OrasTransport({ registryConfig: registry.registryConfig, caFile: registry.caFile });
  await transport.run(["blob", "push", ...registryFlags(transport.options), `${registry.host}/large`, source]);
  const downloaded = path.join(directory, "downloaded-rootfs");
  await transport.run(["blob", "fetch", "--output", "-", ...registryFlags(transport.options), `${registry.host}/large@sha256:${expected}`], { filename: downloaded, limit: size });
  if (fs.statSync(downloaded).size !== size || await hashFile(downloaded, size) !== expected) throw Error("downloaded rootfs identity differs");
  const upload = registry.requests.find((row) => row.method === "PUT" && row.requestBytes === size);
  const download = registry.requests.find((row) => row.method === "GET" && row.status === 200 && row.authenticated && row.path.endsWith(`/blobs/sha256:${expected}`));
  if (!upload || upload.status !== 201 || !upload.authenticated || upload.upstreamError || !download || download.status !== 200 || download.bytes !== size || !download.authenticated || registry.markers.length <= 3) throw Error("large transfer lacks authenticated real API evidence");
  verified = true;
} catch (error) { failure = error; }
finally {
  try { await registry?.close(); } catch (cleanup) { failure = failure === undefined ? cleanup : new AggregateError([failure, cleanup], "large transfer and cleanup failed"); }
  fs.writeFileSync(path.join(directory, "result.json"), JSON.stringify({ verified, size, sha256: expected, elapsedMs: Date.now() - started, error: failure === undefined ? undefined : redactRegistryDiagnostics(String(failure)) }, null, 2), { mode: 0o600 });
}
if (failure !== undefined) throw failure;
console.log("owned authenticated 3 GiB upload and verified download passed");
