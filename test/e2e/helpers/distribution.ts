import fs from "node:fs";
import path from "node:path";
import net from "node:net";
import https from "node:https";
import { execFileSync } from "node:child_process";
import { randomBytes, createHash } from "node:crypto";
import { runOwnedProcess, type OwnedResult } from "./owned-process.ts";
import { registryProxy, type RegistryRequest } from "./registry-proxy.ts";
import { redactRegistryDiagnostics } from "../../../src/layer/diagnostics.ts";
import { attemptCleanup } from "./cleanup.ts";
import { RegistryMarkers } from "./registry-markers.ts";

export const REGISTRY_VERSION = "3.1.2";
export const REGISTRY_ARCHIVE_SHA256 = "40df2224d410f72ae425c3371873b078bbdbda3b8b612be9571f0e6751f3acc8";
export const REGISTRY_BINARY_SHA256 = "7f9e0df42bd028efb1a11eb7f92ef494156bf308770303a256d3acdcadb378cd";
export const REGISTRY_SOURCE = "https://github.com/distribution/distribution/releases/tag/v3.1.2";
export interface RegistryFault { status?: number; body?: Buffer; truncate?: number }
const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));
async function listen(server: net.Server): Promise<number> {
  await new Promise<void>((resolve, reject) => { server.once("error", reject); server.listen(0, "127.0.0.1", resolve); });
  return (server.address() as net.AddressInfo).port;
}
async function closeServer(server: https.Server) {
  server.closeAllConnections(); await new Promise<void>((resolve) => server.close(() => resolve()));
}

export async function startDistribution(root: string) {
  fs.mkdirSync(root, { recursive: true, mode: 0o700 });
  const binary = process.env.CORB_E2E_REGISTRY_BINARY;
  if (!binary || createHash("sha256").update(fs.readFileSync(binary)).digest("hex") !== REGISTRY_BINARY_SHA256) throw Error(`set CORB_E2E_REGISTRY_BINARY to the verified official Distribution ${REGISTRY_VERSION} binary`);
  const version = execFileSync(binary, ["--version"], { encoding: "utf8", timeout: 5000 });
  if (!version.trim().endsWith(` ${REGISTRY_VERSION}`)) throw Error("wrong Distribution version");
  const command = (args: string[]) => execFileSync("openssl", args, { cwd: root, stdio: "pipe", timeout: 15_000 });
  command(["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", "ca.key", "-out", "ca.pem", "-days", "2", "-subj", "/CN=Corb owned registry fixture CA", "-addext", "basicConstraints=critical,CA:TRUE"]);
  command(["req", "-newkey", "rsa:2048", "-nodes", "-keyout", "server.key", "-out", "server.csr", "-subj", "/CN=localhost"]);
  fs.writeFileSync(path.join(root, "server.ext"), "subjectAltName=DNS:localhost,IP:127.0.0.1\nbasicConstraints=critical,CA:FALSE\nextendedKeyUsage=serverAuth\n", { mode: 0o600 });
  command(["x509", "-req", "-in", "server.csr", "-CA", "ca.pem", "-CAkey", "ca.key", "-CAcreateserial", "-out", "server.pem", "-days", "2", "-extfile", "server.ext"]);
  for (const name of ["ca.key", "server.key"]) fs.chmodSync(path.join(root, name), 0o600);
  const username = "corb-fixture"; const password = `c21-password-${randomBytes(24).toString("hex")}`;
  const authorization = `Basic ${Buffer.from(`${username}:${password}`).toString("base64")}`;
  const markers = new RegistryMarkers([password, authorization, Buffer.from(`${username}:${password}`).toString("base64")]);
  const bcrypt = execFileSync("python3", ["-c", "import ctypes,sys; c=ctypes.CDLL('libcrypt.so.1'); c.crypt.restype=ctypes.c_char_p; print(c.crypt(sys.stdin.buffer.read(),b'$2b$04$abcdefghijklmnopqrstuu').decode())"], { input: password, encoding: "utf8", timeout: 5000 }).trim();
  if (!bcrypt.startsWith("$2b$04$")) throw Error("bcrypt fixture creation failed");
  fs.writeFileSync(path.join(root, "htpasswd"), `${username}:${bcrypt}\n`, { flag: "wx", mode: 0o600 });
  const reserved = net.createServer(); const backend = await listen(reserved); await new Promise<void>((resolve) => reserved.close(() => resolve()));
  const caFile = path.join(root, "ca.pem"); const ca = fs.readFileSync(caFile);
  const tls = { key: fs.readFileSync(path.join(root, "server.key")), cert: fs.readFileSync(path.join(root, "server.pem")) };
  const requests: RegistryRequest[] = []; let fault: ((method: string, pathname: string) => RegistryFault | undefined) | undefined;
  const forwarding = registryProxy({
    connect: (options, response) => https.request({ ...options, hostname: "127.0.0.1", port: backend, ca }, response),
    backendOrigin: `https://127.0.0.1:${backend}`, authorization, requests, fault: (method, pathname) => fault?.(method, pathname), location: (value) => markers.location(value),
  });
  const proxy = https.createServer(tls, forwarding.handler);
  const controller = new AbortController(); let closed = false;
  let service: Promise<OwnedResult> | undefined;
  async function close() {
    if (closed) return; closed = true;
    let result: OwnedResult | undefined;
    const failures = await attemptCleanup([
      { name: "upstreams", run: forwarding.close },
      { name: "proxy", run: () => closeServer(proxy) },
      { name: "registry", run: async () => { controller.abort(); result = await service; } },
      { name: "http-receipt", run: () => fs.writeFileSync(path.join(root, "http.json"), JSON.stringify(requests, null, 2), { mode: 0o600 }) },
      { name: "process-receipt", run: () => fs.writeFileSync(path.join(root, "process.json"), JSON.stringify({ version, source: REGISTRY_SOURCE, archiveSha256: REGISTRY_ARCHIVE_SHA256, binarySha256: REGISTRY_BINARY_SHA256, uploadStateMarkerCount: markers.values.length - 3, ...result, output: redactRegistryDiagnostics(result?.output ?? ""), error: result?.error === undefined ? undefined : redactRegistryDiagnostics(result.error.message) }, null, 2), { mode: 0o600 }) },
      { name: "registry-verdict", run: () => { if (result && (result.code !== 0 || result.survivors.length > 0 || result.uncertain || result.forced.length > 0)) throw Error("registry child cleanup failed"); } },
      { name: "diagnostics", run: () => {
        markers.assertValid();
        for (const filename of ["http.json", "process.json"]) if (markers.values.some((marker) => fs.readFileSync(path.join(root, filename), "utf8").includes(marker))) throw Error("registry diagnostics leaked credentials");
      } },
    ]);
    if (failures.length > 0) throw new AggregateError(failures.map((row) => row.error), `registry cleanup failed: ${failures.map((row) => row.name).join(", ")}`);
  }
  try {
    const port = await listen(proxy); const host = `localhost:${port}`;
    const registryConfig = path.join(root, "registry-config.json");
    fs.writeFileSync(registryConfig, JSON.stringify({ auths: { [host]: { auth: Buffer.from(`${username}:${password}`).toString("base64") } } }), { flag: "wx", mode: 0o600 });
    const emptyConfig = path.join(root, "empty-config.json"); fs.writeFileSync(emptyConfig, '{"auths":{}}', { flag: "wx", mode: 0o600 });
    const wrongConfig = path.join(root, "wrong-config.json"); fs.writeFileSync(wrongConfig, JSON.stringify({ auths: { [host]: { auth: Buffer.from(`${username}:wrong-owned-password`).toString("base64") } } }), { flag: "wx", mode: 0o600 });
    const config = path.join(root, "config.yml");
    fs.writeFileSync(config, `version: 0.1\nlog:\n  level: error\n  accesslog:\n    disabled: true\nstorage:\n  filesystem:\n    rootdirectory: ${JSON.stringify(path.join(root, "storage"))}\nhttp:\n  addr: 127.0.0.1:${backend}\n  relativeurls: true\n  draintimeout: 15s\n  tls:\n    certificate: ${JSON.stringify(path.join(root, "server.pem"))}\n    key: ${JSON.stringify(path.join(root, "server.key"))}\nauth:\n  htpasswd:\n    realm: corb-owned-fixture\n    path: ${JSON.stringify(path.join(root, "htpasswd"))}\n`, { flag: "wx", mode: 0o600 });
    service = runOwnedProcess(binary, ["serve", config], { env: { PATH: process.env.PATH, OTEL_TRACES_EXPORTER: "none" }, signal: controller.signal, timeoutMs: 55 * 60_000, graceMs: 20_000 });
    const probe = () => new Promise<number>((resolve) => {
      const req = https.get(`https://${host}/v2/`, { ca, timeout: 1000 }, (response) => { response.resume(); response.on("end", () => resolve(response.statusCode!)); });
      req.on("error", () => resolve(0)); req.on("timeout", () => { req.destroy(); resolve(0); });
    });
    const deadline = Date.now() + 15_000;
    while (await probe() !== 401) { if (Date.now() >= deadline) throw Error("owned authenticated HTTPS registry did not start"); await sleep(100); }
    return { host, root, caFile, registryConfig, emptyConfig, wrongConfig, requests, close, markers: markers.values, setFault(value: typeof fault) { fault = value; } };
  } catch (error) {
    try { await close(); } catch (cleanup) { throw new AggregateError([error, cleanup], "registry setup and cleanup failed"); }
    throw error;
  }
}
