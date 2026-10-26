import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import https from "node:https";
import { execFileSync } from "node:child_process";
import { afterAll, beforeAll, expect, it, vi } from "vitest";
import { downloadInput } from "../../../src/layer/download.ts";
let directory: string;
let server: https.Server;
let origin: string;
const requests: string[] = [];
beforeAll(async () => {
  directory = fs.mkdtempSync(path.join(os.tmpdir(), "corb-https-download-"));
  execFileSync("openssl", ["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", path.join(directory, "key"), "-out", path.join(directory, "cert"), "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost", "-days", "1"], { stdio: "ignore", timeout: 10000 });
  const cert = fs.readFileSync(path.join(directory, "cert"));
  server = https.createServer({ key: fs.readFileSync(path.join(directory, "key")), cert }, (request, response) => {
    requests.push(request.url!);
    if (request.url === "/redirect") { response.writeHead(302, { Location: "/bytes" }); response.end(); }
    else if (request.url === "/foreign") { response.writeHead(302, { Location: "https://unapproved.invalid/bytes" }); response.end(); }
    else if (request.url === "/plain") { response.writeHead(302, { Location: "http://localhost/bytes" }); response.end(); }
    else if (request.url === "/encoded") { response.writeHead(200, { "Content-Encoding": "gzip" }); response.end("compressed"); }
    else if (request.url === "/oversized") { response.writeHead(200); response.write("12345"); response.end("67890"); }
    else if (request.url === "/missing") { response.writeHead(404); response.end(); }
    else { expect(request.headers["accept-encoding"]).toBe("identity"); response.writeHead(200, { "Content-Length": "5" }); response.end("bytes"); }
  });
  await new Promise<void>((resolve) => server.listen(0, "localhost", resolve));
  origin = `https://localhost:${(server.address() as import("node:net").AddressInfo).port}`;
  const original = https.get;
  vi.spyOn(https, "get").mockImplementation(((url: URL, options: https.RequestOptions, callback: (response: import("node:http").IncomingMessage) => void) => original(url, { ...options, ca: cert }, callback)) as typeof https.get);
});
afterAll(async () => { vi.restoreAllMocks(); if (server !== undefined) { server.closeAllConnections(); await new Promise<void>((resolve) => server.close(() => resolve())); } if (directory !== undefined) fs.rmSync(directory, { recursive: true, force: true }); });
it("streams exact HTTPS bytes through a permitted port and relative redirect", async () => {
  const file = path.join(directory, "download"); await downloadInput(`${origin}/redirect`, file, ["localhost"], 100, 5);
  expect(fs.readFileSync(file, "utf8")).toBe("bytes"); expect(requests).toContain("/redirect"); expect(requests).toContain("/bytes");
});
it.each(["foreign", "plain", "encoded", "oversized", "missing"])("fails closed for %s and removes only owned partial output", async (route) => {
  const file = path.join(directory, route); await expect(downloadInput(`${origin}/${route}`, file, ["localhost"], 6)).rejects.toThrow(); expect(fs.existsSync(file)).toBe(false);
});
it("preserves an existing destination and sends no request", async () => {
  const file = path.join(directory, "unowned"); fs.writeFileSync(file, "keep"); const count = requests.length;
  await expect(downloadInput(`${origin}/bytes`, file, ["localhost"], 100)).rejects.toThrow(); expect(fs.readFileSync(file, "utf8")).toBe("keep"); expect(requests).toHaveLength(count);
});
