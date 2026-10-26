import http from "node:http";
import type net from "node:net";
import { afterEach, expect, it } from "vitest";
import { registryProxy, type RegistryRequest } from "../../../e2e/helpers/registry-proxy.ts";
const cleanups: Array<() => Promise<void>> = [];
afterEach(async () => { for (const close of cleanups.splice(0).reverse()) await close(); });
async function listen(server: http.Server) {
  await new Promise<void>((resolve, reject) => { server.once("error", reject); server.listen(0, "127.0.0.1", resolve); });
  cleanups.push(async () => { server.closeAllConnections(); await new Promise<void>((resolve) => server.close(() => resolve())); });
  return (server.address() as net.AddressInfo).port;
}
it.each([{ idle: 2500, expected: 201 }, { idle: 250, expected: 0 }])("bounds a delayed post-body commit with idle=$idle", async ({ idle, expected }) => {
  const bytes = Buffer.alloc(1024 * 1024, 7); let received = 0;
  const backend = http.createServer((req, res) => {
    req.on("data", (chunk: Buffer) => { received += chunk.length; });
    req.on("end", () => { const timer = setTimeout(() => { res.writeHead(201); res.end(); }, 1000); res.once("close", () => clearTimeout(timer)); });
  });
  const port = await listen(backend); const rows: RegistryRequest[] = [];
  const proxy = registryProxy({ connect: (options, response) => http.request({ ...options, hostname: "127.0.0.1", port }, response), backendOrigin: `http://127.0.0.1:${port}`, authorization: "private", requests: rows, idleTimeoutMs: idle, fault: () => undefined });
  const front = await listen(http.createServer(proxy.handler)); cleanups.push(proxy.close);
  const status = await new Promise<number>((resolve) => {
    const req = http.request({ hostname: "127.0.0.1", port: front, path: "/v2/bases/blobs/uploads/id?_state=private", method: "PUT", headers: { authorization: "private", "content-length": bytes.length } }, (res) => { res.resume(); res.once("end", () => resolve(res.statusCode!)); });
    req.on("error", () => resolve(0)); req.end(bytes);
  });
  expect(status).toBe(expected); expect(received).toBe(bytes.length); expect(rows[0]!.requestBytes).toBe(bytes.length); expect(rows[0]!.bodyFinishedMs).toBeTypeOf("number"); expect(rows[0]!.authenticated).toBe(true); expect(rows[0]!.path).toBe("/v2/bases/blobs/uploads/id");
  if (expected === 0) { expect(rows[0]!.upstreamError).toBe("idle-timeout"); expect(rows[0]!.status).toBe(502); } else expect(rows[0]!.upstreamError).toBeUndefined();
}, 5000);
