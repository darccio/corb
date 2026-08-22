// Host-side local streaming test server for M0.1.
//
// Sends a chunked response with deliberate delays between chunks (mimicking
// SSE streaming from a model API) so we can prove whether Gondolin's egress
// mediation preserves incremental delivery end-to-end, independent of
// Anthropic's own infrastructure.
//
// NOTE ON BIND ADDRESS: a first attempt bound this to 127.0.0.1 (host
// loopback) and had the guest fetch "http(s)://127.0.0.1:<port>/stream", per
// the original plan. That failed with ECONNREFUSED from inside the guest —
// because a literal 127.0.0.1 destination is routed by the GUEST's own
// kernel to the guest's own loopback device and never traverses the
// virtio-net path Gondolin mediates, so it can never reach the host's
// loopback at all (confirmed: the host-side access log showed zero
// connection attempts during the failing guest run). So this server instead
// binds to the host's real LAN-facing interface address (e.g. 192.168.1.x)
// passed as --bind, which the guest reaches through Gondolin's virtual
// gateway/NAT like any other network destination. Still no /etc/hosts edit,
// no sudo, no system network config change — just a socket bind.
//
// Usage: node stream-server.mjs <port> --bind <hostIp> [--http]
//   --http forces plain HTTP instead of HTTPS+self-signed-cert (fallback
//   documented in the task brief in case the host TLS stack rejects the
//   self-signed cert on the host->upstream leg).

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const port = Number(process.argv[2] || 8443);
const useHttp = process.argv.includes("--http");
const bindIdx = process.argv.indexOf("--bind");
const bindHost = bindIdx !== -1 ? process.argv[bindIdx + 1] : "127.0.0.1";

const CHUNKS = ["chunk-0\n", "chunk-1\n", "chunk-2\n", "chunk-3\n", "chunk-4\n"];
const DELAY_MS = 400;

function handler(req, res) {
  if (req.url !== "/stream") {
    res.writeHead(404).end("not found\n");
    return;
  }
  res.writeHead(200, {
    "Content-Type": "text/event-stream",
    "Transfer-Encoding": "chunked",
    "Cache-Control": "no-cache",
  });
  console.error(`[server] connection from ${req.socket.remoteAddress}:${req.socket.remotePort} at ${new Date().toISOString()}`);
  let i = 0;
  const timer = setInterval(() => {
    if (i >= CHUNKS.length) {
      clearInterval(timer);
      res.end();
      return;
    }
    const payload = `data: ${CHUNKS[i]}`;
    res.write(payload);
    console.error(`[server] wrote chunk ${i} at ${new Date().toISOString()}`);
    i++;
  }, DELAY_MS);
}

let server;
if (useHttp) {
  const http = await import("node:http");
  server = http.createServer(handler);
} else {
  const https = await import("node:https");
  const key = fs.readFileSync(path.join(__dirname, "key.pem"));
  const cert = fs.readFileSync(path.join(__dirname, "cert.pem"));
  server = https.createServer({ key, cert }, handler);
}

server.listen(port, bindHost, () => {
  console.error(`[server] listening on ${bindHost}:${port} (${useHttp ? "http" : "https"})`);
});
