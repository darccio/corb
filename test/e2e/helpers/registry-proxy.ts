import type { ClientRequest, IncomingMessage, ServerResponse, RequestOptions } from "node:http";
import type { RegistryFault } from "./distribution.ts";

export interface RegistryRequest {
  method: string; path: string; status: number; authenticated: boolean; bytes: number;
  requestBytes: number; elapsedMs: number; bodyFinishedMs?: number; upstreamError?: string;
}
export function registryProxy(options: {
  connect: (options: RequestOptions, response: (response: IncomingMessage) => void) => ClientRequest;
  backendOrigin: string; authorization: string; requests: RegistryRequest[]; idleTimeoutMs?: number;
  location?: (value: string) => void;
  fault: (method: string, pathname: string) => RegistryFault | undefined;
}) {
  const active = new Set<ClientRequest>();
  function handler(req: IncomingMessage, res: ServerResponse) {
    const pathname = req.url ?? "/"; const method = req.method ?? "GET"; const started = performance.now();
    const row: RegistryRequest = { method, path: new URL(pathname, "https://localhost").pathname, status: 0, authenticated: req.headers.authorization === options.authorization, bytes: 0, requestBytes: 0, elapsedMs: 0 };
    options.requests.push(row);
    const injected = options.fault(method, pathname);
    res.once("close", () => { row.elapsedMs = Math.round(performance.now() - started); });
    if (injected?.status !== undefined) { row.status = injected.status; res.writeHead(injected.status, { "Content-Type": "application/json" }); res.end('{"errors":[{"code":"UNKNOWN","message":"owned injected failure"}]}'); return; }
    const upstream = options.connect({ path: pathname, method, headers: req.headers, timeout: options.idleTimeoutMs ?? 120_000 }, (response) => {
      row.status = response.statusCode!;
      const headers = { ...response.headers };
      try { if (typeof headers.location === "string") options.location?.(headers.location); }
      catch { row.upstreamError = "marker-plan"; response.destroy(); res.destroy(); return; }
      if (typeof headers.location === "string") headers.location = headers.location.replace(options.backendOrigin, `https://${req.headers.host}`);
      response.on("error", () => { row.upstreamError ??= "response-error"; res.destroy(); });
      if (injected?.body !== undefined) {
        if (injected.body.length > 1024 * 1024) { response.destroy(); res.destroy(); return; }
        headers["content-length"] = String(injected.body.length);
        res.writeHead(row.status, headers); row.bytes = injected.body.length; res.end(injected.body); response.resume();
      } else if (injected?.truncate !== undefined) {
        let remaining = injected.truncate;
        if (!Number.isSafeInteger(remaining) || remaining < 0 || remaining > 1024 * 1024) { response.destroy(); res.destroy(); return; }
        headers.connection = "close"; res.writeHead(row.status, headers);
        response.on("data", (chunk: Buffer) => { const part = chunk.subarray(0, remaining); remaining -= part.length; row.bytes += part.length; res.write(part); });
        response.on("end", () => res.end());
      } else {
        res.writeHead(row.status, headers); response.on("data", (chunk: Buffer) => { row.bytes += chunk.length; }); response.pipe(res);
      }
    });
    active.add(upstream); upstream.once("close", () => active.delete(upstream));
    req.on("data", (chunk: Buffer) => { row.requestBytes += chunk.length; });
    req.once("aborted", () => { row.upstreamError ??= "client-aborted"; upstream.destroy(); });
    res.once("close", () => { if (!res.writableFinished) upstream.destroy(); });
    upstream.once("finish", () => { row.bodyFinishedMs = Math.round(performance.now() - started); });
    upstream.on("timeout", () => { row.upstreamError = "idle-timeout"; upstream.destroy(Error("owned registry upstream timeout")); });
    upstream.on("error", () => { row.upstreamError ??= "request-error"; row.status = 502; res.destroy(); });
    req.pipe(upstream);
  }
  async function close() {
    await Promise.all([...active].map((request) => new Promise<void>((resolve, reject) => {
      const timer = setTimeout(() => reject(Error("owned registry upstream did not close")), 5000);
      request.once("close", () => { clearTimeout(timer); resolve(); }); request.destroy();
    })));
  }
  return { handler, close };
}
