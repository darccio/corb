import { createRequire } from "node:module";
import type { SecureContext, TLSSocket } from "node:tls";
import type { VM } from "@earendil-works/gondolin";

interface TlsSession {
  syntheticHostname: string | null;
  dstIP: string;
  tls?: { socket: TLSSocket };
}
interface TlsBackend {
  tcpSessions: Map<string, TlsSession>;
  maxTcpPendingWriteBytes: number;
  handleTlsData(key: string, session: TlsSession, data: Buffer): void;
  ensureTlsSession(key: string, session: TlsSession): { socket: TLSSocket };
  getTlsContextAsync(hostname: string): Promise<SecureContext>;
  abortTcpSession(key: string, session: TlsSession, reason: string): void;
}
const configured = new WeakSet<object>();
const require = createRequire(import.meta.url);

/** Prepare the pinned SDK's SNI context before it parses a resumed handshake. */
export function configureTrustedTls(vm: VM): void {
  const version = (require("@earendil-works/gondolin/package.json") as { version: string }).version;
  if (version !== "0.12.0") throw new Error(`Corb TLS compatibility requires review for Gondolin ${version}`);
  const server = (vm as unknown as { server?: { network?: TlsBackend | null } }).server;
  if (!server || server.network === undefined) throw new Error("Gondolin TLS backend is unavailable");
  const backend = server.network;
  if (backend === null || configured.has(backend)) return;
  for (const method of ["handleTlsData", "ensureTlsSession", "getTlsContextAsync", "abortTcpSession"] as const) {
    if (typeof backend[method] !== "function") throw new Error(`Gondolin TLS backend lacks ${method}`);
  }
  if (!(backend.tcpSessions instanceof Map) || !Number.isFinite(backend.maxTcpPendingWriteBytes) || backend.maxTcpPendingWriteBytes <= 0) {
    throw new Error("Gondolin TLS backend has no bounded session buffer");
  }
  const original = backend.handleTlsData.bind(backend);
  const waiting = new WeakMap<TlsSession, { chunks: Buffer[]; bytes: number }>();
  backend.handleTlsData = (key, session, data) => {
    if (session.tls) return original(key, session, data);
    const pending = waiting.get(session);
    if (pending) {
      pending.bytes += data.length;
      if (pending.bytes > backend.maxTcpPendingWriteBytes) {
        waiting.delete(session);
        backend.abortTcpSession(key, session, "TLS context pending buffer exceeded");
      } else pending.chunks.push(data);
      return;
    }
    if (data.length > backend.maxTcpPendingWriteBytes) {
      backend.abortTcpSession(key, session, "TLS context pending buffer exceeded");
      return;
    }
    const chunks = [data];
    waiting.set(session, { chunks, bytes: data.length });
    void backend.getTlsContextAsync(session.syntheticHostname ?? session.dstIP).then((context) => {
      if (backend.tcpSessions.get(key) !== session || !waiting.has(session)) return;
      backend.ensureTlsSession(key, session).socket.setKeyCert(context);
      waiting.delete(session);
      for (const chunk of chunks) original(key, session, chunk);
    }).catch((error: unknown) => {
      if (backend.tcpSessions.get(key) !== session || !waiting.has(session)) return;
      waiting.delete(session);
      backend.abortTcpSession(key, session, `TLS context preparation failed: ${String(error)}`);
    });
  };
  configured.add(backend);
}
