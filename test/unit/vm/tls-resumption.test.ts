import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import net from "node:net";
import tls from "node:tls";
import { Duplex } from "node:stream";
import { execFileSync } from "node:child_process";
import type { VM } from "@earendil-works/gondolin";
import { expect, it } from "vitest";
import { configureTrustedTls } from "../../../src/vm/tls.ts";

it("completes verified TLS 1.3 requests when a client offers a previous SNI session", async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "corb-tls-regression-"));
  const certPath = path.join(dir, "cert.crt");
  const keyPath = path.join(dir, "key.key");
  execFileSync("openssl", ["req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes", "-days", "1",
    "-subj", "/CN=corb-test.invalid", "-addext", "subjectAltName=DNS:corb-test.invalid", "-keyout", keyPath, "-out", certPath],
  { stdio: "ignore", timeout: 10_000 });
  const cert = fs.readFileSync(certPath);
  const context = tls.createSecureContext({ key: fs.readFileSync(keyPath), cert });
  const errors: Error[] = [];
  type Session = { syntheticHostname: string; dstIP: string; stream: Duplex; tls?: { socket: tls.TLSSocket } };
  const backend = {
    maxTcpPendingWriteBytes: 4 * 1024 * 1024,
    tcpSessions: new Map<string, Session>(),
    getTlsContextAsync: async () => context,
    ensureTlsSession(_key: string, session: Session) {
      if (!session.tls) {
        const socket = new tls.TLSSocket(session.stream, {
          isServer: true, ALPNProtocols: ["http/1.1"], SNICallback: (_name, callback) => callback(null, context),
        });
        socket.on("data", () => socket.end("response"));
        socket.on("error", (error) => errors.push(error));
        session.tls = { socket };
      }
      return session.tls;
    },
    handleTlsData(key: string, session: Session, data: Buffer) {
      this.ensureTlsSession(key, session);
      session.stream.push(data);
    },
    abortTcpSession(_key: string, session: Session) { session.stream.destroy(); },
  };
  configureTrustedTls({ server: { network: backend } } as unknown as VM);
  const connections = new Set<net.Socket>();
  let count = 0;
  const server = net.createServer((socket) => {
    connections.add(socket);
    const key = String(++count);
    const stream = new Duplex({
      read() {},
      write(chunk, encoding, callback) { socket.write(chunk, encoding, callback); },
      final(callback) { socket.end(callback); },
    });
    const session: Session = { syntheticHostname: "corb-test.invalid", dstIP: "127.0.0.1", stream };
    backend.tcpSessions.set(key, session);
    socket.on("data", (data) => backend.handleTlsData(key, session, data));
    socket.on("end", () => stream.push(null));
    socket.on("close", () => { backend.tcpSessions.delete(key); connections.delete(socket); stream.destroy(); });
  });
  try {
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    let ticket: Buffer | undefined;
    for (const attempt of [0, 1]) {
      await new Promise<void>((resolve, reject) => {
        const socket = tls.connect({
          host: "127.0.0.1", port: (server.address() as net.AddressInfo).port,
          servername: "corb-test.invalid", ca: cert, minVersion: "TLSv1.3", maxVersion: "TLSv1.3",
          ALPNProtocols: ["h2", "http/1.1"], ...(attempt ? { session: ticket } : {}),
        }, () => {
          try { expect(socket.authorized).toBe(true); expect(socket.getProtocol()).toBe("TLSv1.3"); socket.write("request"); }
          catch (error) { reject(error); socket.destroy(); }
        });
        socket.on("session", (value) => { ticket = value; });
        socket.on("data", (data) => expect(data.toString()).toBe("response"));
        socket.on("error", reject);
        socket.on("close", () => resolve());
        socket.setTimeout(5000, () => socket.destroy(new Error("TLS regression timed out")));
      });
      expect(ticket).toBeDefined();
    }
    expect(errors).toEqual([]);
  } finally {
    for (const socket of connections) socket.destroy();
    await new Promise<void>((resolve) => server.close(() => resolve()));
    fs.rmSync(dir, { recursive: true, force: true });
  }
}, 15_000);
