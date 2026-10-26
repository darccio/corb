import type { VM } from "@earendil-works/gondolin";
import { describe, expect, it, vi } from "vitest";
import { configureTrustedTls } from "../../../src/vm/tls.ts";

function fixture() {
  let resolve: (context: object) => void = () => {};
  let reject: (error: Error) => void = () => {};
  const context = new Promise<object>((yes, no) => { resolve = yes; reject = no; });
  const calls: unknown[] = [];
  const session = { syntheticHostname: "github.com", dstIP: "198.19.0.1" };
  const socket = { setKeyCert: vi.fn(() => calls.push("context")) };
  const backend = {
    maxTcpPendingWriteBytes: 64,
    tcpSessions: new Map([["connection", session]]),
    getTlsContextAsync: vi.fn(() => context),
    ensureTlsSession: vi.fn((_key, target) => { target.tls = { socket }; return target.tls; }),
    handleTlsData: vi.fn((_key, _session, data) => calls.push(data.toString())),
    abortTcpSession: vi.fn(),
  };
  const vm = { server: { network: backend } } as unknown as VM;
  return { vm, backend, session, socket, resolve, reject, calls };
}
const settle = async () => { await new Promise((resolve) => setTimeout(resolve, 0)); };
describe("trusted TLS context preparation", () => {
  it("sets the synthetic host context before ordered handshake bytes", async () => {
    const { vm, backend, session, resolve, calls } = fixture();
    configureTrustedTls(vm);
    backend.handleTlsData("connection", session, Buffer.from("first"));
    backend.handleTlsData("connection", session, Buffer.from("second"));
    expect(calls).toEqual([]);
    resolve({});
    await settle();
    expect(backend.getTlsContextAsync).toHaveBeenCalledExactlyOnceWith("github.com");
    expect(calls).toEqual(["context", "first", "second"]);
    backend.handleTlsData("connection", session, Buffer.from("third"));
    expect(calls.at(-1)).toBe("third");
  });
  it("does not wrap a backend twice", async () => {
    const { vm, backend, session, resolve, calls } = fixture();
    configureTrustedTls(vm);
    const handler = backend.handleTlsData;
    configureTrustedTls(vm);
    expect(backend.handleTlsData).toBe(handler);
    backend.handleTlsData("connection", session, Buffer.from("first"));
    resolve({});
    await settle();
    expect(calls).toEqual(["context", "first"]);
  });
  it("fails the connection when context preparation fails", async () => {
    const { vm, backend, session, reject, calls } = fixture();
    configureTrustedTls(vm);
    backend.handleTlsData("connection", session, Buffer.from("first"));
    reject(new Error("certificate unavailable"));
    await settle();
    expect(backend.abortTcpSession).toHaveBeenCalledWith("connection", session, expect.stringContaining("certificate unavailable"));
    expect(calls).toEqual([]);
  });
  it("does not create a socket after VM cleanup removes the session", async () => {
    const { vm, backend, session, resolve } = fixture();
    configureTrustedTls(vm);
    backend.handleTlsData("connection", session, Buffer.from("first"));
    backend.tcpSessions.clear();
    resolve({});
    await settle();
    expect(backend.ensureTlsSession).not.toHaveBeenCalled();
  });
  it("bounds queued bytes while certificate preparation is pending", () => {
    const { vm, backend, session } = fixture();
    configureTrustedTls(vm);
    backend.handleTlsData("connection", session, Buffer.alloc(32));
    backend.handleTlsData("connection", session, Buffer.alloc(33));
    expect(backend.abortTcpSession).toHaveBeenCalledWith("connection", session, "TLS context pending buffer exceeded");
    expect(backend.ensureTlsSession).not.toHaveBeenCalled();
  });
  it("rejects unsupported SDK shapes instead of omitting the repair", () => {
    expect(() => configureTrustedTls({} as VM)).toThrow(/backend is unavailable/);
  });
});
