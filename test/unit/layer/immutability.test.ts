import fs from "node:fs";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { protectedAncestors, compareFiles, assertSdkDirectoryChain } from "../../../image/helpers/layer.mjs";
const nodes = new Map<string, { uid: number; gid: number; mode: number; link?: boolean }>();
beforeEach(() => {
  nodes.clear(); for (const name of ["/", "/usr", "/usr/local", "/usr/local/bin", "/opt", "/opt/corb", "/opt/corb/toolchains", "/opt/corb/toolchains/go"]) nodes.set(name, { uid: 0, gid: 0, mode: name.endsWith("/go") ? 0o555 : 0o755 });
  vi.spyOn(fs, "lstatSync").mockImplementation(((name: string) => { const node = nodes.get(name)!; return { ...node, isDirectory: () => !node.link, isFile: () => false, isSymbolicLink: () => node.link === true }; }) as typeof fs.lstatSync);
  vi.spyOn(fs, "realpathSync").mockImplementation(((name: string) => nodes.get(name)?.link ? "/outside" : name) as typeof fs.realpathSync);
});
afterEach(() => { vi.restoreAllMocks(); });
it("binds security-tool parent modes and ownership to the original baseline", () => {
  const baseline = protectedAncestors(["/usr/local/bin/git", "/usr/local/bin/dropcap"]);
  expect(baseline.map((row: { path: string }) => row.path)).toEqual(["/", "/usr", "/usr/local", "/usr/local/bin"]);
  expect(() => compareFiles(baseline)).not.toThrow(); nodes.get("/usr/local/bin")!.mode = 0o777;
  expect(() => compareFiles(baseline)).toThrow("protected file changed /usr/local/bin");
});
it.each(["/opt/corb/toolchains/go", "/opt/corb/toolchains", "/opt/corb", "/opt"])("rejects a writable SDK root or ancestor %s", (name) => {
  expect(() => assertSdkDirectoryChain("/opt/corb/toolchains/go")).not.toThrow(); nodes.get(name)!.mode = 0o777; expect(() => assertSdkDirectoryChain("/opt/corb/toolchains/go")).toThrow("writable or unsafe");
});
it("requires the normalized SDK root mode even when ownership remains root", () => { nodes.get("/opt/corb/toolchains/go")!.mode = 0o755; expect(() => assertSdkDirectoryChain("/opt/corb/toolchains/go")).toThrow("root mode changed"); });
it("rejects ownership changes and symlinks along the SDK chain", () => { nodes.get("/opt/corb")!.uid = 1000; expect(() => assertSdkDirectoryChain("/opt/corb/toolchains/go")).toThrow("unsafe"); nodes.get("/opt/corb")!.uid = 0; nodes.get("/opt/corb")!.link = true; expect(() => assertSdkDirectoryChain("/opt/corb/toolchains/go")).toThrow("unsafe"); });
