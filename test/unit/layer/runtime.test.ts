import fs from "node:fs";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { restoreRuntimeDirs } from "../../../image/helpers/layer.mjs";
const nodes = new Map<string, { type: string; uid: number; gid: number; mode: number; target?: string }>();
let passwd: string;
let groups: string;
let mounts: string;
let changed: string[];
beforeEach(() => {
  passwd = "root:x:0:0:root:/root:/bin/sh\nagent:x:1000:1000:agent:/home/agent:/bin/sh\nredis:x:101:101:redis:/var/lib/redis:/sbin/nologin\n";
  groups = "root:x:0:\nagent:x:1000:\nredis:x:101:\n"; mounts = "1 0 0:1 / / rw - ext4 none rw\n2 1 0:2 / /run rw - tmpfs tmpfs rw\n";
  nodes.clear(); for (const path of ["/", "/run", "/var", "/var/log"]) nodes.set(path, { type: "directory", uid: 0, gid: 0, mode: 0o755 }); changed = [];
  vi.spyOn(fs, "readFileSync").mockImplementation(((file: string) => file === "/etc/passwd" ? passwd : file === "/etc/group" ? groups : file === "/proc/self/mountinfo" ? mounts : "") as typeof fs.readFileSync);
  vi.spyOn(fs, "lstatSync").mockImplementation(((path: string) => { const node = nodes.get(path); if (!node) throw Object.assign(new Error("missing"), { code: "ENOENT" }); return { ...node, isDirectory: () => node.type === "directory", isSymbolicLink: () => node.type === "link", isFile: () => node.type === "file" }; }) as typeof fs.lstatSync);
  vi.spyOn(fs, "realpathSync").mockImplementation(((path: string) => nodes.get(path)?.target ?? path) as typeof fs.realpathSync);
  vi.spyOn(fs, "mkdirSync").mockImplementation(((path: string) => { nodes.set(path, { type: "directory", uid: 0, gid: 0, mode: 0o755 }); }) as typeof fs.mkdirSync);
  vi.spyOn(fs, "chownSync").mockImplementation(((path: string, uid: number, gid: number) => { changed.push(path); Object.assign(nodes.get(path)!, { uid, gid }); }) as typeof fs.chownSync);
  vi.spyOn(fs, "chmodSync").mockImplementation(((path: string, mode: number) => { Object.assign(nodes.get(path)!, { mode }); }) as typeof fs.chmodSync);
});
afterEach(() => { vi.restoreAllMocks(); });
const plan = [{ path: "/run/redis", mode: "0750", owner: "redis", group: "redis" }];
it("resolves named accounts and restores only the declared directory", () => {
  nodes.set("/run/redis", { type: "directory", uid: 0, gid: 0, mode: 0o700 }); nodes.set("/run/redis/child", { type: "file", uid: 0, gid: 0, mode: 0o600 });
  const mapping = restoreRuntimeDirs(plan); expect(mapping[0]).toMatchObject({ uid: 101, gid: 101 }); expect(changed).toEqual(["/run/redis"]); expect(nodes.get("/run/redis/child")?.uid).toBe(0);
  expect(restoreRuntimeDirs(plan, mapping)).toEqual(mapping);
});
it.each(["link", "file"])("rejects a %s at the directory or its parent", (type) => {
  nodes.set("/run/redis", { type, uid: 0, gid: 0, mode: 0o755, target: "/outside" }); expect(() => restoreRuntimeDirs(plan)).toThrow("unsafe runtime parent");
  nodes.delete("/run/redis"); nodes.set("/run", { type, uid: 0, gid: 0, mode: 0o755, target: "/outside" }); expect(() => restoreRuntimeDirs(plan)).toThrow("unsafe runtime parent");
});
it.each(["/run", "/run/../etc", "/run/corb/credentials", "/run/gondolin/a", "/var/log/../bad"])("rejects forbidden or malformed path %s", (path) => { expect(() => restoreRuntimeDirs([{ ...plan[0], path }])).toThrow(); });
it("rejects mount crossings", () => { mounts += "3 2 0:3 / /run/redis rw - fuse fuse rw\n"; expect(() => restoreRuntimeDirs(plan)).toThrow("mount"); });
it("rejects missing, duplicate and changed named account IDs", () => {
  expect(() => restoreRuntimeDirs([{ ...plan[0], owner: "missing" }])).toThrow("missing");
  passwd += "alias:x:101:101:alias:/none:/sbin/nologin\n"; expect(() => restoreRuntimeDirs(plan)).toThrow("ambiguous");
  passwd = passwd.replace(/alias:.+\n/, ""); const expected = restoreRuntimeDirs(plan); passwd = passwd.replace("redis:x:101:", "redis:x:102:"); expect(() => restoreRuntimeDirs(plan, expected)).toThrow("mapping changed");
});
