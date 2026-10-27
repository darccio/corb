import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { FsRpcService, RealFSProvider, ReadonlyProvider } from "@earendil-works/gondolin";
import { withGlobPolicy, type GlobPolicyDenyEvent } from "../../../src/vfs/glob-policy.ts";
import type { GlobRule } from "../../../src/vfs/policy.ts";
import { builtinGitRules } from "../../../src/config/gitprotect.ts";
import { toGlobRules } from "../../../src/vm/session.ts";
import { FakeVirtualProvider } from "../../fakes/provider.ts";

const rules: GlobRule[] = [{ glob: "config*", mode: "copy-on-write", reason: "session config" }];

function fixture(customRules = rules) {
  const backend = new FakeVirtualProvider();
  backend.writeFileSync("/config", "original");
  const events: GlobPolicyDenyEvent[] = [];
  const wrapped = withGlobPolicy(backend, { rules: customRules, onDeny: (event) => events.push(event) });
  return { backend, wrapped, events };
}

describe("copy-on-write", () => {
  it("reads its own copy and metadata while preserving the backend", async () => {
    const { backend, wrapped, events } = fixture();
    await wrapped.writeFile("/config", "new");
    expect(await wrapped.readFile("/config", "utf8")).toBe("new");
    expect((await wrapped.stat("/config")).size).toBe(3);
    expect((await wrapped.lstat("/config")).size).toBe(3);
    expect(await backend.readFile("/config", "utf8")).toBe("original");
    expect(events.at(-1)?.reason).toContain("dropped when the session ends");
    expect(events.at(-1)?.rule?.reason).toBe("session config");
  });

  it("copies existing bytes before append, r+ writes, and truncate", async () => {
    const { backend, wrapped } = fixture();
    await wrapped.appendFile("/config", "!");
    const handle = await wrapped.open("/config", "r+");
    await handle.write(Buffer.from("NEW"), 0, 3, 0);
    await handle.close();
    expect(await wrapped.readFile("/config", "utf8")).toBe("NEWginal!");
    await wrapped.truncate("/config", 5);
    expect(await wrapped.readFile("/config", "utf8")).toBe("NEWgi");
    expect(await backend.readFile("/config", "utf8")).toBe("original");
  });

  it("creates, lists, renames and unlinks a config lock as one private namespace", async () => {
    const { backend, wrapped } = fixture();
    await wrapped.writeFile("/config.lock", "replacement");
    expect(await wrapped.readdir("/")).toContain("config.lock");
    expect((await wrapped.readdir("/", { withFileTypes: true })).some((entry: any) => entry.name === "config.lock" && entry.isFile())).toBe(true);
    await wrapped.rename("/config.lock", "/config");
    expect(await wrapped.readFile("/config", "utf8")).toBe("replacement");
    expect(await wrapped.exists("/config.lock")).toBe(false);
    expect(await wrapped.readdir("/")).toEqual(["config"]);
    await wrapped.unlink("/config");
    await expect(wrapped.readFile("/config")).rejects.toMatchObject({ code: "ENOENT" });
    await expect(wrapped.stat("/config")).rejects.toMatchObject({ code: "ENOENT" });
    await expect(wrapped.access("/config")).rejects.toMatchObject({ code: "ENOENT" });
    expect(await wrapped.readdir("/")).toEqual([]);
    expect(await backend.readFile("/config", "utf8")).toBe("original");
    expect(backend.existsSync("/config.lock")).toBe(false);
  });

  it("reuses a removed lock and excludes competing lock creators", async () => {
    const { backend, wrapped } = fixture();
    const attempts = await Promise.allSettled([wrapped.open("/config.lock", "wx"), wrapped.open("/config.lock", "wx")]);
    expect(attempts.map((result) => result.status).sort()).toEqual(["fulfilled", "rejected"]);
    const winner = attempts.find((result) => result.status === "fulfilled") as PromiseFulfilledResult<any>;
    await winner.value.close();
    for (let count = 0; count < 3; count += 1) {
      await wrapped.writeFile("/config.lock", `version-${count}`);
      await wrapped.rename("/config.lock", "/config");
      expect(await wrapped.readFile("/config", "utf8")).toBe(`version-${count}`);
      expect(await wrapped.exists("/config.lock")).toBe(false);
    }
    expect(await backend.readFile("/config", "utf8")).toBe("original");
  });

  it("renames and removes host entries without deleting their host counterparts", async () => {
    const { backend, wrapped } = fixture();
    await wrapped.rename("/config", "/config.saved");
    expect(await wrapped.exists("/config")).toBe(false);
    expect(await wrapped.readFile("/config.saved", "utf8")).toBe("original");
    await wrapped.unlink("/config.saved");
    await wrapped.writeFile("/config", "private");
    expect(await wrapped.readFile("/config", "utf8")).toBe("private");
    expect(backend.readFileSync("/config", "utf8")).toBe("original");
    expect(backend.existsSync("/config.saved")).toBe(false);
    const fresh = withGlobPolicy(backend, { rules, onDeny: () => {} });
    await fresh.unlink("/config");
    expect(await fresh.exists("/config")).toBe(false);
    expect(backend.readFileSync("/config", "utf8")).toBe("original");
  });

  it("applies the same namespace to synchronous operations and copying", () => {
    const { backend, wrapped } = fixture();
    wrapped.copyFileSync("/config", "/config.copy");
    expect(wrapped.readFileSync("/config.copy", "utf8")).toBe("original");
    wrapped.appendFileSync("/config.copy", "!");
    wrapped.renameSync("/config.copy", "/config");
    wrapped.truncateSync("/config", 4);
    expect(wrapped.readFileSync("/config", "utf8")).toBe("orig");
    wrapped.accessSync("/config", fs.constants.W_OK);
    expect(wrapped.statSync("/config").size).toBe(4);
    wrapped.unlinkSync("/config");
    expect(wrapped.existsSync("/config")).toBe(false);
    expect(() => wrapped.lstatSync("/config")).toThrow(/ENOENT/);
    wrapped.writeFileSync("/config", "reborn");
    expect(wrapped.readFileSync("/config", "utf8")).toBe("reborn");
    expect(backend.readFileSync("/config", "utf8")).toBe("original");
  });

  it.each(["rename", "link"] as const)("rejects %s across the covered boundary in both directions", async (operation) => {
    const { backend, wrapped } = fixture();
    backend.writeFileSync("/ordinary", "keep");
    await expect(wrapped[operation]("/config", "/escaped")).rejects.toMatchObject({ code: "EXDEV" });
    await expect(wrapped[operation]("/ordinary", "/config.lock")).rejects.toMatchObject({ code: "EXDEV" });
    expect(backend.readFileSync("/ordinary", "utf8")).toBe("keep");
    expect(backend.readFileSync("/config", "utf8")).toBe("original");
    expect(backend.existsSync("/escaped")).toBe(false);
    expect(backend.existsSync("/config.lock")).toBe(false);
  });

  it("keeps in-memory hard links coherent without creating a host alias", async () => {
    const { backend, wrapped } = fixture();
    await wrapped.link("/config", "/config.link");
    await wrapped.appendFile("/config.link", "!");
    expect(await wrapped.readFile("/config", "utf8")).toBe("original!");
    expect(backend.existsSync("/config.link")).toBe(false);
    expect(backend.readFileSync("/config", "utf8")).toBe("original");
  });

  it("keeps open descriptors coherent through other writes, rename and unlink", async () => {
    const { backend, wrapped } = fixture();
    await wrapped.writeFile("/config.lock", "one");
    const reader = await wrapped.open("/config.lock", "r");
    const writer = await wrapped.open("/config.lock", "r+");
    expect((await wrapped.stat("/config.lock")).nlink).toBe(1);
    expect((await reader.stat()).nlink).toBe(1);
    await wrapped.appendFile("/config.lock", " two");
    expect(await reader.readFile("utf8")).toBe("one two");
    await writer.write(Buffer.from("ONE"), 0, 3, 0);
    expect(await reader.readFile("utf8")).toBe("ONE two");
    await wrapped.rename("/config.lock", "/config");
    expect((await reader.stat()).size).toBe(7);
    await wrapped.unlink("/config");
    expect(await reader.readFile("utf8")).toBe("ONE two");
    await writer.truncate(3);
    expect(await reader.readFile("utf8")).toBe("ONE");
    await expect(reader.write(Buffer.from("bad"), 0, 3, 0)).rejects.toMatchObject({ code: "EBADF" });
    await expect(reader.truncate(0)).rejects.toMatchObject({ code: "EBADF" });
    await writer.close();
    await reader.close();
    await expect(reader.readFile()).rejects.toMatchObject({ code: "EBADF" });
    expect(backend.readFileSync("/config", "utf8")).toBe("original");
  });

  it("keeps descriptors opened before the first write coherent and preserves replaced inodes", async () => {
    const { backend, wrapped } = fixture();
    const reader = await wrapped.open("/config", "r");
    await wrapped.appendFile("/config", " changed");
    expect(await reader.readFile("utf8")).toBe("original changed");
    await wrapped.writeFile("/config.lock", "replacement");
    await wrapped.rename("/config.lock", "/config");
    expect(await wrapped.readFile("/config", "utf8")).toBe("replacement");
    expect(await reader.readFile("utf8")).toBe("original changed");
    await reader.close();
    expect(backend.readFileSync("/config", "utf8")).toBe("original");
  });

  it("isolates mounts and sessions even when they share a backend", async () => {
    const { backend, wrapped } = fixture();
    const other = withGlobPolicy(backend, { rules, onDeny: () => {} });
    await wrapped.writeFile("/config", "private");
    expect(await other.readFile("/config", "utf8")).toBe("original");
    expect(await withGlobPolicy(backend, { rules, onDeny: () => {} }).readFile("/config", "utf8")).toBe("original");
  });

  it("routes resolved symlink aliases to the same copy", async () => {
    const { backend, wrapped } = fixture();
    backend.symlinkSync("config", "/alias");
    await wrapped.appendFile("/alias", "!");
    expect(await wrapped.readFile("/config", "utf8")).toBe("original!");
    expect(await wrapped.readFile("/alias", "utf8")).toBe("original!");
    expect(backend.readFileSync("/config", "utf8")).toBe("original");
  });

  it("protects a covered spelling that aliases an uncovered target", async () => {
    const { backend, wrapped, events } = fixture();
    backend.writeFileSync("/ordinary", "keep");
    backend.symlinkSync("ordinary", "/config.alias");
    await wrapped.writeFile("/config.alias", "private");
    expect(await wrapped.readFile("/config.alias", "utf8")).toBe("private");
    expect(backend.readFileSync("/ordinary", "utf8")).toBe("keep");
    expect(events.at(-1)?.rule?.reason).toBe("session config");
    expect(events.at(-1)?.path).toBe("config.alias");
    await wrapped.appendFile("/ordinary", "!");
    expect(await wrapped.readFile("/ordinary", "utf8")).toBe("private!");
    expect(events.at(-1)?.path).toBe("ordinary");
    expect(events.at(-1)?.op).toBe("write");
    expect(events.at(-1)?.rule?.reason).toBe("session config");
    expect(events.at(-1)?.reason).toContain("dropped when the session ends");
    expect(backend.readFileSync("/ordinary", "utf8")).toBe("keep");
  });

  it.each(["async", "sync"] as const)("isolates canonical audit paths across parallel aliases with a %s second call", async (secondMode) => {
    const { backend, wrapped, events } = fixture([
      { glob: "config", mode: "copy-on-write", reason: "first file" },
      { glob: "config.other", mode: "copy-on-write", reason: "second file" },
    ]);
    backend.writeFileSync("/config.other", "second");
    backend.symlinkSync("config", "/alias-a");
    backend.symlinkSync("config.other", "/alias-b");
    const first = wrapped.open("/alias-a", "r+");
    const second = secondMode === "sync" ? wrapped.openSync("/alias-b", "r+") : wrapped.open("/alias-b", "r+");
    const [firstHandle, secondHandle] = await Promise.all([first, second]);
    await firstHandle.write(Buffer.from("A"), 0, 1, 0);
    await secondHandle.write(Buffer.from("B"), 0, 1, 0);
    await firstHandle.close();
    await secondHandle.close();
    expect(events.map((event) => [event.path, event.op, event.rule?.reason]).sort()).toEqual([
      ["alias-a", "write", "first file"],
      ["alias-b", "write", "second file"],
    ]);
    expect(backend.readFileSync("/config", "utf8")).toBe("original");
    expect(backend.readFileSync("/config.other", "utf8")).toBe("second");
  });

  it("keeps both rename paths and copy destinations in their requested spelling", async () => {
    const { backend, wrapped, events } = fixture([{ glob: "private/config*", mode: "copy-on-write", reason: "private" }]);
    backend.mkdirSync("/private");
    backend.writeFileSync("/private/config", "host");
    backend.symlinkSync("private", "/shortcut");
    await wrapped.writeFile("/shortcut/config.lock", "guest");
    events.length = 0;
    await wrapped.rename("/shortcut/config.lock", "/shortcut/config");
    expect(events.map((event) => [event.path, event.op])).toEqual([
      ["shortcut/config.lock", "rename"],
      ["shortcut/config", "rename"],
    ]);
    await wrapped.copyFile("/config", "/shortcut/config.copy");
    expect(events.at(-1)?.path).toBe("shortcut/config.copy");
    expect(events.at(-1)?.op).toBe("copy-dest");
    expect(backend.readFileSync("/private/config", "utf8")).toBe("host");
    expect(backend.existsSync("/private/config.lock")).toBe(false);
    expect(backend.existsSync("/private/config.copy")).toBe(false);
  });

  it("preserves stricter first-match and resolved-target rules", async () => {
    const { backend, wrapped } = fixture([
      { glob: "secret", mode: "deny-read", reason: "secret" },
      { glob: "config.frozen", mode: "deny-write", reason: "frozen" },
      ...rules,
    ]);
    backend.writeFileSync("/secret", "secret");
    backend.symlinkSync("secret", "/config.alias");
    await expect(wrapped.readFile("/config.alias")).rejects.toMatchObject({ code: "EACCES" });
    await expect(wrapped.writeFile("/config.alias", "private")).rejects.toMatchObject({ code: "EACCES" });
    await expect(wrapped.writeFile("/config.frozen", "private")).rejects.toMatchObject({ code: "EACCES" });
    await wrapped.symlink("secret", "/config.newlink");
    await expect(wrapped.readFile("/config.newlink")).rejects.toMatchObject({ code: "EACCES" });
    await expect(wrapped.readlink("/config.newlink")).rejects.toMatchObject({ code: "EACCES" });
  });

  it("checks the final target again if a covered alias changes after the outer check", async () => {
    const { backend, wrapped, events } = fixture([
      { glob: "secret", mode: "deny-read", reason: "secret bytes" },
      ...rules,
    ]);
    backend.writeFileSync("/ordinary", "safe");
    backend.writeFileSync("/secret", "secret");
    backend.symlinkSync("ordinary", "/config.alias");
    const originalRealpath = backend.realpathSync.bind(backend);
    let first = true;
    backend.realpathSync = (target) => {
      const resolved = originalRealpath(target);
      if (target === "/config.alias" && first) {
        first = false;
        backend.unlinkSync("/config.alias");
        backend.symlinkSync("secret", "/config.alias");
      }
      return resolved;
    };
    await expect(wrapped.readFile("/config.alias")).rejects.toMatchObject({ code: "EACCES" });
    expect(events.at(-1)?.path).toBe("config.alias");
    expect(events.at(-1)?.reason).toContain("secret bytes");
    expect(backend.readFileSync("/secret", "utf8")).toBe("secret");
  });

  it.each([
    ["ordinary.alias", "writeFile"], ["copy.alias", "writeFile"],
    ["ordinary.alias", "copyFile"], ["copy.alias", "copyFile"],
  ] as const)("preserves shadow-write through %s for %s", async (alias, operation) => {
    const { backend, wrapped } = fixture([
      { glob: "copy*", mode: "copy-on-write", reason: "private" },
      { glob: "shadow", mode: "shadow-write", reason: "discard" },
    ]);
    backend.writeFileSync("/shadow", "host");
    backend.writeFileSync("/source", "guest");
    backend.symlinkSync("shadow", `/${alias}`);
    if (operation === "writeFile") await wrapped.writeFile(`/${alias}`, "guest");
    else await wrapped.copyFile("/source", `/${alias}`);
    expect(await wrapped.readFile(`/${alias}`, "utf8")).toBe("host");
    expect(await wrapped.readFile("/shadow", "utf8")).toBe("host");
    expect(backend.readFileSync("/shadow", "utf8")).toBe("host");
  });

  it.each(["ordinary.alias", "copy.alias"])("protects a shadow-write target after a late swap from %s", async (alias) => {
    const { backend, wrapped } = fixture([
      { glob: "copy*", mode: "copy-on-write", reason: "private" },
      { glob: "shadow", mode: "shadow-write", reason: "discard" },
    ]);
    backend.writeFileSync("/ordinary", "safe");
    backend.writeFileSync("/shadow", "host");
    backend.symlinkSync("ordinary", `/${alias}`);
    const originalRealpath = backend.realpathSync.bind(backend);
    let first = true;
    backend.realpathSync = (target) => {
      const resolved = originalRealpath(target);
      if (target === `/${alias}` && first) {
        first = false;
        backend.unlinkSync(`/${alias}`);
        backend.symlinkSync("shadow", `/${alias}`);
      }
      return resolved;
    };
    const result = wrapped.writeFile(`/${alias}`, "guest");
    if (alias === "copy.alias") await expect(result).rejects.toMatchObject({ code: "EACCES" });
    else await expect(result).resolves.toBeUndefined();
    expect(await wrapped.readFile(`/${alias}`, "utf8")).toBe("host");
    expect(backend.readFileSync("/shadow", "utf8")).toBe("host");
    expect(backend.readFileSync("/ordinary", "utf8")).toBe(alias === "copy.alias" ? "safe" : "guest");
  });

  it("supports covered directory creation, rename and removal", async () => {
    const { backend, wrapped } = fixture([{ glob: "private/**", mode: "copy-on-write", reason: "private" }]);
    backend.mkdirSync("/private");
    backend.mkdirSync("/private/old");
    backend.writeFileSync("/private/old/file", "host");
    await wrapped.mkdir("/private/new/nested", { recursive: true });
    await wrapped.writeFile("/private/new/nested/file", "new");
    await wrapped.rename("/private/old", "/private/moved");
    expect(await wrapped.readFile("/private/moved/file", "utf8")).toBe("host");
    expect(await wrapped.exists("/private/old")).toBe(false);
    await wrapped.unlink("/private/moved/file");
    await wrapped.rmdir("/private/moved");
    expect((await wrapped.readdir("/private")).sort()).toEqual(["new"]);
    expect(backend.readFileSync("/private/old/file", "utf8")).toBe("host");
    expect(backend.existsSync("/private/new")).toBe(false);
    expect(backend.existsSync("/private/moved")).toBe(false);
  });

  it("denies moving an uncovered ancestor with covered descendants", async () => {
    const { backend, wrapped } = fixture([{ glob: "tree/config*", mode: "copy-on-write", reason: "private" }]);
    backend.mkdirSync("/tree");
    backend.writeFileSync("/tree/config", "host");
    await expect(wrapped.rename("/tree", "/elsewhere")).rejects.toMatchObject({ code: "EACCES" });
    expect(backend.readFileSync("/tree/config", "utf8")).toBe("host");
  });

  it("removes implicit upper directories before recreating a deleted directory", async () => {
    const { backend, wrapped } = fixture([{ glob: "private/**", mode: "copy-on-write", reason: "private" }]);
    backend.mkdirSync("/private");
    backend.writeFileSync("/private/file", "host");
    await wrapped.writeFile("/private/file", "guest");
    await wrapped.unlink("/private/file");
    await wrapped.rmdir("/private");
    expect(await wrapped.exists("/private")).toBe(false);
    await wrapped.mkdir("/private");
    expect(await wrapped.readdir("/private")).toEqual([]);
    await wrapped.writeFile("/private/new", "new");
    expect(await wrapped.readFile("/private/new", "utf8")).toBe("new");
    expect(backend.readFileSync("/private/file", "utf8")).toBe("host");
    expect(backend.existsSync("/private/new")).toBe(false);
  });
});

describe("copy-on-write with a host directory", () => {
  const temporary: string[] = [];
  afterEach(() => { for (const directory of temporary.splice(0)) fs.rmSync(directory, { recursive: true, force: true }); });

  function hostFixture(readonly = false) {
    const directory = fs.mkdtempSync(path.join(os.tmpdir(), "corb-cow-unit-"));
    temporary.push(directory);
    fs.mkdirSync(path.join(directory, ".git"));
    fs.writeFileSync(path.join(directory, ".git/config"), "host bytes\n");
    const backend = new RealFSProvider(directory);
    const wrapped = withGlobPolicy(readonly ? new ReadonlyProvider(backend) : backend, {
      rules: toGlobRules("repo", builtinGitRules()),
      onDeny: () => {},
    });
    return { directory, wrapped };
  }

  it("never changes host config bytes or leaves a lock after repeated renames", async () => {
    const { directory, wrapped } = hostFixture();
    const original = fs.readFileSync(path.join(directory, ".git/config"));
    for (let count = 0; count < 3; count += 1) {
      const lock = await wrapped.open("/.git/config.lock", "wx");
      await lock.write(Buffer.from(`guest-${count}`), 0, 7, 0);
      await lock.close();
      await wrapped.rename("/.git/config.lock", "/.git/config");
      expect(await wrapped.readFile("/.git/config", "utf8")).toBe(`guest-${count}`);
      expect(fs.readFileSync(path.join(directory, ".git/config"))).toEqual(original);
      expect(fs.existsSync(path.join(directory, ".git/config.lock"))).toBe(false);
    }
  });

  it("reports tombstoned lock lookups as ENOENT through the real VFS RPC service", async () => {
    const { directory, wrapped } = hostFixture();
    const original = fs.readFileSync(path.join(directory, ".git/config"));
    const rpc = new FsRpcService(wrapped);
    let id = 1;
    const request = (op: string, req: Record<string, unknown>) => rpc.handleRequest({ v: 1, t: "fs_request", id: id++, p: { op, req } });
    try {
      const git = (await request("lookup", { parent_ino: 1, name: ".git" })).p.res!.entry.ino;
      await request("lookup", { parent_ino: git, name: "config" });
      for (let count = 0; count < 3; count += 1) {
        const created = await request("create", { parent_ino: git, name: "config.lock", flags: 0xc1, mode: 0o644 });
        expect(created.p.err).toBe(0);
        const fh = created.p.res!.fh;
        const bytes = Buffer.from(`guest-${count}`);
        expect((await request("write", { fh, offset: 0, data: bytes })).p.err).toBe(0);
        expect((await request("release", { fh })).p.err).toBe(0);
        expect((await request("rename", { old_parent_ino: git, old_name: "config.lock", new_parent_ino: git, new_name: "config" })).p.err).toBe(0);
        const removed = await request("lookup", { parent_ino: git, name: "config.lock" });
        expect(removed.p.err).toBe(2);
        expect(removed.p.res).toHaveProperty("entry_ttl_ms");
        expect(await wrapped.readFile("/.git/config", "utf8")).toBe(`guest-${count}`);
        expect(fs.readFileSync(path.join(directory, ".git/config"))).toEqual(original);
        expect(fs.existsSync(path.join(directory, ".git/config.lock"))).toBe(false);
      }
      const escaped = await request("rename", { old_parent_ino: git, old_name: "config", new_parent_ino: 1, new_name: "escape" });
      expect(escaped.p.err).toBe(18);
      const config = (await request("lookup", { parent_ino: git, name: "config" })).p.res!.entry.ino;
      const reader = (await request("open", { ino: config, flags: 0 })).p.res!.fh;
      expect((await request("write", { fh: reader, offset: 0, data: Buffer.from("denied") })).p.err).toBe(9);
      expect((await request("release", { fh: reader })).p.err).toBe(0);
      expect(fs.readFileSync(path.join(directory, ".git/config"))).toEqual(original);
      expect(fs.existsSync(path.join(directory, "escape"))).toBe(false);
    } finally {
      await rpc.close();
    }
  });

  it("preserves the backing provider readonly capability while keeping copies private", async () => {
    const { directory, wrapped } = hostFixture(true);
    expect(wrapped.readonly).toBe(true);
    await wrapped.writeFile("/.git/config", "private");
    await wrapped.access("/.git/config", fs.constants.W_OK);
    expect(await wrapped.readFile("/.git/config", "utf8")).toBe("private");
    expect(fs.readFileSync(path.join(directory, ".git/config"), "utf8")).toBe("host bytes\n");
  });

  it("refuses symlink targets outside the mount", async () => {
    const { directory, wrapped } = hostFixture();
    const outside = fs.mkdtempSync(path.join(os.tmpdir(), "corb-cow-outside-"));
    temporary.push(outside);
    fs.writeFileSync(path.join(outside, "config"), "outside");
    fs.symlinkSync(path.join(outside, "config"), path.join(directory, ".git/config.alias"));
    await expect(wrapped.writeFile("/.git/config.alias", "private")).rejects.toMatchObject({ code: expect.stringMatching(/^(ENOENT|EACCES)$/) });
    expect(fs.readFileSync(path.join(outside, "config"), "utf8")).toBe("outside");
  });
});
