import path from "node:path";
import { AsyncLocalStorage } from "node:async_hooks";
import { constants } from "node:fs";
import { randomUUID } from "node:crypto";
import { ERRNO, isWriteFlag, MemoryProvider } from "@earendil-works/gondolin";
import { normalizeGuestPath } from "./glob.ts";
import type { FsOpKind } from "./policy.ts";

// Calls stay synchronous inside each operation so copy-up and rename cannot interleave.
type Method = (...args: any[]) => any;
type Provider = Record<string, any>;
type Entry = string | { name: string };
type CopyOperation = "write" | "mutate" | "rename" | "link" | "copy-dest";
interface CopyOnWriteView<P> {
  readonly provider: P;
  withRequest<R>(method: string, args: readonly unknown[], callback: () => R): R;
}

// Include numeric errno so the RPC service preserves the intended guest error.
function error(code: keyof typeof ERRNO, target: string): NodeJS.ErrnoException {
  return Object.assign(new Error(`${code}: copy-on-write '${target}'`), { code, errno: ERRNO[code], syscall: "copy-on-write", path: target });
}

function missing(err: unknown): boolean {
  return (err as NodeJS.ErrnoException)?.code === "ENOENT";
}

/** Keep private copies for covered paths until this provider becomes unreachable. */
export function withCopyOnWrite<P extends object>(backend: P, covered: (target: string) => boolean, onWrite: (target: string, requested: string, op: CopyOperation, origin: string) => void, checkAccess: (target: string, op: FsOpKind, requested: string) => void): CopyOnWriteView<P> {
  const requests = new AsyncLocalStorage<{ method: string; args: readonly unknown[] }>();
  const lower = backend as Provider;
  const upper = new MemoryProvider() as unknown as Provider;
  const changed = new Set<string>();
  const deleted = new Set<string>();
  const origins = new Map<string, string>();
  const identities = new Map<string, { pins: number }>();
  const handleRoot = `/.corb-handles-${randomUUID()}`;
  let nextHandle = 0;

  function removed(target: string): boolean {
    for (let current = target; ; current = path.posix.dirname(current)) {
      if (deleted.has(current)) return true;
      if (current === "/") return false;
    }
  }

  function source(target: string): Provider {
    if (removed(target)) throw error("ENOENT", target);
    return changed.has(target) ? upper : lower;
  }

  function lstat(target: string): any {
    return source(target).lstatSync(target);
  }

  function exists(target: string): boolean {
    try {
      lstat(target);
      return true;
    } catch (err) {
      if (!missing(err)) throw err;
      return false;
    }
  }

  // Lower symlinks use the backend resolver, which also enforces its mount boundary.
  function resolve(raw: string, followLeaf = true, allowMissing = false, depth = 0): string {
    if (depth > 40) throw error("ELOOP", raw);
    const normalized = normalizeGuestPath(raw);
    const parts = normalized.split("/").filter(Boolean);
    let current = "/";
    for (let index = 0; index < parts.length; index += 1) {
      current = path.posix.join(current, parts[index]!);
      const leaf = index === parts.length - 1;
      let stat;
      try {
        stat = lstat(current);
      } catch (err) {
        if (leaf && allowMissing && missing(err)) return current;
        throw err;
      }
      if (stat.isSymbolicLink() && (!leaf || followLeaf)) {
        const resolved = changed.has(current)
          ? path.posix.resolve(path.posix.dirname(current), upper.readlinkSync(current))
          : lower.realpathSync(current);
        return resolve(path.posix.join(resolved, ...parts.slice(index + 1)), followLeaf, allowMissing, depth + 1);
      }
      if (!leaf && !stat.isDirectory()) throw error("ENOTDIR", current);
    }
    return current;
  }

  function isCovered(raw: string, target: string): boolean {
    return covered(normalizeGuestPath(raw)) || covered(target) || changed.has(target) || removed(target);
  }

  function parent(target: string): void {
    const directory = path.posix.dirname(target);
    if (!lstat(directory).isDirectory()) throw error("ENOTDIR", directory);
    upper.mkdirSync(directory, { recursive: true });
  }

  function copyUp(target: string): void {
    if (changed.has(target)) return;
    const stat = lstat(target);
    parent(target);
    if (stat.isDirectory()) upper.mkdirSync(target, { recursive: true, mode: stat.mode & 0o777 });
    else if (stat.isSymbolicLink()) upper.symlinkSync(lower.readlinkSync(target), target);
    else if (stat.isFile()) upper.writeFileSync(target, lower.readFileSync(target), { mode: stat.mode & 0o777 });
    else throw error("ENOTSUP", target);
    changed.add(target);
    identities.set(target, { pins: 0 });
  }

  function requestedPath(raw: string, sourceEndpoint = false): string {
    const context = requests.getStore();
    const twoPaths = context && ["rename", "link", "copyFile", "symlink"].includes(context.method);
    const index = twoPaths && !sourceEndpoint ? 1 : 0;
    const requested = context?.args[index];
    return normalizeGuestPath(typeof requested === "string" ? requested : raw);
  }

  function verify(target: string, op: FsOpKind, raw: string, sourceEndpoint = false): void {
    checkAccess(target, op, requestedPath(raw, sourceEndpoint));
  }

  function notify(target: string, raw: string, op: CopyOperation, sourceEndpoint = false): void {
    const requested = requestedPath(raw, sourceEndpoint);
    const origin = covered(requested) ? requested : origins.get(target) ?? normalizeGuestPath(raw);
    origins.set(target, origin);
    onWrite(target, requested, requests.getStore()?.method === "copyFile" ? "copy-dest" : op, origin);
  }

  function mark(target: string, raw = target, op: CopyOperation = "write"): void {
    deleted.delete(target);
    changed.add(target);
    if (!identities.has(target)) identities.set(target, { pins: 0 });
    notify(target, raw, op);
  }

  function fileHandle(target: string, flags: string, mode?: number): any {
    const initial = upper.openSync(target, flags.replace("x", ""), mode);
    const identity = identities.get(target) ?? { pins: 0 };
    identities.set(target, identity);
    const pin = `${handleRoot}/${nextHandle++}`;
    upper.mkdirSync(handleRoot, { recursive: true });
    upper.linkSync(target, pin);
    identity.pins += 1;
    let closed = false;
    const writing = isWriteFlag(flags);
    const reading = flags.startsWith("r") || flags.includes("+");
    function close(): void {
      if (closed) return;
      closed = true;
      upper.unlinkSync(pin);
      identity.pins -= 1;
      initial.closeSync();
    }
    function invoke(method: string, args: any[]): any {
      if (closed) throw error("EBADF", target);
      const mutating = /^(write|truncate|appendFile)/.test(method);
      const reads = /^(read|readFile)/.test(method);
      if ((mutating && !writing) || (reads && !reading)) throw error("EBADF", target);
      // Fresh handles share the current inode bytes, even after rename or unlink.
      const current = upper.openSync(pin, "r+");
      current.position = flags.startsWith("a") && mutating ? upper.statSync(pin).size : initial.position;
      try {
        const actualArgs = [...args];
        if (method === "writeSync" && flags.startsWith("a")) actualArgs[3] = null;
        const result = current[method](...actualArgs);
        if (method === "statSync") result.nlink -= identity.pins;
        initial.position = current.position;
        return result;
      } finally {
        current.closeSync();
      }
    }
    const methods = new Set(["read", "write", "truncate", "readFile", "writeFile", "stat"]);
    return new Proxy(initial, {
      get(value, key) {
        if (key === "closeSync") return close;
        if (key === "close") return async () => close();
        const name = String(key).replace(/Sync$/, "");
        if (methods.has(name)) {
          return String(key).endsWith("Sync")
            ? (...args: any[]) => invoke(`${name}Sync`, args)
            : async (...args: any[]) => {
                const result = invoke(`${name}Sync`, args);
                if (name === "read") return { bytesRead: result, buffer: args[0] };
                if (name === "write") return { bytesWritten: result, buffer: args[0] };
                return result;
              };
        }
        const member = Reflect.get(value, key, value);
        return typeof member === "function" ? member.bind(value) : member;
      },
    });
  }

  function open(raw: string, flags: string, mode?: number): any {
    const writing = isWriteFlag(flags);
    const creates = /[wa]/.test(flags);
    const target = resolve(raw, true, creates);
    verify(target, writing ? "write" : "read", raw);
    if (!isCovered(raw, target)) return lower.openSync(target, flags, mode);
    if (flags.includes("x") && exists(target)) throw error("EEXIST", target);
    if (exists(target)) copyUp(target);
    else {
      if (!creates) throw error("ENOENT", target);
      parent(target);
    }
    const handle = fileHandle(target, flags, mode);
    if (writing) mark(target, raw);
    return handle;
  }

  function readFile(raw: string, options?: any): any {
    const target = resolve(raw);
    verify(target, "read", raw);
    return source(target).readFileSync(target, options);
  }

  function writeFile(raw: string, data: any, options?: any, append = false): void {
    const flags = typeof options === "object" && options?.flag ? options.flag : append ? "a" : "w";
    const handle = open(raw, flags, typeof options === "object" ? options?.mode : undefined);
    try {
      const encoding = typeof options === "string" ? options : options?.encoding;
      const content = typeof data === "string" ? Buffer.from(data, encoding) : data;
      handle.writeSync(content, 0, content.length, null);
    } finally {
      handle.closeSync();
    }
  }

  function readdir(raw: string, options?: any): Entry[] {
    const target = resolve(raw);
    verify(target, "read", raw);
    if (!lstat(target).isDirectory()) throw error("ENOTDIR", target);
    const entries = new Map<string, Entry>();
    try {
      for (const entry of lower.readdirSync(target, options) as Entry[]) {
        const name = typeof entry === "string" ? entry : entry.name;
        if (!removed(path.posix.join(target, name))) entries.set(name, entry);
      }
    } catch (err) {
      if (!missing(err)) throw err;
    }
    if (upper.existsSync(target)) {
      for (const entry of upper.readdirSync(target, options) as Entry[]) {
        const name = typeof entry === "string" ? entry : entry.name;
        const child = path.posix.join(target, name);
        if (changed.has(child) && !removed(child)) entries.set(name, entry);
      }
    }
    return [...entries.values()];
  }

  function unlink(raw: string, directory = false): void {
    const target = resolve(raw, false);
    verify(target, "mutate", raw);
    if (!isCovered(raw, target)) return lower[directory ? "rmdirSync" : "unlinkSync"](target);
    const stat = lstat(target);
    if (directory && !stat.isDirectory()) throw error("ENOTDIR", target);
    if (!directory && stat.isDirectory()) throw error("EISDIR", target);
    if (directory && readdir(target).length) throw error("ENOTEMPTY", target);
    if (changed.has(target) || (directory && upper.existsSync(target))) upper[directory ? "rmdirSync" : "unlinkSync"](target);
    changed.delete(target);
    identities.delete(target);
    deleted.add(target);
    notify(target, raw, "mutate");
  }

  function mkdir(raw: string, options?: any): any {
    const normalized = normalizeGuestPath(raw);
    let target: string;
    try {
      target = resolve(normalized, false, true);
    } catch (err) {
      if (!options?.recursive || !missing(err)) throw err;
      mkdir(path.posix.dirname(normalized), options);
      target = resolve(normalized, false, true);
    }
    verify(target, "mutate", raw);
    if (!isCovered(raw, target)) return lower.mkdirSync(target, options);
    if (exists(target)) {
      if (options?.recursive && lstat(target).isDirectory()) return;
      throw error("EEXIST", target);
    }
    parent(target);
    const result = upper.mkdirSync(target, options);
    mark(target, raw, "mutate");
    return result;
  }

  function rename(rawOld: string, rawNew: string): void {
    const old = resolve(rawOld, false);
    const dest = resolve(rawNew, false, true);
    verify(old, "rename", rawOld, true);
    verify(dest, "rename", rawNew);
    const oldCovered = isCovered(rawOld, old);
    const newCovered = isCovered(rawNew, dest);
    if (!oldCovered && !newCovered) return lower.renameSync(old, dest);
    if (!oldCovered || !newCovered) throw error("EXDEV", dest);
    if (old === dest) return;
    const oldStat = lstat(old);
    if (dest.startsWith(`${old}/`)) throw error("EINVAL", dest);
    if (exists(dest)) {
      const destStat = lstat(dest);
      if (oldStat.isDirectory() !== destStat.isDirectory()) throw error(oldStat.isDirectory() ? "ENOTDIR" : "EISDIR", dest);
      if (destStat.isDirectory() && readdir(dest).length) throw error("ENOTEMPTY", dest);
    }
    const tree: string[] = [];
    function collect(entry: string): void {
      const destination = `${dest}${entry.slice(old.length)}`;
      if (!isCovered(entry, entry) || !isCovered(destination, destination)) throw error("EXDEV", entry);
      tree.push(entry);
      if (lstat(entry).isDirectory()) {
        for (const child of readdir(entry) as string[]) collect(path.posix.join(entry, child));
      }
    }
    collect(old);
    parent(dest);
    for (const entry of tree) copyUp(entry);
    upper.renameSync(old, dest);
    for (const entry of tree) {
      changed.delete(entry);
      deleted.add(entry);
      const destination = `${dest}${entry.slice(old.length)}`;
      deleted.delete(destination);
      changed.add(destination);
      identities.set(destination, identities.get(entry)!);
      identities.delete(entry);
    }
    notify(old, rawOld, "rename", true);
    notify(dest, rawNew, "rename");
  }

  function link(rawOld: string, rawNew: string): void {
    const old = resolve(rawOld, false);
    const dest = resolve(rawNew, false, true);
    verify(old, "link", rawOld, true);
    verify(dest, "link", rawNew);
    const oldCovered = isCovered(rawOld, old);
    const newCovered = isCovered(rawNew, dest);
    if (!oldCovered && !newCovered) return lower.linkSync(old, dest);
    if (!oldCovered || !newCovered) throw error("EXDEV", dest);
    if (exists(dest)) throw error("EEXIST", dest);
    copyUp(old);
    parent(dest);
    upper.linkSync(old, dest);
    identities.set(dest, identities.get(old)!);
    mark(dest, rawNew, "link");
  }

  function symlink(target: string, raw: string, type?: string): void {
    const dest = resolve(raw, false, true);
    verify(dest, "link", raw);
    if (!isCovered(raw, dest)) return lower.symlinkSync(target, dest, type);
    if (exists(dest)) throw error("EEXIST", dest);
    parent(dest);
    upper.symlinkSync(target, dest, type);
    mark(dest, raw, "link");
  }

  function copyFile(rawSrc: string, rawDest: string, mode = 0): void {
    const src = resolve(rawSrc);
    const dest = resolve(rawDest, true, true);
    verify(src, "copy-source", rawSrc, true);
    verify(dest, "copy-dest", rawDest);
    if (!isCovered(rawDest, dest) && !changed.has(src)) return lower.copyFileSync(src, dest, mode);
    if ((mode & constants.COPYFILE_EXCL) && exists(dest)) throw error("EEXIST", dest);
    writeFile(rawDest, readFile(src));
  }

  function access(raw: string, mode = 0): void {
    const target = resolve(raw);
    verify(target, "access-exists", raw);
    if (mode & (constants.R_OK | constants.X_OK)) verify(target, "access-read", raw);
    if (mode & constants.W_OK) verify(target, "access-write", raw);
    if (isCovered(raw, target)) {
      source(target).accessSync(target, mode & ~constants.W_OK);
      return;
    }
    lower.accessSync(target, mode);
  }

  function truncate(raw: string, size = 0): void {
    const handle = open(raw, "r+");
    try { handle.truncateSync(size); } finally { handle.closeSync(); }
  }

  const operations: Record<string, Method> = {
    open,
    readFile,
    writeFile,
    appendFile: (raw, data, options) => writeFile(raw, data, options, true),
    stat: (raw, options) => {
      const target = resolve(raw);
      verify(target, "stat", raw);
      const result = source(target).statSync(target, options);
      const pins = identities.get(target)?.pins;
      if (pins) result.nlink = typeof result.nlink === "bigint" ? result.nlink - BigInt(pins) : result.nlink - pins;
      return result;
    },
    lstat: (raw, options) => {
      const target = resolve(raw, false);
      verify(target, "stat", raw);
      const result = source(target).lstatSync(target, options);
      const pins = identities.get(target)?.pins;
      if (pins) result.nlink = typeof result.nlink === "bigint" ? result.nlink - BigInt(pins) : result.nlink - pins;
      return result;
    },
    realpath: (raw) => resolve(raw),
    readlink: (raw, options) => { const target = resolve(raw, false); verify(target, "readlink", raw); return source(target).readlinkSync(target, options); },
    exists: (raw) => { try { verify(resolve(raw), "exists", raw); return true; } catch { return false; } },
    readdir,
    mkdir,
    unlink,
    rmdir: (raw) => unlink(raw, true),
    rename,
    link,
    symlink,
    copyFile,
    access,
    truncate,
  };
  const handlers: Provider = {};
  for (const [name, operation] of Object.entries(operations)) {
    handlers[`${name}Sync`] = operation;
    handlers[name] = async (...args: any[]) => operation(...args);
  }
  const provider = new Proxy(backend, {
    get(target, key) {
      const member = Reflect.get(target, key, target);
      if (typeof key === "string" && typeof member === "function" && Object.hasOwn(handlers, key)) return handlers[key];
      return typeof member === "function" ? member.bind(target) : member;
    },
  });
  return {
    provider,
    withRequest: (method, args, callback) => requests.run({ method: method.replace(/Sync$/, ""), args }, callback),
  };
}
