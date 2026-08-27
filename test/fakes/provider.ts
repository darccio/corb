// `test/fakes/provider.ts` — the shared, in-memory `VirtualProvider` fake
// this item's own plan names explicitly in the repo layout ("in-memory
// VirtualProvider for policy tests"). Used by `test/unit/vfs/glob-policy.test.ts`
// and every future VFS test that needs a real (never a real
// `RealFSProvider`/real VM — that's M5.5's job) backend to exercise
// `withGlobPolicy` against, including the adversarial cases that make a
// symlink-bypass or hard-link-aliasing defense meaningful to test at all:
// this fake resolves symlink targets for real (so `realpath()` has
// something genuine to catch) and shares object identity across hard-link
// names (so writing through one name is visible through the other, the way
// a real inode is).
//
// Deliberately *not* declared `implements VirtualProvider` (the type
// imported from `@earendil-works/gondolin`): `withGlobPolicy<P extends
// object>` accepts any object, so nothing requires this class to satisfy
// that type nominally, and doing so would drag in `node:fs`'s real `Dirent`
// class as the required shape for `readdir`'s `withFileTypes` entries —
// `Dirent` carries several properties (`parentPath`, deprecated `path`,
// etc.) that add nothing to what these tests need (`.name` plus the
// `is*()` predicates) and exist only to satisfy a type this fake is never
// actually type-checked against at any real call site. Every method
// signature below still mirrors the real interface's shape closely (verified
// against `node_modules/@earendil-works/gondolin/dist/src/vfs/node/index.d.ts`
// and cross-checked behaviorally against the SDK's own `MemoryProvider`,
// `dist/src/vfs/node/vendored-node-vfs/lib/internal/vfs/providers/memory.js`
// — this fake's `lookup`/`ensureParent` symlink-following structure is
// modeled directly on that file's own `_lookupEntry`/`_ensureParent`,
// verified line by line while porting it, not written from scratch and
// hoped to match), so it stays a faithful, trustworthy stand-in either way.
//
// Internal representation: a tree of plain `Entry` objects (files, dirs,
// symlinks). A hard link is two directory-map slots pointing at the *same*
// `Entry` object — mutating content through one name is visible through the
// other for free, because both names' lookups return the identical object.
// This is simple enough to read in one sitting, which matters more for test
// infrastructure than raw performance or completeness.
import fs from "node:fs";
import path from "node:path";

type EntryKind = "file" | "dir" | "symlink";

interface Entry {
  kind: EntryKind;
  /** Only meaningful for `kind === "file"`. */
  content?: Buffer;
  /** Only meaningful for `kind === "dir"`. */
  children?: Map<string, Entry>;
  /** Only meaningful for `kind === "symlink"`. */
  target?: string;
  mode: number;
  mtimeMs: number;
  /** Number of directory-map slots referencing this exact object — a hard link is a second slot referencing the same `Entry`, so this is a real `nlink`-equivalent. */
  linkCount: number;
}

const MAX_SYMLINK_DEPTH = 40;

const MODE_FILE = 0o100000;
const MODE_DIR = 0o040000;
const MODE_SYMLINK = 0o120000;

function makeFile(content: Buffer = Buffer.alloc(0)): Entry {
  return { kind: "file", content, mode: 0o644, mtimeMs: Date.now(), linkCount: 1 };
}
function makeDir(): Entry {
  return { kind: "dir", children: new Map(), mode: 0o755, mtimeMs: Date.now(), linkCount: 1 };
}
function makeSymlink(target: string): Entry {
  return { kind: "symlink", target, mode: 0o777, mtimeMs: Date.now(), linkCount: 1 };
}

function errnoErr(code: string, syscall: string, targetPath?: string): NodeJS.ErrnoException {
  const message = targetPath !== undefined ? `${code}: ${syscall} '${targetPath}'` : `${code}: ${syscall}`;
  const error = new Error(message) as NodeJS.ErrnoException;
  error.code = code;
  error.syscall = syscall;
  if (targetPath !== undefined) {
    error.path = targetPath;
  }
  return error;
}

function isEnoent(err: unknown): boolean {
  return typeof err === "object" && err !== null && (err as { code?: unknown }).code === "ENOENT";
}

function splitSegments(normalizedPath: string): string[] {
  return normalizedPath.split("/").filter((segment) => segment.length > 0);
}

/** Joins a normalized-absolute parent with one child name without ever producing a `//`-shaped result at the root — the same concern `src/vfs/glob.ts`'s module comment documents for `readdir` joins. */
function joinAbs(parent: string, name: string): string {
  return parent === "/" ? `/${name}` : `${parent}/${name}`;
}

function statsFromEntry(entry: Entry): fs.Stats {
  const size = entry.kind === "file" ? (entry.content?.length ?? 0) : entry.kind === "symlink" ? (entry.target?.length ?? 0) : 4096;
  const kindBits = entry.kind === "dir" ? MODE_DIR : entry.kind === "symlink" ? MODE_SYMLINK : MODE_FILE;
  // `Object.create(fs.Stats.prototype)` + `Object.assign` is the same
  // pattern `@earendil-works/gondolin`'s own `createVirtualDirStats`
  // (`dist/src/vfs/utils.js`) uses — `fs.Stats.prototype`'s `isFile`/
  // `isDirectory`/`isSymbolicLink` methods only ever read `this.mode`, so
  // this produces a real, working `fs.Stats` instance without needing
  // Node's own internal stat-producing bindings.
  const stats = Object.create(fs.Stats.prototype) as fs.Stats;
  Object.assign(stats, {
    dev: 0,
    ino: 0,
    mode: entry.mode | kindBits,
    nlink: entry.linkCount,
    uid: 0,
    gid: 0,
    rdev: 0,
    size,
    blksize: 4096,
    blocks: Math.ceil(size / 512),
    atimeMs: entry.mtimeMs,
    mtimeMs: entry.mtimeMs,
    ctimeMs: entry.mtimeMs,
    birthtimeMs: entry.mtimeMs,
    atime: new Date(entry.mtimeMs),
    mtime: new Date(entry.mtimeMs),
    ctime: new Date(entry.mtimeMs),
    birthtime: new Date(entry.mtimeMs),
  });
  return stats;
}

interface LookupResult {
  entry: Entry | undefined;
  resolvedPath: string;
  eloop?: boolean;
}

class FakeFileHandle {
  #entry: Entry;
  #flags: string;
  #position = 0;
  #closed = false;

  constructor(entry: Entry, flags: string) {
    this.#entry = entry;
    this.#flags = flags;
    if (flags === "w" || flags === "w+") {
      entry.content = Buffer.alloc(0);
    } else if (flags === "a" || flags === "a+") {
      this.#position = entry.content?.length ?? 0;
    }
  }

  #checkClosed(): void {
    if (this.#closed) {
      throw errnoErr("EBADF", "read");
    }
  }

  // Real POSIX file descriptors enforce the negotiated open mode at the
  // kernel level regardless of what userspace code calls afterward
  // (`src/vfs/glob-policy.ts`'s module comment, finding #3, verified against
  // `RealFileHandle` in the real SDK). This fake models that same
  // self-enforcement deliberately, rather than the SDK's own laxer
  // `MemoryFileHandle` (which never checks `flags` before writing) — a
  // faithful stand-in for the backend `withGlobPolicy` actually wraps in
  // production should behave like `RealFileHandle`, not like the SDK's own
  // test-only in-memory handle.
  #checkWritable(): void {
    if (!/[wa+]/.test(this.#flags)) {
      throw errnoErr("EBADF", "write");
    }
  }
  #checkReadable(): void {
    if (!/[r+]/.test(this.#flags)) {
      throw errnoErr("EBADF", "read");
    }
  }

  readSync(buffer: Buffer, offset: number, length: number, position?: number | null): number {
    this.#checkClosed();
    this.#checkReadable();
    const content = this.#entry.content ?? Buffer.alloc(0);
    const pos = position ?? this.#position;
    const available = content.length - pos;
    if (available <= 0) {
      return 0;
    }
    const toRead = Math.min(length, available);
    content.copy(buffer, offset, pos, pos + toRead);
    if (position === null || position === undefined) {
      this.#position = pos + toRead;
    }
    return toRead;
  }
  async read(buffer: Buffer, offset: number, length: number, position?: number | null): Promise<{ bytesRead: number; buffer: Buffer }> {
    return { bytesRead: this.readSync(buffer, offset, length, position), buffer };
  }

  writeSync(buffer: Buffer, offset: number, length: number, position?: number | null): number {
    this.#checkClosed();
    this.#checkWritable();
    const pos = position ?? this.#position;
    const data = buffer.subarray(offset, offset + length);
    let content = this.#entry.content ?? Buffer.alloc(0);
    if (pos + length > content.length) {
      const grown = Buffer.alloc(pos + length);
      content.copy(grown);
      content = grown;
    }
    data.copy(content, pos);
    this.#entry.content = content;
    this.#entry.mtimeMs = Date.now();
    if (position === null || position === undefined) {
      this.#position = pos + length;
    }
    return length;
  }
  async write(buffer: Buffer, offset: number, length: number, position?: number | null): Promise<{ bytesWritten: number; buffer: Buffer }> {
    return { bytesWritten: this.writeSync(buffer, offset, length, position), buffer };
  }

  readFileSync(options?: { encoding?: BufferEncoding } | BufferEncoding): Buffer | string {
    this.#checkClosed();
    this.#checkReadable();
    const content = this.#entry.content ?? Buffer.alloc(0);
    const encoding = typeof options === "string" ? options : options?.encoding;
    return encoding ? content.toString(encoding) : Buffer.from(content);
  }
  async readFile(options?: { encoding?: BufferEncoding } | BufferEncoding): Promise<Buffer | string> {
    return this.readFileSync(options);
  }

  writeFileSync(data: Buffer | string, options?: { encoding?: BufferEncoding }): void {
    this.#checkClosed();
    this.#checkWritable();
    const buffer = typeof data === "string" ? Buffer.from(data, options?.encoding) : data;
    if (this.#flags === "a" || this.#flags === "a+") {
      this.#entry.content = Buffer.concat([this.#entry.content ?? Buffer.alloc(0), buffer]);
    } else {
      this.#entry.content = Buffer.from(buffer);
    }
    this.#entry.mtimeMs = Date.now();
    this.#position = this.#entry.content.length;
  }
  async writeFile(data: Buffer | string, options?: { encoding?: BufferEncoding }): Promise<void> {
    this.writeFileSync(data, options);
  }

  statSync(): fs.Stats {
    this.#checkClosed();
    return statsFromEntry(this.#entry);
  }
  async stat(): Promise<fs.Stats> {
    return this.statSync();
  }

  truncateSync(len = 0): void {
    this.#checkClosed();
    this.#checkWritable();
    const content = this.#entry.content ?? Buffer.alloc(0);
    if (len < content.length) {
      this.#entry.content = content.subarray(0, len);
    } else if (len > content.length) {
      const grown = Buffer.alloc(len);
      content.copy(grown);
      this.#entry.content = grown;
    }
    this.#entry.mtimeMs = Date.now();
  }
  async truncate(len?: number): Promise<void> {
    this.truncateSync(len);
  }

  closeSync(): void {
    this.#closed = true;
  }
  async close(): Promise<void> {
    this.closeSync();
  }
}

/**
 * An in-memory `VirtualProvider`-shaped fake. See the module comment above
 * for the design rationale (why not `implements VirtualProvider`, why plain
 * shared-object-identity hard links, why the file handle self-enforces its
 * negotiated mode).
 */
export class FakeVirtualProvider {
  #root: Entry = makeDir();

  readonly readonly = false;
  readonly supportsSymlinks = true;
  readonly supportsWatch = true;

  // -----------------------------------------------------------------
  // Path resolution — modeled directly on `MemoryProvider._lookupEntry`
  // and `._ensureParent` (see the module comment for the citation).
  // -----------------------------------------------------------------

  private normalize(rawPath: string): string {
    const withLeadingSlash = rawPath.startsWith("/") ? rawPath : `/${rawPath}`;
    return path.posix.normalize(withLeadingSlash);
  }

  private resolveSymlinkTarget(symlinkPath: string, target: string): string {
    if (target.startsWith("/")) {
      return this.normalize(target);
    }
    const parent = symlinkPath === "/" ? "/" : path.posix.dirname(symlinkPath);
    return this.normalize(path.posix.join(parent, target));
  }

  private lookup(rawPath: string, followSymlinks: boolean, depth = 0): LookupResult {
    const normalized = this.normalize(rawPath);
    if (normalized === "/") {
      return { entry: this.#root, resolvedPath: "/" };
    }
    const segments = splitSegments(normalized);
    let current = this.#root;
    let currentPath = "/";
    for (const segment of segments) {
      if (current.kind === "symlink" && followSymlinks) {
        if (depth >= MAX_SYMLINK_DEPTH) {
          return { entry: undefined, resolvedPath: "", eloop: true };
        }
        const targetPath = this.resolveSymlinkTarget(currentPath, current.target ?? "");
        const resolved = this.lookup(targetPath, true, depth + 1);
        if (resolved.eloop || !resolved.entry) {
          return resolved;
        }
        current = resolved.entry;
        currentPath = resolved.resolvedPath;
      }
      if (current.kind !== "dir") {
        return { entry: undefined, resolvedPath: "" };
      }
      const child = current.children?.get(segment);
      if (!child) {
        return { entry: undefined, resolvedPath: "" };
      }
      current = child;
      currentPath = joinAbs(currentPath, segment);
    }
    if (current.kind === "symlink" && followSymlinks) {
      if (depth >= MAX_SYMLINK_DEPTH) {
        return { entry: undefined, resolvedPath: "", eloop: true };
      }
      const targetPath = this.resolveSymlinkTarget(currentPath, current.target ?? "");
      return this.lookup(targetPath, true, depth + 1);
    }
    return { entry: current, resolvedPath: currentPath };
  }

  private getEntry(rawPath: string, syscall: string, followSymlinks: boolean): Entry {
    const result = this.lookup(rawPath, followSymlinks);
    if (result.eloop) {
      throw errnoErr("ELOOP", syscall, rawPath);
    }
    if (!result.entry) {
      throw errnoErr("ENOENT", syscall, rawPath);
    }
    return result.entry;
  }

  /** Resolves the parent directory of `rawPath`, following symlinks along every ancestor segment (including a symlinked final ancestor) — this is what makes `open('/decoy/newfile', 'w')` correctly land inside `/decoy`'s real target when `/decoy` is a symlink, the fixture behavior the create-path bypass-recheck adversarial test needs. */
  private ensureParent(rawPath: string, createMissingDirs: boolean, syscall: string): Entry {
    const normalized = this.normalize(rawPath);
    if (normalized === "/") {
      return this.#root;
    }
    const parentSegments = splitSegments(path.posix.dirname(normalized));
    let current = this.#root;
    let currentPath = "/";
    for (const segment of parentSegments) {
      if (current.kind === "symlink") {
        const targetPath = this.resolveSymlinkTarget(currentPath, current.target ?? "");
        const resolved = this.lookup(targetPath, true);
        if (!resolved.entry) {
          throw errnoErr("ENOENT", syscall, rawPath);
        }
        current = resolved.entry;
        currentPath = resolved.resolvedPath;
      }
      if (current.kind !== "dir") {
        throw errnoErr("ENOTDIR", syscall, rawPath);
      }
      let child = current.children?.get(segment);
      if (!child) {
        if (!createMissingDirs) {
          throw errnoErr("ENOENT", syscall, rawPath);
        }
        child = makeDir();
        current.children?.set(segment, child);
      }
      current = child;
      currentPath = joinAbs(currentPath, segment);
    }
    if (current.kind === "symlink") {
      const targetPath = this.resolveSymlinkTarget(currentPath, current.target ?? "");
      const resolved = this.lookup(targetPath, true);
      if (!resolved.entry || resolved.entry.kind !== "dir") {
        throw errnoErr("ENOTDIR", syscall, rawPath);
      }
      return resolved.entry;
    }
    if (current.kind !== "dir") {
      throw errnoErr("ENOTDIR", syscall, rawPath);
    }
    return current;
  }

  // -----------------------------------------------------------------
  // open / openSync
  // -----------------------------------------------------------------

  openSync(rawPath: string, flags: string, mode?: number): FakeFileHandle {
    const normalized = this.normalize(rawPath);
    const create = /[wa]/.test(flags);
    let entry: Entry;
    try {
      entry = this.getEntry(normalized, "open", true);
    } catch (err) {
      if (isEnoent(err) && create) {
        const parent = this.ensureParent(normalized, false, "open");
        entry = makeFile();
        parent.children?.set(path.posix.basename(normalized), entry);
      } else {
        throw err;
      }
    }
    if (entry.kind === "dir") {
      throw errnoErr("EISDIR", "open", rawPath);
    }
    if (entry.kind === "symlink") {
      throw errnoErr("EINVAL", "open", rawPath);
    }
    void mode;
    return new FakeFileHandle(entry, flags);
  }
  async open(rawPath: string, flags: string, mode?: number): Promise<FakeFileHandle> {
    return this.openSync(rawPath, flags, mode);
  }

  // -----------------------------------------------------------------
  // stat / lstat
  // -----------------------------------------------------------------

  statSync(rawPath: string, _options?: object): fs.Stats {
    return statsFromEntry(this.getEntry(rawPath, "stat", true));
  }
  async stat(rawPath: string, options?: object): Promise<fs.Stats> {
    return this.statSync(rawPath, options);
  }
  lstatSync(rawPath: string, _options?: object): fs.Stats {
    return statsFromEntry(this.getEntry(rawPath, "lstat", false));
  }
  async lstat(rawPath: string, options?: object): Promise<fs.Stats> {
    return this.lstatSync(rawPath, options);
  }

  // -----------------------------------------------------------------
  // readdir
  // -----------------------------------------------------------------

  readdirSync(rawPath: string, options?: { withFileTypes?: boolean }): Array<string | { name: string; isFile(): boolean; isDirectory(): boolean; isSymbolicLink(): boolean }> {
    const entry = this.getEntry(rawPath, "scandir", true);
    if (entry.kind !== "dir") {
      throw errnoErr("ENOTDIR", "scandir", rawPath);
    }
    const names = [...(entry.children?.keys() ?? [])];
    if (!options?.withFileTypes) {
      return names;
    }
    return names.map((name) => {
      const child = entry.children?.get(name) as Entry;
      return {
        name,
        isFile: () => child.kind === "file",
        isDirectory: () => child.kind === "dir",
        isSymbolicLink: () => child.kind === "symlink",
      };
    });
  }
  async readdir(rawPath: string, options?: { withFileTypes?: boolean }) {
    return this.readdirSync(rawPath, options);
  }

  // -----------------------------------------------------------------
  // mkdir / rmdir / unlink
  // -----------------------------------------------------------------

  mkdirSync(rawPath: string, options?: { recursive?: boolean; mode?: number }): string | undefined {
    const normalized = this.normalize(rawPath);
    const existing = this.lookup(normalized, true);
    if (existing.entry) {
      if (options?.recursive && existing.entry.kind === "dir") {
        return undefined;
      }
      throw errnoErr("EEXIST", "mkdir", rawPath);
    }
    const parent = this.ensureParent(normalized, options?.recursive === true, "mkdir");
    parent.children?.set(path.posix.basename(normalized), makeDir());
    return undefined;
  }
  async mkdir(rawPath: string, options?: { recursive?: boolean; mode?: number }): Promise<string | undefined> {
    return this.mkdirSync(rawPath, options);
  }

  rmdirSync(rawPath: string): void {
    const normalized = this.normalize(rawPath);
    const entry = this.getEntry(normalized, "rmdir", true);
    if (entry.kind !== "dir") {
      throw errnoErr("ENOTDIR", "rmdir", rawPath);
    }
    if ((entry.children?.size ?? 0) > 0) {
      throw errnoErr("ENOTEMPTY", "rmdir", rawPath);
    }
    const parent = this.ensureParent(normalized, false, "rmdir");
    parent.children?.delete(path.posix.basename(normalized));
  }
  async rmdir(rawPath: string): Promise<void> {
    this.rmdirSync(rawPath);
  }

  unlinkSync(rawPath: string): void {
    const normalized = this.normalize(rawPath);
    const entry = this.getEntry(normalized, "unlink", false);
    if (entry.kind === "dir") {
      throw errnoErr("EISDIR", "unlink", rawPath);
    }
    const parent = this.ensureParent(normalized, false, "unlink");
    parent.children?.delete(path.posix.basename(normalized));
    entry.linkCount = Math.max(0, entry.linkCount - 1);
  }
  async unlink(rawPath: string): Promise<void> {
    this.unlinkSync(rawPath);
  }

  // -----------------------------------------------------------------
  // rename / link / symlink / readlink
  // -----------------------------------------------------------------

  renameSync(rawOld: string, rawNew: string): void {
    const oldNorm = this.normalize(rawOld);
    const newNorm = this.normalize(rawNew);
    const entry = this.getEntry(oldNorm, "rename", false);
    const oldParent = this.ensureParent(oldNorm, false, "rename");
    const newParent = this.ensureParent(newNorm, true, "rename");
    oldParent.children?.delete(path.posix.basename(oldNorm));
    newParent.children?.set(path.posix.basename(newNorm), entry);
  }
  async rename(rawOld: string, rawNew: string): Promise<void> {
    this.renameSync(rawOld, rawNew);
  }

  linkSync(rawExisting: string, rawNew: string): void {
    const existingNorm = this.normalize(rawExisting);
    const newNorm = this.normalize(rawNew);
    const entry = this.getEntry(existingNorm, "link", true);
    if (entry.kind === "dir") {
      throw errnoErr("EISDIR", "link", rawExisting);
    }
    if (this.lookup(newNorm, false).entry) {
      throw errnoErr("EEXIST", "link", rawNew);
    }
    const parent = this.ensureParent(newNorm, false, "link");
    // Sharing the identical `Entry` object across two directory-map slots
    // is what makes this a genuine hard link: mutating `.content` through
    // either name is visible through the other, because both names resolve
    // to the same object, not a copy.
    parent.children?.set(path.posix.basename(newNorm), entry);
    entry.linkCount += 1;
  }
  async link(rawExisting: string, rawNew: string): Promise<void> {
    this.linkSync(rawExisting, rawNew);
  }

  readlinkSync(rawPath: string, _options?: object): string {
    const entry = this.getEntry(rawPath, "readlink", false);
    if (entry.kind !== "symlink") {
      throw errnoErr("EINVAL", "readlink", rawPath);
    }
    return entry.target ?? "";
  }
  async readlink(rawPath: string, options?: object): Promise<string> {
    return this.readlinkSync(rawPath, options);
  }

  symlinkSync(target: string, rawPath: string, _type?: string): void {
    const normalized = this.normalize(rawPath);
    if (this.lookup(normalized, false).entry) {
      throw errnoErr("EEXIST", "symlink", rawPath);
    }
    const parent = this.ensureParent(normalized, false, "symlink");
    parent.children?.set(path.posix.basename(normalized), makeSymlink(target));
  }
  async symlink(target: string, rawPath: string, type?: string): Promise<void> {
    this.symlinkSync(target, rawPath, type);
  }

  // -----------------------------------------------------------------
  // realpath / access
  // -----------------------------------------------------------------

  realpathSync(rawPath: string, _options?: object): string {
    const result = this.lookup(rawPath, true);
    if (result.eloop) {
      throw errnoErr("ELOOP", "realpath", rawPath);
    }
    if (!result.entry) {
      throw errnoErr("ENOENT", "realpath", rawPath);
    }
    return result.resolvedPath;
  }
  async realpath(rawPath: string, options?: object): Promise<string> {
    return this.realpathSync(rawPath, options);
  }

  accessSync(rawPath: string, _mode?: number): void {
    this.getEntry(rawPath, "access", true);
  }
  async access(rawPath: string, mode?: number): Promise<void> {
    this.accessSync(rawPath, mode);
  }

  // -----------------------------------------------------------------
  // readFile / writeFile / appendFile / exists / copyFile
  // -----------------------------------------------------------------

  readFileSync(rawPath: string, options?: { encoding?: BufferEncoding } | BufferEncoding): Buffer | string {
    const entry = this.getEntry(rawPath, "open", true);
    if (entry.kind !== "file") {
      throw errnoErr("EISDIR", "read", rawPath);
    }
    const content = entry.content ?? Buffer.alloc(0);
    const encoding = typeof options === "string" ? options : options?.encoding;
    return encoding ? content.toString(encoding) : Buffer.from(content);
  }
  async readFile(rawPath: string, options?: { encoding?: BufferEncoding } | BufferEncoding): Promise<Buffer | string> {
    return this.readFileSync(rawPath, options);
  }

  writeFileSync(rawPath: string, data: Buffer | string, options?: { encoding?: BufferEncoding; mode?: number }): void {
    const normalized = this.normalize(rawPath);
    const buffer = typeof data === "string" ? Buffer.from(data, options?.encoding) : data;
    let entry = this.lookup(normalized, true).entry;
    if (!entry) {
      const parent = this.ensureParent(normalized, false, "open");
      entry = makeFile();
      parent.children?.set(path.posix.basename(normalized), entry);
    }
    if (entry.kind === "dir") {
      throw errnoErr("EISDIR", "open", rawPath);
    }
    entry.content = Buffer.from(buffer);
    entry.mtimeMs = Date.now();
  }
  async writeFile(rawPath: string, data: Buffer | string, options?: { encoding?: BufferEncoding; mode?: number }): Promise<void> {
    this.writeFileSync(rawPath, data, options);
  }

  appendFileSync(rawPath: string, data: Buffer | string, options?: { encoding?: BufferEncoding; mode?: number }): void {
    const normalized = this.normalize(rawPath);
    const buffer = typeof data === "string" ? Buffer.from(data, options?.encoding) : data;
    let entry = this.lookup(normalized, true).entry;
    if (!entry) {
      const parent = this.ensureParent(normalized, false, "open");
      entry = makeFile();
      parent.children?.set(path.posix.basename(normalized), entry);
    }
    if (entry.kind === "dir") {
      throw errnoErr("EISDIR", "open", rawPath);
    }
    entry.content = Buffer.concat([entry.content ?? Buffer.alloc(0), buffer]);
    entry.mtimeMs = Date.now();
  }
  async appendFile(rawPath: string, data: Buffer | string, options?: { encoding?: BufferEncoding; mode?: number }): Promise<void> {
    this.appendFileSync(rawPath, data, options);
  }

  existsSync(rawPath: string): boolean {
    try {
      this.getEntry(rawPath, "stat", true);
      return true;
    } catch {
      return false;
    }
  }
  async exists(rawPath: string): Promise<boolean> {
    return this.existsSync(rawPath);
  }

  copyFileSync(rawSrc: string, rawDest: string, _mode?: number): void {
    const srcEntry = this.getEntry(rawSrc, "copyfile", true);
    if (srcEntry.kind !== "file") {
      throw errnoErr("EINVAL", "copyfile", rawSrc);
    }
    const destNorm = this.normalize(rawDest);
    const parent = this.ensureParent(destNorm, false, "copyfile");
    parent.children?.set(path.posix.basename(destNorm), makeFile(Buffer.from(srcEntry.content ?? Buffer.alloc(0))));
  }
  async copyFile(rawSrc: string, rawDest: string, mode?: number): Promise<void> {
    this.copyFileSync(rawSrc, rawDest, mode);
  }

  // -----------------------------------------------------------------
  // truncate (top-level) — deliberately implemented here even though the
  // real `RealFSProvider` does *not* have a top-level `truncate` (see
  // `src/vfs/glob-policy.ts`'s module comment, finding #5): having one on
  // this fake is what lets the policy test suite exercise
  // `withGlobPolicy`'s gating of a top-level `truncate` at all, proving the
  // wrapper handles a backend that *does* implement it, for the day one
  // does — the real backend's own case (no top-level `truncate`, RPC-layer
  // open+handle-truncate fallback going through this wrapper's gated
  // `open` instead) is exercised implicitly by every `open`-based test.
  // -----------------------------------------------------------------

  truncateSync(rawPath: string, length: number): void {
    const entry = this.getEntry(rawPath, "truncate", true);
    if (entry.kind !== "file") {
      throw errnoErr("EISDIR", "truncate", rawPath);
    }
    const content = entry.content ?? Buffer.alloc(0);
    if (length < content.length) {
      entry.content = content.subarray(0, length);
    } else if (length > content.length) {
      const grown = Buffer.alloc(length);
      content.copy(grown);
      entry.content = grown;
    }
    entry.mtimeMs = Date.now();
  }
  async truncate(rawPath: string, length: number): Promise<void> {
    this.truncateSync(rawPath, length);
  }

  // -----------------------------------------------------------------
  // statfs / watch family — inert stand-ins; no test in this fixture's own
  // suite depends on the numbers or real change-notification behavior,
  // only on `withGlobPolicy` correctly gating and delegating to them.
  // -----------------------------------------------------------------

  async statfs(_rawPath: string) {
    return { blocks: 1000, bfree: 500, bavail: 500, files: 1000, ffree: 500, bsize: 4096, frsize: 4096, namelen: 255 };
  }

  watch(_rawPath: string, _options?: object): { close(): void } {
    return { close: () => {} };
  }
  watchAsync(_rawPath: string, _options?: object): AsyncIterable<never> {
    return { [Symbol.asyncIterator]: () => ({ next: async () => ({ value: undefined, done: true }) }) } as AsyncIterable<never>;
  }
  watchFile(_rawPath: string, _options?: object, _listener?: (...args: unknown[]) => void): { stop(): void } {
    return { stop: () => {} };
  }
  unwatchFile(_rawPath: string, _listener?: (...args: unknown[]) => void): void {
    // no-op: nothing is actually watching in this fake.
  }
}
