import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import { randomUUID, createHash } from "node:crypto";
import { pipeline } from "node:stream/promises";
import { Transform } from "node:stream";
import { corbCacheRoot, corbStateDir } from "../config/paths.ts";
import { fail, SHA256, sha256 } from "./validate.ts";
import { parseMetadata } from "./metadata.ts";

export function privateDirectory(directory: string): string {
  fs.mkdirSync(directory, { recursive: true, mode: 0o700 });
  if (fs.lstatSync(directory).isSymbolicLink() || !fs.statSync(directory).isDirectory()) fail(`unsafe state directory '${directory}'`);
  fs.chmodSync(directory, 0o700);
  return directory;
}
export function layerCache(): string { return path.join(corbCacheRoot(), "layer-inputs", "v1"); }
export function layerState(workspace: string): string { return path.join(corbStateDir(), "layers", workspace); }
export async function hashFile(filename: string, limit = 32 * 1024 ** 3): Promise<string> {
  const stat = fs.lstatSync(filename);
  if (!stat.isFile() || stat.size > limit) fail(`invalid or excessive cache file '${filename}'`);
  const hash = createHash("sha256");
  let size = 0;
  for await (const chunk of fs.createReadStream(filename)) {
    size += chunk.length;
    if (size > limit) fail(`file exceeds limit '${filename}'`);
    hash.update(chunk);
  }
  if (size !== stat.size) fail(`file changed while reading '${filename}'`);
  return hash.digest("hex");
}
export function blobPath(digest: string): string {
  const hex = digest.replace(/^sha256:/, "");
  if (!SHA256.test(hex)) fail("invalid cache digest");
  return path.join(layerCache(), "blobs", "sha256", hex);
}
export async function verifyBlob(digest: string, expectedSize?: number): Promise<string> {
  const filename = blobPath(digest);
  try {
    if (await hashFile(filename) !== digest.replace(/^sha256:/, "") || (expectedSize !== undefined && fs.statSync(filename).size !== expectedSize)) fail(`corrupt input cache object ${digest}`);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") fail(`missing authenticated input ${digest}. Run corb image layer pull or explicitly refresh with corb image pin`);
    throw error;
  }
  return filename;
}
export async function publishBlob(source: string, digest: string, expectedSize?: number): Promise<string> {
  if (await hashFile(source) !== digest.replace(/^sha256:/, "") || (expectedSize !== undefined && fs.statSync(source).size !== expectedSize)) fail("candidate blob digest or size mismatch");
  const destination = blobPath(digest);
  privateDirectory(path.dirname(destination));
  const staging = path.join(path.dirname(destination), `.publish-${randomUUID()}`);
  try {
    fs.copyFileSync(source, staging, fs.constants.COPYFILE_EXCL);
    if (await hashFile(staging) !== digest.replace(/^sha256:/, "") || (expectedSize !== undefined && fs.statSync(staging).size !== expectedSize)) fail("staged blob digest or size mismatch");
    fs.chmodSync(staging, 0o400);
    const fd = fs.openSync(staging, "r");
    try { fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
    try { fs.linkSync(staging, destination); }
    catch (error) { if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error; }
    return await verifyBlob(digest, expectedSize);
  } finally { fs.rmSync(staging, { force: true }); }
}
export async function publishBytes(bytes: string | Buffer): Promise<string> {
  const digest = `sha256:${sha256(bytes)}`;
  const staging = path.join(privateDirectory(path.join(layerCache(), "staging")), randomUUID());
  try {
    fs.writeFileSync(staging, bytes, { flag: "wx", mode: 0o600 });
    await publishBlob(staging, digest);
    return digest;
  } finally { fs.rmSync(staging, { force: true }); }
}
export function atomicJson(filename: string, value: unknown): void {
  privateDirectory(path.dirname(filename));
  const temporary = path.join(path.dirname(filename), `.write-${randomUUID()}`);
  try {
    fs.writeFileSync(temporary, JSON.stringify(value) + "\n", { flag: "wx", mode: 0o600 });
    const fd = fs.openSync(temporary, "r");
    try { fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
    fs.renameSync(temporary, filename);
    const parent = fs.openSync(path.dirname(filename), "r");
    try { fs.fsyncSync(parent); } finally { fs.closeSync(parent); }
  } finally { fs.rmSync(temporary, { force: true }); }
}
export function readJson(filename: string): unknown {
  const stat = fs.lstatSync(filename);
  if (!stat.isFile() || stat.isSymbolicLink() || stat.size > 1024 * 1024) fail("metadata requires a regular file of at most 1 MiB");
  const fd = fs.openSync(filename, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK);
  try {
    if (!fs.fstatSync(fd).isFile()) fail("metadata is not a regular file");
    const bytes = Buffer.alloc(1024 * 1024 + 1);
    let length = 0;
    while (length < bytes.length) { const count = fs.readSync(fd, bytes, length, bytes.length - length, null); if (count === 0) break; length += count; }
    if (length > 1024 * 1024) fail("metadata exceeds 1 MiB");
    return parseMetadata(bytes.subarray(0, length), filename);
  } finally { fs.closeSync(fd); }
}

interface LockOwner { version: 1; token: string; pid: number; host: string }
function readOwner(filename: string): LockOwner {
  const owner = readJson(filename) as Partial<LockOwner>;
  if (owner.version !== 1 || typeof owner.token !== "string" || !Number.isSafeInteger(owner.pid) || owner.pid! <= 0 || typeof owner.host !== "string") fail("workspace writer lock has an uncertain owner");
  return owner as LockOwner;
}
function dead(owner: LockOwner): boolean {
  if (owner.host !== os.hostname()) return false;
  try { process.kill(owner.pid, 0); return false; }
  catch (error) { return (error as NodeJS.ErrnoException).code === "ESRCH"; }
}
/** One writer per workspace. Uncertain ownership always rejects. */
export function acquireWorkspaceLock(workspace: string): () => void {
  const directory = privateDirectory(layerState(workspace));
  const filename = path.join(directory, "writer.json");
  const reclaim = path.join(directory, "writer-recovery");
  const owner: LockOwner = { version: 1, token: randomUUID(), pid: process.pid, host: os.hostname() };
  const create = () => fs.writeFileSync(filename, JSON.stringify(owner), { flag: "wx", mode: 0o600 });
  if (fs.existsSync(reclaim)) fail("workspace writer lock recovery has an uncertain owner");
  try { create(); }
  catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
    const old = readOwner(filename);
    if (!dead(old)) fail(`workspace writer lock is live or uncertain (PID ${old.pid})`);
    try { fs.mkdirSync(reclaim, { mode: 0o700 }); }
    catch { fail("workspace writer lock is being recovered"); }
    try {
      const current = readOwner(filename);
      if (current.token !== old.token || !dead(current)) fail("workspace writer lock owner changed");
      fs.unlinkSync(filename);
      create();
    } finally { fs.rmdirSync(reclaim); }
  }
  if (fs.existsSync(reclaim)) {
    if (readOwner(filename).token === owner.token) fs.unlinkSync(filename);
    fail("workspace writer lock is being recovered");
  }
  return () => {
    if (fs.existsSync(filename) && readOwner(filename).token === owner.token) fs.unlinkSync(filename);
  };
}

/** Stream through an owned file. No response body enters an in-memory disk buffer. */
export async function boundedCopy(source: NodeJS.ReadableStream, destination: string | number, limit: number): Promise<number> {
  let size = 0;
  const bound = new Transform({ transform(chunk, _encoding, callback) {
    size += chunk.length;
    callback(size > limit ? new Error(`download exceeds ${limit} bytes`) : null, chunk);
  } });
  const output = typeof destination === "number" ? fs.createWriteStream("", { fd: destination, autoClose: false }) : fs.createWriteStream(destination, { flags: "wx", mode: 0o600 });
  await pipeline(source, bound, output);
  return size;
}
