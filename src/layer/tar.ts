import fs from "node:fs";
import path from "node:path";
import { createHash, randomUUID } from "node:crypto";
import { createGunzip } from "node:zlib";
import { Readable } from "node:stream";
import { validateSdkArchiveEntries, SDK_ENTRY_LIMIT, SDK_EXPANDED_LIMIT, type SdkArchiveEntry } from "./archive.ts";
import type { LayerPayload } from "./definition.ts";
import { fail } from "./validate.ts";
import { hashFile } from "./state.ts";

class ByteReader {
  private readonly iterator: AsyncIterator<Buffer>;
  private buffer = Buffer.alloc(0);
  private done = false;
  private count = 0;
  private readonly limit: number;
  constructor(stream: AsyncIterable<Buffer>, limit: number) { this.iterator = stream[Symbol.asyncIterator](); this.limit = limit; }
  async take(size: number, eof = false): Promise<Buffer> {
    const parts: Buffer[] = [];
    let remaining = size;
    while (remaining > 0) {
      if (this.buffer.length === 0 && !this.done) {
        const next = await this.iterator.next();
        this.done = next.done === true;
        this.buffer = next.value ?? Buffer.alloc(0);
        this.count += this.buffer.length;
        if (this.count > this.limit) fail("tar expansion exceeds limit");
      }
      if (this.buffer.length === 0 && this.done) {
        if (eof && remaining === size) return Buffer.alloc(0);
        fail("truncated tar archive");
      }
      const consumed = Math.min(remaining, this.buffer.length);
      parts.push(this.buffer.subarray(0, consumed));
      this.buffer = this.buffer.subarray(consumed);
      remaining -= consumed;
    }
    return parts.length === 1 ? parts[0]! : Buffer.concat(parts, size);
  }
}
export interface TarEntry extends SdkArchiveEntry { link: string }
function tarString(bytes: Buffer): string {
  const nul = bytes.indexOf(0);
  const value = nul === -1 ? bytes : bytes.subarray(0, nul);
  try { return new TextDecoder("utf-8", { fatal: true }).decode(value); }
  catch { fail("tar header is not UTF-8"); }
}
function octal(bytes: Buffer): number {
  const text = bytes.toString("ascii").replace(/[\0 ]+$/g, "").trim();
  if (text === "") return 0;
  if (!/^[0-7]+$/.test(text)) fail("unsupported tar numeric encoding");
  const value = Number.parseInt(text, 8);
  if (!Number.isSafeInteger(value)) fail("excessive tar numeric field");
  return value;
}
function paxFields(bytes: Buffer): Record<string, string> {
  const result: Record<string, string> = {};
  let offset = 0;
  while (offset < bytes.length) {
    const space = bytes.indexOf(32, offset);
    if (space === -1 || !/^[1-9][0-9]*$/.test(bytes.subarray(offset, space).toString())) fail("malformed PAX length");
    const length = Number(bytes.subarray(offset, space).toString());
    if (length <= space - offset + 2 || offset + length > bytes.length || bytes[offset + length - 1] !== 10) fail("malformed PAX record");
    const text = new TextDecoder("utf-8", { fatal: true }).decode(bytes.subarray(space + 1, offset + length - 1));
    const equals = text.indexOf("=");
    const key = text.slice(0, equals);
    if (equals <= 0 || key in result) fail("duplicate or malformed PAX key");
    result[key] = text.slice(equals + 1);
    offset += length;
  }
  return result;
}
/** Consume data before the next header. Extended names remain untrusted until final validation. */
export async function walkTar(stream: AsyncIterable<Buffer>, visit: (entry: TarEntry, chunks: AsyncIterable<Buffer>) => Promise<void>, options: { limit?: number; entries?: number; requireEnd?: boolean } = {}): Promise<void> {
  const reader = new ByteReader(stream, options.limit ?? SDK_EXPANDED_LIMIT + 128 * 1024 ** 2);
  let extended: Record<string, string> | undefined;
  let longName: string | undefined;
  let count = 0;
  let ended = false;
  for (;;) {
    const header = await reader.take(512, true);
    if (header.length === 0) break;
    if (header.every((byte) => byte === 0)) {
      const second = await reader.take(512, true);
      if ((options.requireEnd && second.length !== 512) || (second.length !== 0 && !second.every((byte) => byte === 0))) fail("malformed tar end marker");
      ended = true;
      for (;;) { const padding = await reader.take(512, true); if (padding.length === 0) break; if (!padding.every((byte) => byte === 0)) fail("data after tar end marker"); }
      break;
    }
    const checksum = octal(header.subarray(148, 156));
    let calculated = 0;
    for (let index = 0; index < 512; index++) calculated += index >= 148 && index < 156 ? 32 : header[index]!;
    if (checksum !== calculated) fail("invalid tar header checksum");
    const magic = tarString(header.subarray(257, 263));
    if (magic !== "" && magic !== "ustar" && magic !== "ustar ") fail("unsupported tar header format");
    const type = tarString(header.subarray(156, 157));
    let size = octal(header.subarray(124, 136));
    const mode = octal(header.subarray(100, 108));
    const rawName = [magic === "ustar" ? tarString(header.subarray(345, 500)) : "", tarString(header.subarray(0, 100))].filter(Boolean).join("/");
    const special = type === "x" || type === "L";
    if (type === "g" || type === "K") fail("unsupported global PAX or GNU link header");
    if (!special && extended?.size !== undefined) {
      if (!/^(?:0|[1-9][0-9]*)$/.test(extended.size)) fail("invalid PAX size");
      size = Number(extended.size);
    }
    if (!Number.isSafeInteger(size) || size > SDK_EXPANDED_LIMIT) fail("excessive tar entry");
    async function* data() { let remaining = size; while (remaining > 0) { const length = Math.min(remaining, 64 * 1024); remaining -= length; yield await reader.take(length); } }
    if (special) {
      if (size > 1024 * 1024 || (type === "x" && extended !== undefined) || (type === "L" && longName !== undefined)) fail("excessive or duplicate tar extended header");
      const parts: Buffer[] = [];
      for await (const chunk of data()) parts.push(chunk);
      const bytes = Buffer.concat(parts);
      if (type === "x") extended = paxFields(bytes);
      else longName = tarString(bytes);
    } else {
      count++;
      if (count > (options.entries ?? SDK_ENTRY_LIMIT)) fail("too many tar entries");
      const entry: TarEntry = { path: extended?.path ?? longName ?? rawName, size, mode, type: type === "" || type === "0" ? "file" : type === "5" ? "directory" : type, link: tarString(header.subarray(157, 257)), ...(extended === undefined ? {} : { pax: extended }) };
      let consumed = 0;
      async function* tracked() { for await (const chunk of data()) { consumed += chunk.length; yield chunk; } }
      await visit(entry, tracked());
      if (consumed !== size) fail("tar consumer did not consume complete entry");
      extended = undefined;
      longName = undefined;
    }
    const padding = (512 - size % 512) % 512;
    if (padding > 0) await reader.take(padding);
  }
  if (extended !== undefined || longName !== undefined || (options.requireEnd && !ended)) fail("incomplete tar archive");
}
export interface PayloadTree { hash: string; entries: Array<{ path: string; type: string; mode: number; size: number; sha256?: string }> }
/** Stage under numeric filenames until every effective archive path passes the bounded validator. */
export async function stageSdkArchive(archive: string, payload: LayerPayload, destination: string): Promise<PayloadTree> {
  if (await hashFile(archive, 512 * 1024 ** 2) !== payload.sha256) fail("SDK archive digest mismatch");
  fs.mkdirSync(destination, { mode: 0o700 });
  const raw = path.join(path.dirname(destination), `.sdk-raw-${randomUUID()}`); fs.mkdirSync(raw, { mode: 0o700 });
  const entries: TarEntry[] = [];
  const hashes: string[] = [];
  const stream = fs.createReadStream(archive).pipe(createGunzip());
  try {
    await walkTar(stream, async (entry, chunks) => {
      entries.push(entry);
      const hash = createHash("sha256");
      const fd = fs.openSync(path.join(raw, String(entries.length - 1)), "wx", 0o600);
      try { for await (const chunk of chunks) { hash.update(chunk); fs.writeSync(fd, chunk); } }
      finally { fs.closeSync(fd); }
      hashes.push(hash.digest("hex"));
    }, { requireEnd: true });
    const validated = validateSdkArchiveEntries(entries, payload);
    const tree: PayloadTree["entries"] = [];
    const indices = new Map(entries.map((entry, index) => [entry.path.replace(/\/$/, "").split("/").slice(payload["strip-components"]).join("/"), index]));
    for (const entry of validated) {
      const index = indices.get(entry.path)!;
      const target = path.join(destination, entry.path);
      fs.mkdirSync(path.dirname(target), { recursive: true, mode: 0o700 });
      if (entry.type === "directory") fs.mkdirSync(target, { recursive: true, mode: 0o700 });
      else { fs.copyFileSync(path.join(raw, String(index)), target, fs.constants.COPYFILE_EXCL); fs.chmodSync(target, entry.mode); }
      tree.push({ path: entry.path, type: entry.type, mode: entry.mode, size: entry.size, ...(entry.type === "file" ? { sha256: hashes[index]! } : {}) });
    }
    fs.rmSync(raw, { recursive: true });
    function readonly(directory: string) { for (const name of fs.readdirSync(directory)) { const child = path.join(directory, name); if (fs.lstatSync(child).isDirectory()) readonly(child); } fs.chmodSync(directory, 0o555); }
    readonly(destination);
    const represented = new Set(tree.map((entry) => entry.path));
    for (const row of fs.readdirSync(destination, { recursive: true, withFileTypes: true })) {
      const relative = path.relative(destination, path.join(row.parentPath, row.name)).split(path.sep).join("/");
      if (row.isDirectory() && !represented.has(relative)) tree.push({ path: relative, type: "directory", mode: 0o555, size: 0 });
    }
    tree.sort((a, b) => a.path < b.path ? -1 : a.path > b.path ? 1 : 0);
    return { hash: createHash("sha256").update(JSON.stringify(tree)).digest("hex"), entries: tree };
  } catch (error) { stream.destroy(); fs.rmSync(raw, { recursive: true, force: true }); fs.rmSync(destination, { recursive: true, force: true }); throw error; }
}
export async function tarBuffer(bytes: Buffer): Promise<Map<string, { entry: TarEntry; bytes: Buffer }>> {
  const result = new Map<string, { entry: TarEntry; bytes: Buffer }>();
  await walkTar(Readable.from([bytes]), async (entry, chunks) => {
    if (result.has(entry.path)) fail(`duplicate tar entry '${entry.path}'`);
    const parts: Buffer[] = [];
    for await (const chunk of chunks) parts.push(chunk);
    result.set(entry.path, { entry, bytes: Buffer.concat(parts, entry.size) });
  });
  return result;
}
