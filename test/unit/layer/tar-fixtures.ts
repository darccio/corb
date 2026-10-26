import { gzipSync } from "node:zlib";
export function tar(rows: Array<{ path: string; type?: string; mode?: number; body?: string | Buffer; link?: string }>, end = true): Buffer {
  const parts: Buffer[] = [];
  for (const row of rows) {
    const body = Buffer.from(row.body ?? ""); const header = Buffer.alloc(512);
    header.write(row.path, 0, 100); header.write((row.mode ?? 0o755).toString(8).padStart(7, "0") + "\0", 100, 8);
    header.write("0000000\0", 108, 8); header.write("0000000\0", 116, 8);
    header.write(body.length.toString(8).padStart(11, "0") + "\0", 124, 12);
    header.fill(32, 148, 156); header.write(row.type ?? "0", 156, 1); header.write(row.link ?? "", 157, 100); header.write("ustar\0", 257, 6);
    const checksum = header.reduce((sum, byte) => sum + byte, 0); header.write(checksum.toString(8).padStart(6, "0") + "\0 ", 148, 8);
    parts.push(header, body, Buffer.alloc((512 - body.length % 512) % 512));
  }
  if (end) parts.push(Buffer.alloc(1024)); return Buffer.concat(parts);
}
export function gzipTar(rows: Parameters<typeof tar>[0]): Buffer { return gzipSync(tar(rows)); }
export function pax(key: string, value: string): string {
  let length = key.length + value.length + 4;
  for (;;) { const text = `${length} ${key}=${value}\n`; if (Buffer.byteLength(text) === length) return text; length = Buffer.byteLength(text); }
}
