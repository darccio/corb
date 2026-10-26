import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, expect, it, vi } from "vitest";
import { runOwnedProcess } from "../../../e2e/helpers/owned-process.ts";
const dirs: string[] = [];
afterEach(() => { vi.restoreAllMocks(); for (const directory of dirs.splice(0)) fs.rmSync(directory, { recursive: true, force: true }); });
const fixture = `const{spawn}=require("node:child_process");process.on("SIGTERM",()=>{});const child=spawn(process.execPath,["-e",'process.on("SIGTERM",()=>{});console.log("descendant="+process.pid);setInterval(()=>{},1000)'],{stdio:"inherit"});setInterval(()=>{},1000)`;
it.skipIf(process.platform !== "linux")("kills and drains a TERM-resistant CLI and inherited child after a bounded timeout", async () => {
  const result = await runOwnedProcess(process.execPath, ["-e", fixture], { timeoutMs: 300, graceMs: 100, cleanupMs: 1000 });
  expect(result.error?.message).toContain("deadline"); expect(result.survivors).toEqual([]); expect(result.forced.length).toBeGreaterThanOrEqual(2);
  for (const row of result.pids) expect(fs.existsSync(`/proc/${row.pid}/exe`)).toBe(false);
});
it.skipIf(process.platform !== "linux")("drains an orphan after the caller force-kills only its CLI", async () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "corb-cli-cleanup-")); dirs.push(directory); const file = path.join(directory, "pid");
  const script = `require("node:fs").writeFileSync(${JSON.stringify(file)},String(process.pid));${fixture}`;
  let killed = false;
  const result = await runOwnedProcess(process.execPath, ["-e", script], { timeoutMs: 2000, graceMs: 100, cleanupMs: 100,
    output: (text) => { if (!killed && text.includes("descendant=")) { killed = true; process.kill(Number(fs.readFileSync(file, "utf8")), "SIGKILL"); } } });
  expect(result.error?.message).toContain("descendants survived"); expect(result.survivors).toEqual([]); expect(result.forced.length).toBeGreaterThan(0);
});
it.skipIf(process.platform !== "linux")("closes and drains owned children after an output assertion fails", async () => {
  const result = await runOwnedProcess(process.execPath, ["-e", fixture], { timeoutMs: 2000, graceMs: 100, cleanupMs: 1000, output: () => { throw Error("probe assertion failed"); } });
  expect(result.error?.message).toBe("probe assertion failed"); expect(result.survivors).toEqual([]);
});
it.skipIf(process.platform !== "linux")("cancels and drains an owned CLI without touching an unrelated process", async () => {
  const controller = new AbortController();
  const result = await runOwnedProcess(process.execPath, ["-e", fixture], { timeoutMs: 2000, graceMs: 100, cleanupMs: 1000, signal: controller.signal, output: () => controller.abort() });
  expect(result.error?.message).toContain("cancelled"); expect(result.survivors).toEqual([]); expect(() => process.kill(process.pid, 0)).not.toThrow();
});

it.skipIf(process.platform !== "linux")("does not signal a separate owned session while draining a failed one", async () => {
  const [failed, independent] = await Promise.all([
    runOwnedProcess(process.execPath, ["-e", fixture], { timeoutMs: 300, graceMs: 100, cleanupMs: 1000 }),
    runOwnedProcess(process.execPath, ["-e", 'setTimeout(()=>console.log("INDEPENDENT_OK"),700)'], { timeoutMs: 2000, graceMs: 100, cleanupMs: 1000 }),
  ]);
  expect(failed.error).toBeDefined(); expect(failed.survivors).toEqual([]);
  expect(independent.error).toBeUndefined(); expect(independent.code).toBe(0); expect(independent.output).toContain("INDEPENDENT_OK"); expect(independent.forced).toEqual([]);
});

it.skipIf(process.platform !== "linux")("kills the direct handle and other verified descendants when discovery and one identity fail", async () => {
  const original = fs.readdirSync; const read = fs.readFileSync; let failed = false; let direct: string | undefined;
  vi.spyOn(fs, "readdirSync").mockImplementation(((directory: fs.PathLike, options: unknown) => { if (directory === "/proc" && failed) throw Object.assign(Error("induced discovery failure"), { code: "EIO" }); return original(directory, options as never); }) as typeof fs.readdirSync);
  vi.spyOn(fs, "readFileSync").mockImplementation(((filename: fs.PathOrFileDescriptor, options: unknown) => { if (failed && direct !== undefined && filename === `/proc/${direct}/stat`) throw Object.assign(Error("induced identity failure"), { code: "EIO" }); return read(filename, options as never); }) as typeof fs.readFileSync);
  const result = await runOwnedProcess(process.execPath, ["-e", 'console.log("direct="+process.pid);' + fixture], { timeoutMs: 2000, graceMs: 100, cleanupMs: 1000,
    output: (text) => { direct ??= /direct=(\d+)/.exec(text)?.[1]; setTimeout(() => { failed = true; }, 150); } });
  expect(result.error?.message).toBe("induced discovery failure"); expect(result.uncertain).toBe(true); expect(result.survivors).toEqual([]);
  expect(result.forced.length).toBeGreaterThanOrEqual(2);
  for (const row of result.pids) expect(fs.existsSync(`/proc/${row.pid}/exe`)).toBe(false);
});
