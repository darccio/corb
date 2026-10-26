import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawn, execFileSync } from "node:child_process";
import { expect, it } from "vitest";
const enabled = process.env.CORB_E2E === "1" && process.env.CORB_E2E_LAYER_CONCURRENCY === "1";
const hash = (filename: string) => execFileSync("sha256sum", [filename], { encoding: "utf8", timeout: 120_000 }).split(" ")[0]!;

// The coordinator must grant a separate two-VM slot before enabling this test.
it.skipIf(!enabled)("resumes two isolated overlays without changing the generation or canonical base", async () => {
  const root = process.env.CORB_E2E_LAYER_EXISTING!; const directory = process.env.CORB_E2E_LAYER_GENERATION!;
  expect(path.isAbsolute(root)).toBe(true); expect(path.isAbsolute(directory)).toBe(true);
  const available = /^MemAvailable:\s+(\d+) kB/m.exec(fs.readFileSync("/proc/meminfo", "utf8"));
  expect(Number(available?.[1]) * 1024).toBeGreaterThan(4 * 1024 ** 3);
  expect(execFileSync("ps", ["-eo", "comm="], { encoding: "utf8" }).split("\n").filter((name) => name.trim().startsWith("qemu-system"))).toEqual([]);
  const metadata = JSON.parse(fs.readFileSync(path.join(directory, "metadata.json"), "utf8")); const checkpoint = path.join(directory, "checkpoint.qcow2");
  expect(hash(checkpoint)).toBe(metadata.checkpoint.sha256);
  const backing = JSON.parse(execFileSync("qemu-img", ["info", "--output=json", checkpoint], { encoding: "utf8", timeout: 30_000 }));
  expect(backing["backing-filename"]).toBe(metadata.base.assets.rootfs.path);
  for (const asset of Object.values(metadata.base.assets) as Array<{ path: string; sha256: string }>) expect(hash(asset.path)).toBe(asset.sha256);
  const runtime = fs.mkdtempSync(path.join(os.tmpdir(), "c23-pair-")); fs.chmodSync(runtime, 0o700);
  const env = { PATH: process.env.PATH, CORB_CONFIG_DIR: path.join(root, "config"), CORB_STATE_DIR: path.join(root, "state"), CORB_CACHE_DIR: path.join(root, "cache"), GONDOLIN_IMAGE_STORE: path.join(root, "store"), GONDOLIN_SESSIONS_DIR: runtime };
  fs.copyFileSync("test/e2e/fixtures/layer-go/concurrent.mjs", path.join(root, "project/concurrent.mjs"));
  for (const token of ["A", "B"]) for (const suffix of ["started", "json"]) fs.rmSync(path.join(root, `project/concurrent-${token}.${suffix}`), { force: true });
  const records: Array<{ token: string; code: number | null; output: string; vms: Array<{ pid: number; overlay: string }> }> = [];
  async function run(token: string) {
    const child = spawn(process.execPath, ["src/cli.ts", "run", "--workspace", "go", ...(token === "prime" ? ["--trust-config"] : []), "--", "--extension", "/work/project/concurrent.mjs", "--print", token], { env, stdio: ["ignore", "pipe", "pipe"] });
    let output = ""; const descendants = new Set([child.pid!]); const vms = new Map<number, string>(); let observedError: unknown;
    child.stdout.on("data", (data) => { output += data; if (output.length > 1024 ** 2) child.kill("SIGTERM"); }); child.stderr.on("data", (data) => { output += data; if (output.length > 1024 ** 2) child.kill("SIGTERM"); });
    child.on("error", (error) => { observedError = error; });
    const poll = setInterval(() => {
      try {
        const rows = execFileSync("ps", ["-eo", "pid=,ppid=,comm=,args="], { encoding: "utf8", timeout: 5000 }).split("\n").map((row) => row.trim().split(/\s+/));
        for (let pass = 0; pass < 5; pass++) for (const [pid, parent, name, ...args] of rows) if (descendants.has(Number(parent))) {
          descendants.add(Number(pid)); if (!name?.startsWith("qemu-system") || vms.has(Number(pid))) continue;
          const argv = args.join(" "); expect(argv).toContain("-m 1G -smp 2");
          const overlay = /-drive file=([^,]+),format=qcow2/.exec(argv)?.[1]; expect(overlay).toBeDefined(); expect(overlay).not.toBe(checkpoint);
          const info = JSON.parse(execFileSync("qemu-img", ["info", "--force-share", "--output=json", overlay!], { encoding: "utf8", timeout: 5000 }));
          expect(info["backing-filename"]).toBe(checkpoint); vms.set(Number(pid), overlay!);
        }
      } catch (error) { observedError = error; child.kill("SIGTERM"); }
    }, 100);
    const timer = setTimeout(() => child.kill("SIGTERM"), 120_000); const kill = setTimeout(() => child.kill("SIGKILL"), 130_000);
    let code: number | null;
    try { code = await new Promise<number | null>((resolve) => child.on("close", resolve)); }
    finally { clearInterval(poll); clearTimeout(timer); clearTimeout(kill); }
    records.push({ token, code, output, vms: [...vms].map(([pid, overlay]) => ({ pid, overlay })) });
    if (observedError) throw observedError; expect(code, output).toBe(0); expect(output).toContain(token === "prime" ? "CORB_RESUME_PRIMED" : `CORB_RESUME_ISOLATED_${token}`);
    expect(vms.size).toBe(1);
    for (const [pid, overlay] of vms) { expect(fs.existsSync(overlay)).toBe(false); expect(() => process.kill(pid, 0)).toThrow(); }
  }
  try {
    await run("prime"); const outcomes = await Promise.allSettled([run("A"), run("B")]);
    for (const outcome of outcomes) if (outcome.status === "rejected") throw outcome.reason;
    expect(records[1]!.vms[0]!.overlay).not.toBe(records[2]!.vms[0]!.overlay);
    for (const token of ["A", "B"]) expect(JSON.parse(fs.readFileSync(path.join(root, `project/concurrent-${token}.json`), "utf8"))).toEqual({ token, uid: 1000 });
    expect(hash(checkpoint)).toBe(metadata.checkpoint.sha256);
    for (const asset of Object.values(metadata.base.assets) as Array<{ path: string; sha256: string }>) expect(hash(asset.path)).toBe(asset.sha256);
    expect(fs.readdirSync(runtime)).toEqual([]);
  } finally {
    fs.writeFileSync(path.join(root, "concurrency-results.json"), JSON.stringify({ checkpoint, metadata: { generation: metadata.generation, checkpoint: metadata.checkpoint, base: metadata.base }, records }, null, 2), { mode: 0o600 });
    if (fs.readdirSync(runtime).length === 0) fs.rmdirSync(runtime);
  }
}, 300_000);
