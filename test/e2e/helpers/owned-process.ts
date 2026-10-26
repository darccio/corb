import fs from "node:fs";
import { spawn } from "node:child_process";

interface OwnedPid { pid: number; parent: number; session: number; start: string; args: string[] }
export interface OwnedResult { code: number | null; output: string; pids: OwnedPid[]; forced: number[]; survivors: number[]; error?: Error }
let unsafe = false;
function identity(pid: number): Omit<OwnedPid, "args"> | undefined {
  try {
    const text = fs.readFileSync(`/proc/${pid}/stat`, "utf8"); const fields = text.slice(text.lastIndexOf(")") + 2).split(" ");
    if (fields[0] === "Z") return undefined;
    return { pid, parent: Number(fields[1]), session: Number(fields[3]), start: fields[19]! };
  } catch (error) { if (["ENOENT", "ESRCH"].includes((error as NodeJS.ErrnoException).code!)) return undefined; throw error; }
}
const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

/** Each detached CLI owns a POSIX session. SDK children inherit it, even after their parent exits. */
export async function runOwnedProcess(command: string, args: string[], options: {
  cwd?: string; env?: NodeJS.ProcessEnv; timeoutMs?: number; graceMs?: number; cleanupMs?: number; signal?: AbortSignal;
  observe?: (pid: number, argv: string[]) => void; output?: (text: string) => void;
} = {}): Promise<OwnedResult> {
  if (unsafe) throw Error("previous owned process cleanup was uncertain; refusing another VM group");
  const child = spawn(command, args, { cwd: options.cwd, env: options.env, detached: true, stdio: ["ignore", "pipe", "pipe"] });
  const known = new Map<number, OwnedPid>(); const forced = new Set<number>(); const observed = new Set<number>();
  let output = ""; let outputBytes = 0; let error: Error | undefined; let forceTimer: ReturnType<typeof setTimeout> | undefined;
  const grace = options.graceMs ?? 10_000; const cleanup = options.cleanupMs ?? 5000;
  const live = () => [...known.values()].filter((row) => identity(row.pid)?.start === row.start);
  function sample(notify = true) {
    if (child.pid === undefined) return;
    const rows = fs.readdirSync("/proc").filter((name) => /^\d+$/.test(name)).map((name) => identity(Number(name))).filter((row) => row !== undefined);
    for (let pass = 0; pass < 5; pass++) for (const row of rows) {
      if (row.session !== child.pid && !(known.has(row.parent) && identity(row.parent)?.start === known.get(row.parent)!.start)) continue;
      const previous = known.get(row.pid); if (previous && previous.start !== row.start) continue;
      if (!previous) {
        let argv: string[]; try { argv = fs.readFileSync(`/proc/${row.pid}/cmdline`, "utf8").split("\0").filter(Boolean); } catch (cause) { if ((cause as NodeJS.ErrnoException).code === "ENOENT") continue; throw cause; }
        known.set(row.pid, { ...row, args: argv });
      }
      if (notify && !observed.has(row.pid) && known.get(row.pid)!.args.some((arg) => /(?:^|\/)qemu-system-/.test(arg))) { observed.add(row.pid); options.observe?.(row.pid, known.get(row.pid)!.args); }
    }
  }
  function signalOwned(signal: NodeJS.Signals) {
    for (const row of live()) { try { process.kill(row.pid, signal); if (signal === "SIGKILL") forced.add(row.pid); } catch (cause) { if ((cause as NodeJS.ErrnoException).code !== "ESRCH") throw cause; } }
  }
  const abort = (cause: unknown) => {
    error ??= cause instanceof Error ? cause : Error(String(cause));
    if (forceTimer !== undefined) return;
    child.kill("SIGTERM");
    forceTimer = setTimeout(() => {
      try { sample(false); signalOwned("SIGKILL"); } catch (failure) { error ??= failure as Error; }
      child.stdout.destroy(); child.stderr.destroy();
    }, grace);
  };
  const data = (chunk: Buffer) => {
    const accepted = chunk.subarray(0, 8 * 1024 ** 2 - outputBytes); outputBytes += accepted.length; output += accepted.toString();
    try { if (accepted.length !== chunk.length) throw Error("owned CLI output exceeded 8 MiB"); options.output?.(accepted.toString()); } catch (cause) { abort(cause); }
  };
  child.stdout.on("data", data); child.stderr.on("data", data); child.on("error", abort);
  const cancelled = () => abort(Error("owned CLI cancelled")); options.signal?.addEventListener("abort", cancelled, { once: true });
  const timer = setTimeout(() => abort(Error("owned CLI exceeded command deadline")), options.timeoutMs ?? 180_000);
  const poll = setInterval(() => { try { sample(); } catch (cause) { abort(cause); } }, 100);
  let drainTask: Promise<void> | undefined;
  async function drain() {
    try {
      sample(false);
      if (live().length > 0) {
        error ??= Error("owned descendants survived CLI exit"); signalOwned("SIGTERM");
        const termDeadline = Date.now() + cleanup;
        while (live().length > 0 && Date.now() < termDeadline) { await sleep(20); sample(false); }
        if (live().length > 0) { signalOwned("SIGKILL"); const killDeadline = Date.now() + cleanup; while (live().length > 0 && Date.now() < killDeadline) { await sleep(20); sample(false); } }
      }
    } catch (cause) { error ??= cause as Error; unsafe = true; }
  }
  child.once("exit", () => { drainTask ??= drain(); });
  let code: number | null = null;
  try {
    if (options.signal?.aborted) cancelled();
    code = await new Promise<number | null>((resolve) => child.once("close", resolve));
  } finally {
    clearTimeout(timer); clearInterval(poll); if (forceTimer !== undefined) clearTimeout(forceTimer);
    options.signal?.removeEventListener("abort", cancelled);
    await (drainTask ??= drain());
  }
  const survivors = live().map((row) => row.pid); if (survivors.length > 0) { unsafe = true; error ??= Error("owned VM children survived bounded cleanup"); }
  return { code, output, pids: [...known.values()], forced: [...forced], survivors, ...(error === undefined ? {} : { error }) };
}
