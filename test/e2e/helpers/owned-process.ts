import fs from "node:fs";
import { spawn } from "node:child_process";

interface OwnedPid { pid: number; parent: number; session: number; start: string; args: string[] }
export interface OwnedResult { code: number | null; output: string; pids: OwnedPid[]; forced: number[]; survivors: number[]; uncertain: boolean; error?: Error }
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
  let output = ""; let outputBytes = 0; let error: Error | undefined; let forceTimer: ReturnType<typeof setTimeout> | undefined; let closeTimer: ReturnType<typeof setTimeout> | undefined;
  let uncertain = false; let directExited = false; const unknown = new Set<number>();
  let finishClose: (code: number | null) => void = () => {};
  const grace = options.graceMs ?? 10_000; const cleanup = options.cleanupMs ?? 5000;
  const uncertainError = (cause: unknown) => { uncertain = true; unsafe = true; error ??= cause instanceof Error ? cause : Error(String(cause)); };
  const live = () => {
    const result: OwnedPid[] = [];
    for (const row of known.values()) {
      if (row.pid === child.pid && directExited) continue;
      try { if (identity(row.pid)?.start === row.start) result.push(row); }
      catch (cause) { unknown.add(row.pid); uncertainError(cause); }
    }
    return result;
  };
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
  function discover() { try { sample(false); } catch (cause) { uncertainError(cause); } }
  function signalOwned(signal: NodeJS.Signals) {
    for (const row of live()) {
      try { process.kill(row.pid, signal); if (signal === "SIGKILL") forced.add(row.pid); }
      catch (cause) { if ((cause as NodeJS.ErrnoException).code !== "ESRCH") { unknown.add(row.pid); uncertainError(cause); } }
    }
  }
  function killDirect() { try { if (child.kill("SIGKILL") && child.pid !== undefined) forced.add(child.pid); } catch (cause) { uncertainError(cause); } }
  function force() {
    discover(); killDirect(); signalOwned("SIGKILL");
    child.stdout.destroy(); child.stderr.destroy();
  }
  const abort = (cause: unknown) => {
    error ??= cause instanceof Error ? cause : Error(String(cause));
    if (forceTimer !== undefined) return;
    try { child.kill("SIGTERM"); } catch (failure) { uncertainError(failure); }
    forceTimer = setTimeout(() => {
      force();
      closeTimer = setTimeout(() => { uncertainError(Error("owned CLI close did not drain after escalation")); force(); finishClose(null); }, cleanup * 2 + 1000);
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
    discover();
    if (live().length > 0) {
      error ??= Error("owned descendants survived CLI exit"); signalOwned("SIGTERM");
      const termDeadline = Date.now() + cleanup;
      while (live().length > 0 && Date.now() < termDeadline) { await sleep(20); discover(); }
      if (live().length > 0) {
        killDirect(); signalOwned("SIGKILL"); const killDeadline = Date.now() + cleanup;
        while (live().length > 0 && Date.now() < killDeadline) { await sleep(20); discover(); }
      }
    }
  }
  child.once("exit", () => { directExited = true; if (child.pid !== undefined) unknown.delete(child.pid); drainTask ??= drain(); });
  let code: number | null = null;
  try {
    if (options.signal?.aborted) cancelled();
    code = await new Promise<number | null>((resolve) => { finishClose = resolve; child.once("close", resolve); });
  } finally {
    clearTimeout(timer); clearInterval(poll); if (forceTimer !== undefined) clearTimeout(forceTimer); if (closeTimer !== undefined) clearTimeout(closeTimer);
    options.signal?.removeEventListener("abort", cancelled);
    await (drainTask ??= drain());
  }
  const survivors = [...new Set([...live().map((row) => row.pid), ...unknown])]; if (survivors.length > 0) { unsafe = true; error ??= Error("owned VM children survived bounded cleanup"); }
  return { code, output, pids: [...known.values()], forced: [...forced], survivors, uncertain, ...(error === undefined ? {} : { error }) };
}
