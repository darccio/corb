/** Close the VM and drain its work before the caller can remove owned input staging. */
export async function withBoundedVm<T, V extends { close(): Promise<void> }>(create: () => Promise<V>, work: (vm: V) => Promise<T>, closing: (vm: V) => void, timeoutMs = 15 * 60_000): Promise<T> {
  let vm: V | undefined; let task: Promise<T> | undefined; let interrupted: Error | undefined;
  let rejectInterruption: (error: Error) => void;
  const interruption = new Promise<never>((_resolve, reject) => { rejectInterruption = reject; });
  void interruption.catch(() => {});
  const stop = (reason: string) => { interrupted ??= new Error(reason); rejectInterruption(interrupted); if (vm) void vm.close().catch(() => {}); };
  const sigint = () => stop("VM operation interrupted by SIGINT"); const sigterm = () => stop("VM operation interrupted by SIGTERM");
  process.on("SIGINT", sigint); process.on("SIGTERM", sigterm);
  const timer = setTimeout(() => stop("VM operation exceeded its overall limit"), timeoutMs);
  let result: T;
  try {
    vm = await create();
    if (interrupted) throw interrupted;
    task = Promise.resolve().then(() => work(vm!));
    result = await Promise.race([task, interruption]);
  } finally {
    clearTimeout(timer);
    try { if (vm) { try { closing(vm); } finally { await vm.close(); } } }
    finally {
      if (task) await task.catch(() => {});
      process.off("SIGINT", sigint); process.off("SIGTERM", sigterm);
    }
  }
  if (interrupted) throw interrupted;
  return result;
}
