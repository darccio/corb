import fs from "node:fs";
import { runOwnedProcess } from "../helpers/owned-process.ts";

const [receipt, seconds, command, ...args] = process.argv.slice(2);
if (!receipt || !command || !/^[1-9][0-9]*$/.test(seconds!)) throw Error("receipt, seconds and command are required");
const controller = new AbortController(); const cancel = () => controller.abort();
process.once("SIGINT", cancel); process.once("SIGTERM", cancel);
try {
  const result = await runOwnedProcess(command, args, { cwd: process.cwd(), env: process.env, signal: controller.signal, timeoutMs: Number(seconds) * 1000, output: (text) => process.stdout.write(text) });
  fs.writeFileSync(receipt, JSON.stringify({ ...result, output: undefined, error: result.error?.message }, null, 2), { mode: 0o600 });
  if (result.error || result.code !== 0 || result.uncertain || result.survivors.length > 0) throw Error(`owned group failed: ${result.error?.message ?? result.code}`);
} finally { process.removeListener("SIGINT", cancel); process.removeListener("SIGTERM", cancel); }
