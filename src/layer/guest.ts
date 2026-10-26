import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import type { VM } from "@earendil-works/gondolin";
import { fail } from "./validate.ts";
const packageRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const BASE_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";
export function guestLayerSource(): string { return fs.readFileSync(path.join(packageRoot, "image/helpers/layer.mjs"), "utf8"); }
export async function layerGuest<T>(vm: VM, action: string, input: unknown = {}): Promise<T> {
  const serialized = JSON.stringify(input);
  if (Buffer.byteLength(serialized) > 64 * 1024 ** 2) fail("guest layer plan exceeds 64 MiB");
  const result = await vm.exec(["/usr/bin/node", "--input-type=module", "-e", guestLayerSource(), "--", "--corb-layer-internal", action], {
    stdin: Buffer.from(serialized), env: { PATH: BASE_PATH }, stdout: "buffer", stderr: "buffer", signal: AbortSignal.timeout(120_000),
  });
  if (!result.ok) fail(`guest ${action} failed: ${(result.stderr || result.stdout).slice(-8000)}`);
  if (Buffer.byteLength(result.stdout) > 8 * 1024 ** 2) fail("guest layer evidence exceeds 8 MiB");
  return JSON.parse(result.stdout) as T;
}
