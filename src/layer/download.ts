import fs from "node:fs";
import https from "node:https";
import { boundedCopy } from "./state.ts";
import { fail } from "./validate.ts";

export function assertDownloadUrl(value: string, hosts: readonly string[]): URL {
  const url = new URL(value);
  if (url.protocol !== "https:" || url.username !== "" || url.password !== "" || url.hash !== "" || url.port !== "") fail("archive download requires an HTTPS URL without credentials or port");
  if (!hosts.some((pattern) => new RegExp(`^${pattern.split("*").map((part) => part.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")).join(".*")}$`, "i").test(url.hostname))) fail(`archive download host '${url.hostname}' is not in build-hosts`);
  return url;
}
export async function downloadInput(value: string, filename: string, hosts: readonly string[], limit: number, size?: number): Promise<void> {
  const deadline = Date.now() + 120_000;
  let current = value;
  try {
    for (let redirects = 0; redirects <= 5; redirects++) {
      const url = assertDownloadUrl(current, hosts);
      const response = await new Promise<import("node:http").IncomingMessage>((resolve, reject) => {
        const request = https.get(url, { headers: { "Accept-Encoding": "identity" }, signal: AbortSignal.timeout(Math.max(1, deadline - Date.now())) }, resolve);
        request.on("error", reject);
      });
      if ([301, 302, 303, 307, 308].includes(response.statusCode!)) {
        response.destroy();
        if (!response.headers.location) fail("archive redirect has no location");
        current = new URL(response.headers.location, url).href;
        continue;
      }
      if (response.statusCode !== 200 || (response.headers["content-encoding"] !== undefined && response.headers["content-encoding"] !== "identity")) {
        response.destroy();
        fail(`archive download failed (${response.statusCode}). Exact versions can disappear. Explicitly refresh with corb image pin`);
      }
      const length = response.headers["content-length"];
      if (length !== undefined && (!/^\d+$/.test(length) || Number(length) > limit || (size !== undefined && Number(length) !== size))) { response.destroy(); fail("archive download size mismatch"); }
      const actual = await boundedCopy(response, filename, limit);
      if (size !== undefined && actual !== size) fail("archive download size differs from signed index");
      return;
    }
    fail("too many archive download redirects");
  } catch (error) { fs.rmSync(filename, { force: true }); throw error; }
}
