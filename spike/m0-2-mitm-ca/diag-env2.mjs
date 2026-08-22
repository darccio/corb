import { VM, createHttpHooks } from "@earendil-works/gondolin";
import path from "node:path";
import { fileURLToPath } from "node:url";
const __dirname = path.dirname(fileURLToPath(import.meta.url));

async function main() {
  const created = createHttpHooks({
    allowedHosts: ["api.anthropic.com"],
    allowedInternalHosts: [],
  });
  console.log("--- createHttpHooks() returned env object ---");
  console.log(JSON.stringify(created.env, null, 2));

  // Boot WITHOUT passing that env at all, to see if the trust vars still appear.
  const vm = await VM.create({
    sandbox: { imagePath: path.join(__dirname, "assets") },
    dns: { mode: "synthetic", syntheticHostMapping: "per-host" },
    httpHooks: created.httpHooks,
    // env field omitted entirely on purpose
    sessionLabel: "m0-2-diag-env2",
  });
  try {
    console.log(`VM booted: id=${vm.id}`);
    console.log("\n--- direct-exec /usr/bin/env, VM.create called with NO env field at all ---");
    const r1 = await vm.exec(["/usr/bin/env"], { env: { PATH: "/usr/bin:/bin" }, stdout: "buffer", stderr: "buffer" });
    console.log("exitCode", r1.exitCode);
    console.log(r1.stdout);
    console.log("[stderr]", r1.stderr);
  } finally {
    await vm.close();
  }
}
main().catch((e) => { console.error("FAILED", e?.stack || e); process.exitCode = 1; });
