import { VM, createHttpHooks } from "@earendil-works/gondolin";
import path from "node:path";
import { fileURLToPath } from "node:url";
const __dirname = path.dirname(fileURLToPath(import.meta.url));

async function main() {
  const { httpHooks } = createHttpHooks({ allowedHosts: ["api.anthropic.com"], allowedInternalHosts: [] });
  const vm = await VM.create({
    sandbox: { imagePath: path.join(__dirname, "assets") },
    dns: { mode: "synthetic", syntheticHostMapping: "per-host" },
    httpHooks,
    sessionLabel: "m0-2-diag-ca-install",
  });
  try {
    console.log(`VM booted: id=${vm.id}`);
    const r = await vm.exec(["/bin/sh", "-lc",
      "echo '-- update-ca-certificates present? --'; command -v update-ca-certificates; " +
      "echo '-- installed mitm cert in /usr/local/share/ca-certificates? --'; ls -la /usr/local/share/ca-certificates/ 2>&1; " +
      "echo '-- manual update-ca-certificates run --'; update-ca-certificates; echo EXIT=$?; " +
      "echo '-- system bundle cert count after manual run --'; grep -c 'BEGIN CERTIFICATE' /etc/ssl/certs/ca-certificates.crt"
    ], { stdout: "buffer", stderr: "buffer" });
    console.log("exitCode", r.exitCode);
    console.log(r.stdout);
    console.log("[stderr]", r.stderr);
  } finally {
    await vm.close();
  }
}
main().catch((e) => { console.error("FAILED", e?.stack || e); process.exitCode = 1; });
