import { VM, createHttpHooks } from "@earendil-works/gondolin";
import path from "node:path";
import { fileURLToPath } from "node:url";
const __dirname = path.dirname(fileURLToPath(import.meta.url));

async function main() {
  const { httpHooks, env: secretEnv } = createHttpHooks({
    allowedHosts: ["api.anthropic.com"],
    allowedInternalHosts: [],
  });
  const vm = await VM.create({
    sandbox: { imagePath: path.join(__dirname, "assets") },
    dns: { mode: "synthetic", syntheticHostMapping: "per-host" },
    httpHooks,
    env: { ...secretEnv },
    sessionLabel: "m0-2-diag-env",
  });
  try {
    console.log(`VM booted: id=${vm.id}`);

    console.log("\n--- direct-exec /usr/bin/env with ONLY {PATH} passed in ExecOptions.env ---");
    const r1 = await vm.exec(["/usr/bin/env"], { env: { PATH: "/usr/bin:/bin" }, stdout: "buffer", stderr: "buffer" });
    console.log("exitCode", r1.exitCode);
    console.log(r1.stdout);
    console.log("[stderr]", r1.stderr);

    console.log("\n--- direct-exec /usr/bin/env with NO env field at all (undefined) ---");
    const r2 = await vm.exec(["/usr/bin/env"], { stdout: "buffer", stderr: "buffer" });
    console.log("exitCode", r2.exitCode);
    console.log(r2.stdout);
    console.log("[stderr]", r2.stderr);

    console.log("\n--- login-shell exec: env (string form, /bin/sh -lc) ---");
    const r3 = await vm.exec("env", { stdout: "buffer", stderr: "buffer" });
    console.log("exitCode", r3.exitCode);
    console.log(r3.stdout);

    console.log("\n--- check for /etc/profile.d scripts and /etc/environment ---");
    const r4 = await vm.exec(["/bin/sh", "-lc", "echo '-- /etc/environment --'; cat /etc/environment 2>&1; echo '-- /etc/profile.d --'; ls -la /etc/profile.d 2>&1; for f in /etc/profile.d/*; do echo \"== $f ==\"; cat \"$f\"; done 2>&1"], { stdout: "buffer", stderr: "buffer" });
    console.log(r4.stdout);
    console.log("[stderr]", r4.stderr);
  } finally {
    await vm.close();
  }
}
main().catch((e) => { console.error("FAILED", e?.stack || e); process.exitCode = 1; });
