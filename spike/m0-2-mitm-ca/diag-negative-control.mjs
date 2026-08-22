// Negative control: gondolin's own guest init unconditionally exports
// SSL_CERT_FILE / CURL_CA_BUNDLE / REQUESTS_CA_BUNDLE / NODE_EXTRA_CA_CERTS
// for every process (confirmed by reading node_modules/@earendil-works/gondolin
// /dist/src/alpine/init-scripts.js and by an env dump — see
// evidence-02/03-env-*.log). So a "bare" exec with no env override still
// inherits real trust. To get a genuine negative control, override EVERY
// relevant cert env var to a nonexistent path and confirm each tool then
// fails closed, then restore the real bundle and confirm it passes again.
import { VM, createHttpHooks } from "@earendil-works/gondolin";
import path from "node:path";
import { fileURLToPath } from "node:url";
import fs from "node:fs/promises";
const __dirname = path.dirname(fileURLToPath(import.meta.url));

const BOGUS = "/nonexistent/definitely-not-a-cert.crt";
const REAL_MERGED = "/run/gondolin/ca-certificates.crt";
const BASE_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";

function section(t) { console.log(`\n${"=".repeat(70)}\n${t}\n${"=".repeat(70)}`); }

async function run(vm, label, argv, env) {
  const r = await vm.exec(argv, { env, stdout: "buffer", stderr: "buffer" });
  console.log(`\n--- ${label} --- exitCode=${r.exitCode} ok=${r.ok}`);
  if (r.stdout?.trim()) console.log(`[stdout]\n${r.stdout}`);
  if (r.stderr?.trim()) console.log(`[stderr]\n${r.stderr}`);
  return r;
}

async function main() {
  const { httpHooks } = createHttpHooks({ allowedHosts: ["api.anthropic.com", "github.com"], allowedInternalHosts: [] });
  const vm = await VM.create({
    sandbox: { imagePath: path.join(__dirname, "assets") },
    dns: { mode: "synthetic", syntheticHostMapping: "per-host" },
    httpHooks,
    sessionLabel: "m0-2-negative-control",
  });
  try {
    console.log(`VM booted: id=${vm.id}`);

    const bogusAll = {
      PATH: BASE_PATH, HOME: "/root",
      SSL_CERT_FILE: BOGUS, SSL_CERT_DIR: BOGUS,
      CURL_CA_BUNDLE: BOGUS, REQUESTS_CA_BUNDLE: BOGUS,
      NODE_EXTRA_CA_CERTS: BOGUS, GIT_SSL_CAINFO: BOGUS,
    };
    const realAll = {
      PATH: BASE_PATH, HOME: "/root",
      SSL_CERT_FILE: REAL_MERGED,
      CURL_CA_BUNDLE: REAL_MERGED, REQUESTS_CA_BUNDLE: REAL_MERGED,
      NODE_EXTRA_CA_CERTS: REAL_MERGED, GIT_SSL_CAINFO: REAL_MERGED,
    };

    const nodeArgv = ["/usr/bin/node", "-e",
      "fetch('https://api.anthropic.com/v1/messages',{method:'POST',body:'{}'})" +
      ".then(async r=>{console.log('NODE_STATUS',r.status)})" +
      ".catch(e=>{console.error('NODE_FETCH_ERROR',String(e&&e.cause||e));process.exitCode=1});"];
    section("node — ALL cert env vars bogus (true negative control)");
    await run(vm, "node bogus", nodeArgv, bogusAll);
    section("node — all cert env vars pointed at real merged bundle (positive control)");
    await run(vm, "node real", nodeArgv, realAll);

    const curlArgv = ["/usr/bin/curl", "-sS", "--max-time", "20", "https://api.anthropic.com/v1/messages", "-X", "POST", "-d", "{}"];
    section("curl — ALL cert env vars bogus (true negative control)");
    await run(vm, "curl bogus", curlArgv, bogusAll);
    section("curl — all cert env vars pointed at real merged bundle (positive control)");
    await run(vm, "curl real", curlArgv, realAll);

    const gitArgv = ["/usr/bin/git", "ls-remote", "https://github.com/octocat/Hello-World.git"];
    section("git — ALL cert env vars bogus (true negative control)");
    await run(vm, "git bogus", gitArgv, bogusAll);
    section("git — all cert env vars pointed at real merged bundle (positive control)");
    await run(vm, "git real", gitArgv, realAll);

    section("Writing check.go into guest");
    const checkGoSrc = await fs.readFile(path.join(__dirname, "check.go"), "utf8");
    await vm.fs.writeFile("/root/check.go", checkGoSrc);
    const goArgv = ["/usr/bin/go", "run", "/root/check.go"];
    const goExtra = { GOCACHE: "/root/.cache/go-build", GOPATH: "/root/go", GOTMPDIR: "/tmp", CGO_ENABLED: "0", GOTOOLCHAIN: "local" };
    section("go — ALL cert env vars bogus (true negative control)");
    await run(vm, "go bogus", goArgv, { ...bogusAll, ...goExtra });
    section("go — all cert env vars pointed at real merged bundle (positive control)");
    await run(vm, "go real", goArgv, { ...realAll, ...goExtra });
  } finally {
    section("Closing VM");
    await vm.close();
  }
}
main().catch((e) => { console.error("SPIKE FAILED:", e?.stack || e); process.exitCode = 1; });
