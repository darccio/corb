// M0.2 spike driver — R3: does trust in Gondolin's injected MITM CA
// propagate to node, curl, git and go inside the guest, and does each need
// its own explicit env var, or does Alpine's system trust store already
// cover it?
//
// For each tool this runs a TLS-handshake-only check (real endpoint,
// api.anthropic.com or github.com; no API key needed — a 401/HTTP response
// is a pass, a TLS/cert error is a fail) TWICE:
//   1. "bare" — no tool-specific CA env var set at all.
//   2. "explicit" — the documented env var pointed at
//      /run/gondolin/ca-certificates.crt.
//
// A clean split (bare fails, explicit passes) means the env var is load-
// bearing for that tool. "Both pass" means the system trust store already
// covers it and the env var is redundant for that tool.
//
// Usage: node run-spike.mjs

import { VM, createHttpHooks } from "@earendil-works/gondolin";
import path from "node:path";
import { fileURLToPath } from "node:url";
import fs from "node:fs/promises";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const GONDOLIN_CA = "/run/gondolin/ca-certificates.crt";
const BASE_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";

function section(title) {
  console.log(`\n${"=".repeat(70)}\n${title}\n${"=".repeat(70)}`);
}

async function run(vm, label, argv, env) {
  const result = await vm.exec(argv, {
    env,
    stdout: "buffer",
    stderr: "buffer",
  });
  console.log(`\n--- ${label} --- exitCode=${result.exitCode} ok=${result.ok}`);
  if (result.stdout?.trim()) {
    console.log(`[stdout]\n${result.stdout}`);
  }
  if (result.stderr?.trim()) {
    console.log(`[stderr]\n${result.stderr}`);
  }
  return result;
}

async function main() {
  const { httpHooks, env: secretEnv } = createHttpHooks({
    allowedHosts: ["api.anthropic.com", "github.com"],
    allowedInternalHosts: [],
  });

  section("Booting VM");
  const vm = await VM.create({
    sandbox: { imagePath: path.join(__dirname, "assets") },
    dns: { mode: "synthetic", syntheticHostMapping: "per-host" },
    httpHooks,
    // Deliberately NOT setting any tool-specific CA env var here at the VM
    // level — each check below sets (or withholds) its own var per-exec, so
    // the "bare" runs are a true baseline with nothing pre-configured.
    env: { ...secretEnv },
    sessionLabel: "m0-2-mitm-ca-spike",
  });

  try {
    console.log(`VM booted: id=${vm.id}`);

    section("Locating tool binaries (login shell, $PATH search)");
    const which = await run(
      vm,
      "which node/curl/git/go",
      ["/bin/sh", "-lc", "which node; which curl; which git; which go"],
      { PATH: BASE_PATH },
    );
    console.log(which.stdout);

    section("Diagnostic: does the system trust store already contain the Gondolin CA?");
    await run(
      vm,
      "compare /etc/ssl/certs/ca-certificates.crt vs /run/gondolin/ca-certificates.crt",
      [
        "/bin/sh",
        "-lc",
        "echo '--- system bundle cert count ---'; grep -c 'BEGIN CERTIFICATE' /etc/ssl/certs/ca-certificates.crt; " +
          "echo '--- gondolin merged bundle cert count ---'; grep -c 'BEGIN CERTIFICATE' /run/gondolin/ca-certificates.crt; " +
          "echo '--- gondolin-mitm-ca present in system bundle? ---'; " +
          "(openssl crl2pkcs7 -nocrl -certfile /etc/ssl/certs/ca-certificates.crt | openssl pkcs7 -print_certs -noout | grep -i gondolin && echo YES || echo NO); " +
          "echo '--- byte-identical? ---'; cmp -s /etc/ssl/certs/ca-certificates.crt /run/gondolin/ca-certificates.crt && echo IDENTICAL || echo DIFFERENT",
      ],
      { PATH: BASE_PATH },
    );

    // ---- node -------------------------------------------------------
    const nodeArgv = [
      "/usr/bin/node",
      "-e",
      "fetch('https://api.anthropic.com/v1/messages',{method:'POST',body:'{}'})" +
        ".then(async r=>{console.log('NODE_STATUS',r.status);console.log('NODE_BODY',await r.text())})" +
        ".catch(e=>{console.error('NODE_FETCH_ERROR',String(e&&e.stack||e));process.exitCode=1});",
    ];
    section("node — bare (no NODE_EXTRA_CA_CERTS)");
    await run(vm, "node bare", nodeArgv, { PATH: BASE_PATH, HOME: "/root" });
    section("node — explicit (NODE_EXTRA_CA_CERTS set)");
    await run(vm, "node explicit", nodeArgv, {
      PATH: BASE_PATH,
      HOME: "/root",
      NODE_EXTRA_CA_CERTS: GONDOLIN_CA,
    });

    // ---- curl -------------------------------------------------------
    const curlArgv = [
      "/usr/bin/curl",
      "-v",
      "--max-time",
      "20",
      "https://api.anthropic.com/v1/messages",
      "-X",
      "POST",
      "-d",
      "{}",
    ];
    section("curl — bare (no CURL_CA_BUNDLE)");
    await run(vm, "curl bare", curlArgv, { PATH: BASE_PATH });
    section("curl — explicit (CURL_CA_BUNDLE set)");
    await run(vm, "curl explicit", curlArgv, { PATH: BASE_PATH, CURL_CA_BUNDLE: GONDOLIN_CA });

    // ---- git ----------------------------------------------------------
    const gitArgv = ["/usr/bin/git", "ls-remote", "https://github.com/octocat/Hello-World.git"];
    section("git — bare (no GIT_SSL_CAINFO)");
    await run(vm, "git bare", gitArgv, { PATH: BASE_PATH, HOME: "/root" });
    section("git — explicit (GIT_SSL_CAINFO set)");
    await run(vm, "git explicit", gitArgv, {
      PATH: BASE_PATH,
      HOME: "/root",
      GIT_SSL_CAINFO: GONDOLIN_CA,
    });

    // ---- go -------------------------------------------------------
    section("Writing check.go into guest");
    const checkGoSrc = await fs.readFile(path.join(__dirname, "check.go"), "utf8");
    await vm.fs.writeFile("/root/check.go", checkGoSrc);

    const goArgv = ["/usr/bin/go", "run", "/root/check.go"];
    const goBaseEnv = {
      PATH: BASE_PATH,
      HOME: "/root",
      GOCACHE: "/root/.cache/go-build",
      GOPATH: "/root/go",
      GOTMPDIR: "/tmp",
      CGO_ENABLED: "0",
      GOTOOLCHAIN: "local",
    };
    section("go — bare (no SSL_CERT_FILE)");
    await run(vm, "go bare", goArgv, goBaseEnv);
    section("go — explicit (SSL_CERT_FILE set)");
    await run(vm, "go explicit", goArgv, { ...goBaseEnv, SSL_CERT_FILE: GONDOLIN_CA });
  } finally {
    section("Closing VM");
    await vm.close();
  }
}

main().catch((err) => {
  console.error("SPIKE FAILED:", err?.stack || err);
  process.exitCode = 1;
});
