// M0.1 spike driver.
//
// Boots a Gondolin micro-VM and runs two checks inside it:
//
//   1. Real-endpoint protocol check (no API key needed): `curl -v` against
//      api.anthropic.com. TLS/ALPN negotiation completes before any
//      API-key-gated request logic runs, so curl's verbose banner shows what
//      protocol was actually negotiated even though the request itself will
//      get a 401/400 JSON error.
//
//   2. Local streaming test: a script inside the guest consumes a chunked
//      response from a local test server (stream-server.mjs, run separately
//      on the host loopback) via Node's global fetch, logging a timestamp
//      per chunk. This proves whether Gondolin's egress mediation preserves
//      incremental delivery end-to-end.
//
// Usage:
//   node stream-server.mjs <port> --bind <hostIp> [--http]   (separately)
//   node run-spike.mjs <port> --bind <hostIp> [--http]       (this script)
//
// The two must agree on port, bind address and scheme. <hostIp> must be a
// real address the host is reachable at (not 127.0.0.1 — see the note in
// stream-server.mjs about why guest-side loopback traffic never reaches it).

import { VM, createHttpHooks } from "@earendil-works/gondolin";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

const port = Number(process.argv[2] || 8443);
const useHttp = process.argv.includes("--http");
const skipCurl = process.argv.includes("--skip-curl");
const bindIdx = process.argv.indexOf("--bind");
const bindHost = bindIdx !== -1 ? process.argv[bindIdx + 1] : "127.0.0.1";
const scheme = useHttp ? "http" : "https";
const localUrl = `${scheme}://${bindHost}:${port}/stream`;

function section(title) {
  console.log(`\n${"=".repeat(70)}\n${title}\n${"=".repeat(70)}`);
}

async function main() {
  const { httpHooks, env: secretEnv } = createHttpHooks({
    allowedHosts: ["api.anthropic.com", bindHost],
    allowedInternalHosts: [bindHost],
  });

  section("Booting VM");
  const vm = await VM.create({
    sandbox: { imagePath: path.join(__dirname, "assets") },
    dns: { mode: "synthetic", syntheticHostMapping: "per-host" },
    httpHooks,
    env: {
      NODE_EXTRA_CA_CERTS: "/run/gondolin/ca-certificates.crt",
      ...secretEnv,
    },
    sessionLabel: "m0-1-http2-spike",
  });

  try {
    console.log(`VM booted: id=${vm.id}`);

    if (skipCurl) {
      section("Check 1: SKIPPED (--skip-curl)");
    } else {
      section("Check 1: TLS/ALPN negotiation against api.anthropic.com (no API key)");
      const curlResult = await vm.exec(
        [
          "/usr/bin/curl",
          "-v",
          "--max-time",
          "20",
          "--cacert",
          "/run/gondolin/ca-certificates.crt",
          "https://api.anthropic.com/v1/messages",
          "-X",
          "POST",
          "-d",
          "{}",
        ],
        { stdout: "buffer", stderr: "buffer" },
      );
      console.log(`--- curl exitCode=${curlResult.exitCode} ok=${curlResult.ok} ---`);
      console.log("--- curl stdout ---");
      console.log(curlResult.stdout);
      console.log("--- curl stderr (verbose TLS/ALPN log is here) ---");
      console.log(curlResult.stderr);
    }

    section(`Check 2: incremental streaming delivery from local test server (${localUrl})`);
    await vm.fs.writeFile("/root/guest-stream-check.mjs", await readLocalFile("guest-stream-check.mjs"));
    const streamResult = await vm.exec(
      ["/usr/bin/node", "/root/guest-stream-check.mjs", localUrl],
      { stdout: "buffer", stderr: "buffer" },
    );
    console.log(`--- node stream check exitCode=${streamResult.exitCode} ok=${streamResult.ok} ---`);
    console.log("--- stream check stdout (per-chunk timestamps are here) ---");
    console.log(streamResult.stdout);
    console.log("--- stream check stderr ---");
    console.log(streamResult.stderr);
  } finally {
    section("Closing VM");
    await vm.close();
  }
}

async function readLocalFile(name) {
  const fs = await import("node:fs/promises");
  return fs.readFile(path.join(__dirname, name), "utf8");
}

main().catch((err) => {
  console.error("SPIKE FAILED:", err?.stack || err);
  process.exitCode = 1;
});
