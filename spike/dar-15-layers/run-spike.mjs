import fs from "node:fs";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { VmCheckpoint } from "@earendil-works/gondolin";
import { base, bootstrap, runtime, log, run, save, read, options, boot, protectedHashes, checkpoint, sha256, diskInfo } from "./common.mjs";
import { GATES } from "./verify-copy.ts";

const action = process.argv[2];

async function baseline() {
  log("baseline", { base, bootstrap });
  const vm = await boot("base-install", options("base-install", { build: true }));
  try {
    save("protected-base", { hashes: await protectedHashes(vm, "protected-base") });
    await run(vm, "base-db", "cat /etc/alpine-release; cat /etc/apk/repositories; cat /etc/apk/world; cat /lib/apk/db/installed");
    await run(vm, "apk-version", "/opt/corb-build/apk.static --version");
    const update = await run(vm, "apk-update-https", "/opt/corb-build/apk.static update", { required: false });
    if (!update.ok) {
      if (!/certificate|TLS|SSL/i.test(update.stderr + update.stdout)) throw new Error("apk update failed without a TLS trust error");
      await run(vm, "apk-http-fallback", "sed -i 's@https://@http://@g' /etc/apk/repositories; /opt/corb-build/apk.static update");
    }
    await run(vm, "apk-simulate", "/opt/corb-build/apk.static add --simulate go postgresql16-client");
    await run(vm, "tools-before", "node --version; pi --version; /usr/local/libexec/real-git --version; bindfs --version");
    const start = performance.now();
    await run(vm, "apk-add", "/opt/corb-build/apk.static --no-cache add go postgresql16-client");
    save("base-install-time", { ms: performance.now() - start });
    await run(vm, "tools-after", "node --version; pi --version; /usr/local/libexec/real-git --version; bindfs --version; go version; psql --version; for c in npm npx su sudo doas apk apk.static; do command -v \"$c\" || true; done", { required: false });
    save("protected-after-install", { hashes: await protectedHashes(vm, "protected-after-install") });
    await run(vm, "installed-after", "cat /lib/apk/db/installed");
    await checkpoint(vm, "original-layer");
  } finally {
    await vm.close();
  }
}

async function sessionChecks(vm, label) {
  await run(vm, label + "-agent-tools", "set -e; id; go version; psql --version; node --version; pi --version; /usr/local/libexec/real-git --version; cd /work/work; git -P status --short; bindfs --version", { agent: true });
  await run(vm, label + "-workspace", "printf layer-write > /work/work/from-layer; cat /work/work/from-layer; cat /run/corb/gate.json; test -z \"$(ls -A /opt/corb-build)\"", { agent: true });
  await run(vm, label + "-tls", "curl --max-time 30 -sSfI https://dl-cdn.alpinelinux.org/alpine/v3.23/main/x86_64/APKINDEX.tar.gz; node -e 'fetch(\"https://dl-cdn.alpinelinux.org/alpine/v3.23/main/x86_64/APKINDEX.tar.gz\").then(r=>console.log(r.status))'", { agent: true });
  const models = JSON.stringify({ providers: { dar15: { baseUrl: "https://dar15-model.invalid/v1", api: "openai-completions", apiKey: "synthetic-test-value", models: [{ id: "dar15" }] } } });
  const setup = `const fs = require("node:fs"); fs.mkdirSync("/home/agent/.pi/agent", { recursive: true }); fs.writeFileSync("/home/agent/.pi/agent/models.json", ${JSON.stringify(models)});`;
  const setupResult = await vm.exec(["/usr/local/bin/dropcap", "1000", "1000", "/usr/bin/node", "-e", setup], { env: { PATH: "/usr/local/bin:/usr/bin:/bin", HOME: "/home/agent" }, stdout: "buffer", stderr: "buffer" });
  if (!setupResult.ok) throw new Error("Synthetic Pi model setup failed: " + setupResult.stderr);
  const pi = await run(vm, label + "-pi", "cd /work/work; timeout 20 pi --provider dar15 --model dar15 --no-session --mode json -p 'Reply with the word ready'", { agent: true });
  if (!pi.stdout.includes("ready")) throw new Error("Real Pi session did not emit the synthetic reply");
  log(label + "-host-write", { content: fs.readFileSync(path.join(runtime, "workspace/from-layer"), "utf8") });
}

async function resume(name) {
  const layer = read(name);
  const before = sha256(layer.path);
  const image = layer.base.assetDir;
  const vm = await boot(name + "-resume", options(name + "-resume", { image, workspace: true, verify: true }), layer.path);
  try {
    log("resume-file-sha256", { before, after: sha256(layer.path), same: before === sha256(layer.path) });
    await sessionChecks(vm, name);
    const gates = [];
    for (const gate of GATES) {
      const result = await gate(vm);
      gates.push(result);
      log("verify-gate", result);
    }
    const managers = await run(vm, "apk-static-path", "command -v apk.static || true");
    const hashes = await protectedHashes(vm, "protected-resume");
    const baselineHashes = read(name === "original-layer" ? "protected-base" : "protected-fixed-base").hashes;
    log("protected-comparison", { same: hashes === baselineHashes, before: baselineHashes, after: hashes });
    save(name + "-verification", { gates, apkStaticAbsent: !managers.stdout.trim(), protectedMatch: hashes === baselineHashes });
  } finally {
    await vm.close();
  }
  log("checkpoint-disk-info", diskInfo(layer.path));
}

async function fixedInstall(name, packages) {
  const image = read("image-fixed");
  const vm = await boot(name, options(name, { image: image.assetDir, build: true }));
  try {
    const before = await protectedHashes(vm, name + "-protected-before");
    save("protected-fixed-base", { hashes: before });
    await run(vm, name + "-tools-before", "set -e; node --version; pi --version; /usr/local/libexec/real-git --version; bindfs --version");
    await run(vm, name + "-base-db", "cat /lib/apk/db/installed");
    const beforeFiles = await persistentManifest(vm, name + "-base-files-before");
    let update = await run(vm, name + "-update", "/opt/corb-build/apk.static update", { required: false });
    if (!update.ok && /HTTP 502|Bad Gateway/.test(update.stdout + update.stderr)) {
      update = await run(vm, name + "-update-https-retry", "/opt/corb-build/apk.static update", { required: false });
    }
    if (!update.ok && /certificate verify|certificate.*(?:fail|invalid)|unable to get local issuer|SSL certificate/i.test(update.stdout + update.stderr)) {
      update = await run(vm, name + "-update-http-trust-fallback", "sed -i 's@https://@http://@g' /etc/apk/repositories; /opt/corb-build/apk.static update", { required: false });
    }
    if (!update.ok) throw new Error("Repository update failed before package installation");
    await run(vm, name + "-simulate", "/opt/corb-build/apk.static add --simulate " + packages);
    const start = performance.now();
    await run(vm, name + "-install", "/opt/corb-build/apk.static --no-cache add " + packages);
    save(name + "-install-time", { ms: performance.now() - start });
    const after = await protectedHashes(vm, name + "-protected-after");
    log(name + "-protected-comparison", { same: before === after });
    if (before !== after) throw new Error("Refusing a layer that changed protected base files");
    const afterFiles = await persistentManifest(vm, name + "-base-files-after");
    log(name + "-base-file-changes", {
      changed: [...beforeFiles].filter(([file, digest]) => afterFiles.get(file) !== digest).map(([file]) => file),
      addedCount: [...afterFiles.keys()].filter(file => !beforeFiles.has(file)).length,
    });
    const requested = packages.split(/\s+/);
    const checks = ["node --version", "pi --version", "/usr/local/libexec/real-git --version", "bindfs --version"];
    if (requested.includes("go")) checks.push("go version");
    if (requested.includes("postgresql16-client")) checks.push("psql --version");
    await run(vm, name + "-tools", "set -e; " + checks.join("; "));
    await run(vm, name + "-db-after", "cat /lib/apk/db/installed");
    await cleanRemovals(vm, name);
    await checkpoint(vm, name, image);
  } finally {
    await vm.close();
  }
}

async function persistentManifest(vm, label) {
  const result = await vm.exec(["/bin/sh", "-c", "find / -xdev -type f -exec sha256sum '{}' ';' | sort"], {
    stdout: "buffer", stderr: "buffer", signal: AbortSignal.timeout(180_000),
  });
  if (!result.ok) throw new Error("Persistent file manifest failed: " + result.stderr);
  const digest = createHash("sha256").update(result.stdout).digest("hex");
  const filename = path.join(runtime, label + "-" + digest.slice(0, 8) + ".sha256");
  fs.writeFileSync(filename, result.stdout);
  const entries = new Map(result.stdout.trim().split("\n").filter(Boolean).map(line => [line.slice(66), line.slice(0, 64)]));
  log(label, { files: entries.size, manifestSha256: digest, file: filename });
  return entries;
}

async function cleanRemovals(vm, label) {
  const gate = GATES.find(candidate => candidate.name === "gateRemovals");
  log(label + "-removals-before-cleanup", await gate(vm));
  await run(vm, label + "-remove-restored-tools", "rm -f /usr/bin/npm /usr/bin/npx /bin/su /usr/bin/su /usr/bin/sudo /usr/bin/doas /sbin/apk");
  const result = await gate(vm);
  log(label + "-removals-after-cleanup", result);
  if (!result.ok) throw new Error("Removals gate still fails after cleanup");
}

async function negative(kind) {
  const layer = read(process.argv[4] ?? "cleaned-original");
  const name = "negative-" + kind;
  const vm = await boot(name, options(name, { image: layer.base.assetDir, build: true }), layer.path);
  let bad;
  try {
    const mutations = {
      suid: "cp /bin/busybox /usr/local/bin/dar15-suid; chmod 4755 /usr/local/bin/dar15-suid",
      apk: "cp /opt/corb-build/apk.static /usr/local/bin/apk.static; chmod 755 /usr/local/bin/apk.static",
      allowlist: "cp /bin/busybox /usr/local/bin/dar15-suid; chmod 4755 /usr/local/bin/dar15-suid; printf '\\n/usr/local/bin/dar15-suid\\n' >> /etc/corb/suid-allowlist.txt",
      dropcap: "printf 'DAR15' >> /usr/local/bin/dropcap",
    };
    if (!mutations[kind]) throw new Error("Unknown negative case " + kind);
    await run(vm, name + "-mutation", mutations[kind]);
    bad = await checkpoint(vm, name, layer.base);
  } finally {
    await vm.close();
  }
  const checked = await boot(name + "-check", options(name + "-check", { image: layer.base.assetDir, workspace: true, verify: true }), bad.path);
  try {
    const gates = [];
    for (const gate of GATES) {
      const result = await gate(checked);
      gates.push(result);
      log(name + "-gate", result);
    }
    const manager = await run(checked, name + "-static-manager", "command -v apk.static || true");
    const hashes = await protectedHashes(checked, name + "-protected");
    const baseline = layer.base.buildId === base.buildId ? "protected-base" : "protected-fixed-base";
    const protectedMatch = hashes === read(baseline).hashes;
    const result = { kind, gates, apkStaticAbsent: !manager.stdout.trim(), protectedMatch };
    result.sevenNameRemovals = {
      ok: gates.find(gate => gate.name === "removals").ok && result.apkStaticAbsent,
      names: ["npm", "npx", "su", "sudo", "doas", "apk", "apk.static"],
    };
    result.accepted = gates.every(gate => gate.ok) && result.apkStaticAbsent && protectedMatch;
    const suid = gates.find(gate => gate.name === "suid");
    result.targetDetected = kind === "suid" ? !suid.ok
      : kind === "apk" ? !result.sevenNameRemovals.ok && !result.apkStaticAbsent
      : !protectedMatch;
    log(name + "-verdict", result);
    save(name + "-verification", result);
    if (result.accepted || !result.targetDetected) throw new Error("Negative layer mutation was not detected by its target check");
  } finally {
    await checked.close();
  }
}

async function cleanOriginal() {
  const layer = read("original-layer");
  const vm = await boot("cleaned-original", options("cleaned-original", { build: true }), layer.path);
  try {
    await cleanRemovals(vm, "cleaned-original");
    const hashes = await protectedHashes(vm, "cleaned-original-protected");
    if (hashes !== read("protected-base").hashes) throw new Error("Cleanup changed a protected base file");
    await checkpoint(vm, "cleaned-original", layer.base);
  } finally {
    await vm.close();
  }
}

async function stack() {
  const first = read("go-only");
  const vm = await boot("stack", options("stack", { image: first.base.assetDir, build: true }), first.path);
  let second;
  try {
    await run(vm, "stack-install", "/opt/corb-build/apk.static --no-cache add postgresql16-client");
    await cleanRemovals(vm, "stack");
    const hashes = await protectedHashes(vm, "stack-protected");
    if (hashes !== read("protected-fixed-base").hashes) throw new Error("Stacking changed protected base files");
    second = await checkpoint(vm, "stacked-layer", first.base);
  } finally {
    await vm.close();
  }
  const info = diskInfo(second.path);
  log("stack-disk-info", info);
  if (info["full-backing-filename"] !== path.join(first.base.assetDir, "rootfs.ext4")) throw new Error("Stacked checkpoint is not flat");
  const hidden = first.path + ".hidden";
  fs.renameSync(first.path, hidden);
  let checked;
  try {
    checked = await boot("stack-without-first", options("stack-without-first", { image: first.base.assetDir, workspace: true }), second.path);
    await sessionChecks(checked, "stack-without-first");
  } finally {
    if (checked) await checked.close();
    fs.renameSync(hidden, first.path);
  }
  log("stack-size-comparison", { stacked: second.bytes, single: read("fixed-layer").bytes });
}

async function movedBase() {
  const layer = read("fixed-layer");
  const relocated = path.join(runtime, "relocated-base");
  fs.mkdirSync(relocated, { recursive: true });
  for (const name of fs.readdirSync(layer.base.assetDir)) {
    const from = path.join(layer.base.assetDir, name);
    const to = path.join(relocated, name);
    if (!fs.statSync(from).isFile()) continue;
    if (!fs.existsSync(to)) fs.copyFileSync(from, to, fs.constants.COPYFILE_FICLONE);
  }
  const copied = path.join(runtime, "relocated-layer.qcow2");
  fs.copyFileSync(layer.path, copied);
  const before = sha256(copied);
  log("moved-base-before", { sha256: before, info: diskInfo(copied), trailer: VmCheckpoint.load(copied).toJSON(), originalLayerSha256: sha256(layer.path) });
  const vm = await boot("moved-base", options("moved-base", { image: relocated, workspace: true }), copied);
  try {
    await sessionChecks(vm, "moved-base");
    log("moved-base-hash", {
      before, after: sha256(copied), changed: before !== sha256(copied), info: diskInfo(copied),
      trailerAfterRebase: VmCheckpoint.load(copied).toJSON(),
    });
  } finally {
    await vm.close();
  }
}

async function baseControl(imageName) {
  const image = imageName ? read(imageName) : base;
  const label = imageName ? "fixed-base-control" : "base-control";
  const vm = await boot(label, options(label, { image: image.assetDir, workspace: true, verify: true }));
  try {
    if (imageName) save("protected-fixed-base", { hashes: await protectedHashes(vm, "protected-fixed-base") });
    const gates = [];
    for (const gate of GATES) {
      const result = await gate(vm);
      gates.push(result);
      log(label + "-gate", result);
    }
    await run(vm, "base-git-http1", "/usr/local/libexec/real-git -c http.version=HTTP/1.1 ls-remote https://github.com/octocat/Hello-World.git", { required: false });
    await run(vm, "base-git-trust-explicit", "/usr/local/libexec/real-git ls-remote https://github.com/octocat/Hello-World.git", { required: false, env: { GIT_SSL_CAINFO: "/run/gondolin/ca-certificates.crt" } });
    save(label, { gates });
  } finally {
    await vm.close();
  }
}

async function timingControl() {
  for (const gate of [true, false]) {
    const label = gate ? "timing-with-gate" : "timing-without-gate";
    const vm = await boot(label, options(label, { gate }));
    await vm.close();
  }
}

try {
  if (action === "baseline") await baseline();
  else if (action === "resume") await resume(process.argv[3] ?? "original-layer");
  else if (action === "fixed-install") await fixedInstall(process.argv[3] ?? "fixed-layer", process.argv[4] ?? "go postgresql16-client");
  else if (action === "negative") await negative(process.argv[3]);
  else if (action === "stack") await stack();
  else if (action === "moved-base") await movedBase();
  else if (action === "base-control") await baseControl(process.argv[3]);
  else if (action === "clean-original") await cleanOriginal();
  else if (action === "timing-control") await timingControl();
  else throw new Error("Unknown phase: " + action);
} catch (err) {
  console.error(err.stack ?? String(err));
  process.exitCode = 1;
}
