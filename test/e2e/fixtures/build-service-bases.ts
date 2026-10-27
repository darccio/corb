import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import { runOwnedProcess } from "../helpers/owned-process.ts";
import { OwnedDockerBuild } from "../helpers/owned-docker.ts";

if (process.env.CORB_E2E !== "1") throw Error("CORB_E2E=1 is required");
const root = path.resolve(process.argv[2]!);
const repo = process.cwd();
fs.mkdirSync(root, { recursive: true, mode: 0o700 });
const configs: string[] = [];
for (const name of ["a", "b"]) {
  const config = JSON.parse(fs.readFileSync(path.join(repo, "image/corb-image.json"), "utf8"));
  config.init.rootfsInitExtra = path.join(repo, "image/overlay/init-extra.sh");
  for (const entry of config.postBuild.copy) {
    const local = path.resolve(repo, "image", entry.src.replace("{arch}", "amd64"));
    entry.src = fs.existsSync(local) ? local : path.resolve("/home/dario/Code/corb/image", entry.src.replace("{arch}", "amd64"));
  }
  const index = config.postBuild.commands.indexOf("node /tmp/corb-build/corb-package-coherence.mjs");
  if (index < 0) throw Error("production coherence step is absent");
  config.postBuild.commands.splice(index, 0, ...(name === "a" ? ["apk add --no-cache lua5.4-libs"] : [
    "apk add --no-cache tree",
    "addgroup -g 1601 consumer && adduser -D -u 1601 -G consumer -h /var/lib/consumer -s /sbin/nologin consumer",
    "mkdir -p /var/lib/consumer && echo dar21-existing-consumer > /var/lib/consumer/state && chown -R consumer:consumer /var/lib/consumer",
  ]));
  const filename = path.join(root, `base-${name}.json`);
  fs.writeFileSync(filename, JSON.stringify(config, null, 2) + "\n", { mode: 0o600 }); configs.push(filename);
}
console.log(JSON.stringify({ root, configs }));
if (process.argv[3] === "--build") {
  const results = []; const runtime = fs.mkdtempSync(path.join(os.tmpdir(), "c21-build-"));
  const controller = new AbortController(); const cancel = () => controller.abort();
  process.once("SIGINT", cancel); process.once("SIGTERM", cancel); const deadline = setTimeout(cancel, 28 * 60_000);
  try {
    const dockerConfig = path.join(root, "docker"); fs.mkdirSync(dockerConfig, { mode: 0o700 });
    fs.writeFileSync(path.join(dockerConfig, "config.json"), '{"auths":{}}', { flag: "wx", mode: 0o600 });
    for (const [index, filename] of configs.entries()) {
      if (controller.signal.aborted) throw Error("owned build group cancelled");
      const name = index === 0 ? "a" : "b"; const temporary = fs.mkdtempSync(path.join(os.tmpdir(), `c21-work-${name}-`));
      let docker: OwnedDockerBuild | undefined; let poll: ReturnType<typeof setInterval> | undefined; let discoveryError: unknown;
      try {
        const env = { PATH: process.env.PATH, TMPDIR: temporary, DOCKER_CONFIG: dockerConfig, CORB_CONFIG_DIR: path.join(root, name, "config"), CORB_STATE_DIR: path.join(root, name, "state"), CORB_CACHE_DIR: path.join(root, name, "cache"), GONDOLIN_IMAGE_STORE: path.join(root, name, "store"), GONDOLIN_SESSIONS_DIR: runtime };
        docker = new OwnedDockerBuild(path.join(root, name, "cache/image-build/x86_64"), temporary, env);
        poll = setInterval(() => { try { docker!.sample(); } catch (error) { discoveryError = error; controller.abort(); } }, 500);
        const result = await runOwnedProcess(process.execPath, ["src/cli.ts", "image", "build", "--config", filename, "--tag", `dar21-${name}:acceptance`], { cwd: repo, env, signal: controller.signal, timeoutMs: 12 * 60_000 });
        fs.writeFileSync(path.join(root, `base-${name}.log`), result.output, { mode: 0o600 });
        results.push({ name, ...result, error: result.error?.message });
        fs.writeFileSync(path.join(root, "build-results.json"), JSON.stringify(results, null, 2), { mode: 0o600 });
        if (discoveryError) throw discoveryError;
        if (result.error || result.code !== 0 || result.survivors.length > 0) throw Error(`base ${name} failed: ${result.error?.message ?? result.code}. See base-${name}.log`);
      } finally {
        if (poll) clearInterval(poll);
        if (docker) { const stopped = docker.cleanup(); docker.record(path.join(root, `docker-${name}.json`), stopped); if (stopped.length > 0) throw Error("owned Docker container survived build process exit"); }
        fs.rmSync(temporary, { recursive: true, force: true });
      }
      if (fs.readdirSync(runtime).length !== 0) throw Error(`SDK registry survived base ${name} at ${runtime}`);
    }
  } finally {
    clearTimeout(deadline); process.removeListener("SIGINT", cancel); process.removeListener("SIGTERM", cancel);
    if (fs.readdirSync(runtime).length !== 0) throw Error(`SDK registry survived at ${runtime}`);
    fs.rmdirSync(runtime);
  }
}
