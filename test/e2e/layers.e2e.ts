import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import { randomUUID } from "node:crypto";
import { spawn, execFileSync } from "node:child_process";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import { selectLayerWorkspace } from "../../src/layer/context.ts";
import { bindLayerArtifact } from "../../src/layer/pins.ts";
import { runLayerBuild } from "../../src/commands/image-layer.ts";
import { resolveRuntimeImage } from "../../src/vm/image.ts";

const enabled = process.env.CORB_E2E === "1";
const repo = process.cwd();
const digest = (filename: string) => execFileSync("sha256sum", [filename], { encoding: "utf8", timeout: 120_000 }).split(" ")[0]!;
const goDefinition = `[image.layer]
packages=[]
build-hosts=["go.dev","dl.google.com"]
[[image.layer.payload]]
name="go"
url="https://go.dev/dl/go1.27.3.linux-amd64.tar.gz"
sha256="65efbc80fdc1fa2cd2631cad5b481777a68e8725f34e89f50fc6ac714e379b40"
arch="x86_64"
destination="/opt/corb/toolchains/go"
strip-components=1
path=["bin"]
[[image.layer.runtime-dir]]
path="/run/go-work"
mode="0750"
owner="agent"
group="agent"
`;

describe.skipIf(!enabled)("production layer lifecycle (serial real VMs)", () => {
  let root: string; let runtime: string; let env: NodeJS.ProcessEnv; let base: string;
  const records: Array<{ args: string[]; code: number | null; pids: number[] }> = [];
  const baseline = new Map<string, string>();
  const file = (workspace: string) => path.join(root, "config/workspaces", workspace, "corb.toml");
  const sum = (workspace: string) => path.join(path.dirname(file(workspace)), "corb.sum");
  const generation = (workspace: string) => {
    const bases = path.join(root, "state/layers", workspace, "x86_64/bases");
    const dir = path.join(bases, fs.readdirSync(bases)[0]!);
    const pointer = path.join(dir, "current.json");
    return { pointer, directory: path.join(dir, "generations", JSON.parse(fs.readFileSync(pointer, "utf8")).generation) };
  };
  async function cli(args: string[], expected = 0) {
    const child = spawn(process.execPath, ["src/cli.ts", ...args], { cwd: repo, env, stdio: ["ignore", "pipe", "pipe"] });
    let text = ""; const pids = new Set<number>(); const descendants = new Set([child.pid!]);
    const append = (chunk: Buffer) => { text += chunk.toString(); if (text.length > 8 * 1024 ** 2) child.kill("SIGTERM"); };
    child.stdout.on("data", append); child.stderr.on("data", append);
    const sample = () => {
      const rows = execFileSync("ps", ["-eo", "pid=,ppid=,comm="], { encoding: "utf8", timeout: 5000 }).trim().split("\n").map((row) => row.trim().split(/\s+/));
      for (let pass = 0; pass < 5; pass++) for (const [pid, parent, name] of rows) if (descendants.has(Number(parent))) {
        descendants.add(Number(pid)); if (name?.startsWith("qemu-system")) pids.add(Number(pid));
      }
    };
    const poll = setInterval(sample, 200); const timeout = setTimeout(() => child.kill("SIGTERM"), 14 * 60_000);
    const kill = setTimeout(() => child.kill("SIGKILL"), 15 * 60_000);
    let code: number | null;
    try { code = await new Promise<number | null>((resolve, reject) => { child.on("error", reject); child.on("close", resolve); }); }
    finally { clearInterval(poll); clearTimeout(timeout); clearTimeout(kill); }
    for (const match of text.matchAll(/(?:host PID|builder host PID) (\d+)/g)) pids.add(Number(match[1]));
    for (const pid of pids) { let alive = false; try { process.kill(pid, 0); alive = true; } catch (error) { if ((error as NodeJS.ErrnoException).code !== "ESRCH") throw error; } expect(alive, `VM ${pid} survived CLI exit`).toBe(false); }
    records.push({ args, code, pids: [...pids] });
    fs.writeFileSync(path.join(root, `command-${records.length}.log`), text, { mode: 0o600 });
    expect(code, text.slice(-16000)).toBe(expected); return text;
  }
  const run = (workspace: string, trust = false) => cli(["run", "--workspace", workspace, ...(trust ? ["--trust-config"] : []), "--", "--extension", "/work/project/probe.mjs", "--print", "unused"]);
  beforeAll(() => {
    const parent = process.env.CORB_E2E_LAYER_ROOT ?? path.join(repo, "image/build/dar-23/e2e");
    fs.mkdirSync(parent, { recursive: true }); root = fs.mkdtempSync(path.join(parent, "lifecycle-"));
    runtime = fs.mkdtempSync(path.join(os.tmpdir(), "c23-")); fs.chmodSync(runtime, 0o700);
    base = fs.realpathSync(process.env.CORB_E2E_LAYER_BASE ?? resolveRuntimeImage().assetDir);
    const manifest = JSON.parse(fs.readFileSync(path.join(base, "manifest.json"), "utf8"));
    for (const name of ["manifest.json", ...Object.values(manifest.assets) as string[]]) baseline.set(path.join(base, name), digest(path.join(base, name)));
    for (const name of ["package", "go"]) fs.mkdirSync(path.dirname(file(name)), { recursive: true, mode: 0o700 });
    fs.mkdirSync(path.join(root, "project")); fs.cpSync(path.join(repo, "test/e2e/fixtures/layer-go"), path.join(root, "project"), { recursive: true });
    fs.writeFileSync(path.join(root, "config/config.toml"), `[vm]\nimage=${JSON.stringify(base)}\nmemory="1G"\ncpus=2\nmax-session="5m"\n`);
    fs.writeFileSync(file("package"), '[image.layer]\npackages=["tree"]\n[[dir]]\nname="project"\nhost=' + JSON.stringify(path.join(root, "project")) + "\n");
    fs.writeFileSync(file("go"), goDefinition + '[[dir]]\nname="project"\nhost=' + JSON.stringify(path.join(root, "project")) + "\n");
    env = { PATH: process.env.PATH, CORB_STATE_DIR: path.join(root, "state"), CORB_CACHE_DIR: path.join(root, "cache"), CORB_CONFIG_DIR: path.join(root, "config"), GONDOLIN_IMAGE_STORE: path.join(root, "store"), GONDOLIN_SESSIONS_DIR: runtime };
    console.log(`layer lifecycle evidence: ${root}`);
  });
  afterAll(() => {
    expect(execFileSync("ps", ["-eo", "comm="], { encoding: "utf8", timeout: 5000 }).split("\n").filter((name) => name.trim().startsWith("qemu-system"))).toEqual([]);
    for (const [filename, hash] of baseline) expect(digest(filename), filename).toBe(hash);
    if (runtime) { expect(fs.readdirSync(runtime)).toEqual([]); fs.rmdirSync(runtime); }
    if (root) fs.writeFileSync(path.join(root, "results.json"), JSON.stringify({ base, records, baseline: Object.fromEntries(baseline) }, null, 2), { mode: 0o600 });
  });
  it("pins a real closure, composes only actual additions and runs the package as uid 1000", async () => {
    await cli(["image", "pin", "--workspace", "package"]);
    const build = await cli(["image", "layer", "build", "--workspace", "package"]);
    expect(build).toContain("sanitized bare APK child uses frozen repository defaults"); expect(build).toContain("Installing tree"); expect(build).not.toContain("Installing musl");
    const current = generation("package"); const metadata = JSON.parse(fs.readFileSync(path.join(current.directory, "metadata.json"), "utf8"));
    expect(metadata.packageCoherence).toBe(true); expect(metadata.verification.gates.filter((gate: { ok: boolean }) => gate.ok)).toHaveLength(7);
    const probe = path.join(root, "project/probe.mjs"); const original = fs.readFileSync(probe);
    fs.writeFileSync(probe, 'import {execFileSync} from "node:child_process"; export default function(){if(process.getuid()!==1000)throw Error("uid");if(!execFileSync("tree",["--version"],{encoding:"utf8"}).includes("tree v"))throw Error("tree");execFileSync("/bin/sh",["-c","for n in npm npx su sudo doas apk apk.static; do if command -v $n; then exit 1; fi; done; exit 0"]);console.log("CORB_PACKAGE_OK");process.exit(0)}');
    try { expect(await run("package", true)).toContain("CORB_PACKAGE_OK"); } finally { fs.writeFileSync(probe, original); }
  }, 14 * 60_000);
  it("pins a full Go SDK without APK inputs and resumes twice without changing canonical files", async () => {
    await cli(["image", "pin", "--workspace", "go"]); await cli(["image", "layer", "build", "--workspace", "go"]);
    const current = generation("go"); const snapshot = digest(path.join(current.directory, "checkpoint.qcow2"));
    for (const accept of [true, false]) {
      expect(await run("go", accept)).toContain("CORB_GO_WORKLOAD_OK");
      expect(digest(path.join(current.directory, "checkpoint.qcow2"))).toBe(snapshot);
      const result = JSON.parse(fs.readFileSync(path.join(root, "project/result.json"), "utf8"));
      expect(result.uid).toBe(1000); expect(result.tests.match(/--- PASS:/g)).toHaveLength(3); expect(result.runtime).toEqual({ uid: 1000, gid: 1000, mode: 0o750 });
    }
  }, 14 * 60_000);
  it("rejects stale pins and tampered, foreign-base or rebased checkpoints before VM creation", async () => {
    const original = fs.readFileSync(file("go")); const current = generation("go"); const pointer = fs.readFileSync(current.pointer);
    fs.writeFileSync(file("go"), original.toString().replace("packages=[]", 'packages=["tree"]'));
    try { expect(await cli(["run", "--workspace", "go"], 1)).toMatch(/pin|definition/); expect(records.at(-1)!.pids).toEqual([]); } finally { fs.writeFileSync(file("go"), original); }
    for (const kind of ["bytes", "foreign", "backing"]) {
      const id = randomUUID(); const clone = path.join(path.dirname(current.directory), id); fs.cpSync(current.directory, clone, { recursive: true });
      try {
        const disk = path.join(clone, "checkpoint.qcow2"); fs.chmodSync(disk, 0o600);
        const metadataFile = path.join(clone, "metadata.json"); fs.chmodSync(metadataFile, 0o600); fs.chmodSync(path.join(clone, "complete.json"), 0o600); const metadata = JSON.parse(fs.readFileSync(metadataFile, "utf8")); metadata.generation = id;
        if (kind === "bytes") { const fd = fs.openSync(disk, "r+"); fs.writeSync(fd, Buffer.from("bad"), 0, 3, 100000); fs.closeSync(fd); }
        if (kind === "foreign") metadata.base.manifest.buildId = randomUUID();
        if (kind === "backing") { execFileSync("qemu-img", ["rebase", "-u", "-f", "qcow2", "-F", "raw", "-b", path.join(base, "foreign-rootfs"), disk]); metadata.checkpoint.sha256 = digest(disk); }
        fs.writeFileSync(metadataFile, JSON.stringify(metadata)); fs.writeFileSync(path.join(clone, "complete.json"), JSON.stringify({ version: 1, metadataSha256: digest(metadataFile) }));
        fs.writeFileSync(current.pointer, JSON.stringify({ version: 1, generation: id }));
        expect(await cli(["run", "--workspace", "go"], 1)).toMatch(/checkpoint|generation|backing/); expect(records.at(-1)!.pids).toEqual([]);
      } finally { fs.writeFileSync(current.pointer, pointer); fs.rmSync(clone, { recursive: true, force: true }); }
    }
  }, 180_000);
  it("uses a cached bound graph without ORAS or a VM for an already-installed pull", async () => {
    for (const [key, value] of Object.entries(env)) if (value !== undefined && key !== "PATH") vi.stubEnv(key, value);
    try {
      const context = selectLayerWorkspace("go"); const metadata = JSON.parse(fs.readFileSync(path.join(generation("go").directory, "metadata.json"), "utf8"));
      bindLayerArtifact(context.selected.entry.dir, context.arch, context.pins!, `registry.invalid/corb/go@${metadata.inputDigest}`);
    } finally { vi.unstubAllEnvs(); }
    const pins = fs.readFileSync(sum("go")); const originalPath = env.PATH;
    env.PATH = originalPath?.split(path.delimiter).filter((entry) => !entry.includes("/oras")).join(path.delimiter);
    try { expect(await cli(["image", "layer", "pull", "--workspace", "go"])).toContain("already installed"); expect(records.at(-1)!.pids).toEqual([]); expect(fs.readFileSync(sum("go"))).toEqual(pins); }
    finally { env.PATH = originalPath; }
  });
  it.skipIf(!process.env.CORB_E2E_LAYER_SECOND_BASE)("reuses identical bound SDK inputs in a separate exact-base cache", async () => {
    const global = path.join(root, "config/config.toml"); const original = fs.readFileSync(global); const pins = fs.readFileSync(sum("go"));
    const current = generation("go"); const pointer = fs.readFileSync(current.pointer); const metadata = JSON.parse(fs.readFileSync(path.join(current.directory, "metadata.json"), "utf8"));
    const second = fs.realpathSync(process.env.CORB_E2E_LAYER_SECOND_BASE!); const secondManifest = JSON.parse(fs.readFileSync(path.join(second, "manifest.json"), "utf8"));
    for (const name of ["manifest.json", ...Object.values(secondManifest.assets) as string[]]) baseline.set(path.join(second, name), digest(path.join(second, name)));
    fs.writeFileSync(global, original.toString().replace(JSON.stringify(base), JSON.stringify(second)));
    try {
      const result = await cli(["image", "layer", "build", "--workspace", "go"]); expect(result).toContain(metadata.inputDigest); expect(result).toContain(secondManifest.buildId); expect(secondManifest.buildId).not.toBe(metadata.base.manifest.buildId);
      expect(fs.readFileSync(sum("go"))).toEqual(pins); expect(fs.readFileSync(current.pointer)).toEqual(pointer);
      expect(digest(path.join(current.directory, "checkpoint.qcow2"))).toBe(metadata.checkpoint.sha256);
    } finally { fs.writeFileSync(global, original); }
    expect(await cli(["image", "layer", "build", "--workspace", "go"])).toContain("already installed"); expect(records.at(-1)!.pids).toEqual([]);
  }, 14 * 60_000);
  it("cleans both real checkpoint files after an induced SDK move failure", async () => {
    const original = fs.readFileSync(file("package")); const pins = fs.readFileSync(sum("package")); const current = generation("package"); const pointer = fs.readFileSync(current.pointer);
    fs.writeFileSync(file("package"), original.toString().replace("[image.layer]", '[image.layer]\ncommands=["true"]'));
    let source: string | undefined; let destination: string | undefined;
    try {
      await cli(["image", "pin", "--workspace", "package"]);
      for (const [key, value] of Object.entries(env)) if (value !== undefined && key !== "PATH") vi.stubEnv(key, value);
      const rename = fs.renameSync;
      vi.spyOn(fs, "renameSync").mockImplementation((from, to) => {
        if (String(from).endsWith("/builder.qcow2") && String(to).endsWith("/checkpoint.qcow2")) {
          source = String(from); destination = String(to); fs.writeFileSync(to, "owned partial checkpoint");
          throw Object.assign(Error("induced checkpoint move failure"), { code: "EIO" });
        }
        return rename(from, to);
      });
      await expect(runLayerBuild(["--workspace", "package"])).rejects.toThrow("induced checkpoint move failure");
      expect(source).toBeDefined(); expect(fs.existsSync(source!)).toBe(false); expect(fs.existsSync(destination!)).toBe(false);
      expect(fs.readFileSync(current.pointer)).toEqual(pointer);
      expect(fs.readdirSync(path.join(root, "cache/layer-inputs/v1/staging"))).toEqual([]);
    } finally { vi.restoreAllMocks(); vi.unstubAllEnvs(); fs.writeFileSync(file("package"), original); fs.writeFileSync(sum("package"), pins); }
  }, 14 * 60_000);
  it("rejects a requested replacement of the base SSH provider without replacing pins", async () => {
    const original = fs.readFileSync(file("package")); const pins = fs.readFileSync(sum("package")); const current = generation("package"); const pointer = fs.readFileSync(current.pointer);
    fs.writeFileSync(file("package"), original.toString().replace('packages=["tree"]', 'packages=["openssh-client-default"]'));
    try {
      expect(await cli(["image", "pin", "--workspace", "package"], 1)).toMatch(/base|transaction|conflict|replacement|Purging/);
      expect(fs.readFileSync(sum("package"))).toEqual(pins); expect(fs.readFileSync(current.pointer)).toEqual(pointer);
    } finally { fs.writeFileSync(file("package"), original); }
  }, 14 * 60_000);
  it.each([
    ["go", "chmod 0777 /opt/corb/toolchains/go", /SDK|payload/],
    ["go", "chmod 0777 /opt/corb/toolchains", /SDK|payload/],
    ["go", "chmod 0777 /usr/local/bin", /protected/],
    ["package", "printf changed >> /usr/local/libexec/real-git", /protected|native/],
    ["package", "chmod u+s /bin/busybox", /protected|native|SUID|suid/],
    ["package", "cp /corb-layer-input/bin/apk.static /usr/local/bin/copied-installer", /installer/],
  ])("preserves a valid generation after rejecting %s command %s", async (workspace, command, reason) => {
    const original = fs.readFileSync(file(workspace)); const pins = fs.readFileSync(sum(workspace)); const current = generation(workspace); const pointer = fs.readFileSync(current.pointer);
    fs.writeFileSync(file(workspace), original.toString().replace("[image.layer]", `[image.layer]\ncommands=${JSON.stringify([command])}`));
    try {
      await cli(["image", "pin", "--workspace", workspace]);
      expect(await cli(["image", "layer", "build", "--workspace", workspace], 1)).toMatch(reason);
      expect(fs.readFileSync(current.pointer)).toEqual(pointer);
    } finally { fs.writeFileSync(file(workspace), original); fs.writeFileSync(sum(workspace), pins); fs.writeFileSync(current.pointer, pointer); }
    expect(await cli(["image", "layer", "build", "--workspace", workspace])).toContain("already installed");
  }, 14 * 60_000);
});
