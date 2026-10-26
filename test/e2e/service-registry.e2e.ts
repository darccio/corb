import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import { execFileSync } from "node:child_process";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import { selectLayerWorkspace } from "../../src/layer/context.ts";
import { normalizeLayerDefinition, hashLayerDefinition } from "../../src/layer/definition.ts";
import { readLayerLock, serializeLayerLock } from "../../src/layer/pins.ts";
import { publishInputGraph } from "../../src/layer/graph.ts";
import { OrasTransport, pushArtifact, registryFlags } from "../../src/layer/transport.ts";
import { computePortableBuildId, projectPortableSdkManifest } from "../../src/layer/base.ts";
import { runOwnedProcess } from "./helpers/owned-process.ts";
import { attemptCleanup } from "./helpers/cleanup.ts";
import { isQemuVersionProbe } from "./helpers/qemu.ts";
import { startDistribution } from "./helpers/distribution.ts";
import { sha256 } from "../../src/layer/validate.ts";

const enabled = process.env.CORB_E2E === "1" && process.platform === "linux" && process.arch === "x64";
const repo = process.cwd();
const digest = (filename: string) => execFileSync("sha256sum", [filename], { encoding: "utf8", timeout: 120_000 }).split(" ")[0]!;
const quote = (value: string) => "'" + value.replaceAll("'", "'\"'\"'") + "'";
async function hasCredentialMarker(filename: string, markers: string[]) {
  let tail = Buffer.alloc(0); const longest = Math.max(...markers.map((marker) => Buffer.byteLength(marker)));
  for await (const chunk of fs.createReadStream(filename)) {
    const bytes = Buffer.concat([tail, Buffer.from(chunk)]);
    if (markers.some((marker) => bytes.includes(Buffer.from(marker)))) return true;
    tail = bytes.subarray(Math.max(0, bytes.length - longest));
  }
  return false;
}
const go = `[[image.layer.payload]]
name="go"
url="https://go.dev/dl/go1.27.3.linux-amd64.tar.gz"
sha256="65efbc80fdc1fa2cd2631cad5b481777a68e8725f34e89f50fc6ac714e379b40"
arch="x86_64"
destination="/opt/corb/toolchains/go"
strip-components=1
path=["bin"]
`;
interface Party { name: string; root: string; env: NodeJS.ProcessEnv; base: string }

describe.skipIf(!enabled)("packaged services and remote producer/recipient inputs (serial real VMs)", () => {
  let root: string; let runtime: string; let registry: Awaited<ReturnType<typeof startDistribution>>;
  let a: Party; let b: Party; let sharedSum: Buffer; let sharedDefinition: Buffer; let inputDigest: string; let baseReference: string;
  const optionReceipts: string[] = [];
  const baseline = new Map<string, string>(); const records: Array<{ party: string; args: string[]; code: number | null; pids: number[]; forced: number[] }> = [];
  const file = (party: Party, workspace = "service") => path.join(party.root, "config/workspaces", workspace, "corb.toml");
  const sum = (party: Party, workspace = "service") => path.join(path.dirname(file(party, workspace)), "corb.sum");
  const generation = (party: Party, workspace = "service") => {
    const id = JSON.parse(fs.readFileSync(path.join(party.base, "manifest.json"), "utf8")).buildId;
    const directory = path.join(party.root, "state/layers", workspace, "x86_64/bases", id);
    const pointer = path.join(directory, "current.json"); const name = JSON.parse(fs.readFileSync(pointer, "utf8")).generation;
    const current = path.join(directory, "generations", name);
    return { pointer, directory: current, metadata: JSON.parse(fs.readFileSync(path.join(current, "metadata.json"), "utf8")), evidence: JSON.parse(fs.readFileSync(path.join(current, "evidence.json"), "utf8")) };
  };
  async function execute(party: Party, args: string[], expected = 0, fixture = false) {
    fs.writeFileSync(path.join(registry.root, "private-markers.json"), JSON.stringify(registry.markers), { mode: 0o600 });
    const receipt = path.join(root, `vm-options-${optionReceipts.length + 1}.json`); optionReceipts.push(receipt);
    const result = await runOwnedProcess(process.execPath, ["--import", path.join(repo, "test/e2e/fixtures/observe-vm-options.ts"), ...(fixture ? args : ["src/cli.ts", ...args])], {
      cwd: repo, env: { ...party.env, CORB_E2E_VM_MARKERS: path.join(registry.root, "private-markers.json"), CORB_E2E_VM_RECEIPT: receipt }, timeoutMs: 9 * 60_000,
      observe(_pid, argv) { if (isQemuVersionProbe(argv)) return; expect(["1G", "1024", "1024M"]).toContain(argv[argv.indexOf("-m") + 1]); expect(argv[argv.indexOf("-smp") + 1]).toBe("2"); },
    });
    records.push({ party: party.name, args, code: result.code, pids: result.pids.filter((row) => row.args.some((arg) => /(?:^|\/)qemu-system-/.test(arg)) && !isQemuVersionProbe(row.args)).map((row) => row.pid), forced: result.forced });
    fs.writeFileSync(path.join(root, `command-${records.length}.log`), result.output, { mode: 0o600 });
    expect(result.survivors).toEqual([]); expect(result.uncertain).toBe(false); expect(result.forced).toEqual([]);
    expect(result.error, result.output.slice(-16000)).toBeUndefined(); expect(result.code, result.output.slice(-16000)).toBe(expected);
    expect(fs.readdirSync(runtime)).toEqual([]); return result.output;
  }
  const cli = (party: Party, args: string[], expected = 0) => execute(party, args, expected);
  const flags = () => ["--registry-config", registry.registryConfig, "--ca-file", registry.caFile];
  const run = (party: Party) => cli(party, ["run", "--workspace", "service", "--trust-config", "--", "--extension", "/work/project/probe.mjs", "--print", "unused"]);
  function makeParty(name: string, base: string): Party {
    const directory = path.join(root, name); const config = path.join(directory, "config");
    fs.mkdirSync(path.join(config, "workspaces/service"), { recursive: true, mode: 0o700 });
    fs.mkdirSync(path.join(directory, "project")); fs.cpSync(path.join(repo, "test/e2e/fixtures/layer-go"), path.join(directory, "project"), { recursive: true });
    fs.writeFileSync(path.join(config, "config.toml"), `[vm]\nimage=${JSON.stringify(base)}\nmemory="1G"\ncpus=2\nmax-session="5m"\n[workspaces]\nprojects-root=${JSON.stringify(directory)}\n`);
    return { name, root: directory, base, env: { PATH: process.env.PATH, CORB_CONFIG_DIR: config, CORB_STATE_DIR: path.join(directory, "state"), CORB_CACHE_DIR: path.join(directory, "cache"), GONDOLIN_IMAGE_STORE: path.join(directory, "store"), GONDOLIN_SESSIONS_DIR: runtime } };
  }
  function assertShared() { expect(fs.readFileSync(file(b))).toEqual(sharedDefinition); expect(fs.readFileSync(sum(b))).toEqual(sharedSum); }
  beforeAll(async () => {
    if (!process.env.CORB_E2E_SERVICE_BASE_A || !process.env.CORB_E2E_SERVICE_BASE_B) throw Error("set distinct coherent CORB_E2E_SERVICE_BASE_A and CORB_E2E_SERVICE_BASE_B");
    const parent = process.env.CORB_E2E_LAYER_ROOT ?? path.join(repo, "image/build/dar-21"); fs.mkdirSync(parent, { recursive: true }); root = fs.mkdtempSync(path.join(parent, "service-"));
    runtime = fs.mkdtempSync(path.join(os.tmpdir(), "c21-")); fs.chmodSync(runtime, 0o700);
    a = makeParty("a", fs.realpathSync(process.env.CORB_E2E_SERVICE_BASE_A)); b = makeParty("b", fs.realpathSync(process.env.CORB_E2E_SERVICE_BASE_B));
    for (const party of [a, b]) {
      const manifest = JSON.parse(fs.readFileSync(path.join(party.base, "manifest.json"), "utf8"));
      for (const name of ["manifest.json", ...Object.values(manifest.assets) as string[]]) baseline.set(path.join(party.base, name), digest(path.join(party.base, name)));
    }
    expect(JSON.parse(fs.readFileSync(path.join(a.base, "manifest.json"), "utf8")).buildId).not.toBe(JSON.parse(fs.readFileSync(path.join(b.base, "manifest.json"), "utf8")).buildId);
    const redis = fs.readFileSync(path.join(repo, "test/e2e/fixtures/redis-default.mjs"), "utf8");
    sharedDefinition = Buffer.from(`[image.layer]\npackages=["redis","lua5.4","tree"]\nbuild-hosts=["dl-cdn.alpinelinux.org","go.dev","dl.google.com"]\ncommands=[${JSON.stringify(`/usr/bin/node --input-type=module -e ${quote(redis)} positive`)}]\n` + go + ["/run/redis", "/var/log/redis"].map((directory) => `[[image.layer.runtime-dir]]\npath=${JSON.stringify(directory)}\nmode="0755"\nowner="redis"\ngroup="redis"\n`).join("") + '[[image.layer.runtime-dir]]\npath="/run/go-work"\nmode="0750"\nowner="agent"\ngroup="agent"\n[[dir]]\nname="project"\nhost="project"\n');
    fs.writeFileSync(file(a), sharedDefinition); registry = await startDistribution(path.join(root, "registry"));
    fs.writeFileSync(path.join(registry.root, "private-markers.json"), JSON.stringify(registry.markers), { flag: "wx", mode: 0o600 });
    console.log(`service/recipient evidence: ${root}`);
  });
  afterAll(async () => {
    vi.unstubAllEnvs();
    const failures = await attemptCleanup([
      { name: "registry", run: async () => { if (registry) await registry.close(); } },
      ...[...baseline].map(([filename, hash]) => ({ name: `base:${filename}`, run: () => { expect(digest(filename), filename).toBe(hash); } })),
      { name: "runtime", run: () => { if (runtime) { expect(fs.readdirSync(runtime)).toEqual([]); fs.rmdirSync(runtime); } } },
    ]);
    failures.push(...await attemptCleanup([{ name: "receipt", run: () => { if (root) fs.writeFileSync(path.join(root, "results.json"), JSON.stringify({ records, baseline: Object.fromEntries(baseline), inputDigest, baseReference, runtime, runtimeRemoved: runtime !== undefined && !fs.existsSync(runtime), cleanupFailures: failures.map((row) => row.name) }, null, 2), { mode: 0o600 }); } }]));
    if (failures.length > 0) throw new AggregateError(failures.map((row) => row.error), `service fixture cleanup failed: ${failures.map((row) => row.name).join(", ")}`);
  });
  it("pins a full signed candidate closure and checks fresh default Redis before checkpointing", async () => {
    await cli(a, ["image", "pin", "--workspace", "service"]);
    const pins = readLayerLock(path.dirname(file(a)))!.target.x86_64!;
    expect(pins.package.find((row) => row.name === "lua5.4-libs")?.requested).toBe(false);
    const output = await cli(a, ["image", "layer", "build", "--workspace", "service"]);
    const marker = JSON.parse(/^CORB_REDIS_DEFAULT=(.+)$/m.exec(output)![1]!);
    expect(marker.expected).toBe(true); expect(marker.explicitStartup).toBe(true); expect(marker.automaticStartup).toBe(false); expect(marker.shutdown).toBe(true);
    const current = generation(a); expect(current.metadata.packageCoherence).toBe(true); expect(current.metadata.verification.gates.filter((gate: { ok: boolean }) => gate.ok)).toHaveLength(7);
    expect(current.evidence.baseline.packages.some((row: { P: string }) => row.P === "lua5.4-libs")).toBe(true);
    expect(current.evidence.additions.map((row: { name: string }) => row.name)).not.toContain("lua5.4-libs");
    const archive = current.evidence.archives.find((row: { name: string }) => row.name === "redis");
    expect(archive.files.find((row: { path: string }) => row.path === "/etc/redis.conf").sha256).toBe(marker.configSha256);
    inputDigest = current.metadata.inputDigest;
  }, 18 * 60_000);
  it("pushes immutable inputs and composes them on a genuinely different recipient base", async () => {
    const destination = `${registry.host}/inputs:producer`;
    expect(await cli(a, ["image", "layer", "push", "--workspace", "service", ...flags(), destination])).toContain(inputDigest);
    expect(await cli(a, ["image", "layer", "push", "--workspace", "service", ...flags(), `${registry.host}/inputs:identical`])).toContain(inputDigest);
    sharedSum = fs.readFileSync(sum(a)); fs.writeFileSync(file(b), sharedDefinition); fs.writeFileSync(sum(b), sharedSum);
    expect(fs.existsSync(path.join(b.root, "cache/layer-inputs"))).toBe(false); expect(fs.existsSync(path.join(b.root, "store/objects"))).toBe(false);
    const remoteOptions = { registryConfig: registry.registryConfig, caFile: registry.caFile }; const transport = new OrasTransport(remoteOptions);
    const producerCache = path.join(a.root, "cache/layer-inputs/v1/blobs/sha256"); const manifest = JSON.parse(fs.readFileSync(path.join(producerCache, inputDigest.slice(7)), "utf8"));
    const sdk = manifest.layers.find((row: { annotations: Record<string, string> }) => row.annotations["org.opencontainers.image.title"] === "payload/go");
    const lock = readLayerLock(path.dirname(file(b)))!;
    const immutable = lock.target.x86_64!.artifact!;
    const failures: Array<{ name: string; reference: string; flags?: string[]; expected: RegExp }> = [
      { name: "missing credentials", reference: immutable, flags: ["--registry-config", registry.emptyConfig, "--ca-file", registry.caFile], expected: /401|unauthorized|authentication/ },
      { name: "wrong credentials", reference: immutable, flags: ["--registry-config", registry.wrongConfig, "--ca-file", registry.caFile], expected: /401|unauthorized|authentication/ },
      { name: "untrusted CA", reference: immutable, flags: ["--registry-config", registry.registryConfig], expected: /x509|certificate/ },
      { name: "missing digest", reference: `${registry.host}/inputs@sha256:${"f".repeat(64)}`, expected: /404|not found/ },
    ];
    for (const kind of ["artifact", "media", "url", "title"]) {
      const bad = structuredClone(manifest);
      if (kind === "artifact") bad.artifactType = "application/example.unsupported";
      if (kind === "media") bad.config.mediaType = "application/example.unsupported";
      if (kind === "url") bad.layers[0].urls = ["https://attacker.invalid/blob"];
      if (kind === "title") bad.layers[0].annotations["org.opencontainers.image.title"] = "../../escape";
      const bytes = Buffer.from(JSON.stringify(bad)); const filename = path.join(root, `rejected-${kind}.json`); fs.writeFileSync(filename, bytes, { mode: 0o600 });
      await transport.run(["manifest", "push", ...registryFlags(remoteOptions), `${registry.host}/inputs:rejected-${kind}`, filename]);
      failures.push({ name: kind, reference: `${registry.host}/inputs@sha256:${sha256(bytes)}`, expected: /unsupported|unknown|OCI role/ });
    }
    const foreignConfig = JSON.parse(fs.readFileSync(path.join(producerCache, manifest.config.digest.slice(7)), "utf8"));
    foreignConfig.definition.payload[0].arch = "aarch64"; foreignConfig.pins["definition-sha256"] = hashLayerDefinition(foreignConfig.definition);
    const foreignBytes = Buffer.from(JSON.stringify(foreignConfig)); const foreignFile = path.join(root, "rejected-architecture-config"); fs.writeFileSync(foreignFile, foreignBytes, { mode: 0o600 });
    await transport.run(["blob", "push", ...registryFlags(remoteOptions), `${registry.host}/inputs`, foreignFile]);
    const foreignManifest = { ...manifest, config: { ...manifest.config, digest: `sha256:${sha256(foreignBytes)}`, size: foreignBytes.length } };
    const foreignRoot = Buffer.from(JSON.stringify(foreignManifest)); const foreignRootFile = path.join(root, "rejected-architecture-root"); fs.writeFileSync(foreignRootFile, foreignRoot, { mode: 0o600 });
    await transport.run(["manifest", "push", ...registryFlags(remoteOptions), `${registry.host}/inputs:rejected-architecture`, foreignRootFile]);
    failures.push({ name: "architecture", reference: `${registry.host}/inputs@sha256:${sha256(foreignRoot)}`, expected: /architecture|arch/ });
    try {
      for (const failure of failures) {
        fs.writeFileSync(sum(b), serializeLayerLock({ ...lock, target: { ...lock.target, x86_64: { ...lock.target.x86_64!, artifact: failure.reference } } }));
        const prior = fs.readFileSync(sum(b)); expect(await cli(b, ["image", "layer", "pull", "--workspace", "service", ...(failure.flags ?? flags())], 1), failure.name).toMatch(failure.expected);
        expect(records.at(-1)!.pids).toEqual([]); expect(fs.readFileSync(sum(b))).toEqual(prior);
      }
    } finally { fs.writeFileSync(sum(b), sharedSum); }
    for (const fault of ["digest", "truncated"]) {
      registry.setFault((method, pathname) => method === "GET" && pathname.endsWith(`/blobs/${manifest.config.digest}`) ? fault === "digest" ? { body: Buffer.alloc(manifest.config.size, 32) } : { truncate: 1 } : undefined);
      try { expect(await cli(b, ["image", "layer", "pull", "--workspace", "service", ...flags()], 1)).toMatch(/digest|mismatch|unexpected EOF|size|failed/); expect(records.at(-1)!.pids).toEqual([]); }
      finally { registry.setFault(undefined); }
      expect(fs.readFileSync(sum(b))).toEqual(sharedSum);
    }
    const before = registry.requests.length; const output = await cli(b, ["image", "layer", "pull", "--workspace", "service", ...flags()]);
    expect(output).toContain(inputDigest); expect(output).toContain("CORB_REDIS_DEFAULT=");
    expect(registry.requests.slice(before).some((row) => row.method === "GET" && row.path === `/v2/inputs/blobs/${sdk.digest}` && row.status === 200 && row.bytes === sdk.size && row.authenticated)).toBe(true);
    const producer = generation(a); const recipient = generation(b);
    expect(recipient.evidence.baseline.packages.some((row: { P: string }) => row.P === "tree")).toBe(true);
    expect(recipient.evidence.baseline.packages.some((row: { P: string }) => row.P === "lua5.4-libs")).toBe(false);
    expect(recipient.evidence.baseline.accounts.users.some((row: { name: string; id: number }) => row.name === "consumer" && row.id === 1601)).toBe(true);
    expect(recipient.evidence.additions.map((row: { name: string }) => row.name)).toContain("lua5.4-libs");
    expect(recipient.evidence.additions.map((row: { name: string }) => row.name)).not.toContain("tree");
    expect(producer.evidence.additions.map((row: { name: string }) => row.name)).toContain("tree");
    expect(recipient.metadata.compositionKey).not.toBe(producer.metadata.compositionKey); expect(recipient.metadata.inputDigest).toBe(producer.metadata.inputDigest);
    expect(recipient.evidence.archives.find((row: { name: string }) => row.name === "lua5.4-libs")).toEqual(producer.evidence.archives.find((row: { name: string }) => row.name === "lua5.4-libs"));
    expect(recipient.evidence.payloads).toEqual(producer.evidence.payloads); expect(recipient.evidence.payloads[0].tree.entries).toHaveLength(17372);
    expect(fs.existsSync(path.join(b.root, "store/objects"))).toBe(false); assertShared();
    const cachedRoot = path.join(b.root, "cache/layer-inputs/v1/blobs/sha256", inputDigest.slice(7)); const graphBytes = fs.readFileSync(cachedRoot, "utf8");
    expect(graphBytes).not.toContain("checkpoint"); expect(graphBytes).not.toContain(a.base); expect(graphBytes).not.toContain(producer.metadata.base.manifest.buildId);
  }, 18 * 60_000);
  it("resumes each own-base checkpoint and explicitly runs Redis after production directory restoration", async () => {
    for (const party of [a, b]) {
      const current = generation(party); const checkpoint = digest(path.join(current.directory, "checkpoint.qcow2"));
      const output = await execute(party, ["test/e2e/fixtures/resume-redis.ts", "service", "positive"], 0, true);
      const marker = JSON.parse(/^CORB_REDIS_DEFAULT=(.+)$/m.exec(output)![1]!);
      expect(marker.directories).toEqual(expect.arrayContaining([expect.objectContaining({ path: "/run/redis", exists: true, uid: marker.uid, gid: marker.gid, mode: 0o755 }), expect.objectContaining({ path: "/var/log/redis", exists: true, uid: marker.uid, gid: marker.gid, mode: 0o755 })]));
      expect(marker.configSha256).toBe(current.evidence.archives.find((row: { name: string }) => row.name === "redis").files.find((row: { path: string }) => row.path === "/etc/redis.conf").sha256);
      expect(JSON.parse(/^CORB_REDIS_RESUME=(.+)$/m.exec(output)![1]!).verification.gates.filter((gate: { ok: boolean }) => gate.ok)).toHaveLength(7);
      expect(digest(path.join(current.directory, "checkpoint.qcow2"))).toBe(checkpoint);
    }
    assertShared();
  }, 12 * 60_000);
  it("runs complete Go and native tools as uid 1000 through ordinary offline installed sessions", async () => {
    registry.setFault(() => ({ status: 503 })); const requests = registry.requests.length;
    try {
      for (const party of [a, b]) {
        const probe = path.join(party.root, "project/probe.mjs");
        const original = fs.readFileSync(probe, "utf8");
        const consumer = party === b ? 'const consumer=fs.statSync("/var/lib/consumer/state"); if(consumer.uid!==1601||consumer.gid!==1601||fs.readFileSync("/var/lib/consumer/state","utf8")!=="dar21-existing-consumer\\n"||!/^consumer:[^:]*:1601:1601:/m.test(fs.readFileSync("/etc/passwd","utf8")))throw Error("consumer state changed");console.log("CORB_CONSUMER_STATE_OK="+JSON.stringify({uid:consumer.uid,gid:consumer.gid}));' : 'if(fs.existsSync("/var/lib/consumer/state")||/^consumer:/m.test(fs.readFileSync("/etc/passwd","utf8")))throw Error("producer unexpectedly has recipient state");';
        fs.writeFileSync(probe, original.replace("export default function () {", "export default function () {" + consumer).replace('const version = run("go", ["version"]);', 'for(const name of ["src/net/http/server.go","pkg/tool/linux_amd64/compile","pkg/tool/linux_amd64/link"])if(!fs.statSync("/opt/corb/toolchains/go/"+name).isFile())throw Error("incomplete Go tree"); if(!run("go",["env","GOROOT"]).includes("/opt/corb/toolchains/go"))throw Error("wrong toolchain"); if(run("ldd",["/usr/bin/redis-server"]).includes("not found"))throw Error("native library missing"); if(run("lua5.4",["-e","print(_VERSION)"]).trim()!=="Lua 5.4")throw Error("Lua failed"); if(!run("tree",["--version"]).includes("tree v"))throw Error("tree failed"); const version = run("go", ["version"]);'));
        const saved = party.env.PATH; party.env.PATH = saved?.split(path.delimiter).filter((entry) => !entry.includes("/oras")).join(path.delimiter);
        try { const output = await run(party); expect(output).toContain("CORB_GO_WORKLOAD_OK"); if (party === b) expect(JSON.parse(/^CORB_CONSUMER_STATE_OK=(.+)$/m.exec(output)![1]!)).toEqual({ uid: 1601, gid: 1601 }); } finally { party.env.PATH = saved; }
        if (party === b) {
          const result = JSON.parse(fs.readFileSync(path.join(party.root, "project/result.json"), "utf8")); expect(result.uid).toBe(1000); expect(result.tests.match(/--- PASS:/g)).toHaveLength(3);
        }
      }
    } finally { registry.setFault(undefined); }
    expect(registry.requests).toHaveLength(requests); assertShared();
  }, 12 * 60_000);
  it("does no ORAS, downloads or VM work when a valid composition is already installed", async () => {
    const count = registry.requests.length; const saved = b.env.PATH; b.env.PATH = saved?.split(path.delimiter).filter((entry) => !entry.includes("/oras")).join(path.delimiter);
    try { expect(await cli(b, ["image", "layer", "pull", "--workspace", "service"])).toContain("already installed"); }
    finally { b.env.PATH = saved; }
    expect(records.at(-1)!.pids).toEqual([]); expect(registry.requests).toHaveLength(count); assertShared();
  });
  it("rejects corrupt installed cache content before claiming an already-installed state", async () => {
    const current = generation(b); const pointer = fs.readFileSync(current.pointer); const filename = path.join(b.root, "cache/layer-inputs/v1/blobs/sha256", inputDigest.slice(7)); const bytes = fs.readFileSync(filename); const count = registry.requests.length;
    fs.chmodSync(filename, 0o600); fs.writeFileSync(filename, "owned corrupt complete input");
    try {
      expect(await cli(b, ["image", "layer", "pull", "--workspace", "service", ...flags()], 1)).toContain("corrupt input cache object");
      expect(fs.readFileSync(filename, "utf8")).toBe("owned corrupt complete input"); expect(records.at(-1)!.pids).toEqual([]); expect(registry.requests).toHaveLength(count);
    } finally { fs.writeFileSync(filename, bytes); fs.chmodSync(filename, 0o400); }
    expect(fs.readFileSync(current.pointer)).toEqual(pointer); assertShared();
  });
  it("measures the missing-directory failure after an undeclared-runtime checkpoint resumes", async () => {
    const workspace = "negative"; fs.mkdirSync(path.dirname(file(b, workspace)), { recursive: true }); fs.writeFileSync(file(b, workspace), '[image.layer]\npackages=["redis"]\n');
    await cli(b, ["image", "pin", "--workspace", workspace]); await cli(b, ["image", "layer", "build", "--workspace", workspace]);
    const output = await execute(b, ["test/e2e/fixtures/resume-redis.ts", workspace, "negative"], 0, true);
    const result = JSON.parse(/^CORB_REDIS_DEFAULT=(.+)$/m.exec(output)![1]!); expect(result.expected).toBe(false); expect(result.output).toMatch(/Can't open the log file: (No such file or directory|Permission denied)/); expect(result.automaticStartup).toBe(false);
    expect(result.configSha256).toBe(generation(a).evidence.archives.find((row: { name: string }) => row.name === "redis").files.find((row: { path: string }) => row.path === "/etc/redis.conf").sha256);
    assertShared();
  }, 14 * 60_000);
  it("reports partial publication and failed local binding while preserving the authoritative lock", async () => {
    const prior = fs.readFileSync(sum(a));
    registry.setFault((method, pathname) => method === "PUT" && pathname.endsWith("/manifests/partial") ? { status: 503 } : undefined);
    try { expect(await cli(a, ["image", "layer", "push", "--workspace", "service", ...flags(), `${registry.host}/partial:partial`], 1)).toContain("Remote blobs or the manifest may remain"); }
    finally { registry.setFault(undefined); }
    expect(fs.readFileSync(sum(a))).toEqual(prior);
    const output = await execute(a, ["test/e2e/fixtures/layer-bind-failure.ts", "--workspace", "service", ...flags(), `${registry.host}/inputs:binding-failure`], 0, true);
    expect(output).toContain("remote publication succeeded"); expect(output).toContain("previous corb.sum remains authoritative"); expect(output).toContain("CORB_LOCKFILE_REPLACEMENT_REJECTED"); expect(fs.readFileSync(sum(a))).toEqual(prior);
  });
  it.each(["source", "pins"])("rechecks %s changes at the final remote publication boundary", async (kind) => {
    const source = kind === "source" ? file(a) : sum(a); const prior = fs.readFileSync(source); const locked = fs.readFileSync(sum(a)); let changed = false;
    registry.setFault((method, pathname) => {
      if (!changed && method === "GET" && pathname === `/v2/inputs/manifests/${inputDigest}`) {
        changed = true; fs.writeFileSync(source, kind === "source" ? Buffer.concat([prior, Buffer.from("\n# changed during remote publication\n")]) : prior.toString().replace("/inputs@", "/changed@"));
      }
      return undefined;
    });
    try { expect(await cli(a, ["image", "layer", "push", "--workspace", "service", ...flags(), `${registry.host}/inputs:boundary-${kind}`], 1)).toContain("changed during operation"); expect(changed).toBe(true); }
    finally { registry.setFault(undefined); fs.writeFileSync(source, prior); }
    expect(fs.readFileSync(sum(a))).toEqual(locked);
  });
  it("keeps the current generation after a real downloaded graph fails composition", async () => {
    const current = generation(b); const pointer = fs.readFileSync(current.pointer); const checkpoint = digest(path.join(current.directory, "checkpoint.qcow2"));
    for (const [key, value] of Object.entries(a.env)) if (key !== "PATH" && value !== undefined) vi.stubEnv(key, value);
    let failing: Awaited<ReturnType<typeof publishInputGraph>>;
    try {
      const context = selectLayerWorkspace("service"); const definition = normalizeLayerDefinition({ ...context.definition, commands: ["false"] });
      const pins = { ...context.pins!, "definition-sha256": hashLayerDefinition(definition) }; delete pins.artifact;
      failing = await publishInputGraph({ version: 1, definition, pins }, "x86_64");
      const directory = path.join(root, "failure-transfer"); fs.mkdirSync(directory);
      const reference = await pushArtifact(new OrasTransport({ registryConfig: registry.registryConfig, caFile: registry.caFile }), `${registry.host}/inputs:failed-composition`, failing.manifest, failing.digest, directory);
      fs.writeFileSync(file(b), sharedDefinition.toString().replace(/^commands=.+$/m, 'commands=["false"]'));
      fs.writeFileSync(sum(b), serializeLayerLock({ version: 1, target: { x86_64: { ...pins, artifact: reference } } }));
    } finally { vi.unstubAllEnvs(); }
    const count = registry.requests.length;
    try { expect(await cli(b, ["image", "layer", "pull", "--workspace", "service", ...flags()], 1)).toContain("unpinned root step failed"); }
    finally { fs.writeFileSync(file(b), sharedDefinition); fs.writeFileSync(sum(b), sharedSum); }
    expect(registry.requests.slice(count).some((row) => row.method === "GET" && row.path.includes(failing!.digest))).toBe(true);
    expect(fs.readFileSync(current.pointer)).toEqual(pointer); expect(digest(path.join(current.directory, "checkpoint.qcow2"))).toBe(checkpoint); assertShared();
  }, 12 * 60_000);
  it("refuses a real solver addition omitted from the candidate bundle without replacing the current generation", async () => {
    const current = generation(b); const pointer = fs.readFileSync(current.pointer); const checkpoint = digest(path.join(current.directory, "checkpoint.qcow2"));
    for (const [key, value] of Object.entries(a.env)) if (key !== "PATH" && value !== undefined) vi.stubEnv(key, value);
    try {
      const context = selectLayerWorkspace("service"); const pins = { ...context.pins!, package: context.pins!.package.filter((row) => row.name !== "lua5.4-libs") }; delete pins.artifact;
      const graph = await publishInputGraph({ version: 1, definition: context.definition, pins }, "x86_64");
      const directory = path.join(root, "unbundled-transfer"); fs.mkdirSync(directory);
      const reference = await pushArtifact(new OrasTransport({ registryConfig: registry.registryConfig, caFile: registry.caFile }), `${registry.host}/inputs:unbundled-dependency`, graph.manifest, graph.digest, directory);
      fs.writeFileSync(sum(b), serializeLayerLock({ version: 1, target: { x86_64: { ...pins, artifact: reference } } }));
    } finally { vi.unstubAllEnvs(); }
    try { expect(await cli(b, ["image", "layer", "pull", "--workspace", "service", ...flags()], 1)).toContain("incompatible base: planned unbundled package 'lua5.4-libs="); }
    finally { fs.writeFileSync(sum(b), sharedSum); }
    expect(fs.readFileSync(current.pointer)).toEqual(pointer); expect(digest(path.join(current.directory, "checkpoint.qcow2"))).toBe(checkpoint); assertShared();
  }, 12 * 60_000);
  it("distributes raw base assets independently and verifies before publishing a private tag", async () => {
    const current = generation(b); const pointer = fs.readFileSync(current.pointer);
    const checkpointFile = path.join(current.directory, "checkpoint.qcow2"); const checkpoint = digest(checkpointFile);
    const configFile = path.join(b.root, "config/config.toml"); const selectedConfig = fs.readFileSync(configFile);
    const unchangedLayer = () => { expect(fs.readFileSync(current.pointer)).toEqual(pointer); expect(digest(checkpointFile)).toBe(checkpoint); expect(fs.readFileSync(configFile)).toEqual(selectedConfig); assertShared(); };
    const output = await cli(a, ["image", "push", "--image", a.base, ...flags(), `${registry.host}/bases:producer`]); baseReference = /corb image push: (\S+)/.exec(output)![1]!;
    const objects = path.join(b.root, "store/objects"); expect(fs.existsSync(objects) ? fs.readdirSync(objects) : []).toEqual([]);
    const pull = await cli(b, ["image", "pull", ...flags(), "--tag", "dar21-base:imported", baseReference]); expect(pull).toContain("tag=dar21-base:imported"); unchangedLayer();
    const source = JSON.parse(fs.readFileSync(path.join(a.base, "manifest.json"), "utf8")); const imported = path.join(objects, source.buildId);
    const manifestFile = path.join(imported, "manifest.json"); const manifest = JSON.parse(fs.readFileSync(manifestFile, "utf8"));
    expect(projectPortableSdkManifest(manifest)).toEqual(projectPortableSdkManifest(source)); expect(computePortableBuildId(manifest.checksums, manifest.config.arch)).toBe(source.buildId);
    for (const [role, filename] of Object.entries(manifest.assets) as Array<[string, string]>) expect(digest(path.join(imported, filename))).toBe(manifest.checksums[role]);
    manifest.buildTime = "2001-01-01T00:00:00.000Z"; fs.writeFileSync(manifestFile, JSON.stringify(manifest));
    expect(await cli(b, ["image", "pull", ...flags(), baseReference])).toContain(source.buildId); unchangedLayer();
    const harmless = fs.readFileSync(manifestFile); manifest.config.alpine.version = "3.23.99"; fs.writeFileSync(manifestFile, JSON.stringify(manifest)); const inconsistent = fs.readFileSync(manifestFile);
    try { expect(await cli(b, ["image", "pull", ...flags(), baseReference], 1)).toContain("inconsistent portable config"); expect(fs.readFileSync(manifestFile)).toEqual(inconsistent); expect(records.at(-1)!.pids).toEqual([]); }
    finally { fs.writeFileSync(manifestFile, harmless); }
    unchangedLayer();
    const rootFile = path.join(a.root, "cache/layer-inputs/v1/blobs/sha256", baseReference.split("@sha256:")[1]!); const graph = JSON.parse(fs.readFileSync(rootFile, "utf8"));
    expect(graph.artifactType).toBe("application/vnd.corb.base.v1"); expect(JSON.stringify(graph)).not.toMatch(/checkpoint|source|\/home\//);
    for (const descriptor of [graph.config, graph.layers[0]]) { const bytes = fs.readFileSync(path.join(a.root, "cache/layer-inputs/v1/blobs/sha256", descriptor.digest.slice(7)), "utf8"); expect(bytes).not.toContain("checkpoint"); expect(bytes).not.toContain(repo); expect(bytes).not.toContain(a.base); }
    expect(graph.layers.every((row: { annotations: Record<string, string> }) => /^base\/(manifest|kernel|initramfs|rootfs|krunKernel|krunInitrd)$/.test(row.annotations["org.opencontainers.image.title"]!))).toBe(true);
  }, 18 * 60_000);
  it("keeps registry secrets out of artifact bytes, shared pins, guest options and ordinary diagnostics", async () => {
    expect(registry.markers.length).toBeGreaterThan(3);
    const blobs = new Set<string>();
    for (const [party, reference] of [[b, inputDigest], [a, baseReference.split("@")[1]!]] as const) {
      const directory = path.join(party.root, "cache/layer-inputs/v1/blobs/sha256"); const rootFile = path.join(directory, reference.slice(7));
      const graph = JSON.parse(fs.readFileSync(rootFile, "utf8"));
      for (const descriptor of [{ digest: reference }, graph.config, ...graph.layers]) blobs.add(path.join(directory, descriptor.digest.slice(7)));
    }
    for (const filename of [...blobs, file(a), file(b), sum(a), sum(b), ...fs.readdirSync(root).filter((name) => /^command-\d+\.log$/.test(name)).map((name) => path.join(root, name))]) expect(await hasCredentialMarker(filename, registry.markers), filename).toBe(false);
    for (const marker of registry.markers) expect(JSON.stringify({ records, requests: registry.requests }).includes(marker)).toBe(false);
    const observed = optionReceipts.flatMap((filename) => JSON.parse(fs.readFileSync(filename, "utf8")) as Array<{ kind: string; count: number; clean: boolean }>);
    expect(observed.some((row) => row.kind === "create")).toBe(true); expect(observed.some((row) => row.kind === "resume")).toBe(true); expect(observed.every((row) => row.clean)).toBe(true);
    for (const party of [a, b]) { const current = generation(party); expect(digest(path.join(current.directory, "checkpoint.qcow2"))).toBe(current.metadata.checkpoint.sha256); }
    assertShared();
  });
});
