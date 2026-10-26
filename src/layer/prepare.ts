import fs from "node:fs";
import path from "node:path";
import { randomUUID } from "node:crypto";
import { ReadonlyProvider, RealFSProvider, type VM } from "@earendil-works/gondolin";
import { hashLayerDefinition } from "./definition.ts";
import { downloadInput } from "./download.ts";
import { verifiedIndex, verifiedApk, type ApkIndexRecord, type ApkKeys, type VerifiedApk } from "./apk.ts";
import { layerCache, privateDirectory, publishBlob, hashFile, verifyBlob } from "./state.ts";
import { publishInputGraph, publishPinReceipt, inputBlobFile, type InputGraph } from "./graph.ts";
import { hashRecipePins, normalizeTargetPins, refreshLayerPins, type LayerTargetPins } from "./pins.ts";
import { requireLayerExecution, recheckLayerBase, resolveLayerBase, type LayerBase } from "./local-base.ts";
import { verifyLayerBase, withLayerVm, layerExec, type BaseSnapshot } from "./vm.ts";
import { selectLayerWorkspace, type LayerContext } from "./context.ts";
import { assertPinsMatchDefinition } from "./pins.ts";
import { parsePackagePlan } from "./plan.ts";
import { fail, type LayerArch } from "./validate.ts";
import { stageSdkArchive } from "./tar.ts";

export function ownedLayerStaging(): string {
  const parent = privateDirectory(path.join(layerCache(), "staging"));
  const directory = path.join(parent, randomUUID());
  fs.mkdirSync(directory, { mode: 0o700 });
  return directory;
}
export function removeLayerStaging(directory: string): void {
  function writable(filename: string) { const stat = fs.lstatSync(filename); if (stat.isDirectory()) { fs.chmodSync(filename, 0o700); for (const name of fs.readdirSync(filename)) writable(path.join(filename, name)); } }
  if (fs.existsSync(directory)) { writable(directory); fs.rmSync(directory, { recursive: true }); }
}
function recordUrl(record: ApkIndexRecord, branch: string, arch: LayerArch): string { return `https://dl-cdn.alpinelinux.org/alpine/${branch}/${record.repository}/${arch}/${record.P}-${record.V}.apk`; }
async function downloadApk(record: ApkIndexRecord, branch: string, arch: LayerArch, keys: ApkKeys, hosts: string[], staging: string, installer = false): Promise<VerifiedApk> {
  const filename = path.join(staging, `download-${randomUUID()}`);
  await downloadInput(recordUrl(record, branch, arch), filename, hosts, 512 * 1024 ** 2, record.S);
  const identity = await verifiedApk(fs.readFileSync(filename), record, keys, arch, undefined, installer);
  await publishBlob(filename, `sha256:${identity.archiveSha256}`, record.S);
  return identity;
}
export function prepareRepository(staging: string, indexes: Array<{ repository: string; filename: string }>, installer?: VerifiedApk, arch: LayerArch = "x86_64"): string {
  const input = privateDirectory(path.join(staging, "input"));
  for (const index of indexes) {
    const repository = privateDirectory(path.join(input, "repositories", index.repository, arch));
    fs.copyFileSync(index.filename, path.join(repository, "APKINDEX.tar.gz"), fs.constants.COPYFILE_EXCL);
  }
  fs.writeFileSync(path.join(input, "repositories.list"), indexes.map((row) => `/corb-layer-input/repositories/${row.repository}`).join("\n") + "\n", { flag: "wx", mode: 0o400 });
  if (installer !== undefined) {
    const bin = privateDirectory(path.join(input, "bin"));
    fs.writeFileSync(path.join(bin, "apk.static"), installer.binary!, { flag: "wx", mode: 0o500 });
  }
  return input;
}
export function inputMount(input: string) { return { "/corb-layer-input": new ReadonlyProvider(new RealFSProvider(input)) }; }
export const APK_PREFIX = ["/corb-layer-input/bin/apk.static", "--no-network", "--no-cache", "--repositories-file", "/corb-layer-input/repositories.list"];
async function installerVersion(vm: VM, version: string): Promise<void> {
  const result = await layerExec(vm, [APK_PREFIX[0]!, "--version"]);
  const upstream = version.replace(/-r\d+$/, "");
  if (!result.ok || !result.stdout.includes(`apk-tools ${version},`) || upstream !== "3.0.8") fail("authenticated resolver requires supported apk-tools 3.0.8. Explicitly refresh pins or review the new installer format");
}
export async function pinLayer(context = selectLayerWorkspace()) {
  const base = await resolveLayerBase(context.config.vm?.image); requireLayerExecution(base);
  if (base.manifest.config.arch !== context.arch) fail("base and layer target architectures differ");
  const { baseline } = await verifyLayerBase(base);
  const staging = ownedLayerStaging();
  try {
    const pins: LayerTargetPins = { os: "linux", abi: "musl", "alpine-branch": base.branch, "definition-sha256": hashLayerDefinition(context.definition), index: [], package: [] };
    if (context.definition.packages.length > 0) {
      const records: ApkIndexRecord[] = []; const indexes: Array<{ repository: string; filename: string }> = [];
      for (const repository of ["main", "community"] as const) {
        const url = `https://dl-cdn.alpinelinux.org/alpine/${base.branch}/${repository}/${context.arch}/APKINDEX.tar.gz`;
        const filename = path.join(staging, `${repository}.tar.gz`);
        await downloadInput(url, filename, context.definition["build-hosts"], 16 * 1024 ** 2);
        records.push(...await verifiedIndex(fs.readFileSync(filename), baseline.keys, repository, context.arch));
        const sha256 = await hashFile(filename); await publishBlob(filename, `sha256:${sha256}`);
        pins.index.push({ repository, url, sha256 }); indexes.push({ repository, filename });
      }
      for (const name of context.definition.packages) if (!records.some((row) => row.P === name)) fail(`requested real APK P: name '${name}' is absent from the signed snapshot. Explicitly refresh with corb image pin`);
      const installers = records.filter((row) => row.P === "apk-tools-static" && row.repository === "main");
      if (installers.length !== 1) fail("signed snapshot needs exactly one apk-tools-static identity");
      const installerRecord = installers[0]!;
      const installer = await downloadApk(installerRecord, base.branch, context.arch, baseline.keys, context.definition["build-hosts"], staging, true);
      pins.installer = { name: "apk-tools-static", version: installer.version, repository: "main", "apkindex-checksum": installer.checksum, "archive-sha256": installer.archiveSha256 };
      const input = prepareRepository(staging, indexes, installer, context.arch);
      const candidates = await withLayerVm(base, "corb-layer-resolver", context.definition["build-hosts"], async (vm) => {
        await installerVersion(vm, installer.version);
        const fetched = await layerExec(vm, [...APK_PREFIX, "fetch", "--recursive", "--url", "--simulate", ...context.definition.packages]);
        if (!fetched.ok) fail(`APK candidate closure failed: ${(fetched.stderr || fetched.stdout).slice(-8000)}`);
        process.stderr.write(`corb image pin: recursive APK query stdout=${JSON.stringify(fetched.stdout)} stderr=${JSON.stringify(fetched.stderr)}\n`);
        const rows: ApkIndexRecord[] = [];
        for (const line of (fetched.stdout + fetched.stderr).trim().split("\n").filter(Boolean)) {
          const candidate = records.filter((row) => line === `/corb-layer-input/repositories/${row.repository}/${context.arch}/${row.P}-${row.V}.apk` || line === `file:///corb-layer-input/repositories/${row.repository}/${context.arch}/${row.P}-${row.V}.apk`);
          if (candidate.length !== 1 || rows.some((row) => row.P === candidate[0]!.P)) fail(`recursive APK query returned an unrecognized or duplicate signed identity '${line}'`);
          rows.push(candidate[0]!);
        }
        if (rows.length > 1020 || !context.definition.packages.every((name) => rows.some((row) => row.P === name))) fail("candidate closure omitted a requested real package or exceeded graph bounds");
        return rows;
      }, { mounts: inputMount(input) });
      for (const record of candidates) {
        const identity = await downloadApk(record, base.branch, context.arch, baseline.keys, context.definition["build-hosts"], staging);
        pins.package.push({ name: identity.name, version: identity.version, repository: record.repository, "apkindex-checksum": identity.checksum, "archive-sha256": identity.archiveSha256, requested: context.definition.packages.includes(identity.name) });
        fs.copyFileSync(await verifyBlob(identity.archiveSha256), path.join(input, "repositories", record.repository, context.arch, `${record.P}-${record.V}.apk`), fs.constants.COPYFILE_EXCL);
      }
      const normalized = normalizeTargetPins(pins, context.arch);
      await withLayerVm(base, "corb-layer-compatibility", context.definition["build-hosts"], async (vm) => {
        const result = await layerExec(vm, [...APK_PREFIX, "add", "--simulate", ...normalized.package.filter((row) => row.requested).map((row) => `${row.name}=${row.version}`)]);
        if (!result.ok) fail(`incompatible base: requested APK world rejected: ${(result.stderr || result.stdout).slice(-8000)}`);
        parsePackagePlan(result.stdout, baseline.packages, normalized);
      }, { mounts: inputMount(input) });
    }
    for (const payload of context.definition.payload) {
      const filename = path.join(staging, `payload-${payload.name}`);
      await downloadInput(payload.url, filename, context.definition["build-hosts"], 512 * 1024 ** 2);
      if (await hashFile(filename) !== payload.sha256) fail(`SDK archive digest mismatch '${payload.name}'`);
      await stageSdkArchive(filename, payload, path.join(staging, `checked-${payload.name}`));
      await publishBlob(filename, `sha256:${payload.sha256}`);
    }
    const normalized = normalizeTargetPins(pins, context.arch);
    const graph = await publishInputGraph({ version: 1, definition: context.definition, pins: normalized }, context.arch);
    publishPinReceipt(hashRecipePins(normalized, context.arch), graph);
    await recheckLayerBase(base); context.recheck();
    refreshLayerPins(context.selected.entry.dir, context.arch, normalized);
    return { graph: graph.digest, pins: normalized, base: base.manifest.buildId };
  } finally { removeLayerStaging(staging); }
}
export async function authenticateGraph(graph: InputGraph, context: LayerContext, base: LayerBase, baseline: BaseSnapshot, staging: string) {
  assertPinsMatchDefinition(graph.config.pins, context.definition, context.arch);
  if (graph.config.pins["alpine-branch"] !== base.branch) fail("incompatible base Alpine branch differs from locked inputs");
  const records: ApkIndexRecord[] = [];
  for (const index of graph.config.pins.index) records.push(...await verifiedIndex(fs.readFileSync(inputBlobFile(graph, `index/${index.repository}`)), baseline.keys, index.repository, context.arch));
  const archives: VerifiedApk[] = [];
  let installer: VerifiedApk | undefined;
  for (const pin of [...(graph.config.pins.installer === undefined ? [] : [graph.config.pins.installer]), ...graph.config.pins.package]) {
    const matches = records.filter((row) => row.P === pin.name && row.V === pin.version && row.repository === pin.repository && row.C === pin["apkindex-checksum"]);
    if (matches.length !== 1) fail(`locked APK identity '${pin.name}=${pin.version}' is missing from its signed snapshot. Explicitly refresh with corb image pin`);
    const isInstaller = pin === graph.config.pins.installer;
    const identity = await verifiedApk(fs.readFileSync(inputBlobFile(graph, isInstaller ? "installer" : `package/${pin.name}`)), matches[0]!, baseline.keys, context.arch, pin["archive-sha256"], isInstaller);
    if (isInstaller) installer = identity; else archives.push(identity);
  }
  const input = prepareRepository(staging, graph.config.pins.index.map((index) => ({ repository: index.repository, filename: inputBlobFile(graph, `index/${index.repository}`) })), installer, context.arch);
  for (const pin of graph.config.pins.package) fs.copyFileSync(inputBlobFile(graph, `package/${pin.name}`), path.join(input, "repositories", pin.repository, context.arch, `${pin.name}-${pin.version}.apk`), fs.constants.COPYFILE_EXCL);
  privateDirectory(path.join(input, "sdk"));
  const payloads = [];
  for (const payload of context.definition.payload) {
    const tree = await stageSdkArchive(inputBlobFile(graph, `payload/${payload.name}`), payload, path.join(input, "sdk", payload.name));
    payloads.push({ ...payload, tree });
  }
  return { input, archives: archives.map(({ binary: _binary, ...identity }) => identity), payloads, installer };
}
