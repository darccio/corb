import path from "node:path";
import { architecture, array, fail, integer, PACKAGE_NAME, SHA256, sha256, string, table, type LayerArch } from "./validate.ts";

export { LayerValidationError, nativeLayerArch, type LayerArch } from "./validate.ts";

export interface LayerPayload {
  name: string;
  url: string;
  sha256: string;
  arch: LayerArch;
  destination: string;
  "strip-components": number;
  path: string[];
}

export interface LayerRuntimeDir {
  path: string;
  mode: string;
  owner: string;
  group: string;
}

export interface LayerDefinition {
  packages: string[];
  commands: string[];
  "build-hosts": string[];
  hosts: string[];
  payload: LayerPayload[];
  "runtime-dir": LayerRuntimeDir[];
}

const DEFINITION_KEYS = ["packages", "commands", "build-hosts", "hosts", "payload", "runtime-dir"];
const PAYLOAD_KEYS = ["name", "url", "sha256", "arch", "destination", "strip-components", "path"];
const RUNTIME_KEYS = ["path", "mode", "owner", "group"];
const ACCOUNT = /^[a-z_][a-z0-9_-]*\$?$/;
const PAYLOAD_NAME = /^[a-z0-9][a-z0-9_-]*$/;
export const PROTECTED_RUNTIME_ROOTS = ["/run/corb", "/run/gondolin", "/mnt/corb-raw-gate", "/mnt/corb-raw", "/etc/gondolin", "/home/agent/.pi"] as const;

export function containsPosix(parent: string, child: string): boolean {
  return parent === child || child.startsWith(`${parent}/`);
}

export function normalizedPosixPath(value: unknown, location: string, absolute: boolean): string {
  const result = string(value, location);
  const components = result.split("/");
  if (result === "" || result.includes("\0") || result.includes("\\") || result.startsWith("/") !== absolute
    || components.includes(".") || components.includes("..") || path.posix.normalize(result) !== result
    || result.endsWith("/")) fail(`${location} must be a normalized ${absolute ? "absolute" : "relative"} POSIX path`);
  return result;
}

function hosts(value: unknown, location: string): string[] {
  return [...new Set(array(value, location).map((entry) => {
    const host = string(entry, location);
    // Gondolin treats every '*' as a substring wildcard within or across labels.
    if (host.trim() !== host || !/^[a-zA-Z0-9*](?:[a-zA-Z0-9*.-]*[a-zA-Z0-9*])?$/.test(host)
      || host.includes("..") || host.split(".").some((label) => label.startsWith("-") || label.endsWith("-"))) fail(`invalid hostname pattern in ${location}`);
    return host.toLowerCase();
  }))].sort();
}

function payload(value: unknown): LayerPayload {
  const entry = table(value, "image.layer.payload", PAYLOAD_KEYS);
  const name = string(entry.name, "payload.name", PAYLOAD_NAME);
  const rawUrl = string(entry.url, "payload.url");
  let url: URL;
  try { url = new URL(rawUrl); } catch { fail("payload.url must be an absolute HTTPS archive URL"); }
  if (url.protocol !== "https:" || url.username !== "" || url.password !== "" || url.search !== "" || url.hash !== ""
    || rawUrl.slice(8).split("/")[0]!.includes("@") || !rawUrl.startsWith("https://") || /[\s\\]/.test(rawUrl) || rawUrl.includes("?") || rawUrl.includes("#")) fail("payload.url must be HTTPS without credentials, query or fragment");
  const destination = normalizedPosixPath(entry.destination, "payload.destination", true);
  if (!containsPosix(`/opt/corb/toolchains/${name}`, destination)) fail(`payload.destination must be under /opt/corb/toolchains/${name}`);
  const paths = array(entry.path ?? [], "payload.path").map((value) => normalizedPosixPath(value, "payload.path", false));
  if (new Set(paths).size !== paths.length) fail("duplicate payload PATH entry");
  return { name, url: rawUrl, sha256: string(entry.sha256, "payload.sha256", SHA256), arch: architecture(entry.arch), destination,
    "strip-components": integer(entry["strip-components"] ?? 0, "payload.strip-components", 0, 16), path: paths };
}

function runtimeDir(value: unknown): LayerRuntimeDir {
  const entry = table(value, "image.layer.runtime-dir", RUNTIME_KEYS);
  const target = normalizedPosixPath(entry.path, "runtime-dir.path", true);
  if (!(target.startsWith("/run/") || target.startsWith("/var/log/"))) fail("runtime-dir.path must be strictly below /run or /var/log");
  for (const root of PROTECTED_RUNTIME_ROOTS) {
    if (containsPosix(root, target) || containsPosix(target, root)) fail(`runtime-dir.path overlaps protected root '${root}'`);
  }
  return { path: target, mode: string(entry.mode ?? "0755", "runtime-dir.mode", /^0[0-7]{3}$/),
    owner: string(entry.owner, "runtime-dir.owner", ACCOUNT), group: string(entry.group, "runtime-dir.group", ACCOUNT) };
}

export function normalizeLayerDefinition(value: unknown): LayerDefinition {
  const entry = table(value, "image.layer", DEFINITION_KEYS);
  const packages = [...new Set(array(entry.packages, "image.layer.packages").map((item) => {
    const name = string(item, "image.layer.packages", PACKAGE_NAME);
    if (name.endsWith(".apk")) fail("packages must be Alpine P: names, never APK filenames");
    return name;
  }))].sort();
  const commands = array(entry.commands ?? [], "image.layer.commands").map((item) => string(item, "image.layer.commands", /^[^\0]+$/));
  const payloads = array(entry.payload ?? [], "image.layer.payload").map(payload);
  if (new Set(payloads.map((item) => item.name)).size !== payloads.length) fail("duplicate payload name");
  const names = new Set<string>();
  const paths = new Set<string>();
  for (const current of payloads) {
    if (names.has(current.name)) fail(`duplicate payload name '${current.name}'`);
    names.add(current.name);
    for (const other of payloads) {
      if (current !== other && (containsPosix(current.destination, other.destination) || containsPosix(other.destination, current.destination))) fail("overlapping payload destinations");
    }
    for (const relative of current.path) {
      const full = `${current.destination}/${relative}`;
      if (paths.has(full)) fail("duplicate payload PATH entry");
      paths.add(full);
    }
  }
  const runtime = array(entry["runtime-dir"] ?? [], "image.layer.runtime-dir").map(runtimeDir).sort((a, b) => a.path < b.path ? -1 : a.path > b.path ? 1 : 0);
  if (new Set(runtime.map((item) => item.path)).size !== runtime.length) fail("duplicate runtime-dir path");
  if (packages.length + commands.length + payloads.length === 0) fail("image.layer requires at least one package, payload or command");
  return { packages, commands, "build-hosts": hosts(entry["build-hosts"] ?? ["dl-cdn.alpinelinux.org"], "image.layer.build-hosts"),
    hosts: hosts(entry.hosts ?? [], "image.layer.hosts"), payload: payloads, "runtime-dir": runtime };
}

export function assertLayerTarget(definition: LayerDefinition, arch: LayerArch): void {
  for (const item of definition.payload) {
    if (item.arch !== arch) fail(`payload '${item.name}' architecture '${item.arch}' is incompatible with selected target '${arch}'`);
  }
}

export function serializeLayerDefinition(definition: LayerDefinition): string {
  return JSON.stringify(normalizeLayerDefinition(definition));
}

export function hashLayerDefinition(definition: LayerDefinition): string {
  return sha256(serializeLayerDefinition(definition));
}

export function layerPayloadPath(definition: LayerDefinition): string[] {
  return definition.payload.flatMap((item) => item.path.map((relative) => `${item.destination}/${relative}`));
}
