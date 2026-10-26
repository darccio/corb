import fs from "node:fs";
import path from "node:path";
import { parse, stringify } from "smol-toml";
import { writeFileSecure } from "../util/secure-write.ts";
import { assertLayerTarget, hashLayerDefinition, type LayerDefinition } from "./definition.ts";
import { validateArtifactReference } from "./reference.ts";
import { ARCHES, architecture, array, fail, PACKAGE_NAME, same, SHA256, sha256, string, table, type LayerArch } from "./validate.ts";

export interface LayerIndexPin { repository: "main" | "community"; url: string; sha256: string }
export interface LayerInstallerPin {
  name: "apk-tools-static";
  version: string;
  repository: "main";
  "apkindex-checksum": string;
  "archive-sha256": string;
}
export interface LayerPackagePin {
  name: string;
  version: string;
  repository: "main" | "community";
  "apkindex-checksum": string;
  "archive-sha256": string;
  requested: boolean;
}
export interface LayerTargetPins {
  os: "linux";
  abi: "musl";
  "alpine-branch": string;
  "definition-sha256": string;
  artifact?: string;
  index: LayerIndexPin[];
  installer?: LayerInstallerPin;
  package: LayerPackagePin[];
}
export type LayerRecipePins = Omit<LayerTargetPins, "artifact">;
export interface LayerLock { version: 1; target: Partial<Record<LayerArch, LayerTargetPins>> }
export interface LayerImageConfig { layer: LayerDefinition; pins?: LayerTargetPins }

const TARGET_KEYS = ["os", "abi", "alpine-branch", "definition-sha256", "artifact", "index", "installer", "package"];
const PACKAGE_KEYS = ["name", "version", "repository", "apkindex-checksum", "archive-sha256", "requested"];
const INSTALLER_KEYS = PACKAGE_KEYS.filter((key) => key !== "requested");

function repository(value: unknown): "main" | "community" {
  if (value !== "main" && value !== "community") fail("repository must be main or community");
  return value;
}
function version(value: unknown): string {
  return string(value, "package version", /^[^\s/\0:@]+$/);
}
export function validateApkindexChecksum(value: unknown): string {
  const result = string(value, "apkindex-checksum", /^Q1[A-Za-z0-9+/]{27}=$/);
  const bytes = Buffer.from(result.slice(2), "base64");
  if (bytes.length !== 20 || bytes.toString("base64") !== result.slice(2)) fail("apkindex-checksum must encode exactly 20 bytes");
  return result;
}
function packageIdentity(entry: Record<string, unknown>): Omit<LayerPackagePin, "requested"> {
  return { name: string(entry.name, "package.name", PACKAGE_NAME), version: version(entry.version), repository: repository(entry.repository),
    "apkindex-checksum": validateApkindexChecksum(entry["apkindex-checksum"]), "archive-sha256": string(entry["archive-sha256"], "archive-sha256", SHA256) };
}

export function normalizeTargetPins(value: unknown, arch: LayerArch): LayerTargetPins {
  architecture(arch);
  const entry = table(value, `target.${arch}`, TARGET_KEYS);
  if (entry.os !== "linux" || entry.abi !== "musl") fail("target requires os=linux and abi=musl");
  const branch = string(entry["alpine-branch"], "alpine-branch", /^v[0-9]+\.[0-9]+$/);
  const indexes = array(entry.index ?? [], "target.index").map((value) => {
    const index = table(value, "target.index", ["repository", "url", "sha256"]);
    const repo = repository(index.repository);
    const url = `https://dl-cdn.alpinelinux.org/alpine/${branch}/${repo}/${arch}/APKINDEX.tar.gz`;
    if (index.url !== url) fail(`index.url must equal '${url}'`);
    return { repository: repo, url, sha256: string(index.sha256, "index.sha256", SHA256) };
  }).sort((a, b) => a.repository === b.repository ? 0 : a.repository === "main" ? -1 : 1);
  if (new Set(indexes.map((item) => item.repository)).size !== indexes.length) fail("duplicate index repository");
  const packages = array(entry.package ?? [], "target.package").map((value) => {
    const pkg = table(value, "target.package", PACKAGE_KEYS);
    if (typeof pkg.requested !== "boolean") fail("package.requested must be boolean");
    return { ...packageIdentity(pkg), requested: pkg.requested };
  }).sort((a, b) => a.name < b.name ? -1 : a.name > b.name ? 1 : a.repository < b.repository ? -1 : a.repository > b.repository ? 1 : 0);
  if (new Set(packages.map((item) => item.name)).size !== packages.length) fail("duplicate package name");
  const result: LayerTargetPins = { os: "linux", abi: "musl", "alpine-branch": branch,
    "definition-sha256": string(entry["definition-sha256"], "definition-sha256", SHA256) } as LayerTargetPins;
  if (entry.artifact !== undefined) result.artifact = validateArtifactReference(entry.artifact);
  result.index = indexes;
  if (entry.installer !== undefined) {
    const installer = packageIdentity(table(entry.installer, "target.installer", INSTALLER_KEYS));
    if (installer.name !== "apk-tools-static" || installer.repository !== "main") fail("installer must be apk-tools-static from main");
    result.installer = { ...installer, name: "apk-tools-static", repository: "main" };
  }
  result.package = packages;
  if (packages.length > 0) {
    if (indexes.length !== 2 || result.installer === undefined || !packages.some((pkg) => pkg.requested)) fail("package pins require both indexes, an installer and requested packages");
  } else if (indexes.length > 0 || result.installer !== undefined) fail("recipes without packages cannot contain indexes or installer");
  return result;
}

export function assertPinsMatchDefinition(pins: LayerTargetPins, definition: LayerDefinition, arch: LayerArch): void {
  assertLayerTarget(definition, arch);
  const normalized = normalizeTargetPins(pins, arch);
  if (normalized["definition-sha256"] !== hashLayerDefinition(definition)) fail("pins do not match the layer definition. Refresh recipe pins");
  if (!same(normalized.package.filter((pkg) => pkg.requested).map((pkg) => pkg.name), definition.packages)) fail("requested package pins must equal image.layer.packages exactly");
}

export function recipePins(pins: LayerTargetPins, arch: LayerArch): LayerRecipePins {
  const { artifact: _artifact, ...recipe } = normalizeTargetPins(pins, arch);
  return recipe;
}
export function serializeRecipePins(pins: LayerTargetPins, arch: LayerArch): string { return JSON.stringify(recipePins(pins, arch)); }
export function hashRecipePins(pins: LayerTargetPins, arch: LayerArch): string { return sha256(serializeRecipePins(pins, arch)); }

export function normalizeLayerLock(value: unknown): LayerLock {
  const root = table(value, "corb.sum", ["version", "target"]);
  if (root.version !== 1) fail("corb.sum requires version = 1");
  const targets = table(root.target, "target", ARCHES);
  const result: LayerLock = { version: 1, target: {} };
  for (const arch of ARCHES) if (targets[arch] !== undefined) result.target[arch] = normalizeTargetPins(targets[arch], arch);
  return result;
}
export function parseLayerLock(text: string): LayerLock {
  let parsed: unknown;
  try { parsed = parse(text); } catch (error) { fail(`invalid corb.sum TOML: ${String(error)}`); }
  return normalizeLayerLock(parsed);
}
export function serializeLayerLock(lock: LayerLock): string {
  const normalized = normalizeLayerLock(lock);
  const target = Object.fromEntries(Object.entries(normalized.target).map(([arch, pins]) => {
    const { index, package: packages, ...fields } = pins;
    return [arch, { ...fields, ...(index.length === 0 ? {} : { index }), ...(packages.length === 0 ? {} : { package: packages }) }];
  }));
  return stringify({ version: 1, target });
}

function lockTarget(file: string): string | undefined {
  try {
    const stat = fs.lstatSync(file);
    const target = stat.isSymbolicLink() ? fs.realpathSync(file) : file;
    if (!fs.statSync(target).isFile()) fail(`corb.sum '${file}' is not a regular file`);
    return target;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") {
      // An existing symlink with no target is an error, not missing pins.
      try { if (fs.lstatSync(file).isSymbolicLink()) fail(`dangling corb.sum symlink '${file}'`); }
      catch (nested) { if ((nested as NodeJS.ErrnoException).code !== "ENOENT") throw nested; }
      return undefined;
    }
    throw error;
  }
}
export function readLayerLock(workspaceDir: string): LayerLock | undefined {
  const file = path.join(workspaceDir, "corb.sum");
  const target = lockTarget(file);
  if (target === undefined) return undefined;
  try { return parseLayerLock(fs.readFileSync(target, "utf8")); }
  catch (error) { fail(`could not read '${file}': ${error instanceof Error ? error.message : String(error)}`); }
}

export function refreshLayerPins(workspaceDir: string, arch: LayerArch, pins: LayerTargetPins): LayerLock {
  const prior = readLayerLock(workspaceDir) ?? { version: 1, target: {} };
  const next: LayerLock = { version: 1, target: { ...prior.target, [arch]: recipePins(pins, arch) } };
  const file = path.join(workspaceDir, "corb.sum");
  const target = lockTarget(file) ?? file;
  writeFileSecure(target, serializeLayerLock(next));
  return normalizeLayerLock(next);
}

export function pinCommandHint(workspaceName: string): string {
  return `corb image pin --workspace ${workspaceName}`;
}

export interface PackagePlanAction extends Omit<LayerPackagePin, "requested"> {
  action: "add" | "replace" | "upgrade" | "downgrade" | "reinstall" | "remove";
}

/** Validate solver additions. Candidate closure rows do not require installation on each base. */
export function assertCompatiblePackagePlan(pins: LayerRecipePins, actions: readonly PackagePlanAction[]): void {
  const seen = new Set<string>();
  for (const action of actions) {
    if (action.action !== "add") fail(`incompatible base: package ${action.action} '${action.name}' is forbidden`);
    if (seen.has(action.name)) fail(`duplicate package action '${action.name}'`);
    seen.add(action.name);
    const bundled = pins.package.find((pkg) => pkg.name === action.name);
    const { action: _action, ...identity } = action;
    if (bundled === undefined || !same(packageIdentity(identity), packageIdentity({ ...bundled }))) fail(`incompatible base: unbundled package identity '${action.name}'`);
  }
}
