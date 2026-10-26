import fs from "node:fs";
import path from "node:path";
import { resolveRuntimeImage } from "../vm/image.ts";
import { projectPortableSdkManifest, BASE_ASSET_ROLES } from "./base.ts";
import { hashFile } from "./state.ts";
import { fail, sha256 } from "./validate.ts";

export async function resolveLayerBase(selector?: string) {
  const resolved = resolveRuntimeImage(selector);
  const directory = fs.realpathSync(resolved.assetDir);
  const manifestBytes = fs.readFileSync(path.join(directory, "manifest.json"));
  const manifest = projectPortableSdkManifest(JSON.parse(manifestBytes.toString("utf8")));
  if (resolved.buildId !== manifest.buildId || resolved.arch !== manifest.config.arch) fail("base selector, architecture and asset manifest disagree");
  const assets: Record<string, { path: string; sha256: string; size: number }> = {};
  for (const role of BASE_ASSET_ROLES) {
    const name = manifest.assets[role];
    if (name === undefined) continue;
    const filename = path.join(directory, name);
    if (fs.realpathSync(filename) !== filename || await hashFile(filename, 8 * 1024 ** 3) !== manifest.checksums[role]) fail(`base asset '${role}' has changed or escapes its canonical directory`);
    assets[role] = { path: filename, sha256: manifest.checksums[role]!, size: fs.statSync(filename).size };
  }
  return { selector: resolved.selector, directory, manifest, manifestSha256: sha256(manifestBytes), assets,
    branch: `v${manifest.config.alpine.version.split(".").slice(0, 2).join(".")}` };
}
export type LayerBase = Awaited<ReturnType<typeof resolveLayerBase>>;
export function requireLayerExecution(base: LayerBase): void {
  if (process.platform !== "linux" || process.arch !== "x64" || base.manifest.config.arch !== "x86_64") fail("layer execution requires native Linux x86_64 with qemu");
  if (process.env.GONDOLIN_VMM !== undefined && process.env.GONDOLIN_VMM !== "qemu") fail("layer execution requires qemu");
}
export async function recheckLayerBase(base: LayerBase): Promise<void> {
  const current = await resolveLayerBase(base.selector);
  if (JSON.stringify(current) !== JSON.stringify(base)) fail("selected base changed during operation");
}
