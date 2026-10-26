import fs from "node:fs";
import path from "node:path";
import { parseArgs } from "node:util";
import { listImageRefs } from "@earendil-works/gondolin";
import { corbStateDir } from "../config/paths.ts";
import { resolveLayerBase, recheckLayerBase } from "../layer/local-base.ts";
import { verifyLocalBase } from "../layer/vm.ts";
import { readJson } from "../layer/state.ts";
import { fail, table } from "../layer/validate.ts";

function knownCompositions(): Array<Record<string, unknown>> {
  const root = path.join(corbStateDir(), "layers");
  if (!fs.existsSync(root)) return [];
  const result: Array<Record<string, unknown>> = [];
  for (const workspace of fs.readdirSync(root, { withFileTypes: true }).filter((entry) => entry.isDirectory())) {
    for (const arch of ["x86_64", "aarch64"]) {
      const bases = path.join(root, workspace.name, arch, "bases"); if (!fs.existsSync(bases)) continue;
      for (const base of fs.readdirSync(bases, { withFileTypes: true }).filter((entry) => entry.isDirectory())) {
        const filename = path.join(bases, base.name, "current.json"); if (!fs.existsSync(filename)) continue;
        try { const pointer = table(readJson(filename), "current composition", ["version", "generation"]); if (pointer.version !== 1 || typeof pointer.generation !== "string" || !/^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/.test(pointer.generation)) fail("invalid current composition pointer"); result.push({ workspace: workspace.name, arch, baseBuildId: base.name, generation: pointer.generation, status: "recorded", note: "not verified by this read-only listing" }); }
        catch (error) { result.push({ workspace: workspace.name, arch, baseBuildId: base.name, status: "error", error: error instanceof Error ? error.message : String(error) }); }
      }
    }
  }
  return result;
}
export function runImageLs(argv: string[]): void {
  const { values } = parseArgs({ args: argv, strict: true, allowPositionals: false, options: { json: { type: "boolean" } } });
  const report = { version: 1, inventory: "local-sdk-refs", includesUntaggedObjects: false, refs: listImageRefs(), compositions: knownCompositions() };
  if (values.json) { console.log(JSON.stringify(report)); return; }
  console.log("Local SDK refs. This listing does not enumerate untagged objects.");
  for (const ref of report.refs) for (const [arch, buildId] of Object.entries(ref.targets)) console.log(`${ref.reference}\t${arch}\t${buildId}`);
  for (const composition of report.compositions) console.log(`composition\t${composition.workspace}\t${composition.arch}\tbase=${composition.baseBuildId}\tgeneration=${composition.generation ?? "?"}\t${composition.status}`);
}
export async function runImageVerify(argv: string[]): Promise<void> {
  const { positionals } = parseArgs({ args: argv, strict: true, allowPositionals: true, options: {} });
  if (positionals.length > 1) fail("image verify accepts at most one local selector");
  const base = await resolveLayerBase(positionals[0]);
  await verifyLocalBase(base); await recheckLayerBase(base);
  console.log(`corb image verify: package coherence and 7/7 gates passed buildId=${base.manifest.buildId}`);
}
