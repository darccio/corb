import { parseArgs } from "node:util";
import { selectLayerWorkspace } from "../layer/context.ts";
import { acquireWorkspaceLock } from "../layer/state.ts";
import { composeLayer } from "../layer/compose.ts";
import { pinLayer } from "../layer/prepare.ts";

export function parseLayerCommandArgs(argv: string[], options: { transport?: boolean; destination?: boolean } = {}) {
  const { values, positionals } = parseArgs({ args: argv, strict: true, allowPositionals: options.destination === true, options: {
    workspace: { type: "string" }, ...(options.transport ? { "registry-config": { type: "string" }, "ca-file": { type: "string" } } as const : {}),
  } });
  if (positionals.length !== (options.destination ? 1 : 0)) throw new Error("expected exactly one REGISTRY/REPOSITORY:TAG destination");
  return { workspace: values.workspace, destination: positionals[0], registryConfig: values["registry-config"] as string | undefined, caFile: values["ca-file"] as string | undefined };
}
export async function runLayerPin(argv: string[]): Promise<void> {
  const args = parseLayerCommandArgs(argv);
  const context = selectLayerWorkspace(args.workspace);
  const release = acquireWorkspaceLock(context.selected.name);
  try {
    context.recheck();
    const result = await pinLayer(context);
    console.log(`corb image pin: workspace=${context.selected.name} target=${context.arch} inputs=${result.graph}`);
  } finally { release(); }
}

export async function runLayerBuild(argv: string[]): Promise<void> {
  const args = parseLayerCommandArgs(argv);
  const context = selectLayerWorkspace(args.workspace);
  const release = acquireWorkspaceLock(context.selected.name);
  try {
    context.recheck();
    const result = await composeLayer(context);
    console.log(`corb image layer build: ${result.alreadyInstalled ? "already installed" : "verified"} base=${result.base.manifest.buildId} generation=${result.metadata.generation} inputs=${result.metadata.inputDigest}`);
  } finally { release(); }
}
