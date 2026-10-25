// Inspect the same selection, config, primary, and trust status used by run.
// This command never writes trust records or starts a VM.
import path from "node:path";
import { parseArgs } from "node:util";
import { resolveWorkspace } from "../config/resolve.ts";
import { renderJson, renderText } from "../config/render.ts";
import { buildCliLayer, resolvePrimaryName } from "./run.ts";

export interface ExplainCommandArgs {
  dir: string;
  dirExplicit: boolean;
  workspace: string | undefined;
  json: boolean;
  /** Raw `--dir NAME=HOST[:ro|:rw]` values, in argv order — see `src/commands/run.ts`'s `buildCliLayer`. */
  dirFlags: string[];
  primary: string | undefined;
}

export function parseExplainArgs(argv: string[]): ExplainCommandArgs {
  const { values, positionals } = parseArgs({
    args: argv,
    options: {
      json: { type: "boolean" },
      dir: { type: "string", multiple: true },
      primary: { type: "string" },
      workspace: { type: "string" },
    },
    allowPositionals: true,
    strict: true,
  });

  if (positionals.length > 1) {
    throw new Error(`corb explain: unexpected extra argument '${positionals[1]}' (only one workspace directory is supported)`);
  }

  const dir = positionals[0] !== undefined ? path.resolve(positionals[0]) : process.cwd();
  return { dir, dirExplicit: positionals[0] !== undefined, workspace: values.workspace, json: values.json ?? false, dirFlags: values.dir ?? [], primary: values.primary };
}

export async function runExplainCommand(argv: string[]): Promise<void> {
  const args = parseExplainArgs(argv);
  const cliLayer = buildCliLayer(args.dirFlags);
  const resolved = resolveWorkspace(args.dirExplicit || args.workspace === undefined ? args.dir : undefined, cliLayer, {
    ...(args.workspace === undefined ? {} : { workspace: args.workspace }),
    ...(args.primary === undefined ? {} : { primary: args.primary }),
  });
  resolved.primary = resolvePrimaryName(resolved.fullConfig, args.primary, resolved.primary);
  console.log(args.json ? renderJson(resolved) : renderText(resolved));
}
