// `corb explain` — M2.5: argv parsing and wiring only. Read-only inspection
// of a workspace directory's effective config and trust verdict, without
// booting anything — see `src/config/resolve.ts`'s module comment for what
// "workspace" means here (a directory path, not yet a named workspace file)
// and `src/config/render.ts` for how the result is formatted.
//
// CLI shape: `corb explain [DIR] [--json]`. `DIR` defaults to
// `process.cwd()` when omitted, matching `corb run`'s existing default
// exactly (`src/commands/run.ts`'s `parseRunArgs`). No `--` splitting is
// needed here — `explain` never forwards anything to `pi`.
//
// On a resolution error (bad directory, malformed TOML, malformed trust
// store), this deliberately does not add a second error-formatting layer:
// `src/cli.ts`'s top-level `.catch()` already prints `err.stack ??
// err.message` for anything that escapes `main()`, and every error thrown by
// `src/config/resolve.ts` already has a clear, actionable message (see that
// module's own `WorkspaceDirectoryError`/`ConfigReadError`/`TrustStoreError`).
import path from "node:path";
import { parseArgs } from "node:util";
import { resolveWorkspaceForDirectory } from "../config/resolve.ts";
import { renderJson, renderText } from "../config/render.ts";

export interface ExplainCommandArgs {
  dir: string;
  json: boolean;
}

export function parseExplainArgs(argv: string[]): ExplainCommandArgs {
  const { values, positionals } = parseArgs({
    args: argv,
    options: { json: { type: "boolean" } },
    allowPositionals: true,
    strict: true,
  });

  if (positionals.length > 1) {
    throw new Error(`corb explain: unexpected extra argument '${positionals[1]}' (only one workspace directory is supported)`);
  }

  const dir = positionals[0] !== undefined ? path.resolve(positionals[0]) : process.cwd();
  return { dir, json: values.json ?? false };
}

export async function runExplainCommand(argv: string[]): Promise<void> {
  const args = parseExplainArgs(argv);
  const resolved = resolveWorkspaceForDirectory(args.dir);
  console.log(args.json ? renderJson(resolved) : renderText(resolved));
}
