// `corb explain` — M2.5: argv parsing and wiring only. Read-only inspection
// of a workspace directory's effective config and trust verdict, without
// booting anything — see `src/config/resolve.ts`'s module comment for what
// "workspace" means here (a directory path, not yet a named workspace file)
// and `src/config/render.ts` for how the result is formatted.
//
// CLI shape: `corb explain [DIR] [--dir NAME=HOST[:ro|:rw]]... [--primary
// NAME] [--json]`. `DIR` defaults to `process.cwd()` when omitted, matching
// `corb run`'s existing default exactly (`src/commands/run.ts`'s
// `parseRunArgs`). No `--` splitting is needed here — `explain` never
// forwards anything to `pi`. No `--trust-config` either — `explain` never
// writes `trusted.json` (see `src/config/resolve.ts`'s `acceptWorkspace`,
// which only `corb run` calls).
//
// M2.6: `explain` gained `--dir`/`--primary` alongside `run`, so `corb
// explain DIR --dir extra=~/other:ro` shows exactly what `corb run DIR
// --dir extra=~/other:ro --dry-run` would — the same property M2.5 built
// `explain`/`--dry-run` to share a pipeline for in the first place. The
// `--dir`/`--primary` parsing and validation logic itself
// (`parseDirFlag`/`buildCliLayer`/`resolvePrimaryName`) lives in
// `src/commands/run.ts` and is imported here rather than duplicated, so the
// two commands cannot silently diverge on what a flag means.
//
// On a resolution error (bad directory, malformed TOML, malformed trust
// store, malformed `--dir`/`--primary`), this deliberately does not add a
// second error-formatting layer: `src/cli.ts`'s top-level `.catch()` already
// prints `err.stack ?? err.message` for anything that escapes `main()`, and
// every error thrown along this path already has a clear, actionable
// message (see `src/config/resolve.ts`'s own
// `WorkspaceDirectoryError`/`ConfigReadError`/`TrustStoreError`, and
// `src/commands/run.ts`'s `DirFlagError`/`PrimaryDirectoryError`).
import path from "node:path";
import { parseArgs } from "node:util";
import { resolveWorkspace } from "../config/resolve.ts";
import { renderJson, renderText } from "../config/render.ts";
import { buildCliLayer, resolvePrimaryName } from "./run.ts";

export interface ExplainCommandArgs {
  dir: string;
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
    },
    allowPositionals: true,
    strict: true,
  });

  if (positionals.length > 1) {
    throw new Error(`corb explain: unexpected extra argument '${positionals[1]}' (only one workspace directory is supported)`);
  }

  const dir = positionals[0] !== undefined ? path.resolve(positionals[0]) : process.cwd();
  return { dir, json: values.json ?? false, dirFlags: values.dir ?? [], primary: values.primary };
}

export async function runExplainCommand(argv: string[]): Promise<void> {
  const args = parseExplainArgs(argv);
  const cliLayer = buildCliLayer(args.dirFlags);
  const resolved = resolveWorkspace(args.dir, cliLayer);
  // Validated for parity with what a real `corb run`/`corb run --dry-run`
  // invocation of the same flags would check — see module comment. The
  // resolved primary name itself isn't rendered (`render.ts` doesn't
  // describe "primary" today), only its validity.
  resolvePrimaryName(resolved.fullConfig, args.primary, path.basename(resolved.dir));
  console.log(args.json ? renderJson(resolved) : renderText(resolved));
}
