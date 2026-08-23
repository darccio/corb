// `corb run` — M1.6: argv parsing and wiring only. The actual session
// assembly (image resolution, VFS mounts, secret binding, exec, teardown)
// lives in `src/vm/session.ts`; this file's only job is turning `argv` into
// a `RunSessionOptions`.
//
// CLI shape: `corb run [WORKSPACE] [-- PI_ARGS...]`, matching the surface
// already recorded in the plan (`plans/.../` §2) rather than inventing a
// new one — a positional workspace directory, defaulting to `process.cwd()`
// when omitted, with anything after a literal `--` forwarded to `pi`
// untouched. `--dir` was considered (the M1.6 brief left the choice open)
// but the positional form is what the plan's own CLI surface already
// specifies, so there is no real fork to make here.
//
// M2.4 generalized `runSession` from a single `dir: string` to an explicit
// `dirs`/`primary` shape (N named directories, each `ro`/`rw`), but this
// file's own CLI surface is deliberately unchanged — no new flags. The one
// positional workspace directory this command has always accepted becomes a
// single-entry `dirs` array, named the same way `session.ts` already derived
// `sessionLabel` before this change (`path.basename(hostDir)`), mounted
// `rw`, and set as `primary`. Its guest mount path therefore moves from the
// old `/work` to `/work/<name>` — an intentional consequence of the new
// scheme (`docs/design.md` §3), not a regression. Wiring `--dir`/`--primary`
// flags to let a caller configure more than one directory from the CLI is
// M2.6's job, once the config system is wired in.
//
// M2.5 adds `--dry-run`: it shares the exact `resolve.ts`/`render.ts`
// pipeline `corb explain` (`src/commands/explain.ts`) uses, against the same
// directory `runSession` would otherwise use, and returns without ever
// calling `runSession` — no VM is created, and (this matters)
// `ANTHROPIC_API_KEY` is not required, since no secret binding or VM boot
// happens on this path. When `--dry-run` is not passed, the non-dry-run
// code path below is unchanged from what M2.4 left.
import path from "node:path";
import { parseArgs } from "node:util";
import { runSession } from "../vm/session.ts";
import { resolveWorkspaceForDirectory } from "../config/resolve.ts";
import { renderText } from "../config/render.ts";

export interface RunCommandArgs {
  dir: string;
  piArgs: string[];
  dryRun: boolean;
}

/**
 * Splits `argv` at the first literal `--`. Everything after it is forwarded
 * to `pi` verbatim, so it must not be run through `corb run`'s own arg
 * parser (which would otherwise treat `pi`-destined flags as its own).
 */
function splitPiArgs(argv: string[]): { corbArgs: string[]; piArgs: string[] } {
  const idx = argv.indexOf("--");
  if (idx === -1) {
    return { corbArgs: argv, piArgs: [] };
  }
  return { corbArgs: argv.slice(0, idx), piArgs: argv.slice(idx + 1) };
}

export function parseRunArgs(argv: string[]): RunCommandArgs {
  const { corbArgs, piArgs } = splitPiArgs(argv);
  const { values, positionals } = parseArgs({
    args: corbArgs,
    options: { "dry-run": { type: "boolean" } },
    allowPositionals: true,
    strict: true,
  });

  if (positionals.length > 1) {
    throw new Error(
      `corb run: unexpected extra argument '${positionals[1]}' (only one workspace directory is supported)`,
    );
  }

  const dir = positionals[0] !== undefined ? path.resolve(positionals[0]) : process.cwd();
  return { dir, piArgs, dryRun: values["dry-run"] ?? false };
}

export async function runRunCommand(argv: string[]): Promise<void> {
  const { dir, piArgs, dryRun } = parseRunArgs(argv);

  // `--dry-run`: describe what a real run would do and stop — never call
  // `runSession`, so no VM is created and no secret is required. Shares the
  // exact pipeline `corb explain` uses (see module comment).
  if (dryRun) {
    const resolved = resolveWorkspaceForDirectory(dir);
    console.log(renderText(resolved));
    return;
  }

  const name = path.basename(dir);
  await runSession({ dirs: [{ name, hostPath: dir, mode: "rw" }], primary: name, piArgs });
}
