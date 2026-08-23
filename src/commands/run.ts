// `corb run` — M1.6: argv parsing and wiring only. The actual session
// assembly (image resolution, VFS mount, secret binding, exec, teardown)
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
import path from "node:path";
import { parseArgs } from "node:util";
import { runSession } from "../vm/session.ts";

export interface RunCommandArgs {
  dir: string;
  piArgs: string[];
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
  const { positionals } = parseArgs({ args: corbArgs, allowPositionals: true, strict: true });

  if (positionals.length > 1) {
    throw new Error(
      `corb run: unexpected extra argument '${positionals[1]}' (only one workspace directory is supported)`,
    );
  }

  const dir = positionals[0] !== undefined ? path.resolve(positionals[0]) : process.cwd();
  return { dir, piArgs };
}

export async function runRunCommand(argv: string[]): Promise<void> {
  const { dir, piArgs } = parseRunArgs(argv);
  await runSession({ dir, piArgs });
}
