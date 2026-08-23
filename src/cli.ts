import { parseArgs } from "node:util";
import path from "node:path";
import { runImageCommand } from "./commands/image.ts";
import { runRunCommand } from "./commands/run.ts";

export const STUB_MESSAGE = "corb: not yet implemented";

export function run(argv: string[] = process.argv.slice(2)): string {
  // Parse (and discard) whatever was passed so the toolchain proves it can
  // reach node:util's parseArgs — real subcommand parsing lands in M1.6.
  parseArgs({ args: argv, allowPositionals: true, strict: false });
  return STUB_MESSAGE;
}

// `image build` (M1.3) and `run` (M1.6) are the real subcommands so far.
// Everything else — ls, attach, kill, gc, doctor, explain, and any other
// `image` subcommand — keeps printing the M1.1 stub exactly as before; real
// subcommand parsing for the rest lands in later milestones.
async function main(argv: string[]): Promise<void> {
  if (argv[0] === "image" && argv[1] === "build") {
    await runImageCommand(argv.slice(1));
    return;
  }
  if (argv[0] === "run") {
    await runRunCommand(argv.slice(1));
    return;
  }
  console.log(run(argv));
}

const entry = process.argv[1];
if (entry !== undefined && path.resolve(entry) === import.meta.filename) {
  main(process.argv.slice(2)).catch((err: unknown) => {
    console.error(err instanceof Error ? (err.stack ?? err.message) : String(err));
    process.exitCode = 1;
  });
}
