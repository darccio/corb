import { parseArgs } from "node:util";
import path from "node:path";

export const STUB_MESSAGE = "corb: not yet implemented";

export function run(argv: string[] = process.argv.slice(2)): string {
  // Parse (and discard) whatever was passed so the toolchain proves it can
  // reach node:util's parseArgs — real subcommand parsing lands in M1.6.
  parseArgs({ args: argv, allowPositionals: true, strict: false });
  return STUB_MESSAGE;
}

const entry = process.argv[1];
if (entry !== undefined && path.resolve(entry) === import.meta.filename) {
  console.log(run());
}
