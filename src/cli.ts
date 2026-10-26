#!/usr/bin/env node
import fs from "node:fs";
import { parseArgs } from "node:util";
import { runImageCommand } from "./commands/image.ts";
import { runRunCommand } from "./commands/run.ts";
import { runExplainCommand } from "./commands/explain.ts";
import { runDoctorCommand } from "./commands/doctor.ts";
import { runLsCommand } from "./commands/ls.ts";
import { runKillCommand } from "./commands/kill.ts";
import { runGcCommand } from "./commands/gc.ts";
import { runAttachCommand } from "./commands/attach.ts";
import { runLoginCommand, runLogoutCommand } from "./commands/login.ts";
import { runWorkspaceCommand } from "./commands/workspace.ts";

export const STUB_MESSAGE = "corb: not yet implemented";

export function run(argv: string[] = process.argv.slice(2)): string {
  // Parse (and discard) whatever was passed so the toolchain proves it can
  // reach node:util's parseArgs — real subcommand parsing lands in M1.6.
  parseArgs({ args: argv, allowPositionals: true, strict: false });
  return STUB_MESSAGE;
}

// Each command parses its own flags. Unknown top-level commands keep the historical stub.
async function main(argv: string[]): Promise<void> {
  if (argv[0] === "image") {
    await runImageCommand(argv.slice(1));
    return;
  }
  if (argv[0] === "run") {
    await runRunCommand(argv.slice(1));
    return;
  }
  if (argv[0] === "explain") {
    await runExplainCommand(argv.slice(1));
    return;
  }
  if (argv[0] === "workspace") {
    await runWorkspaceCommand(argv.slice(1));
    return;
  }
  if (argv[0] === "doctor") {
    await runDoctorCommand(argv.slice(1));
    return;
  }
  if (argv[0] === "ls") {
    await runLsCommand(argv.slice(1));
    return;
  }
  if (argv[0] === "kill") {
    await runKillCommand(argv.slice(1));
    return;
  }
  if (argv[0] === "gc") {
    await runGcCommand(argv.slice(1));
    return;
  }
  if (argv[0] === "attach") {
    await runAttachCommand(argv.slice(1));
    return;
  }
  if (argv[0] === "login") {
    await runLoginCommand(argv.slice(1));
    return;
  }
  if (argv[0] === "logout") {
    await runLogoutCommand(argv.slice(1));
    return;
  }
  console.log(run(argv));
}

// Node resolves symlinks when it loads a module, so `import.meta.filename`
// is always the file's *real* path — but `process.argv[1]` is whatever path
// was actually invoked, unresolved. npm's own `bin` mechanism (what turns
// package.json's `bin.corb` into `node_modules/.bin/corb`) installs that as
// a real symlink on Linux/macOS, so comparing it via `path.resolve` against
// `import.meta.filename` is false for exactly that case — the installed
// `corb` binary would silently skip `main()` for every invocation (no
// output, no error, exit 0). `fs.realpathSync` resolves the symlink the same
// way module loading already did, so the two sides compare equal again;
// this is Node's own documented fix for this ESM "is this the entry module"
// check.
const entry = process.argv[1];
if (entry !== undefined && fs.realpathSync(entry) === import.meta.filename) {
  main(process.argv.slice(2)).catch((err: unknown) => {
    console.error(err instanceof Error ? (err.stack ?? err.message) : String(err));
    process.exitCode = 1;
  });
}
