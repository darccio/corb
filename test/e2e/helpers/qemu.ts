import path from "node:path";

export function isQemuVersionProbe(argv: readonly string[]): boolean {
  return argv.length === 2 && path.basename(argv[0]!) === "qemu-system-x86_64" && argv[1] === "--version";
}
