import fs from "node:fs";
import path from "node:path";

/** Resolve existing ancestors when the full path does not exist yet. */
export function realpathOrResolve(rawPath: string): string {
  const resolved = path.resolve(rawPath);
  try {
    return fs.realpathSync(resolved);
  } catch {
    // Resolve the nearest existing ancestor below.
  }
  const remainder: string[] = [];
  let ancestor = resolved;
  for (;;) {
    const parent = path.dirname(ancestor);
    if (parent === ancestor) {
      return resolved;
    }
    remainder.unshift(path.basename(ancestor));
    ancestor = parent;
    try {
      return path.join(fs.realpathSync(ancestor), ...remainder);
    } catch {
      // Continue toward the root.
    }
  }
}

/** True when `target` is `base` itself or lives under it. */
export function isSameOrDescendant(base: string, target: string): boolean {
  if (base === target) {
    return true;
  }
  const rel = path.relative(base, target);
  return rel !== "" && rel !== ".." && !rel.startsWith(`..${path.sep}`) && !path.isAbsolute(rel);
}
