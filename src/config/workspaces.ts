import fs from "node:fs";
import path from "node:path";
import { corbConfigDir, defaultWorkspacesDir, expandHomePrefix } from "./paths.ts";
import { realpathOrResolve } from "./hostpaths.ts";
import type { ConfigLayer } from "./schema.ts";

export interface WorkspaceSourcePath {
  raw: string;
  path: string;
}

export interface WorkspaceSource extends WorkspaceSourcePath {
  realPath: string;
  exists: boolean;
}

export interface ListedWorkspace {
  name: string;
  dir: string;
  realPath: string;
  corbToml: string;
  corbSum?: string;
  source: number;
  valid: boolean;
  reason?: string;
  replaced: Array<{ source: number; dir: string }>;
}

export interface WorkspaceListing {
  sources: WorkspaceSource[];
  workspaces: ListedWorkspace[];
  /** Includes replaced copies so the guard protects them too. */
  allWorkspaces: ListedWorkspace[];
}

export class WorkspaceSourceError extends Error {
  constructor(source: string, detail: string) {
    super(`corb config: workspace source '${source}': ${detail}`);
    this.name = "WorkspaceSourceError";
  }
}

export class InvalidWorkspaceNameError extends Error {
  constructor(name: string) {
    super(`invalid workspace name '${name}': expected one component matching ^[A-Za-z0-9][A-Za-z0-9._-]*$`);
    this.name = "InvalidWorkspaceNameError";
  }
}

export function assertValidWorkspaceName(name: string): void {
  if (!/^[A-Za-z0-9][A-Za-z0-9._-]*$/.test(name)) {
    throw new InvalidWorkspaceNameError(name);
  }
}

export function workspaceSourcePaths(layer: ConfigLayer, configDir: string = corbConfigDir()): WorkspaceSourcePath[] {
  return (layer.workspaces?.paths ?? [defaultWorkspacesDir(configDir)])
    .map((raw) => ({ raw, path: path.resolve(expandHomePrefix(raw)) }));
}

function isMissing(err: unknown): boolean {
  return err instanceof Error && "code" in err && err.code === "ENOENT";
}

function lstatIfPresent(filePath: string): fs.Stats | undefined {
  try {
    return fs.lstatSync(filePath);
  } catch (err) {
    if (isMissing(err)) {
      return undefined;
    }
    throw err;
  }
}

function assertNoDanglingSourceLink(sourcePath: string): void {
  let current = sourcePath;
  for (;;) {
    if (lstatIfPresent(current)?.isSymbolicLink()) {
      fs.realpathSync(current);
    }
    const parent = path.dirname(current);
    if (parent === current) {
      return;
    }
    current = parent;
  }
}

function assertPersonalTrust(directory: string): void {
  if (lstatIfPresent(path.join(directory, "trusted.json")) !== undefined) {
    throw new Error(`'${path.join(directory, "trusted.json")}' exists. Trust must stay in the personal config directory`);
  }
}

function statIfPresent(filePath: string): fs.Stats | undefined {
  try {
    return fs.statSync(filePath);
  } catch (err) {
    if (isMissing(err)) {
      return undefined;
    }
    throw err;
  }
}

/** List directory metadata without parsing any workspace configuration. */
export function listWorkspaces(sourcePaths: readonly WorkspaceSourcePath[], configDir: string = corbConfigDir()): WorkspaceListing {
  const sources: WorkspaceSource[] = [];
  const allWorkspaces: ListedWorkspace[] = [];
  const selected = new Map<string, ListedWorkspace>();
  for (const [source, input] of sourcePaths.entries()) {
    try {
      assertNoDanglingSourceLink(input.path);
      const stat = statIfPresent(input.path);
      const realPath = stat === undefined ? realpathOrResolve(input.path) : fs.realpathSync(input.path);
      if (realPath === realpathOrResolve(configDir)) {
        throw new Error("source equals the personal config directory. Trust must stay in the personal config directory");
      }
      if (stat === undefined) {
        sources.push({ ...input, realPath, exists: false });
        continue;
      }
      if (!stat.isDirectory()) {
        throw new Error("is not a directory");
      }
      sources.push({ ...input, realPath, exists: true });
      assertPersonalTrust(input.path);
      for (const name of fs.readdirSync(input.path).sort()) {
        const dir = path.join(input.path, name);
        if (!statIfPresent(dir)?.isDirectory()) {
          continue;
        }
        assertPersonalTrust(dir);
        if (name.startsWith(".")) {
          continue;
        }
        const toml = path.join(dir, "corb.toml");
        if (!statIfPresent(toml)?.isFile()) {
          continue;
        }
        const entry: ListedWorkspace = {
          name, dir, realPath: fs.realpathSync(dir), corbToml: fs.realpathSync(toml), source,
          valid: true, replaced: [],
        };
        const sum = path.join(dir, "corb.sum");
        if (lstatIfPresent(sum) !== undefined) {
          entry.corbSum = fs.realpathSync(sum);
        }
        try {
          assertValidWorkspaceName(name);
        } catch (err) {
          entry.valid = false;
          entry.reason = err instanceof Error ? err.message : String(err);
        }
        const previous = selected.get(name);
        if (previous !== undefined) {
          entry.replaced = [...previous.replaced, { source: previous.source, dir: previous.dir }];
        }
        allWorkspaces.push(entry);
        selected.set(name, entry);
      }
    } catch (err) {
      const detail = err instanceof Error ? err.message : String(err);
      throw new WorkspaceSourceError(input.raw, detail);
    }
  }
  return { sources, workspaces: [...selected.values()], allWorkspaces };
}
