// Read global and selected workspace layers, then check personal trust and mount safety.
// Persistent layers include an added positional directory. CLI flags only affect fullConfig.
// Selection metadata stays outside the effective config and its trust hash.
import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import { mergeConfigLayers, type DirConfig, type EffectiveConfig } from "./load.ts";
import { parseConfigLayer, type ConfigLayer } from "./schema.ts";
import {
  evaluateTrust,
  hashEffectiveConfig,
  recordAcceptance,
  type TrustEvaluation,
  type TrustStore,
  type TrustedWorkspaceRecord,
} from "./trust.ts";
import { configTomlPath, corbConfigDir, corbStateDir, trustStorePath, expandHomePrefix } from "./paths.ts";
import { writeFileSecure } from "../util/secure-write.ts";
import { agentProviderLayer, applyImpliedHosts, type ImpliedHost } from "./implied.ts";
import { isSameOrDescendant, realpathOrResolve } from "./hostpaths.ts";
import { listWorkspaces, selectWorkspace, workspaceSourcePaths, workspaceTrustKey, WorkspaceSelectionError, type WorkspaceListing } from "./workspaces.ts";
import { resolveLayerHosts } from "./hostpath.ts";

export { isSameOrDescendant, realpathOrResolve } from "./hostpaths.ts";

/** The requested positional directory must exist and be a directory. */
export class WorkspaceDirectoryError extends Error {
  constructor(dir: string, reason: string) {
    super(`corb config: workspace directory '${dir}' ${reason}`);
    this.name = "WorkspaceDirectoryError";
  }
}

/**
 * Thrown when a `[[dir]]`/`--dir` host path is, or overlaps, one of Corb's
 * own config/state directories, or an explicitly-configured `audit.path`.
 * Enforces `docs/adr/0006`'s stated invariant ("workspace files live...
 * entirely outside any directory a workspace mounts") — nothing checked this
 * before: a mount that contained `~/.config/corb` handed a hostile guest
 * read-write access to `config.toml`/`trusted.json`, letting it rewrite the
 * config and pre-accept a matching trust record (`hashEffectiveConfig` is
 * unkeyed, so the guest can reproduce it) for a future, wider-than-intended
 * run. The same reasoning applies to an `[audit] path = "..."` that lands
 * inside a mount: the guest could truncate or rewrite the one record of its
 * own denials.
 */
type ForbiddenMountKind = "config" | "state" | "audit" | "workspace-source" | "workspace" | "workspace-file";

export class ForbiddenMountError extends Error {
  constructor(hostPath: string, corbDir: string, corbDirKind: ForbiddenMountKind) {
    const nouns: Record<ForbiddenMountKind, string> = {
      config: "config directory", state: "state directory", audit: "audit log file",
      "workspace-source": "workspace source directory", workspace: "workspace directory", "workspace-file": "workspace file",
    };
    const noun = nouns[corbDirKind];
    super(
      `corb config: mount host path '${hostPath}' overlaps Corb's own ${noun} '${corbDir}' — refusing to mount it (see docs/adr/0006-workspace-config-outside-every-mount.md and docs/adr/0013-workspaces-as-directories-shared-like-dotfiles.md)`,
    );
    this.name = "ForbiddenMountError";
  }
}

/** Thrown when a file under `configDir` exists but cannot be read for a reason other than "does not exist" (permissions, etc.) — that is a real error and must surface clearly, not be silently swallowed. */
export class ConfigReadError extends Error {
  constructor(filePath: string, cause: unknown) {
    super(`corb config: could not read '${filePath}': ${cause instanceof Error ? cause.message : String(cause)}`);
    this.name = "ConfigReadError";
  }
}

/** Thrown when `trusted.json` exists but is not valid JSON, or does not match the expected `TrustStore` shape — a corrupted trust store must never be silently treated as an empty ("everything is trusted for the first time") one. */
export class TrustStoreError extends Error {
  constructor(storePath: string, detail: string) {
    super(`corb config: trust store '${storePath}' ${detail}`);
    this.name = "TrustStoreError";
  }
}

function isErrnoException(err: unknown): err is NodeJS.ErrnoException {
  return err instanceof Error && "code" in err;
}

function resolveWorkspaceDirectory(dir: string): string {
  const resolved = path.resolve(dir);
  let stat: fs.Stats;
  try {
    stat = fs.statSync(resolved);
  } catch {
    throw new WorkspaceDirectoryError(resolved, "does not exist");
  }
  if (!stat.isDirectory()) {
    throw new WorkspaceDirectoryError(resolved, "is not a directory");
  }
  return resolved;
}

// `config.toml` is optional (`docs/design.md`'s "config.toml holds
// defaults") — its absence is the normal, expected first-run state, not an
// error. Any other read failure (malformed TOML from `parseConfigLayer`
// itself, or a filesystem error like EACCES) propagates as a real error.
function readConfigTomlLayer(configDir: string): ConfigLayer {
  const tomlPath = configTomlPath(configDir);
  let text: string;
  try {
    text = fs.readFileSync(tomlPath, "utf8");
  } catch (err) {
    if (isErrnoException(err) && err.code === "ENOENT") {
      return {};
    }
    throw new ConfigReadError(tomlPath, err);
  }
  return parseConfigLayer(text, tomlPath);
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/**
 * Refuse mounts that overlap personal config, state, audit, sources, or workspace files.
 * The check covers both overlap directions after resolving symlinks.
 * Sources include missing paths and all workspace copies, even replaced or invalid ones.
 * Workspace files can point outside their directories, so their real paths need separate protection.
 * The final directory list covers positional mounts, global entries, and CLI overrides.
 * This runs before VM startup, including explain and dry-run commands.
 */
function assertNoMountOverlapsCorbDirs(dirs: readonly DirConfig[], configDir: string, workspaces: WorkspaceListing, auditPath?: string): void {
  const forbidden: Array<{ resolved: string; label: string; kind: ForbiddenMountKind }> = [
    { resolved: realpathOrResolve(configDir), label: configDir, kind: "config" },
    { resolved: realpathOrResolve(corbStateDir()), label: corbStateDir(), kind: "state" },
  ];
  if (auditPath !== undefined) {
    forbidden.push({ resolved: realpathOrResolve(auditPath), label: auditPath, kind: "audit" });
  }
  for (const source of workspaces.sources) {
    forbidden.push({ resolved: source.realPath, label: source.path, kind: "workspace-source" });
  }
  for (const entry of workspaces.allWorkspaces) {
    forbidden.push({ resolved: entry.realPath, label: entry.dir, kind: "workspace" });
    forbidden.push({ resolved: entry.corbToml, label: entry.corbToml, kind: "workspace-file" });
    if (entry.corbSum !== undefined) {
      forbidden.push({ resolved: entry.corbSum, label: entry.corbSum, kind: "workspace-file" });
    }
  }
  for (const entry of dirs) {
    if (entry.host === undefined) {
      continue;
    }
    const host = realpathOrResolve(entry.host);
    for (const { resolved, label, kind } of forbidden) {
      if (isSameOrDescendant(host, resolved) || isSameOrDescendant(resolved, host)) {
        throw new ForbiddenMountError(entry.host, label, kind);
      }
    }
  }
}

// Deliberately checks shape, not just "is it an object": a `trusted.json`
// that parses as valid JSON but isn't shaped like a `TrustStore` (e.g. an
// array, or an entry missing `configHash`) must fail loudly here rather than
// quietly behaving like an empty store somewhere downstream.
//
// Also recomputes `hashEffectiveConfig(record.acceptedConfig)` and compares
// it to the stored `configHash` — previously `configHash` was written by
// `recordAcceptance` and shape-checked here, but never actually compared to
// anything, so a `trusted.json` hand-edited (or corrupted by a partial
// write) to change `acceptedConfig` without updating `configHash` to match
// was silently accepted as a valid prior record: `evaluateTrust` only ever
// looked at `acceptedConfig`, never at whether `configHash` attested to it.
// This does not make `trusted.json` tamper-*proof* — an attacker with write
// access can trivially recompute a matching hash with the same exported
// function — but it does mean an *inconsistent* store (the two most likely
// real causes: a hand-edit that forgot to update the hash, or a torn write)
// fails loudly here instead of `evaluateTrust` silently comparing against
// whatever `acceptedConfig` happens to contain.
function validateTrustStoreShape(value: unknown, storePath: string): TrustStore {
  if (!isPlainObject(value)) {
    throw new TrustStoreError(storePath, "must contain a JSON object mapping workspace keys to trust records");
  }
  for (const [key, record] of Object.entries(value)) {
    if (!isPlainObject(record)) {
      throw new TrustStoreError(storePath, `entry '${key}' must be an object`);
    }
    if (typeof record.configHash !== "string") {
      throw new TrustStoreError(storePath, `entry '${key}' is missing a string 'configHash' field`);
    }
    if (typeof record.acceptedAt !== "number") {
      throw new TrustStoreError(storePath, `entry '${key}' is missing a numeric 'acceptedAt' field`);
    }
    if (!isPlainObject(record.acceptedConfig)) {
      throw new TrustStoreError(storePath, `entry '${key}' is missing an 'acceptedConfig' object field`);
    }
    const recomputed = hashEffectiveConfig(record.acceptedConfig as unknown as EffectiveConfig);
    if (recomputed !== record.configHash) {
      throw new TrustStoreError(
        storePath,
        `entry '${key}' has a 'configHash' that does not match its 'acceptedConfig' (store is corrupted or was hand-edited)`,
      );
    }
  }
  return value as unknown as TrustStore;
}

// No prior trust record at all (`trusted.json` absent) is the normal
// "never run before" state, not an error — same reasoning as `config.toml`
// being optional above.
function readTrustStore(configDir: string): TrustStore {
  const storePath = trustStorePath(configDir);
  let text: string;
  try {
    text = fs.readFileSync(storePath, "utf8");
  } catch (err) {
    if (isErrnoException(err) && err.code === "ENOENT") {
      return {};
    }
    throw new ConfigReadError(storePath, err);
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch (err) {
    throw new TrustStoreError(storePath, `is not valid JSON: ${err instanceof Error ? err.message : String(err)}`);
  }
  return validateTrustStoreShape(parsed, storePath);
}

export interface ResolveWorkspaceOptions {
  /** Override the personal config directory. */
  configDir?: string;
  workspace?: string;
  /** Allow a named run without its own hosted directory to choose an explicit primary. */
  primary?: string;
}

export interface ResolvedWorkspace {
  /** Undefined only for a named workspace run without positional DIR. */
  dir: string | undefined;
  primary: string;
  selectedWorkspace: {
    name: string;
    selectedBy: "name" | "path";
    source: { index: number; raw: string; path: string };
    dir: string;
    corbToml: string;
  } | undefined;
  /** True when the positional directory contributes a persistent mount layer. */
  positionalDirAdded: boolean;
  persistentConfig: EffectiveConfig;
  fullConfig: EffectiveConfig;
  impliedHosts: ImpliedHost[];
  trustEvaluation: TrustEvaluation;
  trustKey: string;
  priorRecord: TrustedWorkspaceRecord | undefined;
  workspaces: WorkspaceListing;
}

/** Resolve without writes. Track the provider layer before trust, then guard the final CLI merge. */
export function resolveWorkspace(dir: string | undefined, cliLayer: ConfigLayer, opts: ResolveWorkspaceOptions = {}): ResolvedWorkspace {
  if (dir === undefined && opts.workspace === undefined) {
    throw new WorkspaceSelectionError("a directory or --workspace <name> is required");
  }
  const configDir = opts.configDir ?? corbConfigDir();
  const rawConfigLayer = readConfigTomlLayer(configDir);
  const projectsRoot = rawConfigLayer.workspaces?.["projects-root"] === undefined
    ? undefined : expandHomePrefix(rawConfigLayer.workspaces["projects-root"]);
  const hostOptions = { home: os.homedir(), ...(projectsRoot === undefined ? {} : { projectsRoot }) };
  const configTomlLayer = resolveLayerHosts(rawConfigLayer, { ...hostOptions, sourceLabel: configTomlPath(configDir) });
  const workspaces = listWorkspaces(workspaceSourcePaths(configTomlLayer, configDir), configDir);
  if (projectsRoot !== undefined) {
    workspaces.projectsRoot = projectsRoot;
  }
  const resolvedDir = dir === undefined ? undefined : resolveWorkspaceDirectory(dir);
  const selected = selectWorkspace({
    listing: workspaces,
    ...(opts.workspace === undefined ? {} : { byName: opts.workspace }),
    ...(resolvedDir === undefined ? {} : { dir: resolvedDir }),
    loadLayer: (entry) => {
      let text: string;
      try {
        text = fs.readFileSync(entry.corbToml, "utf8");
      } catch (err) {
        throw new ConfigReadError(entry.corbToml, err);
      }
      return resolveLayerHosts(parseConfigLayer(text, entry.corbToml, { scope: "workspace" }), {
        ...hostOptions, sourceLabel: entry.corbToml,
      });
    },
  });
  const positionalDirAdded = resolvedDir !== undefined && selected?.matchedDir === undefined;
  const layers = [configTomlLayer, ...(selected === undefined ? [] : [selected.layer])];
  if (positionalDirAdded) {
    const name = path.basename(resolvedDir!);
    const existingHost = selected === undefined ? undefined
      : layers.flatMap((layer) => layer.dir ?? []).find((entry) => entry.name === name && entry.host !== undefined);
    if (existingHost !== undefined) {
      throw new WorkspaceSelectionError(`positional directory '${resolvedDir}' has the same basename '${name}' as a configured hosted directory. Use --dir NAME=HOST to choose another mount name`);
    }
    layers.push({ dir: [{ name, host: resolvedDir!, mode: "rw" }] });
  }
  const { config: persistentConfig, implied: impliedHosts } = applyImpliedHosts(mergeConfigLayers(layers), {
    providerLayer: agentProviderLayer(configTomlLayer, selected === undefined ? undefined : { name: selected.name, layer: selected.layer }),
  });
  let primary: string;
  let keyDir: string;
  if (selected?.matchedDir?.host !== undefined) {
    primary = selected.matchedDir.name!;
    keyDir = realpathOrResolve(selected.matchedDir.host);
  } else if (resolvedDir !== undefined) {
    primary = path.basename(resolvedDir);
    keyDir = resolvedDir;
  } else {
    const firstHost = selected!.layer.dir?.find((entry) => entry.host !== undefined);
    if (firstHost !== undefined) {
      primary = firstHost.name!;
      keyDir = realpathOrResolve(firstHost.host!);
    } else {
      const explicit = opts.primary === undefined ? undefined
        : mergeConfigLayers([persistentConfig, cliLayer]).dir.find((entry) => entry.name === opts.primary && entry.host !== undefined);
      if (explicit?.host === undefined) {
        throw new WorkspaceSelectionError(`workspace '${selected!.name}' has no hosted directory of its own. Set a host in corb.toml or use --primary with a hosted directory`);
      }
      primary = explicit.name;
      keyDir = realpathOrResolve(explicit.host);
    }
  }
  const trustStore = readTrustStore(configDir);
  const trustKey = selected === undefined ? keyDir : workspaceTrustKey(selected.name, keyDir);
  const priorRecord = trustStore[trustKey];
  const trustEvaluation = evaluateTrust(priorRecord?.acceptedConfig, persistentConfig);
  const fullConfig = mergeConfigLayers([persistentConfig, cliLayer]);
  assertNoMountOverlapsCorbDirs(fullConfig.dir, configDir, workspaces, fullConfig.audit?.path);
  const selectedWorkspace = selected === undefined ? undefined : {
    name: selected.name, selectedBy: selected.selectedBy,
    source: { index: selected.entry.source, raw: workspaces.sources[selected.entry.source]!.raw, path: workspaces.sources[selected.entry.source]!.path },
    dir: selected.entry.dir, corbToml: selected.entry.corbToml,
  };
  return { dir: resolvedDir, primary, selectedWorkspace, positionalDirAdded, persistentConfig, fullConfig, impliedHosts, trustEvaluation, trustKey, priorRecord, workspaces };
}

/**
 * Records acceptance of `persistentConfig` for `trustKey` at `acceptedAt`
 * (caller-supplied — this module doesn't call `Date.now()` itself, matching
 * `trust.ts`'s own discipline) and writes the updated trust store back to
 * `trusted.json`, creating the config directory first if this is the very
 * first file Corb has ever written there for this user. Reads and validates
 * the current store first (reusing `readTrustStore`'s existing logic) so a
 * corrupted `trusted.json` fails loudly here too, rather than being silently
 * clobbered.
 *
 * The write itself goes through `src/util/secure-write.ts`'s
 * `writeFileSecure`: atomic (temp file + rename, so a crash or `SIGKILL`
 * mid-write can never leave a torn `trusted.json` for the next
 * `readTrustStore` call to trip over) and permission-hardened (0600 on the
 * file, 0700 on the config directory if this call is the one that creates
 * it).
 */
export function acceptWorkspace(
  trustKey: string,
  persistentConfig: EffectiveConfig,
  acceptedAt: number,
  opts: ResolveWorkspaceOptions = {},
): void {
  const configDir = opts.configDir ?? corbConfigDir();
  const trustStore = readTrustStore(configDir);
  const updated = recordAcceptance(trustStore, trustKey, persistentConfig, acceptedAt);
  writeFileSecure(trustStorePath(configDir), JSON.stringify(updated, null, 2));
}
