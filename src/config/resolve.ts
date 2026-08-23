// `src/config/resolve.ts` — M2.5: the real disk-I/O bridge between the pure
// `src/config/{schema,load,trust}.ts` modules and a directory path. This is
// the first place in the config system that actually touches the
// filesystem — everything upstream (`schema.ts` M2.1, `load.ts` M2.2,
// `trust.ts` M2.3) is pure, taking already-read strings/objects.
//
// Deliberately does not build named-workspace-file resolution
// (`~/.config/corb/workspaces/<name>.toml`) — the plan's own spec describes
// `[WORKSPACE]` as a name resolved that way, but that machinery does not
// exist yet and is out of scope here (a later milestone's job). Instead,
// both `corb explain` (`src/commands/explain.ts`) and `corb run --dry-run`
// (`src/commands/run.ts`) take the exact same **directory path** argument
// `corb run` already takes today (M1.6/M2.4): a positional directory,
// defaulting to `process.cwd()` if omitted, synthesized into a single
// anonymous `[[dir]]` config-layer entry —
// `{ name: path.basename(resolvedDir), host: resolvedDir, mode: "rw" }` —
// exactly matching what `src/commands/run.ts` already does when calling
// `runSession`. This is what keeps `corb explain DIR` and `corb run DIR`
// (with or without `--dry-run`) describing the *same* thing, which is the
// property that actually matters for `--dry-run` to be trustworthy: if it
// showed something resolved a different way than a real run, it would be
// lying.
//
// Trust key: since there is no named workspace in this item's mode, the
// trust store is keyed by the resolved absolute directory path itself, not
// `EffectiveConfig.name` (which `trust.ts`'s own doc comment on `TrustStore`
// notes is just the caller's chosen key, not something that module derives
// or enforces). A directory path is a perfectly coherent identity for "this
// specific host directory, mounted this way" — the same spirit as that
// name-keying note, just a different key for this item's directory-anonymous
// mode. One consequence, matching that same note: moving a workspace to a
// different path starts a fresh trust history.
//
// This module is read-only with respect to trust: it evaluates
// (`evaluateTrust`) and returns the verdict, but never records an
// acceptance (`recordAcceptance`) and never writes `trusted.json` back to
// disk. Neither `corb explain` nor `corb run --dry-run` is "running"
// anything — there is no session, and no interactive confirmation flow
// exists yet (that is still a later milestone's job, once `corb run` for
// real gates on this).
import fs from "node:fs";
import path from "node:path";
import { mergeConfigLayers, type EffectiveConfig } from "./load.ts";
import { parseConfigLayer, type ConfigLayer } from "./schema.ts";
import { evaluateTrust, type TrustEvaluation, type TrustStore, type TrustedWorkspaceRecord } from "./trust.ts";
import { configTomlPath, corbConfigDir, trustStorePath } from "./paths.ts";

/** Thrown before any config is read when the requested workspace directory is unusable. Mirrors `src/vm/session.ts`'s `WorkspaceDirectoryError` in spirit, but is this module's own class — `src/config/` stays decoupled from `src/vm/` (see that file's own module comment). */
export class WorkspaceDirectoryError extends Error {
  constructor(dir: string, reason: string) {
    super(`corb config: workspace directory '${dir}' ${reason}`);
    this.name = "WorkspaceDirectoryError";
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

// Deliberately checks shape, not just "is it an object": a `trusted.json`
// that parses as valid JSON but isn't shaped like a `TrustStore` (e.g. an
// array, or an entry missing `configHash`) must fail loudly here rather than
// quietly behaving like an empty store somewhere downstream.
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
  /** Overrides `corbConfigDir()` — threads through to `paths.ts` so tests never need to touch the real `~/.config/corb`. */
  configDir?: string;
}

/** Everything a renderer (`src/config/render.ts`) needs to describe one directory's effective config and trust status. */
export interface ResolvedWorkspace {
  /** The resolved, absolute host directory this workspace describes. */
  dir: string;
  effectiveConfig: EffectiveConfig;
  trustEvaluation: TrustEvaluation;
  /** The trust store key this resolution was evaluated against — the resolved absolute directory path itself (see module comment). */
  trustKey: string;
  /** The trust record `trustEvaluation` was compared against, if one existed for `trustKey`; `undefined` for "never run before". */
  priorRecord: TrustedWorkspaceRecord | undefined;
}

/**
 * Resolves `dir` into a `ResolvedWorkspace`: validates the directory exists
 * and is a directory, reads and merges `config.toml` (optional) with a
 * synthesized single-dir layer for `dir` itself, reads the trust store
 * (optional) and evaluates trust for `dir`'s own path-keyed record. Does no
 * writing — see the module comment's "read-only with respect to trust" note.
 *
 * `BUILTIN_DEFAULTS` is not passed explicitly here; `mergeConfigLayers`
 * folds it in automatically (see `load.ts`'s own doc comment on
 * `mergeConfigLayers`).
 */
export function resolveWorkspaceForDirectory(dir: string, opts: ResolveWorkspaceOptions = {}): ResolvedWorkspace {
  const resolvedDir = resolveWorkspaceDirectory(dir);
  const configDir = opts.configDir ?? corbConfigDir();

  const configTomlLayer = readConfigTomlLayer(configDir);
  const dirLayer: ConfigLayer = {
    dir: [{ name: path.basename(resolvedDir), host: resolvedDir, mode: "rw" }],
  };
  const effectiveConfig = mergeConfigLayers([configTomlLayer, dirLayer]);

  const trustStore = readTrustStore(configDir);
  const trustKey = resolvedDir;
  const priorRecord = trustStore[trustKey];
  const trustEvaluation = evaluateTrust(priorRecord?.acceptedConfig, effectiveConfig);

  return { dir: resolvedDir, effectiveConfig, trustEvaluation, trustKey, priorRecord };
}
