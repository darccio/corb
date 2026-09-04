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
// M2.6 update — two `EffectiveConfig` values, not one: `resolveWorkspace`
// below produces a **persistent** config (built-in defaults + `config.toml`
// + the synthesized single-dir layer for the positional `DIR` — exactly
// what this module always computed) and a **full** config (the persistent
// config with a caller-supplied CLI layer, e.g. `--dir`-derived entries,
// merged on top). Only the persistent config ever participates in the trust
// ratchet (`evaluateTrust`, and — new in M2.6 — `acceptWorkspace`'s write of
// `recordAcceptance`'s result back to `trusted.json`): CLI flags are always
// trusted, "the human typed them" (`trust.ts`'s own module comment), and
// that invariant only holds if they never sneak into what gets hashed,
// compared, or recorded. The full config is what an actual `corb run`
// builds `RunSessionOptions` from, and what `corb explain`/`corb run
// --dry-run` display as "what will actually happen" — see
// `src/config/render.ts`.
//
// This module now does write `trusted.json` (`acceptWorkspace`), unlike
// M2.5's read-only version — this may be the first file Corb ever writes
// under `~/.config/corb/` for a given user, so `acceptWorkspace` creates the
// config directory if needed. `resolveWorkspace` itself is still read-only;
// only `acceptWorkspace` writes, and only when a caller (`src/commands/
// run.ts`, on `--trust-config` or an already-trusted verdict) calls it.
import fs from "node:fs";
import path from "node:path";
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
import { configTomlPath, corbConfigDir, corbStateDir, trustStorePath } from "./paths.ts";
import { writeFileSecure } from "../util/secure-write.ts";

/** Thrown before any config is read when the requested workspace directory is unusable. Mirrors `src/vm/session.ts`'s `WorkspaceDirectoryError` in spirit, but is this module's own class — `src/config/` stays decoupled from `src/vm/` (see that file's own module comment). */
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
export class ForbiddenMountError extends Error {
  constructor(hostPath: string, corbDir: string, corbDirKind: "config" | "state" | "audit") {
    // `audit.path` names a file, not a directory — "overlaps Corb's own
    // audit directory" would read oddly, so this case gets its own noun
    // instead of reusing the `${corbDirKind} directory` template.
    const noun = corbDirKind === "audit" ? "audit log file" : `${corbDirKind} directory`;
    super(
      `corb config: mount host path '${hostPath}' overlaps Corb's own ${noun} '${corbDir}' — refusing to mount it (see docs/adr/0006-workspace-config-outside-every-mount.md)`,
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

// Resolves `rawPath` through symlinks as far as an existing ancestor allows,
// so a symlinked ancestor is canonicalized even when the leaf path itself
// doesn't exist yet — e.g. a `create: true` dir that hasn't been `mkdir`'d,
// or Corb's own config/state dir on a first run. Falls back to a lexical
// `path.resolve` only if no ancestor at all exists, which in practice means
// the filesystem root itself is unreachable.
function realpathOrResolve(rawPath: string): string {
  const resolved = path.resolve(rawPath);
  try {
    return fs.realpathSync(resolved);
  } catch {
    // fall through to the ancestor walk below
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
      // keep walking up
    }
  }
}

/** True when `target` is `base` itself, or lives anywhere under it. */
function isSameOrDescendant(base: string, target: string): boolean {
  if (base === target) {
    return true;
  }
  const rel = path.relative(base, target);
  return rel !== "" && !rel.startsWith("..") && !path.isAbsolute(rel);
}

/**
 * Refuses any `dir.host` that is, or overlaps, `configDir`, `corbStateDir()`,
 * or (when given) `auditPath` — see `ForbiddenMountError`. Checked against
 * `fullConfig.dir`, so it covers both `config.toml` `[[dir]]` entries and
 * `--dir` CLI flags (`fullConfig` is `persistentConfig` merged with
 * `cliLayer`, and `mergeDirEntry`/`mergeDirList` fold CLI overrides into the
 * same name-keyed list rather than appending separately), and it covers
 * `corb explain`/`--dry-run`, not just a real `corb run` — this function
 * runs inside `resolveWorkspace`, before any VM boots and before
 * `src/vm/session.ts`'s `create: true` `mkdir` for a dir that doesn't exist
 * yet.
 *
 * `auditPath` should be `fullConfig.audit?.path` — pass `undefined` (the
 * default case) when the caller has no explicit `[audit] path` set. The
 * default (`defaultAuditPath()`, unset here) already lives inside
 * `corbStateDir()`, itself always forbidden, so it needs no separate check;
 * only an *explicit* override needs one, since that's the only way an audit
 * path could land inside a workspace's own mounted tree instead.
 *
 * Both overlap directions are checked: a mount that *contains* a corb
 * directory (e.g. `corb run ~`, which contains `~/.config/corb`) hands the
 * guest read-write access to `config.toml`/`trusted.json`/`audit.jsonl`; a
 * mount that is *inside* a corb directory (e.g. `--dir
 * x=~/.config/corb/workspaces:rw`) hands over a slice of the same thing
 * directly. Both paths are resolved through `realpathOrResolve` first, so a
 * symlink pointing at either directory is caught, not just a lexical match.
 */
function assertNoMountOverlapsCorbDirs(dirs: readonly DirConfig[], configDir: string, auditPath?: string): void {
  const forbidden: Array<{ resolved: string; label: string; kind: "config" | "state" | "audit" }> = [
    { resolved: realpathOrResolve(configDir), label: configDir, kind: "config" },
    { resolved: realpathOrResolve(corbStateDir()), label: corbStateDir(), kind: "state" },
  ];
  if (auditPath !== undefined) {
    forbidden.push({ resolved: realpathOrResolve(auditPath), label: auditPath, kind: "audit" });
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
  /** Overrides `corbConfigDir()` — threads through to `paths.ts` so tests never need to touch the real `~/.config/corb`. */
  configDir?: string;
}

/** Everything a renderer (`src/config/render.ts`) or `corb run` needs to describe and act on one directory's config and trust status. */
export interface ResolvedWorkspace {
  /** The resolved, absolute host directory this workspace describes. */
  dir: string;
  /** Built-in defaults + `config.toml` + the synthesized single-dir layer for `dir` itself. The only config `trustEvaluation`/`acceptWorkspace` ever consider — see module comment. */
  persistentConfig: EffectiveConfig;
  /** `persistentConfig` with the caller's CLI layer (e.g. `--dir`-derived entries) merged on top. What a real run actually uses, and what a renderer should describe as "what will happen". Equals `persistentConfig` exactly when the CLI layer is `{}`. */
  fullConfig: EffectiveConfig;
  /** Evaluated against `persistentConfig` only — never influenced by CLI-added directories. */
  trustEvaluation: TrustEvaluation;
  /** The trust store key this resolution was evaluated against — the resolved absolute directory path itself (see module comment). */
  trustKey: string;
  /** The trust record `trustEvaluation` was compared against, if one existed for `trustKey`; `undefined` for "never run before". */
  priorRecord: TrustedWorkspaceRecord | undefined;
}

/**
 * Resolves `dir` into a `ResolvedWorkspace`: validates the directory exists
 * and is a directory, reads and merges `config.toml` (optional) with a
 * synthesized single-dir layer for `dir` itself into `persistentConfig`,
 * reads the trust store (optional) and evaluates trust for `dir`'s own
 * path-keyed record against `persistentConfig`, then merges `cliLayer` on
 * top of `persistentConfig` into `fullConfig`. Does no writing — see
 * `acceptWorkspace` for recording an acceptance.
 *
 * `BUILTIN_DEFAULTS` is not passed explicitly here; `mergeConfigLayers`
 * folds it in automatically (see `load.ts`'s own doc comment on
 * `mergeConfigLayers`). Re-merging `persistentConfig` itself as a layer
 * (`EffectiveConfig` is structurally assignable to `ConfigLayer`: every
 * field on the former is a required/non-optional refinement of the
 * same-named optional field on the latter) means `BUILTIN_DEFAULTS` gets
 * folded in a second time when building `fullConfig` — harmless, since
 * `persistentConfig` already reflects every value `BUILTIN_DEFAULTS` would
 * set, so it just gets overwritten right back (verified in
 * `resolve.test.ts`).
 */
export function resolveWorkspace(dir: string, cliLayer: ConfigLayer, opts: ResolveWorkspaceOptions = {}): ResolvedWorkspace {
  const resolvedDir = resolveWorkspaceDirectory(dir);
  const configDir = opts.configDir ?? corbConfigDir();

  const configTomlLayer = readConfigTomlLayer(configDir);
  const dirLayer: ConfigLayer = {
    dir: [{ name: path.basename(resolvedDir), host: resolvedDir, mode: "rw" }],
  };
  const persistentConfig = mergeConfigLayers([configTomlLayer, dirLayer]);

  const trustStore = readTrustStore(configDir);
  const trustKey = resolvedDir;
  const priorRecord = trustStore[trustKey];
  const trustEvaluation = evaluateTrust(priorRecord?.acceptedConfig, persistentConfig);

  const fullConfig = mergeConfigLayers([persistentConfig, cliLayer]);
  assertNoMountOverlapsCorbDirs(fullConfig.dir, configDir, fullConfig.audit?.path);

  return { dir: resolvedDir, persistentConfig, fullConfig, trustEvaluation, trustKey, priorRecord };
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
