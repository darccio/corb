// `corb run` — M1.6: argv parsing and wiring only. The actual session
// assembly (image resolution, VFS mounts, secret binding, exec, teardown)
// lives in `src/vm/session.ts`; this file's only job is turning `argv` into
// a `RunSessionOptions`.
//
// CLI shape: `corb run [WORKSPACE] [--dir NAME=HOST[:ro|:rw]]... [--primary
// NAME] [--trust-config] [--dry-run] [-- PI_ARGS...]`, matching the surface
// already recorded in the plan (`plans/.../` §2) rather than inventing a
// new one — a positional workspace directory, defaulting to `process.cwd()`
// when omitted, with anything after a literal `--` forwarded to `pi`
// untouched.
//
// M2.4 generalized `runSession` from a single `dir: string` to an explicit
// `dirs`/`primary` shape (N named directories, each `ro`/`rw`). The
// positional workspace directory always becomes one entry in that array
// (named `path.basename(resolvedDir)`, mounted `rw`) — this happens whether
// or not `--dir` flags are also given (M2.6, see module comment on
// `resolveWorkspace`/`buildCliLayer`). `--dir` flags are purely additive/
// overriding on top of it via `load.ts`'s existing name-keyed merge, so a
// `--dir` flag sharing the positional's derived name replaces it wholesale
// (e.g. `corb run myrepo --dir myrepo=~/other:ro`). One documented
// consequence: `corb run --dir work=~/elsewhere:rw` from an unrelated
// directory still implicitly also mounts that unrelated cwd under its own
// basename-derived name, since the positional defaults to `process.cwd()`
// when omitted. This keeps the mental model simple ("there is always at
// least the directory identified by your positional argument or cwd; --dir
// flags add or override on top of that") rather than special-casing
// "did the user pass any --dir flags".
//
// M2.5 added `--dry-run`: it shares the exact `resolve.ts`/`render.ts`
// pipeline `corb explain` (`src/commands/explain.ts`) uses, against the same
// directory `runSession` would otherwise use, and returns without ever
// calling `runSession` — no VM is created, and (this matters)
// `ANTHROPIC_API_KEY` is not required, since no secret binding or VM boot
// happens on this path.
//
// M2.6 wires the config system in for real: `--dir`/`--primary` let a
// caller configure more than the one positional directory, and a trust gate
// (no interactive prompt — `--trust-config` is required to proceed past a
// `requires-confirmation` verdict) runs before a real (non-dry-run) session
// is ever created. The trust gate is evaluated against the *persistent*
// config only (`config.toml` + the positional directory) — CLI-added `--dir`
// entries never influence it and are never written to `trusted.json`; see
// `src/config/resolve.ts`'s module comment for why that separation matters
// (CLI flags are always trusted, since a human just typed them). `--dry-run`
// still shows the trust verdict (via `renderText`) but never hits the hard
// gate below — only an actual run does.
import path from "node:path";
import { parseArgs } from "node:util";
import { runSession, type WorkspaceDirSpec } from "../vm/session.ts";
import { acceptWorkspace, resolveWorkspace, type ResolvedWorkspace } from "../config/resolve.ts";
import { renderText, renderTrust } from "../config/render.ts";
import type { ConfigLayer, DirMode, PartialDirConfig } from "../config/schema.ts";
import type { DirConfig, EffectiveConfig } from "../config/load.ts";

export interface RunCommandArgs {
  dir: string;
  piArgs: string[];
  dryRun: boolean;
  /** Raw `--dir NAME=HOST[:ro|:rw]` values, in argv order, not yet parsed — see `buildCliLayer`. */
  dirFlags: string[];
  primary: string | undefined;
  trustConfig: boolean;
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
  const { values, positionals } = parseArgs({
    args: corbArgs,
    options: {
      "dry-run": { type: "boolean" },
      dir: { type: "string", multiple: true },
      primary: { type: "string" },
      "trust-config": { type: "boolean" },
    },
    allowPositionals: true,
    strict: true,
  });

  if (positionals.length > 1) {
    throw new Error(
      `corb run: unexpected extra argument '${positionals[1]}' (only one workspace directory is supported)`,
    );
  }

  const dir = positionals[0] !== undefined ? path.resolve(positionals[0]) : process.cwd();
  return {
    dir,
    piArgs,
    dryRun: values["dry-run"] ?? false,
    dirFlags: values.dir ?? [],
    primary: values.primary,
    trustConfig: values["trust-config"] ?? false,
  };
}

/** Thrown by `parseDirFlag` for a `--dir` value that doesn't match `NAME=HOST[:ro|:rw]`. */
export class DirFlagError extends Error {
  constructor(raw: string, reason: string) {
    super(`corb: invalid --dir value '${raw}': ${reason}`);
    this.name = "DirFlagError";
  }
}

/**
 * Parses one `--dir NAME=HOST[:ro|:rw]` value. `NAME` is split off at the
 * *first* `=` (a host path could theoretically contain `=`, however
 * unlikely — the first `=` is the only unambiguous choice). A mode suffix is
 * split off the *last* `:` only when the trailing token has no `/` in it: a
 * trailing token containing `/` is always part of the host path (so a host
 * path with a colon embedded deeper in it isn't misparsed — this project is
 * Linux/macOS-only, so there's no Windows drive letter to worry about
 * either way), while a slash-free trailing token is treated as an
 * intentional mode marker and rejected outright if it isn't exactly `ro` or
 * `rw`, rather than silently folded into the host path.
 */
export function parseDirFlag(raw: string): PartialDirConfig {
  const eqIdx = raw.indexOf("=");
  if (eqIdx === -1) {
    throw new DirFlagError(raw, "expected 'NAME=HOST[:ro|:rw]' (missing '=')");
  }
  const name = raw.slice(0, eqIdx);
  const rest = raw.slice(eqIdx + 1);
  if (name === "") {
    throw new DirFlagError(raw, "NAME must not be empty");
  }
  if (rest === "") {
    throw new DirFlagError(raw, "HOST must not be empty");
  }

  let hostRaw = rest;
  let mode: DirMode = "rw";
  const lastColon = rest.lastIndexOf(":");
  if (lastColon !== -1) {
    const suffix = rest.slice(lastColon + 1);
    if (!suffix.includes("/")) {
      if (suffix === "ro") {
        mode = "ro";
        hostRaw = rest.slice(0, lastColon);
      } else if (suffix === "rw") {
        mode = "rw";
        hostRaw = rest.slice(0, lastColon);
      } else {
        throw new DirFlagError(raw, `mode suffix ':${suffix}' must be exactly ':ro' or ':rw'`);
      }
    }
  }

  if (hostRaw === "") {
    throw new DirFlagError(raw, "HOST must not be empty");
  }

  return { name, host: path.resolve(hostRaw), mode };
}

/**
 * Builds the CLI-derived `ConfigLayer` from every `--dir` value, in argv
 * order. Multiple `--dir` flags naming the same `NAME` need no special
 * "last one wins" handling here — they're just built into one `dir` array in
 * argv order, and `mergeConfigLayers`' existing name-keyed merge rule
 * (`load.ts`) already resolves same-named entries with later-wins semantics
 * when this layer is merged in.
 */
export function buildCliLayer(dirFlags: readonly string[]): ConfigLayer {
  if (dirFlags.length === 0) {
    return {};
  }
  return { dir: dirFlags.map(parseDirFlag) };
}

/** Thrown when `--primary` doesn't name any entry in `fullConfig.dir`. */
export class PrimaryDirectoryError extends Error {
  constructor(primary: string) {
    super(`corb run: --primary '${primary}' does not match any configured directory name`);
    this.name = "PrimaryDirectoryError";
  }
}

/**
 * Resolves which `fullConfig.dir[].name` is primary: the explicit
 * `--primary` flag if given, else `defaultName` (the positional directory's
 * derived name — today's implicit behavior when no flag is given). Errors
 * clearly, before anything else is attempted, if the resolved name doesn't
 * match any configured directory — the same check `src/vm/session.ts`'s
 * `findPrimaryEntry` makes at the `runSession` layer, just earlier and with
 * a message that knows it came from `--primary`.
 */
export function resolvePrimaryName(fullConfig: EffectiveConfig, primaryFlag: string | undefined, defaultName: string): string {
  const primary = primaryFlag ?? defaultName;
  if (!fullConfig.dir.some((entry) => entry.name === primary)) {
    throw new PrimaryDirectoryError(primary);
  }
  return primary;
}

/**
 * Thrown by a real (non-dry-run) `corb run` when the persistent config's
 * trust verdict is `requires-confirmation` and `--trust-config` was not
 * passed. Never thrown for `--dry-run` — showing the requires-confirmation
 * state is the whole point of `--dry-run`; only a real run enforces it as a
 * hard failure. Reuses `render.ts`'s itemized change rendering rather than
 * inventing a second diff format.
 */
export class TrustConfirmationRequiredError extends Error {
  constructor(resolved: ResolvedWorkspace) {
    const lines = [
      `corb run: workspace '${resolved.dir}' requires confirmation before running — no VM will be started.`,
      "",
      ...renderTrust(resolved.trustEvaluation, resolved.trustKey),
      "",
      `Review the full effective config with 'corb explain ${resolved.dir}', or re-run with --trust-config to accept the change above and proceed.`,
    ];
    super(lines.join("\n"));
    this.name = "TrustConfirmationRequiredError";
  }
}

/**
 * Thrown when a `fullConfig.dir` entry has no `host`. Unreachable via the
 * positional directory or `--dir` (both always set `host`) — only possible
 * from a hand-written `config.toml` `[[dir]]` entry that omits it.
 */
export class DirHostMissingError extends Error {
  constructor(name: string) {
    super(`corb run: dir '${name}' has no 'host' path configured (set 'host' in config.toml's [[dir]] entry, or add a --dir ${name}=HOST flag)`);
    this.name = "DirHostMissingError";
  }
}

function toWorkspaceDirSpec(entry: DirConfig): WorkspaceDirSpec {
  if (entry.host === undefined) {
    throw new DirHostMissingError(entry.name);
  }
  const spec: WorkspaceDirSpec = { name: entry.name, hostPath: entry.host, mode: entry.mode ?? "rw" };
  if (entry.create !== undefined) {
    spec.create = entry.create;
  }
  return spec;
}

export async function runRunCommand(argv: string[]): Promise<void> {
  const { dir, piArgs, dryRun, dirFlags, primary: primaryFlag, trustConfig } = parseRunArgs(argv);

  const cliLayer = buildCliLayer(dirFlags);
  const resolved = resolveWorkspace(dir, cliLayer);
  const primary = resolvePrimaryName(resolved.fullConfig, primaryFlag, path.basename(resolved.dir));

  // `--dry-run`: describe what a real run would do and stop — never call
  // `runSession`, so no VM is created and no secret is required. Shares the
  // exact pipeline `corb explain` uses (see module comment). Bypasses the
  // trust gate below entirely — showing a requires-confirmation verdict is
  // the point of `--dry-run`, not a reason for it to fail.
  if (dryRun) {
    console.log(renderText(resolved));
    return;
  }

  // Trust gate (see module comment): evaluated against the *persistent*
  // config only, so CLI-added `--dir` directories never affect the verdict
  // and are never recorded by `acceptWorkspace`.
  if (resolved.trustEvaluation.verdict === "requires-confirmation" && !trustConfig) {
    throw new TrustConfirmationRequiredError(resolved);
  }
  if (trustConfig) {
    acceptWorkspace(resolved.trustKey, resolved.persistentConfig, Date.now());
  }

  const dirs = resolved.fullConfig.dir.map(toWorkspaceDirSpec);
  await runSession({ dirs, primary, piArgs });
}
