// `corb run` — M1.6: argv parsing and wiring only. The actual session
// assembly (image resolution, VFS mounts, secret binding, exec, teardown)
// lives in `src/vm/session.ts`; this file's only job is turning `argv` into
// a `RunSessionOptions`.
//
// CLI shape: `corb run [WORKSPACE] [--dir NAME=HOST[:ro|:rw]]... [--primary
// NAME] [--trust-config] [--dry-run] [--expose PORT] [-- PI_ARGS...]`,
// matching the surface already recorded in the plan (`plans/.../` §2) rather
// than inventing a new one — a positional workspace directory, defaulting to
// `process.cwd()` when omitted, with anything after a literal `--` forwarded
// to `pi` untouched.
//
// M9.4 adds `--expose PORT`: wires Gondolin's host-to-guest ingress reverse
// proxy (`vm.enableIngress()`/`vm.setIngressRoutes()`, `docs/gondolin-notes.md`
// §9) onto a single guest loopback port. `PORT` is parsed and validated (an
// integer in `[1, 65535]`) here, before anything boots — the same "error
// clearly and immediately" discipline `DirFlagError`/`PrimaryDirectoryError`
// already follow for their own flags — then threaded straight through to
// `runSession()`'s own `expose?: number` option, which does the actual
// wiring. Deliberately one port, not repeatable: no path-prefix multiplexing
// across several exposed guest ports, and no `[expose]` config section —
// see `docs/design.md`'s ingress subsection for why.
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
import { runSession, toGlobRules, type WorkspaceDirSpec } from "../vm/session.ts";
import { readDelegatedControllersForCurrentUser } from "../vm/cgroup.ts";
import { decideScope, reExecUnderScope } from "../vm/scope.ts";
import { classifySessionSocketPath, describeSessionSocketOverflow, gondolinSessionsDir } from "../vm/sockpath.ts";
import { acceptWorkspace, resolveWorkspace, type ResolvedWorkspace } from "../config/resolve.ts";
import { renderText, renderTrust } from "../config/render.ts";
import { defaultAuditPath } from "../config/paths.ts";
import { createAuditWriter } from "../policy/audit.ts";
import type { ConfigLayer, DirMode, PartialAgentConfig, PartialDirConfig } from "../config/schema.ts";
import type { DirConfig, EffectiveConfig } from "../config/load.ts";

export interface RunCommandArgs {
  dir: string;
  piArgs: string[];
  dryRun: boolean;
  /** Raw `--dir NAME=HOST[:ro|:rw]` values, in argv order, not yet parsed — see `buildCliLayer`. */
  dirFlags: string[];
  primary: string | undefined;
  trustConfig: boolean;
  /**
   * The guest loopback port to expose via ingress, already validated (an
   * integer in `[1, 65535]`) by `parseExposePort` — see the module comment.
   * `undefined` when `--expose` was not passed, which leaves ingress
   * disabled entirely.
   */
  expose: number | undefined;
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

/** Thrown by `parseExposePort` for an `--expose` value that isn't a valid guest loopback port. */
export class InvalidExposePortError extends Error {
  constructor(raw: string, reason: string) {
    super(`corb run: invalid --expose value '${raw}': ${reason}`);
    this.name = "InvalidExposePortError";
  }
}

/**
 * Parses and validates `--expose`'s raw string value into a guest loopback
 * port, before anything boots — matching `DirFlagError`'s own "fail clearly,
 * before any VM is created" discipline. A bare digit-string check rather than
 * `Number(raw)` alone: `Number("")`/`Number(" ")`/`Number("1e2")` all parse to
 * a finite number despite not being a plain port literal, so accepting
 * anything `Number` doesn't reject would let non-integer or malformed input
 * (whitespace, scientific notation, a leading `+`/`-`) through silently.
 */
export function parseExposePort(raw: string): number {
  if (!/^[0-9]+$/.test(raw)) {
    throw new InvalidExposePortError(raw, "must be a positive integer");
  }
  const port = Number(raw);
  if (port < 1 || port > 65535) {
    throw new InvalidExposePortError(raw, "must be between 1 and 65535");
  }
  return port;
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
      expose: { type: "string" },
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
    expose: values.expose !== undefined ? parseExposePort(values.expose) : undefined,
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

/**
 * Prepends `--provider`/`--model` to `piArgs` when `agent.provider`/
 * `agent.model` are configured, in that order (matching Pi's own examples —
 * `docs/design.md` §8), so `runRunCommand` passes a fully-assembled arg list
 * through to `runSession` rather than doing this translation inline. Neither
 * flag is required: an entirely unset `agent` (or an `agent` present but with
 * neither field set) leaves `piArgs` unchanged. This is the one piece
 * `docs/design.md` §8 calls out as genuinely new for this item — Pi itself
 * already understands both flags; nothing before this translated Corb's
 * `[agent]` config into them.
 */
export function withProviderModelArgs(agent: PartialAgentConfig | undefined, piArgs: string[]): string[] {
  const prefix: string[] = [];
  if (agent?.provider !== undefined) {
    prefix.push("--provider", agent.provider);
  }
  if (agent?.model !== undefined) {
    prefix.push("--model", agent.model);
  }
  return [...prefix, ...piArgs];
}

function toWorkspaceDirSpec(entry: DirConfig): WorkspaceDirSpec {
  if (entry.host === undefined) {
    throw new DirHostMissingError(entry.name);
  }
  // Validated here, eagerly, purely for `toGlobRules`'s side effect (the
  // fully-resolved `GlobRule[]` result is discarded) — a `rules[]` entry
  // missing `glob` or `mode` throws `InvalidDirRuleError` from this call,
  // before `runSession` is ever invoked, the same "error clearly and
  // immediately" discipline `DirHostMissingError` above already follows.
  // `resolveWorkspaceDirs` (`src/vm/session.ts`) performs the authoritative,
  // non-discarded conversion again on every `runSession` call, for any
  // caller that reaches that module directly without going through this
  // function first — this is a deliberate, harmless duplicate check, not a
  // substitute for it.
  toGlobRules(entry.name, entry.rules);
  // `entry.rules` is always an array (possibly empty), never `undefined` —
  // `src/config/load.ts`'s own `DirConfig.rules` comment — so this is a
  // plain pass-through, not a defaulting step; `WorkspaceDirSpec.rules`'s own
  // optionality exists for callers other than this one (e.g. direct
  // `runSession` callers in tests), not because this one ever omits it.
  const spec: WorkspaceDirSpec = { name: entry.name, hostPath: entry.host, mode: entry.mode ?? "rw", rules: entry.rules };
  if (entry.create !== undefined) {
    spec.create = entry.create;
  }
  return spec;
}

export async function runRunCommand(argv: string[]): Promise<void> {
  const { dir, piArgs, dryRun, dirFlags, primary: primaryFlag, trustConfig, expose } = parseRunArgs(argv);

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

  // Resource limits (M8.3, docs/design.md §7): re-exec under a systemd user
  // scope with `vm.limits` applied as `-p` cgroup properties *before*
  // `runSession()` ever boots the VM — see `src/vm/scope.ts`'s module
  // comment for why this beats attaching a cgroup to the VM's host pid
  // after the fact. Runs after `--dry-run` (a dry run boots no VM, so
  // there is nothing to limit) and after the trust gate above (failing
  // trust inside a re-exec'd child would just be a confusing extra process
  // hop before the real error surfaces), and before `runSession()` — that
  // ordering is the entire point, the limit has to exist before QEMU does.
  // `CORB_SCOPED` already set means this process *is* the re-exec'd child,
  // already running inside the scope for its whole process tree — nothing
  // left to do, fall straight through.
  if (resolved.fullConfig.vm?.limits !== undefined && process.env.CORB_SCOPED === undefined) {
    const decision = decideScope(resolved.fullConfig.vm.limits, readDelegatedControllersForCurrentUser());
    if (decision.reExec) {
      const outcome = reExecUnderScope({ properties: decision.properties });
      // A successful spawn already called `exit()` with the child's exact
      // code (the real `process.exit`, by default) — execution never
      // reaches past that in real usage. `outcome.spawnError` set means the
      // spawn itself failed outright (e.g. `systemd-run` isn't installed);
      // treat that exactly like "missing delegated controllers" below: warn
      // and continue unlimited, nothing else attempted.
      if (outcome.spawnError !== undefined) {
        console.error(
          `corb: could not start 'systemd-run' to apply vm.limits (${outcome.spawnError.message}); continuing without host resource limits.`,
        );
      }
    } else if (decision.missingControllers.length > 0) {
      console.error(
        `corb: vm.limits configured, but the user cgroup does not delegate: ${decision.missingControllers.join(", ")}. Continuing without those limits (unlimited).`,
      );
    }
  }

  // Gondolin session socket length (see `src/vm/sockpath.ts`'s module comment
  // for the trap itself). `corb doctor` has a check for this too, but doctor
  // is opt-in and a user who trips this will not have run it — so warn here,
  // unprompted, on the path that actually creates the socket.
  //
  // **Warn and continue, never hard-fail.** The session is completely
  // functional; only `corb ls`/`corb kill`/`corb gc`/`corb attach` degrade.
  // Refusing to boot a working session over a degraded management surface
  // would be the worse outcome, and this matches the precedent M8.3 set
  // directly above for missing cgroup controllers.
  //
  // **Why here and not in `src/vm/session.ts`.** `runSession()` is where the
  // other pre-boot validation lives, but all of that validation *throws* —
  // it has no "print a warning and carry on" channel, and it writes to an
  // injectable `options.stderr` rather than `console.error`. `runSession()`
  // is also called directly, with fabricated options, by the e2e suite, which
  // would then emit this warning on every such boot. Most decisively, the
  // thing being warned about is the degradation of *corb subcommands*
  // (`corb ls`, `corb kill`) — a CLI-surface concern that `session.ts`, which
  // deliberately knows nothing about `src/config/` or the command layer, has
  // no business describing.
  //
  // Placed *after* the scope re-exec block above, not before: a re-exec'd
  // child re-enters this same function from the top with `CORB_SCOPED` set,
  // so warning before that block would print once in the parent and again in
  // the child. After it, exactly the process that boots the VM warns, once.
  {
    const fit = classifySessionSocketPath(gondolinSessionsDir());
    if (!fit.fits) {
      console.error(`corb: ${describeSessionSocketOverflow(fit)}`);
    }
  }

  const dirs = resolved.fullConfig.dir.map(toWorkspaceDirSpec);
  const fullPiArgs = withProviderModelArgs(resolved.fullConfig.agent, piArgs);
  // Hoisted so both `createAuditWriter()` and `runSession()`'s own
  // `auditPath` option share the exact same string, rather than
  // `defaultAuditPath()` being computed a second time and risking drift if
  // its default ever changed between the two call sites.
  const auditPath = resolved.fullConfig.audit?.path ?? defaultAuditPath();
  const audit = createAuditWriter({ path: auditPath });
  await runSession({
    dirs,
    primary,
    piArgs: fullPiArgs,
    ...(resolved.fullConfig.name !== undefined ? { name: resolved.fullConfig.name } : {}),
    ...(resolved.fullConfig.vm?.["max-session"] !== undefined ? { maxSession: resolved.fullConfig.vm["max-session"] } : {}),
    egress: resolved.fullConfig.egress,
    ...(resolved.fullConfig.secrets !== undefined ? { secrets: resolved.fullConfig.secrets } : {}),
    git: resolved.fullConfig.git,
    policy: resolved.fullConfig.policy,
    dirConfigs: resolved.fullConfig.dir,
    audit,
    auditPath,
    ...(expose !== undefined ? { expose } : {}),
  });
}
