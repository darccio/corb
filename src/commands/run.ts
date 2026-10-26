import { preflightComposition } from "../layer/generation.ts";
import { selectLayerWorkspace, type LayerContext } from "../layer/context.ts";
import { hashLayerDefinition } from "../layer/definition.ts";
import { same, fail } from "../layer/validate.ts";
// Parse run flags and resolve the same config shown by explain and dry-run.
// A named workspace without DIR does not mount cwd. Other omitted DIR values use cwd.
// Persistent settings pass the trust gate before any session starts. CLI flags stay personal.
// Session creation, mounts, secrets, and teardown live in src/vm/session.ts.
import path from "node:path";
import { parseArgs } from "node:util";
import { runSession, toGlobRules, type WorkspaceDirSpec } from "../vm/session.ts";
import { readDelegatedControllersForCurrentUser } from "../vm/cgroup.ts";
import { decideScope, reExecUnderScope } from "../vm/scope.ts";
import { classifySessionSocketPath, describeSessionSocketOverflow, gondolinSessionsDir } from "../vm/sockpath.ts";
import { acceptWorkspace, resolveWorkspace, type ResolvedWorkspace } from "../config/resolve.ts";
import { renderText, renderTrust } from "../config/render.ts";
import { credentialsStateDir, defaultAuditPath, expandHomePrefix } from "../config/paths.ts";
import { createAuditWriter } from "../policy/audit.ts";
import { startBrokeredSession, type BrokeredSession } from "../auth/broker.ts";
import { findBrokeredProvider } from "../auth/provider.ts";
import type { ConfigLayer, DirMode, PartialAgentConfig, PartialDirConfig } from "../config/schema.ts";
import type { DirConfig, EffectiveConfig } from "../config/load.ts";

export interface RunCommandArgs {
  dir: string;
  dirExplicit: boolean;
  workspace: string | undefined;
  piArgs: string[];
  dryRun: boolean;
  /** Raw directory flag values in argv order. See `buildCliLayer`. */
  dirFlags: string[];
  primary: string | undefined;
  trustConfig: boolean;
  /** Validated guest loopback port, or undefined when ingress is disabled. */
  expose: number | undefined;
}

/** Forward arguments after the first literal `--` to Pi without parsing them. */
function splitPiArgs(argv: string[]): { corbArgs: string[]; piArgs: string[] } {
  const idx = argv.indexOf("--");
  if (idx === -1) {
    return { corbArgs: argv, piArgs: [] };
  }
  return { corbArgs: argv.slice(0, idx), piArgs: argv.slice(idx + 1) };
}

/** An invalid guest loopback port supplied through `--expose`. */
export class InvalidExposePortError extends Error {
  constructor(raw: string, reason: string) {
    super(`corb run: invalid --expose value '${raw}': ${reason}`);
    this.name = "InvalidExposePortError";
  }
}

/** Require an integer guest loopback port from 1 through 65535. Reject numeric prefixes and alternate representations. */
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
      workspace: { type: "string" },
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
    dirExplicit: positionals[0] !== undefined,
    workspace: values.workspace,
    piArgs,
    dryRun: values["dry-run"] ?? false,
    dirFlags: values.dir ?? [],
    primary: values.primary,
    trustConfig: values["trust-config"] ?? false,
    expose: values.expose !== undefined ? parseExposePort(values.expose) : undefined,
  };
}

/** A directory flag that does not match `NAME=HOST[:ro|:rw]`. */
export class DirFlagError extends Error {
  constructor(raw: string, reason: string) {
    super(`corb: invalid --dir value '${raw}': ${reason}`);
    this.name = "DirFlagError";
  }
}

/** Split at the first equals sign. Treat a final slash-free colon token as a mode and require ro or rw. */
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

  if ((hostRaw.startsWith("~") && hostRaw !== "~" && !hostRaw.startsWith("~/")) ||
      (hostRaw.startsWith("$") && hostRaw !== "$HOME" && !hostRaw.startsWith("$HOME/"))) {
    throw new DirFlagError(raw, "HOST may only use ~ or $HOME as a complete leading path component");
  }
  return { name, host: path.resolve(expandHomePrefix(hostRaw)), mode };
}

/** Preserve directory flags in argv order. The existing named merge applies later entries last. */
export function buildCliLayer(dirFlags: readonly string[]): ConfigLayer {
  if (dirFlags.length === 0) {
    return {};
  }
  return { dir: dirFlags.map(parseDirFlag) };
}

/** The requested primary name does not match any configured directory. */
export class PrimaryDirectoryError extends Error {
  constructor(primary: string) {
    super(`corb run: --primary '${primary}' does not match any configured directory name`);
    this.name = "PrimaryDirectoryError";
  }
}

/** Use the explicit primary name or its selected default, and reject missing directory names before session creation. */
export function resolvePrimaryName(fullConfig: EffectiveConfig, primaryFlag: string | undefined, defaultName: string): string {
  const primary = primaryFlag ?? defaultName;
  if (!fullConfig.dir.some((entry) => entry.name === primary)) {
    throw new PrimaryDirectoryError(primary);
  }
  return primary;
}

/** A real run requires explicit acceptance for changed persistent settings. Dry-run only displays the verdict. */
export class TrustConfirmationRequiredError extends Error {
  constructor(resolved: ResolvedWorkspace, flags: { primary?: string; dirFlags?: readonly string[] } = {}) {
    const selected = resolved.selectedWorkspace;
    const quote = (value: string) => /^[A-Za-z0-9_./:=+-]+$/.test(value) ? value : `'${value.replaceAll("'", "'\"'\"'")}'`;
    const hint = ["corb explain", ...(selected === undefined ? [] : ["--workspace", quote(selected.name)]),
      ...(resolved.dir === undefined ? [] : [quote(resolved.dir)]),
      ...(flags.dirFlags ?? []).flatMap((raw) => ["--dir", quote(raw)]),
      ...(flags.primary === undefined ? [] : ["--primary", quote(flags.primary)]), "--trusted"].join(" ");
    const subject = selected === undefined ? `directory '${resolved.dir}'` : `workspace '${selected.name}'`;
    const lines = [
      `corb run: ${subject} requires confirmation before running. No VM will be started.`,
      "",
      ...renderTrust(resolved.trustEvaluation, resolved.trustKey, resolved),
      "",
      `Review the full effective config with '${hint}', or re-run with --trust-config to accept the change above and proceed.`,
    ];
    super(lines.join("\n"));
    this.name = "TrustConfirmationRequiredError";
  }
}

/** A hand-written directory entry lacks its required host path. */
export class DirHostMissingError extends Error {
  constructor(name: string) {
    super(`corb run: dir '${name}' has no 'host' path configured (set 'host' in config.toml's [[dir]] entry, or add a --dir ${name}=HOST flag)`);
    this.name = "DirHostMissingError";
  }
}

/** Prefix configured provider and model arguments in Pi order. Preserve the forwarded arguments. */
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
  // Validate rules before session creation. Direct runSession callers repeat this check.
  toGlobRules(entry.name, entry.rules);
  const spec: WorkspaceDirSpec = {
    name: entry.name,
    hostPath: entry.host,
    mode: entry.mode ?? "rw",
    rules: [...entry["builtin-rules"], ...entry.rules],
  };
  if (entry.create !== undefined) {
    spec.create = entry.create;
  }
  return spec;
}

export function assertTrustedLayerContext(resolved: ResolvedWorkspace, context: LayerContext): void {
  const selected = resolved.selectedWorkspace;
  const original = resolved.workspaces.workspaces.find((entry) => entry.name === selected?.name);
  const image = resolved.fullConfig.image;
  if (selected === undefined || original === undefined || image === undefined || context.selected.name !== selected.name
    || context.selected.entry.corbToml !== selected.corbToml || context.selected.entry.realPath !== original.realPath
    || context.selected.entry.source !== original.source || hashLayerDefinition(context.definition) !== hashLayerDefinition(image.layer)
    || !same(context.pins, image.pins) || context.config.vm?.image !== resolved.fullConfig.vm?.image) {
    fail("workspace layer changed after trust evaluation. Retry corb run to review the current source, pins and base");
  }
}

export async function runRunCommand(argv: string[]): Promise<void> {
  const { dir, dirExplicit, workspace, piArgs, dryRun, dirFlags, primary: primaryFlag, trustConfig, expose } = parseRunArgs(argv);

  const cliLayer = buildCliLayer(dirFlags);
  const resolved = resolveWorkspace(dirExplicit || workspace === undefined ? dir : undefined, cliLayer, {
    ...(workspace === undefined ? {} : { workspace }),
    ...(primaryFlag === undefined ? {} : { primary: primaryFlag }),
  });
  const primary = resolvePrimaryName(resolved.fullConfig, primaryFlag, resolved.primary);
  resolved.primary = primary;

  // Dry-run shares the explain pipeline and displays trust without creating a session.
  if (dryRun) {
    console.log(renderText(resolved));
    return;
  }

  // Evaluate persistent settings only. acceptWorkspace never records CLI directory additions.
  if (resolved.trustEvaluation.verdict === "requires-confirmation" && !trustConfig) {
    throw new TrustConfirmationRequiredError(resolved, { dirFlags, ...(primaryFlag === undefined ? {} : { primary: primaryFlag }) });
  }
  const layerContext = resolved.fullConfig.image === undefined ? undefined : selectLayerWorkspace(workspace, undefined, dir);
  if (layerContext !== undefined) assertTrustedLayerContext(resolved, layerContext);
  const composition = layerContext === undefined ? undefined : await preflightComposition(
    layerContext, resolved.fullConfig.dir.flatMap((entry) => entry.host === undefined ? [] : [entry.host]),
  );
  if (trustConfig) {
    acceptWorkspace(resolved.trustKey, resolved.persistentConfig, Date.now());
  }

  // Apply host cgroup limits before boot, after dry-run and trust checks.
  // A scoped child skips this step because its process tree already has the limits.
  if (resolved.fullConfig.vm?.limits !== undefined && process.env.CORB_SCOPED === undefined) {
    const decision = decideScope(resolved.fullConfig.vm.limits, readDelegatedControllersForCurrentUser());
    if (decision.reExec) {
      const outcome = reExecUnderScope({ properties: decision.properties });
      // Successful re-exec exits with the child status. On spawn failure, warn and continue without limits.
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

  // Warn about a long SDK registry socket after scope re-exec, so only the VM owner warns.
  // A long socket degrades management commands but does not prevent the session from running.
  {
    const fit = classifySessionSocketPath(gondolinSessionsDir());
    if (!fit.fits) {
      console.error(`corb: ${describeSessionSocketOverflow(fit)}`);
    }
  }

  const dirs = resolved.fullConfig.dir.map(toWorkspaceDirSpec);
  const fullPiArgs = withProviderModelArgs(resolved.fullConfig.agent, piArgs);
  // Use the same audit path for the writer and session.
  const auditPath = resolved.fullConfig.audit?.path ?? defaultAuditPath();
  const audit = createAuditWriter({ path: auditPath });

  // Start a configured broker before boot and register real tokens for audit redaction.
  // The guest receives only the stand-in credential.
  let brokered: BrokeredSession | undefined;
  const brokeredProvider = findBrokeredProvider(resolved.fullConfig.agent?.provider);
  if (brokeredProvider !== undefined) {
    try {
      brokered = await startBrokeredSession(brokeredProvider, {
        dir: credentialsStateDir(),
        onSecrets: (values) => audit.addRedactedSecrets(values),
      });
    } catch (err) {
      // Every failure here (not logged in, an unusable credential file, a
      // refresh the provider refused, a stuck lock) is a sentence for the
      // user, not a stack trace.
      console.error(err instanceof Error ? err.message : String(err));
      process.exitCode = 1;
      return;
    }
  }

  await runSession({
    ...(composition === undefined ? {} : { composition }),
    dirs,
    primary,
    piArgs: fullPiArgs,
    ...(resolved.fullConfig.name !== undefined ? { name: resolved.fullConfig.name } : {}),
    ...(resolved.fullConfig.vm?.["max-session"] !== undefined ? { maxSession: resolved.fullConfig.vm["max-session"] } : {}),
    // Forward the VM settings already resolved, rendered and covered by personal trust.
    ...(resolved.fullConfig.vm?.image !== undefined ? { image: resolved.fullConfig.vm.image } : {}),
    ...(resolved.fullConfig.vm?.memory !== undefined ? { memory: resolved.fullConfig.vm.memory } : {}),
    ...(resolved.fullConfig.vm?.cpus !== undefined ? { cpus: resolved.fullConfig.vm.cpus } : {}),
    egress: resolved.fullConfig.egress,
    ...(resolved.fullConfig.secrets !== undefined ? { secrets: resolved.fullConfig.secrets } : {}),
    git: resolved.fullConfig.git,
    policy: resolved.fullConfig.policy,
    dirConfigs: resolved.fullConfig.dir,
    audit,
    auditPath,
    ...(expose !== undefined ? { expose } : {}),
    ...(brokered !== undefined ? { brokered } : {}),
  });
}
