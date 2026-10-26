// `src/config/render.ts` — M2.5: pure functions (no I/O) that turn a
// `ResolvedWorkspace` (`src/config/resolve.ts`) into output for a human
// (`renderText`) or a machine (`renderJson`). This is the whole point of
// `corb explain` existing: "policy you can't read is policy you won't
// trust" — a human must be able to tell at a glance whether a workspace
// would require confirmation to run, and why.
//
// M2.6 update: `ResolvedWorkspace` now carries two configs. The directory/
// vm/agent/egress/etc. sections below describe `fullConfig` — the
// persistent config plus whatever `--dir` entries the caller passed, i.e.
// "what will actually run". The trust section describes `trustEvaluation`,
// which `resolve.ts` evaluates against `persistentConfig` only — it says so
// explicitly (`renderTrust`'s "scope" line) so a reader doesn't mistake the
// verdict for covering CLI-added directories, which it never does.
//
// Never prints a secret *value* — `EffectiveConfig.secrets` never holds one
// (`PartialSecretConfig` is `hosts`/`optional` host-binding metadata, plus
// an opt-in `verify` sub-table that is itself only a URL/header-name/status
// list — never the secret's own value), so there is nothing secret-valued
// for this module to accidentally leak.
import { hashLayerDefinition, nativeLayerArch, layerPayloadPath } from "../layer/definition.ts";
import { hashRecipePins, pinCommandHint } from "../layer/pins.ts";
import type { DirConfig, EffectiveConfig } from "./load.ts";
import { hashEffectiveConfig, type ConfigChange, type TrustEvaluation, type TrustedWorkspaceRecord } from "./trust.ts";
import type { ResolvedWorkspace } from "./resolve.ts";
import type { WorkspaceListing } from "./workspaces.ts";
import { findBrokeredProvider } from "../auth/provider.ts";
import { describeImpliedHostSource, type ImpliedHost } from "./implied.ts";

function fmtScalar(value: string | number | boolean | undefined): string {
  return value === undefined ? "(unset)" : String(value);
}

function fmtArray(arr: readonly string[] | undefined): string {
  if (arr === undefined) {
    return "(unset)";
  }
  return arr.length === 0 ? "[]" : `[${arr.join(", ")}]`;
}

function indentLines(lines: string[], depth: number): string[] {
  const prefix = "  ".repeat(depth);
  return lines.map((line) => `${prefix}${line}`);
}

function renderVm(vm: EffectiveConfig["vm"]): string[] {
  if (vm === undefined) {
    return ["vm: (unset)"];
  }
  const lines = [
    "vm:",
    `  image: ${fmtScalar(vm.image)}`,
    `  memory: ${fmtScalar(vm.memory)}`,
    `  cpus: ${fmtScalar(vm.cpus)}`,
    `  max-session: ${fmtScalar(vm["max-session"])}`,
  ];
  if (vm.limits === undefined) {
    lines.push("  limits: (unset)");
  } else {
    lines.push(
      "  limits:",
      `    memory-max: ${fmtScalar(vm.limits["memory-max"])}`,
      `    pids-max: ${fmtScalar(vm.limits["pids-max"])}`,
      `    cpu-quota: ${fmtScalar(vm.limits["cpu-quota"])}`,
    );
  }
  return lines;
}

function renderImage(image: EffectiveConfig["image"], workspaceName?: string): string[] {
  if (image === undefined) return [];
  const layer = image.layer;
  const lines = ["image:", "  layer:", `    packages: ${fmtArray(layer.packages)}`,
    `    build-hosts: ${fmtArray(layer["build-hosts"])}`, `    hosts: ${fmtArray(layer.hosts)}`,
    `    definition-sha256: ${hashLayerDefinition(layer)}`, "    payload:"];
  for (const item of layer.payload) {
    lines.push(`      - ${item.name}: url=${item.url} sha256=${item.sha256} arch=${item.arch}`,
      `        destination=${item.destination} strip-components=${item["strip-components"]} path=${fmtArray(item.path)}`);
  }
  lines.push(`    PATH prefix: ${fmtArray(layerPayloadPath(layer))}`, "    runtime-dir:");
  for (const item of layer["runtime-dir"]) lines.push(`      - ${item.path}: mode=${item.mode} owner=${item.owner} group=${item.group}`);
  lines.push("    commands (unpinned root install steps, /bin/sh -ec, cwd /):");
  for (const command of layer.commands) lines.push(`      - ${JSON.stringify(command)}`);
  if (image.pins === undefined) {
    lines.push("  pins: missing");
    if (workspaceName !== undefined) lines.push(`  pin command: ${pinCommandHint(workspaceName)}`);
  } else lines.push(`  recipe-pins-sha256: ${hashRecipePins(image.pins, image.pins.index[0]?.url.includes("/aarch64/") ? "aarch64" : layer.payload[0]?.arch ?? nativeLayerArch())}`,
    `  pins: ${JSON.stringify(image.pins)}`, `  artifact: ${image.pins.artifact ?? "(unbound)"}`);
  return lines;
}


// `extensions`/`append-system-prompt-file` (E2): `schema.ts`'s
// `parseAgentConfig` now rejects a non-empty `extensions` or any
// `append-system-prompt-file` at parse time, so every real `corb
// explain`/`corb run` path (which always goes through `resolveWorkspace` ->
// `parseConfigLayer` first) can only ever hand this function `undefined`/`[]`
// for them. The two lines below are kept anyway rather than deleted:
// `EffectiveConfig["agent"]`'s type still allows a non-trivial value (this
// module doesn't own that type, and narrowing it is out of scope for a
// parse-time check), render.ts is a pure function tested independently of
// the parser (see `render.test.ts`, which builds `EffectiveConfig` values by
// hand), and `renderJson` already serializes whatever `fullConfig` actually
// contains regardless. Silently dropping these fields from `renderText`
// would make it lie by omission relative to `renderJson` for the same
// object, for the sake of deleting two harmless lines.

function renderAgent(agent: EffectiveConfig["agent"]): string[] {
  if (agent === undefined) {
    return ["agent: (unset)"];
  }
  return [
    "agent:",
    `  provider: ${fmtScalar(agent.provider)}`,
    `  model: ${fmtScalar(agent.model)}`,
    `  extensions: ${fmtArray(agent.extensions)}`,
    `  append-system-prompt-file: ${fmtScalar(agent["append-system-prompt-file"])}`,
    ...renderBrokeredLogin(agent.provider),
  ];
}

// A host-brokered provider (ADR 0012) authenticates with `corb login`, not a
// `[secrets.*]` key. Says so, and which hosts it needs, without reading the
// stored login: this module stays a pure function of the config, and `corb
// login`/`corb doctor` report the login itself.
function renderBrokeredLogin(providerId: string | undefined): string[] {
  const provider = findBrokeredProvider(providerId);
  if (provider === undefined) {
    return [];
  }
  return [`  login: host-brokered, see 'corb login ${provider.id}' (allows ${provider.apiHosts.join(", ")} automatically)`];
}

// Names and host-binding metadata only — never a secret value (see module comment).
function renderSecrets(secrets: EffectiveConfig["secrets"]): string[] {
  const names = secrets === undefined ? [] : Object.keys(secrets);
  if (names.length === 0) {
    return ["secrets: (none)"];
  }
  const lines = ["secrets:"];
  for (const name of names) {
    const entry = secrets![name]!;
    lines.push(`  ${name}: hosts=${fmtArray(entry.hosts)} optional=${fmtScalar(entry.optional)}`);
    if (entry.verify === undefined) {
      lines.push("    verify: (unset)");
    } else {
      lines.push(
        `    verify: url=${entry.verify.url} header=${entry.verify.header} header-prefix=${fmtScalar(entry.verify["header-prefix"])} expect-status=${fmtArray(entry.verify["expect-status"]?.map(String))}`,
      );
    }
  }
  return lines;
}

function renderEgress(egress: EffectiveConfig["egress"] | undefined, impliedHosts: readonly ImpliedHost[]): string[] {
  if (egress === undefined) return ["egress: (unset)"];
  const lines = [
    "egress:",
    `  allow: ${fmtArray(egress.allow)}`,
  ];
  if (impliedHosts.length > 0) {
    lines.push("  implied:");
    for (const { host, source } of impliedHosts) {
      lines.push(`    - ${host} (implied by ${describeImpliedHostSource(source)})`);
    }
  }
  lines.push(
    `  allow-internal: ${fmtArray(egress["allow-internal"])}`,
    `  block-internal-ranges: ${fmtScalar(egress["block-internal-ranges"])}`,
    `  websockets: ${fmtScalar(egress.websockets)}`,
  );
  const githubApi = egress["github-api"];
  if (githubApi === undefined) {
    lines.push("  github-api: (unset)");
  } else {
    lines.push(
      "  github-api:",
      // `src/policy/github.ts`'s `githubApiGate` defaults an unset `hosts`
      // to `api.github.com` at enforcement time — say so here too, or an
      // operator reading "(unset)" would wrongly conclude nothing is being
      // gated at all, when in fact the gate is live against the default host.
      `    hosts: ${githubApi.hosts === undefined ? "(unset, defaults to api.github.com)" : fmtArray(githubApi.hosts)}`,
      // Same treatment for `methods`: `githubApiGate` defaults an unset
      // `methods` to `["GET", "HEAD"]` at enforcement time (fail-closed, not
      // "no restriction") — a bare "(unset)" here would misleadingly read as
      // unrestricted.
      `    methods: ${githubApi.methods === undefined ? "(unset, defaults to [GET, HEAD])" : fmtArray(githubApi.methods)}`,
      `    deny-paths: ${fmtArray(githubApi["deny-paths"])}`,
    );
  }
  return lines;
}

function renderGit(git: EffectiveConfig["git"] | undefined): string[] {
  if (git === undefined) return ["git: (unset)"];
  return [
    "git:",
    `  ssh-agent: ${fmtScalar(git["ssh-agent"])}`,
    `  allow-hosts: ${fmtArray(git["allow-hosts"])}`,
    `  allow-repos: ${fmtArray(git["allow-repos"])}`,
    `  allow-push: ${fmtScalar(git["allow-push"])}`,
  ];
}

function renderDirEntry(dir: DirConfig): string[] {
  const lines = [`- ${dir.name} (mode=${fmtScalar(dir.mode)}, host=${fmtScalar(dir.host)}, create=${fmtScalar(dir.create)})`];
  const builtinRules = dir["builtin-rules"] ?? [];
  if (builtinRules.length === 0) {
    lines.push("  builtin rules (protect-git): (none)");
  } else {
    lines.push("  builtin rules (protect-git):");
    for (const rule of builtinRules) {
      lines.push(`    - glob=${fmtScalar(rule.glob)} mode=${fmtScalar(rule.mode)} reason=${fmtScalar(rule.reason)}`);
    }
  }
  if ((dir.rules ?? []).length === 0) {
    lines.push("  rules: (none)");
  } else {
    lines.push("  rules:");
    for (const rule of dir.rules) {
      lines.push(`    - glob=${fmtScalar(rule.glob)} mode=${fmtScalar(rule.mode)} reason=${fmtScalar(rule.reason)}`);
    }
  }
  return lines;
}

function renderDirs(dirs: DirConfig[] = []): string[] {
  if (dirs.length === 0) {
    return ["dir: (none)"];
  }
  const lines = ["dir:"];
  for (const dir of dirs) {
    lines.push(...indentLines(renderDirEntry(dir), 1));
  }
  return lines;
}

function renderPolicy(policy: EffectiveConfig["policy"] | undefined): string[] {
  if (policy === undefined) return ["policy: (unset)"];
  return [
    "policy:",
    `  enabled: ${fmtScalar(policy.enabled)}`,
    `  secret-scan: ${fmtScalar(policy["secret-scan"])}`,
    `  max-changed-files: ${fmtScalar(policy["max-changed-files"])}`,
    `  fail-open: ${fmtScalar(policy["fail-open"])}`,
  ];
}

function renderAudit(audit: EffectiveConfig["audit"]): string[] {
  if (audit === undefined) {
    return ["audit: (unset)"];
  }
  return ["audit:", `  path: ${fmtScalar(audit.path)}`];
}

function renderWorkspaces(listing: WorkspaceListing): string[] {
  const lines = ["workspaces:", `  projects-root: ${fmtScalar(listing.projectsRoot)}`];
  if (listing.sources.length === 0) {
    lines.push("  sources: (none)");
  }
  for (const [index, source] of listing.sources.entries()) {
    lines.push(`  source ${index}: raw=${source.raw} resolved=${source.realPath}${source.exists ? "" : " missing"}`);
  }
  if (listing.workspaces.length === 0) {
    lines.push("  entries: (none)");
  }
  for (const entry of listing.workspaces) {
    lines.push(`  - ${entry.name}: source=${entry.source} dir=${entry.dir}`);
    if (!entry.valid) {
      lines.push(`    invalid: ${entry.reason}`);
    }
    for (const replaced of entry.replaced) {
      lines.push(`    replaces ${replaced.dir} (source=${replaced.source})`);
    }
  }
  return lines;
}

function renderConfigChangeList(label: string, changes: readonly ConfigChange[]): string[] {
  if (changes.length === 0) {
    return [`  ${label}: (none)`];
  }
  const lines = [`  ${label} (${changes.length}):`];
  for (const change of changes) {
    lines.push(`    - [${change.field}] ${change.description}`);
  }
  return lines;
}

/**
 * Exported so `src/commands/run.ts` can reuse the exact same itemized
 * widening/narrowing rendering when it fails a real (non-dry-run) `corb
 * run` for `requires-confirmation` without `--trust-config` — the error
 * message must not reinvent a second diff format.
 */
export function renderTrust(trust: TrustEvaluation, trustKey: string, scope?: {
  selectedWorkspace: { name: string } | undefined;
  dir: string | undefined;
  positionalDirAdded: boolean;
}, hashMatches?: boolean): string[] {
  const layers = ["config.toml"];
  if (scope?.selectedWorkspace !== undefined) {
    layers.push(`workspace ${scope.selectedWorkspace.name} corb.toml`);
  }
  if (scope?.positionalDirAdded) {
    layers.push(`positional directory ${scope.dir}`);
  }
  const isNoOp = trust.verdict === "trusted" && trust.widened.length === 0 && trust.narrowed.length === 0;
  const lines = [
    "trust:",
    `  key: ${trustKey}`,
    `  verdict: ${trust.verdict.toUpperCase()}`,
    `  scope: ${layers.join(" + ")} (does not include any --dir-added directories)`,
  ];
  if (isNoOp) {
    lines.push(hashMatches === false ? "  (only order differs; no effect on trust)" : "  (no changes since the last trusted run)");
    return lines;
  }
  lines.push(...renderConfigChangeList("widened", trust.widened));
  lines.push(...renderConfigChangeList("narrowed", trust.narrowed));
  return lines;
}

/** Shared config text for current settings and accepted snapshots. */
export function renderConfigSections(config: EffectiveConfig, impliedHosts: readonly ImpliedHost[], workspaceName?: string): string[] {
  return [
    `version: ${fmtScalar(config.version)}`,
    `name: ${fmtScalar(config.name)}`,
    ...renderVm(config.vm),
    ...renderImage(config.image, workspaceName),
    ...renderAgent(config.agent),
    ...renderSecrets(config.secrets),
    ...renderEgress(config.egress, impliedHosts),
    ...renderGit(config.git),
    ...renderDirs(config.dir),
    ...renderPolicy(config.policy),
    ...renderAudit(config.audit),
  ];
}

export function renderTrustedSnapshot(record: TrustedWorkspaceRecord | undefined, hashMatches?: boolean): string[] {
  if (record === undefined) return ["accepted snapshot: (none; no trust record for this key)"];
  return [
    "accepted snapshot:",
    `  accepted at: ${new Date(record.acceptedAt).toISOString()}`,
    `  hash: ${record.configHash}${hashMatches === false ? " (differs from current config)" : ""}`,
    ...indentLines(renderConfigSections(record.acceptedConfig, []), 1),
    "  implied hosts are not recorded in trust records",
  ];
}

export interface RenderOptions {
  trusted?: boolean;
}

export function renderText(resolved: ResolvedWorkspace, options: RenderOptions = {}): string {
  const { trustEvaluation, trustKey, dir } = resolved;
  const hashMatches = resolved.priorRecord === undefined ? undefined
    : hashEffectiveConfig(resolved.persistentConfig) === resolved.priorRecord.configHash;
  const lines: string[] = [
    // Neutral header — this rendering is shared by both `corb explain` and
    // `corb run --dry-run` (see `src/commands/run.ts`'s module comment), so
    // it deliberately doesn't name either command.
    `directory: ${dir ?? "(none)"}`,
    resolved.selectedWorkspace === undefined ? "workspace: (none; global config only)"
      : `workspace: ${resolved.selectedWorkspace.name} (selected by ${resolved.selectedWorkspace.selectedBy}; source ${resolved.selectedWorkspace.source.raw}; ${resolved.selectedWorkspace.dir})`,
    `primary: ${resolved.primary}`,
    "",
    ...renderConfigSections(resolved.fullConfig, resolved.impliedHosts, resolved.selectedWorkspace?.name),
    ...renderWorkspaces(resolved.workspaces),
    "",
    ...renderTrust(trustEvaluation, trustKey, resolved, options.trusted ? hashMatches : undefined),
    ...(options.trusted ? ["", ...renderTrustedSnapshot(resolved.priorRecord, hashMatches)] : []),
  ];
  return lines.join("\n");
}

/** The JSON payload `renderJson` serializes — round-trips through `JSON.parse` to structurally the same data. `config` is `fullConfig` (see module comment): what will actually run, not just the persistent layers. */
export interface ExplainJson {
  dir: string | null;
  primary: string;
  selectedWorkspace: ResolvedWorkspace["selectedWorkspace"] | null;
  trustKey: string;
  config: EffectiveConfig;
  impliedHosts: ImpliedHost[];
  trust: TrustEvaluation;
  workspaces: WorkspaceListing;
  imageLayer?: { definitionSha256: string; pinsState: "missing" | "pinned"; pinCommand?: string };
  acceptedSnapshot?: { acceptedAt: number; configHash: string; hashMatches: boolean; config: EffectiveConfig } | null;
}

/** Machine-readable rendering of `resolved`, pretty-printed (this is meant to be read by a human piping through `jq` or eyeballed directly, not a wire format optimized for size). */
export function renderJson(resolved: ResolvedWorkspace, options: RenderOptions = {}): string {
  const payload: ExplainJson = {
    dir: resolved.dir ?? null,
    primary: resolved.primary,
    selectedWorkspace: resolved.selectedWorkspace ?? null,
    trustKey: resolved.trustKey,
    config: resolved.fullConfig,
    ...(resolved.fullConfig.image === undefined ? {} : { imageLayer: {
      definitionSha256: hashLayerDefinition(resolved.fullConfig.image.layer),
      pinsState: resolved.fullConfig.image.pins === undefined ? "missing" as const : "pinned" as const,
      ...(resolved.fullConfig.image.pins === undefined ? { pinCommand: pinCommandHint(resolved.selectedWorkspace!.name) } : {}),
    } }),
    impliedHosts: resolved.impliedHosts,
    trust: resolved.trustEvaluation,
    workspaces: resolved.workspaces,
    ...(options.trusted ? { acceptedSnapshot: resolved.priorRecord === undefined ? null : {
      acceptedAt: resolved.priorRecord.acceptedAt,
      configHash: resolved.priorRecord.configHash,
      hashMatches: hashEffectiveConfig(resolved.persistentConfig) === resolved.priorRecord.configHash,
      config: resolved.priorRecord.acceptedConfig,
    } } : {}),
  };
  return JSON.stringify(payload, null, 2);
}
