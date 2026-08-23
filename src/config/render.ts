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
// (`PartialSecretConfig` is only `hosts`/`optional` host-binding metadata),
// so there is nothing secret-valued for this module to accidentally leak.
import type { DirConfig, EffectiveConfig } from "./load.ts";
import type { ConfigChange, TrustEvaluation } from "./trust.ts";
import type { ResolvedWorkspace } from "./resolve.ts";

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
  ];
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
  }
  return lines;
}

function renderEgress(egress: EffectiveConfig["egress"]): string[] {
  const lines = [
    "egress:",
    `  allow: ${fmtArray(egress.allow)}`,
    `  allow-internal: ${fmtArray(egress["allow-internal"])}`,
    `  block-internal-ranges: ${fmtScalar(egress["block-internal-ranges"])}`,
    `  websockets: ${fmtScalar(egress.websockets)}`,
  ];
  const githubApi = egress["github-api"];
  if (githubApi === undefined) {
    lines.push("  github-api: (unset)");
  } else {
    lines.push(
      "  github-api:",
      `    methods: ${fmtArray(githubApi.methods)}`,
      `    deny-paths: ${fmtArray(githubApi["deny-paths"])}`,
    );
  }
  return lines;
}

function renderGit(git: EffectiveConfig["git"]): string[] {
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
  if (dir.rules.length === 0) {
    lines.push("  rules: (none)");
  } else {
    lines.push("  rules:");
    for (const rule of dir.rules) {
      lines.push(`    - glob=${fmtScalar(rule.glob)} mode=${fmtScalar(rule.mode)} reason=${fmtScalar(rule.reason)}`);
    }
  }
  return lines;
}

function renderDirs(dirs: DirConfig[]): string[] {
  if (dirs.length === 0) {
    return ["dir: (none)"];
  }
  const lines = ["dir:"];
  for (const dir of dirs) {
    lines.push(...indentLines(renderDirEntry(dir), 1));
  }
  return lines;
}

function renderPolicy(policy: EffectiveConfig["policy"]): string[] {
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
export function renderTrust(trust: TrustEvaluation, trustKey: string): string[] {
  const isNoOp = trust.verdict === "trusted" && trust.widened.length === 0 && trust.narrowed.length === 0;
  const lines = [
    "trust:",
    `  key (directory path): ${trustKey}`,
    `  verdict: ${trust.verdict.toUpperCase()}`,
    "  scope: config.toml + this workspace directory only (does not include any --dir-added directories)",
  ];
  if (isNoOp) {
    lines.push("  (no changes since the last trusted run)");
    return lines;
  }
  lines.push(...renderConfigChangeList("widened", trust.widened));
  lines.push(...renderConfigChangeList("narrowed", trust.narrowed));
  return lines;
}

/**
 * Human-readable rendering of `resolved`: the effective config's meaningful
 * sections, then a clearly-labeled trust section. Formatting is deliberately
 * plain (indented key/value lines), not fussy — the goal is that a human can
 * tell at a glance whether running this workspace would require confirmation
 * and why (see module comment).
 */
export function renderText(resolved: ResolvedWorkspace): string {
  const { fullConfig: config, trustEvaluation, trustKey, dir } = resolved;
  const lines: string[] = [
    // Neutral header — this rendering is shared by both `corb explain` and
    // `corb run --dry-run` (see `src/commands/run.ts`'s module comment), so
    // it deliberately doesn't name either command.
    `workspace: ${dir}`,
    "",
    `version: ${fmtScalar(config.version)}`,
    `name: ${fmtScalar(config.name)}`,
    ...renderVm(config.vm),
    ...renderAgent(config.agent),
    ...renderSecrets(config.secrets),
    ...renderEgress(config.egress),
    ...renderGit(config.git),
    ...renderDirs(config.dir),
    ...renderPolicy(config.policy),
    ...renderAudit(config.audit),
    "",
    ...renderTrust(trustEvaluation, trustKey),
  ];
  return lines.join("\n");
}

/** The JSON payload `renderJson` serializes — round-trips through `JSON.parse` to structurally the same data. `config` is `fullConfig` (see module comment): what will actually run, not just the persistent layers. */
export interface ExplainJson {
  dir: string;
  trustKey: string;
  config: EffectiveConfig;
  trust: TrustEvaluation;
}

/** Machine-readable rendering of `resolved`, pretty-printed (this is meant to be read by a human piping through `jq` or eyeballed directly, not a wire format optimized for size). */
export function renderJson(resolved: ResolvedWorkspace): string {
  const payload: ExplainJson = {
    dir: resolved.dir,
    trustKey: resolved.trustKey,
    config: resolved.fullConfig,
    trust: resolved.trustEvaluation,
  };
  return JSON.stringify(payload, null, 2);
}
