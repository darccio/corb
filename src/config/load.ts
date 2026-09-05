// `src/config/load.ts` — M2.2: merges an ordered stack of `ConfigLayer`
// values (`src/config/schema.ts`, M2.1) — built-in defaults, `config.toml`,
// a workspace file, and CLI flags as a pseudo-layer — into one fully-merged
// `EffectiveConfig`. Nothing here reads a path off disk, prompts for trust,
// or parses a `--dir NAME=HOST:ro`-shaped flag string; those are M2.3/M2.5/
// M2.6. This module answers exactly one question: given N already-structured
// layers (later wins), what is the one effective config they produce?
//
// Merge rules (decided; see the M2.2 brief, not re-litigated here):
//   1. List-valued security settings are additive across layers, deduplicated
//      insertion-order: egress.allow, egress.allow-internal,
//      egress.github-api.hosts, egress.github-api.methods,
//      egress.github-api.deny-paths, git.allow-hosts, git.allow-repos,
//      agent.extensions, and a dir's own `rules` list (concatenated per
//      same-named dir, no dedup — see 2).
//   2. `dir` merges name-keyed at every layer boundary: a later layer's
//      entry for an existing name replaces every field wholesale (following
//      rule 3's scalar-replace) EXCEPT `rules`, which append. A new name
//      appends a new entry. This one rule, applied uniformly at every layer
//      transition, is also what gives a CLI dir flag its documented
//      "replaces a same-named entry wholesale" behavior — it is not special-
//      cased for the CLI layer.
//   3. Everything else (scalars, and nested scalar objects like `vm.limits`
//      and `egress.github-api` merged field-by-field) replaces: a later
//      layer's explicitly-set value wins, an unset field keeps whatever the
//      accumulated result already had.
import {
  type ConfigLayer,
  type DirMode,
  type PartialAgentConfig,
  type PartialAuditConfig,
  type PartialDirConfig,
  type PartialDirRuleConfig,
  type PartialEgressConfig,
  type PartialEgressGithubApiConfig,
  type PartialGitConfig,
  type PartialPolicyConfig,
  type PartialSecretConfig,
  type PartialVmConfig,
  type PartialVmLimits,
} from "./schema.ts";
import { validateMountTargets } from "./guestpaths.ts";

/** Thrown when layers cannot be merged as given — currently only a `[[dir]]` entry with no `name`. */
export class ConfigMergeError extends Error {
  constructor(detail: string) {
    super(`corb config: ${detail}`);
    this.name = "ConfigMergeError";
  }
}

/** One `[[dir]].rules[]` entry in the effective config. Shape is unchanged from the parsed layer, so reused as-is. */
export type DirRuleConfig = PartialDirRuleConfig;

/**
 * One `[[dir]]` entry in the effective config. `name` is required (it is the
 * merge key — see module comment, rule 2) and `rules` is always an array
 * (possibly empty), since it is built by concatenation across layers rather
 * than left absent when no layer happens to set it.
 */
export interface DirConfig {
  name: string;
  host?: string;
  mode?: DirMode;
  create?: boolean;
  rules: DirRuleConfig[];
}

export interface EffectiveEgressConfig {
  allow?: string[];
  "allow-internal"?: string[];
  /** Always present: `BUILTIN_DEFAULTS` sets it, and `mergeConfigLayers` always merges that layer in first. */
  "block-internal-ranges": boolean;
  websockets: boolean;
  "github-api"?: PartialEgressGithubApiConfig;
}

export interface EffectiveGitConfig {
  "ssh-agent": boolean;
  "allow-hosts"?: string[];
  "allow-repos"?: string[];
  "allow-push": boolean;
}

export interface EffectivePolicyConfig {
  enabled: boolean;
  "secret-scan": boolean;
  "max-changed-files"?: number;
  "fail-open": boolean;
}

/**
 * The fully-merged result of `mergeConfigLayers`. Fields with no built-in
 * default and no consumer yet (`vm`, `agent`, `secrets`, `audit`, and most
 * sub-fields of `egress`/`git`/`policy`) stay optional, exactly mirroring
 * `ConfigLayer`'s own partiality — they are resolved by whatever later code
 * actually consumes them (e.g. `src/vm/image.ts`'s `resolveRuntimeImage` owns
 * the `vm.image` fallback, not this file). Only `dir`, and the handful of
 * scalar fields `BUILTIN_DEFAULTS` always sets, are non-optional: the merge
 * itself always produces a concrete value for those regardless of input.
 */
export interface EffectiveConfig {
  version?: number;
  name?: string;
  vm?: PartialVmConfig;
  agent?: PartialAgentConfig;
  secrets?: Record<string, PartialSecretConfig>;
  egress: EffectiveEgressConfig;
  git: EffectiveGitConfig;
  dir: DirConfig[];
  policy: EffectivePolicyConfig;
  audit?: PartialAuditConfig;
}

// Single source of truth for every value BUILTIN_DEFAULTS sets, reused again
// in the finalize* functions below so the "guaranteed present" fields never
// have two places to go out of sync.
const DEFAULT_BLOCK_INTERNAL_RANGES = true;
const DEFAULT_WEBSOCKETS = false;
const DEFAULT_SSH_AGENT = true;
const DEFAULT_ALLOW_PUSH = false;
const DEFAULT_POLICY_ENABLED = true;
const DEFAULT_SECRET_SCAN = true;
const DEFAULT_FAIL_OPEN = true;

/**
 * The first, lowest-precedence layer of every merge: genuinely safe-by-default
 * structural values only, not product opinions. Deliberately leaves
 * `vm.image`, `vm.memory`, `vm.cpus`, `agent.provider`, `agent.model`,
 * `egress.allow`, `git.allow-hosts`, `git.allow-repos`, and
 * `policy.max-changed-files` absent — those are choices, not safety
 * defaults, and (for `vm.image` at least) already have their own fallback
 * where they're actually consumed.
 */
export const BUILTIN_DEFAULTS: ConfigLayer = {
  egress: {
    "block-internal-ranges": DEFAULT_BLOCK_INTERNAL_RANGES,
    websockets: DEFAULT_WEBSOCKETS,
  },
  git: {
    "ssh-agent": DEFAULT_SSH_AGENT,
    "allow-push": DEFAULT_ALLOW_PUSH,
  },
  policy: {
    enabled: DEFAULT_POLICY_ENABLED,
    "secret-scan": DEFAULT_SECRET_SCAN,
    "fail-open": DEFAULT_FAIL_OPEN,
  },
};

function mergeAdditiveArray(base: string[] | undefined, next: string[] | undefined): string[] | undefined {
  if (base === undefined && next === undefined) {
    return undefined;
  }
  return Array.from(new Set([...(base ?? []), ...(next ?? [])]));
}

function mergeVmLimits(base: PartialVmLimits | undefined, next: PartialVmLimits | undefined): PartialVmLimits | undefined {
  if (base === undefined && next === undefined) {
    return undefined;
  }
  const result: PartialVmLimits = {};
  const memoryMax = next?.["memory-max"] ?? base?.["memory-max"];
  if (memoryMax !== undefined) {
    result["memory-max"] = memoryMax;
  }
  const pidsMax = next?.["pids-max"] ?? base?.["pids-max"];
  if (pidsMax !== undefined) {
    result["pids-max"] = pidsMax;
  }
  const cpuQuota = next?.["cpu-quota"] ?? base?.["cpu-quota"];
  if (cpuQuota !== undefined) {
    result["cpu-quota"] = cpuQuota;
  }
  return result;
}

function mergeVmConfig(base: PartialVmConfig | undefined, next: PartialVmConfig | undefined): PartialVmConfig | undefined {
  if (base === undefined && next === undefined) {
    return undefined;
  }
  const result: PartialVmConfig = {};
  const image = next?.image ?? base?.image;
  if (image !== undefined) {
    result.image = image;
  }
  const memory = next?.memory ?? base?.memory;
  if (memory !== undefined) {
    result.memory = memory;
  }
  const cpus = next?.cpus ?? base?.cpus;
  if (cpus !== undefined) {
    result.cpus = cpus;
  }
  const maxSession = next?.["max-session"] ?? base?.["max-session"];
  if (maxSession !== undefined) {
    result["max-session"] = maxSession;
  }
  const limits = mergeVmLimits(base?.limits, next?.limits);
  if (limits !== undefined) {
    result.limits = limits;
  }
  return result;
}

// `extensions`/`append-system-prompt-file` need no special handling below
// (E2): `schema.ts`'s `parseAgentConfig` now rejects a non-empty
// `extensions` or any `append-system-prompt-file` at parse time, strictly
// before any layer ever reaches this merge — so the only values this
// function can ever see for them are already the safe, ordinary ones
// (`undefined`, or `[]` for `extensions`) that the existing generic merge
// rules below already handle correctly.
function mergeAgentConfig(
  base: PartialAgentConfig | undefined,
  next: PartialAgentConfig | undefined,
): PartialAgentConfig | undefined {
  if (base === undefined && next === undefined) {
    return undefined;
  }
  const result: PartialAgentConfig = {};
  const provider = next?.provider ?? base?.provider;
  if (provider !== undefined) {
    result.provider = provider;
  }
  const model = next?.model ?? base?.model;
  if (model !== undefined) {
    result.model = model;
  }
  const extensions = mergeAdditiveArray(base?.extensions, next?.extensions);
  if (extensions !== undefined) {
    result.extensions = extensions;
  }
  const appendSystemPromptFile = next?.["append-system-prompt-file"] ?? base?.["append-system-prompt-file"];
  if (appendSystemPromptFile !== undefined) {
    result["append-system-prompt-file"] = appendSystemPromptFile;
  }
  return result;
}

// Not named in the M2.2 brief's explicit list of merge decisions (that list
// covers `secrets` nowhere). Treated the same way as `vm.limits` /
// `egress.github-api`: `secrets` is itself a name-keyed map (like `dir`, but
// already keyed by object key rather than needing array-keying logic), and
// each entry's own fields (`hosts`, `optional`) are plain scalars merged
// field-by-field per rule 3 — not additive, since `hosts` isn't in rule 1's
// enumerated list of additive fields.
function mergeSecretEntry(base: PartialSecretConfig | undefined, next: PartialSecretConfig): PartialSecretConfig {
  const result: PartialSecretConfig = {};
  const hosts = next.hosts ?? base?.hosts;
  if (hosts !== undefined) {
    result.hosts = hosts;
  }
  const optional = next.optional ?? base?.optional;
  if (optional !== undefined) {
    result.optional = optional;
  }
  // `verify` is a single whole-object field here, same as `optional` above —
  // a later layer's `[secrets.NAME.verify]` replaces an earlier layer's
  // wholesale rather than merging its own `url`/`header`/`expect-status`
  // sub-fields individually, matching `parseSecretVerify`'s own all-or-
  // nothing validation (a `verify` table is only ever produced whole).
  const verify = next.verify ?? base?.verify;
  if (verify !== undefined) {
    result.verify = verify;
  }
  return result;
}

function mergeSecrets(
  base: Record<string, PartialSecretConfig> | undefined,
  next: Record<string, PartialSecretConfig> | undefined,
): Record<string, PartialSecretConfig> | undefined {
  if (base === undefined && next === undefined) {
    return undefined;
  }
  const result: Record<string, PartialSecretConfig> = { ...base };
  if (next !== undefined) {
    for (const [name, entry] of Object.entries(next)) {
      result[name] = mergeSecretEntry(result[name], entry);
    }
  }
  return result;
}

function mergeGithubApiConfig(
  base: PartialEgressGithubApiConfig | undefined,
  next: PartialEgressGithubApiConfig | undefined,
): PartialEgressGithubApiConfig | undefined {
  if (base === undefined && next === undefined) {
    return undefined;
  }
  const result: PartialEgressGithubApiConfig = {};
  const hosts = mergeAdditiveArray(base?.hosts, next?.hosts);
  if (hosts !== undefined) {
    result.hosts = hosts;
  }
  const methods = mergeAdditiveArray(base?.methods, next?.methods);
  if (methods !== undefined) {
    result.methods = methods;
  }
  const denyPaths = mergeAdditiveArray(base?.["deny-paths"], next?.["deny-paths"]);
  if (denyPaths !== undefined) {
    result["deny-paths"] = denyPaths;
  }
  return result;
}

function mergeEgressConfig(
  base: PartialEgressConfig | undefined,
  next: PartialEgressConfig | undefined,
): PartialEgressConfig | undefined {
  if (base === undefined && next === undefined) {
    return undefined;
  }
  const result: PartialEgressConfig = {};
  const allow = mergeAdditiveArray(base?.allow, next?.allow);
  if (allow !== undefined) {
    result.allow = allow;
  }
  const allowInternal = mergeAdditiveArray(base?.["allow-internal"], next?.["allow-internal"]);
  if (allowInternal !== undefined) {
    result["allow-internal"] = allowInternal;
  }
  const blockInternalRanges = next?.["block-internal-ranges"] ?? base?.["block-internal-ranges"];
  if (blockInternalRanges !== undefined) {
    result["block-internal-ranges"] = blockInternalRanges;
  }
  const websockets = next?.websockets ?? base?.websockets;
  if (websockets !== undefined) {
    result.websockets = websockets;
  }
  const githubApi = mergeGithubApiConfig(base?.["github-api"], next?.["github-api"]);
  if (githubApi !== undefined) {
    result["github-api"] = githubApi;
  }
  return result;
}

function mergeGitConfig(base: PartialGitConfig | undefined, next: PartialGitConfig | undefined): PartialGitConfig | undefined {
  if (base === undefined && next === undefined) {
    return undefined;
  }
  const result: PartialGitConfig = {};
  const sshAgent = next?.["ssh-agent"] ?? base?.["ssh-agent"];
  if (sshAgent !== undefined) {
    result["ssh-agent"] = sshAgent;
  }
  const allowHosts = mergeAdditiveArray(base?.["allow-hosts"], next?.["allow-hosts"]);
  if (allowHosts !== undefined) {
    result["allow-hosts"] = allowHosts;
  }
  const allowRepos = mergeAdditiveArray(base?.["allow-repos"], next?.["allow-repos"]);
  if (allowRepos !== undefined) {
    result["allow-repos"] = allowRepos;
  }
  const allowPush = next?.["allow-push"] ?? base?.["allow-push"];
  if (allowPush !== undefined) {
    result["allow-push"] = allowPush;
  }
  return result;
}

function mergePolicyConfig(
  base: PartialPolicyConfig | undefined,
  next: PartialPolicyConfig | undefined,
): PartialPolicyConfig | undefined {
  if (base === undefined && next === undefined) {
    return undefined;
  }
  const result: PartialPolicyConfig = {};
  const enabled = next?.enabled ?? base?.enabled;
  if (enabled !== undefined) {
    result.enabled = enabled;
  }
  const secretScan = next?.["secret-scan"] ?? base?.["secret-scan"];
  if (secretScan !== undefined) {
    result["secret-scan"] = secretScan;
  }
  const maxChangedFiles = next?.["max-changed-files"] ?? base?.["max-changed-files"];
  if (maxChangedFiles !== undefined) {
    result["max-changed-files"] = maxChangedFiles;
  }
  const failOpen = next?.["fail-open"] ?? base?.["fail-open"];
  if (failOpen !== undefined) {
    result["fail-open"] = failOpen;
  }
  return result;
}

function mergeAuditConfig(base: PartialAuditConfig | undefined, next: PartialAuditConfig | undefined): PartialAuditConfig | undefined {
  if (base === undefined && next === undefined) {
    return undefined;
  }
  const result: PartialAuditConfig = {};
  const path = next?.path ?? base?.path;
  if (path !== undefined) {
    result.path = path;
  }
  return result;
}

function mergeDirEntry(base: DirConfig[], incoming: PartialDirConfig): DirConfig[] {
  if (incoming.name === undefined) {
    throw new ConfigMergeError("a [[dir]] entry has no 'name', which is required to merge dir layers");
  }
  const idx = base.findIndex((d) => d.name === incoming.name);
  const existing = idx === -1 ? undefined : base[idx];

  const merged: DirConfig = {
    name: incoming.name,
    // Rules append across layers (rule 1); every other field replaces
    // wholesale-if-set (rule 3) — see module comment, rule 2.
    rules: [...(existing?.rules ?? []), ...(incoming.rules ?? [])],
  };
  const host = incoming.host ?? existing?.host;
  if (host !== undefined) {
    merged.host = host;
  }
  const mode = incoming.mode ?? existing?.mode;
  if (mode !== undefined) {
    merged.mode = mode;
  }
  const create = incoming.create ?? existing?.create;
  if (create !== undefined) {
    merged.create = create;
  }

  if (idx === -1) {
    return [...base, merged];
  }
  const copy = [...base];
  copy[idx] = merged;
  return copy;
}

function mergeDirList(base: DirConfig[], next: PartialDirConfig[] | undefined): DirConfig[] {
  if (next === undefined) {
    return base;
  }
  return next.reduce(mergeDirEntry, base);
}

function finalizeEgress(merged: PartialEgressConfig | undefined): EffectiveEgressConfig {
  const result: EffectiveEgressConfig = {
    "block-internal-ranges": merged?.["block-internal-ranges"] ?? DEFAULT_BLOCK_INTERNAL_RANGES,
    websockets: merged?.websockets ?? DEFAULT_WEBSOCKETS,
  };
  if (merged?.allow !== undefined) {
    result.allow = merged.allow;
  }
  if (merged?.["allow-internal"] !== undefined) {
    result["allow-internal"] = merged["allow-internal"];
  }
  if (merged?.["github-api"] !== undefined) {
    result["github-api"] = merged["github-api"];
  }
  return result;
}

function finalizeGit(merged: PartialGitConfig | undefined): EffectiveGitConfig {
  const result: EffectiveGitConfig = {
    "ssh-agent": merged?.["ssh-agent"] ?? DEFAULT_SSH_AGENT,
    "allow-push": merged?.["allow-push"] ?? DEFAULT_ALLOW_PUSH,
  };
  if (merged?.["allow-hosts"] !== undefined) {
    result["allow-hosts"] = merged["allow-hosts"];
  }
  if (merged?.["allow-repos"] !== undefined) {
    result["allow-repos"] = merged["allow-repos"];
  }
  return result;
}

function finalizePolicy(merged: PartialPolicyConfig | undefined): EffectivePolicyConfig {
  const result: EffectivePolicyConfig = {
    enabled: merged?.enabled ?? DEFAULT_POLICY_ENABLED,
    "secret-scan": merged?.["secret-scan"] ?? DEFAULT_SECRET_SCAN,
    "fail-open": merged?.["fail-open"] ?? DEFAULT_FAIL_OPEN,
  };
  if (merged?.["max-changed-files"] !== undefined) {
    result["max-changed-files"] = merged["max-changed-files"];
  }
  return result;
}

/**
 * Merges `layers` (low-to-high precedence — a later layer wins) into one
 * `EffectiveConfig`, then validates the merged `dir` list's guest mount
 * targets (`src/config/guestpaths.ts`), throwing `GuestPathError` rather
 * than silently dropping an invalid one. This is the only place that check
 * runs, so an invalid mount target cannot reach anything downstream of this
 * function.
 *
 * `BUILTIN_DEFAULTS` is merged in unconditionally as the true first layer,
 * ahead of anything in `layers` — callers do not pass it themselves (compare
 * the tests in `load.test.ts`, which call this with just
 * `[configToml, workspace, cliLayer]`). This is a deliberate choice, not an
 * oversight: `EffectiveConfig`'s non-optional fields (`dir`,
 * `egress.block-internal-ranges`, `git.ssh-agent`, `policy.enabled`, ...) are
 * only honestly non-optional if they are *always* present regardless of what
 * `layers` contains, and "regardless of input" only holds if this function
 * guarantees the defaults itself rather than trusting every caller to
 * remember to pass `BUILTIN_DEFAULTS` first. One consequence, verified by a
 * test below: `mergeConfigLayers([])` and `mergeConfigLayers([BUILTIN_DEFAULTS])`
 * produce the same result.
 */
export function mergeConfigLayers(layers: ConfigLayer[]): EffectiveConfig {
  let version: number | undefined;
  let name: string | undefined;
  let vm: PartialVmConfig | undefined;
  let agent: PartialAgentConfig | undefined;
  let secrets: Record<string, PartialSecretConfig> | undefined;
  let egress: PartialEgressConfig | undefined;
  let git: PartialGitConfig | undefined;
  let dir: DirConfig[] = [];
  let policy: PartialPolicyConfig | undefined;
  let audit: PartialAuditConfig | undefined;

  for (const layer of [BUILTIN_DEFAULTS, ...layers]) {
    version = layer.version ?? version;
    name = layer.name ?? name;
    vm = mergeVmConfig(vm, layer.vm);
    agent = mergeAgentConfig(agent, layer.agent);
    secrets = mergeSecrets(secrets, layer.secrets);
    egress = mergeEgressConfig(egress, layer.egress);
    git = mergeGitConfig(git, layer.git);
    dir = mergeDirList(dir, layer.dir);
    policy = mergePolicyConfig(policy, layer.policy);
    audit = mergeAuditConfig(audit, layer.audit);
  }

  validateMountTargets(dir);

  const result: EffectiveConfig = {
    egress: finalizeEgress(egress),
    git: finalizeGit(git),
    dir,
    policy: finalizePolicy(policy),
  };
  if (version !== undefined) {
    result.version = version;
  }
  if (name !== undefined) {
    result.name = name;
  }
  if (vm !== undefined) {
    result.vm = vm;
  }
  if (agent !== undefined) {
    result.agent = agent;
  }
  if (secrets !== undefined) {
    result.secrets = secrets;
  }
  if (audit !== undefined) {
    result.audit = audit;
  }
  return result;
}
