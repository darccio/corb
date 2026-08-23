// `src/config/schema.ts` — M2.1: the data shape of one `corb.toml` document
// (`~/.config/corb/config.toml`, or one `~/.config/corb/workspaces/<name>.toml`)
// and a parser for it. Nothing here merges layers or resolves defaults — that
// is M2.2 (`src/config/load.ts`). Nothing here reads a path off disk or knows
// about trust — that is also M2.2/M2.3. This module answers exactly one
// question: given the text of a single TOML document, is it well-formed
// against Corb's config schema, and if so what does it say?
//
// Corb layers config as: built-in defaults < config.toml < workspace file <
// CLI-flags-as-a-pseudo-layer. Any single document in that stack is
// legitimately partial (a workspace file might set only `[[dir]]` entries and
// inherit everything else), so every field below is optional — the exception
// is the wrapping object for a table that *is* present (`vm` on a `ConfigLayer`
// that has a `[vm]` section is a `PartialVmConfig`, never `undefined`), which
// falls out of TOML's own nesting rather than being a schema choice.
import { parse, TomlError } from "smol-toml";

/**
 * Exactly the four `[[dir]].rules[]` modes the implementation plan's
 * `corb.toml` spec uses (including `shadow-write`, absent from
 * `docs/design.md` §3's three-mode `GlobRuleMode` — that doc is stale here;
 * this is the current, authoritative set).
 */
export const RULE_MODES = ["deny-write", "deny-read", "hidden", "shadow-write"] as const;
export type RuleMode = (typeof RULE_MODES)[number];

/** `[[dir]].mode` — the directory's own mode, distinct from a rule's `mode`. */
export const DIR_MODES = ["ro", "rw"] as const;
export type DirMode = (typeof DIR_MODES)[number];

// Duration/size/percentage fields stay opaque, format-validated strings: no
// downstream consumer parses them into a structured value before M8 (session
// limits), so there is nothing for this milestone to convert them into.
const MEMORY_SIZE_RE = /^\d+[KMGT]?$/i;
const DURATION_RE = /^\d+[smhd]$/;
const PERCENT_RE = /^\d+%$/;

export interface PartialVmLimits {
  "memory-max"?: string;
  "pids-max"?: number;
  "cpu-quota"?: string;
}

export interface PartialVmConfig {
  image?: string;
  memory?: string;
  cpus?: number;
  "max-session"?: string;
  limits?: PartialVmLimits;
}

export interface PartialAgentConfig {
  provider?: string;
  model?: string;
  extensions?: string[];
  "append-system-prompt-file"?: string;
}

/** One `[secrets.NAME]` entry. `NAME` itself is a user-chosen secret name, not part of this shape. */
export interface PartialSecretConfig {
  hosts?: string[];
  optional?: boolean;
}

export interface PartialEgressGithubApiConfig {
  /**
   * The host(s) this gate targets. Parsed the same way as `methods`/
   * `deny-paths` — a plain string array, no special validation beyond that.
   * Absent within a present `[egress.github-api]` table is meaningful and is
   * NOT resolved here: `src/policy/github.ts` (M4.2) is what defaults it to
   * `["api.github.com"]`, and only once the table itself is present — see
   * that module's own doc comment for why the default deliberately does not
   * live in `src/config/load.ts`'s `BUILTIN_DEFAULTS`.
   */
  hosts?: string[];
  methods?: string[];
  "deny-paths"?: string[];
}

export interface PartialEgressConfig {
  allow?: string[];
  "allow-internal"?: string[];
  "block-internal-ranges"?: boolean;
  websockets?: boolean;
  "github-api"?: PartialEgressGithubApiConfig;
}

export interface PartialGitConfig {
  "ssh-agent"?: boolean;
  "allow-hosts"?: string[];
  "allow-repos"?: string[];
  "allow-push"?: boolean;
}

export interface PartialDirRuleConfig {
  glob?: string;
  mode?: RuleMode;
  reason?: string;
}

export interface PartialDirConfig {
  name?: string;
  host?: string;
  mode?: DirMode;
  create?: boolean;
  rules?: PartialDirRuleConfig[];
}

export interface PartialPolicyConfig {
  enabled?: boolean;
  "secret-scan"?: boolean;
  "max-changed-files"?: number;
  "fail-open"?: boolean;
}

export interface PartialAuditConfig {
  path?: string;
}

/**
 * One layer's worth of config, as parsed from a single TOML document —
 * `config.toml`, or one workspace file. M2.2's loader merges several of
 * these (plus built-in defaults and CLI flags) into a single, fully-required
 * effective config; that merge, and the "everything required" type it
 * produces, live there, not here.
 */
export interface ConfigLayer {
  version?: number;
  name?: string;
  vm?: PartialVmConfig;
  agent?: PartialAgentConfig;
  secrets?: Record<string, PartialSecretConfig>;
  egress?: PartialEgressConfig;
  git?: PartialGitConfig;
  dir?: PartialDirConfig[];
  policy?: PartialPolicyConfig;
  audit?: PartialAuditConfig;
}

/**
 * Thrown for any malformed `corb.toml` document: invalid TOML syntax, an
 * unrecognized key at any level, a value of the wrong type, an out-of-set
 * enum value, or a duration/size/percentage string that doesn't match its
 * expected format. `location`, when present, is the dotted/indexed field
 * path (e.g. `"vm.memory"`, `"dir[0].rules[1].mode"`) that failed.
 */
export class ConfigParseError extends Error {
  readonly sourceLabel: string;
  readonly location: string | undefined;

  constructor(sourceLabel: string, detail: string, location?: string) {
    super(`corb config: ${sourceLabel}: ${detail}`);
    this.name = "ConfigParseError";
    this.sourceLabel = sourceLabel;
    this.location = location;
  }
}

function joinPath(location: string, key: string): string {
  return location === "" ? key : `${location}.${key}`;
}

function describeType(value: unknown): string {
  if (value === null) {
    return "null";
  }
  if (Array.isArray(value)) {
    return "array";
  }
  return typeof value;
}

// Unknown keys are rejected everywhere (not just validated where present) so
// that a typo like `memroy` for `memory` fails loudly at parse time instead
// of silently vanishing as an ignored field.
function assertKnownKeys(
  table: Record<string, unknown>,
  allowedKeys: readonly string[],
  location: string,
  sourceLabel: string,
): void {
  for (const key of Object.keys(table)) {
    if (!allowedKeys.includes(key)) {
      const fieldPath = joinPath(location, key);
      throw new ConfigParseError(
        sourceLabel,
        `unknown key '${fieldPath}' (allowed: ${allowedKeys.join(", ")})`,
        fieldPath,
      );
    }
  }
}

function expectTable(value: unknown, fieldPath: string, sourceLabel: string): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new ConfigParseError(sourceLabel, `field '${fieldPath}' must be a table, got ${describeType(value)}`, fieldPath);
  }
  return value as Record<string, unknown>;
}

function expectArray(value: unknown, fieldPath: string, sourceLabel: string): unknown[] {
  if (!Array.isArray(value)) {
    throw new ConfigParseError(sourceLabel, `field '${fieldPath}' must be an array, got ${describeType(value)}`, fieldPath);
  }
  return value;
}

function expectString(value: unknown, fieldPath: string, sourceLabel: string): string {
  if (typeof value !== "string") {
    throw new ConfigParseError(sourceLabel, `field '${fieldPath}' must be a string, got ${describeType(value)}`, fieldPath);
  }
  return value;
}

function expectBoolean(value: unknown, fieldPath: string, sourceLabel: string): boolean {
  if (typeof value !== "boolean") {
    throw new ConfigParseError(sourceLabel, `field '${fieldPath}' must be a boolean, got ${describeType(value)}`, fieldPath);
  }
  return value;
}

function expectNumber(value: unknown, fieldPath: string, sourceLabel: string): number {
  if (typeof value !== "number" || !Number.isFinite(value)) {
    throw new ConfigParseError(sourceLabel, `field '${fieldPath}' must be a number, got ${describeType(value)}`, fieldPath);
  }
  return value;
}

function expectInteger(value: unknown, fieldPath: string, sourceLabel: string, min: number): number {
  const num = expectNumber(value, fieldPath, sourceLabel);
  if (!Number.isInteger(num) || num < min) {
    throw new ConfigParseError(sourceLabel, `field '${fieldPath}' must be an integer >= ${min}, got ${num}`, fieldPath);
  }
  return num;
}

function expectStringArray(value: unknown, fieldPath: string, sourceLabel: string): string[] {
  const arr = expectArray(value, fieldPath, sourceLabel);
  return arr.map((item, i) => expectString(item, `${fieldPath}[${i}]`, sourceLabel));
}

function expectEnum<T extends string>(value: unknown, fieldPath: string, allowed: readonly T[], sourceLabel: string): T {
  const str = expectString(value, fieldPath, sourceLabel);
  if (!(allowed as readonly string[]).includes(str)) {
    throw new ConfigParseError(
      sourceLabel,
      `field '${fieldPath}' has invalid value '${str}' (allowed: ${allowed.join(", ")})`,
      fieldPath,
    );
  }
  return str as T;
}

function expectFormattedString(
  value: unknown,
  fieldPath: string,
  sourceLabel: string,
  pattern: RegExp,
  example: string,
): string {
  const str = expectString(value, fieldPath, sourceLabel);
  if (!pattern.test(str)) {
    throw new ConfigParseError(sourceLabel, `field '${fieldPath}' has invalid format '${str}' (expected e.g. '${example}')`, fieldPath);
  }
  return str;
}

const VM_LIMITS_KEYS = ["memory-max", "pids-max", "cpu-quota"] as const;

function parseVmLimits(value: unknown, location: string, sourceLabel: string): PartialVmLimits {
  const table = expectTable(value, location, sourceLabel);
  assertKnownKeys(table, VM_LIMITS_KEYS, location, sourceLabel);
  const result: PartialVmLimits = {};
  if (table["memory-max"] !== undefined) {
    result["memory-max"] = expectFormattedString(table["memory-max"], joinPath(location, "memory-max"), sourceLabel, MEMORY_SIZE_RE, "6G");
  }
  if (table["pids-max"] !== undefined) {
    result["pids-max"] = expectInteger(table["pids-max"], joinPath(location, "pids-max"), sourceLabel, 1);
  }
  if (table["cpu-quota"] !== undefined) {
    result["cpu-quota"] = expectFormattedString(table["cpu-quota"], joinPath(location, "cpu-quota"), sourceLabel, PERCENT_RE, "400%");
  }
  return result;
}

const VM_KEYS = ["image", "memory", "cpus", "max-session", "limits"] as const;

function parseVmConfig(value: unknown, sourceLabel: string): PartialVmConfig {
  const table = expectTable(value, "vm", sourceLabel);
  assertKnownKeys(table, VM_KEYS, "vm", sourceLabel);
  const result: PartialVmConfig = {};
  if (table.image !== undefined) {
    result.image = expectString(table.image, "vm.image", sourceLabel);
  }
  if (table.memory !== undefined) {
    result.memory = expectFormattedString(table.memory, "vm.memory", sourceLabel, MEMORY_SIZE_RE, "4G");
  }
  if (table.cpus !== undefined) {
    result.cpus = expectInteger(table.cpus, "vm.cpus", sourceLabel, 1);
  }
  if (table["max-session"] !== undefined) {
    result["max-session"] = expectFormattedString(table["max-session"], "vm.max-session", sourceLabel, DURATION_RE, "4h");
  }
  if (table.limits !== undefined) {
    result.limits = parseVmLimits(table.limits, "vm.limits", sourceLabel);
  }
  return result;
}

const AGENT_KEYS = ["provider", "model", "extensions", "append-system-prompt-file"] as const;

function parseAgentConfig(value: unknown, sourceLabel: string): PartialAgentConfig {
  const table = expectTable(value, "agent", sourceLabel);
  assertKnownKeys(table, AGENT_KEYS, "agent", sourceLabel);
  const result: PartialAgentConfig = {};
  if (table.provider !== undefined) {
    result.provider = expectString(table.provider, "agent.provider", sourceLabel);
  }
  if (table.model !== undefined) {
    result.model = expectString(table.model, "agent.model", sourceLabel);
  }
  if (table.extensions !== undefined) {
    result.extensions = expectStringArray(table.extensions, "agent.extensions", sourceLabel);
  }
  if (table["append-system-prompt-file"] !== undefined) {
    result["append-system-prompt-file"] = expectString(
      table["append-system-prompt-file"],
      "agent.append-system-prompt-file",
      sourceLabel,
    );
  }
  return result;
}

const SECRET_KEYS = ["hosts", "optional"] as const;

function parseSecretEntry(value: unknown, location: string, sourceLabel: string): PartialSecretConfig {
  const table = expectTable(value, location, sourceLabel);
  assertKnownKeys(table, SECRET_KEYS, location, sourceLabel);
  const result: PartialSecretConfig = {};
  if (table.hosts !== undefined) {
    result.hosts = expectStringArray(table.hosts, joinPath(location, "hosts"), sourceLabel);
  }
  if (table.optional !== undefined) {
    result.optional = expectBoolean(table.optional, joinPath(location, "optional"), sourceLabel);
  }
  return result;
}

// `secrets`' own keys are user-chosen secret names (ANTHROPIC_API_KEY,
// GITHUB_TOKEN, ...), not schema fields — they are never checked against a
// known-key list. Only the fixed shape of each entry's own table is.
function parseSecretsConfig(value: unknown, sourceLabel: string): Record<string, PartialSecretConfig> {
  const table = expectTable(value, "secrets", sourceLabel);
  const result: Record<string, PartialSecretConfig> = {};
  for (const [name, entry] of Object.entries(table)) {
    result[name] = parseSecretEntry(entry, `secrets.${name}`, sourceLabel);
  }
  return result;
}

const EGRESS_GITHUB_API_KEYS = ["hosts", "methods", "deny-paths"] as const;

function parseEgressGithubApi(value: unknown, sourceLabel: string): PartialEgressGithubApiConfig {
  const table = expectTable(value, "egress.github-api", sourceLabel);
  assertKnownKeys(table, EGRESS_GITHUB_API_KEYS, "egress.github-api", sourceLabel);
  const result: PartialEgressGithubApiConfig = {};
  if (table.hosts !== undefined) {
    result.hosts = expectStringArray(table.hosts, "egress.github-api.hosts", sourceLabel);
  }
  if (table.methods !== undefined) {
    result.methods = expectStringArray(table.methods, "egress.github-api.methods", sourceLabel);
  }
  if (table["deny-paths"] !== undefined) {
    result["deny-paths"] = expectStringArray(table["deny-paths"], "egress.github-api.deny-paths", sourceLabel);
  }
  return result;
}

const EGRESS_KEYS = ["allow", "allow-internal", "block-internal-ranges", "websockets", "github-api"] as const;

function parseEgressConfig(value: unknown, sourceLabel: string): PartialEgressConfig {
  const table = expectTable(value, "egress", sourceLabel);
  assertKnownKeys(table, EGRESS_KEYS, "egress", sourceLabel);
  const result: PartialEgressConfig = {};
  if (table.allow !== undefined) {
    result.allow = expectStringArray(table.allow, "egress.allow", sourceLabel);
  }
  if (table["allow-internal"] !== undefined) {
    result["allow-internal"] = expectStringArray(table["allow-internal"], "egress.allow-internal", sourceLabel);
  }
  if (table["block-internal-ranges"] !== undefined) {
    result["block-internal-ranges"] = expectBoolean(table["block-internal-ranges"], "egress.block-internal-ranges", sourceLabel);
  }
  if (table.websockets !== undefined) {
    result.websockets = expectBoolean(table.websockets, "egress.websockets", sourceLabel);
  }
  if (table["github-api"] !== undefined) {
    result["github-api"] = parseEgressGithubApi(table["github-api"], sourceLabel);
  }
  return result;
}

const GIT_KEYS = ["ssh-agent", "allow-hosts", "allow-repos", "allow-push"] as const;

function parseGitConfig(value: unknown, sourceLabel: string): PartialGitConfig {
  const table = expectTable(value, "git", sourceLabel);
  assertKnownKeys(table, GIT_KEYS, "git", sourceLabel);
  const result: PartialGitConfig = {};
  if (table["ssh-agent"] !== undefined) {
    result["ssh-agent"] = expectBoolean(table["ssh-agent"], "git.ssh-agent", sourceLabel);
  }
  if (table["allow-hosts"] !== undefined) {
    result["allow-hosts"] = expectStringArray(table["allow-hosts"], "git.allow-hosts", sourceLabel);
  }
  if (table["allow-repos"] !== undefined) {
    result["allow-repos"] = expectStringArray(table["allow-repos"], "git.allow-repos", sourceLabel);
  }
  if (table["allow-push"] !== undefined) {
    result["allow-push"] = expectBoolean(table["allow-push"], "git.allow-push", sourceLabel);
  }
  return result;
}

const DIR_RULE_KEYS = ["glob", "mode", "reason"] as const;

function parseDirRule(value: unknown, location: string, sourceLabel: string): PartialDirRuleConfig {
  const table = expectTable(value, location, sourceLabel);
  assertKnownKeys(table, DIR_RULE_KEYS, location, sourceLabel);
  const result: PartialDirRuleConfig = {};
  if (table.glob !== undefined) {
    result.glob = expectString(table.glob, joinPath(location, "glob"), sourceLabel);
  }
  if (table.mode !== undefined) {
    result.mode = expectEnum(table.mode, joinPath(location, "mode"), RULE_MODES, sourceLabel);
  }
  if (table.reason !== undefined) {
    result.reason = expectString(table.reason, joinPath(location, "reason"), sourceLabel);
  }
  return result;
}

const DIR_KEYS = ["name", "host", "mode", "create", "rules"] as const;

function parseDirEntry(value: unknown, location: string, sourceLabel: string): PartialDirConfig {
  const table = expectTable(value, location, sourceLabel);
  assertKnownKeys(table, DIR_KEYS, location, sourceLabel);
  const result: PartialDirConfig = {};
  if (table.name !== undefined) {
    result.name = expectString(table.name, joinPath(location, "name"), sourceLabel);
  }
  if (table.host !== undefined) {
    result.host = expectString(table.host, joinPath(location, "host"), sourceLabel);
  }
  if (table.mode !== undefined) {
    result.mode = expectEnum(table.mode, joinPath(location, "mode"), DIR_MODES, sourceLabel);
  }
  if (table.create !== undefined) {
    result.create = expectBoolean(table.create, joinPath(location, "create"), sourceLabel);
  }
  if (table.rules !== undefined) {
    const rulesPath = joinPath(location, "rules");
    const rulesArr = expectArray(table.rules, rulesPath, sourceLabel);
    result.rules = rulesArr.map((rule, i) => parseDirRule(rule, `${rulesPath}[${i}]`, sourceLabel));
  }
  return result;
}

function parseDirList(value: unknown, sourceLabel: string): PartialDirConfig[] {
  const arr = expectArray(value, "dir", sourceLabel);
  return arr.map((entry, i) => parseDirEntry(entry, `dir[${i}]`, sourceLabel));
}

const POLICY_KEYS = ["enabled", "secret-scan", "max-changed-files", "fail-open"] as const;

function parsePolicyConfig(value: unknown, sourceLabel: string): PartialPolicyConfig {
  const table = expectTable(value, "policy", sourceLabel);
  assertKnownKeys(table, POLICY_KEYS, "policy", sourceLabel);
  const result: PartialPolicyConfig = {};
  if (table.enabled !== undefined) {
    result.enabled = expectBoolean(table.enabled, "policy.enabled", sourceLabel);
  }
  if (table["secret-scan"] !== undefined) {
    result["secret-scan"] = expectBoolean(table["secret-scan"], "policy.secret-scan", sourceLabel);
  }
  if (table["max-changed-files"] !== undefined) {
    result["max-changed-files"] = expectInteger(table["max-changed-files"], "policy.max-changed-files", sourceLabel, 0);
  }
  if (table["fail-open"] !== undefined) {
    result["fail-open"] = expectBoolean(table["fail-open"], "policy.fail-open", sourceLabel);
  }
  return result;
}

const AUDIT_KEYS = ["path"] as const;

function parseAuditConfig(value: unknown, sourceLabel: string): PartialAuditConfig {
  const table = expectTable(value, "audit", sourceLabel);
  assertKnownKeys(table, AUDIT_KEYS, "audit", sourceLabel);
  const result: PartialAuditConfig = {};
  if (table.path !== undefined) {
    result.path = expectString(table.path, "audit.path", sourceLabel);
  }
  return result;
}

const TOP_LEVEL_KEYS = ["version", "name", "vm", "agent", "secrets", "egress", "git", "dir", "policy", "audit"] as const;

/**
 * Parses the text of one `corb.toml`-shaped document (`config.toml`, or one
 * workspace file — both share this exact schema) into a `ConfigLayer`.
 * Throws `ConfigParseError` for invalid TOML syntax, an unknown key at any
 * level, a value of the wrong type or shape, or a malformed duration/size/
 * percentage string. `sourceLabel` (e.g. `~/.config/corb/config.toml`) is
 * folded into every thrown error so the caller doesn't need to re-wrap.
 */
export function parseConfigLayer(toml: string, sourceLabel: string): ConfigLayer {
  let parsed: unknown;
  try {
    parsed = parse(toml);
  } catch (err) {
    if (err instanceof TomlError) {
      throw new ConfigParseError(sourceLabel, `invalid TOML syntax (line ${err.line}, column ${err.column}): ${err.message}`);
    }
    throw new ConfigParseError(sourceLabel, `could not parse TOML: ${String(err)}`);
  }

  const table = expectTable(parsed, "", sourceLabel);
  assertKnownKeys(table, TOP_LEVEL_KEYS, "", sourceLabel);

  const layer: ConfigLayer = {};
  if (table.version !== undefined) {
    layer.version = expectNumber(table.version, "version", sourceLabel);
  }
  if (table.name !== undefined) {
    layer.name = expectString(table.name, "name", sourceLabel);
  }
  if (table.vm !== undefined) {
    layer.vm = parseVmConfig(table.vm, sourceLabel);
  }
  if (table.agent !== undefined) {
    layer.agent = parseAgentConfig(table.agent, sourceLabel);
  }
  if (table.secrets !== undefined) {
    layer.secrets = parseSecretsConfig(table.secrets, sourceLabel);
  }
  if (table.egress !== undefined) {
    layer.egress = parseEgressConfig(table.egress, sourceLabel);
  }
  if (table.git !== undefined) {
    layer.git = parseGitConfig(table.git, sourceLabel);
  }
  if (table.dir !== undefined) {
    layer.dir = parseDirList(table.dir, sourceLabel);
  }
  if (table.policy !== undefined) {
    layer.policy = parsePolicyConfig(table.policy, sourceLabel);
  }
  if (table.audit !== undefined) {
    layer.audit = parseAuditConfig(table.audit, sourceLabel);
  }
  return layer;
}
